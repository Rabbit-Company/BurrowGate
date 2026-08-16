import { describe, expect, test } from "bun:test";
import { StreamProxyManager } from "../src/services/stream-proxy-service.ts";
import { registerBundledStreamRuleSets } from "../src/services/stream-ruleset-defaults.ts";
import { serializeStreamBandwidthPolicy } from "../src/services/stream-bandwidth-policy-service.ts";
import { evaluateStreamIp } from "../src/services/stream-ip-rule-service.ts";
import type { StreamRecord } from "../src/types.ts";

function varint(value: number): number[] {
	const bytes: number[] = [];
	let remaining = value;
	do {
		let byte = remaining & 0x7f;
		remaining >>>= 7;
		if (remaining !== 0) byte |= 0x80;
		bytes.push(byte);
	} while (remaining !== 0);
	return bytes;
}

function mcString(value: string): number[] {
	const utf8 = [...Buffer.from(value, "utf8")];
	return [...varint(utf8.length), ...utf8];
}

function handshakePacket(nextState: number): Buffer {
	const payload = [0x00, ...varint(47), ...mcString("localhost"), 0x63, 0xdd, ...varint(nextState)];
	return Buffer.from([...varint(payload.length), ...payload]);
}

function loginStartPacket(username: string): Buffer {
	const payload = [0x00, ...mcString(username)];
	return Buffer.from([...varint(payload.length), ...payload]);
}

function record(): StreamRecord {
	return {
		id: "stream-test",
		name: "Stream test",
		incoming_port: 12345,
		forward_host: "origin.test",
		forward_port: 23456,
		tcp_enabled: 1,
		udp_enabled: 0,
		proxy_protocol: "disabled",
		certificate_id: null,
		event_retention_days: 7,
		default_ip_action: "inherit",
		default_country_action: "inherit",
		max_connections_per_ip: 0,
		connection_rate_limit_enabled: 0,
		connection_rate_limit_algorithm: "sliding-window",
		connection_rate_limit_window_ms: 60_000,
		connection_rate_limit_max: 60,
		connection_rate_limit_refill_rate: 10,
		connection_rate_limit_refill_interval_ms: 1_000,
		connection_rate_limit_precision_ms: 100,
		udp_amplification_max_ratio: 0,
		protection_policy_json: null,
		bandwidth_policy_json: null,
		origin_health_check_enabled: 0,
		origin_health_check_interval_seconds: 10,
		origin_health_check_timeout_ms: 3_000,
		created_at: Date.now(),
		updated_at: Date.now(),
	};
}

function fakeSocket(address: string, port: number, maxWriteBytes = Number.POSITIVE_INFINITY) {
	return {
		data: undefined as any,
		remoteAddress: address,
		remotePort: port,
		remoteFamily: address.includes(":") ? "IPv6" : "IPv4",
		localAddress: address.includes(":") ? "2001:db8::10" : "192.0.2.20",
		localPort: 12345,
		localFamily: address.includes(":") ? "IPv6" : "IPv4",
		writes: [] as Uint8Array[],
		terminated: false,
		write(data: Uint8Array) {
			const written = Math.min(data.byteLength, maxWriteBytes);
			this.writes.push(Buffer.from(data.subarray(0, written)));
			return written;
		},
		end() {},
		terminate() {
			this.terminated = true;
		},
		pause() {},
		resume() {},
		timeout() {},
	};
}

async function flushMicrotasks(times = 10): Promise<void> {
	for (let i = 0; i < times; i += 1) await Promise.resolve();
}

async function waitUntil(check: () => boolean, timeoutMs = 2_000): Promise<void> {
	const start = Date.now();
	while (!check()) {
		if (Date.now() - start > timeoutMs) throw new Error("Timed out waiting for condition");
		await new Promise((resolve) => setTimeout(resolve, 5));
	}
}

describe("TCP stream proxy", () => {
	test("forwards bytes in both directions and reports an active connection", async () => {
		let listenOptions: any;
		let connectOptions: any;
		const client = fakeSocket("203.0.113.8", 45678);
		const upstream = fakeSocket("192.0.2.10", 23456);
		const manager = new StreamProxyManager({
			listen(options) {
				listenOptions = options;
				return { port: options.port, hostname: options.hostname, data: undefined, stop() {}, ref() {}, unref() {}, reload() {}, [Symbol.dispose]() {} } as any;
			},
			async connect(options) {
				connectOptions = options;
				upstream.data = options.data;
				await options.socket.open?.(upstream as any);
				return upstream as any;
			},
		});

		await manager.apply(record());
		await listenOptions.socket.open(client);
		await Promise.resolve();
		listenOptions.socket.data(client, Buffer.from("hello"));
		connectOptions.socket.data(upstream, Buffer.from("world"));

		expect(Buffer.concat(upstream.writes).toString()).toBe("hello");
		expect(Buffer.concat(client.writes).toString()).toBe("world");
		expect(manager.activeConnections()).toMatchObject([
			{ streamId: "stream-test", protocol: "tcp", clientIp: "203.0.113.8", clientToUpstreamBytes: 5, upstreamToClientBytes: 5 },
		]);
		await manager.remove("stream-test");
	});

	test("writes a complete PROXY v1 header before buffered client bytes and excludes it from traffic totals", async () => {
		let listenOptions: any;
		let connectOptions: any;
		let releaseConnect!: () => void;
		const client = fakeSocket("203.0.113.8", 45_678);
		const upstream = fakeSocket("192.0.2.10", 23_456, 10);
		const manager = new StreamProxyManager({
			listen(options) {
				listenOptions = options;
				return { port: options.port, hostname: options.hostname, data: undefined, stop() {}, ref() {}, unref() {}, reload() {}, [Symbol.dispose]() {} } as any;
			},
			async connect(options) {
				connectOptions = options;
				await new Promise<void>((resolve) => {
					releaseConnect = resolve;
				});
				upstream.data = options.data;
				await options.socket.open?.(upstream as any);
				return upstream as any;
			},
		});

		await manager.apply({ ...record(), proxy_protocol: "v1" });
		const opening = listenOptions.socket.open(client);
		await waitUntil(() => connectOptions !== undefined);
		listenOptions.socket.data(client, Buffer.from("hello"));
		releaseConnect();
		await opening;
		for (let attempt = 0; attempt < 10; attempt += 1) connectOptions.socket.drain(upstream);

		expect(Buffer.concat(upstream.writes).toString()).toBe("PROXY TCP4 203.0.113.8 192.0.2.20 45678 12345\r\nhello");
		expect(manager.activeConnections()).toMatchObject([{ clientToUpstreamBytes: 5 }]);
		await manager.remove("stream-test");
	});

	test("rejects additional connections from the same IP once the per-IP limit is reached", async () => {
		let listenOptions: any;
		let connectCallCount = 0;
		const clientA = fakeSocket("203.0.113.8", 45678);
		const clientB = fakeSocket("203.0.113.8", 45679);
		const manager = new StreamProxyManager({
			listen(options) {
				listenOptions = options;
				return { port: options.port, hostname: options.hostname, data: undefined, stop() {}, ref() {}, unref() {}, reload() {}, [Symbol.dispose]() {} } as any;
			},
			async connect(options) {
				connectCallCount += 1;
				const upstream = fakeSocket("192.0.2.10", 23456);
				upstream.data = options.data;
				await options.socket.open?.(upstream as any);
				return upstream as any;
			},
		});

		await manager.apply({ ...record(), max_connections_per_ip: 1 });
		await listenOptions.socket.open(clientA);
		await Promise.resolve();
		await listenOptions.socket.open(clientB);
		await Promise.resolve();

		expect(connectCallCount).toBe(1);
		expect(clientB.terminated).toBe(true);
		expect(manager.activeConnections()).toMatchObject([{ streamId: "stream-test", protocol: "tcp", clientIp: "203.0.113.8", clientPort: 45678 }]);
		await manager.remove("stream-test");
	});

	test("rejects additional connections from the same IP once the connection rate limit is reached", async () => {
		let listenOptions: any;
		let connectCallCount = 0;
		const clientA = fakeSocket("203.0.113.9", 45678);
		const clientB = fakeSocket("203.0.113.9", 45679);
		const manager = new StreamProxyManager({
			listen(options) {
				listenOptions = options;
				return { port: options.port, hostname: options.hostname, data: undefined, stop() {}, ref() {}, unref() {}, reload() {}, [Symbol.dispose]() {} } as any;
			},
			async connect(options) {
				connectCallCount += 1;
				const upstream = fakeSocket("192.0.2.10", 23456);
				upstream.data = options.data;
				await options.socket.open?.(upstream as any);
				return upstream as any;
			},
		});

		await manager.apply({
			...record(),
			id: "stream-rate-test",
			connection_rate_limit_enabled: 1,
			connection_rate_limit_algorithm: "fixed-window",
			connection_rate_limit_max: 1,
		});
		await listenOptions.socket.open(clientA);
		await Promise.resolve();
		await listenOptions.socket.open(clientB);
		await Promise.resolve();

		expect(connectCallCount).toBe(1);
		expect(clientB.terminated).toBe(true);
		expect(manager.activeConnections()).toMatchObject([{ streamId: "stream-rate-test", protocol: "tcp", clientIp: "203.0.113.9", clientPort: 45678 }]);
		await manager.remove("stream-rate-test");
	});
});

describe("UDP stream proxy", () => {
	test("prepends a PROXY v2 DGRAM header to every upstream datagram without counting header bytes", async () => {
		let listenerOptions: any;
		const upstreamWrites: Buffer[] = [];
		const manager = new StreamProxyManager({
			resolveHost: async () => "192.0.2.10",
			udpSocket: (async (options: any) => {
				if (options.connect) {
					return {
						send: (data: Uint8Array) => {
							upstreamWrites.push(Buffer.from(data));
							return true;
						},
						close() {},
					} as any;
				}
				listenerOptions = options;
				return {
					address: { address: "192.0.2.20", port: 19_132, family: "IPv4" },
					send: () => true,
					close() {},
				} as any;
			}) as any,
		});

		await manager.apply({
			...record(),
			id: "stream-udp-proxy-v2-test",
			incoming_port: 19_132,
			forward_port: 19_133,
			tcp_enabled: 0,
			udp_enabled: 1,
			proxy_protocol: "v2",
		});

		listenerOptions.socket.data(undefined, Buffer.from("ping"), 40_000, "203.0.113.20", { truncated: false });
		listenerOptions.socket.data(undefined, Buffer.from("pong"), 40_000, "203.0.113.20", { truncated: false });
		await waitUntil(() => upstreamWrites.length === 2);

		const datagram = upstreamWrites[0]!;
		expect(datagram.subarray(0, 16).toString("hex")).toBe("0d0a0d0a000d0a515549540a2112000c");
		expect(datagram.subarray(16, 28).toString("hex")).toBe("cb007114c00002149c404abc");
		expect(datagram.subarray(28).toString()).toBe("ping");
		expect(upstreamWrites[1]!.subarray(0, 28)).toEqual(datagram.subarray(0, 28));
		expect(upstreamWrites[1]!.subarray(28).toString()).toBe("pong");
		expect(manager.activeConnections()).toMatchObject([{ protocol: "udp", clientToUpstreamBytes: 8 }]);
		await manager.remove("stream-udp-proxy-v2-test");
	});

	test("throttles UDP replies once the amplification ratio is exceeded", async () => {
		let listenerOptions: any;
		let upstreamOptions: any;
		const listenerSends: number[] = [];
		const manager = new StreamProxyManager({
			resolveHost: async () => "192.0.2.10",
			udpSocket: (async (options: any) => {
				if (options.connect) {
					upstreamOptions = options;
					return { send: () => true, close() {} } as any;
				}
				listenerOptions = options;
				return {
					send: (data: Uint8Array) => {
						listenerSends.push(data.byteLength);
						return true;
					},
					close() {},
				} as any;
			}) as any,
		});

		await manager.apply({
			...record(),
			id: "stream-udp-amp-test",
			tcp_enabled: 0,
			udp_enabled: 1,
			udp_amplification_max_ratio: 2,
		});

		listenerOptions.socket.data(undefined, Buffer.alloc(10), 40_000, "203.0.113.20", { truncated: false });
		await waitUntil(() => upstreamOptions !== undefined);
		await flushMicrotasks();

		upstreamOptions.socket.data(undefined, Buffer.alloc(5_000), 0, "", { truncated: false });
		await flushMicrotasks();

		expect(listenerSends).toEqual([]);
		await manager.remove("stream-udp-amp-test");
	});

	test("allows UDP replies within the configured amplification ratio", async () => {
		let listenerOptions: any;
		let upstreamOptions: any;
		const listenerSends: number[] = [];
		const manager = new StreamProxyManager({
			resolveHost: async () => "192.0.2.10",
			udpSocket: (async (options: any) => {
				if (options.connect) {
					upstreamOptions = options;
					return { send: () => true, close() {} } as any;
				}
				listenerOptions = options;
				return {
					send: (data: Uint8Array) => {
						listenerSends.push(data.byteLength);
						return true;
					},
					close() {},
				} as any;
			}) as any,
		});

		await manager.apply({
			...record(),
			id: "stream-udp-amp-ok-test",
			tcp_enabled: 0,
			udp_enabled: 1,
			udp_amplification_max_ratio: 2,
		});

		listenerOptions.socket.data(undefined, Buffer.alloc(10), 40_000, "203.0.113.21", { truncated: false });
		await waitUntil(() => upstreamOptions !== undefined);
		await flushMicrotasks();

		upstreamOptions.socket.data(undefined, Buffer.alloc(400), 0, "", { truncated: false });
		await flushMicrotasks();

		expect(listenerSends).toEqual([400]);
		await manager.remove("stream-udp-amp-ok-test");
	});
});

describe("Stream protection rulesets", () => {
	registerBundledStreamRuleSets();

	function protectionPolicy(rulesetIds: string[], mode: "monitor" | "block" = "block"): string {
		return JSON.stringify({ mode, rulesetIds, excludedRuleIds: [], banDurations: { low: 0, medium: 0, high: 0, critical: 0 } });
	}

	test("blocks a connection whose handshake fails minecraft-java decoding", async () => {
		let listenOptions: any;
		let connectCallCount = 0;
		const client = fakeSocket("203.0.113.40", 45678);
		const manager = new StreamProxyManager({
			listen(options) {
				listenOptions = options;
				return { port: options.port, hostname: options.hostname, data: undefined, stop() {}, ref() {}, unref() {}, reload() {}, [Symbol.dispose]() {} } as any;
			},
			async connect(options) {
				connectCallCount += 1;
				const upstream = fakeSocket("192.0.2.10", 23456);
				upstream.data = options.data;
				await options.socket.open?.(upstream as any);
				return upstream as any;
			},
		});

		await manager.apply({ ...record(), id: "stream-mc-block-test", protection_policy_json: protectionPolicy(["minecraft-java"]) });
		await listenOptions.socket.open(client);
		listenOptions.socket.data(client, Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]));
		await flushMicrotasks(20);

		expect(connectCallCount).toBe(0);
		expect(client.terminated).toBe(true);
		await manager.remove("stream-mc-block-test");
	});

	test("forwards a valid handshake to upstream once protection inspection clears it", async () => {
		let listenOptions: any;
		let connectOptions: any;
		const client = fakeSocket("203.0.113.41", 45678);
		const upstream = fakeSocket("192.0.2.10", 23456);
		const manager = new StreamProxyManager({
			listen(options) {
				listenOptions = options;
				return { port: options.port, hostname: options.hostname, data: undefined, stop() {}, ref() {}, unref() {}, reload() {}, [Symbol.dispose]() {} } as any;
			},
			async connect(options) {
				connectOptions = options;
				upstream.data = options.data;
				await options.socket.open?.(upstream as any);
				return upstream as any;
			},
		});

		await manager.apply({ ...record(), id: "stream-mc-ok-test", protection_policy_json: protectionPolicy(["minecraft-java"], "monitor") });
		await listenOptions.socket.open(client);
		const packet = handshakePacket(1); // status ping - decodes immediately, no login-start to wait for
		listenOptions.socket.data(client, packet);
		await flushMicrotasks(20);
		await waitUntil(() => connectOptions !== undefined);
		await flushMicrotasks();

		expect(Buffer.concat(upstream.writes).toString("hex")).toBe(packet.toString("hex"));
		await manager.remove("stream-mc-ok-test");
	});

	test("a status-ping handshake in block mode is not falsely flagged for a missing username", async () => {
		let listenOptions: any;
		let connectOptions: any;
		const client = fakeSocket("203.0.113.42", 45678);
		const upstream = fakeSocket("192.0.2.10", 23456);
		const manager = new StreamProxyManager({
			listen(options) {
				listenOptions = options;
				return { port: options.port, hostname: options.hostname, data: undefined, stop() {}, ref() {}, unref() {}, reload() {}, [Symbol.dispose]() {} } as any;
			},
			async connect(options) {
				connectOptions = options;
				upstream.data = options.data;
				await options.socket.open?.(upstream as any);
				return upstream as any;
			},
		});

		await manager.apply({ ...record(), id: "stream-mc-ping-block-test", protection_policy_json: protectionPolicy(["minecraft-java"]) });
		await listenOptions.socket.open(client);
		const packet = handshakePacket(1); // status ping - no login-start packet ever follows
		listenOptions.socket.data(client, packet);
		await flushMicrotasks(20);
		await waitUntil(() => connectOptions !== undefined);
		await flushMicrotasks();

		expect(client.terminated).toBe(false);
		expect(Buffer.concat(upstream.writes).toString("hex")).toBe(packet.toString("hex"));
		await manager.remove("stream-mc-ping-block-test");
	});

	test("captures the Minecraft username from a login-start packet onto the connection", async () => {
		let listenOptions: any;
		let connectOptions: any;
		const client = fakeSocket("203.0.113.44", 45678);
		const upstream = fakeSocket("192.0.2.10", 23456);
		const manager = new StreamProxyManager({
			listen(options) {
				listenOptions = options;
				return { port: options.port, hostname: options.hostname, data: undefined, stop() {}, ref() {}, unref() {}, reload() {}, [Symbol.dispose]() {} } as any;
			},
			async connect(options) {
				connectOptions = options;
				upstream.data = options.data;
				await options.socket.open?.(upstream as any);
				return upstream as any;
			},
		});

		await manager.apply({ ...record(), id: "stream-mc-username-test", protection_policy_json: protectionPolicy(["minecraft-java"], "monitor") });
		await listenOptions.socket.open(client);
		listenOptions.socket.data(client, handshakePacket(2)); // login state
		listenOptions.socket.data(client, loginStartPacket("Notch"));
		await flushMicrotasks(20);
		await waitUntil(() => connectOptions !== undefined);
		await flushMicrotasks();

		expect(manager.activeConnections()).toMatchObject([{ username: "Notch" }]);
		await manager.remove("stream-mc-username-test");
	});

	test("blocking a connection mid protection-decode does not poison the next connection as a zero-byte scan", async () => {
		let listenOptions: any;
		let connectCallCount = 0;
		const clientA = fakeSocket("203.0.113.43", 45678);
		const clientB = fakeSocket("203.0.113.43", 45679);
		const manager = new StreamProxyManager({
			listen(options) {
				listenOptions = options;
				return { port: options.port, hostname: options.hostname, data: undefined, stop() {}, ref() {}, unref() {}, reload() {}, [Symbol.dispose]() {} } as any;
			},
			async connect(options) {
				connectCallCount += 1;
				const upstream = fakeSocket("192.0.2.10", 23456);
				upstream.data = options.data;
				await options.socket.open?.(upstream as any);
				return upstream as any;
			},
		});

		await manager.apply({
			...record(),
			id: "stream-mc-gen020-test",
			protection_policy_json: protectionPolicy(["minecraft-java", "stream-connection-abuse"]),
		});

		await listenOptions.socket.open(clientA);
		listenOptions.socket.data(clientA, Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff])); // malformed - blocked mid-decode
		await flushMicrotasks(20);
		expect(clientA.terminated).toBe(true);
		expect(connectCallCount).toBe(0);

		await listenOptions.socket.open(clientB);
		const packet = handshakePacket(1); // a legitimate status ping from the same IP right after
		listenOptions.socket.data(clientB, packet);
		await flushMicrotasks(20);
		await waitUntil(() => connectCallCount === 1);
		await flushMicrotasks();

		expect(clientB.terminated).toBe(false);
		await manager.remove("stream-mc-gen020-test");
	});
});

describe("Bandwidth limit live updates", () => {
	test("enabling the TCP bandwidth limit via refreshRecord bans and closes an already-open connection", async () => {
		let listenOptions: any;
		const client = fakeSocket("203.0.113.60", 45678);
		const upstream = fakeSocket("192.0.2.10", 23456);
		const manager = new StreamProxyManager({
			listen(options) {
				listenOptions = options;
				return { port: options.port, hostname: options.hostname, data: undefined, stop() {}, ref() {}, unref() {}, reload() {}, [Symbol.dispose]() {} } as any;
			},
			async connect(options) {
				upstream.data = options.data;
				await options.socket.open?.(upstream as any);
				return upstream as any;
			},
		});

		const initial = record();
		await manager.apply(initial);
		await listenOptions.socket.open(client);
		await Promise.resolve();
		listenOptions.socket.data(client, Buffer.from("hello")); // 5 bytes while the limit is disabled - must not count against anything
		expect(client.terminated).toBe(false);

		// Enabling the limit does not restart the TCP listener (the port/host/cert fingerprint
		// is unchanged), so this must apply to the connection already open above, not just to
		// connections accepted afterward.
		manager.refreshRecord({
			...initial,
			bandwidth_policy_json: serializeStreamBandwidthPolicy({ tcp: { enabled: true, maxBytes: 8, windowSeconds: 60, banSeconds: 900 } }),
		});
		// Bytes sent while the limit was disabled were never counted, so this write alone must
		// exceed the cap on its own (it does not accumulate on top of the earlier "hello").
		listenOptions.socket.data(client, Buffer.from("well over eight bytes"));
		await waitUntil(() => client.terminated);

		expect(client.terminated).toBe(true);
		const decision = await evaluateStreamIp(initial, "203.0.113.60");
		expect(decision.action).toBe("block");
		await manager.remove("stream-test");
	});

	test("enabling the UDP bandwidth limit via refreshRecord bans and closes an already-open peer", async () => {
		let listenerOptions: any;
		const manager = new StreamProxyManager({
			resolveHost: async () => "192.0.2.10",
			udpSocket: (async (options: any) => {
				if (options.connect) return { send: () => true, close() {} } as any;
				listenerOptions = options;
				return { address: { address: "192.0.2.20", port: 19_132, family: "IPv4" }, send: () => true, close() {} } as any;
			}) as any,
		});

		const initial = { ...record(), id: "stream-udp-live-test", tcp_enabled: 0, udp_enabled: 1, incoming_port: 19_132 };
		await manager.apply(initial);
		listenerOptions.socket.data(undefined, Buffer.alloc(5), 40_000, "203.0.113.61", { truncated: false });
		await waitUntil(() => manager.activeConnections().length === 1);

		manager.refreshRecord({
			...initial,
			bandwidth_policy_json: serializeStreamBandwidthPolicy({ udp: { enabled: true, maxBytes: 8, windowSeconds: 60, banSeconds: 900 } }),
		});
		// Bytes sent while the limit was disabled were never counted, so this datagram alone
		// must exceed the cap on its own (10 bytes against an 8 byte cap).
		listenerOptions.socket.data(undefined, Buffer.alloc(10), 40_000, "203.0.113.61", { truncated: false });
		await waitUntil(() => manager.activeConnections().length === 0);

		const decision = await evaluateStreamIp(initial, "203.0.113.61");
		expect(decision.action).toBe("block");
		await manager.remove("stream-udp-live-test");
	});
});
