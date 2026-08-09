import { describe, expect, test } from "bun:test";
import { StreamProxyManager } from "../src/services/stream-proxy-service.ts";
import type { StreamRecord } from "../src/types.ts";

function record(): StreamRecord {
	return {
		id: "stream-test",
		incoming_port: 12345,
		forward_host: "origin.test",
		forward_port: 23456,
		tcp_enabled: 1,
		udp_enabled: 0,
		certificate_id: null,
		event_retention_days: 7,
		default_ip_action: "inherit",
		default_country_action: "inherit",
		max_connections_per_ip: 0,
		created_at: Date.now(),
		updated_at: Date.now(),
	};
}

function fakeSocket(address: string, port: number) {
	return {
		data: undefined as any,
		remoteAddress: address,
		remotePort: port,
		writes: [] as Uint8Array[],
		terminated: false,
		write(data: Uint8Array) {
			this.writes.push(Buffer.from(data));
			return data.byteLength;
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
});
