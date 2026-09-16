import { describe, expect, test } from "bun:test";
import { repository } from "../src/db/repository.ts";
import { buildStream, pickStreamRestartFields, streamRestartDiffers, streamView } from "../src/services/stream-service.ts";
import { serializeNetworkPrivacyPolicy } from "../src/services/network-privacy-service.ts";

describe("stream configuration", () => {
	test("persists incoming trust settings independently from outgoing forwarding and preserves them on partial updates", async () => {
		const stream = await buildStream({
			name: "Load balancer stream",
			incomingPort: 39002,
			forwardHost: "localhost",
			forwardPort: 39003,
			incomingProxyProtocol: true,
			trustedProxyCidrs: ["10.0.0.2/32", "2001:db8::2", "10.0.0.2/32"],
		});
		await repository.saveStream(stream);
		try {
			const stored = (await repository.streamById(stream.id))!;
			expect(streamView(stored)).toMatchObject({ incomingProxyProtocol: true, trustedProxyCidrs: ["10.0.0.2/32", "2001:db8::2"], proxyProtocol: "disabled" });
			const updated = await buildStream({ name: "Renamed" }, stored);
			expect(streamRestartDiffers(stored, updated)).toBe(false);
			expect(updated.proxy_protocol_trusted_cidrs_json).toBe(stored.proxy_protocol_trusted_cidrs_json);
		} finally {
			await repository.deleteStream(stream.id);
		}
	});

	test("rejects incoming PROXY without trusted addresses, malformed trust entries, and UDP-only enablement", async () => {
		const base = { name: "Load balancer stream", incomingPort: 39004, forwardHost: "localhost", forwardPort: 39005, incomingProxyProtocol: true };
		await expect(buildStream(base)).rejects.toThrow("at least one trusted");
		await expect(buildStream({ ...base, trustedProxyCidrs: ["not-an-ip"] })).rejects.toThrow("Invalid trusted");
		await expect(buildStream({ ...base, trustedProxyCidrs: ["10.0.0.2"], tcpEnabled: false, udpEnabled: true })).rejects.toThrow("requires TCP");
	});

	test("legacy missing/null incoming fields do not restart a listener on a name edit", async () => {
		const stream = await buildStream({ name: "Legacy stream", incomingPort: 39006, forwardHost: "localhost", forwardPort: 39007 });
		const legacy = { ...stream, incoming_proxy_protocol: undefined, proxy_protocol_trusted_cidrs_json: null };
		expect(streamRestartDiffers(legacy, await buildStream({ name: "Renamed" }, legacy))).toBe(false);
		expect(streamRestartDiffers(stream, await buildStream({ incomingProxyProtocol: true, trustedProxyCidrs: ["10.0.0.2"] }, stream))).toBe(true);
	});

	test("requires at least one transport protocol", async () => {
		await expect(
			buildStream({ name: "Test stream", incomingPort: 9000, forwardHost: "127.0.0.1", forwardPort: 9001, tcpEnabled: false, udpEnabled: false }),
		).rejects.toThrow("at least one");
	});

	test("normalizes a TCP and UDP stream with independent retention", async () => {
		const stream = await buildStream({
			name: "Test stream",
			incomingPort: 19132,
			forwardHost: "[::1]",
			forwardPort: 19133,
			tcpEnabled: true,
			udpEnabled: true,
			eventRetentionDays: 14,
		});
		expect(streamView(stream)).toMatchObject({
			incomingPort: 19132,
			forwardHost: "::1",
			forwardPort: 19133,
			tcpEnabled: true,
			udpEnabled: true,
			eventRetentionDays: 14,
		});
	});

	test("rejects TLS when TCP is disabled", async () => {
		await expect(
			buildStream({
				name: "Test stream",
				incomingPort: 9000,
				forwardHost: "localhost",
				forwardPort: 9001,
				tcpEnabled: false,
				udpEnabled: true,
				certificateId: "cert-a",
			}),
		).rejects.toThrow("only be used when TCP is enabled");
	});

	test("defaults client IP forwarding to disabled and accepts v2 for TCP and UDP", async () => {
		const disabled = await buildStream({ name: "Test stream", incomingPort: 9002, forwardHost: "localhost", forwardPort: 9003 });
		expect(disabled.proxy_protocol).toBe("disabled");
		expect(streamView(disabled).proxyProtocol).toBe("disabled");

		const v2 = await buildStream({
			name: "Test stream",
			incomingPort: 19_132,
			forwardHost: "localhost",
			forwardPort: 19_133,
			tcpEnabled: true,
			udpEnabled: true,
			proxyProtocol: "v2",
		});
		expect(v2.proxy_protocol).toBe("v2");
	});

	test("rejects PROXY protocol v1 for an UDP-only stream", async () => {
		await expect(
			buildStream({
				name: "Test stream",
				incomingPort: 19_132,
				forwardHost: "localhost",
				forwardPort: 19_133,
				tcpEnabled: false,
				udpEnabled: true,
				proxyProtocol: "v1",
			}),
		).rejects.toThrow("only available for TCP");
	});

	test("persists the selected PROXY protocol mode", async () => {
		const stream = await buildStream({
			name: "Test stream",
			incomingPort: 29_132,
			forwardHost: "localhost",
			forwardPort: 29_133,
			proxyProtocol: "v2",
		});
		await repository.saveStream(stream);
		expect((await repository.streamById(stream.id))?.proxy_protocol).toBe("v2");
		await repository.deleteStream(stream.id);
	});

	test("exposes and persists stream network privacy modes", async () => {
		const stream = await buildStream({ name: "Privacy stream", incomingPort: 29_134, forwardHost: "localhost", forwardPort: 29_135 });
		stream.network_privacy_policy_json = serializeNetworkPrivacyPolicy({ tor: "monitor", vpn: "block" });
		await repository.saveStream(stream);
		expect(streamView((await repository.streamById(stream.id))!).networkPrivacyPolicy).toEqual({
			tor: "monitor",
			vpn: "block",
		});
		await repository.deleteStream(stream.id);
	});
});

describe("streamRestartDiffers", () => {
	test("is false when only live-appliable fields change", async () => {
		const previous = await buildStream({ name: "Test stream", incomingPort: 40_000, forwardHost: "localhost", forwardPort: 40_001 });
		const candidate = await buildStream({ name: "Renamed stream", maxConnectionsPerIp: 25 }, previous);
		expect(streamRestartDiffers(previous, candidate)).toBe(false);
	});

	test("is true when the incoming port changes", async () => {
		const previous = await buildStream({ name: "Test stream", incomingPort: 40_002, forwardHost: "localhost", forwardPort: 40_003 });
		const candidate = await buildStream({ incomingPort: 40_004 }, previous);
		expect(streamRestartDiffers(previous, candidate)).toBe(true);
	});

	test("is true when the forward host or port changes", async () => {
		const previous = await buildStream({ name: "Test stream", incomingPort: 40_005, forwardHost: "localhost", forwardPort: 40_006 });
		expect(streamRestartDiffers(previous, await buildStream({ forwardHost: "example.test" }, previous))).toBe(true);
		expect(streamRestartDiffers(previous, await buildStream({ forwardPort: 40_007 }, previous))).toBe(true);
	});

	test("is true when a transport protocol is toggled", async () => {
		const previous = await buildStream({
			name: "Test stream",
			incomingPort: 40_008,
			forwardHost: "localhost",
			forwardPort: 40_009,
			tcpEnabled: true,
			udpEnabled: false,
		});
		const candidate = await buildStream({ tcpEnabled: true, udpEnabled: true }, previous);
		expect(streamRestartDiffers(previous, candidate)).toBe(true);
	});

	test("is true when the PROXY protocol mode changes", async () => {
		const previous = await buildStream({ name: "Test stream", incomingPort: 40_010, forwardHost: "localhost", forwardPort: 40_011 });
		const candidate = await buildStream({ proxyProtocol: "v2" }, previous);
		expect(streamRestartDiffers(previous, candidate)).toBe(true);
	});
});

describe("pickStreamRestartFields", () => {
	test("only carries the fingerprint-relevant fields", async () => {
		const stream = await buildStream({
			name: "Test stream",
			incomingPort: 40_012,
			forwardHost: "localhost",
			forwardPort: 40_013,
			maxConnectionsPerIp: 42,
		});
		expect(pickStreamRestartFields(stream)).toEqual({
			tcp_enabled: stream.tcp_enabled,
			udp_enabled: stream.udp_enabled,
			incoming_port: stream.incoming_port,
			forward_host: stream.forward_host,
			forward_port: stream.forward_port,
			certificate_id: stream.certificate_id,
			proxy_protocol: stream.proxy_protocol,
			incoming_proxy_protocol: stream.incoming_proxy_protocol,
			proxy_protocol_trusted_cidrs_json: stream.proxy_protocol_trusted_cidrs_json,
		});
	});
});
