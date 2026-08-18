import { describe, expect, test } from "bun:test";
import { repository } from "../src/db/repository.ts";
import { buildStream, pickStreamRestartFields, streamRestartDiffers, streamView } from "../src/services/stream-service.ts";

describe("stream configuration", () => {
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
		});
	});
});
