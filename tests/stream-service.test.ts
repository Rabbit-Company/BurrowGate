import { describe, expect, test } from "bun:test";
import { repository } from "../src/db/repository.ts";
import { buildStream, streamView } from "../src/services/stream-service.ts";

describe("stream configuration", () => {
	test("requires at least one transport protocol", async () => {
		await expect(buildStream({ incomingPort: 9000, forwardHost: "127.0.0.1", forwardPort: 9001, tcpEnabled: false, udpEnabled: false })).rejects.toThrow(
			"at least one",
		);
	});

	test("normalizes a TCP and UDP stream with independent retention", async () => {
		const stream = await buildStream({
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
			buildStream({ incomingPort: 9000, forwardHost: "localhost", forwardPort: 9001, tcpEnabled: false, udpEnabled: true, certificateId: "cert-a" }),
		).rejects.toThrow("only be used when TCP is enabled");
	});

	test("defaults client IP forwarding to disabled and accepts v2 for TCP and UDP", async () => {
		const disabled = await buildStream({ incomingPort: 9002, forwardHost: "localhost", forwardPort: 9003 });
		expect(disabled.proxy_protocol).toBe("disabled");
		expect(streamView(disabled).proxyProtocol).toBe("disabled");

		const v2 = await buildStream({
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
