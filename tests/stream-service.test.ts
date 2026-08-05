import { describe, expect, test } from "bun:test";
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
});
