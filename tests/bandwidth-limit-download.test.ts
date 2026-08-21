import { afterAll, describe, expect, test } from "bun:test";
import { proxyRequest } from "../src/services/proxy-service.ts";
import { clearBandwidthLimitEntries } from "../src/services/bandwidth-limit-service.ts";
import { evaluateIp } from "../src/services/ip-rule-service.ts";
import { createSite } from "../src/services/site-service.ts";
import type { ResolvedHttpPolicy } from "../src/services/http-policy-service.ts";

const bigBody = "x".repeat(2_000);

const origin = Bun.serve({
	hostname: "127.0.0.1",
	port: 0,
	fetch() {
		return new Response(bigBody, { headers: { "content-type": "text/plain" } });
	},
});

afterAll(() => origin.stop(true));

function policyWithBandwidthLimit(scopeId: string): ResolvedHttpPolicy {
	return {
		requestHeaders: { set: [], remove: [] },
		responseHeaders: { set: [], remove: [] },
		limits: { maxBodyBytes: 0, maxRequestTargetBytes: 0, maxHeaderBytes: 0 },
		cache: { mode: "disabled", ttlSeconds: 3_600, maxObjectBytes: 5_242_880, extensions: [".css"] },
		protection: { mode: "disabled", rulesetId: "default", excludedRuleIds: [] },
		banDurations: { low: 0, medium: 600, high: 3_600, critical: 86_400 },
		bandwidthLimit: { enabled: true, maxBytes: 1_000, windowSeconds: 60, banSeconds: 900, scopeId },
		bodyCapture: { mode: "disabled", maxRequestBytes: 4_096, maxResponseBytes: 4_096, expiresAt: null, contentTypes: ["*"] },
		headerCapture: { mode: "disabled", redactAuthHeaders: true, redactedHeaders: [], expiresAt: null },
		cors: {
			mode: "disabled",
			allowedOrigins: [],
			allowedMethods: ["GET", "HEAD", "POST"],
			allowedHeaders: ["content-type", "authorization"],
			exposedHeaders: [],
			allowCredentials: false,
			maxAgeSeconds: 86_400,
		},
		hsts: { mode: "disabled", maxAgeSeconds: 15_552_000, includeSubDomains: false, preload: false },
	};
}

async function drain(body: ReadableStream<Uint8Array> | null): Promise<void> {
	if (!body) return;
	for await (const _chunk of body) {
		/* consume to trigger the metering transform */
	}
}

describe("bandwidth limit counts response (download) bytes", () => {
	test("a GET-only client that never uploads anything still gets banned once downloads cross the threshold", async () => {
		clearBandwidthLimitEntries();
		const site = (await createSite({ name: "Download limit", publicHost: `bw-download-${crypto.randomUUID()}.test`, originUrl: origin.url.toString() })).site;
		const ip = "203.0.113.50";
		const policy = policyWithBandwidthLimit(site.id);

		// Each response body is 2000 bytes; the threshold is 1000, so the first
		// completed download alone should already cross it.
		const { response } = await proxyRequest(
			new Request("http://proxy.test/download"),
			site,
			ip,
			null,
			undefined,
			null,
			false,
			null,
			origin.url.toString(),
			policy,
		);
		expect(response.status).toBe(200);
		await drain(response.body);
		await new Promise((resolve) => setTimeout(resolve, 50));

		const decision = await evaluateIp(site, ip);
		expect(decision.action).toBe("block");
	});
});
