import { afterAll, afterEach, beforeEach, describe, expect, test } from "bun:test";
import { config } from "../src/config.ts";
import { connectionControlFor, withConnectionControl } from "../src/services/connection-control-service.ts";
import { proxyRequest } from "../src/services/proxy-service.ts";
import {
	guardResponseBody,
	readBodyWithinDeadline,
	RequestBodyIncompleteError,
	RequestBodyTimeoutError,
	UploadDeadline,
} from "../src/services/transfer-timeout-service.ts";
import type { ResolvedHttpPolicy } from "../src/services/http-policy-service.ts";
import type { SiteRecord } from "../src/types.ts";

const encoder = new TextEncoder();
const saved = { originTimeoutMs: config.originTimeoutMs, client: { ...config.client } };

beforeEach(() => {
	config.originTimeoutMs = 400;
	config.client.timeoutMs = 300;
	config.client.minRateBytesPerSecond = 1_000;
});

afterEach(() => {
	config.originTimeoutMs = saved.originTimeoutMs;
	Object.assign(config.client, saved.client);
});

function slowStream(chunks: string[], delayMs: number): ReadableStream<Uint8Array> {
	let index = 0;
	return new ReadableStream({
		async pull(controller) {
			await Bun.sleep(delayMs);
			if (index >= chunks.length) return controller.close();
			controller.enqueue(encoder.encode(chunks[index++]!));
		},
	});
}

describe("upload deadline", () => {
	test("expires when the gap between chunks exceeds the client timeout", async () => {
		let expired = false;
		const deadline = new UploadDeadline(() => (expired = true));
		await Bun.sleep(200);
		deadline.received(10_000);
		await Bun.sleep(200);
		expect(expired).toBe(false);
		await Bun.sleep(150);
		expect(expired).toBe(true);
	});

	test("expires when the average rate falls below the minimum despite short gaps", async () => {
		let expiredAt = 0;
		const started = Date.now();
		const deadline = new UploadDeadline(() => (expiredAt = Date.now() - started));
		for (let i = 0; i < 6 && !expiredAt; i++) {
			await Bun.sleep(100);
			deadline.received(10);
		}
		deadline.stop();
		expect(expiredAt).toBeGreaterThan(250);
		expect(expiredAt).toBeLessThan(450);
	});

	test("rejects a buffered body that arrives too slowly or ends early", async () => {
		const trickled = new Request("http://proxy.test/", { method: "POST", body: slowStream(["a", "b", "c", "d", "e"], 400) });
		expect(readBodyWithinDeadline(trickled, 5, null)).rejects.toBeInstanceOf(RequestBodyTimeoutError);
		const short = new Request("http://proxy.test/", { method: "POST", body: "abc" });
		expect(readBodyWithinDeadline(short, 10, null)).rejects.toBeInstanceOf(RequestBodyIncompleteError);
		const complete = new Request("http://proxy.test/", { method: "POST", body: "abcdef" });
		expect(new TextDecoder().decode(await readBodyWithinDeadline(complete, 6, null))).toBe("abcdef");
	});
});

describe("guarded response body", () => {
	test("closes when the origin goes silent mid-body", async () => {
		let abortedWith: unknown = null;
		const stalled = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(encoder.encode("first"));
			},
			pull: () => new Promise<void>(() => {}),
		});
		const reader = guardResponseBody(stalled, { control: null, abortOrigin: (reason) => (abortedWith = reason), originIdleMs: 200, describe: {} }).getReader();
		expect(new TextDecoder().decode((await reader.read()).value)).toBe("first");
		expect(reader.read()).rejects.toThrow("stopped sending");
		await Bun.sleep(250);
		expect((abortedWith as Error).name).toBe("TimeoutError");
	});

	test("closes when the client stops taking chunks", async () => {
		let aborted = false;
		const reader = guardResponseBody(slowStream(["one", "two"], 0), {
			control: null,
			abortOrigin: () => (aborted = true),
			originIdleMs: 1_000,
			describe: {},
		}).getReader();
		await reader.read();
		await Bun.sleep(200);
		expect(aborted).toBe(false);
		await Bun.sleep(200);
		expect(aborted).toBe(true);
	});
});

describe("proxied responses outlive the listener timeout", () => {
	const origin = Bun.serve({
		hostname: "127.0.0.1",
		port: 0,
		idleTimeout: 0,
		fetch: () =>
			new Response(
				slowStream(
					Array.from({ length: 11 }, (_, i) => `chunk${i}\n`),
					500,
				),
			),
	});
	const site = {
		id: "site-transfer-timeout",
		name: "Transfer timeout",
		public_host: "proxy.test",
		origin_url: `http://127.0.0.1:${origin.port}`,
		origin_signing_secret: "test-signing-secret-that-is-at-least-32-characters",
		ip_extraction_preset: "direct",
	} as SiteRecord;
	const policy = {
		requestHeaders: { set: [], remove: [] },
		responseHeaders: { set: [], remove: [] },
		limits: {
			maxBodyBytes: 0,
			maxRequestTargetBytes: 0,
			maxHeaderBytes: 0,
			maxHeaderCount: 0,
			maxInputFields: 0,
			maxMultipartParts: 0,
			maxInputNestingDepth: 0,
		},
		blockedMultipartFields: [],
		cache: { mode: "disabled", ttlSeconds: 3_600, maxObjectBytes: 5_242_880, extensions: [] },
		protection: { mode: "disabled", rulesetId: "default", excludedRuleIds: [] },
		banDurations: { low: 0, medium: 600, high: 3_600, critical: 86_400 },
		bandwidthLimit: { enabled: false, maxBytes: 1, windowSeconds: 60, banSeconds: 0, scopeId: site.id },
		bodyCapture: { mode: "disabled", maxRequestBytes: 0, maxResponseBytes: 0, expiresAt: null, contentTypes: [] },
		headerCapture: { mode: "disabled", redactAuthHeaders: true, redactedHeaders: [], expiresAt: null },
		cors: { mode: "disabled", allowedOrigins: [], allowedMethods: [], allowedHeaders: [], exposedHeaders: [], allowCredentials: false, maxAgeSeconds: 0 },
		hsts: { mode: "disabled", maxAgeSeconds: 0, includeSubDomains: false, preload: false },
	} as ResolvedHttpPolicy;
	const gateway = Bun.serve({
		hostname: "127.0.0.1",
		port: 0,
		idleTimeout: 2,
		fetch: (request, server) =>
			withConnectionControl(connectionControlFor(request, server), async () => {
				const { response } = await proxyRequest(request, site, "127.0.0.1", null, undefined, null, false, null, site.origin_url, policy);
				return response;
			}),
	});
	afterAll(() => {
		gateway.stop(true);
		origin.stop(true);
	});

	test("streams a slow but steady 5.5s response through a listener with a 2s timeout", async () => {
		config.originTimeoutMs = 1_000;
		config.client.timeoutMs = 1_000;
		const response = await fetch(`http://127.0.0.1:${gateway.port}/download`);
		const text = await response.text();
		expect(text.split("\n").filter(Boolean)).toHaveLength(11);
	}, 15_000);
});
