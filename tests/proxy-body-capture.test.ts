import { afterAll, describe, expect, test } from "bun:test";
import { proxyRequest } from "../src/services/proxy-service.ts";
import type { ResolvedHttpPolicy } from "../src/services/http-policy-service.ts";
import type { SiteRecord } from "../src/types.ts";

const origin = Bun.serve({
	hostname: "127.0.0.1",
	port: 0,
	async fetch(request) {
		if (new URL(request.url).pathname === "/echo-json") {
			const body = await request.text();
			return new Response(body, { headers: { "content-type": "application/json" } });
		}
		if (new URL(request.url).pathname === "/binary") {
			return new Response(new Uint8Array([0, 1, 2, 3, 4]), { headers: { "content-type": "application/octet-stream" } });
		}
		if (new URL(request.url).pathname === "/html") {
			return new Response("<html><body>hi</body></html>", { headers: { "content-type": "text/html" } });
		}
		return new Response("plain text response body", { headers: { "content-type": "text/plain" } });
	},
});

afterAll(() => origin.stop(true));

const site: SiteRecord = {
	id: "site-body-capture-test",
	name: "Body capture test",
	public_host: "proxy.test",
	origin_url: `http://127.0.0.1:${origin.port}`,
	origin_signing_secret: "test-signing-secret-that-is-at-least-32-characters",
	ip_extraction_preset: "direct",
	enabled: 1,
	session_ttl_seconds: 3_600,
	challenge_auto_ban_enabled: 0,
	challenge_auto_ban_max_failures: 5,
	challenge_auto_ban_seconds: 3_600,
	default_access_mode: "challenge",
	event_retention_days: 7,
	default_ip_action: "inherit",
	default_country_action: "inherit",
	error_response_mode: "json",
	error_html_template: "",
	error_json_fields_json: '["error","status"]',
	challenge_policy_json: "[]",
	challenge_html_template: "",
	created_at: Date.now(),
	updated_at: Date.now(),
};

function basePolicy(): ResolvedHttpPolicy {
	return {
		requestHeaders: { set: [], remove: [] },
		responseHeaders: { set: [], remove: [] },
		limits: { maxBodyBytes: 0, maxRequestTargetBytes: 0, maxHeaderBytes: 0 },
		cache: { mode: "disabled", ttlSeconds: 3_600, maxObjectBytes: 5_242_880, extensions: [".css"] },
		protection: { mode: "disabled", rulesetId: "default", excludedRuleIds: [] },
		banDurations: { low: 0, medium: 600, high: 3_600, critical: 86_400 },
		bandwidthLimit: { enabled: false, maxBytes: 50 * 1_024 * 1_024, windowSeconds: 60, banSeconds: 3_600, scopeId: "site-body-capture-test" },
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

describe("body capture through the proxy", () => {
	test("captures nothing when body capture is disabled", async () => {
		const { response, capturedRequestBody, capturedResponseBody } = await proxyRequest(
			new Request("http://proxy.test/echo-json", { method: "POST", headers: { "content-type": "application/json" }, body: '{"a":1}' }),
			site,
			"127.0.0.1",
			null,
			undefined,
			null,
			false,
			null,
			site.origin_url,
			basePolicy(),
		);
		expect(response.status).toBe(200);
		expect(capturedRequestBody).toBeNull();
		expect(capturedResponseBody).toBeNull();
	});

	test("captures small text request and response bodies when enabled", async () => {
		const policy = basePolicy();
		policy.bodyCapture = { mode: "enabled", maxRequestBytes: 4_096, maxResponseBytes: 4_096, expiresAt: null, contentTypes: ["*"] };
		const { response, capturedRequestBody, capturedResponseBody } = await proxyRequest(
			new Request("http://proxy.test/echo-json", { method: "POST", headers: { "content-type": "application/json" }, body: '{"a":1}' }),
			site,
			"127.0.0.1",
			null,
			undefined,
			null,
			false,
			null,
			site.origin_url,
			policy,
		);
		expect(response.status).toBe(200);
		expect(await response.text()).toBe('{"a":1}');
		expect(capturedRequestBody).toEqual({ text: '{"a":1}', truncated: false, contentType: "application/json" });
		expect(capturedResponseBody).not.toBeNull();
		expect(await capturedResponseBody).toEqual({ text: '{"a":1}', truncated: false, contentType: "application/json" });
	});

	test("truncates captured bodies at the configured limit without altering what's forwarded", async () => {
		const policy = basePolicy();
		policy.bodyCapture = { mode: "enabled", maxRequestBytes: 4, maxResponseBytes: 4_096, expiresAt: null, contentTypes: ["*"] };
		const { response, capturedRequestBody } = await proxyRequest(
			new Request("http://proxy.test/echo-json", { method: "POST", headers: { "content-type": "application/json" }, body: '{"long":"payload"}' }),
			site,
			"127.0.0.1",
			null,
			undefined,
			null,
			false,
			null,
			site.origin_url,
			policy,
		);
		expect(await response.text()).toBe('{"long":"payload"}');
		expect(capturedRequestBody).toEqual({ text: '{"lo', truncated: true, contentType: "application/json" });
	});

	test("never captures non-text content types", async () => {
		const policy = basePolicy();
		policy.bodyCapture = { mode: "enabled", maxRequestBytes: 4_096, maxResponseBytes: 4_096, expiresAt: null, contentTypes: ["*"] };
		const { response, capturedResponseBody } = await proxyRequest(
			new Request("http://proxy.test/binary"),
			site,
			"127.0.0.1",
			null,
			undefined,
			null,
			false,
			null,
			site.origin_url,
			policy,
		);
		expect(new Uint8Array(await response.arrayBuffer())).toEqual(new Uint8Array([0, 1, 2, 3, 4]));
		expect(await capturedResponseBody).toBeNull();
	});

	test("does not capture once the policy has expired", async () => {
		const policy = basePolicy();
		policy.bodyCapture = { mode: "enabled", maxRequestBytes: 4_096, maxResponseBytes: 4_096, expiresAt: Date.now() - 1_000, contentTypes: ["*"] };
		const { capturedRequestBody, capturedResponseBody } = await proxyRequest(
			new Request("http://proxy.test/echo-json", { method: "POST", headers: { "content-type": "application/json" }, body: '{"a":1}' }),
			site,
			"127.0.0.1",
			null,
			undefined,
			null,
			false,
			null,
			site.origin_url,
			policy,
		);
		expect(capturedRequestBody).toBeNull();
		expect(capturedResponseBody).toBeNull();
	});

	test("only captures content types the admin configured, even when text-based", async () => {
		const policy = basePolicy();
		policy.bodyCapture = { mode: "enabled", maxRequestBytes: 4_096, maxResponseBytes: 4_096, expiresAt: null, contentTypes: ["application/json"] };

		const htmlResult = await proxyRequest(
			new Request("http://proxy.test/html"),
			site,
			"127.0.0.1",
			null,
			undefined,
			null,
			false,
			null,
			site.origin_url,
			policy,
		);
		expect(await htmlResult.capturedResponseBody).toBeNull();

		const jsonResult = await proxyRequest(
			new Request("http://proxy.test/echo-json", { method: "POST", headers: { "content-type": "application/json" }, body: '{"a":1}' }),
			site,
			"127.0.0.1",
			null,
			undefined,
			null,
			false,
			null,
			site.origin_url,
			policy,
		);
		expect(jsonResult.capturedRequestBody).toEqual({ text: '{"a":1}', truncated: false, contentType: "application/json" });
		expect(await jsonResult.capturedResponseBody).toEqual({ text: '{"a":1}', truncated: false, contentType: "application/json" });
	});
});
