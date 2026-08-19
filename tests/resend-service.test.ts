import { afterEach, describe, expect, test } from "bun:test";
import { resendCapturedRequest, ResendTargetError } from "../src/services/resend-service.ts";
import { captureHeaders } from "../src/services/header-capture-service.ts";
import type { RequestEventRecord, SiteRecord } from "../src/types.ts";

const site: SiteRecord = {
	id: "site-resend-test",
	name: "Resend test",
	public_host: "resend.test",
	origin_url: "http://127.0.0.1:9",
	origin_signing_secret: "test-signing-secret-that-is-at-least-32-characters",
	ip_extraction_preset: "direct",
	enabled: 1,
	session_ttl_seconds: 3_600,
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

function event(overrides: Partial<RequestEventRecord> = {}): RequestEventRecord {
	return {
		id: "evt_resend_test",
		site_id: site.id,
		session_id: null,
		ip: "203.0.113.9",
		method: "GET",
		path: "/api/widgets",
		status: 200,
		decision: "proxied",
		latency_ms: 12,
		country_code: null,
		asn: null,
		asn_org: null,
		origin_id: null,
		cache_status: null,
		protection_status: null,
		protection_rule_id: null,
		protection_category: null,
		protection_severity: null,
		protection_ruleset_id: null,
		protection_ruleset_version: null,
		protection_matches_json: null,
		access_username: null,
		referer: null,
		referer_host: null,
		request_body: null,
		request_body_truncated: null,
		request_content_type: null,
		response_body: null,
		response_body_truncated: null,
		response_content_type: null,
		request_headers: null,
		request_headers_truncated: null,
		response_headers: null,
		response_headers_truncated: null,
		created_at: Date.now(),
		...overrides,
	};
}

const originalFetch = globalThis.fetch;

afterEach(() => {
	globalThis.fetch = originalFetch;
});

describe("resendCapturedRequest", () => {
	test("dispatches to the site's real public host and strips framing headers from the capture", async () => {
		const captured = captureHeaders(new Headers({ "x-custom": "value", host: "wrong-host.test", "content-length": "0" }), {
			redactAuthHeaders: true,
			redactedHeaders: [],
		});
		let seenUrl: unknown;
		let seenHeaders: Headers | undefined;
		globalThis.fetch = (async (url: unknown, init: RequestInit) => {
			seenUrl = url;
			seenHeaders = init.headers as Headers;
			return new Response("ok", { status: 200, headers: { "content-type": "text/plain" } });
		}) as typeof fetch;

		const result = await resendCapturedRequest(event({ request_headers: captured?.json ?? null }), site, {});
		expect(result.status).toBe(200);
		expect(String(seenUrl)).toBe(`https://${site.public_host}/api/widgets`);
		expect(seenHeaders?.get("x-custom")).toBe("value");
		expect(seenHeaders?.has("host")).toBe(false);
		expect(seenHeaders?.has("content-length")).toBe(false);
	});

	test("omits a redacted header unless the caller supplies an override value", async () => {
		const captured = captureHeaders(new Headers({ authorization: "Bearer secret" }), { redactAuthHeaders: true, redactedHeaders: [] });
		let seenHeaders: Headers | undefined;
		globalThis.fetch = (async (_url: unknown, init: RequestInit) => {
			seenHeaders = init.headers as Headers;
			return new Response("ok", { status: 200 });
		}) as typeof fetch;

		await resendCapturedRequest(event({ request_headers: captured?.json ?? null }), site, {});
		expect(seenHeaders?.has("authorization")).toBe(false);

		await resendCapturedRequest(event({ request_headers: captured?.json ?? null }), site, { headers: { Authorization: "Bearer replacement" } });
		expect(seenHeaders?.get("authorization")).toBe("Bearer replacement");
	});

	test("sends no body for GET/HEAD even when a body override is supplied", async () => {
		let seenBody: unknown;
		globalThis.fetch = (async (_url: unknown, init: RequestInit) => {
			seenBody = init.body;
			return new Response("ok", { status: 200 });
		}) as typeof fetch;

		await resendCapturedRequest(event({ method: "GET" }), site, { body: "should be ignored" });
		expect(seenBody).toBeNull();
	});

	test("sends the overridden body for non-GET methods", async () => {
		let seenBody: unknown;
		let seenMethod: unknown;
		globalThis.fetch = (async (_url: unknown, init: RequestInit) => {
			seenBody = init.body;
			seenMethod = init.method;
			return new Response("ok", { status: 200 });
		}) as typeof fetch;

		await resendCapturedRequest(event({ method: "POST", request_body: "captured" }), site, { body: "overridden" });
		expect(seenMethod).toBe("POST");
		expect(seenBody).toBe("overridden");
	});

	test("defaults Content-Type from the captured body's content type when nothing else set it", async () => {
		let seenHeaders: Headers | undefined;
		globalThis.fetch = (async (_url: unknown, init: RequestInit) => {
			seenHeaders = init.headers as Headers;
			return new Response("ok", { status: 200 });
		}) as typeof fetch;

		await resendCapturedRequest(event({ method: "POST", request_body: '{"a":1}', request_content_type: "application/json; charset=utf-8" }), site, {});
		expect(seenHeaders?.get("content-type")).toBe("application/json; charset=utf-8");
	});

	test("does not override an explicitly supplied Content-Type with the captured one", async () => {
		let seenHeaders: Headers | undefined;
		globalThis.fetch = (async (_url: unknown, init: RequestInit) => {
			seenHeaders = init.headers as Headers;
			return new Response("ok", { status: 200 });
		}) as typeof fetch;

		await resendCapturedRequest(event({ method: "POST", request_body: '{"a":1}', request_content_type: "application/json" }), site, {
			headers: { "Content-Type": "text/plain" },
		});
		expect(seenHeaders?.get("content-type")).toBe("text/plain");
	});

	test("does not set a Content-Type default when there is no body to send", async () => {
		let seenHeaders: Headers | undefined;
		globalThis.fetch = (async (_url: unknown, init: RequestInit) => {
			seenHeaders = init.headers as Headers;
			return new Response("ok", { status: 200 });
		}) as typeof fetch;

		await resendCapturedRequest(event({ method: "GET", request_content_type: "application/json" }), site, {});
		expect(seenHeaders?.has("content-type")).toBe(false);
	});

	test("wraps a fetch failure in ResendTargetError", async () => {
		globalThis.fetch = (async () => {
			throw new Error("connection refused");
		}) as unknown as typeof fetch;

		await expect(resendCapturedRequest(event(), site, {})).rejects.toBeInstanceOf(ResendTargetError);
	});

	test("follows a same-site redirect, preserving method, body, and headers", async () => {
		const captured = captureHeaders(new Headers({ authorization: "Bearer secret" }), { redactAuthHeaders: false, redactedHeaders: [] });
		const calls: Array<{ path: string; method: string; body: unknown; authorization: string | null }> = [];
		globalThis.fetch = (async (url: unknown, init: RequestInit) => {
			const path = new URL(String(url)).pathname;
			const headers = init.headers as Headers;
			calls.push({ path, method: String(init.method), body: init.body, authorization: headers.get("authorization") });
			if (calls.length === 1) {
				return new Response(null, {
					status: 308,
					headers: { location: `https://${site.public_host}/api/v1/result/abc.html` },
				});
			}
			return new Response("final content", { status: 200 });
		}) as typeof fetch;

		const result = await resendCapturedRequest(event({ method: "POST", request_body: "payload", request_headers: captured?.json ?? null }), site, {});
		expect(calls).toHaveLength(2);
		expect(calls[0]?.path).toBe("/api/widgets");
		expect(calls[1]?.path).toBe("/api/v1/result/abc.html");
		expect(calls[1]?.method).toBe("POST");
		expect(calls[1]?.body).toBe("payload");
		expect(calls[1]?.authorization).toBe("Bearer secret");
		expect(result.status).toBe(200);
		expect(result.body).toBe("final content");
		expect(result.hops).toEqual([
			{ method: "POST", path: "/api/widgets", status: 308, location: "https://resend.test/api/v1/result/abc.html", followed: true, notFollowedReason: null },
			{ method: "POST", path: "/api/v1/result/abc.html", status: 200, location: null, followed: false, notFollowedReason: null },
		]);
	});

	test("follows a same-site redirect even when the site's public host carries an explicit port", async () => {
		const portedSite: SiteRecord = { ...site, public_host: `${site.public_host}:8443` };
		const calls: string[] = [];
		globalThis.fetch = (async (url: unknown) => {
			calls.push(new URL(String(url)).pathname);
			if (calls.length === 1) {
				return new Response(null, { status: 308, headers: { location: `https://${site.public_host}/api/v1/result/abc.html` } });
			}
			return new Response("final content", { status: 200 });
		}) as typeof fetch;

		const result = await resendCapturedRequest(event(), portedSite, {});
		expect(calls).toHaveLength(2);
		expect(result.status).toBe(200);
		expect(result.body).toBe("final content");
	});

	test("does not follow a redirect to a different host, returning the raw redirect instead", async () => {
		globalThis.fetch = (async () => {
			return new Response(null, { status: 302, headers: { location: "https://attacker.example/steal" } });
		}) as unknown as typeof fetch;

		const result = await resendCapturedRequest(event(), site, {});
		expect(result.status).toBe(302);
		expect(result.headers).toContainEqual(["location", "https://attacker.example/steal"]);
		expect(result.hops).toHaveLength(1);
		expect(result.hops[0]?.notFollowedReason).toBe("off-site");
	});

	test("preserves method and body on a same-path 308 per spec, hitting the redirect limit rather than guessing a different method", async () => {
		const calls: Array<{ method: string; body: unknown }> = [];
		globalThis.fetch = (async (_url: unknown, init: RequestInit) => {
			calls.push({ method: String(init.method), body: init.body });
			return new Response(null, { status: 308, headers: { location: `https://${site.public_host}/api/widgets` } });
		}) as typeof fetch;

		const result = await resendCapturedRequest(event({ method: "POST", request_body: "payload" }), site, {});
		expect(calls).toHaveLength(11);
		expect(calls.every((call) => call.method === "POST" && call.body === "payload")).toBe(true);
		expect(result.hops[10]?.notFollowedReason).toBe("redirect-limit");
		expect(result.status).toBe(308);
	});

	test("stops after the redirect limit on a genuinely non-terminating redirect chain, surfacing every hop", async () => {
		let calls = 0;
		globalThis.fetch = (async (url: unknown) => {
			calls += 1;
			const next = new URL(String(url)).pathname === "/a" ? "/b" : "/a";
			return new Response(null, { status: 307, headers: { location: `https://${site.public_host}${next}` } });
		}) as unknown as typeof fetch;

		const result = await resendCapturedRequest(event({ method: "GET" }), site, {});
		expect(calls).toBe(11);
		expect(result.hops).toHaveLength(11);
		expect(result.hops.slice(0, 10).every((hop) => hop.followed)).toBe(true);
		expect(result.hops[10]?.notFollowedReason).toBe("redirect-limit");
		expect(result.status).toBe(307);
	});

	test("converts to a bodyless GET when a same-site 303 redirects a POST", async () => {
		const calls: Array<{ method: string; body: unknown }> = [];
		globalThis.fetch = (async (_url: unknown, init: RequestInit) => {
			calls.push({ method: String(init.method), body: init.body });
			if (calls.length === 1) {
				return new Response(null, { status: 303, headers: { location: `https://${site.public_host}/api/v1/receipt` } });
			}
			return new Response("receipt", { status: 200 });
		}) as typeof fetch;

		await resendCapturedRequest(event({ method: "POST", request_body: "payload" }), site, {});
		expect(calls[1]?.method).toBe("GET");
		expect(calls[1]?.body).toBeNull();
	});
});
