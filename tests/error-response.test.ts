import { describe, expect, test } from "bun:test";
import { DEFAULT_ERROR_HTML_TEMPLATE, resolveRequestId, siteErrorResponse, validateErrorJsonFields } from "../src/services/error-response-service.ts";
import type { SiteRecord } from "../src/types.ts";

function site(overrides: Partial<SiteRecord> = {}): SiteRecord {
	return {
		id: "site-error-test",
		name: "Error test",
		public_host: "example.test",
		origin_url: "http://127.0.0.1:3000",
		origin_signing_secret: "test-signing-secret-that-is-at-least-32-characters",
		ip_extraction_preset: "direct",
		enabled: 1,
		session_ttl_seconds: 3_600,
		challenge_policy_json: "[]",
		challenge_html_template: "",
		challenge_auto_ban_enabled: 0,
		challenge_auto_ban_max_failures: 5,
		challenge_auto_ban_seconds: 3_600,
		default_access_mode: "challenge",
		event_retention_days: 7,
		default_ip_action: "inherit",
		default_country_action: "inherit",
		error_response_mode: "json",
		error_html_template: DEFAULT_ERROR_HTML_TEMPLATE,
		error_json_fields_json: JSON.stringify(["error", "code", "status", "reason"]),
		created_at: Date.now(),
		updated_at: Date.now(),
		...overrides,
	};
}

describe("custom site error responses", () => {
	test("returns only selected JSON fields", async () => {
		const response = siteErrorResponse(site(), new Request("https://example.test/private?item=1", { method: "POST" }), {
			status: 403,
			code: "route_blocked",
			error: "Blocked",
			reason: "Private route",
			clientIp: "203.0.113.20",
		});
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({
			error: "Blocked",
			code: "route_blocked",
			status: 403,
			reason: "Private route",
		});
	});

	test("escapes placeholder values in HTML templates", async () => {
		const response = siteErrorResponse(
			site({
				error_response_mode: "html",
				error_html_template: "<h1>{{error}}</h1><p>{{reason}}</p><code>{{requestId}}</code>",
			}),
			new Request("https://example.test/"),
			{
				status: 502,
				code: "origin_unavailable",
				error: "Origin <offline>",
				reason: '<script>alert("x")</script>',
				requestId: "request-1",
			},
		);
		const html = await response.text();
		expect(html).toContain("Origin &lt;offline&gt;");
		expect(html).toContain("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;");
		expect(html).not.toContain("<script>");
		expect(response.headers.get("x-burrowgate-request-id")).toBe("request-1");
	});

	test("requires at least one supported JSON field", () => {
		expect(() => validateErrorJsonFields([])).toThrow();
		expect(() => validateErrorJsonFields(["not-a-field"])).toThrow();
		expect(validateErrorJsonFields(["status", "status", "error"])).toEqual(["status", "error"]);
	});

	test("includes a generated requestId in the default JSON fields", async () => {
		const response = siteErrorResponse(
			site({ error_json_fields_json: JSON.stringify(["error", "code", "status", "requestId"]) }),
			new Request("https://example.test/"),
			{
				status: 403,
				code: "network_blocked",
				error: "Blocked",
			},
		);
		const body = (await response.json()) as { requestId?: string };
		expect(body.requestId).toBeTruthy();
		expect(response.headers.get("x-burrowgate-request-id")).toBe(body.requestId ?? null);
	});
});

describe("resolveRequestId", () => {
	test("never trusts a client-supplied x-burrowgate-request-id header", () => {
		const spoofed = new Request("https://example.test/", {
			headers: { "x-burrowgate-request-id": "attacker-controlled" },
		});
		const id = resolveRequestId(spoofed);
		expect(id).not.toBe("attacker-controlled");
		expect(id).not.toBe("also-attacker-controlled");
	});

	test("returns the same ID for repeated calls on the same request", () => {
		const request = new Request("https://example.test/");
		expect(resolveRequestId(request)).toBe(resolveRequestId(request));
	});

	test("returns a different ID for a different request", () => {
		const first = resolveRequestId(new Request("https://example.test/a"));
		const second = resolveRequestId(new Request("https://example.test/b"));
		expect(first).not.toBe(second);
	});

	test("caps an explicitly supplied ID at 128 characters", () => {
		const request = new Request("https://example.test/");
		const id = resolveRequestId(request, "x".repeat(500));
		expect(id.length).toBe(128);
	});
});
