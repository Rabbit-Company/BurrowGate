import { describe, expect, test } from "bun:test";
import { DEFAULT_ERROR_HTML_TEMPLATE, siteErrorResponse, validateErrorJsonFields } from "../src/services/error-response-service.ts";
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
		expect(response.headers.get("x-request-id")).toBe("request-1");
	});

	test("requires at least one supported JSON field", () => {
		expect(() => validateErrorJsonFields([])).toThrow();
		expect(() => validateErrorJsonFields(["not-a-field"])).toThrow();
		expect(validateErrorJsonFields(["status", "status", "error"])).toEqual(["status", "error"]);
	});
});
