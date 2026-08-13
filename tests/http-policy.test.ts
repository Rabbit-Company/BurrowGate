import { describe, expect, test } from "bun:test";
import type { RoutePolicyRecord, SiteRecord } from "../src/types.ts";
import {
	applyHeaderPolicy,
	isBodyCaptureActive,
	requestLimitViolation,
	resolveHttpPolicy,
	routeHttpPolicyView,
	serializeRouteHttpPolicy,
	serializeSiteHttpPolicy,
	siteHttpPolicyView,
	instanceBodyCaptureDefaults,
	instanceStaticCacheDefaults,
} from "../src/services/http-policy-service.ts";

function site(httpPolicy?: string | null): SiteRecord {
	return {
		id: "site_http_policy",
		name: "HTTP policy",
		public_host: "http.example.test",
		origin_url: "http://127.0.0.1:8080",
		origin_signing_secret: "test-signing-secret-that-is-at-least-32-characters",
		ip_extraction_preset: "direct",
		enabled: 1,
		session_ttl_seconds: 3_600,
		challenge_policy_json: "[]",
		default_access_mode: "bypass",
		event_retention_days: 7,
		default_ip_action: "inherit",
		default_country_action: "inherit",
		error_response_mode: "json",
		error_html_template: "",
		error_json_fields_json: "[]",
		challenge_html_template: "",
		http_policy_json: httpPolicy,
		created_at: 1,
		updated_at: 1,
	};
}

function route(httpPolicy?: string | null): RoutePolicyRecord {
	return {
		id: "route_http_policy",
		site_id: "site_http_policy",
		name: "Upload route",
		path_pattern: "/upload/**",
		methods_json: '["POST"]',
		access_mode: "inherit",
		challenge_policy_json: null,
		rate_limit_enabled: 0,
		rate_limit_algorithm: "sliding-window",
		rate_limit_window_ms: 60_000,
		rate_limit_max: 120,
		rate_limit_refill_rate: 10,
		rate_limit_refill_interval_ms: 1_000,
		rate_limit_precision_ms: 100,
		rate_limit_key_mode: "ip",
		rate_limit_key_header: null,
		rate_limit_scope: "policy",
		http_policy_json: httpPolicy,
		priority: 0,
		enabled: 1,
		created_at: 1,
		updated_at: 1,
	};
}

describe("HTTP header and request-limit policies", () => {
	test("defaults sites to no header changes and unlimited requests", () => {
		const { maxEntries: _maxEntries, maxBytes: _maxBytes, instanceMaxObjectBytes: _instanceMaxObjectBytes, ...cache } = instanceStaticCacheDefaults();
		const { instanceMaxBytesCeiling: _instanceMaxBytesCeiling, ...bodyCapture } = instanceBodyCaptureDefaults();
		expect(siteHttpPolicyView(site(null))).toEqual({
			requestHeaders: { set: [], remove: [] },
			responseHeaders: { set: [], remove: [] },
			limits: { maxBodyBytes: 0, maxRequestTargetBytes: 0, maxHeaderBytes: 0 },
			cache,
			protection: { mode: "monitor", rulesetId: "default", excludedRuleIds: [] },
			banDurations: { low: 0, medium: 600, high: 3_600, critical: 86_400 },
			bodyCapture,
		});
	});

	test("inherits managed protection while adding route exclusions", () => {
		const sitePolicy = serializeSiteHttpPolicy({ protection: { mode: "monitor", excludedRuleIds: ["BG-CORE-1001"] } });
		const routePolicy = serializeRouteHttpPolicy({ protection: { mode: "block", excludedRuleIds: ["BG-CORE-2002"] } });
		expect(resolveHttpPolicy(site(sitePolicy), route(routePolicy)).protection).toEqual({
			mode: "block",
			rulesetId: "default",
			excludedRuleIds: ["BG-CORE-1001", "BG-CORE-2002"],
		});
		expect(() => serializeSiteHttpPolicy({ protection: { mode: "enforce" } })).toThrow("Managed protection mode");
	});

	test("inherits cache defaults while allowing safe route overrides", () => {
		const sitePolicy = serializeSiteHttpPolicy({ cache: { mode: "enabled", ttlSeconds: 7_200, maxObjectBytes: 10_000, extensions: [".css", ".png"] } });
		const routePolicy = serializeRouteHttpPolicy({ cache: { mode: "enabled", ttlSeconds: 300, extensions: [".css"] } });
		const resolved = resolveHttpPolicy(site(sitePolicy), route(routePolicy));
		expect(resolved.cache).toEqual({ mode: "enabled", ttlSeconds: 300, maxObjectBytes: 10_000, extensions: [".css"] });
		expect(() => serializeSiteHttpPolicy({ cache: { mode: "enabled", extensions: ["css"] } })).toThrow("Invalid static cache extension");
	});

	test("inherits site limits and lets route rules take precedence", () => {
		const sitePolicy = serializeSiteHttpPolicy({
			requestHeaders: { set: [{ name: "x-application", value: "site" }], remove: ["x-remove"] },
			responseHeaders: { set: [{ name: "x-frame-options", value: "DENY" }], remove: [] },
			limits: { maxBodyBytes: 10_000, maxRequestTargetBytes: 2_048, maxHeaderBytes: 4_096 },
		});
		const routePolicy = serializeRouteHttpPolicy({
			requestHeaders: { set: [{ name: "X-Application", value: "route" }], remove: [] },
			responseHeaders: { set: [], remove: ["x-frame-options"] },
			limits: { maxBodyBytes: 2_000 },
		});
		const resolved = resolveHttpPolicy(site(sitePolicy), route(routePolicy));

		expect(resolved.requestHeaders).toEqual({ set: [{ name: "x-application", value: "route" }], remove: ["x-remove"] });
		expect(resolved.responseHeaders).toEqual({ set: [], remove: ["x-frame-options"] });
		expect(resolved.limits).toEqual({ maxBodyBytes: 2_000, maxRequestTargetBytes: 2_048, maxHeaderBytes: 4_096 });
	});

	test("keeps route limits nullable and supports an explicit unlimited override", () => {
		const policy = routeHttpPolicyView(route(serializeRouteHttpPolicy({ limits: { maxBodyBytes: 0 } })));
		expect(policy.limits).toEqual({ maxBodyBytes: 0, maxRequestTargetBytes: null, maxHeaderBytes: null });
	});

	test("preserves omitted fields during partial updates", () => {
		const existing = serializeSiteHttpPolicy({
			requestHeaders: { set: [{ name: "x-existing", value: "yes" }], remove: [] },
			limits: { maxBodyBytes: 100 },
		});
		const updated = serializeSiteHttpPolicy({ limits: { maxHeaderBytes: 200 } }, existing);
		const view = siteHttpPolicyView(site(updated));
		expect(view.requestHeaders.set).toEqual([{ name: "x-existing", value: "yes" }]);
		expect(view.limits).toEqual({ maxBodyBytes: 100, maxRequestTargetBytes: 0, maxHeaderBytes: 200 });
	});

	test("rejects changes to proxy-owned request headers", () => {
		expect(() => serializeSiteHttpPolicy({ requestHeaders: { set: [{ name: "X-Forwarded-For", value: "attacker" }], remove: [] } })).toThrow(
			"managed by BurrowGate",
		);
		expect(() => serializeRouteHttpPolicy({ requestHeaders: { set: [{ name: "X-BurrowGate-Verified", value: "true" }], remove: [] } })).toThrow(
			"managed by BurrowGate",
		);
	});

	test("applies set and remove operations", () => {
		const headers = new Headers({ "x-remove": "old", "x-keep": "yes" });
		applyHeaderPolicy(headers, { set: [{ name: "x-added", value: "new" }], remove: ["x-remove"] });
		expect(headers.get("x-added")).toBe("new");
		expect(headers.has("x-remove")).toBe(false);
		expect(headers.get("x-keep")).toBe("yes");
	});

	test("reports target, header, and declared body violations", () => {
		expect(requestLimitViolation(new Request("https://example.test/too-long"), { maxBodyBytes: 0, maxRequestTargetBytes: 4, maxHeaderBytes: 0 })?.status).toBe(
			414,
		);
		expect(
			requestLimitViolation(new Request("https://example.test/", { headers: { "x-large": "1234567890" } }), {
				maxBodyBytes: 0,
				maxRequestTargetBytes: 0,
				maxHeaderBytes: 8,
			})?.status,
		).toBe(431);
		expect(
			requestLimitViolation(new Request("https://example.test/upload", { method: "POST", headers: { "content-length": "101" } }), {
				maxBodyBytes: 100,
				maxRequestTargetBytes: 0,
				maxHeaderBytes: 0,
			})?.status,
		).toBe(413);
	});
});

describe("body capture policy", () => {
	test("defaults to disabled with low byte caps and no expiration", () => {
		const view = siteHttpPolicyView(site(null));
		expect(view.bodyCapture.mode).toBe("disabled");
		expect(view.bodyCapture.expiresAt).toBeNull();
		expect(view.bodyCapture.maxRequestBytes).toBeGreaterThan(0);
		expect(view.bodyCapture.maxResponseBytes).toBeGreaterThan(0);
	});

	test("lets a route enable capture and override sizes while inheriting others", () => {
		const sitePolicy = serializeSiteHttpPolicy({
			bodyCapture: { mode: "disabled", maxRequestBytes: 2_048, maxResponseBytes: 8_192, expiresAt: null },
		});
		const routePolicy = serializeRouteHttpPolicy({ bodyCapture: { mode: "enabled", maxRequestBytes: 512 } });
		const resolved = resolveHttpPolicy(site(sitePolicy), route(routePolicy));
		expect(resolved.bodyCapture.mode).toBe("enabled");
		expect(resolved.bodyCapture.maxRequestBytes).toBe(512);
		expect(resolved.bodyCapture.maxResponseBytes).toBe(8_192);
	});

	test("clamps configured sizes to the instance-wide ceiling", () => {
		const ceiling = instanceBodyCaptureDefaults().instanceMaxBytesCeiling;
		const sitePolicy = serializeSiteHttpPolicy({
			bodyCapture: { mode: "enabled", maxRequestBytes: ceiling, maxResponseBytes: ceiling, expiresAt: null },
		});
		const resolved = resolveHttpPolicy(site(sitePolicy));
		expect(resolved.bodyCapture.maxRequestBytes).toBeLessThanOrEqual(ceiling);
		expect(resolved.bodyCapture.maxResponseBytes).toBeLessThanOrEqual(ceiling);
	});

	test("route without an override inherits the site's expiration", () => {
		const expiresAt = Date.now() + 3_600_000;
		const sitePolicy = serializeSiteHttpPolicy({ bodyCapture: { mode: "enabled", expiresAt } });
		const resolved = resolveHttpPolicy(site(sitePolicy), route(serializeRouteHttpPolicy({})));
		expect(resolved.bodyCapture.expiresAt).toBe(expiresAt);
	});

	test("rejects an invalid mode", () => {
		expect(() => serializeSiteHttpPolicy({ bodyCapture: { mode: "sometimes" } })).toThrow("Body capture mode");
		expect(() => serializeRouteHttpPolicy({ bodyCapture: { mode: "sometimes" } })).toThrow("Body capture mode");
	});

	test("defaults content types to a broad text-based list and lets an admin narrow it to just JSON", () => {
		const view = siteHttpPolicyView(site(null));
		expect(view.bodyCapture.contentTypes).toContain("application/json");
		expect(view.bodyCapture.contentTypes).toContain("text/html");

		const narrowed = serializeSiteHttpPolicy({ bodyCapture: { contentTypes: "application/json" } });
		expect(siteHttpPolicyView(site(narrowed)).bodyCapture.contentTypes).toEqual(["application/json"]);
	});

	test("a route can narrow content types independently of the site while inheriting sizes", () => {
		const sitePolicy = serializeSiteHttpPolicy({ bodyCapture: { mode: "enabled", contentTypes: "application/json, text/plain" } });
		const routePolicy = serializeRouteHttpPolicy({ bodyCapture: { contentTypes: "application/json" } });
		const resolved = resolveHttpPolicy(site(sitePolicy), route(routePolicy));
		expect(resolved.bodyCapture.contentTypes).toEqual(["application/json"]);
	});

	test("a route without its own content types inherits the site's list", () => {
		const sitePolicy = serializeSiteHttpPolicy({ bodyCapture: { contentTypes: "application/json" } });
		const resolved = resolveHttpPolicy(site(sitePolicy), route(serializeRouteHttpPolicy({})));
		expect(resolved.bodyCapture.contentTypes).toEqual(["application/json"]);
	});

	test("accepts the * wildcard for any text-based content type", () => {
		const view = siteHttpPolicyView(site(serializeSiteHttpPolicy({ bodyCapture: { contentTypes: "*" } })));
		expect(view.bodyCapture.contentTypes).toEqual(["*"]);
	});

	test("rejects binary or malformed content types", () => {
		expect(() => serializeSiteHttpPolicy({ bodyCapture: { contentTypes: "image/png" } })).toThrow("text-based content types");
		expect(() => serializeSiteHttpPolicy({ bodyCapture: { contentTypes: "not-a-content-type" } })).toThrow("text-based content types");
	});
});

describe("isBodyCaptureActive", () => {
	test("is false when disabled even without an expiration", () => {
		expect(isBodyCaptureActive({ mode: "disabled", maxRequestBytes: 4_096, maxResponseBytes: 4_096, expiresAt: null, contentTypes: [] })).toBe(false);
	});

	test("is true when enabled with no expiration", () => {
		expect(isBodyCaptureActive({ mode: "enabled", maxRequestBytes: 4_096, maxResponseBytes: 4_096, expiresAt: null, contentTypes: [] })).toBe(true);
	});

	test("is true when enabled and the expiration is in the future", () => {
		expect(isBodyCaptureActive({ mode: "enabled", maxRequestBytes: 4_096, maxResponseBytes: 4_096, expiresAt: Date.now() + 60_000, contentTypes: [] })).toBe(
			true,
		);
	});

	test("is false once the expiration has passed", () => {
		expect(isBodyCaptureActive({ mode: "enabled", maxRequestBytes: 4_096, maxResponseBytes: 4_096, expiresAt: Date.now() - 1_000, contentTypes: [] })).toBe(
			false,
		);
	});
});
