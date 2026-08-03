import { describe, expect, test } from "bun:test";
import type { RoutePolicyRecord } from "../src/types.ts";
import { parseRouteMethods, pathPatternMatches, routePolicyMatches } from "../src/services/route-policy-service.ts";
import { applyRouteRateLimit, invalidateRouteRateLimiter } from "../src/services/rate-limit-service.ts";

function policy(overrides: Partial<RoutePolicyRecord> = {}): RoutePolicyRecord {
	const now = Date.now();
	return {
		id: `route_${crypto.randomUUID()}`,
		site_id: "site_test",
		name: "API",
		path_pattern: "/api/**",
		methods_json: "[]",
		access_mode: "bypass",
		challenge_policy_json: null,
		rate_limit_enabled: 1,
		rate_limit_algorithm: "sliding-window",
		rate_limit_window_ms: 60_000,
		rate_limit_max: 2,
		rate_limit_refill_rate: 1,
		rate_limit_refill_interval_ms: 1_000,
		rate_limit_precision_ms: 100,
		rate_limit_key_mode: "ip",
		rate_limit_key_header: null,
		rate_limit_scope: "policy",
		priority: 0,
		enabled: 1,
		created_at: now,
		updated_at: now,
		...overrides,
	};
}

describe("route policy matching", () => {
	test("double-star matches nested paths", () => {
		expect(pathPatternMatches("/api/**", "/api")).toBe(true);
		expect(pathPatternMatches("/api/**", "/api/v1/users/42")).toBe(true);
		expect(pathPatternMatches("/api/**", "/other/v1/users")).toBe(false);
	});

	test("single-star does not cross a slash", () => {
		expect(pathPatternMatches("/api/*", "/api/users")).toBe(true);
		expect(pathPatternMatches("/api/*", "/api/v1/users")).toBe(false);
	});

	test("method restrictions are case-insensitive", () => {
		const value = policy({ methods_json: JSON.stringify(["GET", "POST"]) });
		expect(routePolicyMatches(value, "get", "/api/users")).toBe(true);
		expect(routePolicyMatches(value, "DELETE", "/api/users")).toBe(false);
	});

	test("blank or wildcard methods mean all methods", () => {
		expect(parseRouteMethods("")).toEqual([]);
		expect(parseRouteMethods("*")).toEqual([]);
		expect(parseRouteMethods("get, POST")).toEqual(["GET", "POST"]);
	});
});

describe("route rate limiting", () => {
	test("returns 429 after the configured limit", async () => {
		const value = policy();
		const request = new Request("https://example.com/api/items");
		try {
			expect((await applyRouteRateLimit(value, request, "203.0.113.10", null)).limited).toBe(false);
			expect((await applyRouteRateLimit(value, request, "203.0.113.10", null)).limited).toBe(false);
			const limited = await applyRouteRateLimit(value, request, "203.0.113.10", null);
			expect(limited.limited).toBe(true);
			expect(limited.response?.status).toBe(429);
			expect(limited.response?.headers.get("retry-after")).not.toBeNull();
		} finally {
			invalidateRouteRateLimiter(value.id);
		}
	});
});
