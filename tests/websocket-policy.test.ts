import { describe, expect, test } from "bun:test";
import type { RoutePolicyRecord, SiteRecord } from "../src/types.ts";
import {
	instanceWebSocketDefaults,
	resolveWebSocketPolicy,
	routeWebSocketPolicyView,
	serializeRouteWebSocketPolicy,
	serializeSiteWebSocketPolicy,
	siteWebSocketPolicyView,
} from "../src/services/websocket-policy-service.ts";

function site(websocketPolicy?: string | null): SiteRecord {
	return {
		id: "site_websocket_policy",
		name: "WebSocket policy",
		public_host: "socket.example.test",
		origin_url: "http://127.0.0.1:8096",
		origin_signing_secret: "test-signing-secret-that-is-at-least-32-characters",
		ip_extraction_preset: "direct",
		enabled: 1,
		session_ttl_seconds: 3_600,
		challenge_policy_json: "[]",
		challenge_auto_ban_enabled: 0,
		challenge_auto_ban_max_failures: 5,
		challenge_auto_ban_seconds: 3_600,
		default_access_mode: "bypass",
		event_retention_days: 7,
		default_ip_action: "inherit",
		default_country_action: "inherit",
		error_response_mode: "json",
		error_html_template: "",
		error_json_fields_json: "[]",
		challenge_html_template: "",
		websocket_policy_json: websocketPolicy,
		created_at: 1,
		updated_at: 1,
	};
}

function route(websocketPolicy?: string | null): RoutePolicyRecord {
	return {
		id: "route_websocket_policy",
		site_id: "site_websocket_policy",
		name: "Socket route",
		path_pattern: "/socket/**",
		methods_json: '["GET"]',
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
		websocket_policy_json: websocketPolicy,
		priority: 0,
		enabled: 1,
		created_at: 1,
		updated_at: 1,
	};
}

describe("WebSocket transport policies", () => {
	test("uses the instance limits for a site with no stored overrides", () => {
		const defaults = instanceWebSocketDefaults();
		expect(siteWebSocketPolicyView(site(null))).toEqual(defaults);
	});

	test("resolves route mode and limits over the site defaults", () => {
		const sitePolicy = serializeSiteWebSocketPolicy({
			mode: "deny",
			connectTimeoutMs: 2_000,
			idleTimeoutSeconds: 10,
			maxPayloadBytes: 2_048,
			preOpenQueueBytes: 1_024,
			upstreamBufferBytes: 4_096,
		});
		const routePolicy = serializeRouteWebSocketPolicy({ mode: "allow", maxPayloadBytes: 1_024 });
		const resolved = resolveWebSocketPolicy(site(sitePolicy), route(routePolicy));

		expect(resolved.mode).toBe(instanceWebSocketDefaults().available ? "allow" : "deny");
		expect(resolved.connectTimeoutMs).toBe(2_000);
		expect(resolved.maxPayloadBytes).toBe(1_024);
		expect(resolved.upstreamBufferBytes).toBe(4_096);
	});

	test("keeps route limits nullable when they inherit", () => {
		expect(routeWebSocketPolicyView(route(serializeRouteWebSocketPolicy({ mode: "inherit" })))).toEqual({
			mode: "inherit",
			connectTimeoutMs: null,
			idleTimeoutSeconds: null,
			maxPayloadBytes: null,
			preOpenQueueBytes: null,
			upstreamBufferBytes: null,
		});
	});

	test("removes an existing route override when the field is cleared", () => {
		const existing = serializeRouteWebSocketPolicy({ mode: "allow", maxPayloadBytes: 2_048 });
		const updated = serializeRouteWebSocketPolicy({ maxPayloadBytes: null }, existing);
		expect(routeWebSocketPolicyView(route(updated)).maxPayloadBytes).toBeNull();
	});

	test("rejects values above the instance safety ceiling", () => {
		const defaults = instanceWebSocketDefaults();
		expect(() => serializeSiteWebSocketPolicy({ maxPayloadBytes: defaults.maxPayloadBytes + 1 })).toThrow("WebSocket maximum payload");
	});
});
