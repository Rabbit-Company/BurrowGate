import { describe, expect, test } from "bun:test";
import {
	isWebSocketUpgrade,
	offeredWebSocketProtocols,
	selectedProtocolHeaders,
	websocketUpstreamHeaders,
	websocketUpstreamUrl,
} from "../src/services/websocket-proxy-service.ts";
import type { AccessSessionRecord, SiteRecord } from "../src/types.ts";
import { hmacSha256Hex } from "../src/utils/crypto.ts";

const site: SiteRecord = {
	id: "site-websocket-test",
	name: "WebSocket test",
	public_host: "socket.example.test",
	origin_url: "https://origin.example.test/base",
	origin_signing_secret: "test-signing-secret-that-is-at-least-32-characters",
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

const accessSession: AccessSessionRecord = {
	id: "sess_identity_test",
	site_id: site.id,
	token_hash: "hash",
	initial_ip: "203.0.113.8",
	last_ip: "203.0.113.8",
	user_agent_hash: "user-agent-hash",
	created_at: Date.now(),
	last_seen_at: Date.now(),
	expires_at: Date.now() + 3_600_000,
	revoked_at: null,
	verification_summary_json: "{}",
	request_count: 1,
	country_code: "US",
	access_user_id: "user_ziga",
	authenticated_at: Date.now(),
};

describe("WebSocket reverse proxy", () => {
	test("recognizes valid WebSocket upgrade requests", () => {
		expect(
			isWebSocketUpgrade(
				new Request("https://socket.example.test/ws", {
					headers: { connection: "keep-alive, Upgrade", upgrade: "websocket" },
				}),
			),
		).toBe(true);
		expect(isWebSocketUpgrade(new Request("https://socket.example.test/ws"))).toBe(false);
	});

	test("parses and preserves offered subprotocol order", () => {
		const request = new Request("https://socket.example.test/ws", {
			headers: { "sec-websocket-protocol": " graphql-ws, graphql-transport-ws " },
		});
		expect(offeredWebSocketProtocols(request)).toEqual(["graphql-ws", "graphql-transport-ws"]);
		expect(offeredWebSocketProtocols(new Request("https://socket.example.test/ws"))).toEqual([]);
	});

	test("returns the upstream-selected subprotocol in upgrade headers", () => {
		const headers = selectedProtocolHeaders({ protocol: "graphql-transport-ws" });
		expect(new Headers(headers).get("sec-websocket-protocol")).toBe("graphql-transport-ws");
		expect(selectedProtocolHeaders({ protocol: "" })).toBeUndefined();
	});

	test("maps HTTPS origins to WSS and preserves paths", () => {
		const target = websocketUpstreamUrl(site, new Request("https://socket.example.test/api/ws?token=1"));
		expect(target.toString()).toBe("wss://origin.example.test/base/api/ws?token=1");
	});

	test("maps HTTP origins to WS", () => {
		const httpSite = { ...site, origin_url: "http://127.0.0.1:8989" };
		const target = websocketUpstreamUrl(httpSite, new Request("https://socket.example.test/signalr/messages?id=1"));
		expect(target.toString()).toBe("ws://127.0.0.1:8989/signalr/messages?id=1");
	});

	test("creates a fresh upstream handshake without leaking edge credentials", async () => {
		const headers = await websocketUpstreamHeaders(
			new Request("https://socket.example.test/ws", {
				headers: {
					connection: "Upgrade",
					upgrade: "websocket",
					cookie: "application=value; bg_session=edge-secret",
					authorization: "Burrow edge-header-token",
					"x-burrow-token": "edge-token",
					"sec-websocket-key": "downstream-key",
					"sec-websocket-version": "13",
					"sec-websocket-extensions": "permessage-deflate",
					"sec-websocket-protocol": "graphql-ws, graphql-transport-ws",
				},
			}),
			site,
			"203.0.113.7",
			null,
		);

		expect(headers.get("cookie")).toBe("application=value");
		expect(headers.has("authorization")).toBe(false);
		expect(headers.has("x-burrow-token")).toBe(false);
		expect(headers.has("sec-websocket-key")).toBe(false);
		expect(headers.has("sec-websocket-version")).toBe(false);
		expect(headers.has("sec-websocket-extensions")).toBe(false);
		expect(headers.get("sec-websocket-protocol")).toBe("graphql-ws, graphql-transport-ws");
		expect(headers.get("x-forwarded-for")).toBe("203.0.113.7");
		expect(headers.get("x-forwarded-proto")).toBe("https");
		expect(headers.get("x-burrowgate-verified")).toBe("true");
	});

	test("preserves application authorization and replaces spoofed identity assertions", async () => {
		const request = new Request("https://socket.example.test/ws?room=1", {
			headers: {
				connection: "Upgrade",
				upgrade: "websocket",
				authorization: "Bearer application-token",
				cookie: "application=value; bg_authenticated_user=mallory; bg_identity_signature=spoofed",
				"x-burrowgate-authenticated-user": "mallory",
				"x-burrowgate-identity-signature": "spoofed",
			},
		});
		const headers = await websocketUpstreamHeaders(request, site, "203.0.113.8", accessSession, "verified", "https", "ziga", true);

		expect(headers.get("authorization")).toBe("Bearer application-token");
		expect(headers.get("cookie")).toContain("application=value");
		expect(headers.get("cookie")).toContain("bg_authenticated_user=ziga");
		expect(headers.get("cookie")).not.toContain("mallory");
		const cookieCanonical = ["identity-cookie-v1", site.id, accessSession.id, "ziga"].join("\n");
		expect(headers.get("cookie")).toContain(`bg_identity_signature=${await hmacSha256Hex(site.origin_signing_secret, cookieCanonical)}`);
		expect(headers.get("x-burrowgate-authenticated-user")).toBe("ziga");
		const timestamp = headers.get("x-burrowgate-timestamp")!;
		const canonical = ["GET", "/ws?room=1", accessSession.id, "203.0.113.8", timestamp, "ziga"].join("\n");
		expect(headers.get("x-burrowgate-identity-signature")).toBe(await hmacSha256Hex(site.origin_signing_secret, canonical));
	});

	test("strips client identity assertions when username forwarding is disabled", async () => {
		const headers = await websocketUpstreamHeaders(
			new Request("https://socket.example.test/ws", {
				headers: { connection: "Upgrade", upgrade: "websocket", "x-burrowgate-authenticated-user": "mallory" },
			}),
			site,
			"203.0.113.9",
			null,
		);

		expect(headers.has("x-burrowgate-authenticated-user")).toBe(false);
		expect(headers.has("x-burrowgate-identity-signature")).toBe(false);
	});
});
