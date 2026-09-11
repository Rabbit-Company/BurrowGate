import { describe, expect, test } from "bun:test";
import { verifyOriginRequest } from "../packages/burrowgate-auth/src/mod.ts";
import { resolveRequestId } from "../src/services/error-response-service.ts";
import { upstreamHeaders, upstreamUrlForOrigin } from "../src/services/proxy-service.ts";
import { websocketUpstreamHeaders, websocketUpstreamUrl } from "../src/services/websocket-proxy-service.ts";
import type { AccessSessionRecord, SiteRecord } from "../src/types.ts";

const site = {
	id: "site-proxy-headers",
	origin_signing_secret: "proxy-header-secret-that-is-at-least-32-characters",
} as SiteRecord;

describe("reverse-proxy authority headers", () => {
	test("preserves the public HTTPS authority for Jellyfin-style redirects", async () => {
		const headers = await upstreamHeaders(
			new Request("https://example.com/", {
				headers: {
					host: "example.com",
					forwarded: "for=198.51.100.99;host=attacker.test;proto=http",
					"x-forwarded-host": "attacker.test:8097",
					"x-forwarded-port": "8097",
					"x-forwarded-proto": "http",
					"x-real-ip": "198.51.100.99",
				},
			}),
			site,
			"203.0.113.7",
			null,
			"allowlisted",
			"https",
		);

		expect(headers.get("host")).toBe("example.com");
		expect(headers.get("x-forwarded-host")).toBe("example.com");
		expect(headers.get("x-forwarded-port")).toBe("443");
		expect(headers.get("x-forwarded-proto")).toBe("https");
		expect(headers.get("x-forwarded-protocol")).toBe("https");
		expect(headers.get("x-forwarded-for")).toBe("203.0.113.7");
		expect(headers.get("x-real-ip")).toBe("203.0.113.7");
		expect(headers.has("forwarded")).toBe(false);
	});

	test("keeps an explicit public port", async () => {
		const headers = await upstreamHeaders(new Request("https://example.com:8443/web/"), site, "203.0.113.8", null, "allowlisted", "https");

		expect(headers.get("host")).toBe("example.com:8443");
		expect(headers.get("x-forwarded-host")).toBe("example.com:8443");
		expect(headers.get("x-forwarded-port")).toBe("8443");
	});

	test("forwards BurrowGate's own request ID upstream and ignores a client-supplied one", async () => {
		const request = new Request("https://example.com/", {
			headers: { host: "example.com", "x-burrowgate-request-id": "attacker-controlled" },
		});
		const expectedId = resolveRequestId(request);

		const headers = await upstreamHeaders(request, site, "203.0.113.9", null, "allowlisted", "https");

		expect(headers.get("x-burrowgate-request-id")).toBe(expectedId);
		expect(headers.get("x-burrowgate-request-id")).not.toBe("attacker-controlled");
	});

	test("never forwards BurrowGate API credentials while preserving application bearer tokens", async () => {
		for (const authorization of ["Bearer bgat_secret", "Bearer bgro_secret", "Burrow access-secret"]) {
			const headers = await upstreamHeaders(new Request("https://example.com/", { headers: { authorization } }), site, "203.0.113.10", null);
			expect(headers.has("authorization")).toBe(false);
		}

		const application = await upstreamHeaders(
			new Request("https://example.com/", { headers: { authorization: "Bearer application-secret" } }),
			site,
			"203.0.113.10",
			null,
		);
		expect(application.get("authorization")).toBe("Bearer application-secret");
	});
});

describe("origin request signature", () => {
	const session = { id: "sess_signed" } as AccessSessionRecord;

	/** Replays the upstream request the way the origin receives it. */
	function originRequest(target: URL, headers: Headers, method = "GET"): Request {
		const url = new URL(target);
		if (url.protocol === "ws:") url.protocol = "http:";
		else if (url.protocol === "wss:") url.protocol = "https:";
		return new Request(url.href, { method, headers });
	}

	for (const originUrl of ["http://app.internal:3000", "http://app.internal:3000/", "http://app.internal:3000/api", "http://app.internal:3000/api/"]) {
		test(`verifies at an origin configured as ${originUrl}`, async () => {
			const request = new Request("https://example.com/items/42?sort=desc", { method: "POST" });
			const target = upstreamUrlForOrigin(originUrl, request);
			const headers = await upstreamHeaders(request, site, "203.0.113.20", session, "verified", "https", "ziga", true, "SI", target);

			const result = await verifyOriginRequest(originRequest(target, headers, "POST"), site.origin_signing_secret);

			expect(result).toMatchObject({ valid: true, clientIp: "203.0.113.20", country: "SI", sessionId: "sess_signed", authenticatedUser: "ziga" });
		});
	}

	test("signs the path the origin receives, including the origin path prefix", async () => {
		const request = new Request("https://example.com/items?page=2");
		const target = upstreamUrlForOrigin("http://app.internal:3000/api", request);
		const headers = await upstreamHeaders(request, site, "203.0.113.21", null, "allowlisted", "https", null, false, null, target);

		expect(target.pathname + target.search).toBe("/api/items?page=2");
		expect((await verifyOriginRequest(originRequest(target, headers), site.origin_signing_secret)).valid).toBe(true);
		// The unprefixed public path must no longer verify
		const publicPath = await verifyOriginRequest(new Request("http://app.internal:3000/items?page=2", { headers }), site.origin_signing_secret);
		expect(publicPath).toEqual({ valid: false, reason: "invalid-signature" });
	});

	test("defaults to the incoming path when no target is supplied", async () => {
		const request = new Request("https://example.com/items?page=2");
		const headers = await upstreamHeaders(request, site, "203.0.113.22", null);

		const result = await verifyOriginRequest(new Request("http://app.internal:3000/items?page=2", { headers }), site.origin_signing_secret);

		expect(result.valid).toBe(true);
	});

	test("signs WebSocket upgrades for the prefixed origin path", async () => {
		const wsSite = { ...site, origin_url: "http://app.internal:3000/realtime" } as SiteRecord;
		const request = new Request("https://example.com/socket?room=1", { headers: { connection: "Upgrade", upgrade: "websocket" } });
		const target = websocketUpstreamUrl(wsSite, request);
		const headers = await websocketUpstreamHeaders(request, wsSite, "203.0.113.23", session, "verified", "https", "ziga", true, "DE", target);

		expect(target.href).toBe("ws://app.internal:3000/realtime/socket?room=1");
		const result = await verifyOriginRequest(originRequest(target, headers), wsSite.origin_signing_secret);
		expect(result).toMatchObject({ valid: true, authenticatedUser: "ziga", country: "DE" });
	});
});
