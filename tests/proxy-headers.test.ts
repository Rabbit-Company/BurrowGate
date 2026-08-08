import { describe, expect, test } from "bun:test";
import { resolveRequestId } from "../src/services/error-response-service.ts";
import { upstreamHeaders } from "../src/services/proxy-service.ts";
import type { SiteRecord } from "../src/types.ts";

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
		const request = new Request("https://example.com/", { headers: { host: "example.com", "x-request-id": "attacker-controlled" } });
		const expectedId = resolveRequestId(request);

		const headers = await upstreamHeaders(request, site, "203.0.113.9", null, "allowlisted", "https");

		expect(headers.get("x-request-id")).toBe(expectedId);
		expect(headers.get("x-request-id")).not.toBe("attacker-controlled");
	});
});
