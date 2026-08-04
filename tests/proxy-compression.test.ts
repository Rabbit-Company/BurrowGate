import { afterAll, describe, expect, test } from "bun:test";
import { proxyRequest } from "../src/services/proxy-service.ts";
import type { SiteRecord } from "../src/types.ts";

const plainBody = new TextEncoder().encode("Compressed reverse-proxy response from a qBittorrent or Sonarr-like origin.");
const compressedBody = Bun.gzipSync(plainBody);

const origin = Bun.serve({
	hostname: "127.0.0.1",
	port: 0,
	fetch() {
		return new Response(compressedBody, {
			headers: {
				"content-type": "text/plain; charset=utf-8",
				"content-encoding": "gzip",
				"content-length": String(compressedBody.byteLength),
			},
		});
	},
});

afterAll(() => origin.stop(true));

const site: SiteRecord = {
	id: "site-test",
	name: "Compression test",
	public_host: "proxy.test",
	origin_url: `http://127.0.0.1:${origin.port}`,
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

describe("reverse-proxy compression", () => {
	test("preserves compressed bytes and representation headers", async () => {
		const response = await proxyRequest(
			new Request("http://proxy.test/", {
				headers: { "accept-encoding": "gzip" },
			}),
			site,
			"127.0.0.1",
			null,
		);

		expect(response.status).toBe(200);
		expect(response.headers.get("content-encoding")).toBe("gzip");
		expect(response.headers.get("content-length")).toBe(String(compressedBody.byteLength));
		expect(new Uint8Array(await response.arrayBuffer())).toEqual(compressedBody);
	});
});
