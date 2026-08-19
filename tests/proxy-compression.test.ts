import { afterAll, describe, expect, test } from "bun:test";
import { proxyRequest, RequestBodyTooLargeError } from "../src/services/proxy-service.ts";
import type { ResolvedHttpPolicy } from "../src/services/http-policy-service.ts";
import type { SiteRecord } from "../src/types.ts";

const plainBody = new TextEncoder().encode("Compressed reverse-proxy response from a qBittorrent or Sonarr-like origin.");
const compressedBody = Bun.gzipSync(plainBody);
let receivedHost: string | null = null;
let receivedContentLength: string | null = null;
let receivedTransferEncoding: string | null = null;
let receivedRequestBody: string | null = null;
let receivedPolicyHeader: string | null = null;
let receivedRemovedHeader: string | null = null;

const origin = Bun.serve({
	hostname: "127.0.0.1",
	port: 0,
	async fetch(request) {
		receivedHost = request.headers.get("host");
		if (new URL(request.url).pathname === "/redirect-test") {
			return new Response(null, { status: 302, headers: { location: "/web/" } });
		}
		if (new URL(request.url).pathname === "/form-test") {
			receivedContentLength = request.headers.get("content-length");
			receivedTransferEncoding = request.headers.get("transfer-encoding");
			receivedRequestBody = await request.text();
			return new Response("ok");
		}
		if (new URL(request.url).pathname === "/header-policy") {
			receivedPolicyHeader = request.headers.get("x-policy");
			receivedRemovedHeader = request.headers.get("x-remove-me");
			return new Response("headers", { headers: { "x-origin-remove": "yes", "x-origin-keep": "yes" } });
		}
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

const headerPolicy: ResolvedHttpPolicy = {
	requestHeaders: { set: [{ name: "x-policy", value: "route" }], remove: ["x-remove-me"] },
	responseHeaders: { set: [{ name: "content-security-policy", value: "default-src 'self'" }], remove: ["x-origin-remove"] },
	limits: { maxBodyBytes: 0, maxRequestTargetBytes: 0, maxHeaderBytes: 0 },
	cache: { mode: "disabled", ttlSeconds: 3_600, maxObjectBytes: 5_242_880, extensions: [".css"] },
	protection: { mode: "disabled", rulesetId: "default", excludedRuleIds: [] },
	banDurations: { low: 0, medium: 600, high: 3_600, critical: 86_400 },
	bandwidthLimit: { enabled: false, maxBytes: 50 * 1_024 * 1_024, windowSeconds: 60, banSeconds: 3_600, scopeId: "site-test" },
	bodyCapture: { mode: "disabled", maxRequestBytes: 4_096, maxResponseBytes: 4_096, expiresAt: null, contentTypes: ["*"] },
	headerCapture: { mode: "disabled", redactAuthHeaders: true, redactedHeaders: [], expiresAt: null },
};

describe("reverse-proxy compression", () => {
	test("preserves compressed bytes and representation headers", async () => {
		const { response } = await proxyRequest(
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
		expect(receivedHost).toBe("proxy.test");
	});

	test("does not leak the origin port into relative redirects", async () => {
		const { response } = await proxyRequest(new Request("https://proxy.test/redirect-test"), site, "127.0.0.1", null);

		expect(response.status).toBe(302);
		expect(response.headers.get("location")).toBe("https://proxy.test/web/");
	});

	test("preserves fixed-length request bodies without chunked framing", async () => {
		const body = "username=admin&password=correct";
		const { response } = await proxyRequest(
			new Request("http://proxy.test/form-test", {
				method: "POST",
				headers: {
					"content-type": "application/x-www-form-urlencoded;charset=UTF-8",
					"content-length": String(Buffer.byteLength(body)),
				},
				body,
			}),
			site,
			"127.0.0.1",
			null,
		);

		expect(response.status).toBe(200);
		expect(receivedContentLength).toBe(String(Buffer.byteLength(body)));
		expect(receivedTransferEncoding).toBeNull();
		expect(receivedRequestBody).toBe(body);
	});

	test("derives the upstream length from the buffered request bytes", async () => {
		const body = "action=pause&hashes=all";
		const { response } = await proxyRequest(
			new Request("http://proxy.test/form-test", {
				method: "POST",
				headers: {
					"content-type": "application/x-www-form-urlencoded",
					"content-length": String(Buffer.byteLength(body) + 1),
				},
				body,
			}),
			site,
			"127.0.0.1",
			null,
		);

		expect(response.status).toBe(200);
		expect(receivedContentLength).toBe(String(Buffer.byteLength(body)));
		expect(receivedTransferEncoding).toBeNull();
		expect(receivedRequestBody).toBe(body);
	});

	test("applies request and response header policies at the origin boundary", async () => {
		const { response } = await proxyRequest(
			new Request("http://proxy.test/header-policy", { headers: { "x-remove-me": "client" } }),
			site,
			"127.0.0.1",
			null,
			undefined,
			null,
			false,
			null,
			site.origin_url,
			headerPolicy,
		);

		expect(response.status).toBe(200);
		expect(receivedPolicyHeader).toBe("route");
		expect(receivedRemovedHeader).toBeNull();
		expect(response.headers.get("content-security-policy")).toBe("default-src 'self'");
		expect(response.headers.has("x-origin-remove")).toBe(false);
		expect(response.headers.get("x-origin-keep")).toBe("yes");
	});

	test("enforces the body limit when content length is unavailable", async () => {
		const limitedPolicy: ResolvedHttpPolicy = { ...headerPolicy, limits: { ...headerPolicy.limits, maxBodyBytes: 4 } };
		const request = new Request("http://proxy.test/form-test", { method: "POST", body: "12345" });
		expect(request.headers.has("content-length")).toBe(false);

		await expect(proxyRequest(request, site, "127.0.0.1", null, undefined, null, false, null, site.origin_url, limitedPolicy)).rejects.toBeInstanceOf(
			RequestBodyTooLargeError,
		);
	});

	test("writes fixed-length request framing on the upstream connection", async () => {
		let resolveWireRequest!: (value: string) => void;
		let proxy: ReturnType<typeof Bun.serve> | null = null;
		const wireRequest = new Promise<string>((resolve) => {
			resolveWireRequest = resolve;
		});
		const rawOrigin = Bun.listen<{ bytes: Buffer; complete: boolean }>({
			hostname: "127.0.0.1",
			port: 0,
			socket: {
				open(socket) {
					socket.data = { bytes: Buffer.alloc(0), complete: false };
				},
				data(socket, chunk) {
					socket.data.bytes = Buffer.concat([socket.data.bytes, chunk]);
					const headerEnd = socket.data.bytes.indexOf("\r\n\r\n");
					if (headerEnd < 0 || socket.data.complete) return;

					const head = socket.data.bytes.subarray(0, headerEnd).toString("latin1");
					const contentLength = Number(/^content-length:\s*(\d+)\s*$/imu.exec(head)?.[1] ?? "0");
					const isChunked = /^transfer-encoding:\s*chunked\s*$/imu.test(head);
					const bodyBytes = socket.data.bytes.length - (headerEnd + 4);
					const hasCompleteBody = isChunked ? socket.data.bytes.subarray(headerEnd + 4).includes(Buffer.from("\r\n0\r\n\r\n")) : bodyBytes >= contentLength;
					if (!hasCompleteBody) return;

					socket.data.complete = true;
					resolveWireRequest(socket.data.bytes.toString("latin1"));
					socket.end("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
				},
			},
		});

		try {
			const body = "username=admin&password=correct";
			const rawSite = { ...site, origin_url: `http://127.0.0.1:${rawOrigin.port}` };
			proxy = Bun.serve({
				hostname: "127.0.0.1",
				port: 0,
				fetch: async (request) => (await proxyRequest(request, rawSite, "127.0.0.1", null)).response,
			});
			const response = await fetch(`http://127.0.0.1:${proxy.port}/form-test`, {
				method: "POST",
				headers: {
					"content-type": "application/x-www-form-urlencoded;charset=UTF-8",
					"content-length": String(Buffer.byteLength(body)),
				},
				body,
			});
			expect(await response.text()).toBe("ok");

			const raw = await wireRequest;
			const [head = "", receivedBody] = raw.split("\r\n\r\n", 2);
			expect(head.toLowerCase()).toContain(`content-length: ${Buffer.byteLength(body)}`);
			expect(head.toLowerCase()).not.toContain("transfer-encoding: chunked");
			expect(receivedBody).toBe(body);
		} finally {
			proxy?.stop(true);
			rawOrigin.stop(true);
		}
	});
});
