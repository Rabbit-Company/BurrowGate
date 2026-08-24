import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { resolveHttpPolicy } from "../src/services/http-policy-service.ts";
import { serveStaticOrigin } from "../src/services/static-origin-service.ts";
import type { SiteOriginRecord, SiteRecord } from "../src/types.ts";

let root: string;

beforeAll(async () => {
	root = await mkdtemp(join(tmpdir(), "burrowgate-static-test-"));
	await writeFile(join(root, "index.html"), "<html>home</html>");
	await writeFile(join(root, "range.txt"), "hello range bytes");
	await mkdir(join(root, "sub"));
	await writeFile(join(root, "sub", "index.html"), "<html>sub</html>");
	await mkdir(join(root, "secret-sibling-marker"));
	await writeFile(join(root, "report.html"), "<html>report</html>");
	await mkdir(join(root, "nested"));
	await writeFile(join(root, "nested", "page.html"), "<html>nested page</html>");
});

afterAll(async () => {
	await rm(root, { recursive: true, force: true });
});

const site = {
	id: "site-static-test",
	error_response_mode: "json",
} as SiteRecord;

function makeOrigin(overrides: Partial<SiteOriginRecord> = {}): SiteOriginRecord {
	return {
		id: "origin-static-test",
		site_id: site.id,
		name: "static",
		origin_type: "static",
		origin_url: root,
		static_index_file: "index.html",
		static_spa_fallback: 0,
		enabled: 1,
		draining: 0,
		priority: 0,
		weight: 1,
		health_check_path: null,
		is_primary: 0,
		mtls_enabled: 0,
		mtls_certificate_pem: null,
		mtls_encrypted_private_key: null,
		mtls_ca_pem: null,
		created_at: 1,
		updated_at: 1,
		...overrides,
	};
}

const httpPolicy = resolveHttpPolicy(site);

describe("serveStaticOrigin", () => {
	test("serves the index file for the site root", async () => {
		const response = await serveStaticOrigin(new Request("https://example.com/"), site, makeOrigin(), "203.0.113.1", null, httpPolicy);
		expect(response.status).toBe(200);
		expect(await response.text()).toBe("<html>home</html>");
	});

	test("serves a directory's index file", async () => {
		const response = await serveStaticOrigin(new Request("https://example.com/sub/"), site, makeOrigin(), "203.0.113.1", null, httpPolicy);
		expect(response.status).toBe(200);
		expect(await response.text()).toBe("<html>sub</html>");
	});

	test("serves a clean URL by appending .html", async () => {
		const response = await serveStaticOrigin(new Request("https://example.com/report"), site, makeOrigin(), "203.0.113.1", null, httpPolicy);
		expect(response.status).toBe(200);
		expect(await response.text()).toBe("<html>report</html>");
	});

	test("serves a nested clean URL by appending .html", async () => {
		const response = await serveStaticOrigin(new Request("https://example.com/nested/page"), site, makeOrigin(), "203.0.113.1", null, httpPolicy);
		expect(response.status).toBe(200);
		expect(await response.text()).toBe("<html>nested page</html>");
	});

	test("does not append .html to a path with a trailing slash", async () => {
		const response = await serveStaticOrigin(new Request("https://example.com/report/"), site, makeOrigin(), "203.0.113.1", null, httpPolicy);
		expect(response.status).toBe(404);
	});

	test("an exact file match still wins over the clean-URL fallback", async () => {
		const response = await serveStaticOrigin(new Request("https://example.com/report.html"), site, makeOrigin(), "203.0.113.1", null, httpPolicy);
		expect(response.status).toBe(200);
		expect(await response.text()).toBe("<html>report</html>");
	});

	test("404s for a missing file without SPA fallback", async () => {
		const response = await serveStaticOrigin(new Request("https://example.com/missing"), site, makeOrigin(), "203.0.113.1", null, httpPolicy);
		expect(response.status).toBe(404);
	});

	test("falls back to the index file when SPA fallback is enabled", async () => {
		const response = await serveStaticOrigin(
			new Request("https://example.com/app/some/deep/route"),
			site,
			makeOrigin({ static_spa_fallback: 1 }),
			"203.0.113.1",
			null,
			httpPolicy,
		);
		expect(response.status).toBe(200);
		expect(await response.text()).toBe("<html>home</html>");
	});

	test("rejects path traversal outside the static root", async () => {
		const response = await serveStaticOrigin(new Request("https://example.com/../../../../etc/passwd"), site, makeOrigin(), "203.0.113.1", null, httpPolicy);
		expect(response.status).toBe(404);
	});

	test("rejects an encoded traversal attempt", async () => {
		const response = await serveStaticOrigin(
			new Request("https://example.com/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"),
			site,
			makeOrigin(),
			"203.0.113.1",
			null,
			httpPolicy,
		);
		expect(response.status).toBe(404);
	});

	test("serves a partial range and reports the total size", async () => {
		const response = await serveStaticOrigin(
			new Request("https://example.com/range.txt", { headers: { range: "bytes=6-10" } }),
			site,
			makeOrigin(),
			"203.0.113.1",
			null,
			httpPolicy,
		);
		expect(response.status).toBe(206);
		expect(response.headers.get("content-range")).toBe("bytes 6-10/17");
		expect(await response.text()).toBe("range");
	});

	test("rejects methods other than GET and HEAD", async () => {
		const response = await serveStaticOrigin(new Request("https://example.com/", { method: "POST" }), site, makeOrigin(), "203.0.113.1", null, httpPolicy);
		expect(response.status).toBe(405);
	});

	test("HEAD returns headers without a body", async () => {
		const response = await serveStaticOrigin(new Request("https://example.com/", { method: "HEAD" }), site, makeOrigin(), "203.0.113.1", null, httpPolicy);
		expect(response.status).toBe(200);
		expect(response.headers.get("content-length")).toBe("17");
		expect(await response.text()).toBe("");
	});

	test("sends an ETag and Last-Modified on a normal response", async () => {
		const response = await serveStaticOrigin(new Request("https://example.com/"), site, makeOrigin(), "203.0.113.1", null, httpPolicy);
		expect(response.status).toBe(200);
		expect(response.headers.get("etag")).toMatch(/^W\/"[0-9a-f]+-[0-9a-f]+"$/);
		expect(response.headers.get("last-modified")).toBeTruthy();
	});

	test("returns 304 when If-None-Match matches the current ETag", async () => {
		const first = await serveStaticOrigin(new Request("https://example.com/"), site, makeOrigin(), "203.0.113.1", null, httpPolicy);
		const etag = first.headers.get("etag")!;

		const second = await serveStaticOrigin(
			new Request("https://example.com/", { headers: { "if-none-match": etag } }),
			site,
			makeOrigin(),
			"203.0.113.1",
			null,
			httpPolicy,
		);
		expect(second.status).toBe(304);
		expect(second.headers.get("etag")).toBe(etag);
		expect(await second.text()).toBe("");
	});

	test("If-None-Match: * always matches", async () => {
		const response = await serveStaticOrigin(
			new Request("https://example.com/", { headers: { "if-none-match": "*" } }),
			site,
			makeOrigin(),
			"203.0.113.1",
			null,
			httpPolicy,
		);
		expect(response.status).toBe(304);
	});

	test("serves fresh content when If-None-Match does not match", async () => {
		const response = await serveStaticOrigin(
			new Request("https://example.com/", { headers: { "if-none-match": 'W/"stale-etag"' } }),
			site,
			makeOrigin(),
			"203.0.113.1",
			null,
			httpPolicy,
		);
		expect(response.status).toBe(200);
		expect(await response.text()).toBe("<html>home</html>");
	});

	test("returns 304 when If-Modified-Since is at or after the file's mtime", async () => {
		const response = await serveStaticOrigin(
			new Request("https://example.com/", { headers: { "if-modified-since": new Date(Date.now() + 60_000).toUTCString() } }),
			site,
			makeOrigin(),
			"203.0.113.1",
			null,
			httpPolicy,
		);
		expect(response.status).toBe(304);
	});

	test("serves fresh content when If-Modified-Since is before the file's mtime", async () => {
		const response = await serveStaticOrigin(
			new Request("https://example.com/", { headers: { "if-modified-since": new Date(0).toUTCString() } }),
			site,
			makeOrigin(),
			"203.0.113.1",
			null,
			httpPolicy,
		);
		expect(response.status).toBe(200);
	});

	test("If-None-Match takes precedence over If-Modified-Since", async () => {
		const response = await serveStaticOrigin(
			new Request("https://example.com/", {
				headers: { "if-none-match": 'W/"stale-etag"', "if-modified-since": new Date(Date.now() + 60_000).toUTCString() },
			}),
			site,
			makeOrigin(),
			"203.0.113.1",
			null,
			httpPolicy,
		);
		// A non-matching If-None-Match must serve fresh content even though
		// If-Modified-Since alone would have been satisfied.
		expect(response.status).toBe(200);
	});
});
