import { describe, expect, test } from "bun:test";
import type { RoutePolicyRecord, SiteRecord } from "../src/types.ts";
import type { SiteStaticCachePolicy } from "../src/services/http-policy-service.ts";
import { rememberOriginResponse, StaticAssetCache } from "../src/services/static-cache-service.ts";

const policy: SiteStaticCachePolicy = {
	mode: "enabled",
	ttlSeconds: 60,
	maxObjectBytes: 1_024,
	extensions: [".css", ".js", ".png"],
};

function site(id = "cache-site"): SiteRecord {
	return { id, updated_at: 1 } as SiteRecord;
}

function route(id = "cache-route"): RoutePolicyRecord {
	return { id, updated_at: 1 } as RoutePolicyRecord;
}

async function fill(
	cache: StaticAssetCache,
	request: Request,
	siteRecord = site(),
	routeRecord: RoutePolicyRecord | null = null,
	response = new Response("body", { headers: { "content-type": "text/css", "cache-control": "public, max-age=120" } }),
	now = 1_000,
): Promise<Response> {
	const lookup = cache.lookup(request, siteRecord, routeRecord, policy, now);
	const downstream = cache.observeResponse(request, response, lookup, siteRecord, routeRecord, policy, "origin-1", now);
	await downstream.arrayBuffer();
	await cache.waitForIdle();
	return downstream;
}

describe("safe static asset cache", () => {
	test("stores a public static response and serves GET and HEAD hits", async () => {
		const cache = new StaticAssetCache({ maxEntries: 10, maxBytes: 10_000 });
		const request = new Request("https://assets.test/app.css", { headers: { "accept-encoding": "gzip" } });
		const first = await fill(cache, request);
		expect(first.headers.get("x-burrowgate-cache")).toBe("MISS");

		const hit = cache.lookup(request, site(), null, policy, 2_000);
		expect(hit.outcome).toBe("hit");
		expect(hit.response?.headers.get("x-burrowgate-cache")).toBe("HIT");
		expect(hit.response?.headers.get("age")).toBe("1");
		expect(await hit.response?.text()).toBe("body");

		const head = cache.lookup(new Request(request.url, { method: "HEAD", headers: request.headers }), site(), null, policy, 2_000);
		expect(head.outcome).toBe("hit");
		expect(await head.response?.text()).toBe("");
		expect(cache.metrics(site().id)).toMatchObject({ hits: 2, misses: 1, stores: 1, entries: 1 });
		expect(cache.metrics(site().id).bytes).toBeGreaterThanOrEqual(4);
	});

	test("bypasses credentials, application cookies, refreshes, ranges, and non-assets", () => {
		const cache = new StaticAssetCache({ maxEntries: 10, maxBytes: 10_000 });
		for (const request of [
			new Request("https://assets.test/app.css", { headers: { authorization: "Bearer secret" } }),
			new Request("https://assets.test/app.css", { headers: { cookie: "SSID=application" } }),
			new Request("https://assets.test/app.css", { headers: { range: "bytes=0-10" } }),
			new Request("https://assets.test/app.css", { headers: { "cache-control": "no-cache" } }),
			new Request("https://assets.test/api/data"),
		]) {
			expect(cache.lookup(request, site(), null, policy).outcome).toBe("bypass");
		}
		expect(cache.lookup(new Request("https://assets.test/app.css", { headers: { cookie: "bg_session=internal" } }), site(), null, policy).outcome).toBe("miss");
		expect(cache.metrics(site().id).bypasses).toBe(5);
	});

	test("does not store unsafe origin responses even if downstream headers were rewritten", async () => {
		const cache = new StaticAssetCache({ maxEntries: 10, maxBytes: 10_000 });
		const request = new Request("https://assets.test/app.css");
		const lookup = cache.lookup(request, site(), null, policy, 1_000);
		const origin = new Response("private", { headers: { "content-type": "text/css", "cache-control": "private, max-age=120", "set-cookie": "user=1" } });
		const downstream = rememberOriginResponse(
			new Response("private", { headers: { "content-type": "text/css", "cache-control": "public, max-age=120" } }),
			origin,
		);
		const result = cache.observeResponse(request, downstream, lookup, site(), null, policy, null, 1_000);
		await result.arrayBuffer();
		await cache.waitForIdle();
		expect(cache.lookup(request, site(), null, policy, 2_000).outcome).toBe("miss");
		expect(cache.metrics(site().id).entries).toBe(0);
	});

	test("honors expiry, encoding and route isolation, and scoped purge", async () => {
		const cache = new StaticAssetCache({ maxEntries: 10, maxBytes: 10_000 });
		const gzip = new Request("https://assets.test/app.js?v=1", { headers: { "accept-encoding": "gzip" } });
		await fill(cache, gzip, site(), route(), new Response("script", { headers: { "content-type": "text/javascript", "cache-control": "max-age=1" } }), 1_000);
		expect(cache.lookup(new Request(gzip.url, { headers: { "accept-encoding": "br" } }), site(), route(), policy, 1_500).outcome).toBe("miss");
		expect(cache.lookup(gzip, site(), null, policy, 1_500).outcome).toBe("miss");
		expect(cache.purge({ siteId: site().id, routePolicyId: route().id })).toBe(1);
		expect(cache.lookup(gzip, site(), route(), policy, 1_500).outcome).toBe("miss");

		await fill(cache, gzip, site(), route(), new Response("script", { headers: { "content-type": "text/javascript", "cache-control": "max-age=1" } }), 2_000);
		expect(cache.lookup(gzip, site(), route(), policy, 3_001).outcome).toBe("miss");
		expect(cache.metrics(site().id).expired).toBe(1);
	});

	test("enforces object and global LRU memory bounds", async () => {
		const cache = new StaticAssetCache({ maxEntries: 1, maxBytes: 10_000 });
		await fill(cache, new Request("https://assets.test/one.css"), site(), null, new Response("1234", { headers: { "content-type": "text/css" } }));
		await fill(cache, new Request("https://assets.test/two.css"), site(), null, new Response("5678", { headers: { "content-type": "text/css" } }));
		expect(cache.lookup(new Request("https://assets.test/one.css"), site(), null, policy, 2_000).outcome).toBe("miss");
		expect(cache.lookup(new Request("https://assets.test/two.css"), site(), null, policy, 2_000).outcome).toBe("hit");
		expect(cache.metrics(site().id)).toMatchObject({ entries: 1, evictions: 1 });
		expect(cache.metrics(site().id).bytes).toBeGreaterThanOrEqual(4);

		const tinyPolicy = { ...policy, maxObjectBytes: 1_024 };
		const oversized = new Response(new Uint8Array(1_025), { headers: { "content-type": "text/css" } });
		const request = new Request("https://assets.test/large.css");
		const lookup = cache.lookup(request, site(), null, tinyPolicy);
		const result = cache.observeResponse(request, oversized, lookup, site(), null, tinyPolicy, null);
		await result.arrayBuffer();
		await cache.waitForIdle();
		expect(cache.lookup(request, site(), null, tinyPolicy).outcome).toBe("miss");
	});
});
