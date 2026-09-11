import { beforeAll, describe, expect, test } from "bun:test";
import { Web } from "@rabbit-company/web";
import { repository } from "../src/db/repository.ts";
import { registerMonitoringRoutes } from "../src/routes/monitoring-routes.ts";
import { monitoringData } from "../src/services/monitoring-service.ts";
import { createAdminUser } from "../src/services/admin-user-service.ts";
import { createApiToken } from "../src/services/api-token-service.ts";
import { createSite } from "../src/services/site-service.ts";
import type { RequestEventRecord } from "../src/types.ts";

const NOW = Date.now();
const HOUR = 3_600_000;

let siteId: string;

function event(path: string, country: string, referer: string | null, at: number, status = 200): RequestEventRecord {
	return {
		id: `evt-${Math.random().toString(36).slice(2)}-${at}`,
		site_id: siteId,
		session_id: null,
		ip: "203.0.113.10",
		method: "GET",
		path,
		status,
		decision: "allowed",
		latency_ms: 20,
		country_code: country,
		asn: null,
		asn_org: null,
		origin_id: null,
		cache_status: "hit",
		protection_status: null,
		protection_rule_id: null,
		protection_category: null,
		protection_severity: null,
		protection_ruleset_id: null,
		protection_ruleset_version: null,
		protection_matches_json: null,
		access_username: null,
		referer,
		referer_host: referer,
		bot_id: null,
		bot_name: null,
		bot_category: null,
		bot_verified: null,
		network_privacy_json: null,
		created_at: at,
	} as RequestEventRecord;
}

beforeAll(async () => {
	siteId = (await createSite({ name: "Bloggy", publicHost: `bloggy-${crypto.randomUUID()}.test`, originUrl: "http://origin.test" })).site.id;

	const at = NOW - HOUR / 2;
	for (let i = 0; i < 5; i++) await repository.insertEvent(event("/creator/alice/post-one", "SI", "news.example", at));
	for (let i = 0; i < 3; i++) await repository.insertEvent(event("/creator/alice/post-two", "DE", null, at));
	for (let i = 0; i < 7; i++) await repository.insertEvent(event("/creator/bob/post-one", "US", "other.example", at));
	for (let i = 0; i < 4; i++) await repository.insertEvent(event("/creator/alice", "SI", null, at));
	for (let i = 0; i < 6; i++) await repository.insertEvent(event("/creator/alice-blog/post", "BR", null, at));
	await repository.insertEvent(event("/", "FR", null, at));

	for (let i = 0; i < 9; i++) await repository.insertEvent(event(`/creator/alice/wp-admin-${i}`, "CN", "spam.example", at, 404));

	await repository.insertEvent(event("/creator/alice/post-one/", "FR", null, at));
});

describe("monitoring pathPrefix", () => {
	test("traffic counts only the matching tenant", async () => {
		const all = await monitoringData("overview", 24, siteId, NOW);
		const alice = await monitoringData("overview", 24, siteId, NOW, { prefix: "/creator/alice/" });
		const bob = await monitoringData("overview", 24, siteId, NOW, { prefix: "/creator/bob/" });

		const requests = (data: Awaited<ReturnType<typeof monitoringData>>) => data.stats.find((s) => s.label === "Requests")?.value;

		expect(requests(all)).toBe(36);
		expect(requests(alice)).toBe(22);
		expect(requests(bob)).toBe(7);
	});

	test("top paths are scoped, and never leak another tenant", async () => {
		const alice = await monitoringData("paths", 24, siteId, NOW, { prefix: "/creator/alice/" });
		const labels = alice.rows.map((row) => row.label);

		expect(labels).toEqual(expect.arrayContaining(["/creator/alice/post-one", "/creator/alice/post-two"]));
		expect(labels.some((label) => label.includes("bob"))).toBe(false);
		expect(alice.rows.find((row) => row.label === "/creator/alice/post-one")?.value).toBe(5);
	});

	test("geography is scoped, which is what the map draws", async () => {
		const alice = await monitoringData("geography", 24, siteId, NOW, { prefix: "/creator/alice/" });
		const codes = alice.rows.map((row) => row.label);

		expect(codes).toEqual(expect.arrayContaining(["SI", "DE"]));
		expect(codes).not.toContain("US");
	});

	test("referrers are scoped", async () => {
		const alice = await monitoringData("referrers", 24, siteId, NOW, { prefix: "/creator/alice/" });
		const hosts = alice.rows.map((row) => row.label);

		expect(hosts).toContain("news.example");
		expect(hosts).not.toContain("other.example");
	});

	test("cache metrics are scoped", async () => {
		const alice = await monitoringData("cache", 24, siteId, NOW, { prefix: "/creator/alice/" });
		expect(alice.stats.find((s) => s.label === "Hits")?.value).toBe(22);
	});

	test("a prefix matching nothing returns no data rather than everything", async () => {
		const nobody = await monitoringData("paths", 24, siteId, NOW, { prefix: "/creator/nobody/" });
		expect(nobody.rows).toHaveLength(0);
	});

	test("LIKE wildcards in the prefix cannot widen the scope", async () => {
		const wildcard = await monitoringData("paths", 24, siteId, NOW, { prefix: "/creator/%" });
		expect(wildcard.rows).toHaveLength(0);
	});

	test("views with no path column refuse the filter instead of ignoring it", async () => {
		expect(monitoringData("bandwidth", 24, siteId, NOW, { prefix: "/creator/alice/" })).rejects.toThrow(/pathPrefix/);
		expect(monitoringData("cpu", 24, undefined, NOW, { prefix: "/creator/alice/" })).rejects.toThrow(/pathPrefix/);
	});

	test("a scope includes the tenant's own index page", async () => {
		const alice = await monitoringData("paths", 24, siteId, NOW, { prefix: "/creator/alice" });
		expect(alice.rows.map((row) => row.label)).toContain("/creator/alice");
	});

	test("a scope excludes a sibling whose name shares the prefix", async () => {
		const alice = await monitoringData("paths", 24, siteId, NOW, { prefix: "/creator/alice" });
		expect(alice.rows.some((row) => row.label.includes("alice-blog"))).toBe(false);

		const sibling = await monitoringData("paths", 24, siteId, NOW, { prefix: "/creator/alice-blog" });
		expect(sibling.rows.map((row) => row.label)).toEqual(["/creator/alice-blog/post"]);
	});

	test("a trailing slash is accepted and means the same subtree", async () => {
		const withSlash = await monitoringData("overview", 24, siteId, NOW, { prefix: "/creator/alice/" });
		const without = await monitoringData("overview", 24, siteId, NOW, { prefix: "/creator/alice" });
		expect(withSlash.stats).toEqual(without.stats);
	});

	test("the applied scope is echoed back so callers can verify it", async () => {
		const scoped = await monitoringData("overview", 24, siteId, NOW, { prefix: "/creator/alice" });
		expect(scoped.pathPrefix).toBe("/creator/alice");
		const unscoped = await monitoringData("overview", 24, siteId, NOW);
		expect(unscoped.pathPrefix).toBeNull();
	});

	test("omitting the prefix is unchanged behaviour", async () => {
		const before = await monitoringData("paths", 24, siteId, NOW);
		expect(before.rows.length).toBeGreaterThan(2);
	});
});

describe("monitoring exact path", () => {
	test("an exact path counts one page, not its neighbours", async () => {
		const post = await monitoringData("overview", 24, siteId, NOW, { exact: "/creator/alice/post-one" });
		const requests = post.stats.find((s) => s.label === "Requests")?.value;

		expect(requests).toBe(6);
	});

	test("an exact path does not sweep in the subtree below it", async () => {
		const index = await monitoringData("overview", 24, siteId, NOW, { exact: "/creator/alice" });
		const subtree = await monitoringData("overview", 24, siteId, NOW, { prefix: "/creator/alice" });

		expect(index.stats.find((s) => s.label === "Requests")?.value).toBe(4);
		expect(subtree.stats.find((s) => s.label === "Requests")?.value).toBe(22);
	});

	test("per-post countries and referrers are what the drill-down is for", async () => {
		const countries = await monitoringData("geography", 24, siteId, NOW, { exact: "/creator/alice/post-one" });
		expect(countries.rows.map((row) => row.label)).toEqual(expect.arrayContaining(["SI", "FR"]));
		expect(countries.rows.map((row) => row.label)).not.toContain("DE");

		const referrers = await monitoringData("referrers", 24, siteId, NOW, { exact: "/creator/alice/post-one" });
		expect(referrers.rows.map((row) => row.label)).toEqual(["news.example"]);
	});

	test("a prefix and an exact path together are refused, not silently merged", async () => {
		expect(monitoringData("overview", 24, siteId, NOW, { prefix: "/creator/alice", exact: "/creator/alice/post-one" })).rejects.toThrow(/mutually exclusive/);
	});

	test("the applied exact path is echoed back", async () => {
		const scoped = await monitoringData("overview", 24, siteId, NOW, { exact: "/creator/alice/post-one" });
		expect(scoped.path).toBe("/creator/alice/post-one");
		expect(scoped.pathPrefix).toBeNull();
	});
});

describe("monitoring successfulOnly", () => {
	test("404 probes are excluded from a blog's totals", async () => {
		const withProbes = await monitoringData("overview", 24, siteId, NOW, { prefix: "/creator/alice" });
		const readers = await monitoringData("overview", 24, siteId, NOW, { prefix: "/creator/alice", successfulOnly: true });

		expect(withProbes.stats.find((s) => s.label === "Requests")?.value).toBe(22);
		expect(readers.stats.find((s) => s.label === "Requests")?.value).toBe(13);
	});

	test("probe paths, countries and referrers all disappear together", async () => {
		const scope = { prefix: "/creator/alice", successfulOnly: true };

		const paths = await monitoringData("paths", 24, siteId, NOW, scope);
		expect(paths.rows.some((row) => row.label.includes("wp-admin"))).toBe(false);

		const countries = await monitoringData("geography", 24, siteId, NOW, scope);
		expect(countries.rows.map((row) => row.label)).not.toContain("CN");

		const referrers = await monitoringData("referrers", 24, siteId, NOW, scope);
		expect(referrers.rows.map((row) => row.label)).not.toContain("spam.example");
	});

	test("views about refused requests reject the filter as contradictory", async () => {
		expect(monitoringData("blocked", 24, siteId, NOW, { successfulOnly: true })).rejects.toThrow(/successfulOnly/);
		expect(monitoringData("protection", 24, siteId, NOW, { successfulOnly: true })).rejects.toThrow(/successfulOnly/);
	});

	test("the filter is echoed so a caller can tell it was applied", async () => {
		const filtered = await monitoringData("overview", 24, siteId, NOW, { successfulOnly: true });
		expect(filtered.successfulOnly).toBe(true);
		const unfiltered = await monitoringData("overview", 24, siteId, NOW);
		expect(unfiltered.successfulOnly).toBe(false);
	});
});

describe("monitoring path scoping with query strings", () => {
	let querySiteId: string;

	beforeAll(async () => {
		querySiteId = (await createSite({ name: "Query", publicHost: `query-${crypto.randomUUID()}.test`, originUrl: "http://origin.test" })).site.id;

		const at = NOW - HOUR / 2;
		const record = (path: string) => repository.insertEvent({ ...event(path, "SI", null, at), site_id: querySiteId });

		await record("/creator/alice");
		await record("/creator/alice?page=2");
		await record("/creator/alice/post-one");
		await record("/creator/alice/post-one?utm_source=news&session=s3cret");
		await record("/creator/bob?page=2");
	});

	const requests = (data: Awaited<ReturnType<typeof monitoringData>>) => data.stats.find((s) => s.label === "Requests")?.value;

	test("a prefix counts pages that carried a query string", async () => {
		const alice = await monitoringData("overview", 24, querySiteId, NOW, { prefix: "/creator/alice" });
		expect(requests(alice)).toBe(4);
	});

	test("an exact path counts its query-string variants", async () => {
		const post = await monitoringData("overview", 24, querySiteId, NOW, { exact: "/creator/alice/post-one" });
		expect(requests(post)).toBe(2);
	});

	test("a sibling with a query string is still excluded", async () => {
		const alice = await monitoringData("paths", 24, querySiteId, NOW, { prefix: "/creator/alice" });
		expect(alice.rows.some((row) => row.label.includes("bob"))).toBe(false);
	});

	test("the paths view groups variants as one page and emits no query strings", async () => {
		const paths = await monitoringData("paths", 24, querySiteId, NOW);
		const labels = paths.rows.map((row) => row.label);

		expect(labels.some((label) => label.includes("?"))).toBe(false);
		expect(JSON.stringify(paths.rows)).not.toContain("s3cret");
		expect(paths.rows.find((row) => row.label === "/creator/alice")?.value).toBe(2);
		expect(paths.rows.find((row) => row.label === "/creator/alice/post-one")?.value).toBe(2);
	});
});

describe("monitoring pathPrefix over HTTP", () => {
	const app = new Web();
	registerMonitoringRoutes(app);

	let headers: Record<string, string>;

	beforeAll(async () => {
		const admin = await createAdminUser({ username: `mon-${crypto.randomUUID()}`, password: "password123", role: "administrator" }, "test-suite");
		const { token } = await createApiToken(admin.id, { name: "Scoped analytics", expiresInDays: null, scope: "monitoring" });
		headers = { authorization: `Bearer ${token}` };
	});

	const get = async (query: string) => {
		const response = await app.handle(new Request(`http://gateway.test/_burrowgate/api/v1/monitoring?${query}`, { headers }));
		return { status: response.status, body: (await response.json()) as any };
	};

	test("the route forwards pathPrefix to the service", async () => {
		const scoped = await get(`view=paths&hours=24&siteId=${siteId}&pathPrefix=/creator/alice`);

		expect(scoped.status).toBe(200);
		expect(scoped.body.pathPrefix).toBe("/creator/alice");
		expect(scoped.body.rows.map((row: { label: string }) => row.label)).toContain("/creator/alice/post-one");
		expect(scoped.body.rows.some((row: { label: string }) => row.label.includes("bob"))).toBe(false);
	});

	test("an unscoped request still answers for the whole site", async () => {
		const all = await get(`view=paths&hours=24&siteId=${siteId}`);

		expect(all.body.pathPrefix).toBeNull();
		expect(all.body.rows.some((row: { label: string }) => row.label.includes("bob"))).toBe(true);
	});

	test("a malformed prefix is refused, never dropped", async () => {
		const relative = await get(`view=paths&hours=24&siteId=${siteId}&pathPrefix=creator/alice`);
		expect(relative.status).toBe(400);

		const tooLong = await get(`view=paths&hours=24&siteId=${siteId}&pathPrefix=/${"a".repeat(300)}`);
		expect(tooLong.status).toBe(400);
	});

	test("a view that cannot honour the filter answers 400, not unscoped numbers", async () => {
		const bandwidth = await get(`view=bandwidth&hours=24&siteId=${siteId}&pathPrefix=/creator/alice`);

		expect(bandwidth.status).toBe(400);
		expect(String(bandwidth.body.error)).toMatch(/pathPrefix/);
	});

	test("any whole number of hours is accepted, up to a year", async () => {
		for (const hours of [1, 5, 24, 168, 720, 8784]) {
			expect((await get(`view=overview&hours=${hours}&siteId=${siteId}`)).status).toBe(200);
		}
	});

	test("a nonsensical window is still refused", async () => {
		for (const hours of ["0", "-3", "1.5", "abc", "", "8785", "1e9"]) {
			expect((await get(`view=overview&hours=${encodeURIComponent(hours)}&siteId=${siteId}`)).status).toBe(400);
		}
	});

	test("the window still bounds the series, whatever it is", async () => {
		const day = await get(`view=overview&hours=24&siteId=${siteId}`);
		const year = await get(`view=overview&hours=8784&siteId=${siteId}`);

		expect(day.body.points.length).toBeLessThanOrEqual(49);
		expect(year.body.points.length).toBeLessThanOrEqual(49);
	});

	test("the route forwards an exact path", async () => {
		const post = await get(`view=overview&hours=24&siteId=${siteId}&path=/creator/alice/post-one`);

		expect(post.body.path).toBe("/creator/alice/post-one");
		expect(post.body.pathPrefix).toBeNull();
		expect(post.body.stats.find((s: { label: string }) => s.label === "Requests").value).toBe(6);
	});

	test("the route forwards successfulOnly", async () => {
		const all = await get(`view=overview&hours=24&siteId=${siteId}&pathPrefix=/creator/alice`);
		const readers = await get(`view=overview&hours=24&siteId=${siteId}&pathPrefix=/creator/alice&successfulOnly=true`);

		expect(all.body.successfulOnly).toBe(false);
		expect(readers.body.successfulOnly).toBe(true);
		expect(readers.body.stats.find((s: { label: string }) => s.label === "Requests").value).toBe(13);
	});

	test("asking for both a prefix and an exact path is a 400", async () => {
		const both = await get(`view=overview&hours=24&siteId=${siteId}&pathPrefix=/creator/alice&path=/creator/alice/post-one`);

		expect(both.status).toBe(400);
		expect(String(both.body.error)).toMatch(/mutually exclusive/);
	});

	test("a malformed exact path is refused like a malformed prefix", async () => {
		expect((await get(`view=overview&hours=24&siteId=${siteId}&path=creator/alice`)).status).toBe(400);
		expect((await get(`view=overview&hours=24&siteId=${siteId}&successfulOnly=maybe`)).status).toBe(400);
	});
});
