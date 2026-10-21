import { beforeAll, describe, expect, test } from "bun:test";
import { Web } from "@rabbit-company/web";
import { repository } from "../src/db/repository.ts";
import { registerAdminRoutes } from "../src/routes/admin-routes.ts";
import { createAdminSession } from "../src/services/session-service.ts";
import { createAdminUser } from "../src/services/admin-user-service.ts";
import { createSite } from "../src/services/site-service.ts";
import type { RequestEventRecord } from "../src/types.ts";

const app = new Web();
registerAdminRoutes(app);

const NOW = Date.now();
let siteId: string;
let cookie: string;

function event(path: string, accessUsername: string | null, status: number, originUsername: string | null = null): RequestEventRecord {
	return {
		id: `evt-search-${crypto.randomUUID()}`,
		site_id: siteId,
		session_id: null,
		ip: "203.0.113.10",
		method: "GET",
		path,
		status,
		decision: "proxied",
		latency_ms: 20,
		country_code: "SI",
		asn: null,
		asn_org: null,
		origin_id: null,
		cache_status: null,
		protection_status: null,
		protection_rule_id: null,
		protection_category: null,
		protection_severity: null,
		protection_ruleset_id: null,
		protection_ruleset_version: null,
		protection_matches_json: null,
		access_username: accessUsername,
		origin_username: originUsername,
		referer: null,
		referer_host: null,
		bot_id: null,
		bot_name: null,
		bot_category: null,
		bot_verified: null,
		network_privacy_json: null,
		created_at: NOW - 60_000,
	} as RequestEventRecord;
}

beforeAll(async () => {
	siteId = (await createSite({ name: "Search routes", publicHost: `search-${crypto.randomUUID()}.test`, originUrl: "http://origin.test" })).site.id;
	const admin = await createAdminUser({ username: `search-admin-${crypto.randomUUID()}`, password: "password123", role: "administrator" }, "test-suite");
	cookie = (await createAdminSession(new Request("http://admin.test/"), admin.username, admin.id)).cookie.split(";")[0]!;
	await repository.insertEvent(event("/health", null, 200));
	await repository.insertEvent(event("/healthz", null, 200));
	await repository.insertEvent(event("/account", "alice", 200));
	await repository.insertEvent(event("/orders", "bob", 500));
	await repository.insertEvent(event("/profile", null, 200, "carol"));
});

async function traffic(search: string) {
	const url = new URL("http://admin.test/_burrowgate/api/admin/events");
	url.searchParams.set("siteId", siteId);
	url.searchParams.set("search", search);
	url.searchParams.set("from", String(NOW - 3_600_000));
	url.searchParams.set("to", String(NOW));
	return await app.handle(new Request(url.href, { headers: { cookie } }));
}

async function paths(search: string): Promise<string[]> {
	const response = await traffic(search);
	expect(response.status).toBe(200);
	const body = (await response.json()) as { items: Array<{ path: string }> };
	return body.items.map((item) => item.path).sort();
}

describe("traffic search through the admin API", () => {
	test("hides health checks, missing users, and one user", async () => {
		expect(await paths("-path:/health*")).toEqual(["/account", "/orders", "/profile"]);
		expect(await paths("user:*")).toEqual(["/account", "/orders", "/profile"]);
		expect(await paths("-user:*")).toEqual(["/health", "/healthz"]);
		expect(await paths("-user:alice -path:/health*")).toEqual(["/orders", "/profile"]);
		expect(await paths("access_user:* OR status:5xx")).toEqual(["/account", "/orders"]);
	});

	test("keeps plain free text working", async () => {
		expect(await paths("health")).toEqual(["/health", "/healthz"]);
		expect(await paths("carol")).toEqual(["/profile"]);
	});

	test("rejects invalid syntax with a 400 that says where", async () => {
		const response = await traffic("status:>=abc");
		expect(response.status).toBe(400);
		expect(await response.json()).toMatchObject({ code: "invalid_search", error: "Invalid search: status must be a number" });
	});

	test("reports unknown fields as warnings", async () => {
		const response = await traffic("usr:alice");
		const body = (await response.json()) as { searchWarnings: string[] };
		expect(body.searchWarnings).toEqual(['"usr" is not a field here, so "usr:alice" was searched as text']);
	});

	test("serves the field catalog for the help panel", async () => {
		const response = await app.handle(new Request("http://admin.test/_burrowgate/api/admin/search-fields", { headers: { cookie } }));
		const body = (await response.json()) as { schemas: Array<{ id: string; fields: Array<{ name: string }> }> };
		const traffic = body.schemas.find((schema) => schema.id === "traffic");
		expect(traffic?.fields.map((field) => field.name)).toEqual(expect.arrayContaining(["path", "user", "status", "ip"]));
		expect(body.schemas.map((schema) => schema.id)).toEqual(
			expect.arrayContaining([
				"traffic",
				"sessions",
				"ip-rules",
				"bandwidth",
				"audit-log",
				"notifications",
				"stream-events",
				"stream-rules",
				"stream-bandwidth",
				"logs",
			]),
		);
	});
});
