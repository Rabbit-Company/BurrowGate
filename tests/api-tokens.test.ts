import { describe, expect, test } from "bun:test";
import { Web } from "@rabbit-company/web";
import { registerAdminRoutes } from "../src/routes/admin-routes.ts";
import { config } from "../src/config.ts";
import { monitoringData } from "../src/services/monitoring-service.ts";
import { repository, type ReplicationChangelogRow } from "../src/db/repository.ts";
import { db } from "../src/db/client.ts";
import { createAdminUser } from "../src/services/admin-user-service.ts";
import { createAdminSession } from "../src/services/session-service.ts";
import { createApiToken } from "../src/services/api-token-service.ts";
import { createSite } from "../src/services/site-service.ts";
import { MONITORING_VIEWS } from "../src/services/monitoring-service.ts";

const app = new Web();
registerAdminRoutes(app);
// Model an otherwise public origin: tokens must not be allowed to reach it.
app.get("/origin", () => new Response("origin"));
app.post("/origin", () => new Response("changed"));
const BASE = "http://admin.test/_burrowgate/api";

async function account(role: "administrator" | "member" = "administrator") {
	const user = await createAdminUser({ username: `api-${crypto.randomUUID()}`, password: "password123", role }, "test-suite");
	const { cookie } = await createAdminSession(new Request("http://admin.test/"), user.username, user.id);
	return { user, headers: { cookie: cookie.split(";")[0]!, "x-burrowgate-admin": "1", "content-type": "application/json" } };
}

describe("read-only monitoring API tokens", () => {
	test("creation shows the secret once, persists only its hash, and revocation takes effect", async () => {
		const { user, headers } = await account();
		const created = await app.handle(
			new Request(`${BASE}/admin/me/api-tokens`, { method: "POST", headers, body: JSON.stringify({ name: "TRMNL", expiresInDays: 30 }) }),
		);
		expect(created.status).toBe(201);
		expect(created.headers.get("cache-control")).toBe("no-store");
		const result = (await created.json()) as { token: string; id: string };
		expect(result.token).toMatch(/^bgro_[A-Za-z0-9_-]{43}$/);
		const records = await repository.apiTokensForUser(user.id);
		expect(records[0]!.token_hash).toHaveLength(64);
		expect(JSON.stringify(records)).not.toContain(result.token);
		const list = await app.handle(new Request(`${BASE}/admin/me/api-tokens`, { headers }));
		const text = await list.text();
		expect(text).toContain("monitoring:read");
		expect(text).not.toContain(result.token);
		expect(text).not.toContain(records[0]!.token_hash);
		const bearer = { authorization: `Bearer ${result.token}` };
		expect((await app.handle(new Request(`${BASE}/v1/monitoring`, { headers: bearer }))).status).toBe(200);
		expect((await app.handle(new Request(`${BASE}/admin/me/api-tokens/${result.id}`, { method: "DELETE", headers }))).status).toBe(200);
		expect((await app.handle(new Request(`${BASE}/v1/monitoring`, { headers: bearer }))).status).toBe(401);
	});

	test("rejects every non-GET method and endpoints outside the allowlist, even with an admin cookie", async () => {
		const { user, headers } = await account();
		const { token } = await createApiToken(user.id, { name: "Boundary" });
		const combined = { ...headers, authorization: `Bearer ${token}` };
		for (const method of ["POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]) {
			for (const path of ["/v1/monitoring", "/v1/sites", "/admin/sites", "/admin/me/api-tokens"]) {
				expect([403, 404]).toContain((await app.handle(new Request(`${BASE}${path}`, { method, headers: combined }))).status);
			}
		}
		for (const path of ["/admin/me", "/admin/sites", "/admin/events", "/admin/sessions", "/admin/me/api-tokens"]) {
			expect((await app.handle(new Request(`${BASE}${path}`, { headers: combined }))).status).toBe(403);
		}
		for (const method of ["GET", "POST"]) expect((await app.handle(new Request("http://admin.test/origin", { method, headers: combined }))).status).toBe(403);
		expect((await app.handle(new Request("http://admin.test/origin"))).status).toBe(200);
	});

	test("requires a bearer token, rejects expiry and disabled, deleted, or demoted owners", async () => {
		const { user, headers } = await account();
		const created = await createApiToken(user.id, { name: "Lifecycle" });
		const read = () => app.handle(new Request(`${BASE}/v1/sites`, { headers: { authorization: `Bearer ${created.token}` } }));
		for (const invalidHeaders of [new Headers(), new Headers(headers), new Headers({ authorization: "Bearer bad-token" })]) {
			expect((await app.handle(new Request(`${BASE}/v1/sites`, { headers: invalidHeaders }))).status).toBe(401);
		}
		expect((await app.handle(new Request(`${BASE}/v1/sites?token=${created.token}`))).status).toBe(401);
		await db`UPDATE api_tokens SET expires_at=${Date.now() - 1} WHERE id=${created.id}`;
		expect((await read()).status).toBe(401);
		await db`UPDATE api_tokens SET expires_at=NULL WHERE id=${created.id}`;
		const owner = (await repository.adminUserById(user.id))!;
		await repository.updateAdminUser({ ...owner, enabled: 0 });
		expect((await read()).status).toBe(401);
		await repository.updateAdminUser({ ...owner, role: "member" });
		expect((await read()).status).toBe(401);
		await repository.updateAdminUser(owner);
		expect((await read()).status).toBe(200);
		await repository.deleteAdminUserCascade(user.id);
		expect((await read()).status).toBe(401);
	});

	test("management requires an administrator session, CSRF protection, and ownership", async () => {
		const owner = await account();
		const member = await account("member");
		const other = await account();
		const created = await createApiToken(owner.user.id, { name: "Private token" });
		for (const method of ["GET", "POST"]) {
			expect((await app.handle(new Request(`${BASE}/admin/me/api-tokens`, { method, headers: member.headers }))).status).toBe(403);
			expect((await app.handle(new Request(`${BASE}/admin/me/api-tokens`, { method }))).status).toBe(401);
		}
		expect((await app.handle(new Request(`${BASE}/admin/me/api-tokens`, { method: "POST", headers: { cookie: owner.headers.cookie } }))).status).toBe(403);
		expect(
			(await app.handle(new Request(`${BASE}/admin/me/api-tokens`, { method: "POST", headers: { ...owner.headers, origin: "http://evil.test" } }))).status,
		).toBe(403);
		expect((await app.handle(new Request(`${BASE}/admin/me/api-tokens/${created.id}`, { method: "DELETE", headers: other.headers }))).status).toBe(404);
		for (const body of [null, [], {}, { name: " " }, { name: "x", expiresInDays: -1 }, { name: "x", expiresInDays: "30" }]) {
			expect(
				(await app.handle(new Request(`${BASE}/admin/me/api-tokens`, { method: "POST", headers: owner.headers, body: JSON.stringify(body) }))).status,
			).toBe(400);
		}
	});

	test("all views return bounded aggregates, site filtering is validated, and secrets are excluded", async () => {
		const { user } = await account();
		const { token } = await createApiToken(user.id, { name: "Views", expiresInDays: null });
		const headers = { authorization: `Bearer ${token}` };
		const { site } = await createSite({
			name: "Monitoring site",
			publicHost: `monitoring-${crypto.randomUUID()}.test`,
			originUrl: "http://secret-origin.test",
		});
		const sites = await app.handle(new Request(`${BASE}/v1/sites`, { headers }));
		const text = await sites.text();
		expect(text).toContain(site.id);
		expect(text).not.toContain("secret-origin");
		expect(text).not.toContain(site.origin_signing_secret);
		for (const view of MONITORING_VIEWS) {
			const result = await app.handle(new Request(`${BASE}/v1/monitoring?view=${view}&hours=168`, { headers }));
			expect(result.status).toBe(200);
			const data = (await result.json()) as any;
			expect(data.schemaVersion).toBe(1);
			expect(data.view).toBe(view);
			expect(data.points.length).toBeLessThanOrEqual(49);
			if (["cpu", "memory", "disk", "network"].includes(view)) {
				expect(data.hasData).toBe(false);
				expect(data.stats[0].value).toBeNull();
			}
		}
		for (const query of ["view=bad", "hours=999999", "hours=", "siteId=missing", `view=cpu&siteId=${site.id}`]) {
			expect((await app.handle(new Request(`${BASE}/v1/monitoring?${query}`, { headers }))).status).toBe(400);
		}
		const scoped = await app.handle(new Request(`${BASE}/v1/monitoring?siteId=${site.id}`, { headers }));
		expect(((await scoped.json()) as any).scope).toBe(site.name);
	});
	test("site aggregates preserve percentages, latency, and data isolation", async () => {
		const { site } = await createSite({ name: "Aggregate fixture", publicHost: `aggregate-${crypto.randomUUID()}.test`, originUrl: "http://origin.test" });
		const now = Date.now();
		for (let i = 0; i < 5; i++) {
			await db`INSERT INTO request_events (id,site_id,ip,method,path,status,decision,latency_ms,country_code,cache_status,created_at)
				VALUES (${crypto.randomUUID()},${i === 4 ? "other-site" : site.id},'192.0.2.1','GET','/private-path',${i === 3 ? 503 : 200},${i === 2 ? "blocked" : "proxied"},${i * 100},'SI',${i < 3 ? "hit" : "miss"},${now - 1000})`;
		}
		const traffic = await monitoringData("traffic", 1, site.id, now);
		expect(traffic.stats.map((s) => s.value)).toEqual([4, 1, 1]);
		expect(traffic.points.reduce((sum, p) => sum + (p.value ?? 0), 0)).toBe(4);
		const cache = await monitoringData("cache", 1, site.id, now);
		expect(cache.stats[0]!.value).toBe(75);
		expect(cache.points.filter((p) => p.value !== null).map((p) => p.value)).toEqual([75]);
		const latency = await monitoringData("latency", 1, site.id, now);
		expect(latency.stats[0]!.value).toBe(150);
		const geography = await monitoringData("geography", 1, site.id, now);
		expect(geography.rows).toEqual([{ label: "SI", value: 4 }]);
		expect(JSON.stringify([traffic, cache, latency, geography])).not.toContain("private-path");
		expect(JSON.stringify([traffic, cache, latency, geography])).not.toContain("192.0.2.1");
	});

	test("HA snapshots and changelog replication preserve token creation and revocation", async () => {
		const { user } = await account();
		const previousEnabled = config.ha.enabled;
		const previousRole = config.ha.role;
		try {
			config.ha.enabled = true;
			config.ha.role = "primary";
			const created = await createApiToken(user.id, { name: "Replicated" });
			const snapshot = await repository.fullSnapshot();
			const tokenRow = snapshot.rows.find((row) => row.entity_type === "api_token" && row.entity_id === created.id);
			expect(tokenRow).toBeDefined();
			expect(tokenRow!.payload_json).not.toContain(created.token);
			await repository.deleteApiToken(created.id, user.id);
			const rows =
				(await db`SELECT * FROM replication_changelog WHERE entity_type='api_token' AND entity_id=${created.id} ORDER BY seq`) as ReplicationChangelogRow[];
			expect(rows.map((row) => row.op)).toEqual(["insert", "delete"]);
			await repository.applyReplicatedChange(rows[0]!);
			expect((await repository.apiTokensForUser(user.id)).map((t) => t.id)).toContain(created.id);
			await repository.applyReplicatedChange(rows[1]!);
			expect((await repository.apiTokensForUser(user.id)).map((t) => t.id)).not.toContain(created.id);
		} finally {
			config.ha.enabled = previousEnabled;
			config.ha.role = previousRole;
		}
	});
});
