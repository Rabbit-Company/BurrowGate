import { afterAll, afterEach, describe, expect, test } from "bun:test";
import { Web } from "@rabbit-company/web";
import { config } from "../src/config.ts";
import { db } from "../src/db/client.ts";
import { repository } from "../src/db/repository.ts";
import { registerHaClusterAdminRoutes } from "../src/routes/ha-cluster-admin-routes.ts";
import { createAdminUser } from "../src/services/admin-user-service.ts";
import { createAdminSession } from "../src/services/session-service.ts";
import { APP_VERSION } from "../src/ui/layout.ts";

const app = new Web();
registerHaClusterAdminRoutes(app);

const originalFetch = globalThis.fetch;
const originalEnabled = config.ha.enabled;
const originalRole = config.ha.role;
const originalPrimaryAdminUrl = config.ha.primaryAdminUrl;
const originalNodeName = config.ha.nodeName;

async function resetHaConfig(): Promise<void> {
	globalThis.fetch = originalFetch;
	config.ha.enabled = originalEnabled;
	config.ha.role = originalRole;
	config.ha.primaryAdminUrl = originalPrimaryAdminUrl;
	config.ha.nodeName = originalNodeName;
	config.ha.fencedForPromotion = false;
	config.ha.authorityFence = null;
	await db`DELETE FROM session_relay_outbox`;
	await db`DELETE FROM ha_promotion_intent`;
}

afterEach(resetHaConfig);
afterAll(resetHaConfig);

async function sessionCookie(): Promise<string> {
	const user = await createAdminUser({ username: `cluster-status-${crypto.randomUUID()}`, password: "password123", role: "administrator" }, "test-suite");
	const { cookie } = await createAdminSession(new Request("http://admin.test/"), user.username, user.id, null, false);
	return cookie.split(";")[0]!;
}

async function memberSessionCookie(): Promise<string> {
	const user = await createAdminUser({ username: `cluster-status-member-${crypto.randomUUID()}`, password: "password123", role: "member" }, "test-suite");
	const { cookie } = await createAdminSession(new Request("http://admin.test/"), user.username, user.id, null, false);
	return cookie.split(";")[0]!;
}

function statusRequest(cookie: string): Request {
	return new Request("http://admin.test/_burrowgate/api/admin/ha/status", { headers: { cookie, "x-burrowgate-admin": "1" } });
}

describe("HA cluster admin API requires the administrator role", () => {
	test("GET /_burrowgate/api/admin/ha/status rejects a member admin", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		const response = await app.handle(statusRequest(await memberSessionCookie()));
		expect(response.status).toBe(403);
	});

	test("GET /_burrowgate/api/admin/ha/dead-letters rejects a member admin", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		const response = await app.handle(
			new Request("http://admin.test/_burrowgate/api/admin/ha/dead-letters", {
				headers: { cookie: await memberSessionCookie(), "x-burrowgate-admin": "1" },
			}),
		);
		expect(response.status).toBe(403);
	});
});

describe("GET /_burrowgate/api/admin/ha/status", () => {
	test("reports HA disabled when config.ha.enabled is false", async () => {
		config.ha.enabled = false;
		const response = await app.handle(statusRequest(await sessionCookie()));
		expect(await response.json()).toEqual({ enabled: false });
	});

	test("on a replica with a reachable primary, reports this node's OWN identity, not the primary's", async () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		config.ha.primaryAdminUrl = "https://primary.internal";
		config.ha.nodeName = "replica-node";
		globalThis.fetch = (async (url: unknown) => {
			expect(String(url)).toBe("https://primary.internal/_burrowgate/api/admin/ha/status");
			return Response.json({
				enabled: true,
				role: "primary",
				self: { name: "primary-node", version: "9.9.9" },
				nodes: [{ name: "other-replica", version: "9.9.9", connectedAt: 123 }],
			});
		}) as typeof fetch;

		const response = await app.handle(statusRequest(await sessionCookie()));
		const body = (await response.json()) as Record<string, unknown>;

		expect(body.role).toBe("replica");
		expect(body.self).toEqual({ name: "replica-node", version: APP_VERSION, selfAdminUrl: null });
		expect(body.primary).toEqual({ name: "primary-node", version: "9.9.9" });
		expect(body.nodes).toEqual([{ name: "other-replica", version: "9.9.9", connectedAt: 123 }]);
		expect(body.primaryReachable).toBe(true);
	});

	test("on a replica whose primary is itself (a pre-existing self-join), falls back to a local view after exactly one bounded hop", async () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		config.ha.primaryAdminUrl = "https://self-joined-node.test";
		config.ha.nodeName = "self-joined-node";
		let fetchCalls = 0;
		globalThis.fetch = (async (url: unknown, init?: RequestInit) => {
			fetchCalls += 1;
			return app.handle(new Request(String(url), init));
		}) as typeof fetch;

		const response = await app.handle(statusRequest(await sessionCookie()));
		const body = (await response.json()) as Record<string, unknown>;

		expect(fetchCalls).toBe(1);
		expect(response.status).toBe(200);
		expect(body.role).toBe("replica");
		expect(body.self).toEqual({ name: "self-joined-node", version: APP_VERSION, selfAdminUrl: null });
		expect(body.primaryReachable).toBe(false);
	});

	test("on a replica with an unreachable primary, falls back to a local-only view instead of erroring", async () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		config.ha.primaryAdminUrl = "https://primary.internal";
		config.ha.nodeName = "replica-node";
		globalThis.fetch = (async () => {
			throw new Error("simulated network failure");
		}) as unknown as typeof fetch;

		const response = await app.handle(statusRequest(await sessionCookie()));
		const body = (await response.json()) as Record<string, unknown>;

		expect(response.status).toBe(200);
		expect(body.role).toBe("replica");
		expect(body.self).toEqual({ name: "replica-node", version: APP_VERSION, selfAdminUrl: null });
		expect(body.primaryReachable).toBe(false);
	});

	test("a healthy primary with no promotion in progress reports fencedForPromotion false and no stuck intent", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		const response = await app.handle(statusRequest(await sessionCookie()));
		const body = (await response.json()) as Record<string, unknown>;
		expect(body.fencedForPromotion).toBe(false);
		expect(body.authorityFence).toBeNull();
		expect(body.stuckPromotionIntent).toBeNull();
	});

	test("a stale primary exposes its durable authority fence", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		const cookie = await sessionCookie();
		config.ha.authorityFence = { observedEpoch: 9, sourceNodeId: "new-primary-node", observedAt: 123456 };
		const response = await app.handle(statusRequest(cookie));
		const body = (await response.json()) as Record<string, unknown>;
		expect(body.authorityFence).toEqual({ observedEpoch: 9, sourceNodeId: "new-primary-node", observedAt: 123456 });
	});

	test("a primary durably fenced with an unresolved promotion intent reports it in stuckPromotionIntent", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";

		const cookie = await sessionCookie();
		config.ha.fencedForPromotion = true;
		await repository.saveHaPromotionIntent({
			promotion_id: "status-route-stuck-promotion",
			target_node_id: "status-route-stuck-target",
			target_url: "https://stuck-target.test:7443",
			target_admin_url: "https://stuck-target.test",
			new_epoch: 1,
			created_at: Date.now(),
		});
		const response = await app.handle(statusRequest(cookie));
		const body = (await response.json()) as Record<string, unknown>;
		expect(body.fencedForPromotion).toBe(true);
		expect(body.stuckPromotionIntent).toEqual({ promotionId: "status-route-stuck-promotion", targetNodeId: "status-route-stuck-target" });
	});

	test("on a replica, a stuck promotion intent forwarded from the primary is passed through", async () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		config.ha.primaryAdminUrl = "https://primary.internal";
		config.ha.nodeName = "replica-node";
		globalThis.fetch = (async () =>
			Response.json({
				enabled: true,
				role: "primary",
				self: { name: "primary-node", version: APP_VERSION },
				nodes: [],
				fencedForPromotion: true,
				stuckPromotionIntent: { promotionId: "forwarded-promotion", targetNodeId: "forwarded-target" },
			})) as unknown as typeof fetch;

		const response = await app.handle(statusRequest(await sessionCookie()));
		const body = (await response.json()) as Record<string, unknown>;
		expect(body.fencedForPromotion).toBe(true);
		expect(body.stuckPromotionIntent).toEqual({ promotionId: "forwarded-promotion", targetNodeId: "forwarded-target" });
	});
});
