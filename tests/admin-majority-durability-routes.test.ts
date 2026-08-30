import { afterEach, describe, expect, test } from "bun:test";
import { Web } from "@rabbit-company/web";
import { config } from "../src/config.ts";
import { db } from "../src/db/client.ts";
import { repository } from "../src/db/repository.ts";
import { registerAdminRoutes } from "../src/routes/admin-routes.ts";
import { createAdminUser } from "../src/services/admin-user-service.ts";
import { haMeshService } from "../src/services/ha-mesh-service.ts";
import { createAdminSession } from "../src/services/session-service.ts";
import { APP_VERSION } from "../src/ui/layout.ts";
import { sha256Hex } from "../src/utils/crypto.ts";

const app = new Web();
registerAdminRoutes(app);

const mesh = haMeshService as unknown as { nodes: Map<unknown, unknown> };

const originalEnabled = config.ha.enabled;
const originalRole = config.ha.role;

afterEach(async () => {
	config.ha.enabled = originalEnabled;
	config.ha.role = originalRole;
	mesh.nodes.clear();
	await db`DELETE FROM ha_cluster_members`;
});

async function sessionCookie(): Promise<string> {
	const user = await createAdminUser({ username: `durability-route-${crypto.randomUUID()}`, password: "password123", role: "administrator" }, "test-suite");
	const { cookie } = await createAdminSession(new Request("http://admin.test/"), user.username, user.id, null, false);
	return cookie.split(";")[0]!;
}

async function seedThreeMembers(): Promise<void> {
	const selfNodeId = await repository.haNodeId();
	const now = Date.now();
	for (const nodeId of [selfNodeId, "durability-route-peer-1", "durability-route-peer-2"]) {
		await repository.upsertHaClusterMember({
			node_id: nodeId,
			name: nodeId,
			version: APP_VERSION,
			admin_url: `https://${nodeId}.test`,
			first_seen_at: now,
			last_seen_at: now,
			credential_hash: await sha256Hex(`${nodeId}-credential`),
			activated_at: now,
		});
	}
}

function createSitePayload(): Record<string, unknown> {
	return { name: `Durability route site ${crypto.randomUUID()}`, publicHost: `durability-route-${crypto.randomUUID()}.test`, originUrl: "https://origin.test" };
}

describe("majority-durability confirmation on a real admin route (POST /sites)", () => {
	test("reports durabilityConfirmed:true once a majority (self + an acked replica) is reached", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		await seedThreeMembers();
		mesh.nodes.set(
			{ send: () => {}, close: () => {} },
			{
				nodeId: "durability-route-peer-1",
				name: "durability-route-peer-1",
				version: APP_VERSION,
				connectedAt: Date.now(),
				connected: true,
				lastSeenAt: Date.now(),
				adminUrl: "https://durability-route-peer-1.test",
				lastAckedSeq: Number.MAX_SAFE_INTEGER,
			},
		);
		const cookie = await sessionCookie();

		const response = await app.handle(
			new Request("http://admin.test/_burrowgate/api/admin/sites", {
				method: "POST",
				headers: { cookie, "content-type": "application/json", "x-burrowgate-admin": "1" },
				body: JSON.stringify(createSitePayload()),
			}),
		);

		expect(response.status).toBe(201);
		const body = (await response.json()) as { durabilityConfirmed?: boolean };
		expect(body.durabilityConfirmed).toBe(true);
	});

	test("reports durabilityConfirmed:false when no replica has acked in time, without failing the request", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		await seedThreeMembers();
		const cookie = await sessionCookie();

		const response = await app.handle(
			new Request("http://admin.test/_burrowgate/api/admin/sites", {
				method: "POST",
				headers: { cookie, "content-type": "application/json", "x-burrowgate-admin": "1" },
				body: JSON.stringify(createSitePayload()),
			}),
		);

		expect(response.status).toBe(201);
		const body = (await response.json()) as { durabilityConfirmed?: boolean; site?: { id: string } };
		expect(body.durabilityConfirmed).toBe(false);
		expect(body.site?.id).toBeTruthy();
	}, 10_000);
});
