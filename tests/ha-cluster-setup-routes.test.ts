import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Web } from "@rabbit-company/web";
import { config } from "../src/config.ts";
import { db } from "../src/db/client.ts";
import { repository } from "../src/db/repository.ts";
import { registerHaClusterAdminRoutes } from "../src/routes/ha-cluster-admin-routes.ts";
import { haEnrollmentClient, loadHaClusterConfigAtBoot } from "../src/services/ha-config-service.ts";
import { haMeshService } from "../src/services/ha-mesh-service.ts";
import { processLifecycle } from "../src/services/process-lifecycle-service.ts";
import { createAdminUser } from "../src/services/admin-user-service.ts";
import { createAdminSession } from "../src/services/session-service.ts";
import { APP_VERSION } from "../src/ui/layout.ts";
import { sha256Hex } from "../src/utils/crypto.ts";

const mesh = haMeshService as unknown as {
	handlePrimaryMessage(ws: unknown, data: string): Promise<void>;
	loadRegisteredMembers(): Promise<void>;
	nodes: Map<unknown, unknown>;
	registeredMembers: Map<string, unknown>;
	offlineSince: Map<string, number>;
};

let restartCalls: string[] = [];
processLifecycle.gracefulRestart = (async (reason: string) => {
	restartCalls.push(reason);
}) as typeof processLifecycle.gracefulRestart;

const app = new Web();
registerHaClusterAdminRoutes(app);

const originalHa = { ...config.ha };
const originalDataDirectory = config.dataDirectory;
let tlsDataDirectory = "";

beforeEach(async () => {
	restartCalls = [];
	tlsDataDirectory = await mkdtemp(join(tmpdir(), "burrowgate-ha-routes-test-"));
	config.dataDirectory = tlsDataDirectory;
});

afterEach(async () => {
	Object.assign(config.ha, originalHa);
	config.dataDirectory = originalDataDirectory;
	await db`DELETE FROM ha_cluster_config`;
	await db`DELETE FROM ha_promotion_intent`;
	await db`DELETE FROM ha_cluster_members`;
	mesh.nodes.clear();
	mesh.registeredMembers.clear();
	if (tlsDataDirectory) await rm(tlsDataDirectory, { recursive: true, force: true });
});

async function administratorCookie(): Promise<string> {
	const user = await createAdminUser({ username: `ha-setup-admin-${crypto.randomUUID()}`, password: "password123", role: "administrator" }, "test-suite");
	const { cookie } = await createAdminSession(new Request("http://admin.test/"), user.username, user.id, null, false);
	return cookie.split(";")[0]!;
}

async function memberCookie(): Promise<string> {
	const user = await createAdminUser({ username: `ha-setup-member-${crypto.randomUUID()}`, password: "password123", role: "member" }, "test-suite");
	const { cookie } = await createAdminSession(new Request("http://admin.test/"), user.username, user.id, null, false);
	return cookie.split(";")[0]!;
}

function req(path: string, cookie?: string, init: RequestInit = {}): Request {
	const headers: Record<string, string> = { ...(init.headers as Record<string, string>) };
	if (cookie) headers.cookie = cookie;
	if (init.method && init.method !== "GET") headers["x-burrowgate-admin"] = "1";
	return new Request(`http://admin.test/_burrowgate/api/admin/ha${path}`, { ...init, headers });
}

async function freshPrimaryNode(): Promise<void> {
	config.ha.enabled = true;
	config.ha.role = "primary";
	await loadHaClusterConfigAtBoot();
}

describe("PUT /ha/identity", () => {
	test("requires authentication", async () => {
		const response = await app.handle(req("/identity", undefined, { method: "PUT" }));
		expect(response.status).toBe(401);
	});

	test("requires administrator role, not just any admin member", async () => {
		await freshPrimaryNode();
		const response = await app.handle(
			req("/identity", await memberCookie(), {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ selfAdminUrl: "https://a.test" }),
			}),
		);
		expect(response.status).toBe(403);
	});

	test("rejects a mutating request without the CSRF header", async () => {
		await freshPrimaryNode();
		const cookie = await administratorCookie();
		const response = await app.handle(
			new Request("http://admin.test/_burrowgate/api/admin/ha/identity", {
				method: "PUT",
				headers: { cookie, "content-type": "application/json" },
				body: JSON.stringify({ selfAdminUrl: "https://a.test" }),
			}),
		);
		expect(response.status).toBe(403);
	});

	test("rejects a missing selfAdminUrl", async () => {
		await freshPrimaryNode();
		const cookie = await administratorCookie();
		const response = await app.handle(req("/identity", cookie, { method: "PUT", headers: { "content-type": "application/json" }, body: "{}" }));
		expect(response.status).toBe(400);
	});

	test("updates this node's identity immediately, with no restart", async () => {
		await freshPrimaryNode();
		const cookie = await administratorCookie();
		const response = await app.handle(
			req("/identity", cookie, {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ selfAdminUrl: "https://primary-node.test", nodeName: "route-test-primary" }),
			}),
		);
		expect(response.status).toBe(200);
		expect(config.ha.selfAdminUrl).toBe("https://primary-node.test");
		expect(config.ha.nodeName).toBe("route-test-primary");

		await new Promise((resolve) => setTimeout(resolve, 350));
		expect(restartCalls).toEqual([]);
	});

	test("also works on an existing replica - it's an identity edit, not a role change", async () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		config.ha.sharedToken = "replica-token";
		config.ha.primaryUrl = "https://primary.test:7443";
		config.ha.primaryAdminUrl = "https://primary.test";
		await loadHaClusterConfigAtBoot();
		const cookie = await administratorCookie();
		const response = await app.handle(
			req("/identity", cookie, {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ selfAdminUrl: "https://this-replica.test" }),
			}),
		);
		expect(response.status).toBe(200);
		const roleAfter: string = config.ha.role;
		expect(roleAfter).toBe("replica");
		expect(config.ha.selfAdminUrl).toBe("https://this-replica.test");
	});
});

describe("POST /ha/join", () => {
	test("requires authentication", async () => {
		const response = await app.handle(req("/join", undefined, { method: "POST" }));
		expect(response.status).toBe(401);
	});

	test("rejects a garbled join code", async () => {
		await freshPrimaryNode();
		const cookie = await administratorCookie();
		const response = await app.handle(
			req("/join", cookie, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ joinCode: "not-a-real-code", selfAdminUrl: "https://replica.test" }),
			}),
		);
		expect(response.status).toBe(400);
	});

	test("joins a cluster given a valid join code and schedules a restart, even though this node was already a (self-)primary", async () => {
		await freshPrimaryNode();
		const primaryAdminCookie = await administratorCookie();
		await app.handle(
			req("/identity", primaryAdminCookie, {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ selfAdminUrl: "https://primary-for-join-test.test" }),
			}),
		);

		const originalHaNodeId = repository.haNodeId;
		repository.haNodeId = async () => "simulated-join-test-primary-node-id";
		const joinCodeResponse = await app.handle(req("/join-code", primaryAdminCookie, { method: "POST" }));
		repository.haNodeId = originalHaNodeId;
		const { joinCode } = (await joinCodeResponse.json()) as { joinCode: string };

		const primaryToken = config.ha.sharedToken;

		const cookie = await administratorCookie();
		const originalRedeem = haEnrollmentClient.redeem;
		haEnrollmentClient.redeem = async () => primaryToken!;
		const response = await app.handle(
			req("/join", cookie, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ joinCode, selfAdminUrl: "https://replica-for-join-test.test" }),
			}),
		);
		haEnrollmentClient.redeem = originalRedeem;
		expect(response.status).toBe(200);
		expect(config.ha.enabled).toBe(true);
		const roleAfter: string = config.ha.role;
		expect(roleAfter).toBe("replica");
		expect(config.ha.primaryAdminUrl).toBe("https://primary-for-join-test.test");

		await new Promise((resolve) => setTimeout(resolve, 350));
		expect(restartCalls).toContain("ha-config-changed");
	});
});

describe("POST /ha/leave", () => {
	test("requires authentication", async () => {
		const response = await app.handle(req("/leave", undefined, { method: "POST" }));
		expect(response.status).toBe(401);
	});

	test("requires administrator role, not just any admin member", async () => {
		await freshPrimaryNode();
		const response = await app.handle(req("/leave", await memberCookie(), { method: "POST" }));
		expect(response.status).toBe(403);
	});

	test("rejects a mutating request without the CSRF header", async () => {
		const cookie = await administratorCookie();
		const response = await app.handle(new Request("http://admin.test/_burrowgate/api/admin/ha/leave", { method: "POST", headers: { cookie } }));
		expect(response.status).toBe(403);
	});

	test("refuses on a node that is not a replica", async () => {
		await freshPrimaryNode();
		const response = await app.handle(req("/leave", await administratorCookie(), { method: "POST" }));
		expect(response.status).toBe(400);
		expect(((await response.json()) as { error: string }).error).toContain("nothing to leave");
	});

	test("turns a replica back into a standalone primary and schedules a restart", async () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		config.ha.sharedToken = "replica-token";
		config.ha.primaryUrl = "https://primary.test:7443";
		config.ha.primaryAdminUrl = "https://primary.test";
		config.ha.nodeName = "leaving-route-node";
		config.ha.selfAdminUrl = "https://leaving-route-node.test";
		await loadHaClusterConfigAtBoot();

		const response = await app.handle(req("/leave", await administratorCookie(), { method: "POST" }));
		expect(response.status).toBe(200);
		const roleAfter: string = config.ha.role;
		expect(roleAfter).toBe("primary");
		expect(config.ha.primaryUrl).toBeNull();
		expect(config.ha.primaryAdminUrl).toBeNull();
		expect(config.ha.nodeName).toBe("leaving-route-node");

		await new Promise((resolve) => setTimeout(resolve, 350));
		expect(restartCalls).toContain("ha-config-changed");
	});
});

describe("POST /ha/join-code", () => {
	test("requires authentication", async () => {
		const response = await app.handle(req("/join-code", undefined, { method: "POST" }));
		expect(response.status).toBe(401);
	});

	test("requires administrator role", async () => {
		await freshPrimaryNode();
		const response = await app.handle(req("/join-code", await memberCookie(), { method: "POST" }));
		expect(response.status).toBe(403);
	});

	test("rejects a mutating request without the CSRF header", async () => {
		await freshPrimaryNode();
		const response = await app.handle(
			new Request("http://admin.test/_burrowgate/api/admin/ha/join-code", {
				method: "POST",
				headers: { cookie: await administratorCookie() },
			}),
		);
		expect(response.status).toBe(403);
	});

	test("refuses on a node that is not the primary", async () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		config.ha.sharedToken = "replica-token";
		config.ha.primaryUrl = "https://primary.test:7443";
		config.ha.primaryAdminUrl = "https://primary.test";
		await loadHaClusterConfigAtBoot();
		const response = await app.handle(req("/join-code", await administratorCookie(), { method: "POST" }));
		expect(response.status).toBe(400);
	});

	test("returns a decodable join code on the primary", async () => {
		await freshPrimaryNode();
		const cookie = await administratorCookie();
		await app.handle(
			req("/identity", cookie, {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ selfAdminUrl: "https://view-code-primary.test" }),
			}),
		);
		const response = await app.handle(req("/join-code", cookie, { method: "POST" }));
		expect(response.status).toBe(200);
		const { joinCode } = (await response.json()) as { joinCode: string };
		expect(typeof joinCode).toBe("string");
		expect(joinCode.length).toBeGreaterThan(0);
	});
});

describe("DELETE /ha/nodes/:nodeId", () => {
	test("forgets an offline durable member and clears its version fence", async () => {
		await freshPrimaryNode();
		const now = Date.now();
		await repository.upsertHaClusterMember({
			node_id: "decommissioned-old-node",
			name: "decommissioned node",
			version: "0.0.1",
			admin_url: "https://decommissioned.test",
			first_seen_at: now,
			last_seen_at: now,
			credential_hash: await sha256Hex("decommissioned-old-node-credential"),
		});
		await mesh.loadRegisteredMembers();
		expect(config.ha.versionMismatchNodes).toHaveLength(1);

		mesh.offlineSince.set("decommissioned-old-node", Date.now() - 3_600_000);

		const response = await app.handle(req("/nodes/decommissioned-old-node", await administratorCookie(), { method: "DELETE" }));

		expect(response.status).toBe(200);
		expect(config.ha.versionMismatchNodes).toEqual([]);
		expect((await repository.haClusterMembers()).some((member) => member.node_id === "decommissioned-old-node")).toBe(false);
	});
});

describe("POST /ha/promote/:nodeId", () => {
	afterEach(() => {
		mesh.nodes.clear();
	});

	test("requires authentication", async () => {
		const response = await app.handle(req("/promote/some-node", undefined, { method: "POST" }));
		expect(response.status).toBe(401);
	});

	test("requires administrator role, not just any admin member", async () => {
		await freshPrimaryNode();
		const response = await app.handle(req("/promote/some-node", await memberCookie(), { method: "POST" }));
		expect(response.status).toBe(403);
	});

	test("rejects a mutating request without the CSRF header", async () => {
		const cookie = await administratorCookie();
		const response = await app.handle(new Request("http://admin.test/_burrowgate/api/admin/ha/promote/some-node", { method: "POST", headers: { cookie } }));
		expect(response.status).toBe(403);
	});

	test("refuses when this node is not the primary and there is no reachable primary to forward to", async () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		config.ha.sharedToken = "replica-token";
		config.ha.primaryUrl = "https://primary.test:7443";
		config.ha.primaryAdminUrl = null;
		const response = await app.handle(req("/promote/some-node", await administratorCookie(), { method: "POST" }));
		expect(response.status).toBe(500);
		expect(((await response.json()) as { error: string }).error).toContain("misconfigured");
	});

	test("rejects a target that is not currently connected", async () => {
		await freshPrimaryNode();
		const cookie = await administratorCookie();
		await app.handle(
			req("/identity", cookie, {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ selfAdminUrl: "https://promote-route-primary.test" }),
			}),
		);
		const response = await app.handle(req("/promote/never-connected", cookie, { method: "POST" }));
		expect(response.status).toBe(400);
		expect(((await response.json()) as { error: string }).error).toContain("not currently connected");
	});

	test("promotes a connected node and records an audit entry", async () => {
		await freshPrimaryNode();
		const cookie = await administratorCookie();
		await app.handle(
			req("/identity", cookie, {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ selfAdminUrl: "https://promote-route-primary-2.test" }),
			}),
		);

		const ws = {
			send: (data: string) => {
				const message = JSON.parse(data) as { type: string; promotionId?: string };
				if (message.type === "prepare_promote") {
					void mesh.handlePrimaryMessage(
						ws,
						JSON.stringify({ type: "prepare_promote_ack", cursor: Number.MAX_SAFE_INTEGER, promotionId: message.promotionId }),
					);
				} else if (message.type === "promote") {
					void mesh.handlePrimaryMessage(ws, JSON.stringify({ type: "promote_applied_ack", promotionId: message.promotionId, success: true }));
				}
			},
			close: () => {},
			data: { authenticatedNodeId: "route-promote-target", authenticatedActive: true },
		};
		await mesh.handlePrimaryMessage(
			ws,
			JSON.stringify({ type: "announce", nodeId: "route-promote-target", name: "target", version: APP_VERSION, adminUrl: "https://route-promote-target.test" }),
		);

		const response = await app.handle(req("/promote/route-promote-target", cookie, { method: "POST" }));
		expect(response.status).toBe(200);
		const roleAfter: string = config.ha.role;
		expect(roleAfter).toBe("replica");
		expect(config.ha.primaryAdminUrl).toBe("https://route-promote-target.test");

		await new Promise((resolve) => setTimeout(resolve, 350));
		expect(restartCalls).toContain("ha-promote");
	});
});
