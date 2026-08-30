import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { Web } from "@rabbit-company/web";
import { config } from "../src/config.ts";
import { db } from "../src/db/client.ts";
import { repository } from "../src/db/repository.ts";
import { registerAdminRoutes } from "../src/routes/admin-routes.ts";
import { createAdminSession } from "../src/services/session-service.ts";
import { createAdminUser } from "../src/services/admin-user-service.ts";
import { sha256Hex } from "../src/utils/crypto.ts";

const app = new Web();
registerAdminRoutes(app);

const originalEnabled = config.ha.enabled;
const originalRole = config.ha.role;
const originalToken = config.ha.sharedToken;

beforeEach(async () => {
	const now = Date.now();
	await repository.upsertHaClusterMember({
		node_id: "resolve-session-route-test-caller",
		name: "resolve-session-route-test-caller",
		version: "1.0.0",
		admin_url: null,
		first_seen_at: now,
		last_seen_at: now,
		credential_hash: await sha256Hex("test-shared-token"),
	});
});

afterEach(async () => {
	config.ha.enabled = originalEnabled;
	config.ha.role = originalRole;
	config.ha.sharedToken = originalToken;
	await db`DELETE FROM ha_cluster_members WHERE node_id='resolve-session-route-test-caller'`;
});

function request(body: unknown, token = "test-shared-token"): Request {
	return new Request("http://primary.test/_burrowgate/api/admin/ha/resolve-admin-session", {
		method: "POST",
		headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
		body: JSON.stringify(body),
	});
}

describe("POST /_burrowgate/api/admin/ha/resolve-admin-session", () => {
	test("404s when HA is disabled", async () => {
		config.ha.enabled = false;
		const response = await app.handle(request({ tokenHash: "a".repeat(64) }));
		expect(response.status).toBe(404);
	});

	test("401s without a valid bearer token", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		config.ha.sharedToken = "test-shared-token";
		const response = await app.handle(request({ tokenHash: "a".repeat(64) }, "wrong-token"));
		expect(response.status).toBe(401);
	});

	test("400s when this node is not the primary - only the primary is authoritative", async () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		config.ha.sharedToken = "test-shared-token";
		const response = await app.handle(request({ tokenHash: "a".repeat(64) }));
		expect(response.status).toBe(400);
	});

	test("400s on a malformed token hash instead of querying with it", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		config.ha.sharedToken = "test-shared-token";
		const response = await app.handle(request({ tokenHash: "not-a-real-hash" }));
		expect(response.status).toBe(400);
	});

	test("returns session: null for an unknown token hash, not a 404 or error", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		config.ha.sharedToken = "test-shared-token";
		const response = await app.handle(request({ tokenHash: "0".repeat(64) }));
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ session: null });
	});

	test("returns the session for a valid, unexpired token hash", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		config.ha.sharedToken = "test-shared-token";
		const user = await createAdminUser({ username: `resolve-session-${crypto.randomUUID()}`, password: "password123", role: "administrator" }, "test-suite");
		const { token } = await createAdminSession(new Request("http://admin.test/"), user.username, user.id, null, false);
		const tokenHash = await sha256Hex(token);

		const response = await app.handle(request({ tokenHash }));
		expect(response.status).toBe(200);
		const body = (await response.json()) as { session: { token_hash: string; username: string } | null };
		expect(body.session?.token_hash).toBe(tokenHash);
		expect(body.session?.username).toBe(user.username);
	});
});
