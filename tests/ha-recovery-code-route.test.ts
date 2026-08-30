import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { Web } from "@rabbit-company/web";
import { config } from "../src/config.ts";
import { db } from "../src/db/client.ts";
import { repository } from "../src/db/repository.ts";
import { registerAdminRoutes } from "../src/routes/admin-routes.ts";
import { createAdminUser } from "../src/services/admin-user-service.ts";
import { sha256Hex, randomId } from "../src/utils/crypto.ts";

const app = new Web();
registerAdminRoutes(app);

const originalEnabled = config.ha.enabled;
const originalRole = config.ha.role;
const originalToken = config.ha.sharedToken;

beforeEach(async () => {
	const now = Date.now();
	await repository.upsertHaClusterMember({
		node_id: "recovery-route-test-caller",
		name: "recovery-route-test-caller",
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
	await db`DELETE FROM ha_cluster_members WHERE node_id='recovery-route-test-caller'`;
});

function request(body: unknown, token = "test-shared-token"): Request {
	return new Request("http://primary.test/_burrowgate/api/admin/ha/consume-recovery-code", {
		method: "POST",
		headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
		body: JSON.stringify(body),
	});
}

describe("POST /_burrowgate/api/admin/ha/consume-recovery-code", () => {
	test("404s when HA is disabled", async () => {
		config.ha.enabled = false;
		const response = await app.handle(request({ userId: "x", codeHash: "y" }));
		expect(response.status).toBe(404);
	});

	test("401s without a valid bearer token", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		config.ha.sharedToken = "test-shared-token";
		const response = await app.handle(request({ userId: "x", codeHash: "y" }, "wrong-token"));
		expect(response.status).toBe(401);
	});

	test("400s when this node is not the primary - a replica must never locally serialize consumption", async () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		config.ha.sharedToken = "test-shared-token";
		const response = await app.handle(request({ userId: "x", codeHash: "y" }));
		expect(response.status).toBe(400);
	});

	test("consumes an unused code exactly once on the primary", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		config.ha.sharedToken = "test-shared-token";
		const user = await createAdminUser({ username: `ha-recovery-${crypto.randomUUID()}`, password: "password123", role: "administrator" }, "test-suite");
		const plaintext = randomId("recovery");
		const hash = await sha256Hex(plaintext);
		await repository.replaceAdminRecoveryCodes(user.id, [
			{ id: randomId("admin_rc"), user_id: user.id, code_hash: hash, created_at: Date.now(), used_at: null },
		]);

		const first = await app.handle(request({ userId: user.id, codeHash: hash }));
		expect(first.status).toBe(200);
		expect(await first.json()).toEqual({ consumed: true });

		const second = await app.handle(request({ userId: user.id, codeHash: hash }));
		expect(await second.json()).toEqual({ consumed: false });
	});
});
