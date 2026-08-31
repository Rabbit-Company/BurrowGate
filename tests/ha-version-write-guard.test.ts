import { afterEach, describe, expect, test } from "bun:test";
import { config } from "../src/config.ts";
import { haVersionWriteGuard } from "../src/routes/ha-version-write-guard.ts";
import { APP_VERSION } from "../src/ui/layout.ts";
import { Web } from "@rabbit-company/web";

const originalHa = { ...config.ha };

afterEach(() => Object.assign(config.ha, originalHa));

describe("HA cluster version admin-write guard", () => {
	test("returns a structured conflict for a primary admin mutation while a member version differs", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		config.ha.versionMismatchNodes = [{ nodeId: "old-node", name: "old replica", version: "0.0.1" }];
		const response = haVersionWriteGuard(new Request("https://primary.test/_burrowgate/api/admin/sites", { method: "POST" }));
		expect(response?.status).toBe(409);
		expect(await response!.json()).toEqual({
			error: "Cluster configuration is read-only until every registered BurrowGate node runs the same version as the primary",
			code: "cluster_version_mismatch",
			primaryVersion: APP_VERSION,
			mismatchedNodes: [{ nodeId: "old-node", name: "old replica", version: "0.0.1" }],
		});
	});

	test("allows reads, replica forwarding, and recovery operations", () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		config.ha.versionMismatchNodes = [{ nodeId: "old-node", name: "old replica", version: "0.0.1" }];
		expect(haVersionWriteGuard(new Request("https://primary.test/_burrowgate/api/admin/sites"))).toBeNull();
		expect(haVersionWriteGuard(new Request("https://primary.test/_burrowgate/api/admin/logs/settings", { method: "PUT" }))).toBeNull();
		expect(haVersionWriteGuard(new Request("https://primary.test/_burrowgate/api/admin/ha/nodes/old-node", { method: "DELETE" }))).toBeNull();
		expect(haVersionWriteGuard(new Request("https://primary.test/_burrowgate/api/admin/ha/leave", { method: "POST" }))).toBeNull();
		config.ha.role = "replica";
		expect(haVersionWriteGuard(new Request("https://replica.test/_burrowgate/api/admin/sites", { method: "POST" }))).toBeNull();
	});

	test("the admin API prefix middleware blocks a real nested route before its handler runs", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		config.ha.versionMismatchNodes = [{ nodeId: "old-node", name: "old replica", version: "0.0.1" }];
		let routeRan = false;
		const app = new Web();
		app.use(async (ctx, next) => {
			const blocked = haVersionWriteGuard(ctx.req);
			if (blocked) return blocked;
			await next();
		});
		app.post("/_burrowgate/api/admin/sites", () => {
			routeRan = true;
			return Response.json({ ok: true });
		});

		const response = await app.handle(new Request("https://primary.test/_burrowgate/api/admin/sites", { method: "POST" }));
		expect(response.status).toBe(409);
		expect(routeRan).toBe(false);
	});
});
