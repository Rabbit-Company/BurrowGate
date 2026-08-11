import { describe, expect, test } from "bun:test";
import { Web } from "@rabbit-company/web";
import { registerAdminRoutes } from "../src/routes/admin-routes.ts";
import { createAccessUser } from "../src/services/access-list-service.ts";
import { createAdminSession } from "../src/services/session-service.ts";
import { createAdminUser } from "../src/services/admin-user-service.ts";
import { createSite } from "../src/services/site-service.ts";

const app = new Web();
registerAdminRoutes(app);

async function sessionCookie(username: string, userId: string): Promise<string> {
	const { cookie } = await createAdminSession(new Request("http://admin.test/"), username, userId);
	return cookie.split(";")[0]!;
}

function importRequest(siteId: string, cookie: string, userIds: string[]): Request {
	return new Request(`http://admin.test/_burrowgate/api/admin/access-list/import?siteId=${siteId}`, {
		method: "POST",
		headers: { cookie, "content-type": "application/json", "x-burrowgate-admin": "1" },
		body: JSON.stringify({ userIds }),
	});
}

describe("access-list import requires manage permission on the target site", () => {
	test("a member with only view access is forbidden from importing users", async () => {
		const site = (
			await createSite({ name: "Import perms viewer site", publicHost: `import-view-${crypto.randomUUID()}.test`, originUrl: "http://origin.test" })
		).site;
		const source = (
			await createSite({ name: "Import perms source A", publicHost: `import-src-a-${crypto.randomUUID()}.test`, originUrl: "http://origin2.test" })
		).site;
		const importable = await createAccessUser(source.id, { username: `importable-a-${crypto.randomUUID()}`, password: "password123" });
		const viewer = await createAdminUser(
			{ username: `viewer-${crypto.randomUUID()}`, password: "password123", role: "member", sitePermissions: [{ siteId: site.id, level: "viewer" }] },
			"test-suite",
		);
		const cookie = await sessionCookie(viewer.username, viewer.id);

		const response = await app.handle(importRequest(site.id, cookie, [importable.id]));

		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "Forbidden" });
	});

	test("a member with manage access can import users", async () => {
		const site = (
			await createSite({ name: "Import perms manager site", publicHost: `import-mgr-${crypto.randomUUID()}.test`, originUrl: "http://origin.test" })
		).site;
		const source = (
			await createSite({ name: "Import perms source B", publicHost: `import-src-b-${crypto.randomUUID()}.test`, originUrl: "http://origin2.test" })
		).site;
		const importable = await createAccessUser(source.id, { username: `importable-b-${crypto.randomUUID()}`, password: "password123" });
		const manager = await createAdminUser(
			{ username: `manager-${crypto.randomUUID()}`, password: "password123", role: "member", sitePermissions: [{ siteId: site.id, level: "manager" }] },
			"test-suite",
		);
		const cookie = await sessionCookie(manager.username, manager.id);

		const response = await app.handle(importRequest(site.id, cookie, [importable.id]));

		expect(response.status).toBe(201);
		expect(await response.json()).toEqual({ imported: 1 });
	});
});
