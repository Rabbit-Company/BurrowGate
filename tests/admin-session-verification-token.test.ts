import { describe, expect, test } from "bun:test";
import { Web } from "@rabbit-company/web";
import { registerAdminRoutes } from "../src/routes/admin-routes.ts";
import { createAdminUser } from "../src/services/admin-user-service.ts";
import { createAdminSession } from "../src/services/session-service.ts";
import { createSite } from "../src/services/site-service.ts";

const app = new Web();
registerAdminRoutes(app);

describe("session verification token administration", () => {
	test("a site manager can generate and revoke the server-only token", async () => {
		const site = (
			await createSite({
				name: "Session token admin site",
				publicHost: `session-token-admin-${crypto.randomUUID()}.test`,
				originUrl: "http://origin.test",
			})
		).site;
		const manager = await createAdminUser(
			{
				username: `session-token-manager-${crypto.randomUUID()}`,
				password: "password123",
				role: "member",
				sitePermissions: [{ siteId: site.id, level: "manager" }],
			},
			"test-suite",
		);
		const { cookie } = await createAdminSession(new Request("http://admin.test/"), manager.username, manager.id);
		const headers = { cookie: cookie.split(";")[0]!, "x-burrowgate-admin": "1" };
		const endpoint = `http://admin.test/_burrowgate/api/admin/access-list/session-verification-token?siteId=${site.id}`;

		const generated = await app.handle(new Request(endpoint, { method: "POST", headers }));
		expect(generated.status).toBe(201);
		const generatedBody = (await generated.json()) as { token: string };
		expect(generatedBody.token).toStartWith("bgsv_");

		const list = await app.handle(
			new Request(`http://admin.test/_burrowgate/api/admin/access-list?siteId=${site.id}`, { headers: { cookie: headers.cookie } }),
		);
		expect(list.status).toBe(200);
		expect(await list.json()).toMatchObject({ settings: { sessionVerificationTokenEnabled: true } });

		const revoked = await app.handle(new Request(endpoint, { method: "DELETE", headers }));
		expect(revoked.status).toBe(200);
		expect(await revoked.json()).toEqual({ ok: true });
	});
});
