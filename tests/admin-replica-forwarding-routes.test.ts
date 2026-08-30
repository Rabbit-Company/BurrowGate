import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Web } from "@rabbit-company/web";
import { config } from "../src/config.ts";
import { registerAdminRoutes } from "../src/routes/admin-routes.ts";
import { pinPrimaryHaCertificate } from "../src/services/ha-tls-service.ts";
import { createAdminSession } from "../src/services/session-service.ts";
import { createAdminUser } from "../src/services/admin-user-service.ts";
import { createSite } from "../src/services/site-service.ts";

const app = new Web();
registerAdminRoutes(app);

const originalEnabled = config.ha.enabled;
const originalRole = config.ha.role;
const originalPrimaryAdminUrl = config.ha.primaryAdminUrl;

afterEach(() => {
	config.ha.enabled = originalEnabled;
	config.ha.role = originalRole;
	config.ha.primaryAdminUrl = originalPrimaryAdminUrl;
});

async function sessionCookie(): Promise<string> {
	const user = await createAdminUser({ username: `replica-fwd-${crypto.randomUUID()}`, password: "password123", role: "administrator" }, "test-suite");
	const { cookie } = await createAdminSession(new Request("http://admin.test/"), user.username, user.id, null, false);
	return cookie.split(";")[0]!;
}

function asReplicaWithNoPrimary(): void {
	config.ha.enabled = true;
	config.ha.role = "replica";
	config.ha.primaryAdminUrl = null;
}

describe("replica forwarding on routes an audit found missing it", () => {
	test("PUT .../sites/:id/notification-policy forwards instead of hitting the local write guard", async () => {
		const site = (await createSite({ name: "Replica fwd site", publicHost: `replica-fwd-${crypto.randomUUID()}.test`, originUrl: "https://origin.test" })).site;
		const cookie = await sessionCookie();
		asReplicaWithNoPrimary();

		const response = await app.handle(
			new Request(`http://admin.test/_burrowgate/api/admin/sites/${site.id}/notification-policy`, {
				method: "PUT",
				headers: { cookie, "content-type": "application/json", "x-burrowgate-admin": "1" },
				body: JSON.stringify({}),
			}),
		);

		expect(response.status).toBe(500);
		expect(((await response.json()) as { error: string }).error).toContain("misconfigured");
	});

	test("POST .../access-list/session-verification-token forwards instead of hitting the local write guard", async () => {
		const site = (await createSite({ name: "Replica fwd site 2", publicHost: `replica-fwd-2-${crypto.randomUUID()}.test`, originUrl: "https://origin.test" }))
			.site;
		const cookie = await sessionCookie();
		asReplicaWithNoPrimary();

		const response = await app.handle(
			new Request(`http://admin.test/_burrowgate/api/admin/access-list/session-verification-token?siteId=${site.id}`, {
				method: "POST",
				headers: { cookie, "x-burrowgate-admin": "1" },
			}),
		);

		expect(response.status).toBe(500);
		expect(((await response.json()) as { error: string }).error).toContain("misconfigured");
	});

	test("DELETE .../access-list/session-verification-token forwards instead of hitting the local write guard", async () => {
		const site = (await createSite({ name: "Replica fwd site 3", publicHost: `replica-fwd-3-${crypto.randomUUID()}.test`, originUrl: "https://origin.test" }))
			.site;
		const cookie = await sessionCookie();
		asReplicaWithNoPrimary();

		const response = await app.handle(
			new Request(`http://admin.test/_burrowgate/api/admin/access-list/session-verification-token?siteId=${site.id}`, {
				method: "DELETE",
				headers: { cookie, "x-burrowgate-admin": "1" },
			}),
		);

		expect(response.status).toBe(500);
		expect(((await response.json()) as { error: string }).error).toContain("misconfigured");
	});
});

describe("forwarding verifies the primary's admin URL against the pinned HA certificate", () => {
	const originalFetch = globalThis.fetch;
	const originalDataDirectory = config.dataDirectory;

	afterEach(async () => {
		globalThis.fetch = originalFetch;
		config.dataDirectory = originalDataDirectory;
	});

	test("uses the pinned certificate, not the system CA store, once one is pinned", async () => {
		const tempDir = await mkdtemp(join(tmpdir(), "bg-ha-forward-tls-test-"));
		config.dataDirectory = tempDir;
		try {
			const site = (
				await createSite({ name: "Replica fwd TLS site", publicHost: `replica-fwd-tls-${crypto.randomUUID()}.test`, originUrl: "https://origin.test" })
			).site;
			const cookie = await sessionCookie();
			config.ha.enabled = true;
			config.ha.role = "replica";
			config.ha.primaryAdminUrl = "https://primary.internal";
			await pinPrimaryHaCertificate("pinned-primary-admin-certificate");
			let capturedTls: unknown;
			globalThis.fetch = (async (_url: unknown, init?: RequestInit) => {
				capturedTls = (init as (RequestInit & { tls?: unknown }) | undefined)?.tls;
				return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
			}) as unknown as typeof fetch;

			await app.handle(
				new Request(`http://admin.test/_burrowgate/api/admin/sites/${site.id}/notification-policy`, {
					method: "PUT",
					headers: { cookie, "content-type": "application/json", "x-burrowgate-admin": "1" },
					body: JSON.stringify({}),
				}),
			);

			expect(capturedTls).toMatchObject({ ca: "pinned-primary-admin-certificate", checkServerIdentity: expect.any(Function) });
		} finally {
			await rm(tempDir, { recursive: true, force: true });
		}
	});
});
