import { afterEach, describe, expect, test } from "bun:test";
import { Web } from "@rabbit-company/web";
import { repository } from "../src/db/repository.ts";
import { registerFirewallSyncAdminRoutes } from "../src/routes/firewall-sync-admin-routes.ts";
import { createAdminUser } from "../src/services/admin-user-service.ts";
import { createAdminSession } from "../src/services/session-service.ts";

const app = new Web();
registerFirewallSyncAdminRoutes(app);

afterEach(async () => {
	for (const provider of await repository.allFirewallSyncProviders()) await repository.deleteFirewallSyncProvider(provider.id);
	for (const entry of await repository.allFirewallSyncWhitelistCidrs()) await repository.deleteFirewallSyncWhitelistCidr(entry.id);
});

async function administratorCookie(): Promise<string> {
	const user = await createAdminUser({ username: `fw-admin-${crypto.randomUUID()}`, password: "password123", role: "administrator" }, "test-suite");
	const { cookie } = await createAdminSession(new Request("http://admin.test/"), user.username, user.id);
	return cookie.split(";")[0]!;
}

async function memberCookie(): Promise<string> {
	const user = await createAdminUser({ username: `fw-member-${crypto.randomUUID()}`, password: "password123", role: "member" }, "test-suite");
	const { cookie } = await createAdminSession(new Request("http://admin.test/"), user.username, user.id);
	return cookie.split(";")[0]!;
}

function req(path: string, cookie?: string, init: RequestInit = {}): Request {
	const headers: Record<string, string> = { ...(init.headers as Record<string, string>) };
	if (cookie) headers.cookie = cookie;
	if (init.method && init.method !== "GET") headers["x-burrowgate-admin"] = "1";
	return new Request(`http://admin.test/_burrowgate/api/admin/firewall-sync${path}`, { ...init, headers });
}

describe("firewall sync provider routes", () => {
	test("requires authentication", async () => {
		const response = await app.handle(req("/providers"));
		expect(response.status).toBe(401);
	});

	test("requires administrator role, not just any admin member", async () => {
		const cookie = await memberCookie();
		const response = await app.handle(req("/providers", cookie));
		expect(response.status).toBe(403);
	});

	test("rejects a mutating request without the CSRF header", async () => {
		const cookie = await administratorCookie();
		const response = await app.handle(
			new Request("http://admin.test/_burrowgate/api/admin/firewall-sync/providers", {
				method: "POST",
				headers: { cookie, "content-type": "application/json" },
				body: JSON.stringify({ name: "x", type: "nftables" }),
			}),
		);
		expect(response.status).toBe(403);
	});

	test("creates, lists, updates, and deletes an nftables provider, and never echoes secrets since none apply", async () => {
		const cookie = await administratorCookie();

		const created = await app.handle(
			req("/providers", cookie, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ name: "Local nft", type: "nftables", acknowledgedNoWhitelist: true, config: { nftBinaryPath: "nft" } }),
			}),
		);
		expect(created.status).toBe(201);
		const createdBody = (await created.json()) as { id: string; name: string; type: string };
		expect(createdBody.name).toBe("Local nft");
		expect(createdBody.type).toBe("nftables");

		const listed = await app.handle(req("/providers", cookie));
		const listedBody = (await listed.json()) as { items: Array<{ id: string }> };
		expect(listedBody.items.some((item) => item.id === createdBody.id)).toBe(true);

		const updated = await app.handle(
			req(`/providers/${createdBody.id}`, cookie, {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ name: "Renamed nft" }),
			}),
		);
		expect(updated.status).toBe(200);
		expect(((await updated.json()) as { name: string }).name).toBe("Renamed nft");

		const deleted = await app.handle(req(`/providers/${createdBody.id}`, cookie, { method: "DELETE" }));
		expect(deleted.status).toBe(200);

		const listedAfterDelete = await app.handle(req("/providers", cookie));
		const listedAfterDeleteBody = (await listedAfterDelete.json()) as { items: Array<{ id: string }> };
		expect(listedAfterDeleteBody.items.some((item) => item.id === createdBody.id)).toBe(false);
	});

	test("refuses to enable a provider with no whitelist entries and no explicit acknowledgement", async () => {
		const cookie = await administratorCookie();
		const created = await app.handle(
			req("/providers", cookie, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ name: "Guarded nft", type: "nftables" }),
			}),
		);
		const createdBody = (await created.json()) as { id: string };

		const response = await app.handle(
			req(`/providers/${createdBody.id}`, cookie, {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ enabled: true }),
			}),
		);
		expect(response.status).toBe(400);
	});
});

describe("firewall sync unifi sites route", () => {
	test("requires authentication and a CSRF header", async () => {
		expect((await app.handle(req("/providers/unifi/sites", undefined, { method: "POST" }))).status).toBe(401);
		const cookie = await administratorCookie();
		const response = await app.handle(
			new Request("http://admin.test/_burrowgate/api/admin/firewall-sync/providers/unifi/sites", { method: "POST", headers: { cookie } }),
		);
		expect(response.status).toBe(403);
	});

	test("rejects a request with no controller URL before attempting any network call", async () => {
		const cookie = await administratorCookie();
		const response = await app.handle(
			req("/providers/unifi/sites", cookie, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({}) }),
		);
		expect(response.status).toBe(400);
		expect(((await response.json()) as { error: string }).error).toContain("Controller URL");
	});
});

describe("firewall sync whitelist routes", () => {
	test("adds and removes a whitelist entry", async () => {
		const cookie = await administratorCookie();
		const created = await app.handle(
			req("/whitelist", cookie, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ networkCidr: "203.0.113.4/32", note: "test admin ip" }),
			}),
		);
		expect(created.status).toBe(201);
		const createdBody = (await created.json()) as { id: string; networkCidr: string };
		expect(createdBody.networkCidr).toBe("203.0.113.4/32");

		const listed = await app.handle(req("/whitelist", cookie));
		const listedBody = (await listed.json()) as { items: Array<{ id: string }> };
		expect(listedBody.items.some((item) => item.id === createdBody.id)).toBe(true);

		const deleted = await app.handle(req(`/whitelist/${createdBody.id}`, cookie, { method: "DELETE" }));
		expect(deleted.status).toBe(200);
	});

	test("rejects an invalid CIDR", async () => {
		const cookie = await administratorCookie();
		const response = await app.handle(
			req("/whitelist", cookie, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ networkCidr: "not-an-ip" }),
			}),
		);
		expect(response.status).toBe(400);
	});
});
