import { afterEach, describe, expect, test } from "bun:test";
import { Web } from "@rabbit-company/web";
import { repository } from "../src/db/repository.ts";
import { registerDnsAdminRoutes } from "../src/routes/dns-admin-routes.ts";
import { createAdminUser } from "../src/services/admin-user-service.ts";
import { createAdminSession } from "../src/services/session-service.ts";
import { createSite } from "../src/services/site-service.ts";

const app = new Web();
registerDnsAdminRoutes(app);

afterEach(async () => {
	for (const provider of await repository.allDnsProviders()) await repository.deleteDnsProvider(provider.id);
});

async function administratorCookie(): Promise<string> {
	const user = await createAdminUser({ username: `dns-admin-${crypto.randomUUID()}`, password: "password123", role: "administrator" }, "test-suite");
	const { cookie } = await createAdminSession(new Request("http://admin.test/"), user.username, user.id);
	return cookie.split(";")[0]!;
}

async function memberCookie(): Promise<string> {
	const user = await createAdminUser({ username: `dns-member-${crypto.randomUUID()}`, password: "password123", role: "member" }, "test-suite");
	const { cookie } = await createAdminSession(new Request("http://admin.test/"), user.username, user.id);
	return cookie.split(";")[0]!;
}

function req(path: string, cookie?: string, init: RequestInit = {}): Request {
	const headers: Record<string, string> = { ...(init.headers as Record<string, string>) };
	if (cookie) headers.cookie = cookie;
	if (init.method && init.method !== "GET") headers["x-burrowgate-admin"] = "1";
	return new Request(`http://admin.test/_burrowgate/api/admin/dns-providers${path}`, { ...init, headers });
}

function rfc2136Body(overrides: Record<string, unknown> = {}): string {
	return JSON.stringify({
		name: "Home lab BIND",
		type: "rfc2136",
		config: { server: "ns1.example.com", port: 53, zone: "example.com", tsigKeyName: "burrowgate-key", tsigSecret: "c2VjcmV0LWJ5dGVz", ...overrides },
	});
}

describe("dns provider routes", () => {
	test("requires authentication", async () => {
		const response = await app.handle(req(""));
		expect(response.status).toBe(401);
	});

	test("requires administrator role, not just any admin member", async () => {
		const cookie = await memberCookie();
		const response = await app.handle(req("", cookie));
		expect(response.status).toBe(403);
	});

	test("rejects a mutating request without the CSRF header", async () => {
		const cookie = await administratorCookie();
		const response = await app.handle(
			new Request("http://admin.test/_burrowgate/api/admin/dns-providers", {
				method: "POST",
				headers: { cookie, "content-type": "application/json" },
				body: rfc2136Body(),
			}),
		);
		expect(response.status).toBe(403);
	});

	test("creates, lists, updates, and deletes a provider, redacting the TSIG secret in every response", async () => {
		const cookie = await administratorCookie();

		const created = await app.handle(req("", cookie, { method: "POST", headers: { "content-type": "application/json" }, body: rfc2136Body() }));
		expect(created.status).toBe(201);
		const createdBody = (await created.json()) as { id: string; name: string; type: string; config: Record<string, unknown> };
		expect(createdBody.name).toBe("Home lab BIND");
		expect(createdBody.type).toBe("rfc2136");
		expect(createdBody.config.zone).toBe("example.com.");
		expect(createdBody.config.tsigSecretConfigured).toBe(true);
		expect(createdBody.config.tsigSecretEncrypted).toBeUndefined();

		const listed = await app.handle(req("", cookie));
		const listedBody = (await listed.json()) as { items: Array<{ id: string }> };
		expect(listedBody.items.some((item) => item.id === createdBody.id)).toBe(true);

		const updated = await app.handle(
			req(`/${createdBody.id}`, cookie, { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: "Renamed" }) }),
		);
		expect(updated.status).toBe(200);
		const updatedBody = (await updated.json()) as { name: string; config: Record<string, unknown> };
		expect(updatedBody.name).toBe("Renamed");
		expect(updatedBody.config.tsigSecretConfigured).toBe(true); // secret carried over without being resent

		const deleted = await app.handle(req(`/${createdBody.id}`, cookie, { method: "DELETE" }));
		expect(deleted.status).toBe(200);

		const listedAfterDelete = await app.handle(req("", cookie));
		const listedAfterDeleteBody = (await listedAfterDelete.json()) as { items: Array<{ id: string }> };
		expect(listedAfterDeleteBody.items.some((item) => item.id === createdBody.id)).toBe(false);
	});

	test("rejects creation with no server, zone, key name, or secret", async () => {
		const cookie = await administratorCookie();
		const response = await app.handle(
			req("", cookie, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ name: "Incomplete", type: "rfc2136", config: {} }),
			}),
		);
		expect(response.status).toBe(400);
	});

	test("test-connection surfaces a network error instead of throwing", async () => {
		const cookie = await administratorCookie();
		const created = await app.handle(
			req("", cookie, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: rfc2136Body({ server: "dns-server-that-does-not-exist.invalid" }),
			}),
		);
		const createdBody = (await created.json()) as { id: string };
		const tested = await app.handle(req(`/${createdBody.id}/test`, cookie, { method: "POST" }));
		expect(tested.status).toBe(200);
		const testedBody = (await tested.json()) as { ok: boolean; message: string };
		expect(testedBody.ok).toBe(false);
	});

	test("refuses to delete a provider that a site still uses for DNS-01", async () => {
		const cookie = await administratorCookie();
		const created = await app.handle(req("", cookie, { method: "POST", headers: { "content-type": "application/json" }, body: rfc2136Body() }));
		const createdBody = (await created.json()) as { id: string };

		const { site } = await createSite({ name: "Dependent site", publicHost: `dns-dependent-${crypto.randomUUID()}.test`, originUrl: "http://origin.test" });
		const settings = await repository.ensureTlsSettings(site.id);
		await repository.saveTlsSettings({ ...settings, acme_challenge_type: "dns-01", acme_dns_provider_id: createdBody.id });

		const deleted = await app.handle(req(`/${createdBody.id}`, cookie, { method: "DELETE" }));
		expect(deleted.status).toBe(400);
		const deletedBody = (await deleted.json()) as { error: string };
		expect(deletedBody.error).toContain("Dependent site");

		await repository.deleteSiteCascade(site.id);
	});
});
