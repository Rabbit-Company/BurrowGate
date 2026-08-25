import { describe, expect, test } from "bun:test";
import { Web } from "@rabbit-company/web";
import { repository } from "../src/db/repository.ts";
import { registerAdminRoutes } from "../src/routes/admin-routes.ts";
import { createAdminUser } from "../src/services/admin-user-service.ts";
import { createAdminSession } from "../src/services/session-service.ts";
import { createSite } from "../src/services/site-service.ts";
import { createDnsProvider, deleteDnsProvider } from "../src/services/dns-provider-service.ts";

const app = new Web();
registerAdminRoutes(app);

function req(path: string, cookie: string, init: RequestInit = {}): Request {
	const headers: Record<string, string> = { ...(init.headers as Record<string, string>) };
	headers.cookie = cookie;
	if (init.method && init.method !== "GET") headers["x-burrowgate-admin"] = "1";
	return new Request(`http://admin.test${path}`, { ...init, headers });
}

async function administratorCookie(): Promise<string> {
	const user = await createAdminUser({ username: `dns-authz-admin-${crypto.randomUUID()}`, password: "password123", role: "administrator" }, "test-suite");
	const { cookie } = await createAdminSession(new Request("http://admin.test/"), user.username, user.id);
	return cookie.split(";")[0]!;
}

/** A "member" granted only "manage" access to one specific site - the role a DNS-01 provider must not be selectable by, since providers are a shared, cross-site resource. */
async function memberCookieWithSiteManageAccess(siteId: string): Promise<string> {
	const user = await createAdminUser({ username: `dns-authz-member-${crypto.randomUUID()}`, password: "password123", role: "member" }, "test-suite");
	await repository.replaceAdminSitePermissions(user.id, [{ siteId, level: "manager" }]);
	const { cookie } = await createAdminSession(new Request("http://admin.test/"), user.username, user.id);
	return cookie.split(";")[0]!;
}

async function siteAndProvider() {
	const { site } = await createSite({ name: "DNS-01 authz test", publicHost: `dns-authz-${crypto.randomUUID()}.test`, originUrl: "http://origin.test" });
	const provider = await createDnsProvider({
		name: "Shared provider",
		type: "rfc2136",
		config: { server: "ns1.example.com", port: 53, zone: "example.com", tsigKeyName: "burrowgate-key", tsigSecret: "c2VjcmV0LWJ5dGVz" },
	});
	return { site, provider };
}

describe("DNS-01 provider selection requires administrator access", () => {
	test("a site-scoped member cannot switch a site's TLS settings to dns-01 with a DNS provider", async () => {
		const { site, provider } = await siteAndProvider();
		const cookie = await memberCookieWithSiteManageAccess(site.id);

		const response = await app.handle(
			req(`/_burrowgate/api/admin/sites/${site.id}/tls`, cookie, {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ acmeChallengeType: "dns-01", acmeDnsProviderId: provider.id }),
			}),
		);
		expect(response.status).toBe(403);

		const settings = await repository.ensureTlsSettings(site.id);
		expect(settings.acme_challenge_type).toBe("http-01");
		expect(settings.acme_dns_provider_id).toBeNull();
	});

	test("a site-scoped member cannot request a DNS-01 certificate with an explicit provider", async () => {
		const { site, provider } = await siteAndProvider();
		const cookie = await memberCookieWithSiteManageAccess(site.id);

		const response = await app.handle(
			req(`/_burrowgate/api/admin/sites/${site.id}/certificate/letsencrypt`, cookie, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					email: "admin@example.com",
					directoryUrl: "https://acme-staging.test/directory",
					termsAccepted: true,
					challengeType: "dns-01",
					dnsProviderId: provider.id,
				}),
			}),
		);
		expect(response.status).toBe(403);
	});

	test("a site-scoped member can still manage plain HTTP-01/upload TLS settings on their own site", async () => {
		const { site } = await siteAndProvider();
		const cookie = await memberCookieWithSiteManageAccess(site.id);

		const response = await app.handle(
			req(`/_burrowgate/api/admin/sites/${site.id}/tls`, cookie, {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ acmeChallengeType: "http-01" }),
			}),
		);
		expect(response.status).toBe(200);
	});

	test("an administrator can select a DNS provider for a site", async () => {
		const { site, provider } = await siteAndProvider();
		const cookie = await administratorCookie();

		const response = await app.handle(
			req(`/_burrowgate/api/admin/sites/${site.id}/tls`, cookie, {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ acmeChallengeType: "dns-01", acmeDnsProviderId: provider.id }),
			}),
		);
		expect(response.status).toBe(200);
		const settings = await repository.ensureTlsSettings(site.id);
		expect(settings.acme_challenge_type).toBe("dns-01");
		expect(settings.acme_dns_provider_id).toBe(provider.id);
	});
});

describe("switching a site off dns-01 releases its DNS provider reference", () => {
	test("reverting to http-01 clears acme_dns_provider_id, so the provider can be deleted afterward", async () => {
		const { site, provider } = await siteAndProvider();
		const cookie = await administratorCookie();

		const toDns01 = await app.handle(
			req(`/_burrowgate/api/admin/sites/${site.id}/tls`, cookie, {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ acmeChallengeType: "dns-01", acmeDnsProviderId: provider.id }),
			}),
		);
		expect(toDns01.status).toBe(200);
		expect((await repository.ensureTlsSettings(site.id)).acme_dns_provider_id).toBe(provider.id);

		// The dashboard resubmits whatever the (now-hidden) DNS provider select last held, regardless of challenge type -
		// the backend must be the one to drop the stale reference, not rely on the client to omit it.
		const backToHttp01 = await app.handle(
			req(`/_burrowgate/api/admin/sites/${site.id}/tls`, cookie, {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ acmeChallengeType: "http-01", acmeDnsProviderId: provider.id }),
			}),
		);
		expect(backToHttp01.status).toBe(200);

		const settings = await repository.ensureTlsSettings(site.id);
		expect(settings.acme_challenge_type).toBe("http-01");
		expect(settings.acme_dns_provider_id).toBeNull();

		expect(await repository.sitesUsingDnsProvider(provider.id)).toHaveLength(0);
		await expect(deleteDnsProvider(provider.id)).resolves.toBeUndefined();
	});
});
