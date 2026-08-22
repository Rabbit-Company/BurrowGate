import { describe, expect, test } from "bun:test";
import { Web } from "@rabbit-company/web";
import { registerAdminRoutes } from "../src/routes/admin-routes.ts";
import { createAdminUser } from "../src/services/admin-user-service.ts";
import { createAdminSession } from "../src/services/session-service.ts";
import { createSite } from "../src/services/site-service.ts";
import { createOrigin } from "../src/services/origin-pool-service.ts";

const app = new Web();
registerAdminRoutes(app);

async function administratorCookie(): Promise<string> {
	const user = await createAdminUser({ username: `mtls-admin-${crypto.randomUUID()}`, password: "password123", role: "administrator" }, "test-suite");
	const { cookie } = await createAdminSession(new Request("http://admin.test/"), user.username, user.id);
	return cookie.split(";")[0]!;
}

function req(path: string, cookie: string, init: RequestInit = {}): Request {
	const headers: Record<string, string> = { ...(init.headers as Record<string, string>) };
	headers.cookie = cookie;
	if (init.method && init.method !== "GET") headers["x-burrowgate-admin"] = "1";
	return new Request(`http://admin.test${path}`, { ...init, headers });
}

async function siteWithOrigin() {
	const { site } = await createSite({ name: "mTLS route test", publicHost: `mtls-route-${crypto.randomUUID()}.test`, originUrl: "https://backend.test" });
	const origin = await createOrigin(site.id, { name: "backend", originUrl: "https://backend.test" });
	return { site, origin };
}

describe("origin mTLS admin routes", () => {
	test("generate requires authentication", async () => {
		const { origin } = await siteWithOrigin();
		const response = await app.handle(new Request(`http://admin.test/_burrowgate/api/admin/origins/${origin.id}/mtls/generate`, { method: "POST" }));
		expect(response.status).toBe(401);
	});

	test("generate creates and enables a certificate, download returns it", async () => {
		const cookie = await administratorCookie();
		const { origin } = await siteWithOrigin();

		const generateResponse = await app.handle(req(`/_burrowgate/api/admin/origins/${origin.id}/mtls/generate`, cookie, { method: "POST" }));
		expect(generateResponse.status).toBe(200);
		const body = (await generateResponse.json()) as { origin: { mtls: { enabled: boolean; configured: boolean } } };
		expect(body.origin.mtls.enabled).toBe(true);
		expect(body.origin.mtls.configured).toBe(true);
		expect(JSON.stringify(body)).not.toContain("PRIVATE KEY");

		const downloadResponse = await app.handle(req(`/_burrowgate/api/admin/origins/${origin.id}/mtls/certificate`, cookie));
		expect(downloadResponse.status).toBe(200);
		expect(downloadResponse.headers.get("content-disposition")).toContain("attachment");
		expect(downloadResponse.headers.get("content-disposition")).toContain("backend-client-cert.pem");
		const pem = await downloadResponse.text();
		expect(pem).toContain("BEGIN CERTIFICATE");
		expect(pem).not.toContain("PRIVATE KEY");
	});

	test("download 404s when no certificate is configured", async () => {
		const cookie = await administratorCookie();
		const { origin } = await siteWithOrigin();
		const response = await app.handle(req(`/_burrowgate/api/admin/origins/${origin.id}/mtls/certificate`, cookie));
		expect(response.status).toBe(404);
	});

	test("generate 404s for an origin that does not exist", async () => {
		const cookie = await administratorCookie();
		const response = await app.handle(req("/_burrowgate/api/admin/origins/origin_does_not_exist/mtls/generate", cookie, { method: "POST" }));
		expect(response.status).toBe(404);
	});

	test("generate-origin-certificate returns the private key once, download serves the certificate, mTLS stays off", async () => {
		const cookie = await administratorCookie();
		const { origin } = await siteWithOrigin();

		const generateResponse = await app.handle(req(`/_burrowgate/api/admin/origins/${origin.id}/mtls/generate-origin-certificate`, cookie, { method: "POST" }));
		expect(generateResponse.status).toBe(200);
		const body = (await generateResponse.json()) as {
			origin: { mtls: { enabled: boolean; configured: boolean; caConfigured: boolean } };
			certificatePem: string;
			privateKeyPem: string;
		};
		expect(body.origin.mtls.caConfigured).toBe(true);
		expect(body.origin.mtls.enabled).toBe(false);
		expect(body.origin.mtls.configured).toBe(false);
		expect(body.certificatePem).toContain("BEGIN CERTIFICATE");
		expect(body.privateKeyPem).toContain("BEGIN PRIVATE KEY");

		const downloadResponse = await app.handle(req(`/_burrowgate/api/admin/origins/${origin.id}/mtls/trusted-ca`, cookie));
		expect(downloadResponse.status).toBe(200);
		expect(downloadResponse.headers.get("content-disposition")).toContain("backend-trusted-ca.pem");
		const pem = await downloadResponse.text();
		expect(pem).toContain("BEGIN CERTIFICATE");
		expect(pem).not.toContain("PRIVATE KEY");
	});

	test("trusted-ca download 404s when nothing is configured", async () => {
		const cookie = await administratorCookie();
		const { origin } = await siteWithOrigin();
		const response = await app.handle(req(`/_burrowgate/api/admin/origins/${origin.id}/mtls/trusted-ca`, cookie));
		expect(response.status).toBe(404);
	});
});
