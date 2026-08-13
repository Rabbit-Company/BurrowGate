import { beforeAll, describe, expect, test } from "bun:test";
import { Web } from "@rabbit-company/web";
import { repository } from "../src/db/repository.ts";
import { registerAccessRoutes } from "../src/routes/access-routes.ts";
import { createAccessUser, generateSessionVerificationToken, updateAccessSettings } from "../src/services/access-list-service.ts";
import { createAccessSession } from "../src/services/session-service.ts";
import { createSite } from "../src/services/site-service.ts";
import type { SiteRecord } from "../src/types.ts";

const app = new Web();
registerAccessRoutes(app);

let site: SiteRecord;
let cookie: string;
let verificationToken: string;

beforeAll(async () => {
	site = (
		await createSite({
			name: "Cross-site session test",
			publicHost: `cross-site-${crypto.randomUUID()}.test`,
			originUrl: "http://origin.test",
		})
	).site;
	const user = await createAccessUser(site.id, { username: `cross-site-${crypto.randomUUID()}`, password: "password123" });
	await updateAccessSettings(site.id, { enabled: true, sendUsernameToUpstream: true });
	const request = new Request(`http://${site.public_host}/`);
	const created = await createAccessSession(request, site, "127.0.0.1", "user-agent", { method: "test" });
	await repository.authenticateSession(created.record.id, site.id, user.id, Date.now());
	cookie = created.cookie.split(";")[0]!;
	verificationToken = (await generateSessionVerificationToken(site.id)).token;
});

describe("cross-site access session introspection", () => {
	test("mints, introspects, and revokes the current browser session", async () => {
		const mintResponse = await app.handle(
			new Request(`http://${site.public_host}/_burrowgate/access/session-token`, {
				method: "POST",
				headers: { cookie, origin: `http://${site.public_host}` },
			}),
		);
		expect(mintResponse.status).toBe(200);
		const assertion = (await mintResponse.json()) as { token: string; user: { username: string } };
		expect(assertion.token).toStartWith("bgsa_");
		expect(assertion.user.username).toStartWith("cross-site-");

		const introspect = async () =>
			await app.handle(
				new Request(`http://${site.public_host}/_burrowgate/api/access/session/introspect`, {
					method: "POST",
					headers: { authorization: `Bearer ${verificationToken}`, "content-type": "application/json", "x-burrowgate-site-id": site.id },
					body: JSON.stringify({ token: assertion.token }),
				}),
			);

		const activeResponse = await introspect();
		expect(activeResponse.status).toBe(200);
		expect(await activeResponse.json()).toMatchObject({ active: true, siteId: site.id, user: { username: assertion.user.username } });

		const logoutResponse = await app.handle(
			new Request(`http://${site.public_host}/_burrowgate/access/logout`, {
				method: "POST",
				headers: { cookie, origin: `http://${site.public_host}` },
			}),
		);
		expect(logoutResponse.status).toBe(200);
		expect(await logoutResponse.json()).toEqual({ ok: true });
		const setCookies = (logoutResponse.headers as Headers & { getSetCookie(): string[] }).getSetCookie();
		expect(setCookies.some((value) => value.startsWith("bg_session="))).toBe(true);
		expect(setCookies.some((value) => value.startsWith("bg_authenticated_user="))).toBe(true);

		const inactiveResponse = await introspect();
		expect(inactiveResponse.status).toBe(200);
		expect(await inactiveResponse.json()).toEqual({ active: false });
	});

	test("rejects invalid backend verification credentials", async () => {
		const response = await app.handle(
			new Request(`http://${site.public_host}/_burrowgate/api/access/session/introspect`, {
				method: "POST",
				headers: { authorization: "Bearer wrong", "content-type": "application/json", "x-burrowgate-site-id": site.id },
				body: JSON.stringify({ token: "invalid" }),
			}),
		);
		expect(response.status).toBe(401);
	});
});
