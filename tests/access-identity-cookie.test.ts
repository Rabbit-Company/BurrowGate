import { describe, expect, test } from "bun:test";
import { accessIdentityCookieValues, accessIdentitySetCookies } from "../src/services/access-list-service.ts";
import type { AccessSessionRecord, SiteRecord } from "../src/types.ts";
import { hmacSha256Hex } from "../src/utils/crypto.ts";
import { appendSetCookies } from "../src/utils/http.ts";

const now = Date.now();
const site = {
	id: "site_cookie_test",
	name: "Cookie test",
	origin_signing_secret: "cookie-test-secret-that-is-at-least-32-characters",
} as SiteRecord;
const session = {
	id: "sess_cookie_test",
	expires_at: now + 3_600_000,
} as AccessSessionRecord;

describe("access identity cookies", () => {
	test("creates a session-bound signed username assertion", async () => {
		const values = await accessIdentityCookieValues(site, session, "ziga");
		const canonical = ["identity-cookie-v1", site.id, session.id, "ziga"].join("\n");
		expect(values).toEqual({ username: "ziga", signature: await hmacSha256Hex(site.origin_signing_secret, canonical) });
	});

	test("sets browser-readable secure cookies that expire with the session", async () => {
		const cookies = await accessIdentitySetCookies(new Request("https://example.test/"), site, session, "ziga");
		expect(cookies).toHaveLength(2);
		expect(cookies[0]).toContain("bg_authenticated_user=ziga");
		expect(cookies[0]).toContain("Secure");
		expect(cookies[0]).not.toContain("HttpOnly");
		expect(cookies[1]).toContain("bg_identity_signature=");
	});

	test("appends identity cookies without dropping an origin cookie", () => {
		const origin = new Response("ok", { headers: { "set-cookie": "application=value; Path=/" } });
		const response = appendSetCookies(origin, ["bg_authenticated_user=ziga; Path=/; SameSite=Lax"]);
		const values = (response.headers as Headers & { getSetCookie(): string[] }).getSetCookie();
		expect(values).toContain("application=value; Path=/");
		expect(values).toContain("bg_authenticated_user=ziga; Path=/; SameSite=Lax");
	});
});
