import { afterEach, describe, expect, test } from "bun:test";
import { Web } from "@rabbit-company/web";
import { repository } from "../src/db/repository.ts";
import { registerCrowdSecAdminRoutes } from "../src/routes/crowdsec-admin-routes.ts";
import { createAdminUser } from "../src/services/admin-user-service.ts";
import { crowdSecDecisions } from "../src/services/crowdsec-decision-store.ts";
import { crowdSecService } from "../src/services/crowdsec-service.ts";
import { createAdminSession } from "../src/services/session-service.ts";

const app = new Web();
registerCrowdSecAdminRoutes(app);

afterEach(async () => {
	crowdSecDecisions.clear();
	const settings = await repository.ensureCrowdSecSettings();
	await repository.saveCrowdSecSettings({
		...settings,
		enabled: 0,
		lapi_url: null,
		api_key_encrypted: null,
		scopes: "ip,range",
		poll_interval_seconds: 10,
		unknown_remediation: "ban",
		updated_at: Date.now(),
	});
	await crowdSecService.reload();
});

async function administratorCookie(): Promise<string> {
	const user = await createAdminUser({ username: `cs-admin-${crypto.randomUUID()}`, password: "password123", role: "administrator" }, "test-suite");
	const { cookie } = await createAdminSession(new Request("http://admin.test/"), user.username, user.id, null, false);
	return cookie.split(";")[0]!;
}

async function memberCookie(): Promise<string> {
	const user = await createAdminUser({ username: `cs-member-${crypto.randomUUID()}`, password: "password123", role: "member" }, "test-suite");
	const { cookie } = await createAdminSession(new Request("http://admin.test/"), user.username, user.id, null, false);
	return cookie.split(";")[0]!;
}

function req(path: string, cookie?: string, init: RequestInit = {}): Request {
	const headers: Record<string, string> = { ...(init.headers as Record<string, string>) };
	if (cookie) headers.cookie = cookie;
	if (init.method && init.method !== "GET") headers["x-burrowgate-admin"] = "1";
	return new Request(`http://admin.test/_burrowgate/api/admin/crowdsec${path}`, { ...init, headers });
}

function settingsBody(overrides: Record<string, unknown> = {}): RequestInit {
	return {
		method: "PUT",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({ lapiUrl: "http://127.0.0.1:8080", apiKey: "test-bouncer-key", ...overrides }),
	};
}

describe("authorization", () => {
	test("status requires authentication", async () => {
		expect((await app.handle(req("/status"))).status).toBe(401);
	});

	test("status requires administrator, not just any admin member", async () => {
		expect((await app.handle(req("/status", await memberCookie()))).status).toBe(403);
	});

	test("settings requires administrator", async () => {
		expect((await app.handle(req("/settings", await memberCookie(), settingsBody()))).status).toBe(403);
	});

	test("lookup requires administrator", async () => {
		expect((await app.handle(req("/lookup?ip=203.0.113.5", await memberCookie()))).status).toBe(403);
	});

	test("refresh requires administrator", async () => {
		expect((await app.handle(req("/refresh", await memberCookie(), { method: "POST" }))).status).toBe(403);
	});

	test("rejects a mutating request without the CSRF header", async () => {
		const cookie = await administratorCookie();
		const response = await app.handle(
			new Request("http://admin.test/_burrowgate/api/admin/crowdsec/settings", {
				method: "PUT",
				headers: { cookie, "content-type": "application/json" },
				body: JSON.stringify({ lapiUrl: "http://127.0.0.1:8080" }),
			}),
		);
		expect(response.status).toBe(403);
	});
});

describe("settings", () => {
	test("stores a connection and reports it without leaking the key", async () => {
		const cookie = await administratorCookie();
		const response = await app.handle(req("/settings", cookie, settingsBody()));
		expect(response.status).toBe(200);
		const status = (await response.json()) as Record<string, unknown>;
		expect(status.lapiUrl).toBe("http://127.0.0.1:8080");
		expect(status.apiKeyConfigured).toBe(true);
		expect(JSON.stringify(status)).not.toContain("test-bouncer-key");
	});

	test("the stored key is never returned by the status endpoint either", async () => {
		const cookie = await administratorCookie();
		await app.handle(req("/settings", cookie, settingsBody()));
		const body = await (await app.handle(req("/status", cookie))).text();
		expect(body).not.toContain("test-bouncer-key");
		expect(JSON.parse(body).apiKeyConfigured).toBe(true);
	});

	test("normalizes the Local API URL and strips a trailing slash", async () => {
		const cookie = await administratorCookie();
		const response = await app.handle(req("/settings", cookie, settingsBody({ lapiUrl: "http://127.0.0.1:8080/" })));
		expect(((await response.json()) as Record<string, unknown>).lapiUrl).toBe("http://127.0.0.1:8080");
	});

	test("rejects a Local API URL that is not http or https", async () => {
		const cookie = await administratorCookie();
		const response = await app.handle(req("/settings", cookie, settingsBody({ lapiUrl: "ftp://127.0.0.1:8080" })));
		expect(response.status).toBe(400);
	});

	test("refuses to enable without a Local API URL", async () => {
		const cookie = await administratorCookie();
		const response = await app.handle(
			req("/settings", cookie, { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ enabled: true }) }),
		);
		expect(response.status).toBe(400);
		expect(((await response.json()) as { error: string }).error).toContain("Local API URL");
	});

	test("refuses to enable without an API key", async () => {
		const cookie = await administratorCookie();
		const response = await app.handle(
			req("/settings", cookie, {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ enabled: true, lapiUrl: "http://127.0.0.1:8080" }),
			}),
		);
		expect(response.status).toBe(400);
		expect(((await response.json()) as { error: string }).error).toContain("API key");
	});

	test("omitting the API key keeps the stored one rather than clearing it", async () => {
		const cookie = await administratorCookie();
		await app.handle(req("/settings", cookie, settingsBody()));
		const response = await app.handle(
			req("/settings", cookie, { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ pollIntervalSeconds: 30 }) }),
		);
		const status = (await response.json()) as Record<string, unknown>;
		expect(status.apiKeyConfigured).toBe(true);
		expect(status.pollIntervalSeconds).toBe(30);
	});

	test("accepts scopes as an array and echoes them back", async () => {
		const cookie = await administratorCookie();
		const response = await app.handle(req("/settings", cookie, settingsBody({ scopes: ["ip", "range", "country", "as"] })));
		expect(((await response.json()) as { scopes: string[] }).scopes).toEqual(["ip", "range", "country", "as"]);
	});

	test("rejects an unsupported scope", async () => {
		const cookie = await administratorCookie();
		const response = await app.handle(req("/settings", cookie, settingsBody({ scopes: ["ip", "username"] })));
		expect(response.status).toBe(400);
	});

	test("rejects an out-of-range poll interval", async () => {
		const cookie = await administratorCookie();
		expect((await app.handle(req("/settings", cookie, settingsBody({ pollIntervalSeconds: 1 })))).status).toBe(400);
		expect((await app.handle(req("/settings", cookie, settingsBody({ pollIntervalSeconds: 100_000 })))).status).toBe(400);
	});

	test("rejects an unknown remediation fallback it does not understand", async () => {
		const cookie = await administratorCookie();
		expect((await app.handle(req("/settings", cookie, settingsBody({ unknownRemediation: "explode" })))).status).toBe(400);
	});
});

describe("test connection", () => {
	/**
	 * The stored key is never sent to the browser, but the test runs on the server, which holds it.
	 * Demanding a retype to test a saved connection was a real usability bug.
	 */
	test("falls back to the stored key when the form leaves it blank", async () => {
		const cookie = await administratorCookie();
		await app.handle(req("/settings", cookie, settingsBody()));
		const response = await app.handle(
			req("/test", cookie, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ lapiUrl: "http://127.0.0.1:9" }),
			}),
		);
		// Port 9 refuses, so this fails on the connection rather than on a missing key.
		const outcome = (await response.json()) as { ok: boolean; message: string };
		expect(outcome.ok).toBe(false);
		expect(outcome.message).not.toContain("API key is configured");
	});

	test("says so plainly when no key is stored and none is supplied", async () => {
		const cookie = await administratorCookie();
		const response = await app.handle(
			req("/test", cookie, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ lapiUrl: "http://127.0.0.1:9" }),
			}),
		);
		const outcome = (await response.json()) as { ok: boolean; message: string };
		expect(outcome.ok).toBe(false);
		expect(outcome.message).toContain("No bouncer API key is configured");
	});

	test("reports an unreachable Local API rather than throwing", async () => {
		const cookie = await administratorCookie();
		const response = await app.handle(
			req("/test", cookie, {
				method: "POST",
				headers: { "content-type": "application/json" },
				// Port 9 (discard) refuses fast, so this exercises the failure path without a long wait.
				body: JSON.stringify({ lapiUrl: "http://127.0.0.1:9", apiKey: "irrelevant" }),
			}),
		);
		const outcome = (await response.json()) as { ok: boolean; message: string };
		expect(outcome.ok).toBe(false);
		expect(outcome.message.length).toBeGreaterThan(0);
	});
});

describe("lookup", () => {
	test("requires an ip parameter", async () => {
		expect((await app.handle(req("/lookup", await administratorCookie()))).status).toBe(400);
	});

	test("reports no decision for an address that is not covered", async () => {
		const cookie = await administratorCookie();
		const body = (await (await app.handle(req("/lookup?ip=203.0.113.5", cookie))).json()) as { decision: unknown };
		expect(body.decision).toBeNull();
	});

	test("returns the matching decision for a covered address", async () => {
		const cookie = await administratorCookie();
		crowdSecDecisions.applySnapshot([
			{ id: 42, type: "ban", scope: "Ip", value: "203.0.113.5", duration: "4h", origin: "CAPI", scenario: "crowdsecurity/http-probing" },
		]);
		const body = (await (await app.handle(req("/lookup?ip=203.0.113.5", cookie))).json()) as {
			decision: { id: number; remediation: string; scenario: string } | null;
		};
		expect(body.decision?.id).toBe(42);
		expect(body.decision?.remediation).toBe("ban");
		expect(body.decision?.scenario).toBe("crowdsecurity/http-probing");
	});

	test("matches an address inside a loaded range", async () => {
		const cookie = await administratorCookie();
		crowdSecDecisions.applySnapshot([{ id: 7, type: "ban", scope: "Range", value: "203.0.113.0/24", duration: "4h", origin: "CAPI", scenario: "blocklist" }]);
		const body = (await (await app.handle(req("/lookup?ip=203.0.113.99", cookie))).json()) as { decision: { value: string } | null };
		expect(body.decision?.value).toBe("203.0.113.0/24");
	});
});

describe("status reporting", () => {
	test("reports decision counts broken down by scope and origin", async () => {
		const cookie = await administratorCookie();
		crowdSecDecisions.applySnapshot([
			{ id: 1, type: "ban", scope: "Ip", value: "203.0.113.5", duration: "4h", origin: "CAPI", scenario: "s" },
			{ id: 2, type: "captcha", scope: "Range", value: "198.51.100.0/24", duration: "4h", origin: "cscli", scenario: "s" },
		]);
		const status = (await (await app.handle(req("/status", cookie))).json()) as {
			decisions: { total: number; byScope: Record<string, number>; byRemediation: Record<string, number>; byOrigin: Record<string, number> };
		};
		expect(status.decisions.total).toBe(2);
		expect(status.decisions.byScope.ip).toBe(1);
		expect(status.decisions.byScope.range).toBe(1);
		expect(status.decisions.byRemediation.captcha).toBe(1);
		expect(status.decisions.byOrigin.CAPI).toBe(1);
	});
});
