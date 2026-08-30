import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { config } from "../src/config.ts";
import { db } from "../src/db/client.ts";
import { createAdminUser } from "../src/services/admin-user-service.ts";
import { pinPrimaryHaCertificate } from "../src/services/ha-tls-service.ts";
import { haMeshService } from "../src/services/ha-mesh-service.ts";
import { createAdminSession, getAdminSession, HaSessionPublicationError } from "../src/services/session-service.ts";
import { sha256Hex } from "../src/utils/crypto.ts";

const originalHa = { ...config.ha };
const originalFetch = globalThis.fetch;

const originalDataDirectory = config.dataDirectory;

afterEach(async () => {
	Object.assign(config.ha, originalHa);
	globalThis.fetch = originalFetch;
	config.dataDirectory = originalDataDirectory;
	await db`DELETE FROM session_relay_outbox`;
});

describe("haMeshService.waitForRelayPublication", () => {
	test("returns immediately when HA is disabled", async () => {
		config.ha.enabled = false;
		await haMeshService.waitForRelayPublication("admin_session", "irrelevant-entity", 50);
	});

	test("returns immediately on a primary - only a replica has anything to publish", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		await haMeshService.waitForRelayPublication("admin_session", "irrelevant-entity", 50);
	});

	test("resolves immediately when there is no pending relay row for this entity", async () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		await haMeshService.waitForRelayPublication("admin_session", "never-queued-entity", 50);
	});

	test("throws once the deadline passes if the relay is never acknowledged", async () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		await db`INSERT INTO session_relay_outbox (entity_type,entity_id,op,payload_json,created_at) VALUES ('admin_session','stuck-session','insert','{}',${Date.now()})`;
		const started = Date.now();
		await expect(haMeshService.waitForRelayPublication("admin_session", "stuck-session", 60)).rejects.toThrow(
			/did not acknowledge the new session before the publication deadline/,
		);
		expect(Date.now() - started).toBeLessThan(1_000);
	});

	test("resolves as soon as the pending row is acknowledged (deleted), without waiting out the full deadline", async () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		await db`INSERT INTO session_relay_outbox (entity_type,entity_id,op,payload_json,created_at) VALUES ('admin_session','acked-session','insert','{}',${Date.now()})`;
		const started = Date.now();
		const wait = haMeshService.waitForRelayPublication("admin_session", "acked-session", 5_000);

		await new Promise((resolve) => setTimeout(resolve, 40));
		await db`DELETE FROM session_relay_outbox WHERE entity_type='admin_session' AND entity_id='acked-session'`;
		await wait;
		expect(Date.now() - started).toBeLessThan(500);
	});
});

describe("createAdminSession's requireHaPublication behavior", () => {
	test("requireHaPublication=true on a replica throws HaSessionPublicationError if the relay is never acknowledged", async () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		const user = await createAdminUser({ username: `pub-required-${crypto.randomUUID()}`, password: "password123", role: "administrator" }, "test-suite");
		await expect(createAdminSession(new Request("http://admin.test/"), user.username, user.id, null, true)).rejects.toBeInstanceOf(HaSessionPublicationError);
	}, 15_000);

	test("requireHaPublication=false on a replica does not wait on the relay at all", async () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		const user = await createAdminUser({ username: `pub-skipped-${crypto.randomUUID()}`, password: "password123", role: "administrator" }, "test-suite");
		const result = await createAdminSession(new Request("http://admin.test/"), user.username, user.id, null, false);
		expect(result.cookie).toBeTruthy();
	});

	test("on a primary, requireHaPublication has no effect - there is nothing to publish to", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		const user = await createAdminUser({ username: `pub-primary-${crypto.randomUUID()}`, password: "password123", role: "administrator" }, "test-suite");
		const result = await createAdminSession(new Request("http://admin.test/"), user.username, user.id, null, true);
		expect(result.cookie).toBeTruthy();
	});
});

describe("getAdminSession's remote-resolution fallback", () => {
	test("on a local miss, a replica asks the primary and accepts a session it returns", async () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		config.ha.primaryAdminUrl = "https://primary.internal";
		config.ha.sharedToken = "test-shared-token";
		const token = "remote-resolved-token";
		const tokenHash = await sha256Hex(token);
		let requestedTokenHash: string | undefined;
		globalThis.fetch = (async (url: unknown, init?: RequestInit) => {
			expect(String(url)).toBe("https://primary.internal/_burrowgate/api/admin/ha/resolve-admin-session");
			requestedTokenHash = (JSON.parse(String(init?.body)) as { tokenHash: string }).tokenHash;
			return Response.json({
				session: {
					id: "admin_remote-session",
					token_hash: tokenHash,
					username: "remote-user",
					user_id: null,
					created_at: Date.now(),
					expires_at: Date.now() + 60_000,
					last_seen_at: Date.now(),
					sso_sid: null,
				},
			});
		}) as unknown as typeof fetch;

		const request = new Request("http://replica.test/", { headers: { cookie: `__Host-bg_admin=${token}` } });
		const session = await getAdminSession(request);
		expect(requestedTokenHash).toBe(tokenHash);
		expect(session?.username).toBe("remote-user");
	});

	test("verifies the primary's admin URL against the pinned HA certificate, not the system CA store, once one is pinned", async () => {
		const tempDir = await mkdtemp(join(tmpdir(), "bg-ha-session-tls-test-"));
		config.dataDirectory = tempDir;
		try {
			config.ha.enabled = true;
			config.ha.role = "replica";
			config.ha.primaryAdminUrl = "https://primary.internal";
			config.ha.sharedToken = "test-shared-token";
			await pinPrimaryHaCertificate("pinned-primary-admin-certificate");
			let capturedTls: unknown;
			globalThis.fetch = (async (_url: unknown, init?: RequestInit) => {
				capturedTls = (init as (RequestInit & { tls?: unknown }) | undefined)?.tls;
				return Response.json({ session: null });
			}) as unknown as typeof fetch;

			await getAdminSession(new Request("http://replica.test/", { headers: { cookie: "__Host-bg_admin=some-token" } }));

			expect(capturedTls).toMatchObject({ ca: "pinned-primary-admin-certificate", checkServerIdentity: expect.any(Function) });
		} finally {
			await rm(tempDir, { recursive: true, force: true });
		}
	});

	test("falls back to ordinary system-CA verification when nothing is pinned yet", async () => {
		const tempDir = await mkdtemp(join(tmpdir(), "bg-ha-session-tls-test-"));
		config.dataDirectory = tempDir;
		try {
			config.ha.enabled = true;
			config.ha.role = "replica";
			config.ha.primaryAdminUrl = "https://primary.internal";
			config.ha.sharedToken = "test-shared-token";
			let capturedTls: unknown = "not-yet-captured";
			globalThis.fetch = (async (_url: unknown, init?: RequestInit) => {
				capturedTls = (init as (RequestInit & { tls?: unknown }) | undefined)?.tls;
				return Response.json({ session: null });
			}) as unknown as typeof fetch;

			await getAdminSession(new Request("http://replica.test/", { headers: { cookie: "__Host-bg_admin=some-token" } }));

			expect(capturedTls).toBeUndefined();
		} finally {
			await rm(tempDir, { recursive: true, force: true });
		}
	});

	test("falls back to no session (not an error) when the primary cannot be reached", async () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		config.ha.primaryAdminUrl = "https://primary.internal";
		config.ha.sharedToken = "test-shared-token";
		globalThis.fetch = (async () => {
			throw new Error("simulated network failure");
		}) as unknown as typeof fetch;

		const request = new Request("http://replica.test/", { headers: { cookie: "__Host-bg_admin=unknown-token" } });
		const session = await getAdminSession(request);
		expect(session).toBeNull();
	});

	test("does not attempt a remote fallback on a primary - there is nowhere to ask", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		let fetchCalled = false;
		globalThis.fetch = (async () => {
			fetchCalled = true;
			throw new Error("should not be called");
		}) as unknown as typeof fetch;

		const request = new Request("http://primary.test/", { headers: { cookie: "__Host-bg_admin=unknown-token" } });
		const session = await getAdminSession(request);
		expect(session).toBeNull();
		expect(fetchCalled).toBe(false);
	});
});
