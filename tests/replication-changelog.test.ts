import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test";
import { config } from "../src/config.ts";
import { db } from "../src/db/client.ts";
import { migrate } from "../src/db/migrate.ts";
import { repository, type ReplicationChangelogRow } from "../src/db/repository.ts";
import { createAdminSession, createAccessSession } from "../src/services/session-service.ts";
import { createSite, updateSite } from "../src/services/site-service.ts";
import { buildStream } from "../src/services/stream-service.ts";
import { randomId, sha256Hex } from "../src/utils/crypto.ts";
import type {
	AccessSessionRecord,
	AccessUserRecord,
	AccessWebauthnCredentialRecord,
	AcmeAccountRecord,
	AcmeHttpChallengeRecord,
	AdminRecoveryCodeRecord,
	AdminSessionRecord,
	AdminSsoSettingsRecord,
	AdminUserRecord,
	AdminWebauthnCredentialRecord,
	AsnRuleRecord,
	CertificateRecord,
	CountryRuleRecord,
	FirewallSyncProviderRecord,
	FirewallSyncWhitelistCidrRecord,
	IpRuleRecord,
	PendingChangeRecord,
	SiteAccessSettingsRecord,
	SiteOriginRecord,
	SiteRecord,
	SiteSsoSettingsRecord,
	SiteTlsSettingsRecord,
	StreamAsnRuleRecord,
	StreamCountryRuleRecord,
	StreamIpRuleRecord,
} from "../src/types.ts";

let nextTestStreamPort = 20_000;
async function makeStream(name: string): Promise<import("../src/types.ts").StreamRecord> {
	const port = nextTestStreamPort++;
	const stream = await buildStream({ name, incomingPort: port, forwardHost: "127.0.0.1", forwardPort: port + 1, tcpEnabled: true, udpEnabled: false });
	await repository.saveStream(stream);
	return stream;
}

function fakeStreamIpRule(streamId: string): StreamIpRuleRecord {
	return {
		id: randomId("stream_iprule"),
		stream_id: streamId,
		network_cidr: "203.0.113.0/24",
		action: "block",
		reason: "test ban",
		created_at: Date.now(),
		expires_at: null,
	};
}

function fakeStreamCountryRule(streamId: string): StreamCountryRuleRecord {
	return {
		id: randomId("stream_countryrule"),
		stream_id: streamId,
		country_code: "US",
		action: "block",
		reason: "test ban",
		created_at: Date.now(),
		expires_at: null,
	};
}

function fakeStreamAsnRule(streamId: string): StreamAsnRuleRecord {
	return { id: randomId("stream_asnrule"), stream_id: streamId, asn: 64500, action: "block", reason: "test ban", created_at: Date.now(), expires_at: null };
}

function fakeAdminUser(username: string): AdminUserRecord {
	const now = Date.now();
	return {
		id: randomId("admin_user"),
		username,
		password_hash: "fake-hash",
		role: "administrator",
		totp_secret_encrypted: null,
		totp_enrolled_at: null,
		must_enroll_totp: 0,
		enabled: 1,
		created_at: now,
		updated_at: now,
		created_by_user_id: null,
		sso_subject: null,
		auth_source: "password",
	};
}

function fakeAccessUser(username: string): AccessUserRecord {
	const now = Date.now();
	return {
		id: randomId("access_user"),
		username,
		password_hash: "fake-hash",
		enabled: 1,
		created_at: now,
		updated_at: now,
		totp_required: 0,
		totp_secret_encrypted: null,
		totp_enrolled_at: null,
		api_token_hash: null,
		api_token_created_at: null,
		sso_subject: null,
		auth_source: "password",
	};
}

function fakeAdminRecoveryCode(userId: string): AdminRecoveryCodeRecord {
	return { id: randomId("admin_rc"), user_id: userId, code_hash: randomId("hash"), created_at: Date.now(), used_at: null };
}

function fakeAdminWebauthnCredential(userId: string): AdminWebauthnCredentialRecord {
	const now = Date.now();
	return {
		id: randomId("admin_wan"),
		user_id: userId,
		rp_id: "localhost",
		credential_id: randomId("cred"),
		credential_id_hash: randomId("credhash"),
		public_key: "fake-public-key",
		sign_count: 0,
		transports_json: null,
		aaguid: null,
		device_type: null,
		backed_up: 0,
		nickname: null,
		created_at: now,
		last_used_at: null,
		updated_at: now,
	};
}

function fakeAccessWebauthnCredential(userId: string, siteId: string): AccessWebauthnCredentialRecord {
	const now = Date.now();
	return {
		id: randomId("access_wan"),
		user_id: userId,
		site_id: siteId,
		rp_id: "localhost",
		credential_id: randomId("cred"),
		credential_id_hash: randomId("credhash"),
		public_key: "fake-public-key",
		sign_count: 0,
		transports_json: null,
		aaguid: null,
		device_type: null,
		backed_up: 0,
		nickname: null,
		created_at: now,
		last_used_at: null,
		updated_at: now,
	};
}

function fakeIpRule(siteId: string): IpRuleRecord {
	return {
		id: randomId("iprule"),
		site_id: siteId,
		network_cidr: "203.0.113.0/24",
		action: "block",
		reason: "test ban",
		created_at: Date.now(),
		expires_at: null,
		rule_id: null,
	};
}

function fakeCountryRule(siteId: string): CountryRuleRecord {
	return { id: randomId("countryrule"), site_id: siteId, country_code: "US", action: "block", reason: "test ban", created_at: Date.now(), expires_at: null };
}

function fakeAsnRule(siteId: string): AsnRuleRecord {
	return { id: randomId("asnrule"), site_id: siteId, asn: 64500, action: "block", reason: "test ban", created_at: Date.now(), expires_at: null };
}

function fakeOrigin(siteId: string): SiteOriginRecord {
	const now = Date.now();
	return {
		id: randomId("origin"),
		site_id: siteId,
		name: "secondary origin",
		origin_type: "proxy",
		origin_url: "https://secondary-origin.test",
		static_index_file: null,
		static_spa_fallback: 0,
		enabled: 1,
		draining: 0,
		priority: 10,
		weight: 1,
		health_check_path: null,
		is_primary: 0,
		mtls_enabled: 0,
		mtls_certificate_pem: null,
		mtls_encrypted_private_key: null,
		mtls_ca_pem: null,
		created_at: now,
		updated_at: now,
	};
}

function fakeCertificate(siteId: string): CertificateRecord {
	const now = Date.now();
	return {
		id: randomId("cert"),
		site_id: siteId,
		source: "uploaded",
		status: "active",
		primary_domain: "cert-test.example",
		alternative_names_json: "[]",
		certificate_pem: null,
		encrypted_private_key: null,
		issuer: null,
		serial_number: null,
		valid_from: now,
		expires_at: now + 86_400_000,
		next_renewal_at: null,
		last_attempt_at: null,
		last_error: null,
		created_at: now,
		updated_at: now,
	};
}

function fakeTlsSettings(siteId: string): SiteTlsSettingsRecord {
	const now = Date.now();
	return {
		site_id: siteId,
		mode: "disabled",
		force_https: 0,
		acme_email: null,
		acme_directory_url: null,
		acme_challenge_type: "http-01",
		acme_dns_provider_id: null,
		created_at: now,
		updated_at: now,
	};
}

function fakeAcmeChallenge(siteId: string): AcmeHttpChallengeRecord {
	const now = Date.now();
	return {
		token: randomId("acme_token"),
		site_id: siteId,
		hostname: "cert-test.example",
		key_authorization: "fake-key-authorization",
		created_at: now,
		expires_at: now + 900_000,
	};
}

function fakeRequest(): Request {
	return new Request("http://localhost/");
}

function fakeFirewallSyncProvider(name: string): FirewallSyncProviderRecord {
	const now = Date.now();
	return {
		id: randomId("firewall_sync_provider"),
		name,
		type: "nftables",
		enabled: 0,
		max_entries: 50,
		config_json: JSON.stringify({ nftBinaryPath: "nft" }),
		acknowledged_no_whitelist: 1,
		last_checked_at: null,
		last_synced_at: null,
		last_sync_status: null,
		last_sync_error: null,
		last_applied_count: 0,
		last_applied_hash: null,
		created_at: now,
		updated_at: now,
	};
}

function fakeFirewallSyncWhitelistCidr(): FirewallSyncWhitelistCidrRecord {
	return { id: randomId("firewall_whitelist"), network_cidr: "203.0.113.9/32", note: null, created_at: Date.now() };
}

async function makeSite(publicHost: string): Promise<SiteRecord> {
	const { site } = await createSite({ name: "HA test site", publicHost, originUrl: "https://origin.test" });
	return site;
}

async function changelogFor(entityId: string): Promise<ReplicationChangelogRow[]> {
	const rows = await repository.changelogSince(0, 1_000);
	return rows.filter((row) => row.entity_id === entityId);
}

async function changelogByType(entityType: string): Promise<ReplicationChangelogRow[]> {
	const rows = await repository.changelogSince(0, 1_000);
	return rows.filter((row) => row.entity_type === entityType);
}

describe("HA replication: disabled (explicit)", () => {
	let previousEnabled: boolean;

	beforeAll(() => {
		previousEnabled = config.ha.enabled;
		config.ha.enabled = false;
	});

	afterAll(() => {
		config.ha.enabled = previousEnabled;
	});

	test("insertSite does not append a changelog entry", async () => {
		const site = await makeSite("ha-disabled.test");
		expect(await changelogFor(site.id)).toHaveLength(0);
	});
});

describe("HA replication: primary", () => {
	let previousEnabled: boolean;
	let previousRole: typeof config.ha.role;

	beforeAll(() => {
		previousEnabled = config.ha.enabled;
		previousRole = config.ha.role;
		config.ha.enabled = true;
		config.ha.role = "primary";
	});

	afterAll(() => {
		config.ha.enabled = previousEnabled;
		config.ha.role = previousRole;
	});

	test("insertSite appends an insert row carrying the full row snapshot", async () => {
		const site = await makeSite("ha-primary-insert.test");
		const rows = await changelogFor(site.id);
		expect(rows).toHaveLength(1);
		expect(rows[0]!.entity_type).toBe("site");
		expect(rows[0]!.op).toBe("insert");
		const payload = JSON.parse(rows[0]!.payload_json!) as SiteRecord;
		expect(payload.public_host).toBe("ha-primary-insert.test");
		expect(payload.id).toBe(site.id);
	});

	test("updateSite appends an update row after the insert row", async () => {
		const site = await makeSite("ha-primary-update.test");
		await updateSite(site.id, { name: "Renamed", publicHost: "ha-primary-update.test", originUrl: "https://origin.test" }, "tester");
		const rows = await changelogFor(site.id);
		expect(rows.map((row) => row.op)).toEqual(["insert", "update"]);
		const payload = JSON.parse(rows[1]!.payload_json!) as SiteRecord;
		expect(payload.name).toBe("Renamed");
	});

	test("updateSiteNetworkDefaults appends an update row carrying the new defaults", async () => {
		const site = await makeSite("ha-primary-network-defaults.test");
		await repository.updateSiteNetworkDefaults(site.id, "block", "challenge", Date.now());
		const rows = await changelogFor(site.id);
		expect(rows.map((row) => row.op)).toEqual(["insert", "update"]);
		expect(rows[1]!.entity_type).toBe("site");
		const payload = JSON.parse(rows[1]!.payload_json!) as SiteRecord;
		expect(payload.default_ip_action).toBe("block");
		expect(payload.default_country_action).toBe("challenge");
	});

	test("insertOrigin, updateOrigin, and deleteOrigin append changelog rows", async () => {
		const site = await makeSite("ha-primary-origin.test");
		const origin = fakeOrigin(site.id);
		await repository.insertOrigin(origin);
		await repository.updateOrigin({ ...origin, name: "renamed origin", updated_at: Date.now() });
		await repository.deleteOrigin(origin.id, site.id);
		const rows = await changelogFor(origin.id);
		expect(rows.map((row) => row.op)).toEqual(["insert", "update", "delete"]);
		expect(rows[0]!.entity_type).toBe("site_origin");
		expect(rows[2]!.payload_json).toBeNull();
		const updatedPayload = JSON.parse(rows[1]!.payload_json!) as SiteOriginRecord;
		expect(updatedPayload.name).toBe("renamed origin");
	});

	test("deleteSiteCascade also appends a delete row for the site's non-primary origins", async () => {
		const site = await makeSite("ha-primary-delete-origin.test");
		const origin = fakeOrigin(site.id);
		await repository.insertOrigin(origin);
		await repository.deleteSiteCascade(site.id);
		expect((await changelogFor(origin.id)).map((row) => row.op)).toEqual(["insert", "delete"]);
	});

	test("applyChangelogRow round-trips a site_origin row", async () => {
		const site = await makeSite("ha-primary-origin-apply.test");
		const origin = fakeOrigin(site.id);
		await repository.insertOrigin(origin);
		const insertRow = (await changelogFor(origin.id))[0]!;
		await repository.deleteOrigin(origin.id, site.id);
		expect(await repository.originById(origin.id)).toBeNull();
		await repository.applyReplicatedChange(insertRow);
		const applied = await repository.originById(origin.id);
		expect(applied).not.toBeNull();
		expect(applied!.name).toBe(origin.name);
	});

	test("deleteSiteCascade appends a delete row with a null payload", async () => {
		const site = await makeSite("ha-primary-delete.test");
		await repository.deleteSiteCascade(site.id);
		const rows = (await changelogFor(site.id)).filter((row) => row.entity_type === "site");
		expect(rows.map((row) => row.op)).toEqual(["insert", "delete"]);
		expect(rows[1]!.payload_json).toBeNull();
	});

	test("deleteSiteCascade also appends a delete row for the site's TLS settings", async () => {
		const site = await makeSite("ha-primary-delete-tls.test");
		await repository.ensureTlsSettings(site.id);
		await repository.deleteSiteCascade(site.id);
		const rows = (await changelogFor(site.id)).filter((row) => row.entity_type === "site_tls_settings");
		expect(rows.map((row) => row.op)).toEqual(["delete"]);
	});

	test("deleteSiteCascade also appends delete rows for access settings, SSO settings, and access-user memberships", async () => {
		const site = await makeSite("ha-primary-delete-access.test");
		await repository.ensureAccessSettings(site.id);
		await repository.ensureSiteSsoSettings(site.id);
		const user = fakeAccessUser("ha-primary-delete-access-user");
		await repository.insertAccessUser(user);
		await repository.assignAccessUser(site.id, user.id);

		await repository.deleteSiteCascade(site.id);

		expect((await changelogFor(site.id)).filter((row) => row.entity_type === "site_access_settings").map((row) => row.op)).toEqual(["delete"]);
		expect((await changelogFor(site.id)).filter((row) => row.entity_type === "site_sso_settings").map((row) => row.op)).toEqual(["delete"]);
		expect((await changelogFor(`${site.id}:${user.id}`)).map((row) => row.op)).toEqual(["insert", "delete"]);
	});

	test("deleteSiteCascade does not append access/SSO settings deletes when none were ever created", async () => {
		const site = await makeSite("ha-primary-delete-no-access.test");
		await repository.deleteSiteCascade(site.id);
		expect((await changelogFor(site.id)).filter((row) => row.entity_type === "site_access_settings")).toHaveLength(0);
		expect((await changelogFor(site.id)).filter((row) => row.entity_type === "site_sso_settings")).toHaveLength(0);
	});

	test("applyReplicatedChange reconstructs an equivalent row from the changelog snapshot", async () => {
		const site = await makeSite("ha-apply.test");
		const rows = await changelogFor(site.id);
		const insertRow = rows[0]!;
		await repository.deleteSiteCascade(site.id);
		await repository.applyReplicatedChange(insertRow);
		const applied = await repository.siteById(site.id);
		expect(applied).not.toBeNull();
		expect(applied!.public_host).toBe("ha-apply.test");
		expect(applied!.name).toBe("HA test site");
	});
});

describe("HA replication: replica write guard", () => {
	let previousEnabled: boolean;
	let previousRole: typeof config.ha.role;
	let site: SiteRecord;

	beforeAll(async () => {
		previousEnabled = config.ha.enabled;
		previousRole = config.ha.role;
		config.ha.enabled = true;
		config.ha.role = "primary";
		site = await makeSite("ha-replica-guard.test");
		config.ha.role = "replica";
	});

	afterAll(() => {
		config.ha.enabled = previousEnabled;
		config.ha.role = previousRole;
	});

	test("updateSite throws instead of writing locally", async () => {
		await expect(repository.updateSite({ ...site, name: "Should not apply" })).rejects.toThrow(/Replica nodes cannot write/);
	});

	test("deleteSiteCascade throws instead of writing locally", async () => {
		await expect(repository.deleteSiteCascade(site.id)).rejects.toThrow(/Replica nodes cannot write/);
	});

	test("updateSiteNetworkDefaults throws instead of writing locally", async () => {
		await expect(repository.updateSiteNetworkDefaults(site.id, "block", "block", Date.now())).rejects.toThrow(/Replica nodes cannot write/);
	});

	test("insertOrigin, updateOrigin, and deleteOrigin all throw instead of writing locally", async () => {
		const origin = fakeOrigin(site.id);
		await expect(repository.insertOrigin(origin)).rejects.toThrow(/Replica nodes cannot write/);
		await expect(repository.updateOrigin(origin)).rejects.toThrow(/Replica nodes cannot write/);
		await expect(repository.deleteOrigin(origin.id, site.id)).rejects.toThrow(/Replica nodes cannot write/);
	});
});

describe("HA replication: write fencing during a promotion", () => {
	let previousEnabled: boolean;
	let previousRole: typeof config.ha.role;
	let site: SiteRecord;

	beforeAll(async () => {
		previousEnabled = config.ha.enabled;
		previousRole = config.ha.role;
		config.ha.enabled = true;
		config.ha.role = "primary";
		site = await makeSite("ha-fencing.test");
	});

	afterAll(() => {
		config.ha.enabled = previousEnabled;
		config.ha.role = previousRole;
	});

	afterEach(() => {
		config.ha.fencedForPromotion = false;
		config.ha.versionMismatchNodes = [];
	});

	test("updateSite throws while fenced, even though this node is still the primary", async () => {
		config.ha.fencedForPromotion = true;
		await expect(repository.updateSite({ ...site, name: "Should not apply while fenced" })).rejects.toThrow(/promoting a replica/);
	});

	test("writes succeed again once fencing is lifted", async () => {
		config.ha.fencedForPromotion = true;
		await expect(repository.updateSite({ ...site, name: "Should not apply while fenced" })).rejects.toThrow(/promoting a replica/);
		config.ha.fencedForPromotion = false;
		await repository.updateSite({ ...site, name: "Applies once unfenced" });
		expect((await repository.siteById(site.id))?.name).toBe("Applies once unfenced");
	});

	test("repository writes remain fenced even when an HTTP middleware is bypassed", async () => {
		config.ha.versionMismatchNodes = [{ nodeId: "old-node", name: "old replica", version: "0.0.1" }];
		await expect(repository.updateSite({ ...site, name: "Should not apply across versions" })).rejects.toThrow(/cluster versions differ/);
	});
});

describe("HA replication: sessions, primary", () => {
	let previousEnabled: boolean;
	let previousRole: typeof config.ha.role;

	beforeAll(() => {
		previousEnabled = config.ha.enabled;
		previousRole = config.ha.role;
		config.ha.enabled = true;
		config.ha.role = "primary";
	});

	afterAll(() => {
		config.ha.enabled = previousEnabled;
		config.ha.role = previousRole;
	});

	test("createAdminSession appends an insert row, and logging out appends a delete row", async () => {
		const before = await changelogByType("admin_session");
		await createAdminSession(fakeRequest(), "tester");
		const afterInsert = await changelogByType("admin_session");
		expect(afterInsert.length).toBe(before.length + 1);
		const insertRow = afterInsert[afterInsert.length - 1]!;
		expect(insertRow.op).toBe("insert");
		const inserted = JSON.parse(insertRow.payload_json!) as AdminSessionRecord;
		expect(inserted.username).toBe("tester");

		await repository.deleteAdmin(inserted.token_hash);
		const afterDelete = await changelogByType("admin_session");
		const deleteRow = afterDelete[afterDelete.length - 1]!;
		expect(deleteRow.op).toBe("delete");
		expect(deleteRow.entity_id).toBe(inserted.id);
		expect(deleteRow.payload_json).toBeNull();
	});

	test("createAccessSession, authenticateSession, and revokeSession each append the right row", async () => {
		const site = await makeSite("ha-session-access.test");
		const { record } = await createAccessSession(fakeRequest(), site, "203.0.113.5", "ua-hash", { steps: [] });

		const insertRows = await changelogFor(record.id);
		expect(insertRows).toHaveLength(1);
		expect(insertRows[0]!.op).toBe("insert");

		await repository.authenticateSession(record.id, site.id, "access_user_test", Date.now());
		const afterAuth = await changelogFor(record.id);
		expect(afterAuth.map((row) => row.op)).toEqual(["insert", "update"]);
		const authPayload = JSON.parse(afterAuth[1]!.payload_json!) as AccessSessionRecord;
		expect(authPayload.access_user_id).toBe("access_user_test");

		await repository.revokeSession(record.id, Date.now());
		const afterRevoke = await changelogFor(record.id);
		expect(afterRevoke.map((row) => row.op)).toEqual(["insert", "update", "update"]);
		const revokePayload = JSON.parse(afterRevoke[2]!.payload_json!) as AccessSessionRecord;
		expect(revokePayload.revoked_at).not.toBeNull();
	});
});

describe("HA replication: sessions, replica", () => {
	let previousEnabled: boolean;
	let previousRole: typeof config.ha.role;
	let site: SiteRecord;

	beforeAll(async () => {
		previousEnabled = config.ha.enabled;
		previousRole = config.ha.role;
		config.ha.enabled = true;
		config.ha.role = "primary";
		site = await makeSite("ha-session-replica.test");
		config.ha.role = "replica";
	});

	afterAll(() => {
		config.ha.enabled = previousEnabled;
		config.ha.role = previousRole;
	});

	test("session writes are not gated (multi-writer) and queue a relay row instead of a changelog row", async () => {
		const { token, cookie } = await createAdminSession(fakeRequest(), "replica-tester", null, null, false);
		expect(token).toBeTruthy();
		expect(cookie).toBeTruthy();

		const relayRows = await repository.pendingSessionRelayRows(1_000);
		const adminRelay = relayRows.filter((row) => row.entity_type === "admin_session");
		expect(adminRelay.length).toBeGreaterThan(0);
		const last = adminRelay[adminRelay.length - 1]!;
		expect(last.op).toBe("insert");
		const payload = JSON.parse(last.payload_json!) as AdminSessionRecord;
		expect(payload.username).toBe("replica-tester");

		const changelogRows = await changelogByType("admin_session");
		expect(changelogRows.find((row) => row.entity_id === payload.id)).toBeUndefined();
	});

	test("createAccessSession on a replica also queues a relay row", async () => {
		const before = (await repository.pendingSessionRelayRows(1_000)).filter((row) => row.entity_type === "access_session").length;
		await createAccessSession(fakeRequest(), site, "203.0.113.9", "ua-hash", { steps: [] }, false);
		const after = (await repository.pendingSessionRelayRows(1_000)).filter((row) => row.entity_type === "access_session").length;
		expect(after).toBe(before + 1);
	});
});

describe("HA replication: applyReplicatedSessionRelay", () => {
	let previousEnabled: boolean;

	beforeAll(() => {
		previousEnabled = config.ha.enabled;
		config.ha.enabled = true;
	});

	afterAll(() => {
		config.ha.enabled = previousEnabled;
	});

	test("applies an insert relay and makes the session locally lookupable", async () => {
		const record: AdminSessionRecord = {
			id: "admin_relay_test_1",
			token_hash: "relay-test-token-hash-1",
			username: "relayed-admin",
			user_id: null,
			created_at: Date.now(),
			expires_at: Date.now() + 60_000,
			last_seen_at: Date.now(),
			sso_sid: null,
		};
		await repository.applyReplicatedSessionRelay("test-node", 1, "admin_session", record.id, "insert", record);
		const found = await repository.adminByHash(record.token_hash);
		expect(found?.username).toBe("relayed-admin");
	});

	test("a revoke relay with a full snapshot applies cleanly even with no prior local row", async () => {
		const record: AccessSessionRecord = {
			id: "access_relay_test_1",
			site_id: "site-does-not-matter",
			token_hash: "relay-test-token-hash-2",
			initial_ip: "203.0.113.1",
			last_ip: "203.0.113.1",
			user_agent_hash: "ua",
			created_at: Date.now(),
			last_seen_at: Date.now(),
			expires_at: Date.now() + 60_000,
			revoked_at: Date.now(),
			verification_summary_json: "{}",
			request_count: 0,
			country_code: null,
			asn: null,
			asn_org: null,
			access_user_id: null,
			authenticated_at: null,
			sso_sid: null,
		};
		await repository.applyReplicatedSessionRelay("test-node", 2, "access_session", record.id, "update", record);
		const found = await repository.sessionById(record.site_id, record.id);
		expect(found).not.toBeNull();
		expect(found!.revoked_at).not.toBeNull();
	});

	test("applies a delete relay by removing the row", async () => {
		const record: AdminSessionRecord = {
			id: "admin_relay_test_2",
			token_hash: "relay-test-token-hash-3",
			username: "relayed-admin-2",
			user_id: null,
			created_at: Date.now(),
			expires_at: Date.now() + 60_000,
			last_seen_at: Date.now(),
			sso_sid: null,
		};
		await repository.applyReplicatedSessionRelay("test-node", 3, "admin_session", record.id, "insert", record);
		expect(await repository.adminByHash(record.token_hash)).not.toBeNull();
		await repository.applyReplicatedSessionRelay("test-node", 4, "admin_session", record.id, "delete", null);
		expect(await repository.adminByHash(record.token_hash)).toBeNull();
	});
});

describe("HA replication: relay self-echo skip", () => {
	let previousEnabled: boolean;

	beforeAll(() => {
		previousEnabled = config.ha.enabled;
		config.ha.enabled = true;
	});

	afterAll(() => {
		config.ha.enabled = previousEnabled;
	});

	test("applying a node's own relayed insert back to it does not resurrect a newer local delete", async () => {
		const record: AdminSessionRecord = {
			id: "admin_self_echo_test_1",
			token_hash: "self-echo-token-hash-1",
			username: "self-echo-admin",
			user_id: null,
			created_at: Date.now(),
			expires_at: Date.now() + 60_000,
			last_seen_at: Date.now(),
			sso_sid: null,
		};
		await repository.applyReplicatedSessionRelay("self-echo-node", 1, "admin_session", record.id, "insert", record);
		const insertRow = (await changelogFor(record.id))[0]!;

		await repository.applyReplicatedSessionRelay("self-echo-node", 2, "admin_session", record.id, "delete", null);
		expect(await repository.adminByHash(record.token_hash)).toBeNull();

		await repository.applyReplicatedChange(insertRow, "self-echo-node");
		expect(await repository.adminByHash(record.token_hash)).toBeNull();

		await repository.applyReplicatedChange(insertRow, "some-other-node");
		expect((await repository.adminByHash(record.token_hash))?.username).toBe("self-echo-admin");
	});

	test("watermark bookkeeping still advances even when the self-echo payload apply is skipped", async () => {
		const record: AdminSessionRecord = {
			id: "admin_self_echo_test_2",
			token_hash: "self-echo-token-hash-2",
			username: "self-echo-admin-2",
			user_id: null,
			created_at: Date.now(),
			expires_at: Date.now() + 60_000,
			last_seen_at: Date.now(),
			sso_sid: null,
		};
		await repository.applyReplicatedSessionRelay("self-echo-node-2", 5, "admin_session", record.id, "insert", record);
		const insertRow = (await changelogFor(record.id))[0]!;
		const rowsBefore = (await changelogFor(record.id)).length;

		await repository.applyReplicatedChange(insertRow, "self-echo-node-2");

		await repository.applyReplicatedSessionRelay("self-echo-node-2", 5, "admin_session", record.id, "insert", record);
		expect((await changelogFor(record.id)).length).toBe(rowsBefore);
	});
});

describe("HA replication: certificates, TLS settings, ACME challenges - primary", () => {
	let previousEnabled: boolean;
	let previousRole: typeof config.ha.role;

	beforeAll(() => {
		previousEnabled = config.ha.enabled;
		previousRole = config.ha.role;
		config.ha.enabled = true;
		config.ha.role = "primary";
	});

	afterAll(() => {
		config.ha.enabled = previousEnabled;
		config.ha.role = previousRole;
	});

	test("saveCertificate appends insert then update rows, deleteCertificate appends a delete row", async () => {
		const site = await makeSite("ha-cert-primary.test");
		const certificate = fakeCertificate(site.id);
		await repository.saveCertificate(certificate);
		const afterInsert = await changelogFor(certificate.id);
		expect(afterInsert.map((row) => row.op)).toEqual(["insert"]);

		await repository.saveCertificate({ ...certificate, status: "active", primary_domain: "renewed.example" });
		const afterUpdate = await changelogFor(certificate.id);
		expect(afterUpdate.map((row) => row.op)).toEqual(["insert", "update"]);
		expect((JSON.parse(afterUpdate[1]!.payload_json!) as CertificateRecord).primary_domain).toBe("renewed.example");

		await repository.deleteCertificate(site.id);
		const afterDelete = await changelogFor(certificate.id);
		expect(afterDelete.map((row) => row.op)).toEqual(["insert", "update", "delete"]);
		expect(afterDelete[2]!.payload_json).toBeNull();
	});

	test("updateCertificateAttempt appends an update row with the overlaid failure fields", async () => {
		const site = await makeSite("ha-cert-attempt.test");
		const certificate = fakeCertificate(site.id);
		await repository.saveCertificate(certificate);
		await repository.updateCertificateAttempt(site.id, Date.now(), "simulated ACME failure");
		const rows = await changelogFor(certificate.id);
		expect(rows.map((row) => row.op)).toEqual(["insert", "update"]);
		const payload = JSON.parse(rows[1]!.payload_json!) as CertificateRecord;
		expect(payload.last_error).toBe("simulated ACME failure");
	});

	test("saveTlsSettings appends a row keyed by site_id", async () => {
		const site = await makeSite("ha-tls-primary.test");
		await repository.saveTlsSettings({ ...fakeTlsSettings(site.id), mode: "letsencrypt" });
		const rows = await changelogFor(site.id);
		const tlsRows = rows.filter((row) => row.entity_type === "site_tls_settings");
		expect(tlsRows).toHaveLength(1);
		expect(tlsRows[0]!.op).toBe("update");
		expect((JSON.parse(tlsRows[0]!.payload_json!) as SiteTlsSettingsRecord).mode).toBe("letsencrypt");
	});

	test("saveAcmeChallenge and deleteAcmeChallenge append rows keyed by token", async () => {
		const site = await makeSite("ha-acme-challenge.test");
		const challenge = fakeAcmeChallenge(site.id);
		await repository.saveAcmeChallenge(challenge);
		const afterInsert = await changelogFor(challenge.token);
		expect(afterInsert.map((row) => row.op)).toEqual(["insert"]);

		await repository.deleteAcmeChallenge(challenge.token);
		const afterDelete = await changelogFor(challenge.token);
		expect(afterDelete.map((row) => row.op)).toEqual(["insert", "delete"]);
	});

	test("applyChangelogRow round-trips a certificate onto a replica-like empty table", async () => {
		const site = await makeSite("ha-cert-apply.test");
		const certificate = fakeCertificate(site.id);
		await repository.saveCertificate(certificate);
		const rows = await changelogFor(certificate.id);
		await repository.deleteCertificate(site.id);
		await repository.applyReplicatedChange(rows[0]!);
		const applied = await repository.certificateBySite(site.id);
		expect(applied?.primary_domain).toBe(certificate.primary_domain);
	});
});

describe("HA replication: certificates, TLS settings, ACME challenges - replica write guard", () => {
	let previousEnabled: boolean;
	let previousRole: typeof config.ha.role;
	let site: SiteRecord;
	let certificate: CertificateRecord;

	beforeAll(async () => {
		previousEnabled = config.ha.enabled;
		previousRole = config.ha.role;
		config.ha.enabled = true;
		config.ha.role = "primary";
		site = await makeSite("ha-cert-replica-guard.test");
		certificate = fakeCertificate(site.id);
		await repository.saveCertificate(certificate);
		config.ha.role = "replica";
	});

	afterAll(() => {
		config.ha.enabled = previousEnabled;
		config.ha.role = previousRole;
	});

	test("saveCertificate throws instead of writing locally", async () => {
		await expect(repository.saveCertificate(certificate)).rejects.toThrow(/Replica nodes cannot write/);
	});

	test("deleteCertificate throws instead of writing locally", async () => {
		await expect(repository.deleteCertificate(site.id)).rejects.toThrow(/Replica nodes cannot write/);
	});

	test("saveTlsSettings throws instead of writing locally", async () => {
		await expect(repository.saveTlsSettings(fakeTlsSettings(site.id))).rejects.toThrow(/Replica nodes cannot write/);
	});

	test("saveAcmeChallenge throws instead of writing locally", async () => {
		await expect(repository.saveAcmeChallenge(fakeAcmeChallenge(site.id))).rejects.toThrow(/Replica nodes cannot write/);
	});
});

describe("HA replication: auto-ban rules (ip/country/asn), primary", () => {
	let previousEnabled: boolean;
	let previousRole: typeof config.ha.role;

	beforeAll(() => {
		previousEnabled = config.ha.enabled;
		previousRole = config.ha.role;
		config.ha.enabled = true;
		config.ha.role = "primary";
	});

	afterAll(() => {
		config.ha.enabled = previousEnabled;
		config.ha.role = previousRole;
	});

	test("insertRule and deleteRuleForSite append changelog rows", async () => {
		const site = await makeSite("ha-ipban-primary.test");
		const rule = fakeIpRule(site.id);
		await repository.insertRule(rule);
		expect((await changelogFor(rule.id)).map((row) => row.op)).toEqual(["insert"]);
		await repository.deleteRuleForSite(rule.id, site.id);
		expect((await changelogFor(rule.id)).map((row) => row.op)).toEqual(["insert", "delete"]);
	});

	test("deleteRulesForSite (bulk) appends one delete row per id", async () => {
		const site = await makeSite("ha-ipban-bulk.test");
		const ruleA = fakeIpRule(site.id);
		const ruleB = fakeIpRule(site.id);
		await repository.insertRule(ruleA);
		await repository.insertRule(ruleB);
		await repository.deleteRulesForSite([ruleA.id, ruleB.id], site.id);
		expect((await changelogFor(ruleA.id)).map((row) => row.op)).toEqual(["insert", "delete"]);
		expect((await changelogFor(ruleB.id)).map((row) => row.op)).toEqual(["insert", "delete"]);
	});

	test("insertCountryRule and insertAsnRule append changelog rows", async () => {
		const site = await makeSite("ha-country-asn-primary.test");
		const countryRule = fakeCountryRule(site.id);
		const asnRule = fakeAsnRule(site.id);
		await repository.insertCountryRule(countryRule);
		await repository.insertAsnRule(asnRule);
		expect((await changelogFor(countryRule.id))[0]!.entity_type).toBe("country_rule");
		expect((await changelogFor(asnRule.id))[0]!.entity_type).toBe("asn_rule");
		await repository.deleteCountryRuleForSite(countryRule.id, site.id);
		await repository.deleteAsnRuleForSite(asnRule.id, site.id);
		expect((await changelogFor(countryRule.id)).map((row) => row.op)).toEqual(["insert", "delete"]);
		expect((await changelogFor(asnRule.id)).map((row) => row.op)).toEqual(["insert", "delete"]);
	});

	test("applyChangelogRow round-trips an ip_rule", async () => {
		const site = await makeSite("ha-ipban-apply.test");
		const rule = fakeIpRule(site.id);
		await repository.insertRule(rule);
		const insertRow = (await changelogFor(rule.id))[0]!;
		await repository.deleteRuleForSite(rule.id, site.id);
		await repository.applyReplicatedChange(insertRow);
		const rows = await repository.rules(site.id);
		expect(rows.find((r) => r.id === rule.id)?.network_cidr).toBe(rule.network_cidr);
	});
});

describe("HA replication: auto-ban rules (ip/country/asn), replica", () => {
	let previousEnabled: boolean;
	let previousRole: typeof config.ha.role;
	let site: SiteRecord;

	beforeAll(async () => {
		previousEnabled = config.ha.enabled;
		previousRole = config.ha.role;
		config.ha.enabled = true;
		config.ha.role = "primary";
		site = await makeSite("ha-ipban-replica.test");
		config.ha.role = "replica";
	});

	afterAll(() => {
		config.ha.enabled = previousEnabled;
		config.ha.role = previousRole;
	});

	test("a replica writes an auto-ban locally (multi-writer, no throw) and queues a relay row instead of a changelog row", async () => {
		const rule = fakeIpRule(site.id);
		await repository.insertRule(rule);

		const localRows = await repository.rules(site.id);
		expect(localRows.find((r) => r.id === rule.id)).toBeDefined();

		const relayRows = (await repository.pendingSessionRelayRows(1_000)).filter((row) => row.entity_type === "ip_rule" && row.entity_id === rule.id);
		expect(relayRows).toHaveLength(1);
		expect(relayRows[0]!.op).toBe("insert");

		const changelogRows = await changelogFor(rule.id);
		expect(changelogRows).toHaveLength(0);
	});

	test("insertCountryRule and insertAsnRule on a replica also queue relay rows", async () => {
		const countryRule = fakeCountryRule(site.id);
		const asnRule = fakeAsnRule(site.id);
		await repository.insertCountryRule(countryRule);
		await repository.insertAsnRule(asnRule);
		const relayRows = await repository.pendingSessionRelayRows(1_000);
		expect(relayRows.find((row) => row.entity_type === "country_rule" && row.entity_id === countryRule.id)).toBeDefined();
		expect(relayRows.find((row) => row.entity_type === "asn_rule" && row.entity_id === asnRule.id)).toBeDefined();
	});
});

describe("HA replication: identity settings (single-writer), primary", () => {
	let previousEnabled: boolean;
	let previousRole: typeof config.ha.role;

	beforeAll(() => {
		previousEnabled = config.ha.enabled;
		previousRole = config.ha.role;
		config.ha.enabled = true;
		config.ha.role = "primary";
	});

	afterAll(() => {
		config.ha.enabled = previousEnabled;
		config.ha.role = previousRole;
	});

	test("updateAccessSettings appends a row keyed by site_id", async () => {
		const site = await makeSite("ha-access-settings.test");
		const current = await repository.ensureAccessSettings(site.id);
		await repository.updateAccessSettings({ ...current, enabled: 1 });
		const rows = (await changelogFor(site.id)).filter((row) => row.entity_type === "site_access_settings");
		expect(rows.map((row) => row.op)).toEqual(["update"]);
		expect((JSON.parse(rows[0]!.payload_json!) as SiteAccessSettingsRecord).enabled).toBe(1);
	});

	test("saveAdminSsoSettings appends a row keyed by the constant instance id", async () => {
		const current = await repository.ensureAdminSsoSettings();
		await repository.saveAdminSsoSettings({ ...current, enabled: 1, issuer_url: "https://idp.example" });
		const rows = await changelogFor(current.id);
		expect(rows[rows.length - 1]!.entity_type).toBe("admin_sso_settings");
		expect((JSON.parse(rows[rows.length - 1]!.payload_json!) as AdminSsoSettingsRecord).issuer_url).toBe("https://idp.example");
	});

	test("saveSiteSsoSettings appends a row keyed by site_id", async () => {
		const site = await makeSite("ha-site-sso.test");
		const current = await repository.ensureSiteSsoSettings(site.id);
		await repository.saveSiteSsoSettings({ ...current, enabled: 1 });
		const rows = (await changelogFor(site.id)).filter((row) => row.entity_type === "site_sso_settings");
		expect(rows.map((row) => row.op)).toEqual(["update"]);
		expect((JSON.parse(rows[0]!.payload_json!) as SiteSsoSettingsRecord).enabled).toBe(1);
	});
});

describe("HA replication: identity settings (single-writer), replica write guard", () => {
	let previousEnabled: boolean;
	let previousRole: typeof config.ha.role;
	let site: SiteRecord;

	beforeAll(async () => {
		previousEnabled = config.ha.enabled;
		previousRole = config.ha.role;
		config.ha.enabled = true;
		config.ha.role = "primary";
		site = await makeSite("ha-identity-settings-guard.test");
		await repository.ensureAccessSettings(site.id);
		await repository.ensureSiteSsoSettings(site.id);
		config.ha.role = "replica";
	});

	afterAll(() => {
		config.ha.enabled = previousEnabled;
		config.ha.role = previousRole;
	});

	test("updateAccessSettings, saveAdminSsoSettings, and saveSiteSsoSettings all throw", async () => {
		const current = await repository.ensureAccessSettings(site.id);
		await expect(repository.updateAccessSettings(current)).rejects.toThrow(/Replica nodes cannot write/);
		const adminSso = await repository.ensureAdminSsoSettings();
		await expect(repository.saveAdminSsoSettings(adminSso)).rejects.toThrow(/Replica nodes cannot write/);
		const siteSso = await repository.ensureSiteSsoSettings(site.id);
		await expect(repository.saveSiteSsoSettings(siteSso)).rejects.toThrow(/Replica nodes cannot write/);
	});
});

describe("HA replication: firewall sync provider/whitelist (single-writer), primary", () => {
	let previousEnabled: boolean;
	let previousRole: typeof config.ha.role;

	beforeAll(() => {
		previousEnabled = config.ha.enabled;
		previousRole = config.ha.role;
		config.ha.enabled = true;
		config.ha.role = "primary";
	});

	afterAll(() => {
		config.ha.enabled = previousEnabled;
		config.ha.role = previousRole;
	});

	test("insertFirewallSyncProvider, updateFirewallSyncProviderConfig, deleteFirewallSyncProvider append changelog rows", async () => {
		const provider = fakeFirewallSyncProvider("HA fw provider");
		await repository.insertFirewallSyncProvider(provider);
		await repository.updateFirewallSyncProviderConfig(provider.id, "Renamed", 1, 75, provider.config_json, 1, Date.now());
		await repository.deleteFirewallSyncProvider(provider.id);
		const rows = await changelogFor(provider.id);
		expect(rows.map((row) => row.op)).toEqual(["insert", "update", "delete"]);
		expect((JSON.parse(rows[1]!.payload_json!) as FirewallSyncProviderRecord).name).toBe("Renamed");
		expect(rows[2]!.payload_json).toBeNull();
	});

	test("insertFirewallSyncWhitelistCidr and deleteFirewallSyncWhitelistCidr append changelog rows", async () => {
		const entry = fakeFirewallSyncWhitelistCidr();
		await repository.insertFirewallSyncWhitelistCidr(entry);
		await repository.deleteFirewallSyncWhitelistCidr(entry.id);
		const rows = await changelogFor(entry.id);
		expect(rows.map((row) => row.op)).toEqual(["insert", "delete"]);
		expect(rows[0]!.entity_type).toBe("firewall_sync_whitelist_cidr");
	});

	test("a replica applies a replicated provider insert/update/delete via applyChangelogRow", async () => {
		const provider = fakeFirewallSyncProvider("HA fw provider round-trip");
		await repository.insertFirewallSyncProvider(provider);
		await repository.updateFirewallSyncProviderConfig(provider.id, "Round trip renamed", 1, 30, provider.config_json, 1, Date.now());
		await repository.deleteFirewallSyncProvider(provider.id);
		for (const row of await changelogFor(provider.id)) await repository.applyReplicatedChange(row);
		expect(await repository.firewallSyncProviderById(provider.id)).toBeNull();
	});
});

describe("HA replication: firewall sync provider/whitelist (single-writer), replica write guard", () => {
	let previousEnabled: boolean;
	let previousRole: typeof config.ha.role;

	beforeAll(() => {
		previousEnabled = config.ha.enabled;
		previousRole = config.ha.role;
		config.ha.enabled = true;
		config.ha.role = "replica";
	});

	afterAll(() => {
		config.ha.enabled = previousEnabled;
		config.ha.role = previousRole;
	});

	test("insert/update/delete on providers and whitelist entries all throw", async () => {
		const provider = fakeFirewallSyncProvider("HA fw provider guard");
		await expect(repository.insertFirewallSyncProvider(provider)).rejects.toThrow(/Replica nodes cannot write/);
		await expect(repository.updateFirewallSyncProviderConfig(provider.id, "x", 1, 10, provider.config_json, 1, Date.now())).rejects.toThrow(
			/Replica nodes cannot write/,
		);
		await expect(repository.deleteFirewallSyncProvider(provider.id)).rejects.toThrow(/Replica nodes cannot write/);
		const entry = fakeFirewallSyncWhitelistCidr();
		await expect(repository.insertFirewallSyncWhitelistCidr(entry)).rejects.toThrow(/Replica nodes cannot write/);
		await expect(repository.deleteFirewallSyncWhitelistCidr(entry.id)).rejects.toThrow(/Replica nodes cannot write/);
	});
});

function fakePendingChange(entityId: string): PendingChangeRecord {
	const now = Date.now();
	return {
		id: randomId("pending"),
		entity_type: "site",
		entity_id: entityId,
		changes_json: JSON.stringify({ name: "Renamed via schedule" }),
		summary: "Scheduled rename",
		apply_at: now + 3_600_000,
		status: "pending",
		attempts: 0,
		last_error: null,
		created_by: "test-suite",
		created_at: now,
		applied_at: null,
	};
}

describe("HA replication: pending changes (single-writer), primary", () => {
	let previousEnabled: boolean;
	let previousRole: typeof config.ha.role;

	beforeAll(() => {
		previousEnabled = config.ha.enabled;
		previousRole = config.ha.role;
		config.ha.enabled = true;
		config.ha.role = "primary";
	});

	afterAll(() => {
		config.ha.enabled = previousEnabled;
		config.ha.role = previousRole;
	});

	test("insertPendingChange, updatePendingChangeStatus, deletePendingChange append changelog rows", async () => {
		const change = fakePendingChange("some-site-id");
		await repository.insertPendingChange(change);
		await repository.updatePendingChangeStatus(change.id, "failed", 1, change.apply_at, "simulated failure", null);
		await repository.deletePendingChange(change.id);
		const rows = await changelogFor(change.id);
		expect(rows.map((row) => row.op)).toEqual(["insert", "update", "delete"]);
		expect(rows.every((row) => row.entity_type === "pending_change")).toBe(true);
		expect((JSON.parse(rows[1]!.payload_json!) as PendingChangeRecord).status).toBe("failed");
		expect(rows[2]!.payload_json).toBeNull();
	});

	test("deleteFailedPendingChangesFor appends a changelog delete for the row it removes", async () => {
		const change = fakePendingChange("another-site-id");
		await repository.insertPendingChange(change);
		await repository.updatePendingChangeStatus(change.id, "failed", 1, change.apply_at, "simulated failure", null);
		await repository.deleteFailedPendingChangesFor("site", "another-site-id");
		const rows = await changelogFor(change.id);
		expect(rows.map((row) => row.op)).toEqual(["insert", "update", "delete"]);
	});

	test("deleteSiteCascade and deleteStream changelog the pending changes they cascade-delete", async () => {
		const site = await makeSite("pending-change-cascade.test");
		const change = fakePendingChange(site.id);
		await repository.insertPendingChange(change);
		await repository.deleteSiteCascade(site.id);
		const rows = await changelogFor(change.id);
		expect(rows.map((row) => row.op)).toEqual(["insert", "delete"]);
	});

	test("a replica applies a replicated pending change insert/update/delete via applyChangelogRow", async () => {
		const change = fakePendingChange("round-trip-site-id");
		await repository.insertPendingChange(change);
		await repository.updatePendingChangeStatus(change.id, "applied", 0, change.apply_at, null, Date.now());
		for (const row of await changelogFor(change.id)) await repository.applyReplicatedChange(row);
		expect((await repository.pendingChangeById(change.id))?.status).toBe("applied");
		await repository.deletePendingChange(change.id);
		for (const row of (await changelogFor(change.id)).slice(-1)) await repository.applyReplicatedChange(row);
		expect(await repository.pendingChangeById(change.id)).toBeNull();
	});
});

describe("HA replication: pending changes (single-writer), replica write guard", () => {
	let previousEnabled: boolean;
	let previousRole: typeof config.ha.role;

	beforeAll(() => {
		previousEnabled = config.ha.enabled;
		previousRole = config.ha.role;
		config.ha.enabled = true;
		config.ha.role = "replica";
	});

	afterAll(() => {
		config.ha.enabled = previousEnabled;
		config.ha.role = previousRole;
	});

	test("insert/update/delete all throw", async () => {
		const change = fakePendingChange("guard-site-id");
		await expect(repository.insertPendingChange(change)).rejects.toThrow(/Replica nodes cannot write/);
		await expect(repository.updatePendingChangeStatus(change.id, "failed", 1, change.apply_at, "x", null)).rejects.toThrow(/Replica nodes cannot write/);
		await expect(repository.deletePendingChange(change.id)).rejects.toThrow(/Replica nodes cannot write/);
		await expect(repository.deleteFailedPendingChangesFor("site", "guard-site-id")).rejects.toThrow(/Replica nodes cannot write/);
	});
});

describe("HA replication: ACME account (single-writer), primary", () => {
	let previousEnabled: boolean;
	let previousRole: typeof config.ha.role;

	beforeAll(() => {
		previousEnabled = config.ha.enabled;
		previousRole = config.ha.role;
		config.ha.enabled = true;
		config.ha.role = "primary";
	});

	afterAll(() => {
		config.ha.enabled = previousEnabled;
		config.ha.role = previousRole;
	});

	function fakeAcmeAccount(directoryUrl: string): AcmeAccountRecord {
		return {
			id: randomId("acme_account"),
			directory_url: directoryUrl,
			email: "ops@example.test",
			account_url: null,
			encrypted_account_key: "encrypted-key-placeholder",
			terms_accepted_at: Date.now(),
			created_at: Date.now(),
			updated_at: Date.now(),
		};
	}

	test("saveAcmeAccount appends an insert then an update changelog row", async () => {
		const account = fakeAcmeAccount("https://acme.example.test/directory/insert-update");
		await repository.saveAcmeAccount(account);
		const updated = { ...account, account_url: "https://acme.example.test/acct/1", updated_at: Date.now() };
		await repository.saveAcmeAccount(updated);
		const rows = await changelogFor(account.id);
		expect(rows.map((row) => row.op)).toEqual(["insert", "update"]);
		expect(rows.every((row) => row.entity_type === "acme_account")).toBe(true);
		expect((JSON.parse(rows[1]!.payload_json!) as AcmeAccountRecord).account_url).toBe("https://acme.example.test/acct/1");
	});

	test("a replica applies a replicated ACME account insert/update via applyChangelogRow", async () => {
		const account = fakeAcmeAccount("https://acme.example.test/directory/round-trip");
		await repository.saveAcmeAccount(account);
		const updated = { ...account, account_url: "https://acme.example.test/acct/2", updated_at: Date.now() };
		await repository.saveAcmeAccount(updated);
		for (const row of await changelogFor(account.id)) await repository.applyReplicatedChange(row);
		expect((await repository.acmeAccount(account.directory_url))?.account_url).toBe("https://acme.example.test/acct/2");
	});
});

describe("HA replication: admin/access identity (multi-writer), primary", () => {
	let previousEnabled: boolean;
	let previousRole: typeof config.ha.role;

	beforeAll(() => {
		previousEnabled = config.ha.enabled;
		previousRole = config.ha.role;
		config.ha.enabled = true;
		config.ha.role = "primary";
	});

	afterAll(() => {
		config.ha.enabled = previousEnabled;
		config.ha.role = previousRole;
	});

	test("insertAdminUser and updateAdminUser append changelog rows", async () => {
		const user = fakeAdminUser("ha-identity-admin");
		await repository.insertAdminUser(user);
		await repository.updateAdminUser({ ...user, username: "ha-identity-admin-renamed" });
		const rows = await changelogFor(user.id);
		expect(rows.map((row) => row.op)).toEqual(["insert", "update"]);
		expect(rows[0]!.entity_type).toBe("admin_user");
	});

	test("insertAccessUser, assignAccessUser, and unassignAccessUser append changelog rows", async () => {
		const site = await makeSite("ha-identity-access-user.test");
		const user = fakeAccessUser("ha-identity-access-user");
		await repository.insertAccessUser(user);
		await repository.assignAccessUser(site.id, user.id);
		const joinKey = `${site.id}:${user.id}`;
		const joinRows = await changelogFor(joinKey);
		expect(joinRows.map((row) => row.op)).toEqual(["insert"]);
		expect(joinRows[0]!.entity_type).toBe("site_access_user");

		await repository.unassignAccessUser(site.id, user.id);
		expect((await changelogFor(joinKey)).map((row) => row.op)).toEqual(["insert", "delete"]);
	});

	test("replaceAdminRecoveryCodes and consumeAdminRecoveryCodeByHash append changelog rows", async () => {
		const user = fakeAdminUser("ha-identity-recovery");
		await repository.insertAdminUser(user);
		const codeA = fakeAdminRecoveryCode(user.id);
		const codeB = fakeAdminRecoveryCode(user.id);
		await repository.replaceAdminRecoveryCodes(user.id, [codeA, codeB]);
		expect((await changelogFor(codeA.id))[0]!.op).toBe("insert");
		expect((await changelogFor(codeB.id))[0]!.op).toBe("insert");

		const consumed = await repository.consumeAdminRecoveryCodeByHash(user.id, codeA.code_hash, Date.now());
		expect(consumed).toBe(true);
		const rows = await changelogFor(codeA.id);
		expect(rows.map((row) => row.op)).toEqual(["insert", "update"]);
	});

	test("admin and access webauthn credential writes append changelog rows", async () => {
		const adminUser = fakeAdminUser("ha-identity-wan-admin");
		await repository.insertAdminUser(adminUser);
		const adminCred = fakeAdminWebauthnCredential(adminUser.id);
		await repository.insertAdminWebauthnCredential(adminCred);
		await repository.renameAdminWebauthnCredential(adminCred.id, adminUser.id, "My key", Date.now());
		await repository.deleteAdminWebauthnCredential(adminCred.id, adminUser.id);
		expect((await changelogFor(adminCred.id)).map((row) => row.op)).toEqual(["insert", "update", "delete"]);

		const site = await makeSite("ha-identity-wan-access.test");
		const accessUser = fakeAccessUser("ha-identity-wan-access");
		await repository.insertAccessUser(accessUser);
		const accessCred = fakeAccessWebauthnCredential(accessUser.id, site.id);
		await repository.insertAccessWebauthnCredential(accessCred);
		await repository.deleteAccessWebauthnCredential(accessCred.id, accessUser.id, site.id);
		expect((await changelogFor(accessCred.id)).map((row) => row.op)).toEqual(["insert", "delete"]);
	});

	test("deleteAdminUserCascade emits delete entries for the user, recovery codes, and webauthn credentials", async () => {
		const user = fakeAdminUser("ha-identity-cascade");
		await repository.insertAdminUser(user);
		const code = fakeAdminRecoveryCode(user.id);
		await repository.replaceAdminRecoveryCodes(user.id, [code]);
		const cred = fakeAdminWebauthnCredential(user.id);
		await repository.insertAdminWebauthnCredential(cred);

		await repository.deleteAdminUserCascade(user.id);

		expect((await changelogFor(user.id)).map((row) => row.op)).toEqual(["insert", "delete"]);
		expect((await changelogFor(code.id)).map((row) => row.op)).toEqual(["insert", "delete"]);
		expect((await changelogFor(cred.id)).map((row) => row.op)).toEqual(["insert", "delete"]);
	});

	test("applyChangelogRow round-trips a site_access_user composite-key row", async () => {
		const site = await makeSite("ha-identity-join-apply.test");
		const user = fakeAccessUser("ha-identity-join-apply");
		await repository.insertAccessUser(user);
		await repository.assignAccessUser(site.id, user.id);
		const insertRow = (await changelogFor(`${site.id}:${user.id}`))[0]!;
		await repository.unassignAccessUser(site.id, user.id);
		expect(await repository.accessSiteIdsForUser(user.id)).toEqual([]);
		await repository.applyReplicatedChange(insertRow);
		expect(await repository.accessSiteIdsForUser(user.id)).toEqual([site.id]);
	});
});

describe("HA replication: admin/access identity (multi-writer), replica", () => {
	let previousEnabled: boolean;
	let previousRole: typeof config.ha.role;

	beforeAll(() => {
		previousEnabled = config.ha.enabled;
		previousRole = config.ha.role;
		config.ha.enabled = true;
		config.ha.role = "replica";
	});

	afterAll(() => {
		config.ha.enabled = previousEnabled;
		config.ha.role = previousRole;
	});

	test("insertAdminUser and insertAccessUser write locally and queue relay rows instead of throwing", async () => {
		const adminUser = fakeAdminUser("ha-identity-replica-admin");
		await repository.insertAdminUser(adminUser);
		expect(await repository.adminUserById(adminUser.id)).not.toBeNull();
		const relayRows = await repository.pendingSessionRelayRows(1_000);
		expect(relayRows.find((row) => row.entity_type === "admin_user" && row.entity_id === adminUser.id)).toBeDefined();

		const accessUser = fakeAccessUser("ha-identity-replica-access");
		await repository.insertAccessUser(accessUser);
		expect(await repository.accessUserById(accessUser.id)).not.toBeNull();
		const relayRows2 = await repository.pendingSessionRelayRows(1_000);
		expect(relayRows2.find((row) => row.entity_type === "access_user" && row.entity_id === accessUser.id)).toBeDefined();
	});
});

describe("HA replication: sequence continuation on promotion", () => {
	let previousEnabled: boolean;
	let previousRole: typeof config.ha.role;

	beforeAll(() => {
		previousEnabled = config.ha.enabled;
		previousRole = config.ha.role;
		config.ha.enabled = true;
		config.ha.role = "primary";
	});

	afterAll(() => {
		config.ha.enabled = previousEnabled;
		config.ha.role = previousRole;
	});

	test("bumpChangelogSequenceTo raises the next issued seq and a lower watermark never regresses it", async () => {
		const site = await makeSite("ha-seq-bump-baseline.test");
		const baselineSeq = (await changelogFor(site.id))[0]!.seq;

		await repository.bumpChangelogSequenceTo(baselineSeq + 1_000);
		const afterBump = await makeSite("ha-seq-bump-after.test");
		const seqAfterBump = (await changelogFor(afterBump.id))[0]!.seq;
		expect(seqAfterBump).toBeGreaterThan(baselineSeq + 1_000);

		await repository.bumpChangelogSequenceTo(1);
		const afterLowBump = await makeSite("ha-seq-bump-after-low.test");
		const seqAfterLowBump = (await changelogFor(afterLowBump.id))[0]!.seq;
		expect(seqAfterLowBump).toBeGreaterThan(seqAfterBump);
	});
});

describe("HA replication: full snapshot bootstrap", () => {
	let previousEnabled: boolean;
	let previousRole: typeof config.ha.role;

	beforeAll(() => {
		previousEnabled = config.ha.enabled;
		previousRole = config.ha.role;
		config.ha.enabled = true;
		config.ha.role = "primary";
	});

	afterAll(() => {
		config.ha.enabled = previousEnabled;
		config.ha.role = previousRole;
	});

	test("fullSnapshot captures the current state of every replicated entity type, keyed like applyChangelogRow expects", async () => {
		const site = await makeSite("ha-snapshot.test");
		const origin = fakeOrigin(site.id);
		await repository.insertOrigin(origin);
		const user = fakeAccessUser("ha-snapshot-access-user");
		await repository.insertAccessUser(user);
		await repository.assignAccessUser(site.id, user.id);

		const snapshot = await repository.fullSnapshot();
		expect(snapshot.seq).toBeGreaterThan(0);

		const siteRow = snapshot.rows.find((row) => row.entity_type === "site" && row.entity_id === site.id);
		expect(siteRow).toBeDefined();
		expect((JSON.parse(siteRow!.payload_json) as SiteRecord).public_host).toBe("ha-snapshot.test");
		const originRow = snapshot.rows.find((row) => row.entity_type === "site_origin" && row.entity_id === origin.id);
		expect(originRow).toBeDefined();
		const joinRow = snapshot.rows.find((row) => row.entity_type === "site_access_user" && row.entity_id === `${site.id}:${user.id}`);
		expect(joinRow).toBeDefined();
	});

	test("fullSnapshot carries durable HA membership so a promoted replica keeps offline-node version fences", async () => {
		const now = Date.now();
		await repository.upsertHaClusterMember({
			node_id: "snapshot-offline-member",
			name: "offline member",
			version: "0.0.1",
			admin_url: "https://offline-member.test",
			first_seen_at: now,
			last_seen_at: now,
			credential_hash: await sha256Hex("snapshot-offline-member-credential"),
		});
		try {
			const snapshot = await repository.fullSnapshot();
			const member = snapshot.rows.find((row) => row.entity_type === "ha_cluster_member" && row.entity_id === "snapshot-offline-member");
			expect(member).toBeDefined();
			expect(JSON.parse(member!.payload_json).version).toBe("0.0.1");
		} finally {
			await repository.deleteHaClusterMember("snapshot-offline-member", 1);
		}
	});

	test("a snapshot row round-trips through applyReplicatedChange, same as a live changelog row", async () => {
		const site = await makeSite("ha-snapshot-apply.test");
		const snapshot = await repository.fullSnapshot();
		const siteRow = snapshot.rows.find((row) => row.entity_type === "site" && row.entity_id === site.id)!;
		await repository.deleteSiteCascade(site.id);
		expect(await repository.siteById(site.id)).toBeNull();
		await repository.applyReplicatedChange({
			seq: 0,
			entity_type: siteRow.entity_type,
			entity_id: siteRow.entity_id,
			op: "insert",
			payload_json: siteRow.payload_json,
			created_at: Date.now(),
		});
		expect(await repository.siteById(site.id)).not.toBeNull();
	});

	test("needsBootstrap/markBootstrapped round-trip, distinct from the incremental cursor", async () => {
		await repository.markBootstrapped(42);
		expect(await repository.needsBootstrap()).toBe(false);
		expect(await repository.replicationCursor()).toBe(42);
	});
});

describe("HA replication: changelog pruning", () => {
	let previousEnabled: boolean;
	let previousRole: typeof config.ha.role;

	beforeAll(() => {
		previousEnabled = config.ha.enabled;
		previousRole = config.ha.role;
		config.ha.enabled = true;
		config.ha.role = "primary";
	});

	afterAll(() => {
		config.ha.enabled = previousEnabled;
		config.ha.role = previousRole;
	});

	test("deleteReplicationChangelogBeforeBatch removes only rows older than the cutoff", async () => {
		const oldSite = await makeSite("ha-prune-old.test");
		const oldRow = (await changelogFor(oldSite.id))[0]!;
		const cutoff = Date.now();
		await db`UPDATE replication_changelog SET created_at=${cutoff - 10_000} WHERE seq=${oldRow.seq}`;

		const newSite = await makeSite("ha-prune-new.test");
		const newRow = (await changelogFor(newSite.id))[0]!;
		await db`UPDATE replication_changelog SET created_at=${cutoff + 10_000} WHERE seq=${newRow.seq}`;

		await repository.deleteReplicationChangelogBeforeBatch(cutoff, 1_000);
		const remaining = (await repository.changelogSince(0, 100_000)).map((row) => row.seq);
		expect(remaining).not.toContain(oldRow.seq);
		expect(remaining).toContain(newRow.seq);
	});

	test("deleteReplicationChangelogBeforeBatch respects the batch limit", async () => {
		const cutoff = Date.now() + 60_000;
		const siteA = await makeSite("ha-prune-batch-a.test");
		const siteB = await makeSite("ha-prune-batch-b.test");
		const rowA = (await changelogFor(siteA.id))[0]!;
		const rowB = (await changelogFor(siteB.id))[0]!;
		await db`UPDATE replication_changelog SET created_at=${cutoff - 1_000} WHERE seq=${rowA.seq}`;
		await db`UPDATE replication_changelog SET created_at=${cutoff - 1_000} WHERE seq=${rowB.seq}`;

		const deleted = await repository.deleteReplicationChangelogBeforeBatch(cutoff, 1);
		expect(deleted).toBe(1);
	});

	test("latestChangelogSeq retains its durable high watermark after every changelog row is pruned", async () => {
		await makeSite("ha-prune-watermark.test");
		const highWatermark = await repository.latestChangelogSeq();
		expect(highWatermark).toBeGreaterThan(0);

		await db`DELETE FROM replication_changelog`;

		expect(await repository.changelogSince(0, 10)).toHaveLength(0);
		expect(await repository.latestChangelogSeq()).toBe(highWatermark);
		expect((await repository.fullSnapshot()).seq).toBe(highWatermark);
	});

	test("deleteDeadLetteredRelaysBeforeBatch removes only rows older than the cutoff", async () => {
		await repository.deadLetterRelay("prune-node", 1, "admin_session", "sess_old", "insert", null, "old failure");
		const cutoff = Date.now();
		await db`UPDATE dead_lettered_relays SET occurred_at=${cutoff - 10_000} WHERE node_id='prune-node' AND relay_id=1`;
		await repository.deadLetterRelay("prune-node", 2, "admin_session", "sess_new", "insert", null, "new failure");
		await db`UPDATE dead_lettered_relays SET occurred_at=${cutoff + 10_000} WHERE node_id='prune-node' AND relay_id=2`;

		await repository.deleteDeadLetteredRelaysBeforeBatch(cutoff, 1_000);

		const remaining = (await db`SELECT relay_id FROM dead_lettered_relays WHERE node_id='prune-node'`) as Array<{ relay_id: number }>;
		expect(remaining.map((r) => r.relay_id)).toEqual([2]);
	});
});

describe("HA replication: snapshot reconciliation removes stale local rows", () => {
	let previousEnabled: boolean;
	let previousRole: typeof config.ha.role;

	beforeAll(() => {
		previousEnabled = config.ha.enabled;
		previousRole = config.ha.role;
		config.ha.enabled = true;
		config.ha.role = "primary";
	});

	afterAll(() => {
		config.ha.enabled = previousEnabled;
		config.ha.role = previousRole;
	});

	test("a row present locally but absent from the snapshot is removed, not left behind", async () => {
		const site = await makeSite("ha-reconcile.test");
		const staleRule = fakeIpRule(site.id);
		await repository.insertRule(staleRule);
		expect(await repository.rules(site.id)).toHaveLength(1);

		const snapshotSite = await repository.siteById(site.id);
		await repository.reconcileToSnapshot([{ entity_type: "site", entity_id: site.id, payload_json: JSON.stringify(snapshotSite) }]);

		expect(await repository.rules(site.id)).toHaveLength(0);
		expect(await repository.siteById(site.id)).not.toBeNull();
		expect((await repository.siteById(site.id))!.id).toBe(site.id);
	});

	test("a snapshot preserves and reapplies local replica writes still queued for relay", async () => {
		const site = await makeSite("ha-reconcile-outbox.test");
		const snapshotSite = await repository.siteById(site.id);
		const pendingRule = fakeIpRule(site.id);
		config.ha.role = "replica";
		try {
			await repository.insertRule(pendingRule);
			const queuedBefore = (await db`SELECT id FROM session_relay_outbox WHERE entity_id=${pendingRule.id}`) as Array<{ id: number }>;
			expect(queuedBefore).toHaveLength(1);

			await repository.reconcileToSnapshot([{ entity_type: "site", entity_id: site.id, payload_json: JSON.stringify(snapshotSite) }]);

			expect((await repository.rules(site.id)).map((rule) => rule.id)).toContain(pendingRule.id);
			const queuedAfter = (await db`SELECT id FROM session_relay_outbox WHERE entity_id=${pendingRule.id}`) as Array<{ id: number }>;
			expect(queuedAfter).toEqual(queuedBefore);
			await repository.deleteSessionRelayRows(queuedAfter.map((row) => row.id));
		} finally {
			config.ha.role = "primary";
		}
	});

	test("a snapshot does not resurrect an accepted relay whose acknowledgement was lost", async () => {
		const user = fakeAdminUser("ha-reconcile-accepted-outbox");
		await repository.insertAdminUser(user);
		const localNodeId = await repository.haNodeId();
		config.ha.role = "replica";
		try {
			await repository.updateAdminUser({ ...user, username: "stale-local-retry", updated_at: user.updated_at + 1 });
			const queued = (await db`SELECT id FROM session_relay_outbox WHERE entity_id=${user.id} ORDER BY id ASC`) as Array<{ id: number }>;
			expect(queued).toHaveLength(1);
			const relayId = queued[0]!.id;
			const authoritative = { ...user, username: "newer-authoritative-value", updated_at: user.updated_at + 2 };

			await repository.reconcileToSnapshot([
				{ entity_type: "admin_user", entity_id: user.id, payload_json: JSON.stringify(authoritative) },
				{
					entity_type: "relay_watermark",
					entity_id: localNodeId,
					payload_json: JSON.stringify({ node_id: localNodeId, last_relay_id: relayId, updated_at: Date.now() }),
				},
			]);

			expect((await repository.adminUserById(user.id))?.username).toBe("newer-authoritative-value");
			expect((await db`SELECT id FROM session_relay_outbox WHERE id=${relayId}`) as unknown[]).toHaveLength(1);
			await repository.deleteSessionRelayRows([relayId]);
		} finally {
			config.ha.role = "primary";
		}
	});
});

describe("HA replication: relay dedup by (nodeId, relayId)", () => {
	let previousEnabled: boolean;
	let previousRole: typeof config.ha.role;

	beforeAll(() => {
		previousEnabled = config.ha.enabled;
		previousRole = config.ha.role;
		config.ha.enabled = true;
		config.ha.role = "primary";
	});

	afterAll(() => {
		config.ha.enabled = previousEnabled;
		config.ha.role = previousRole;
	});

	test("a retried relay with the same (nodeId, relayId) is ignored, even carrying a different payload", async () => {
		const user = fakeAdminUser("ha-relay-dedup");
		await repository.insertAdminUser(user);
		const firstPayload = { ...user, username: "first-username" };
		const secondPayload = { ...user, username: "clobbering-retry-username" };

		await repository.applyReplicatedSessionRelay("replica-a", 99, "admin_user", user.id, "update", firstPayload);
		expect((await repository.adminUserById(user.id))!.username).toBe("first-username");
		const rowsAfterFirst = await changelogFor(user.id);

		await repository.applyReplicatedSessionRelay("replica-a", 99, "admin_user", user.id, "update", secondPayload);
		expect((await repository.adminUserById(user.id))!.username).toBe("first-username");
		expect(await changelogFor(user.id)).toEqual(rowsAfterFirst);

		await repository.applyReplicatedSessionRelay("replica-a", 100, "admin_user", user.id, "update", secondPayload);
		expect((await repository.adminUserById(user.id))!.username).toBe("clobbering-retry-username");

		await repository.applyReplicatedSessionRelay("replica-a", 102, "admin_user", user.id, "update", firstPayload);
		expect((await repository.adminUserById(user.id))!.username).toBe("first-username");
	});

	test("a promoted replica adopts relay rows created after its prepare acknowledgement", async () => {
		const user = fakeAdminUser("ha-promotion-outbox-adoption");
		const localNodeId = await repository.haNodeId();

		await db`DELETE FROM session_relay_outbox`;
		config.ha.role = "replica";
		await repository.insertAdminUser(user);
		const queued = (await db`SELECT id FROM session_relay_outbox WHERE entity_id=${user.id} ORDER BY id ASC`) as Array<{ id: number }>;
		expect(queued).toHaveLength(1);

		config.ha.role = "primary";
		const adopted = await repository.adoptPendingSessionRelaysAsPrimary(localNodeId);
		expect(adopted).toBe(1);
		expect((await db`SELECT id FROM session_relay_outbox WHERE id=${queued[0]!.id}`) as unknown[]).toHaveLength(0);
		const watermarks = (await db`SELECT last_relay_id FROM replication_relay_watermarks WHERE node_id=${localNodeId}`) as Array<{
			last_relay_id: number;
		}>;
		expect(Number(watermarks[0]?.last_relay_id)).toBe(queued[0]!.id);
		expect((await changelogFor(user.id)).at(-1)?.payload_json).toContain("burrowgate-ha-relay-event-v1");
	});

	test("relay dedup watermarks are included in snapshots and survive primary promotion", async () => {
		const user = fakeAdminUser("ha-relay-promotion");
		await repository.insertAdminUser(user);
		await repository.applyReplicatedSessionRelay("stable-node-id", 41, "admin_user", user.id, "update", { ...user, username: "first-apply" });
		const relayChange = (await changelogFor(user.id)).at(-1)!;
		const snapshot = await repository.fullSnapshot();
		const watermark = snapshot.rows.find((row) => row.entity_type === "relay_watermark" && row.entity_id === "stable-node-id");
		expect(watermark).toBeDefined();

		await db`DELETE FROM replication_relay_watermarks WHERE node_id='stable-node-id'`;
		await repository.applyReplicatedChange(relayChange);
		await repository.applyReplicatedSessionRelay("stable-node-id", 41, "admin_user", user.id, "update", { ...user, username: "stale-retry" });
		expect((await repository.adminUserById(user.id))!.username).toBe("first-apply");

		const rows = (await db`SELECT * FROM replication_relay_watermarks WHERE node_id='stable-node-id'`) as unknown[];
		expect(rows).toHaveLength(1);
	});

	test("replica identity updates relay field patches and cannot restore an unrelated stale password", async () => {
		const user = fakeAdminUser("ha-field-patch");
		await repository.insertAdminUser(user);
		config.ha.role = "replica";
		try {
			await repository.updateAdminUser({ ...user, role: "member", updated_at: user.updated_at + 1 });
		} finally {
			config.ha.role = "primary";
		}
		const queued = (
			(await db`SELECT * FROM session_relay_outbox WHERE entity_id=${user.id} ORDER BY id DESC LIMIT 1`) as Array<{
				id: number;
				entity_type: "admin_user";
				entity_id: string;
				op: "update";
				payload_json: string;
			}>
		)[0]!;

		const current = (await repository.adminUserById(user.id))!;
		await repository.updateAdminUser({ ...current, password_hash: "new-primary-password", role: "administrator", updated_at: current.updated_at + 1 });
		await repository.applyReplicatedSessionRelay(
			"field-patch-node",
			queued.id,
			queued.entity_type,
			queued.entity_id,
			queued.op,
			JSON.parse(queued.payload_json),
		);

		const applied = (await repository.adminUserById(user.id))!;
		expect(applied.role).toBe("member");
		expect(applied.password_hash).toBe("new-primary-password");
		await repository.deleteSessionRelayRows([queued.id]);
	});
});

describe("HA replication: migration adds bootstrapped to an existing replication_cursor table", () => {
	test("migrate preserves the node's immutable relay identity", async () => {
		const before = await repository.haNodeId();
		await migrate();
		expect(await repository.haNodeId()).toBe(before);
	});

	test("needsBootstrap works again after the missing column is added back by re-running migrate()", async () => {
		await db.unsafe("ALTER TABLE replication_cursor DROP COLUMN bootstrapped");
		await expect(repository.needsBootstrap()).rejects.toThrow();

		await migrate();

		const stillNeedsBootstrap = await repository.needsBootstrap();
		expect(typeof stillNeedsBootstrap).toBe("boolean");
	});
});

describe("HA replication: streams, primary", () => {
	let previousEnabled: boolean;
	let previousRole: typeof config.ha.role;

	beforeAll(() => {
		previousEnabled = config.ha.enabled;
		previousRole = config.ha.role;
		config.ha.enabled = true;
		config.ha.role = "primary";
	});

	afterAll(() => {
		config.ha.enabled = previousEnabled;
		config.ha.role = previousRole;
	});

	test("saveStream appends insert then update rows carrying the full row snapshot", async () => {
		const stream = await makeStream("ha-stream-insert");
		const renamed = { ...stream, name: "renamed stream", updated_at: Date.now() };
		await repository.saveStream(renamed);
		const rows = await changelogFor(stream.id);
		expect(rows.map((row) => row.op)).toEqual(["insert", "update"]);
		expect(rows[0]!.entity_type).toBe("stream");
		const insertPayload = JSON.parse(rows[0]!.payload_json!) as { incoming_port: number };
		expect(insertPayload.incoming_port).toBe(stream.incoming_port);
		const updatePayload = JSON.parse(rows[1]!.payload_json!) as { name: string };
		expect(updatePayload.name).toBe("renamed stream");
	});

	test("insertStreamRule, insertStreamCountryRule, and insertStreamAsnRule append changelog rows", async () => {
		const stream = await makeStream("ha-stream-rules");
		const ipRule = fakeStreamIpRule(stream.id);
		const countryRule = fakeStreamCountryRule(stream.id);
		const asnRule = fakeStreamAsnRule(stream.id);
		await repository.insertStreamRule(ipRule);
		await repository.insertStreamCountryRule(countryRule);
		await repository.insertStreamAsnRule(asnRule);
		expect((await changelogFor(ipRule.id))[0]!.entity_type).toBe("stream_ip_rule");
		expect((await changelogFor(countryRule.id))[0]!.entity_type).toBe("stream_country_rule");
		expect((await changelogFor(asnRule.id))[0]!.entity_type).toBe("stream_asn_rule");

		await repository.deleteStreamRuleForStream(ipRule.id, stream.id);
		await repository.deleteStreamCountryRuleForStream(countryRule.id, stream.id);
		await repository.deleteStreamAsnRuleForStream(asnRule.id, stream.id);
		expect((await changelogFor(ipRule.id)).map((r) => r.op)).toEqual(["insert", "delete"]);
		expect((await changelogFor(countryRule.id)).map((r) => r.op)).toEqual(["insert", "delete"]);
		expect((await changelogFor(asnRule.id)).map((r) => r.op)).toEqual(["insert", "delete"]);
	});

	test("updateStreamNetworkDefaults, updateStreamProtectionPolicy, updateStreamBandwidthPolicy, and updateStreamNotificationPolicy all append update rows for the stream", async () => {
		const stream = await makeStream("ha-stream-policies");
		await repository.updateStreamNetworkDefaults(stream.id, "block", "block", Date.now());
		await repository.updateStreamProtectionPolicy(stream.id, "{}", Date.now());
		await repository.updateStreamBandwidthPolicy(stream.id, "{}", Date.now());
		await repository.updateStreamNotificationPolicy(stream.id, "{}", Date.now());
		const rows = (await changelogFor(stream.id)).filter((row) => row.entity_type === "stream");
		expect(rows.map((row) => row.op)).toEqual(["insert", "update", "update", "update", "update"]);
	});

	test("deleteStream appends delete rows for the stream and its network rules", async () => {
		const stream = await makeStream("ha-stream-delete");
		const ipRule = fakeStreamIpRule(stream.id);
		await repository.insertStreamRule(ipRule);
		await repository.deleteStream(stream.id);
		expect((await changelogFor(stream.id)).filter((row) => row.entity_type === "stream").map((row) => row.op)).toEqual(["insert", "delete"]);
		expect((await changelogFor(ipRule.id)).map((row) => row.op)).toEqual(["insert", "delete"]);
	});

	test("applyChangelogRow round-trips a stream row, rebuilding stream_bindings the same way saveStream does", async () => {
		const stream = await makeStream("ha-stream-apply");
		const insertRow = (await changelogFor(stream.id))[0]!;
		await repository.deleteStream(stream.id);
		expect(await repository.streamById(stream.id)).toBeNull();

		await repository.applyReplicatedChange(insertRow);

		const applied = await repository.streamById(stream.id);
		expect(applied).not.toBeNull();
		expect(applied!.name).toBe(stream.name);
		const bindings = (await db`SELECT protocol FROM stream_bindings WHERE stream_id=${stream.id}`) as Array<{ protocol: string }>;
		expect(bindings.map((b) => b.protocol)).toEqual(["tcp"]);
	});
});

describe("HA replication: streams, replica write guard", () => {
	let previousEnabled: boolean;
	let previousRole: typeof config.ha.role;
	let stream: Awaited<ReturnType<typeof makeStream>>;

	beforeAll(async () => {
		previousEnabled = config.ha.enabled;
		previousRole = config.ha.role;
		config.ha.enabled = true;
		config.ha.role = "primary";
		stream = await makeStream("ha-stream-guard");
		config.ha.role = "replica";
	});

	afterAll(() => {
		config.ha.enabled = previousEnabled;
		config.ha.role = previousRole;
	});

	test("saveStream and deleteStream throw instead of writing locally", async () => {
		await expect(repository.saveStream({ ...stream, name: "should not apply" })).rejects.toThrow(/Replica nodes cannot write/);
		await expect(repository.deleteStream(stream.id)).rejects.toThrow(/Replica nodes cannot write/);
	});

	test("updateStreamNetworkDefaults throws instead of writing locally", async () => {
		await expect(repository.updateStreamNetworkDefaults(stream.id, "block", "block", Date.now())).rejects.toThrow(/Replica nodes cannot write/);
	});

	test("insertStreamRule writes locally and queues a relay instead of throwing", async () => {
		const rule = fakeStreamIpRule(stream.id);
		await repository.insertStreamRule(rule);

		expect((await repository.streamRules(stream.id)).map((r) => r.id)).toContain(rule.id);
		const queued = (await db`SELECT id, entity_type FROM session_relay_outbox WHERE entity_id=${rule.id}`) as Array<{ id: number; entity_type: string }>;
		expect(queued).toHaveLength(1);
		expect(queued[0]?.entity_type).toBe("stream_ip_rule");
		await repository.deleteSessionRelayRows(queued.map((row) => row.id));
	});
});

describe("HA replication: admin RBAC (multi-writer), primary", () => {
	let previousEnabled: boolean;
	let previousRole: typeof config.ha.role;

	beforeAll(() => {
		previousEnabled = config.ha.enabled;
		previousRole = config.ha.role;
		config.ha.enabled = true;
		config.ha.role = "primary";
	});

	afterAll(() => {
		config.ha.enabled = previousEnabled;
		config.ha.role = previousRole;
	});

	test("replaceAdminSitePermissions and replaceAdminStreamPermissions append per-permission changelog rows", async () => {
		const site = await makeSite("ha-rbac-site.test");
		const stream = await makeStream("ha-rbac-stream");
		const user = fakeAdminUser("ha-rbac-user");
		await repository.insertAdminUser(user);

		await repository.replaceAdminSitePermissions(user.id, [{ siteId: site.id, level: "manager" }]);
		const siteJoinKey = `${user.id}:${site.id}`;
		expect((await changelogFor(siteJoinKey)).map((row) => row.op)).toEqual(["insert"]);
		expect((await changelogFor(siteJoinKey))[0]!.entity_type).toBe("admin_site_permission");

		await repository.replaceAdminStreamPermissions(user.id, [{ streamId: stream.id, level: "manager" }]);
		const streamJoinKey = `${user.id}:${stream.id}`;
		expect((await changelogFor(streamJoinKey)).map((row) => row.op)).toEqual(["insert"]);

		await repository.replaceAdminSitePermissions(user.id, []);
		expect((await changelogFor(siteJoinKey)).map((row) => row.op)).toEqual(["insert", "delete"]);
	});

	test("applyChangelogRow round-trips an admin_site_permission composite-key row", async () => {
		const site = await makeSite("ha-rbac-apply.test");
		const user = fakeAdminUser("ha-rbac-apply-user");
		await repository.insertAdminUser(user);
		await repository.replaceAdminSitePermissions(user.id, [{ siteId: site.id, level: "viewer" }]);
		const insertRow = (await changelogFor(`${user.id}:${site.id}`))[0]!;

		await repository.replaceAdminSitePermissions(user.id, []);
		expect(await repository.adminSitePermission(user.id, site.id)).toBeNull();

		await repository.applyReplicatedChange(insertRow);
		const applied = await repository.adminSitePermission(user.id, site.id);
		expect(applied).not.toBeNull();
		expect(applied!.level).toBe("viewer");
	});

	test("deleteStream cascades a delete row for any admin_stream_permission granted on it", async () => {
		const stream = await makeStream("ha-rbac-stream-delete");
		const user = fakeAdminUser("ha-rbac-stream-delete-user");
		await repository.insertAdminUser(user);
		await repository.replaceAdminStreamPermissions(user.id, [{ streamId: stream.id, level: "manager" }]);
		await repository.deleteStream(stream.id);
		expect((await changelogFor(`${user.id}:${stream.id}`)).map((row) => row.op)).toEqual(["insert", "delete"]);
	});
});
