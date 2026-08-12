import { beforeAll, describe, expect, test } from "bun:test";
import { repository } from "../src/db/repository.ts";
import { createAccessUser, importAccessUsers, resetAccessUserTwoFactor, setAccessUserTotpRequired } from "../src/services/access-list-service.ts";
import { createSite } from "../src/services/site-service.ts";
import { randomId } from "../src/utils/crypto.ts";
import type { AccessWebauthnCredentialRecord, SiteRecord } from "../src/types.ts";

let siteA: SiteRecord;
let siteB: SiteRecord;
let userId: string;

function credentialRecord(overrides: Partial<AccessWebauthnCredentialRecord>): AccessWebauthnCredentialRecord {
	const now = Date.now();
	return {
		id: randomId("wak"),
		user_id: userId,
		site_id: siteA.id,
		rp_id: "example.test",
		credential_id: randomId("cred"),
		credential_id_hash: randomId("hash"),
		public_key: "cGxhY2Vob2xkZXI",
		sign_count: 0,
		transports_json: JSON.stringify(["usb"]),
		aaguid: "00000000-0000-0000-0000-000000000000",
		device_type: "singleDevice",
		backed_up: 0,
		nickname: null,
		created_at: now,
		last_used_at: null,
		updated_at: now,
		...overrides,
	};
}

beforeAll(async () => {
	siteA = (await createSite({ name: "Webauthn site A", publicHost: `webauthn-a-${crypto.randomUUID()}.test`, originUrl: "http://origin-a.test" })).site;
	siteB = (await createSite({ name: "Webauthn site B", publicHost: `webauthn-b-${crypto.randomUUID()}.test`, originUrl: "http://origin-b.test" })).site;
	const user = await createAccessUser(siteA.id, { username: `webauthn-user-${crypto.randomUUID()}`, password: "password123" });
	userId = user.id;
	await importAccessUsers(siteB.id, [userId]);
});

describe("access WebAuthn credentials are scoped per site", () => {
	test("a credential registered for site A is not visible on site B, though the user belongs to both", async () => {
		await repository.insertAccessWebauthnCredential(credentialRecord({ site_id: siteA.id, rp_id: siteA.public_host }));

		const onSiteA = await repository.accessWebauthnCredentialsForUserAndSite(userId, siteA.id);
		const onSiteB = await repository.accessWebauthnCredentialsForUserAndSite(userId, siteB.id);

		expect(onSiteA).toHaveLength(1);
		expect(onSiteB).toHaveLength(0);
	});

	test("a credential registered separately for site B only appears there", async () => {
		await repository.insertAccessWebauthnCredential(credentialRecord({ site_id: siteB.id, rp_id: siteB.public_host }));

		const onSiteA = await repository.accessWebauthnCredentialsForUserAndSite(userId, siteA.id);
		const onSiteB = await repository.accessWebauthnCredentialsForUserAndSite(userId, siteB.id);

		expect(onSiteA).toHaveLength(1);
		expect(onSiteB).toHaveLength(1);
	});

	test("resetting 2FA for site A clears only that site's WebAuthn credential and the (shared) TOTP secret", async () => {
		await setAccessUserTotpRequired(siteA.id, userId, true);

		const view = await resetAccessUserTwoFactor(siteA.id, userId);

		expect(view.totpEnrolled).toBe(false);
		expect(await repository.accessWebauthnCredentialsForUserAndSite(userId, siteA.id)).toHaveLength(0);
		expect(await repository.accessWebauthnCredentialsForUserAndSite(userId, siteB.id)).toHaveLength(1);
	});
});
