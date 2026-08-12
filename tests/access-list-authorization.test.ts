import { beforeAll, describe, expect, test } from "bun:test";
import { repository } from "../src/db/repository.ts";
import {
	createAccessUser,
	generateAccessUserApiToken,
	resetAccessUserTwoFactor,
	revokeAccessUserApiToken,
	setAccessUserTotpRequired,
} from "../src/services/access-list-service.ts";
import { createSite } from "../src/services/site-service.ts";
import type { SiteRecord } from "../src/types.ts";

let siteA: SiteRecord;
let siteB: SiteRecord;
let userId: string;

beforeAll(async () => {
	siteA = (await createSite({ name: "Authz site A", publicHost: `authz-a-${crypto.randomUUID()}.test`, originUrl: "http://origin-a.test" })).site;
	siteB = (await createSite({ name: "Authz site B", publicHost: `authz-b-${crypto.randomUUID()}.test`, originUrl: "http://origin-b.test" })).site;
	const user = await createAccessUser(siteB.id, { username: `authz-user-${crypto.randomUUID()}`, password: "password123" });
	userId = user.id;
});

describe("access-list user mutations are scoped to the requesting site", () => {
	test("the target user is only visible through the site they are assigned to", async () => {
		expect(await repository.accessUserForSite(siteA.id, userId)).toBeNull();
		expect(await repository.accessUserForSite(siteB.id, userId)).not.toBeNull();
	});

	test("requiring 2FA for a user on an unrelated site is rejected", async () => {
		await expect(setAccessUserTotpRequired(siteA.id, userId, true)).rejects.toThrow("Access user not found");
	});

	test("requiring 2FA for a user on their assigned site succeeds", async () => {
		const view = await setAccessUserTotpRequired(siteB.id, userId, true);
		expect(view.totpRequired).toBe(true);
	});

	test("resetting 2FA for a user on an unrelated site is rejected", async () => {
		await expect(resetAccessUserTwoFactor(siteA.id, userId)).rejects.toThrow("Access user not found");
	});

	test("resetting 2FA for a user on their assigned site succeeds", async () => {
		const view = await resetAccessUserTwoFactor(siteB.id, userId);
		expect(view.totpEnrolled).toBe(false);
	});

	test("minting an API token for a user on an unrelated site is rejected", async () => {
		await expect(generateAccessUserApiToken(siteA.id, userId)).rejects.toThrow("Access user not found");
	});

	test("minting an API token for a user on their assigned site succeeds", async () => {
		const { view, token } = await generateAccessUserApiToken(siteB.id, userId);
		expect(view.apiTokenEnabled).toBe(true);
		expect(token.length).toBeGreaterThan(20);
	});

	test("revoking an API token for a user on an unrelated site is rejected", async () => {
		await expect(revokeAccessUserApiToken(siteA.id, userId)).rejects.toThrow("Access user not found");
	});

	test("revoking an API token for a user on their assigned site succeeds", async () => {
		const view = await revokeAccessUserApiToken(siteB.id, userId);
		expect(view.apiTokenEnabled).toBe(false);
	});
});
