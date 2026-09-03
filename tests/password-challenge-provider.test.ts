import { describe, expect, test } from "bun:test";
import { passwordProvider } from "../src/challenges/providers/password.ts";
import type { ChallengeVerifyContext } from "../src/challenges/types.ts";

const verifyContext: ChallengeVerifyContext = {
	flowId: "flow_1",
	siteId: "site_1",
	clientIp: "203.0.113.10",
	userAgentHash: "ua",
	expiresAt: Date.now() + 60_000,
	attempts: 0,
	createdAt: Date.now() - 60_000,
};

describe("passwordProvider", () => {
	test("validateConfig accepts a non-empty password", () => {
		expect(() => passwordProvider.validateConfig?.({ password: "hunter2" })).not.toThrow();
	});

	test("validateConfig rejects a missing, empty, or oversized password", () => {
		expect(() => passwordProvider.validateConfig?.({})).toThrow();
		expect(() => passwordProvider.validateConfig?.({ password: "" })).toThrow();
		expect(() => passwordProvider.validateConfig?.({ password: "   " })).toThrow();
		expect(() => passwordProvider.validateConfig?.({ password: "a".repeat(257) })).toThrow();
	});

	test("normalizeConfigForStorage hashes a plaintext password with argon2id", async () => {
		const stored = await passwordProvider.normalizeConfigForStorage?.({ password: "hunter2" });
		expect(stored?.password).not.toBe("hunter2");
		expect(String(stored?.password)).toMatch(/^\$argon2id\$/);
	});

	test("normalizeConfigForStorage leaves an already-hashed password unchanged", async () => {
		const first = await passwordProvider.normalizeConfigForStorage?.({ password: "hunter2" });
		const second = await passwordProvider.normalizeConfigForStorage?.(first!);
		expect(second?.password).toBe(first?.password);
	});

	test("create returns no trace of the password in publicData, only a hash in privateData", async () => {
		const config = (await passwordProvider.normalizeConfigForStorage?.({ password: "hunter2" }))!;
		const material = await passwordProvider.create(
			{ flowId: "flow_1", siteId: "site_1", clientIp: "203.0.113.10", userAgentHash: "ua", expiresAt: Date.now() + 60_000 },
			config,
		);
		expect(material.publicData).toEqual({ kind: "password" });
		expect(String(material.privateData.passwordHash)).toMatch(/^\$argon2id\$/);
	});

	test("verify accepts the correct password and rejects a wrong one", async () => {
		const config = (await passwordProvider.normalizeConfigForStorage?.({ password: "hunter2" }))!;
		const material = await passwordProvider.create(
			{ flowId: "flow_1", siteId: "site_1", clientIp: "203.0.113.10", userAgentHash: "ua", expiresAt: Date.now() + 60_000 },
			config,
		);
		const correct = await passwordProvider.verify(verifyContext, config, material.privateData, { password: "hunter2" });
		expect(correct.success).toBe(true);

		const wrong = await passwordProvider.verify(verifyContext, config, material.privateData, { password: "wrong" });
		expect(wrong.success).toBe(false);
		expect(wrong.reason).toBe("incorrectPassword");
	});

	test("verify rejects a missing or malformed answer", async () => {
		const privateData = { passwordHash: await Bun.password.hash("hunter2", { algorithm: "argon2id" }) };
		expect((await passwordProvider.verify(verifyContext, {}, privateData, {})).success).toBe(false);
		expect((await passwordProvider.verify(verifyContext, {}, privateData, { password: "" })).success).toBe(false);
		expect((await passwordProvider.verify(verifyContext, {}, {}, { password: "hunter2" })).success).toBe(false);
	});
});
