import { afterEach, describe, expect, test } from "bun:test";
import { recaptchaV2Provider } from "../src/challenges/providers/recaptcha-v2.ts";
import { recaptchaV3Provider } from "../src/challenges/providers/recaptcha-v3.ts";
import { challengePageCsp } from "../src/services/challenge-page-service.ts";
import { isEncryptedSecret } from "../src/services/secret-encryption-service.ts";
import type { ChallengeVerifyContext } from "../src/challenges/types.ts";
import type { SiteRecord } from "../src/types.ts";

const originalFetch = globalThis.fetch;

afterEach(() => {
	globalThis.fetch = originalFetch;
});

const baseSite: SiteRecord = {
	id: "site-csp-test",
	name: "CSP test",
	public_host: "example.test",
	origin_url: "http://127.0.0.1:3000",
	origin_signing_secret: "test-signing-secret-that-is-at-least-32-characters",
	ip_extraction_preset: "direct",
	enabled: 1,
	session_ttl_seconds: 3_600,
	challenge_policy_json: "[]",
	challenge_auto_ban_enabled: 0,
	challenge_auto_ban_max_failures: 5,
	challenge_auto_ban_seconds: 3_600,
	default_access_mode: "challenge",
	event_retention_days: 7,
	default_ip_action: "inherit",
	default_country_action: "inherit",
	error_response_mode: "json",
	error_html_template: "",
	error_json_fields_json: '["error","status"]',
	challenge_html_template: "",
	created_at: Date.now(),
	updated_at: Date.now(),
};

const verifyContext: ChallengeVerifyContext = {
	flowId: "flow_1",
	siteId: "site_1",
	clientIp: "203.0.113.10",
	userAgentHash: "ua",
	expiresAt: Date.now() + 60_000,
	attempts: 0,
	createdAt: Date.now(),
};

const SITEVERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";

describe("recaptcha-v2", () => {
	const provider = recaptchaV2Provider;

	test("validateConfig accepts a minimal valid config", () => {
		expect(() => provider.validateConfig?.({ siteKey: "sk", secretKey: "secret" })).not.toThrow();
	});

	test("validateConfig rejects missing siteKey/secretKey", () => {
		expect(() => provider.validateConfig?.({ secretKey: "secret" })).toThrow();
		expect(() => provider.validateConfig?.({ siteKey: "sk" })).toThrow();
	});

	test("validateConfig rejects an invalid theme or size", () => {
		expect(() => provider.validateConfig?.({ siteKey: "sk", secretKey: "secret", theme: "auto" })).toThrow();
		expect(() => provider.validateConfig?.({ siteKey: "sk", secretKey: "secret", size: "huge" })).toThrow();
	});

	test("create returns publicData with the site key but never the secret key", async () => {
		const material = await provider.create(
			{ flowId: "flow_1", siteId: "site_1", clientIp: "203.0.113.10", userAgentHash: "ua", expiresAt: Date.now() + 60_000 },
			{ siteKey: "public-site-key", secretKey: "super-secret" },
		);
		expect(material.publicData.siteKey).toBe("public-site-key");
		expect(JSON.stringify(material.publicData)).not.toContain("super-secret");
	});

	test("normalizeConfigForStorage encrypts a plaintext secret key and is idempotent", async () => {
		const once = await provider.normalizeConfigForStorage!({ siteKey: "sk", secretKey: "plaintext-secret" });
		expect(isEncryptedSecret(once.secretKey as string)).toBe(true);
		const twice = await provider.normalizeConfigForStorage!(once);
		expect(twice.secretKey).toBe(once.secretKey);
	});

	test("verify fails when the answer has no token", async () => {
		const result = await provider.verify(verifyContext, { siteKey: "sk", secretKey: "secret" }, {}, {});
		expect(result.success).toBe(false);
	});

	test("verify succeeds and posts the decrypted secret, response token, and client IP", async () => {
		const config = await provider.normalizeConfigForStorage!({ siteKey: "sk", secretKey: "the-real-secret" });
		let seenUrl: unknown;
		let seenBody: URLSearchParams | undefined;
		globalThis.fetch = (async (url: unknown, init: RequestInit) => {
			seenUrl = url;
			seenBody = init.body as URLSearchParams;
			return new Response(JSON.stringify({ success: true, hostname: "example.test" }), { status: 200 });
		}) as typeof fetch;

		const result = await provider.verify(verifyContext, config, {}, { token: "widget-token" });
		expect(result.success).toBe(true);
		expect(String(seenUrl)).toBe(SITEVERIFY_URL);
		expect(seenBody?.get("secret")).toBe("the-real-secret");
		expect(seenBody?.get("response")).toBe("widget-token");
		expect(seenBody?.get("remoteip")).toBe("203.0.113.10");
	});

	test("verify fails when the verification API reports failure", async () => {
		const config = await provider.normalizeConfigForStorage!({ siteKey: "sk", secretKey: "secret" });
		globalThis.fetch = (async () => new Response(JSON.stringify({ success: false }), { status: 200 })) as unknown as typeof fetch;
		const result = await provider.verify(verifyContext, config, {}, { token: "widget-token" });
		expect(result.success).toBe(false);
	});

	test("verify fails without throwing when the verification service is unreachable", async () => {
		const config = await provider.normalizeConfigForStorage!({ siteKey: "sk", secretKey: "secret" });
		globalThis.fetch = (async () => {
			throw new Error("network down");
		}) as unknown as typeof fetch;
		const result = await provider.verify(verifyContext, config, {}, { token: "widget-token" });
		expect(result.success).toBe(false);
	});

	test("verify fails without throwing on a malformed JSON response", async () => {
		const config = await provider.normalizeConfigForStorage!({ siteKey: "sk", secretKey: "secret" });
		globalThis.fetch = (async () => new Response("not json", { status: 200 })) as unknown as typeof fetch;
		const result = await provider.verify(verifyContext, config, {}, { token: "widget-token" });
		expect(result.success).toBe(false);
	});
});

describe("recaptcha-v3", () => {
	const provider = recaptchaV3Provider;

	test("validateConfig accepts a minimal valid config and defaults action/scoreThreshold", () => {
		expect(() => provider.validateConfig?.({ siteKey: "sk", secretKey: "secret" })).not.toThrow();
	});

	test("validateConfig rejects an out-of-range scoreThreshold", () => {
		expect(() => provider.validateConfig?.({ siteKey: "sk", secretKey: "secret", scoreThreshold: -0.1 })).toThrow();
		expect(() => provider.validateConfig?.({ siteKey: "sk", secretKey: "secret", scoreThreshold: 1.1 })).toThrow();
	});

	test("validateConfig accepts boundary scoreThreshold values 0 and 1", () => {
		expect(() => provider.validateConfig?.({ siteKey: "sk", secretKey: "secret", scoreThreshold: 0 })).not.toThrow();
		expect(() => provider.validateConfig?.({ siteKey: "sk", secretKey: "secret", scoreThreshold: 1 })).not.toThrow();
	});

	test("validateConfig rejects a malformed action", () => {
		expect(() => provider.validateConfig?.({ siteKey: "sk", secretKey: "secret", action: "has spaces" })).toThrow();
		expect(() => provider.validateConfig?.({ siteKey: "sk", secretKey: "secret", action: "" })).toThrow();
	});

	test("create returns the site key and action (defaulted) in publicData, never the secret", async () => {
		const material = await provider.create(
			{ flowId: "flow_1", siteId: "site_1", clientIp: "203.0.113.10", userAgentHash: "ua", expiresAt: Date.now() + 60_000 },
			{ siteKey: "public-site-key", secretKey: "super-secret" },
		);
		expect(material.publicData.siteKey).toBe("public-site-key");
		expect(material.publicData.action).toBe("challenge");
		expect(JSON.stringify(material.publicData)).not.toContain("super-secret");
	});

	test("verify succeeds when the score meets the threshold and the action matches", async () => {
		const config = await provider.normalizeConfigForStorage!({ siteKey: "sk", secretKey: "secret", scoreThreshold: 0.5, action: "login" });
		globalThis.fetch = (async () => new Response(JSON.stringify({ success: true, score: 0.5, action: "login" }), { status: 200 })) as unknown as typeof fetch;
		const result = await provider.verify(verifyContext, config, {}, { token: "v3-token" });
		expect(result.success).toBe(true);
	});

	test("verify fails when the score is just below the threshold", async () => {
		const config = await provider.normalizeConfigForStorage!({ siteKey: "sk", secretKey: "secret", scoreThreshold: 0.5, action: "login" });
		globalThis.fetch = (async () => new Response(JSON.stringify({ success: true, score: 0.49, action: "login" }), { status: 200 })) as unknown as typeof fetch;
		const result = await provider.verify(verifyContext, config, {}, { token: "v3-token" });
		expect(result.success).toBe(false);
	});

	test("verify fails when the action doesn't match, even with success:true and a passing score", async () => {
		const config = await provider.normalizeConfigForStorage!({ siteKey: "sk", secretKey: "secret", scoreThreshold: 0.5, action: "login" });
		globalThis.fetch = (async () =>
			new Response(JSON.stringify({ success: true, score: 0.9, action: "some-other-action" }), { status: 200 })) as unknown as typeof fetch;
		const result = await provider.verify(verifyContext, config, {}, { token: "v3-token" });
		expect(result.success).toBe(false);
	});

	test("verify fails without throwing on a malformed JSON response", async () => {
		const config = await provider.normalizeConfigForStorage!({ siteKey: "sk", secretKey: "secret" });
		globalThis.fetch = (async () => new Response("not json", { status: 200 })) as unknown as typeof fetch;
		const result = await provider.verify(verifyContext, config, {}, { token: "v3-token" });
		expect(result.success).toBe(false);
	});
});

describe("challengePageCsp", () => {
	test("widens the policy to Google's hosts for recaptcha-v2", () => {
		const csp = challengePageCsp(baseSite, recaptchaV2Provider);
		expect(csp).toContain("https://www.google.com");
		expect(csp).toContain("https://www.gstatic.com");
		expect(csp).toContain("frame-src 'self' https://www.google.com");
	});

	test("widens the policy to Google's hosts for recaptcha-v3, including a frame-src for its hidden verification iframe", () => {
		const csp = challengePageCsp(baseSite, recaptchaV3Provider);
		expect(csp).toContain("https://www.google.com");
		expect(csp).toContain("frame-src 'self' https://www.google.com");
	});
});
