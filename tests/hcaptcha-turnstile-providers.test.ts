import { afterEach, describe, expect, test } from "bun:test";
import { hcaptchaProvider } from "../src/challenges/providers/hcaptcha.ts";
import { turnstileProvider } from "../src/challenges/providers/turnstile.ts";
import { challengePageCsp } from "../src/services/challenge-page-service.ts";
import { powSha256Provider } from "../src/challenges/providers/pow-sha256.ts";
import { isEncryptedSecret } from "../src/services/secret-encryption-service.ts";
import type { ChallengeProvider, ChallengeVerifyContext } from "../src/challenges/types.ts";
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

const providers: [string, ChallengeProvider, string][] = [
	["hcaptcha", hcaptchaProvider, "https://hcaptcha.com/siteverify"],
	["turnstile", turnstileProvider, "https://challenges.cloudflare.com/turnstile/v0/siteverify"],
];

for (const [name, provider, siteverifyUrl] of providers) {
	describe(name, () => {
		test("validateConfig accepts a minimal valid config", () => {
			expect(() => provider.validateConfig?.({ siteKey: "sk", secretKey: "secret" })).not.toThrow();
		});

		test("validateConfig rejects missing siteKey/secretKey", () => {
			expect(() => provider.validateConfig?.({ secretKey: "secret" })).toThrow();
			expect(() => provider.validateConfig?.({ siteKey: "sk" })).toThrow();
			expect(() => provider.validateConfig?.({ siteKey: "", secretKey: "secret" })).toThrow();
		});

		test("validateConfig rejects an invalid theme or size", () => {
			expect(() => provider.validateConfig?.({ siteKey: "sk", secretKey: "secret", theme: "rainbow" })).toThrow();
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

		test("normalizeConfigForStorage encrypts a plaintext secret key", async () => {
			const normalized = await provider.normalizeConfigForStorage!({ siteKey: "sk", secretKey: "plaintext-secret" });
			expect(normalized.secretKey).not.toBe("plaintext-secret");
			expect(isEncryptedSecret(normalized.secretKey as string)).toBe(true);
		});

		test("normalizeConfigForStorage leaves an already-encrypted secret key untouched", async () => {
			const once = await provider.normalizeConfigForStorage!({ siteKey: "sk", secretKey: "plaintext-secret" });
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
			expect(String(seenUrl)).toBe(siteverifyUrl);
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
}

describe("challengePageCsp", () => {
	test("returns the default same-origin policy for a provider with no extra CSP sources", () => {
		const csp = challengePageCsp(baseSite, powSha256Provider);
		expect(csp).toContain("script-src 'self' 'unsafe-inline'");
		expect(csp).not.toContain("hcaptcha");
	});

	test("widens the policy to hCaptcha's hosts for the hcaptcha provider", () => {
		const csp = challengePageCsp(baseSite, hcaptchaProvider);
		expect(csp).toContain("https://*.hcaptcha.com");
		expect(csp).toContain("frame-src 'self' https://*.hcaptcha.com");
	});

	test("widens the policy to Cloudflare's host for the turnstile provider", () => {
		const csp = challengePageCsp(baseSite, turnstileProvider);
		expect(csp).toContain("https://challenges.cloudflare.com");
		expect(csp).toContain("frame-src 'self' https://challenges.cloudflare.com");
	});
});
