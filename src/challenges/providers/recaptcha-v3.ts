import { decryptSecret, encryptSecret, isEncryptedSecret } from "../../services/secret-encryption-service.ts";
import { buildChallengeTemplate } from "../../services/challenge-page-service.ts";
import type { ChallengeProvider } from "../types.ts";

// No visible widget - the client calls grecaptcha.execute() automatically, so no widget-container hook is needed.
const DEFAULT_TEMPLATE = buildChallengeTemplate();

const SITEVERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";
const ACTION_PATTERN = /^[A-Za-z0-9_/]{1,100}$/u;
const DEFAULT_ACTION = "challenge";
const DEFAULT_SCORE_THRESHOLD = 0.5;

function siteKey(config: Record<string, unknown>): string {
	const value = config.siteKey;
	if (typeof value !== "string" || !value.trim() || value.length > 256) throw new Error("reCAPTCHA site key is required");
	return value;
}

function secretKey(config: Record<string, unknown>): string {
	const value = config.secretKey;
	if (typeof value !== "string" || !value.trim() || value.length > 512) throw new Error("reCAPTCHA secret key is required");
	return value;
}

function action(config: Record<string, unknown>): string {
	if (config.action === undefined) return DEFAULT_ACTION;
	if (typeof config.action !== "string" || !ACTION_PATTERN.test(config.action)) {
		throw new Error("reCAPTCHA action must be 1-100 letters, digits, underscores, or slashes");
	}
	return config.action;
}

function scoreThreshold(config: Record<string, unknown>): number {
	if (config.scoreThreshold === undefined) return DEFAULT_SCORE_THRESHOLD;
	const value = Number(config.scoreThreshold);
	if (!Number.isFinite(value) || value < 0 || value > 1) throw new Error("reCAPTCHA minimum score must be a number from 0 to 1");
	return value;
}

export const recaptchaV3Provider: ChallengeProvider = {
	name: "recaptcha-v3",
	clientScript: "/_burrowgate/static/challenges/recaptcha-v3.js",
	title: "Verifying your browser",
	description: "This website uses reCAPTCHA to score visitor traffic before continuing.",
	defaultHtmlTemplate: DEFAULT_TEMPLATE,
	cspSources: {
		scriptSrc: ["https://www.google.com", "https://www.gstatic.com"],
		frameSrc: ["https://www.google.com"],
		connectSrc: ["https://www.google.com"],
		styleSrc: ["https://www.gstatic.com"],
	},

	validateConfig(config) {
		siteKey(config);
		secretKey(config);
		action(config);
		scoreThreshold(config);
	},

	async normalizeConfigForStorage(config) {
		const secret = secretKey(config);
		if (isEncryptedSecret(secret)) return config;
		return { ...config, secretKey: await encryptSecret(secret) };
	},

	async create(_context, config) {
		return {
			publicData: { kind: "recaptcha-v3", siteKey: siteKey(config), action: action(config) },
			privateData: {},
		};
	},

	async verify(context, config, _privateData, answer) {
		const token = answer && typeof answer === "object" ? String((answer as Record<string, unknown>).token ?? "") : "";
		if (!token) return { success: false, reason: "Missing verification token" };

		const storedSecret = secretKey(config);
		const secret = isEncryptedSecret(storedSecret) ? await decryptSecret(storedSecret) : storedSecret;
		const expectedAction = action(config);
		const minimumScore = scoreThreshold(config);

		const body = new URLSearchParams({ secret, response: token });
		if (context.clientIp) body.set("remoteip", context.clientIp);

		let response: Response;
		try {
			response = await fetch(SITEVERIFY_URL, {
				method: "POST",
				headers: { "content-type": "application/x-www-form-urlencoded" },
				body,
				signal: AbortSignal.timeout(10_000),
			});
		} catch {
			return { success: false, reason: "reCAPTCHA verification service is unreachable" };
		}
		if (!response.ok) return { success: false, reason: "reCAPTCHA verification service returned an error" };

		let data: unknown;
		try {
			data = await response.json();
		} catch {
			return { success: false, reason: "reCAPTCHA verification service returned an invalid response" };
		}
		const result = data as Record<string, unknown>;
		if (!result || result.success !== true) return { success: false, reason: "reCAPTCHA verification failed" };
		if (result.action !== expectedAction) return { success: false, reason: "reCAPTCHA verification failed" };
		const score = Number(result.score);
		if (!Number.isFinite(score) || score < minimumScore) return { success: false, reason: "reCAPTCHA score was too low" };
		return { success: true, metadata: { provider: "recaptcha-v3", score, hostname: result.hostname } };
	},
};
