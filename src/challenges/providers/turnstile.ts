import { decryptSecret, encryptSecret, isEncryptedSecret } from "../../services/secret-encryption-service.ts";
import type { ChallengeProvider } from "../types.ts";

const SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const THEMES = new Set(["light", "dark", "auto"]);
const SIZES = new Set(["normal", "flexible", "compact"]);

function siteKey(config: Record<string, unknown>): string {
	const value = config.siteKey;
	if (typeof value !== "string" || !value.trim() || value.length > 256) throw new Error("Turnstile site key is required");
	return value;
}

function secretKey(config: Record<string, unknown>): string {
	const value = config.secretKey;
	if (typeof value !== "string" || !value.trim() || value.length > 512) throw new Error("Turnstile secret key is required");
	return value;
}

function theme(config: Record<string, unknown>): string | undefined {
	if (config.theme === undefined) return undefined;
	if (typeof config.theme !== "string" || !THEMES.has(config.theme)) throw new Error("Turnstile theme must be light, dark, or auto");
	return config.theme;
}

function size(config: Record<string, unknown>): string | undefined {
	if (config.size === undefined) return undefined;
	if (typeof config.size !== "string" || !SIZES.has(config.size)) throw new Error("Turnstile size must be normal, flexible, or compact");
	return config.size;
}

export const turnstileProvider: ChallengeProvider = {
	name: "turnstile",
	clientScript: "/_burrowgate/static/challenges/turnstile.js",
	title: "Confirm you are human",
	description: "This website asks visitors to complete a Cloudflare Turnstile challenge before continuing.",
	cspSources: {
		scriptSrc: ["https://challenges.cloudflare.com"],
		frameSrc: ["https://challenges.cloudflare.com"],
		connectSrc: ["https://challenges.cloudflare.com"],
	},

	validateConfig(config) {
		siteKey(config);
		secretKey(config);
		theme(config);
		size(config);
	},

	async normalizeConfigForStorage(config) {
		const secret = secretKey(config);
		if (isEncryptedSecret(secret)) return config;
		return { ...config, secretKey: await encryptSecret(secret) };
	},

	async create(_context, config) {
		return {
			publicData: { kind: "turnstile", siteKey: siteKey(config), theme: theme(config), size: size(config) },
			privateData: {},
		};
	},

	async verify(context, config, _privateData, answer) {
		const token = answer && typeof answer === "object" ? String((answer as Record<string, unknown>).token ?? "") : "";
		if (!token) return { success: false, reason: "Missing verification token" };

		const storedSecret = secretKey(config);
		const secret = isEncryptedSecret(storedSecret) ? await decryptSecret(storedSecret) : storedSecret;

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
			return { success: false, reason: "Turnstile verification service is unreachable" };
		}
		if (!response.ok) return { success: false, reason: "Turnstile verification service returned an error" };

		let data: unknown;
		try {
			data = await response.json();
		} catch {
			return { success: false, reason: "Turnstile verification service returned an invalid response" };
		}
		const result = data as Record<string, unknown>;
		if (!result || result.success !== true) return { success: false, reason: "Turnstile verification failed" };
		return { success: true, metadata: { provider: "turnstile", hostname: result.hostname } };
	},
};
