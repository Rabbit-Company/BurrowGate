import type { ChallengeProvider } from "../types.ts";

const ARGON2ID_PREFIX = /^\$argon2id\$/;

function password(config: Record<string, unknown>): string {
	const value = config.password;
	if (typeof value !== "string" || !value.trim() || value.length > 256) throw new Error("A password is required");
	return value;
}

export const passwordProvider: ChallengeProvider = {
	name: "password",
	clientScript: "/_burrowgate/static/challenges/password.js",
	title: "Enter the password",
	description: "This website asks visitors to enter a password before continuing.",

	validateConfig(config) {
		password(config);
	},

	async normalizeConfigForStorage(config) {
		const value = password(config);
		if (ARGON2ID_PREFIX.test(value)) return config;
		return { ...config, password: await Bun.password.hash(value, { algorithm: "argon2id" }) };
	},

	async create(_context, config) {
		return { publicData: { kind: "password" }, privateData: { passwordHash: password(config) } };
	},

	async verify(_context, _config, privateData, answer) {
		const submitted = answer && typeof answer === "object" ? String((answer as Record<string, unknown>).password ?? "") : "";
		if (!submitted) return { success: false, reason: "Incorrect password" };
		const hash = String(privateData.passwordHash ?? "");
		if (!hash) return { success: false, reason: "Incorrect password" };
		const ok = await Bun.password.verify(submitted, hash);
		return ok ? { success: true, metadata: { provider: "password" } } : { success: false, reason: "Incorrect password" };
	},
};
