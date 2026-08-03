import { countLeadingZeroBits, randomToken, sha256Bytes, toHex } from "../../utils/crypto.ts";
import type { ChallengeProvider } from "../types.ts";

function difficulty(config: Record<string, unknown>): number {
	const n = Number(config.difficulty ?? 18);
	if (!Number.isInteger(n) || n < 8 || n > 63) throw new Error("PoW difficulty must be an integer from 8 to 63");
	return n;
}

export const powSha256Provider: ChallengeProvider = {
	name: "pow-sha256",
	clientScript: "/_burrowgate/static/challenges/pow-sha256.js",
	title: "Verifying your browser",
	description: "This website asks browsers to complete a small proof of work before continuing.",

	validateConfig(config) {
		difficulty(config);
	},

	async create(context, config) {
		const seed = randomToken(32);
		const bits = difficulty(config);
		return { publicData: { kind: "pow-sha256", seed, difficulty: bits, expiresAt: context.expiresAt }, privateData: { seed, difficulty: bits } };
	},

	async verify(_context, _config, privateData, answer) {
		if (!answer || typeof answer !== "object") return { success: false, reason: "Missing proof" };
		const nonce = String((answer as Record<string, unknown>).nonce ?? "");
		if (!/^\d{1,20}$/u.test(nonce)) return { success: false, reason: "Invalid nonce" };
		const seed = String(privateData.seed ?? "");
		const bits = Number(privateData.difficulty);
		const digest = await sha256Bytes(`${seed}:${nonce}`);
		const actual = countLeadingZeroBits(digest);
		return actual >= bits
			? { success: true, metadata: { nonce, hash: toHex(digest), leadingZeroBits: actual } }
			: { success: false, reason: "Proof does not meet target" };
	},
};
