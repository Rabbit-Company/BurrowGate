import { repository } from "../db/repository.ts";
import type { ApiTokenRecord } from "../types.ts";
import { randomId, randomToken, sha256Hex } from "../utils/crypto.ts";

export class ApiTokenValidationError extends Error {}

export function apiTokenView(record: ApiTokenRecord) {
	return {
		id: record.id,
		name: record.name,
		prefix: record.token_prefix,
		scope: "monitoring:read" as const,
		createdAt: Number(record.created_at),
		expiresAt: record.expires_at === null ? null : Number(record.expires_at),
	};
}

export async function createApiToken(userId: string, input: unknown) {
	const user = await repository.adminUserById(userId);
	if (!user || user.enabled !== 1 || user.role !== "administrator") throw new ApiTokenValidationError("Administrator access required");
	if (!input || typeof input !== "object" || Array.isArray(input)) throw new ApiTokenValidationError("Expected a JSON object");
	const { name, expiresInDays = 90 } = input as { name?: unknown; expiresInDays?: unknown };
	if (typeof name !== "string" || !name.trim() || name.trim().length > 100) throw new ApiTokenValidationError("Name must contain 1 to 100 characters");
	if (expiresInDays !== null && (typeof expiresInDays !== "number" || !Number.isInteger(expiresInDays) || expiresInDays < 1 || expiresInDays > 365)) {
		throw new ApiTokenValidationError("Expiry must be 1 to 365 days, or null for no expiry");
	}
	const token = `bgro_${randomToken()}`;
	const now = Date.now();
	const record: ApiTokenRecord = {
		id: randomId("apit"),
		user_id: userId,
		name: name.trim(),
		token_hash: await sha256Hex(token),
		token_prefix: token.slice(0, 13),
		created_at: now,
		expires_at: expiresInDays === null ? null : now + expiresInDays * 86_400_000,
	};
	await repository.insertApiToken(record);
	return { ...apiTokenView(record), token };
}

/** These credentials are deliberately independent of dashboard sessions and site access tokens. */
export async function authenticateApiToken(request: Request): Promise<boolean> {
	const match = /^Bearer (bgro_[A-Za-z0-9_-]{43})$/i.exec(request.headers.get("authorization") ?? "");
	if (!match) return false;
	const record = await repository.apiTokenByHash(await sha256Hex(match[1]!));
	if (!record || (record.expires_at !== null && Number(record.expires_at) <= Date.now())) return false;
	const user = await repository.adminUserById(record.user_id);
	return !!user && user.enabled === 1 && user.role === "administrator";
}
