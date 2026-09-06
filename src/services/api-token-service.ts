import { repository } from "../db/repository.ts";
import type { ApiTokenRecord } from "../types.ts";
import { randomId, randomToken, sha256Hex } from "../utils/crypto.ts";
import { jsonResponse } from "../utils/http.ts";
import type { AuthenticatedAdmin } from "./admin-permission-service.ts";

export class ApiTokenValidationError extends Error {}

const TOKEN_PREFIX: Record<ApiTokenRecord["scope"], string> = { monitoring: "bgro_", full: "bgat_" };
const FULL_ACCESS_TOKEN_PATTERN = /^Bearer (bgat_[A-Za-z0-9_-]{43})$/i;
const FULL_ACCESS_CREDENTIAL_PATTERN = /^Bearer\s+bgat_/i;

export function apiTokenView(record: ApiTokenRecord) {
	return {
		id: record.id,
		name: record.name,
		prefix: record.token_prefix,
		scope: record.scope,
		createdAt: Number(record.created_at),
		expiresAt: record.expires_at === null ? null : Number(record.expires_at),
	};
}

export async function createApiToken(userId: string, input: unknown) {
	const user = await repository.adminUserById(userId);
	if (!user || user.enabled !== 1) throw new ApiTokenValidationError("Account is not enabled");
	if (!input || typeof input !== "object" || Array.isArray(input)) throw new ApiTokenValidationError("Expected a JSON object");
	const { name, expiresInDays = 90, scope } = input as { name?: unknown; expiresInDays?: unknown; scope?: unknown };
	if (scope !== "monitoring" && scope !== "full") throw new ApiTokenValidationError('Scope must be "monitoring" or "full"');
	if (scope === "monitoring" && user.role !== "administrator") throw new ApiTokenValidationError("Administrator access required for a monitoring token");
	if (typeof name !== "string" || !name.trim() || name.trim().length > 100) throw new ApiTokenValidationError("Name must contain 1 to 100 characters");
	if (expiresInDays !== null && (typeof expiresInDays !== "number" || !Number.isInteger(expiresInDays) || expiresInDays < 1 || expiresInDays > 365)) {
		throw new ApiTokenValidationError("Expiry must be 1 to 365 days, or null for no expiry");
	}
	const token = `${TOKEN_PREFIX[scope]}${randomToken()}`;
	const now = Date.now();
	const record: ApiTokenRecord = {
		id: randomId("apit"),
		user_id: userId,
		name: name.trim(),
		token_hash: await sha256Hex(token),
		token_prefix: token.slice(0, 13),
		scope,
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
	if (!record || record.scope !== "monitoring" || (record.expires_at !== null && Number(record.expires_at) <= Date.now())) return false;
	const user = await repository.adminUserById(record.user_id);
	return !!user && user.enabled === 1 && user.role === "administrator";
}

export function isFullAccessTokenRequest(request: Request): boolean {
	return FULL_ACCESS_TOKEN_PATTERN.test(request.headers.get("authorization") ?? "");
}

export function hasFullAccessTokenCredential(request: Request): boolean {
	return FULL_ACCESS_CREDENTIAL_PATTERN.test(request.headers.get("authorization") ?? "");
}

export function fullAccessTokenBoundaryResponse(request: Request): Response | null {
	if (!hasFullAccessTokenCredential(request)) return null;
	const path = new URL(request.url).pathname;
	if (path === "/_burrowgate/api/admin" || path.startsWith("/_burrowgate/api/admin/")) return null;
	const result = jsonResponse({ error: "Full-access API tokens are only accepted by the admin API" }, 403);
	result.headers.set("cache-control", "no-store");
	return result;
}

export async function authenticateFullAccessApiToken(request: Request): Promise<AuthenticatedAdmin | null> {
	const match = FULL_ACCESS_TOKEN_PATTERN.exec(request.headers.get("authorization") ?? "");
	if (!match) return null;
	const record = await repository.apiTokenByHash(await sha256Hex(match[1]!));
	if (!record || record.scope !== "full" || (record.expires_at !== null && Number(record.expires_at) <= Date.now())) return null;
	const user = await repository.adminUserById(record.user_id);
	if (!user || user.enabled !== 1) return null;
	return { id: user.id, username: user.username, role: user.role };
}
