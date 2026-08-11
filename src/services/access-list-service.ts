import { repository } from "../db/repository.ts";
import type { AccessSessionRecord, AccessUserRecord, SiteAccessSettingsRecord, SiteRecord } from "../types.ts";
import { hmacSha256Hex, randomId, randomToken, sha256Hex } from "../utils/crypto.ts";
import { config, secureCookieForRequest } from "../config.ts";
import { serializeCookie } from "../utils/cookies.ts";
import { decryptSecret, encryptSecret } from "./secret-encryption-service.ts";
import { countryCodeForStorage } from "./geoip-service.ts";

export interface AccessUserInput {
	username?: unknown;
	password?: unknown;
	enabled?: unknown;
}

export interface AccessUserView {
	id: string;
	username: string;
	enabled: boolean;
	siteCount: number;
	createdAt: number;
	updatedAt: number;
	siteIds: string[];
	totpRequired: boolean;
	totpEnrolled: boolean;
	apiTokenEnabled: boolean;
	apiTokenCreatedAt: number | null;
}

export interface AccessListView {
	settings: {
		enabled: boolean;
		sendUsernameToUpstream: boolean;
	};
	users: AccessUserView[];
	availableUsers: AccessUserView[];
}

const LOGIN_WINDOW_MS = 60_000;
const LOGIN_MAX_FAILURES = 8;
const LOGIN_SWEEP_INTERVAL_MS = 10_000;

export class LoginFailureTracker {
	private readonly entries = new Map<string, { count: number; resetAt: number }>();
	private lastSweepAt = 0;

	constructor(
		private readonly maxKeys: number,
		private readonly windowMs = LOGIN_WINDOW_MS,
		private readonly maxFailures = LOGIN_MAX_FAILURES,
	) {}

	get size(): number {
		return this.entries.size;
	}

	status(keys: string[], now: number): number {
		let retryAfter = 0;
		for (const key of keys) {
			const entry = this.entries.get(key);
			if (!entry) continue;
			if (entry.resetAt <= now) {
				this.entries.delete(key);
				continue;
			}
			if (entry.count >= this.maxFailures) retryAfter = Math.max(retryAfter, Math.ceil((entry.resetAt - now) / 1_000));
		}
		return retryAfter;
	}

	record(keys: string[], now: number): void {
		this.sweep(now);
		for (const key of keys) {
			const entry = this.entries.get(key);
			if (entry && entry.resetAt > now) {
				entry.count += 1;
				continue;
			}
			while (this.entries.size >= this.maxKeys) {
				const oldest = this.entries.keys().next().value as string | undefined;
				if (oldest === undefined) break;
				this.entries.delete(oldest);
			}
			this.entries.set(key, { count: 1, resetAt: now + this.windowMs });
		}
	}

	clear(keys?: string[]): void {
		if (!keys) {
			this.entries.clear();
			return;
		}
		for (const key of keys) this.entries.delete(key);
	}

	clearPrefix(prefix: string): void {
		for (const key of this.entries.keys()) if (key.startsWith(prefix)) this.entries.delete(key);
	}

	private sweep(now: number): void {
		if (now - this.lastSweepAt < LOGIN_SWEEP_INTERVAL_MS) return;
		this.lastSweepAt = now;
		for (const [key, entry] of this.entries) if (entry.resetAt <= now) this.entries.delete(key);
	}
}

const loginFailures = new LoginFailureTracker(config.accessLoginMaxFailureKeys);
const settingsCache = new Map<string, { settings: SiteAccessSettingsRecord; expiresAt: number }>();
const SETTINGS_CACHE_TTL_MS = 5_000;
export const accessIdentityCookieNames = ["bg_authenticated_user", "bg_identity_signature"] as const;
let dummyHash: Promise<string> | null = null;

function booleanValue(value: unknown, fallback: boolean): boolean {
	if (value === undefined) return fallback;
	if (typeof value === "boolean") return value;
	if (value === 1 || value === "1" || value === "true") return true;
	if (value === 0 || value === "0" || value === "false") return false;
	throw new Error("Boolean value expected");
}

export function normalizeAccessUsername(value: unknown): string {
	const username = String(value ?? "")
		.trim()
		.toLowerCase();
	if (!username) throw new Error("Username is required");
	if (username.length > 255) throw new Error("Username must be at most 255 characters");
	if (!/^[a-z0-9][a-z0-9._@+-]*$/u.test(username)) {
		throw new Error("Username may contain lowercase letters, numbers, dots, underscores, @, +, and hyphens");
	}
	return username;
}

function passwordValue(value: unknown, required: boolean): string | null {
	if (value === undefined || value === null || value === "") {
		if (required) throw new Error("Password is required");
		return null;
	}
	const password = String(value);
	if (password.length < 8) throw new Error("Password must be at least 8 characters");
	if (password.length > 1024) throw new Error("Password must be at most 1024 characters");
	return password;
}

function userView(user: AccessUserRecord & { site_count?: number | string }, siteIds: string[] = []): AccessUserView {
	return {
		id: user.id,
		username: user.username,
		enabled: user.enabled === 1,
		siteCount: Number(user.site_count ?? 1),
		createdAt: Number(user.created_at),
		updatedAt: Number(user.updated_at),
		siteIds,
		totpRequired: user.totp_required === 1,
		totpEnrolled: user.totp_secret_encrypted !== null,
		apiTokenEnabled: user.api_token_hash !== null,
		apiTokenCreatedAt: user.api_token_created_at !== null ? Number(user.api_token_created_at) : null,
	};
}

async function activeUserCount(siteId: string, excludedUserId?: string): Promise<number> {
	return (await repository.accessUsersForSite(siteId)).filter((user) => user.enabled === 1 && user.id !== excludedUserId).length;
}

export async function accessListView(siteId: string): Promise<AccessListView> {
	const [settings, users, available] = await Promise.all([
		repository.ensureAccessSettings(siteId),
		repository.accessUsersForSite(siteId),
		repository.availableAccessUsers(siteId),
	]);
	const siteIds = new Map<string, string[]>();
	for (const user of [...users, ...available]) siteIds.set(user.id, await repository.accessSiteIdsForUser(user.id));
	return {
		settings: { enabled: settings.enabled === 1, sendUsernameToUpstream: settings.send_username_to_upstream === 1 },
		users: users.map((user) => userView(user, siteIds.get(user.id))),
		availableUsers: available.map((user) => userView(user, siteIds.get(user.id))),
	};
}

export async function accessSettingsForSite(siteId: string): Promise<SiteAccessSettingsRecord> {
	const cached = settingsCache.get(siteId);
	if (cached && cached.expiresAt > Date.now()) return cached.settings;
	const settings = await repository.ensureAccessSettings(siteId);
	settingsCache.set(siteId, { settings, expiresAt: Date.now() + SETTINGS_CACHE_TTL_MS });
	return settings;
}

export async function updateAccessSettings(siteId: string, input: { enabled?: unknown; sendUsernameToUpstream?: unknown }): Promise<SiteAccessSettingsRecord> {
	const existing = await repository.ensureAccessSettings(siteId);
	const enabled = booleanValue(input.enabled, existing.enabled === 1);
	if (enabled && (await activeUserCount(siteId)) === 0) throw new Error("Assign at least one active user before enabling access authentication");
	const updated: SiteAccessSettingsRecord = {
		...existing,
		enabled: enabled ? 1 : 0,
		send_username_to_upstream: booleanValue(input.sendUsernameToUpstream, existing.send_username_to_upstream === 1) ? 1 : 0,
		updated_at: Date.now(),
	};
	await repository.updateAccessSettings(updated);
	settingsCache.set(siteId, { settings: updated, expiresAt: Date.now() + SETTINGS_CACHE_TTL_MS });
	return updated;
}

export async function createAccessUser(siteId: string, input: AccessUserInput): Promise<AccessUserView> {
	const username = normalizeAccessUsername(input.username);
	if (await repository.accessUserByUsername(username)) throw new Error("This username already exists; add the existing user instead");
	const password = passwordValue(input.password, true)!;
	const now = Date.now();
	const user: AccessUserRecord = {
		id: randomId("user"),
		username,
		password_hash: await Bun.password.hash(password, { algorithm: "argon2id" }),
		enabled: booleanValue(input.enabled, true) ? 1 : 0,
		created_at: now,
		updated_at: now,
		totp_required: 0,
		totp_secret_encrypted: null,
		totp_enrolled_at: null,
		api_token_hash: null,
		api_token_created_at: null,
		sso_subject: null,
		auth_source: "password",
	};
	await repository.insertAccessUser(user);
	await repository.assignAccessUser(siteId, user.id, now);
	return userView(user);
}

export async function importAccessUsers(siteId: string, userIds: unknown): Promise<number> {
	if (!Array.isArray(userIds) || userIds.length === 0) throw new Error("Select at least one user to add");
	let imported = 0;
	for (const rawId of [...new Set(userIds.map((value) => String(value)))]) {
		const user = await repository.accessUserById(rawId);
		if (!user) throw new Error("One of the selected users no longer exists");
		if (await repository.accessUserForSite(siteId, user.id)) continue;
		await repository.assignAccessUser(siteId, user.id);
		imported += 1;
	}
	return imported;
}

export async function updateAccessUser(siteId: string, userId: string, input: AccessUserInput): Promise<AccessUserView> {
	const existing = await repository.accessUserForSite(siteId, userId);
	if (!existing) throw new Error("Access user not found");
	const username = input.username === undefined ? existing.username : normalizeAccessUsername(input.username);
	const conflict = await repository.accessUserByUsername(username);
	if (conflict && conflict.id !== userId) throw new Error("This username already exists");
	const password = passwordValue(input.password, false);
	const enabled = booleanValue(input.enabled, existing.enabled === 1);
	if (!enabled && existing.enabled === 1) {
		for (const assignedSiteId of await repository.accessSiteIdsForUser(userId)) {
			const settings = await repository.ensureAccessSettings(assignedSiteId);
			if (settings.enabled === 1 && (await activeUserCount(assignedSiteId, userId)) === 0) {
				throw new Error("This user is the last active user on an enabled access list");
			}
		}
	}
	const updated: AccessUserRecord = {
		...existing,
		username,
		password_hash: password ? await Bun.password.hash(password, { algorithm: "argon2id" }) : existing.password_hash,
		enabled: enabled ? 1 : 0,
		updated_at: Date.now(),
	};
	await repository.updateAccessUser(updated);
	if (password || !enabled) await repository.revokeSessionsForAccessUser(userId, Date.now());
	return userView({ ...updated, site_count: (await repository.accessSiteIdsForUser(userId)).length });
}

export async function removeAccessUser(siteId: string, userId: string): Promise<void> {
	const existing = await repository.accessUserForSite(siteId, userId);
	if (!existing) throw new Error("Access user not found");
	const settings = await repository.ensureAccessSettings(siteId);
	if (settings.enabled === 1 && existing.enabled === 1 && (await activeUserCount(siteId, userId)) === 0) {
		throw new Error("This user is the last active user on the enabled access list");
	}
	await repository.unassignAccessUser(siteId, userId);
	await repository.revokeSessionsForAccessUser(userId, Date.now(), siteId);
	if ((await repository.accessSiteIdsForUser(userId)).length === 0) await repository.deleteAccessUser(userId);
}

function failureKeys(siteId: string, ip: string, username: string): string[] {
	return [`site:${siteId}:ip:${ip}`, `site:${siteId}:user:${username}`];
}

export async function authenticateAccessUser(
	siteId: string,
	ip: string,
	usernameInput: unknown,
	passwordInput: unknown,
): Promise<{ user: AccessUserRecord | null; retryAfterSeconds: number }> {
	let username = "invalid";
	try {
		username = normalizeAccessUsername(usernameInput);
	} catch {
		// Invalid usernames receive the same response and password-verification work.
	}
	const suppliedPassword = String(passwordInput ?? "");
	const password = suppliedPassword.length <= 1024 ? suppliedPassword : "";
	const now = Date.now();
	const keys = failureKeys(siteId, ip, username);
	const retryAfterSeconds = loginFailures.status(keys, now);
	if (retryAfterSeconds > 0) return { user: null, retryAfterSeconds };
	const user = await repository.accessUserForSiteByUsername(siteId, username);
	dummyHash ??= Bun.password.hash("burrowgate-dummy-access-password", { algorithm: "argon2id" });
	const valid = await Bun.password.verify(password, user?.password_hash ?? (await dummyHash));
	if (!valid || !user || user.enabled !== 1) {
		loginFailures.record(keys, now);
		return { user: null, retryAfterSeconds: 0 };
	}
	loginFailures.clear(keys);
	return { user, retryAfterSeconds: 0 };
}

export async function authenticatedAccessUser(siteId: string, session: AccessSessionRecord | null): Promise<AccessUserRecord | null> {
	if (!session?.access_user_id) return null;
	const user = await repository.accessUserForSite(siteId, session.access_user_id);
	return user?.enabled === 1 ? user : null;
}

export async function accessIdentityCookieValues(
	site: SiteRecord,
	session: AccessSessionRecord,
	username: string,
): Promise<{ username: string; signature: string }> {
	const canonical = ["identity-cookie-v1", site.id, session.id, username].join("\n");
	return { username, signature: await hmacSha256Hex(site.origin_signing_secret, canonical) };
}

export async function accessIdentitySetCookies(request: Request, site: SiteRecord, session: AccessSessionRecord, username: string): Promise<string[]> {
	const values = await accessIdentityCookieValues(site, session, username);
	const options = {
		secure: secureCookieForRequest(request),
		httpOnly: false,
		sameSite: "Lax" as const,
		maxAge: Math.max(0, Math.ceil((Number(session.expires_at) - Date.now()) / 1000)),
	};
	return [serializeCookie(accessIdentityCookieNames[0], values.username, options), serializeCookie(accessIdentityCookieNames[1], values.signature, options)];
}

export function clearAccessIdentityCookies(request: Request): string[] {
	const options = { secure: secureCookieForRequest(request), httpOnly: false, sameSite: "Lax" as const, maxAge: 0 };
	return accessIdentityCookieNames.map((name) => serializeCookie(name, "", options));
}

export function resetAccessLoginRateLimits(): void {
	loginFailures.clear();
}

export function invalidateAccessSite(siteId: string): void {
	settingsCache.delete(siteId);
	loginFailures.clearPrefix(`site:${siteId}:`);
}

async function userViewById(userId: string): Promise<AccessUserView> {
	const user = await repository.accessUserById(userId);
	if (!user) throw new Error("Access user not found");
	return userView({ ...user, site_count: (await repository.accessSiteIdsForUser(userId)).length });
}

export async function setAccessUserTotpRequired(userId: string, required: boolean): Promise<AccessUserView> {
	const existing = await repository.accessUserById(userId);
	if (!existing) throw new Error("Access user not found");
	await repository.updateAccessUser({ ...existing, totp_required: required ? 1 : 0, updated_at: Date.now() });
	await repository.revokeSessionsForAccessUser(userId, Date.now());
	return userViewById(userId);
}

export async function resetAccessUserTotp(userId: string): Promise<AccessUserView> {
	const existing = await repository.accessUserById(userId);
	if (!existing) throw new Error("Access user not found");
	await repository.updateAccessUser({ ...existing, totp_secret_encrypted: null, totp_enrolled_at: null, updated_at: Date.now() });
	await repository.revokeSessionsForAccessUser(userId, Date.now());
	return userViewById(userId);
}

export async function generateAccessUserApiToken(userId: string): Promise<{ view: AccessUserView; token: string }> {
	const existing = await repository.accessUserById(userId);
	if (!existing) throw new Error("Access user not found");
	const token = randomToken(32);
	await repository.updateAccessUser({
		...existing,
		api_token_hash: await sha256Hex(token),
		api_token_created_at: Date.now(),
		updated_at: Date.now(),
	});
	return { view: await userViewById(userId), token };
}

export async function revokeAccessUserApiToken(userId: string): Promise<AccessUserView> {
	const existing = await repository.accessUserById(userId);
	if (!existing) throw new Error("Access user not found");
	await repository.updateAccessUser({ ...existing, api_token_hash: null, api_token_created_at: null, updated_at: Date.now() });
	return userViewById(userId);
}

export async function accessUserByApiToken(token: string): Promise<AccessUserRecord | null> {
	const trimmed = token.trim();
	if (!trimmed) return null;
	const user = await repository.accessUserByApiTokenHash(await sha256Hex(trimmed));
	return user?.enabled === 1 ? user : null;
}

export async function resolveApiTokenAccess(
	request: Request,
	site: SiteRecord,
	ip: string,
): Promise<{ session: AccessSessionRecord; user: AccessUserRecord } | null> {
	const header = request.headers.get("authorization");
	if (!header?.startsWith("Bearer ")) return null;
	const user = await accessUserByApiToken(header.slice(7));
	if (!user) return null;
	if (!(await repository.accessUserForSite(site.id, user.id))) return null;
	const now = Date.now();
	const existing = await repository.activeAccessSessionForUser(site.id, user.id, now);
	if (existing) {
		await repository.touchSession(existing.id, ip, now);
		return { session: existing, user };
	}
	const record: AccessSessionRecord = {
		id: randomId("sess"),
		site_id: site.id,
		token_hash: await sha256Hex(randomToken()),
		initial_ip: ip,
		last_ip: ip,
		user_agent_hash: await sha256Hex(request.headers.get("user-agent") ?? ""),
		created_at: now,
		last_seen_at: now,
		expires_at: now + site.session_ttl_seconds * 1_000,
		revoked_at: null,
		verification_summary_json: JSON.stringify({ method: "api-token" }),
		request_count: 0,
		country_code: countryCodeForStorage(ip),
		access_user_id: user.id,
		authenticated_at: now,
		sso_sid: null,
	};
	await repository.insertSession(record);
	return { session: record, user };
}

export interface PendingAccessTotp {
	userId: string;
	mode: "totp-enroll" | "totp-verify";
	tentativeSecret: string | null;
	expiresAt: number;
}

const PENDING_ACCESS_TOTP_TTL_MS = 5 * 60_000;
const pendingAccessTotps = new Map<string, PendingAccessTotp>();
const accessTotpFailures = new LoginFailureTracker(config.accessLoginMaxFailureKeys);

function sweepPendingAccessTotps(now: number): void {
	for (const [key, entry] of pendingAccessTotps) if (entry.expiresAt <= now) pendingAccessTotps.delete(key);
}

export function beginAccessTotpChallenge(sessionId: string, user: AccessUserRecord): "totp-enroll" | "totp-verify" {
	const now = Date.now();
	sweepPendingAccessTotps(now);
	const mode = user.totp_secret_encrypted ? "totp-verify" : "totp-enroll";
	pendingAccessTotps.set(sessionId, { userId: user.id, mode, tentativeSecret: null, expiresAt: now + PENDING_ACCESS_TOTP_TTL_MS });
	return mode;
}

export function pendingAccessTotp(sessionId: string, mode: "totp-enroll" | "totp-verify"): PendingAccessTotp | null {
	const entry = pendingAccessTotps.get(sessionId);
	if (!entry || entry.expiresAt <= Date.now() || entry.mode !== mode) return null;
	return entry;
}

export function setPendingAccessTotpSecret(sessionId: string, secret: string): void {
	const entry = pendingAccessTotps.get(sessionId);
	if (entry) entry.tentativeSecret = secret;
}

export function consumePendingAccessTotp(sessionId: string): void {
	pendingAccessTotps.delete(sessionId);
}

export function accessTotpRetryAfterSeconds(sessionId: string): number {
	return accessTotpFailures.status([`totp:${sessionId}`], Date.now());
}

export function recordAccessTotpFailure(sessionId: string): void {
	accessTotpFailures.record([`totp:${sessionId}`], Date.now());
}

export function clearAccessTotpFailures(sessionId: string): void {
	accessTotpFailures.clear([`totp:${sessionId}`]);
}

export async function decryptAccessTotpSecret(user: AccessUserRecord): Promise<string | null> {
	return user.totp_secret_encrypted ? decryptSecret(user.totp_secret_encrypted) : null;
}

export async function completeAccessTotpEnrollment(userId: string, secret: string): Promise<void> {
	const existing = await repository.accessUserById(userId);
	if (!existing) throw new Error("Access user not found");
	await repository.updateAccessUser({
		...existing,
		totp_secret_encrypted: await encryptSecret(secret),
		totp_enrolled_at: Date.now(),
		updated_at: Date.now(),
	});
}
