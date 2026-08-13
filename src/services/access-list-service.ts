import { repository } from "../db/repository.ts";
import type { AccessSessionRecord, AccessUserRecord, SiteAccessSettingsRecord, SiteRecord } from "../types.ts";
import { fromBase64Url, hmacSha256Hex, randomId, randomToken, sha256Hex, timingSafeEqualText, toBase64Url } from "../utils/crypto.ts";
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
	webauthnCredentialCount: number;
	apiTokenEnabled: boolean;
	apiTokenCreatedAt: number | null;
}

export interface AccessListView {
	settings: {
		enabled: boolean;
		sendUsernameToUpstream: boolean;
		sessionVerificationTokenEnabled: boolean;
		sessionVerificationTokenCreatedAt: number | null;
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

function userView(user: AccessUserRecord & { site_count?: number | string }, siteIds: string[] = [], webauthnCredentialCount = 0): AccessUserView {
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
		webauthnCredentialCount,
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
	const webauthnCounts = new Map<string, number>();
	for (const user of [...users, ...available]) {
		siteIds.set(user.id, await repository.accessSiteIdsForUser(user.id));
		webauthnCounts.set(user.id, (await repository.accessWebauthnCredentialsForUserAndSite(user.id, siteId)).length);
	}
	return {
		settings: {
			enabled: settings.enabled === 1,
			sendUsernameToUpstream: settings.send_username_to_upstream === 1,
			sessionVerificationTokenEnabled: settings.session_verification_token_hash !== null,
			sessionVerificationTokenCreatedAt:
				settings.session_verification_token_created_at !== null ? Number(settings.session_verification_token_created_at) : null,
		},
		users: users.map((user) => userView(user, siteIds.get(user.id), webauthnCounts.get(user.id))),
		availableUsers: available.map((user) => userView(user, siteIds.get(user.id), webauthnCounts.get(user.id))),
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
	if ((await repository.accessSiteIdsForUser(userId)).length === 0) {
		await repository.deleteAllAccessWebauthnCredentialsForUser(userId);
		await repository.deleteAccessUser(userId);
	}
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

interface AccessSessionAssertionPayload {
	v: 1;
	siteId: string;
	sessionId: string;
	userId: string;
	iat: number;
	exp: number;
}

export interface ActiveAccessSessionIdentity {
	active: true;
	siteId: string;
	sessionId: string;
	user: { id: string; username: string };
	authenticatedAt: number;
	expiresAt: number;
	assertionExpiresAt: number;
}

const ACCESS_SESSION_ASSERTION_PREFIX = "bgsa_";
const assertionDecoder = new TextDecoder();

function assertionCanonical(encodedPayload: string): string {
	return `access-session-assertion-v1\n${encodedPayload}`;
}

export async function issueAccessSessionAssertion(
	site: SiteRecord,
	session: AccessSessionRecord,
	user: AccessUserRecord,
	now = Date.now(),
): Promise<{ token: string; expiresAt: number; user: { id: string; username: string } }> {
	if (session.site_id !== site.id || session.access_user_id !== user.id || session.revoked_at !== null || session.expires_at <= now || user.enabled !== 1) {
		throw new Error("An active authenticated session is required");
	}
	const issuedAt = Math.floor(now / 1_000);
	const expiresAt = Math.min(Number(session.expires_at), now + config.accessSessionAssertionTtlSeconds * 1_000);
	const payload: AccessSessionAssertionPayload = {
		v: 1,
		siteId: site.id,
		sessionId: session.id,
		userId: user.id,
		iat: issuedAt,
		exp: Math.ceil(expiresAt / 1_000),
	};
	const encodedPayload = toBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
	const signature = await hmacSha256Hex(site.origin_signing_secret, assertionCanonical(encodedPayload));
	return { token: `${ACCESS_SESSION_ASSERTION_PREFIX}${encodedPayload}.${signature}`, expiresAt, user: { id: user.id, username: user.username } };
}

async function parseAccessSessionAssertion(site: SiteRecord, token: string, now = Date.now()): Promise<AccessSessionAssertionPayload | null> {
	const trimmed = token.trim();
	if (!trimmed.startsWith(ACCESS_SESSION_ASSERTION_PREFIX) || trimmed.length > 8_192) return null;
	const [encodedPayload, suppliedSignature, ...extra] = trimmed.slice(ACCESS_SESSION_ASSERTION_PREFIX.length).split(".");
	if (!encodedPayload || !suppliedSignature || extra.length > 0 || !/^[a-f0-9]{64}$/iu.test(suppliedSignature)) return null;
	const expectedSignature = await hmacSha256Hex(site.origin_signing_secret, assertionCanonical(encodedPayload));
	if (!(await timingSafeEqualText(expectedSignature, suppliedSignature.toLowerCase()))) return null;
	try {
		const payload = JSON.parse(assertionDecoder.decode(fromBase64Url(encodedPayload))) as Partial<AccessSessionAssertionPayload>;
		if (
			payload.v !== 1 ||
			payload.siteId !== site.id ||
			typeof payload.sessionId !== "string" ||
			!payload.sessionId ||
			typeof payload.userId !== "string" ||
			!payload.userId ||
			!Number.isInteger(payload.iat) ||
			!Number.isInteger(payload.exp)
		) {
			return null;
		}
		const issuedAt = payload.iat;
		const expiresAt = payload.exp;
		if (typeof issuedAt !== "number" || typeof expiresAt !== "number") return null;
		const nowSeconds = Math.floor(now / 1_000);
		if (issuedAt > nowSeconds + 30 || expiresAt <= nowSeconds || expiresAt <= issuedAt) return null;
		return payload as AccessSessionAssertionPayload;
	} catch {
		return null;
	}
}

export async function introspectAccessSessionAssertion(siteId: string, token: string, now = Date.now()): Promise<ActiveAccessSessionIdentity | null> {
	const site = await repository.siteById(siteId);
	if (!site || site.enabled !== 1) return null;
	const settings = await repository.ensureAccessSettings(site.id);
	if (settings.enabled !== 1) return null;
	const payload = await parseAccessSessionAssertion(site, token, now);
	if (!payload) return null;
	const session = await repository.sessionById(site.id, payload.sessionId);
	if (
		!session ||
		session.revoked_at !== null ||
		Number(session.expires_at) <= now ||
		session.access_user_id !== payload.userId ||
		session.authenticated_at === null
	) {
		return null;
	}
	const user = await repository.accessUserForSite(site.id, payload.userId);
	if (!user || user.enabled !== 1) return null;
	return {
		active: true,
		siteId: site.id,
		sessionId: session.id,
		user: { id: user.id, username: user.username },
		authenticatedAt: Number(session.authenticated_at),
		expiresAt: Number(session.expires_at),
		assertionExpiresAt: payload.exp * 1_000,
	};
}

export async function generateSessionVerificationToken(siteId: string): Promise<{ token: string; createdAt: number }> {
	const existing = await repository.ensureAccessSettings(siteId);
	const token = `bgsv_${randomToken(32)}`;
	const createdAt = Date.now();
	const updated: SiteAccessSettingsRecord = {
		...existing,
		session_verification_token_hash: await sha256Hex(token),
		session_verification_token_created_at: createdAt,
		updated_at: createdAt,
	};
	await repository.updateAccessSettings(updated);
	settingsCache.set(siteId, { settings: updated, expiresAt: Date.now() + SETTINGS_CACHE_TTL_MS });
	return { token, createdAt };
}

export async function revokeSessionVerificationToken(siteId: string): Promise<void> {
	const existing = await repository.ensureAccessSettings(siteId);
	const updated: SiteAccessSettingsRecord = {
		...existing,
		session_verification_token_hash: null,
		session_verification_token_created_at: null,
		updated_at: Date.now(),
	};
	await repository.updateAccessSettings(updated);
	settingsCache.set(siteId, { settings: updated, expiresAt: Date.now() + SETTINGS_CACHE_TTL_MS });
}

export async function verifySessionVerificationToken(siteId: string, token: string): Promise<boolean> {
	const supplied = token.trim();
	if (!supplied) return false;
	const settings = await repository.accessSettings(siteId);
	if (!settings?.session_verification_token_hash) return false;
	return await timingSafeEqualText(await sha256Hex(supplied), settings.session_verification_token_hash);
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

async function userViewById(userId: string, siteId: string): Promise<AccessUserView> {
	const user = await repository.accessUserById(userId);
	if (!user) throw new Error("Access user not found");
	return userView(
		{ ...user, site_count: (await repository.accessSiteIdsForUser(userId)).length },
		undefined,
		(await repository.accessWebauthnCredentialsForUserAndSite(userId, siteId)).length,
	);
}

export async function setAccessUserTotpRequired(siteId: string, userId: string, required: boolean): Promise<AccessUserView> {
	const existing = await repository.accessUserForSite(siteId, userId);
	if (!existing) throw new Error("Access user not found");
	await repository.updateAccessUser({ ...existing, totp_required: required ? 1 : 0, updated_at: Date.now() });
	await repository.revokeSessionsForAccessUser(userId, Date.now());
	return userViewById(userId, siteId);
}

export async function resetAccessUserTwoFactor(siteId: string, userId: string): Promise<AccessUserView> {
	const existing = await repository.accessUserForSite(siteId, userId);
	if (!existing) throw new Error("Access user not found");
	await repository.updateAccessUser({ ...existing, totp_secret_encrypted: null, totp_enrolled_at: null, updated_at: Date.now() });
	await repository.deleteAccessWebauthnCredentialsForUserAndSite(userId, siteId);
	await repository.revokeSessionsForAccessUser(userId, Date.now());
	return userViewById(userId, siteId);
}

export async function generateAccessUserApiToken(siteId: string, userId: string): Promise<{ view: AccessUserView; token: string }> {
	const existing = await repository.accessUserForSite(siteId, userId);
	if (!existing) throw new Error("Access user not found");
	const token = randomToken(32);
	await repository.updateAccessUser({
		...existing,
		api_token_hash: await sha256Hex(token),
		api_token_created_at: Date.now(),
		updated_at: Date.now(),
	});
	return { view: await userViewById(userId, siteId), token };
}

export async function revokeAccessUserApiToken(siteId: string, userId: string): Promise<AccessUserView> {
	const existing = await repository.accessUserForSite(siteId, userId);
	if (!existing) throw new Error("Access user not found");
	await repository.updateAccessUser({ ...existing, api_token_hash: null, api_token_created_at: null, updated_at: Date.now() });
	return userViewById(userId, siteId);
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

export type PendingAccessTwoFactorMode = "enroll" | "verify";

export interface PendingAccessTwoFactor {
	userId: string;
	siteId: string;
	mode: PendingAccessTwoFactorMode;
	tentativeSecret: string | null;
	webauthnChallenge: string | null;
	expiresAt: number;
}

const PENDING_ACCESS_TOTP_TTL_MS = 5 * 60_000;
const pendingAccessTwoFactors = new Map<string, PendingAccessTwoFactor>();
const accessTwoFactorFailures = new LoginFailureTracker(config.accessLoginMaxFailureKeys);

function sweepPendingAccessTwoFactors(now: number): void {
	for (const [key, entry] of pendingAccessTwoFactors) if (entry.expiresAt <= now) pendingAccessTwoFactors.delete(key);
}

export async function beginAccessTwoFactorChallenge(sessionId: string, siteId: string, user: AccessUserRecord): Promise<PendingAccessTwoFactorMode> {
	const now = Date.now();
	sweepPendingAccessTwoFactors(now);
	const hasWebauthn = (await repository.accessWebauthnCredentialsForUserAndSite(user.id, siteId)).length > 0;
	const mode: PendingAccessTwoFactorMode = user.totp_secret_encrypted || hasWebauthn ? "verify" : "enroll";
	pendingAccessTwoFactors.set(sessionId, {
		userId: user.id,
		siteId,
		mode,
		tentativeSecret: null,
		webauthnChallenge: null,
		expiresAt: now + PENDING_ACCESS_TOTP_TTL_MS,
	});
	return mode;
}

export function pendingAccessTwoFactor(sessionId: string, mode: PendingAccessTwoFactorMode): PendingAccessTwoFactor | null {
	const entry = pendingAccessTwoFactors.get(sessionId);
	if (!entry || entry.expiresAt <= Date.now() || entry.mode !== mode) return null;
	return entry;
}

export function setPendingAccessTotpSecret(sessionId: string, secret: string): void {
	const entry = pendingAccessTwoFactors.get(sessionId);
	if (entry) entry.tentativeSecret = secret;
}

export function setPendingAccessWebauthnChallenge(sessionId: string, challenge: string): void {
	const entry = pendingAccessTwoFactors.get(sessionId);
	if (entry) entry.webauthnChallenge = challenge;
}

export function consumePendingAccessTwoFactor(sessionId: string): void {
	pendingAccessTwoFactors.delete(sessionId);
}

export function accessTwoFactorRetryAfterSeconds(sessionId: string): number {
	return accessTwoFactorFailures.status([`totp:${sessionId}`], Date.now());
}

export function recordAccessTwoFactorFailure(sessionId: string): void {
	accessTwoFactorFailures.record([`totp:${sessionId}`], Date.now());
}

export function clearAccessTwoFactorFailures(sessionId: string): void {
	accessTwoFactorFailures.clear([`totp:${sessionId}`]);
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
