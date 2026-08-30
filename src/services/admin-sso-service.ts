import { repository } from "../db/repository.ts";
import type { AdminSsoSettingsRecord, AdminUserRecord } from "../types.ts";
import { randomToken, sha256Hex } from "../utils/crypto.ts";
import { normalizeAdminUsername } from "./admin-user-service.ts";
import {
	buildAuthorizationUrl,
	discoverOidcConfig,
	exchangeAuthorizationCode,
	generatePkce,
	invalidateOidcDiscoveryCache,
	verifyBackchannelLogoutToken,
	verifyIdToken,
	type VerifiedOidcIdentity,
} from "./oidc-service.ts";
import { decryptSecret, encryptSecret } from "./secret-encryption-service.ts";

export interface AdminSsoSettingsView {
	enabled: boolean;
	enforceSso: boolean;
	issuerUrl: string;
	clientId: string;
	clientSecretConfigured: boolean;
	scopes: string;
	buttonLabel: string;
}

export interface AdminSsoLoginInfo {
	enabled: boolean;
	enforceSso: boolean;
	buttonLabel: string;
}

function booleanValue(value: unknown, fallback: boolean): boolean {
	if (value === undefined) return fallback;
	if (typeof value === "boolean") return value;
	if (value === 1 || value === "1" || value === "true") return true;
	if (value === 0 || value === "0" || value === "false") return false;
	throw new Error("Boolean value expected");
}

function view(settings: AdminSsoSettingsRecord): AdminSsoSettingsView {
	return {
		enabled: settings.enabled === 1,
		enforceSso: settings.enforce_sso === 1,
		issuerUrl: settings.issuer_url ?? "",
		clientId: settings.client_id ?? "",
		clientSecretConfigured: settings.client_secret_encrypted !== null,
		scopes: settings.scopes,
		buttonLabel: settings.button_label,
	};
}

const SETTINGS_CACHE_TTL_MS = 5_000;
let settingsCache: { settings: AdminSsoSettingsRecord; expiresAt: number } | null = null;

async function currentSettings(): Promise<AdminSsoSettingsRecord> {
	if (settingsCache && settingsCache.expiresAt > Date.now()) return settingsCache.settings;
	const settings = await repository.ensureAdminSsoSettings();
	settingsCache = { settings, expiresAt: Date.now() + SETTINGS_CACHE_TTL_MS };
	return settings;
}

export async function adminSsoSettingsView(): Promise<AdminSsoSettingsView> {
	return view(await currentSettings());
}

export async function adminSsoLoginInfo(): Promise<AdminSsoLoginInfo> {
	const settings = await currentSettings();
	return { enabled: settings.enabled === 1, enforceSso: settings.enforce_sso === 1, buttonLabel: settings.button_label };
}

export interface AdminSsoSettingsInput {
	enabled?: unknown;
	enforceSso?: unknown;
	issuerUrl?: unknown;
	clientId?: unknown;
	clientSecret?: unknown;
	scopes?: unknown;
	buttonLabel?: unknown;
}

export async function updateAdminSsoSettings(input: AdminSsoSettingsInput): Promise<AdminSsoSettingsView> {
	const existing = await repository.ensureAdminSsoSettings();
	const issuerUrl = input.issuerUrl === undefined ? (existing.issuer_url ?? "") : String(input.issuerUrl ?? "").trim();
	const clientId = input.clientId === undefined ? (existing.client_id ?? "") : String(input.clientId ?? "").trim();
	const scopes = input.scopes === undefined ? existing.scopes : String(input.scopes ?? "").trim() || "openid email profile";
	const buttonLabel = input.buttonLabel === undefined ? existing.button_label : String(input.buttonLabel ?? "").trim() || "Single sign-on";
	const enabled = booleanValue(input.enabled, existing.enabled === 1);
	const enforceSso = booleanValue(input.enforceSso, existing.enforce_sso === 1);
	let clientSecretEncrypted = existing.client_secret_encrypted;
	if (typeof input.clientSecret === "string" && input.clientSecret.trim()) {
		clientSecretEncrypted = await encryptSecret(input.clientSecret.trim());
	}
	if (enabled) {
		if (!issuerUrl) throw new Error("Issuer URL is required to enable SSO");
		if (!clientId) throw new Error("Client ID is required to enable SSO");
		if (!clientSecretEncrypted) throw new Error("Client secret is required to enable SSO");
		try {
			new URL(issuerUrl);
		} catch {
			throw new Error("Issuer URL must be a valid URL");
		}
		await discoverOidcConfig(issuerUrl);
	}
	if (existing.issuer_url && existing.issuer_url !== issuerUrl) invalidateOidcDiscoveryCache(existing.issuer_url);
	const updated: AdminSsoSettingsRecord = {
		...existing,
		enabled: enabled ? 1 : 0,
		enforce_sso: enforceSso ? 1 : 0,
		issuer_url: issuerUrl || null,
		client_id: clientId || null,
		client_secret_encrypted: clientSecretEncrypted,
		scopes,
		button_label: buttonLabel,
		updated_at: Date.now(),
	};
	await repository.saveAdminSsoSettings(updated);
	settingsCache = { settings: updated, expiresAt: Date.now() + SETTINGS_CACHE_TTL_MS };
	return view(updated);
}

interface PendingAdminSso {
	nonce: string;
	codeVerifier: string;
	redirectUri: string;
	expiresAt: number;
}

const PENDING_SSO_TTL_MS = 5 * 60_000;
const pendingAdminSso = new Map<string, PendingAdminSso>();

function sweepPendingAdminSso(now: number): void {
	for (const [key, entry] of pendingAdminSso) if (entry.expiresAt <= now) pendingAdminSso.delete(key);
}

export async function beginAdminSsoLogin(redirectUri: string): Promise<string> {
	const settings = await repository.ensureAdminSsoSettings();
	if (settings.enabled !== 1 || !settings.issuer_url || !settings.client_id) throw new Error("Single sign-on is not configured");
	const document = await discoverOidcConfig(settings.issuer_url);
	const state = randomToken();
	const nonce = randomToken();
	const pkce = await generatePkce();
	const now = Date.now();
	sweepPendingAdminSso(now);
	pendingAdminSso.set(state, { nonce, codeVerifier: pkce.verifier, redirectUri, expiresAt: now + PENDING_SSO_TTL_MS });
	return buildAuthorizationUrl(document, { clientId: settings.client_id, redirectUri, scope: settings.scopes, state, nonce, codeChallenge: pkce.challenge });
}

async function resolveOrProvisionAdminUser(identity: VerifiedOidcIdentity): Promise<{ user: AdminUserRecord; provisioned: boolean }> {
	const bySubject = await repository.adminUserBySsoSubject(identity.subject);
	if (bySubject) return { user: bySubject, provisioned: false };
	if (!identity.email) throw new Error("The identity provider did not return an email address");
	const username = normalizeAdminUsername(identity.email);
	const byUsername = await repository.adminUserByUsername(username);
	if (byUsername) {
		if (byUsername.sso_subject && byUsername.sso_subject !== identity.subject) {
			throw new Error("This account is already linked to a different single sign-on identity");
		}
		const linked: AdminUserRecord = { ...byUsername, sso_subject: identity.subject, auth_source: "sso", updated_at: Date.now() };
		await repository.updateAdminUser(linked);
		return { user: linked, provisioned: false };
	}
	const now = Date.now();
	const user: AdminUserRecord = {
		id: `admin_sso_${(await sha256Hex(identity.subject)).slice(0, 32)}`,
		username,
		password_hash: await Bun.password.hash(randomToken(32), { algorithm: "argon2id" }),
		role: "member",
		totp_secret_encrypted: null,
		totp_enrolled_at: null,
		must_enroll_totp: 0,
		enabled: 1,
		created_at: now,
		updated_at: now,
		created_by_user_id: null,
		sso_subject: identity.subject,
		auth_source: "sso",
	};
	await repository.insertAdminUser(user);
	return { user, provisioned: true };
}

export interface AdminSsoLoginResult {
	user: AdminUserRecord;
	provisioned: boolean;
	sid: string | null;
}

export async function completeAdminSsoLogin(code: string, state: string): Promise<AdminSsoLoginResult> {
	const pending = pendingAdminSso.get(state);
	if (!pending || pending.expiresAt <= Date.now()) throw new Error("The sign-in attempt expired. Try again.");
	pendingAdminSso.delete(state);
	const settings = await repository.ensureAdminSsoSettings();
	if (settings.enabled !== 1 || !settings.issuer_url || !settings.client_id || !settings.client_secret_encrypted) {
		throw new Error("Single sign-on is not configured");
	}
	const document = await discoverOidcConfig(settings.issuer_url);
	const clientSecret = await decryptSecret(settings.client_secret_encrypted);
	const tokens = await exchangeAuthorizationCode(document, {
		clientId: settings.client_id,
		clientSecret,
		code,
		redirectUri: pending.redirectUri,
		codeVerifier: pending.codeVerifier,
	});
	if (!tokens.id_token) throw new Error("The identity provider did not return an ID token");
	const identity = await verifyIdToken(document, tokens.id_token, settings.client_id, pending.nonce);
	const { user, provisioned } = await resolveOrProvisionAdminUser(identity);
	if (user.enabled !== 1) throw new Error("This account is disabled");
	return { user, provisioned, sid: identity.sid };
}

export async function handleAdminBackchannelLogout(logoutToken: string): Promise<void> {
	const settings = await repository.ensureAdminSsoSettings();
	if (settings.enabled !== 1 || !settings.issuer_url || !settings.client_id) throw new Error("Single sign-on is not configured");
	const document = await discoverOidcConfig(settings.issuer_url);
	const { subject, sid } = await verifyBackchannelLogoutToken(document, logoutToken, settings.client_id);
	let revoked = 0;
	if (sid) revoked = await repository.revokeAdminSessionsBySsoSid(sid);
	if (revoked === 0 && subject) {
		const user = await repository.adminUserBySsoSubject(subject);
		if (user) await repository.revokeAdminSessionsForUser(user.id);
	}
}
