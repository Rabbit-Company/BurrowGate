import { repository } from "../db/repository.ts";
import type { AccessUserRecord, SiteSsoSettingsRecord } from "../types.ts";
import { randomId, randomToken } from "../utils/crypto.ts";
import { normalizeAccessUsername } from "./access-list-service.ts";
import {
	buildAuthorizationUrl,
	discoverOidcConfig,
	exchangeAuthorizationCode,
	generatePkce,
	invalidateOidcDiscoveryCache,
	verifyIdToken,
	type VerifiedOidcIdentity,
} from "./oidc-service.ts";
import { decryptSecret, encryptSecret } from "./secret-encryption-service.ts";

export interface SiteSsoSettingsView {
	enabled: boolean;
	enforceSso: boolean;
	issuerUrl: string;
	clientId: string;
	clientSecretConfigured: boolean;
	scopes: string;
	buttonLabel: string;
}

export interface SiteSsoLoginInfo {
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

function view(settings: SiteSsoSettingsRecord): SiteSsoSettingsView {
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
const settingsCache = new Map<string, { settings: SiteSsoSettingsRecord; expiresAt: number }>();

async function currentSettings(siteId: string): Promise<SiteSsoSettingsRecord> {
	const cached = settingsCache.get(siteId);
	if (cached && cached.expiresAt > Date.now()) return cached.settings;
	const settings = await repository.ensureSiteSsoSettings(siteId);
	settingsCache.set(siteId, { settings, expiresAt: Date.now() + SETTINGS_CACHE_TTL_MS });
	return settings;
}

export function invalidateSiteSso(siteId: string): void {
	settingsCache.delete(siteId);
}

export async function siteSsoSettingsView(siteId: string): Promise<SiteSsoSettingsView> {
	return view(await currentSettings(siteId));
}

export async function siteSsoLoginInfo(siteId: string): Promise<SiteSsoLoginInfo> {
	const settings = await currentSettings(siteId);
	return { enabled: settings.enabled === 1, enforceSso: settings.enforce_sso === 1, buttonLabel: settings.button_label };
}

export interface SiteSsoSettingsInput {
	enabled?: unknown;
	enforceSso?: unknown;
	issuerUrl?: unknown;
	clientId?: unknown;
	clientSecret?: unknown;
	scopes?: unknown;
	buttonLabel?: unknown;
}

export async function updateSiteSsoSettings(siteId: string, input: SiteSsoSettingsInput): Promise<SiteSsoSettingsView> {
	const existing = await repository.ensureSiteSsoSettings(siteId);
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
	const updated: SiteSsoSettingsRecord = {
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
	await repository.saveSiteSsoSettings(updated);
	settingsCache.set(siteId, { settings: updated, expiresAt: Date.now() + SETTINGS_CACHE_TTL_MS });
	return view(updated);
}

interface PendingAccessSso {
	siteId: string;
	returnPath: string;
	nonce: string;
	codeVerifier: string;
	redirectUri: string;
	expiresAt: number;
}

const PENDING_SSO_TTL_MS = 5 * 60_000;
const pendingAccessSso = new Map<string, PendingAccessSso>();

function sweepPendingAccessSso(now: number): void {
	for (const [key, entry] of pendingAccessSso) if (entry.expiresAt <= now) pendingAccessSso.delete(key);
}

export async function beginAccessSsoLogin(siteId: string, returnPath: string, redirectUri: string): Promise<string> {
	const settings = await repository.ensureSiteSsoSettings(siteId);
	if (settings.enabled !== 1 || !settings.issuer_url || !settings.client_id) throw new Error("Single sign-on is not configured for this site");
	const document = await discoverOidcConfig(settings.issuer_url);
	const state = randomToken();
	const nonce = randomToken();
	const pkce = await generatePkce();
	const now = Date.now();
	sweepPendingAccessSso(now);
	pendingAccessSso.set(state, { siteId, returnPath, nonce, codeVerifier: pkce.verifier, redirectUri, expiresAt: now + PENDING_SSO_TTL_MS });
	return buildAuthorizationUrl(document, { clientId: settings.client_id, redirectUri, scope: settings.scopes, state, nonce, codeChallenge: pkce.challenge });
}

async function resolveOrProvisionAccessUser(siteId: string, identity: VerifiedOidcIdentity): Promise<AccessUserRecord> {
	let user = await repository.accessUserBySsoSubject(identity.subject);
	if (!user) {
		if (!identity.email) throw new Error("The identity provider did not return an email address");
		const username = normalizeAccessUsername(identity.email);
		const existing = await repository.accessUserByUsername(username);
		if (existing) {
			if (existing.sso_subject && existing.sso_subject !== identity.subject) {
				throw new Error("This account is already linked to a different single sign-on identity");
			}
			user = { ...existing, sso_subject: identity.subject, auth_source: "sso", updated_at: Date.now() };
			await repository.updateAccessUser(user);
		} else {
			const now = Date.now();
			user = {
				id: randomId("user"),
				username,
				password_hash: await Bun.password.hash(randomToken(32), { algorithm: "argon2id" }),
				enabled: 1,
				created_at: now,
				updated_at: now,
				totp_required: 0,
				totp_secret_encrypted: null,
				totp_enrolled_at: null,
				api_token_hash: null,
				api_token_created_at: null,
				sso_subject: identity.subject,
				auth_source: "sso",
			};
			await repository.insertAccessUser(user);
		}
	}
	if (!(await repository.accessUserForSite(siteId, user.id))) await repository.assignAccessUser(siteId, user.id);
	return user;
}

export interface AccessSsoLoginResult {
	user: AccessUserRecord;
	returnPath: string;
}

export async function completeAccessSsoLogin(siteId: string, code: string, state: string): Promise<AccessSsoLoginResult> {
	const pending = pendingAccessSso.get(state);
	if (!pending || pending.expiresAt <= Date.now() || pending.siteId !== siteId) throw new Error("The sign-in attempt expired. Try again.");
	pendingAccessSso.delete(state);
	const settings = await repository.ensureSiteSsoSettings(siteId);
	if (settings.enabled !== 1 || !settings.issuer_url || !settings.client_id || !settings.client_secret_encrypted) {
		throw new Error("Single sign-on is not configured for this site");
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
	const user = await resolveOrProvisionAccessUser(siteId, identity);
	if (user.enabled !== 1) throw new Error("This account is disabled");
	return { user, returnPath: pending.returnPath };
}
