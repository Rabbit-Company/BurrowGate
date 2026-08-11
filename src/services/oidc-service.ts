import { createRemoteJWKSet, jwtVerify } from "jose";
import { randomToken, sha256Bytes, toBase64Url } from "../utils/crypto.ts";

export interface OidcDiscoveryDocument {
	issuer: string;
	authorization_endpoint: string;
	token_endpoint: string;
	jwks_uri: string;
	userinfo_endpoint?: string;
}

export interface PkcePair {
	verifier: string;
	challenge: string;
}

export interface TokenResponse {
	id_token?: string;
	access_token?: string;
	token_type?: string;
	expires_in?: number;
}

export interface VerifiedOidcIdentity {
	subject: string;
	email: string | null;
	emailVerified: boolean;
	name: string | null;
	sid: string | null;
}

export interface BackchannelLogoutIdentity {
	subject: string | null;
	sid: string | null;
}

const DISCOVERY_CACHE_TTL_MS = 10 * 60_000;
const discoveryCache = new Map<string, { document: OidcDiscoveryDocument; expiresAt: number }>();
const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function normalizeIssuer(issuerUrl: string): string {
	return issuerUrl.trim().replace(/\/+$/u, "");
}

export async function discoverOidcConfig(issuerUrl: string): Promise<OidcDiscoveryDocument> {
	const normalized = normalizeIssuer(issuerUrl);
	const cached = discoveryCache.get(normalized);
	if (cached && cached.expiresAt > Date.now()) return cached.document;
	let response: Response;
	try {
		response = await fetch(`${normalized}/.well-known/openid-configuration`);
	} catch (error) {
		throw new Error(`Unable to reach the identity provider: ${error instanceof Error ? error.message : "network error"}`);
	}
	if (!response.ok) throw new Error(`The identity provider's discovery document returned HTTP ${response.status}`);
	const document = (await response.json()) as OidcDiscoveryDocument;
	if (!document.issuer || !document.authorization_endpoint || !document.token_endpoint || !document.jwks_uri) {
		throw new Error("The identity provider's discovery document is missing required fields");
	}
	discoveryCache.set(normalized, { document, expiresAt: Date.now() + DISCOVERY_CACHE_TTL_MS });
	return document;
}

export function invalidateOidcDiscoveryCache(issuerUrl: string): void {
	const normalized = normalizeIssuer(issuerUrl);
	discoveryCache.delete(normalized);
	jwksCache.delete(normalized);
}

function remoteJwks(document: OidcDiscoveryDocument): ReturnType<typeof createRemoteJWKSet> {
	const normalized = normalizeIssuer(document.issuer);
	let set = jwksCache.get(normalized);
	if (!set) {
		set = createRemoteJWKSet(new URL(document.jwks_uri));
		jwksCache.set(normalized, set);
	}
	return set;
}

export async function generatePkce(): Promise<PkcePair> {
	const verifier = randomToken(48);
	const challenge = toBase64Url(await sha256Bytes(verifier));
	return { verifier, challenge };
}

export function buildAuthorizationUrl(
	document: OidcDiscoveryDocument,
	params: { clientId: string; redirectUri: string; scope: string; state: string; nonce: string; codeChallenge: string },
): string {
	const url = new URL(document.authorization_endpoint);
	url.searchParams.set("response_type", "code");
	url.searchParams.set("client_id", params.clientId);
	url.searchParams.set("redirect_uri", params.redirectUri);
	url.searchParams.set("scope", params.scope);
	url.searchParams.set("state", params.state);
	url.searchParams.set("nonce", params.nonce);
	url.searchParams.set("code_challenge", params.codeChallenge);
	url.searchParams.set("code_challenge_method", "S256");
	return url.href;
}

export async function exchangeAuthorizationCode(
	document: OidcDiscoveryDocument,
	params: { clientId: string; clientSecret: string; code: string; redirectUri: string; codeVerifier: string },
): Promise<TokenResponse> {
	const body = new URLSearchParams({
		grant_type: "authorization_code",
		code: params.code,
		redirect_uri: params.redirectUri,
		client_id: params.clientId,
		client_secret: params.clientSecret,
		code_verifier: params.codeVerifier,
	});
	let response: Response;
	try {
		response = await fetch(document.token_endpoint, {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
			body,
		});
	} catch (error) {
		throw new Error(`Unable to reach the identity provider's token endpoint: ${error instanceof Error ? error.message : "network error"}`);
	}
	if (!response.ok) throw new Error(`The identity provider rejected the sign-in (HTTP ${response.status})`);
	return (await response.json()) as TokenResponse;
}

export async function verifyIdToken(document: OidcDiscoveryDocument, idToken: string, clientId: string, expectedNonce: string): Promise<VerifiedOidcIdentity> {
	const { payload } = await jwtVerify(idToken, remoteJwks(document), { issuer: document.issuer, audience: clientId });
	if (typeof payload.nonce !== "string" || payload.nonce !== expectedNonce) {
		throw new Error("The identity provider returned an unexpected nonce");
	}
	const subject = typeof payload.sub === "string" ? payload.sub : "";
	if (!subject) throw new Error("The identity provider did not return a subject claim");
	return {
		subject,
		email: typeof payload.email === "string" ? payload.email.trim().toLowerCase() : null,
		emailVerified: payload.email_verified === true,
		name: typeof payload.name === "string" ? payload.name : null,
		sid: typeof payload.sid === "string" ? payload.sid : null,
	};
}

const BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";
const LOGOUT_TOKEN_FRESHNESS_MS = 5 * 60_000;
const usedLogoutTokenIds = new Map<string, number>();

function sweepUsedLogoutTokenIds(now: number): void {
	for (const [jti, expiresAt] of usedLogoutTokenIds) if (expiresAt <= now) usedLogoutTokenIds.delete(jti);
}

export async function verifyBackchannelLogoutToken(document: OidcDiscoveryDocument, logoutToken: string, clientId: string): Promise<BackchannelLogoutIdentity> {
	const { payload } = await jwtVerify(logoutToken, remoteJwks(document), { issuer: document.issuer, audience: clientId });
	if (payload.nonce !== undefined) throw new Error("Logout token must not contain a nonce claim");
	const events = payload.events;
	if (!events || typeof events !== "object" || !(BACKCHANNEL_LOGOUT_EVENT in events)) {
		throw new Error("Logout token is missing the back-channel logout event claim");
	}
	const subject = typeof payload.sub === "string" ? payload.sub : null;
	const sid = typeof payload.sid === "string" ? payload.sid : null;
	if (!subject && !sid) throw new Error("Logout token must contain a subject or session identifier");
	const jti = typeof payload.jti === "string" ? payload.jti : null;
	if (!jti) throw new Error("Logout token must contain a jti claim");
	const iat = typeof payload.iat === "number" ? payload.iat * 1_000 : 0;
	const now = Date.now();
	if (!iat || Math.abs(now - iat) > LOGOUT_TOKEN_FRESHNESS_MS) throw new Error("Logout token is expired or not yet valid");
	sweepUsedLogoutTokenIds(now);
	if (usedLogoutTokenIds.has(jti)) throw new Error("Logout token has already been used");
	usedLogoutTokenIds.set(jti, now + LOGOUT_TOKEN_FRESHNESS_MS);
	return { subject, sid };
}
