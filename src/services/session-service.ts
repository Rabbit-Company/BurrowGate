import {
	adminCookieName,
	adminCookieNames,
	config,
	cookieCanBeIssuedForRequest,
	insecureCookieConfigurationMessage,
	secureCookieForRequest,
	visitorCookieName,
	visitorCookieNames,
} from "../config.ts";
import { repository } from "../db/repository.ts";
import type { AccessSessionRecord, AdminSessionRecord, SiteRecord } from "../types.ts";
import { parseCookies, serializeCookie } from "../utils/cookies.ts";
import { randomId, randomToken, sha256Hex } from "../utils/crypto.ts";
import { asnForStorage, countryCodeForStorage } from "./geoip-service.ts";

function cookieTokens(request: Request, names: readonly string[]): string[] {
	const cookies = parseCookies(request.headers.get("cookie"));
	const tokens: string[] = [];
	for (const name of names) {
		const token = cookies.get(name);
		if (token && !tokens.includes(token)) tokens.push(token);
	}
	return tokens;
}

export async function userAgentHash(request: Request): Promise<string> {
	return await sha256Hex(request.headers.get("user-agent") ?? "");
}

export async function findAccessSession(request: Request, site: SiteRecord, ip: string): Promise<AccessSessionRecord | null> {
	const authorization = request.headers.get("authorization");
	const explicitToken = authorization?.startsWith("Burrow ") ? authorization.slice(7) : (request.headers.get("x-burrow-token") ?? undefined);
	const tokens = explicitToken ? [explicitToken] : cookieTokens(request, visitorCookieNames);

	for (const token of tokens) {
		const session = await repository.sessionByHash(site.id, await sha256Hex(token));
		if (!session || session.revoked_at !== null || session.expires_at <= Date.now()) continue;
		await repository.touchSession(session.id, ip, Date.now());
		return session;
	}
	return null;
}

export async function createAccessSession(
	request: Request,
	site: SiteRecord,
	ip: string,
	userAgentHashValue: string,
	summary: unknown,
): Promise<{ record: AccessSessionRecord; token: string; cookie: string }> {
	if (!cookieCanBeIssuedForRequest(request)) {
		throw new Error(insecureCookieConfigurationMessage());
	}
	const token = randomToken();
	const now = Date.now();
	const secure = secureCookieForRequest(request);
	const asn = asnForStorage(ip);
	const record: AccessSessionRecord = {
		id: randomId("sess"),
		site_id: site.id,
		token_hash: await sha256Hex(token),
		initial_ip: ip,
		last_ip: ip,
		user_agent_hash: userAgentHashValue,
		created_at: now,
		last_seen_at: now,
		expires_at: now + site.session_ttl_seconds * 1_000,
		revoked_at: null,
		verification_summary_json: JSON.stringify(summary),
		request_count: 0,
		country_code: countryCodeForStorage(ip),
		asn: asn.asn,
		asn_org: asn.org,
		access_user_id: null,
		authenticated_at: null,
		sso_sid: null,
	};
	await repository.insertSession(record);
	return {
		record,
		token,
		cookie: serializeCookie(visitorCookieName(secure), token, {
			secure,
			httpOnly: true,
			sameSite: "Lax",
			maxAge: site.session_ttl_seconds,
		}),
	};
}

export function clearAccessSessionCookies(request: Request): string[] {
	return visitorCookieNames.map((name) =>
		serializeCookie(name, "", {
			secure: name.startsWith("__Host-") || secureCookieForRequest(request),
			httpOnly: true,
			sameSite: "Lax",
			maxAge: 0,
		}),
	);
}

export async function createAdminSession(
	request: Request,
	username: string,
	userId: string | null = null,
	ssoSid: string | null = null,
): Promise<{ token: string; cookie: string }> {
	if (!cookieCanBeIssuedForRequest(request)) {
		throw new Error(insecureCookieConfigurationMessage());
	}
	const token = randomToken();
	const now = Date.now();
	const secure = secureCookieForRequest(request);
	const session: AdminSessionRecord = {
		id: randomId("admin"),
		token_hash: await sha256Hex(token),
		username,
		user_id: userId,
		created_at: now,
		expires_at: now + config.admin.sessionTtlSeconds * 1_000,
		last_seen_at: now,
		sso_sid: ssoSid,
	};
	await repository.insertAdmin(session);
	return {
		token,
		cookie: serializeCookie(adminCookieName(secure), token, {
			secure,
			httpOnly: true,
			sameSite: "Strict",
			maxAge: config.admin.sessionTtlSeconds,
		}),
	};
}

export async function getAdminSession(request: Request): Promise<AdminSessionRecord | null> {
	for (const token of cookieTokens(request, adminCookieNames)) {
		const session = await repository.adminByHash(await sha256Hex(token));
		if (!session || session.expires_at <= Date.now()) continue;
		await repository.touchAdmin(session.id, Date.now());
		return session;
	}
	return null;
}

export function adminSessionTokens(request: Request): string[] {
	return cookieTokens(request, adminCookieNames);
}
