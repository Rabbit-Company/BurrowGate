import { getClientIp } from "@rabbit-company/web-middleware/ip-extract";
import type { Web } from "@rabbit-company/web";
import { repository } from "../db/repository.ts";
import {
	accessIdentitySetCookies,
	accessSettingsForSite,
	accessTwoFactorRetryAfterSeconds,
	authenticateAccessUser,
	authenticatedAccessUser,
	beginAccessTwoFactorChallenge,
	clearAccessIdentityCookies,
	clearAccessTwoFactorFailures,
	completeAccessTotpEnrollment,
	consumePendingAccessTwoFactor,
	decryptAccessTotpSecret,
	pendingAccessTwoFactor,
	recordAccessTwoFactorFailure,
	setPendingAccessTotpSecret,
	setPendingAccessWebauthnChallenge,
	type PendingAccessTwoFactorMode,
} from "../services/access-list-service.ts";
import { beginAccessSsoLogin, completeAccessSsoLogin, handleAccessBackchannelLogout, siteSsoLoginInfo } from "../services/access-sso-service.ts";
import { createFlow } from "../services/challenge-service.ts";
import { recordEvent } from "../services/event-service.ts";
import { findAccessSession, userAgentHash } from "../services/session-service.ts";
import { resolveSiteForHost } from "../services/site-service.ts";
import { enrollmentUri, generateSecret, qrSvg, verifyCode as verifyTotpCode } from "../services/totp-service.ts";
import type { AccessSessionRecord, AccessUserRecord, SiteRecord } from "../types.ts";
import { accessLoginPage, accessTwoFactorEnrollPage, accessTwoFactorVerifyPage } from "../ui/access-login-page.ts";
import { randomId, sha256Hex } from "../utils/crypto.ts";
import { appendSetCookies, htmlResponse, jsonResponse, normalizeHost, requestHost, safeReturnPath, sameOriginRequest } from "../utils/http.ts";
import { buildAuthenticationOptions, buildRegistrationOptions, verifyAuthentication, verifyRegistration } from "../services/webauthn-service.ts";

function loginPath(returnPath: string): string {
	return `/_burrowgate/access/login?return=${encodeURIComponent(returnPath)}`;
}

function webauthnRelyingParty(request: Request): { rpID: string; origin: string } {
	const url = new URL(request.url);
	return { rpID: url.hostname, origin: url.origin };
}

async function context(ctx: any): Promise<{
	site: Awaited<ReturnType<typeof resolveSiteForHost>>;
	ip: string;
	returnPath: string;
}> {
	const url = new URL(ctx.req.url);
	return {
		site: ctx.state?.site ?? (await resolveSiteForHost(normalizeHost(requestHost(ctx.req)))),
		ip: getClientIp(ctx) ?? "unknown",
		returnPath: safeReturnPath(url.searchParams.get("return")),
	};
}

interface ResolvedPendingTwoFactor {
	site: SiteRecord;
	session: AccessSessionRecord;
	user: AccessUserRecord;
	tentativeSecret: string | null;
	webauthnChallenge: string | null;
}

async function resolvePendingAccessTwoFactor(ctx: any, mode: PendingAccessTwoFactorMode): Promise<ResolvedPendingTwoFactor | null> {
	const site = ctx.state?.site ?? (await resolveSiteForHost(normalizeHost(requestHost(ctx.req))));
	if (!site) return null;
	const ip = getClientIp(ctx) ?? "unknown";
	const session = await findAccessSession(ctx.req, site, ip);
	if (!session) return null;
	const entry = pendingAccessTwoFactor(session.id, mode);
	if (!entry) return null;
	const user = await repository.accessUserForSite(site.id, entry.userId);
	if (!user) return null;
	return { site, session, user, tentativeSecret: entry.tentativeSecret, webauthnChallenge: entry.webauthnChallenge };
}

async function issueAccessSession(
	ctx: any,
	site: SiteRecord,
	session: AccessSessionRecord,
	user: AccessUserRecord,
	ssoSid: string | null = null,
): Promise<string[]> {
	await repository.authenticateSession(session.id, site.id, user.id, Date.now(), ssoSid);
	const settings = await accessSettingsForSite(site.id);
	return settings.send_username_to_upstream === 1 ? await accessIdentitySetCookies(ctx.req, site, session, user.username) : clearAccessIdentityCookies(ctx.req);
}

export function registerAccessRoutes(app: Web<any>): void {
	app.get("/_burrowgate/access/login", async (ctx) => {
		const { site, ip, returnPath } = await context(ctx);
		if (!site) return htmlResponse("No BurrowGate site is configured for this host.", 421);
		const settings = await accessSettingsForSite(site.id);
		if (settings.enabled !== 1) return appendSetCookies(Response.redirect(new URL(returnPath, ctx.req.url).href, 302), clearAccessIdentityCookies(ctx.req));
		const session = await findAccessSession(ctx.req, site, ip);
		if (!session) {
			const returnToLogin = loginPath(returnPath);
			const flow = await createFlow(site, returnToLogin, ip, await userAgentHash(ctx.req));
			return Response.redirect(new URL(`/_burrowgate/verify?flow=${encodeURIComponent(flow.id)}`, ctx.req.url).href, 302);
		}
		const user = await authenticatedAccessUser(site.id, session);
		if (user) {
			const cookies =
				settings.send_username_to_upstream === 1 ? await accessIdentitySetCookies(ctx.req, site, session, user.username) : clearAccessIdentityCookies(ctx.req);
			return appendSetCookies(Response.redirect(new URL(returnPath, ctx.req.url).href, 302), cookies);
		}
		return appendSetCookies(htmlResponse(accessLoginPage(site, returnPath, "", await siteSsoLoginInfo(site.id))), clearAccessIdentityCookies(ctx.req));
	});

	app.post("/_burrowgate/access/login", async (ctx) => {
		const started = performance.now();
		const form = await ctx.req.formData();
		const returnPath = safeReturnPath(String(form.get("return") ?? "/"));
		const site = ctx.state?.site ?? (await resolveSiteForHost(normalizeHost(requestHost(ctx.req))));
		if (!site) return htmlResponse("No BurrowGate site is configured for this host.", 421);
		if (!sameOriginRequest(ctx.req)) return htmlResponse(accessLoginPage(site, returnPath, "Request validation failed.", await siteSsoLoginInfo(site.id)), 403);
		const settings = await accessSettingsForSite(site.id);
		if (settings.enabled !== 1) return appendSetCookies(Response.redirect(new URL(returnPath, ctx.req.url).href, 302), clearAccessIdentityCookies(ctx.req));
		const ip = getClientIp(ctx) ?? "unknown";
		const session = await findAccessSession(ctx.req, site, ip);
		if (!session) {
			const flow = await createFlow(site, loginPath(returnPath), ip, await userAgentHash(ctx.req));
			return Response.redirect(new URL(`/_burrowgate/verify?flow=${encodeURIComponent(flow.id)}`, ctx.req.url).href, 302);
		}
		const result = await authenticateAccessUser(site.id, ip, form.get("username"), form.get("password"));
		if (!result.user) {
			const limited = result.retryAfterSeconds > 0;
			await recordEvent({
				siteId: site.id,
				sessionId: session.id,
				ip,
				method: "POST",
				path: "/_burrowgate/access/login",
				status: limited ? 429 : 401,
				decision: limited ? "access-login-rate-limited" : "access-login-failed",
				latencyMs: Math.round(performance.now() - started),
			});
			return appendSetCookies(
				htmlResponse(
					accessLoginPage(
						site,
						returnPath,
						limited ? `Too many failed attempts. Try again in ${result.retryAfterSeconds} seconds.` : "Invalid username or password.",
						await siteSsoLoginInfo(site.id),
					),
					limited ? 429 : 401,
					limited ? { "retry-after": String(result.retryAfterSeconds) } : undefined,
				),
				clearAccessIdentityCookies(ctx.req),
			);
		}
		if (result.user.totp_required === 1) {
			const mode = await beginAccessTwoFactorChallenge(session.id, site.id, result.user);
			await recordEvent({
				siteId: site.id,
				sessionId: session.id,
				ip,
				method: "POST",
				path: "/_burrowgate/access/login",
				status: 302,
				decision: "access-login-required",
				latencyMs: Math.round(performance.now() - started),
			});
			const target = mode === "enroll" ? "/_burrowgate/access/login/enroll" : "/_burrowgate/access/login/verify";
			return Response.redirect(new URL(`${target}?return=${encodeURIComponent(returnPath)}`, ctx.req.url).href, 302);
		}
		const cookies = await issueAccessSession(ctx, site, session, result.user);
		await recordEvent({
			siteId: site.id,
			sessionId: session.id,
			ip,
			method: "POST",
			path: "/_burrowgate/access/login",
			status: 302,
			decision: "access-authenticated",
			accessUsername: result.user.username,
			latencyMs: Math.round(performance.now() - started),
		});
		return appendSetCookies(Response.redirect(new URL(returnPath, ctx.req.url).href, 302), cookies);
	});

	app.get("/_burrowgate/access/login/sso", async (ctx) => {
		const { site, ip, returnPath } = await context(ctx);
		if (!site) return htmlResponse("No BurrowGate site is configured for this host.", 421);
		const settings = await accessSettingsForSite(site.id);
		if (settings.enabled !== 1) return Response.redirect(new URL(returnPath, ctx.req.url).href, 302);
		const session = await findAccessSession(ctx.req, site, ip);
		if (!session) {
			const flow = await createFlow(site, `/_burrowgate/access/login/sso?return=${encodeURIComponent(returnPath)}`, ip, await userAgentHash(ctx.req));
			return Response.redirect(new URL(`/_burrowgate/verify?flow=${encodeURIComponent(flow.id)}`, ctx.req.url).href, 302);
		}
		try {
			const redirectUri = new URL("/_burrowgate/access/sso/callback", ctx.req.url).href;
			const url = await beginAccessSsoLogin(site.id, returnPath, redirectUri);
			return Response.redirect(url, 302);
		} catch (error) {
			return htmlResponse(
				accessLoginPage(site, returnPath, error instanceof Error ? error.message : "Unable to start single sign-on", await siteSsoLoginInfo(site.id)),
				400,
			);
		}
	});

	app.get("/_burrowgate/access/sso/callback", async (ctx) => {
		const url = new URL(ctx.req.url);
		const site = ctx.state?.site ?? (await resolveSiteForHost(normalizeHost(requestHost(ctx.req))));
		if (!site) return htmlResponse("No BurrowGate site is configured for this host.", 421);
		const ip = getClientIp(ctx) ?? "unknown";
		const code = url.searchParams.get("code") ?? "";
		const state = url.searchParams.get("state") ?? "";
		const idpError = url.searchParams.get("error");
		if (idpError || !code || !state) {
			return htmlResponse(accessLoginPage(site, "/", "Single sign-on was cancelled or failed.", await siteSsoLoginInfo(site.id)), 400);
		}
		const session = await findAccessSession(ctx.req, site, ip);
		if (!session) return Response.redirect(new URL(loginPath("/"), ctx.req.url).href, 302);
		try {
			const { user, returnPath, sid } = await completeAccessSsoLogin(site.id, code, state);
			const cookies = await issueAccessSession(ctx, site, session, user, sid);
			await recordEvent({
				siteId: site.id,
				sessionId: session.id,
				ip,
				method: "GET",
				path: "/_burrowgate/access/sso/callback",
				status: 302,
				decision: "access-authenticated",
				accessUsername: user.username,
				latencyMs: 0,
			});
			return appendSetCookies(Response.redirect(new URL(returnPath, ctx.req.url).href, 302), cookies);
		} catch (error) {
			return htmlResponse(accessLoginPage(site, "/", error instanceof Error ? error.message : "Single sign-on failed.", await siteSsoLoginInfo(site.id)), 400);
		}
	});

	app.post("/_burrowgate/access/sso/backchannel-logout", async (ctx) => {
		const site = ctx.state?.site ?? (await resolveSiteForHost(normalizeHost(requestHost(ctx.req))));
		if (!site) return jsonResponse({ error: "invalid_request", error_description: "No BurrowGate site is configured for this host." }, 421);
		try {
			const form = await ctx.req.formData();
			const logoutToken = String(form.get("logout_token") ?? "");
			if (!logoutToken) return jsonResponse({ error: "invalid_request", error_description: "logout_token is required" }, 400);
			await handleAccessBackchannelLogout(site.id, logoutToken);
			return new Response(null, { status: 200 });
		} catch (error) {
			return jsonResponse({ error: "invalid_request", error_description: error instanceof Error ? error.message : "Unable to process logout token" }, 400);
		}
	});

	app.get("/_burrowgate/access/login/enroll", async (ctx) => {
		const returnPath = safeReturnPath(new URL(ctx.req.url).searchParams.get("return"));
		const resolved = await resolvePendingAccessTwoFactor(ctx, "enroll");
		if (!resolved) return Response.redirect(new URL(loginPath(returnPath), ctx.req.url).href, 302);
		const { site, session, user } = resolved;
		let secret = resolved.tentativeSecret;
		if (!secret) {
			secret = generateSecret();
			setPendingAccessTotpSecret(session.id, secret);
		}
		const uri = enrollmentUri(user.username, secret, `BurrowGate (${site.name})`);
		return htmlResponse(accessTwoFactorEnrollPage(site, uri, secret, await qrSvg(uri), returnPath));
	});

	app.post("/_burrowgate/access/login/enroll", async (ctx) => {
		const form = await ctx.req.formData();
		const returnPath = safeReturnPath(String(form.get("return") ?? "/"));
		if (!sameOriginRequest(ctx.req)) return htmlResponse("Request validation failed.", 403);
		const resolved = await resolvePendingAccessTwoFactor(ctx, "enroll");
		if (!resolved?.tentativeSecret) return Response.redirect(new URL(loginPath(returnPath), ctx.req.url).href, 302);
		const { site, session, user, tentativeSecret: secret } = resolved;
		const code = String(form.get("code") ?? "");
		if (!secret || !(await verifyTotpCode(secret, code))) {
			const uri = enrollmentUri(user.username, secret ?? "", `BurrowGate (${site.name})`);
			return htmlResponse(accessTwoFactorEnrollPage(site, uri, secret ?? "", await qrSvg(uri), returnPath, "Invalid code, try again"), 401);
		}
		await completeAccessTotpEnrollment(user.id, secret);
		consumePendingAccessTwoFactor(session.id);
		const cookies = await issueAccessSession(ctx, site, session, user);
		await recordEvent({
			siteId: site.id,
			sessionId: session.id,
			ip: getClientIp(ctx) ?? "unknown",
			method: "POST",
			path: "/_burrowgate/access/login/enroll",
			status: 302,
			decision: "access-authenticated",
			accessUsername: user.username,
			latencyMs: 0,
		});
		return appendSetCookies(Response.redirect(new URL(returnPath, ctx.req.url).href, 302), cookies);
	});

	app.get("/_burrowgate/access/login/verify", async (ctx) => {
		const returnPath = safeReturnPath(new URL(ctx.req.url).searchParams.get("return"));
		const resolved = await resolvePendingAccessTwoFactor(ctx, "verify");
		if (!resolved) return Response.redirect(new URL(loginPath(returnPath), ctx.req.url).href, 302);
		const hasWebauthn = (await repository.accessWebauthnCredentialsForUserAndSite(resolved.user.id, resolved.site.id)).length > 0;
		return htmlResponse(accessTwoFactorVerifyPage(resolved.site, returnPath, { hasWebauthn, hasTotp: resolved.user.totp_secret_encrypted !== null }));
	});

	app.post("/_burrowgate/access/login/verify", async (ctx) => {
		const form = await ctx.req.formData();
		const returnPath = safeReturnPath(String(form.get("return") ?? "/"));
		if (!sameOriginRequest(ctx.req)) return htmlResponse("Request validation failed.", 403);
		const resolved = await resolvePendingAccessTwoFactor(ctx, "verify");
		if (!resolved) return Response.redirect(new URL(loginPath(returnPath), ctx.req.url).href, 302);
		const { site, session, user } = resolved;
		const hasWebauthn = (await repository.accessWebauthnCredentialsForUserAndSite(user.id, site.id)).length > 0;
		const methods = { hasWebauthn, hasTotp: user.totp_secret_encrypted !== null };
		const retryAfterSeconds = accessTwoFactorRetryAfterSeconds(session.id);
		if (retryAfterSeconds > 0) return htmlResponse(accessTwoFactorVerifyPage(site, returnPath, methods, "Too many failed attempts. Try again later."), 429);
		const secret = user.totp_secret_encrypted ? await decryptAccessTotpSecret(user) : null;
		const code = String(form.get("code") ?? "");
		if (!secret || !(await verifyTotpCode(secret, code))) {
			recordAccessTwoFactorFailure(session.id);
			return htmlResponse(accessTwoFactorVerifyPage(site, returnPath, methods, "Invalid code"), 401);
		}
		clearAccessTwoFactorFailures(session.id);
		consumePendingAccessTwoFactor(session.id);
		const cookies = await issueAccessSession(ctx, site, session, user);
		await recordEvent({
			siteId: site.id,
			sessionId: session.id,
			ip: getClientIp(ctx) ?? "unknown",
			method: "POST",
			path: "/_burrowgate/access/login/verify",
			status: 302,
			decision: "access-authenticated",
			accessUsername: user.username,
			latencyMs: 0,
		});
		return appendSetCookies(Response.redirect(new URL(returnPath, ctx.req.url).href, 302), cookies);
	});

	app.post("/_burrowgate/api/access/login/webauthn/register/options", async (ctx) => {
		if (!sameOriginRequest(ctx.req)) return jsonResponse({ error: "Request validation failed" }, 403);
		const resolved = await resolvePendingAccessTwoFactor(ctx, "enroll");
		if (!resolved) return jsonResponse({ error: "No pending enrollment" }, 428);
		const { site, session, user } = resolved;
		const { rpID } = webauthnRelyingParty(ctx.req);
		const existing = await repository.accessWebauthnCredentialsForUserAndSite(user.id, site.id);
		const options = await buildRegistrationOptions({
			rpID,
			userId: user.id,
			username: user.username,
			excludeCredentials: existing.map((credential) => ({
				credentialId: credential.credential_id,
				transports: credential.transports_json ? (JSON.parse(credential.transports_json) as string[]) : [],
			})),
		});
		setPendingAccessWebauthnChallenge(session.id, options.challenge);
		return jsonResponse(options);
	});

	app.post("/_burrowgate/api/access/login/webauthn/register/verify", async (ctx) => {
		if (!sameOriginRequest(ctx.req)) return jsonResponse({ error: "Request validation failed" }, 403);
		const resolved = await resolvePendingAccessTwoFactor(ctx, "enroll");
		if (!resolved?.webauthnChallenge) return jsonResponse({ error: "No pending enrollment" }, 428);
		const { site, session, user, webauthnChallenge } = resolved;
		let body: { response?: unknown };
		try {
			body = (await ctx.req.json()) as any;
		} catch {
			return jsonResponse({ error: "Invalid JSON" }, 400);
		}
		const { rpID, origin } = webauthnRelyingParty(ctx.req);
		let verified;
		try {
			verified = await verifyRegistration({ response: body.response as any, expectedChallenge: webauthnChallenge, expectedOrigin: origin, expectedRPID: rpID });
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Security key registration failed" }, 400);
		}
		const now = Date.now();
		await repository.insertAccessWebauthnCredential({
			id: randomId("wak"),
			user_id: user.id,
			site_id: site.id,
			rp_id: rpID,
			credential_id: verified.credentialId,
			credential_id_hash: verified.credentialIdHash,
			public_key: verified.publicKey,
			sign_count: verified.signCount,
			transports_json: JSON.stringify(verified.transports),
			aaguid: verified.aaguid,
			device_type: verified.deviceType,
			backed_up: verified.backedUp ? 1 : 0,
			nickname: null,
			created_at: now,
			last_used_at: null,
			updated_at: now,
		});
		consumePendingAccessTwoFactor(session.id);
		const cookies = await issueAccessSession(ctx, site, session, user);
		await recordEvent({
			siteId: site.id,
			sessionId: session.id,
			ip: getClientIp(ctx) ?? "unknown",
			method: "POST",
			path: "/_burrowgate/api/access/login/webauthn/register/verify",
			status: 200,
			decision: "access-authenticated",
			accessUsername: user.username,
			latencyMs: 0,
		});
		return appendSetCookies(jsonResponse({ authenticated: true, username: user.username }), cookies);
	});

	app.post("/_burrowgate/api/access/login/webauthn/authenticate/options", async (ctx) => {
		if (!sameOriginRequest(ctx.req)) return jsonResponse({ error: "Request validation failed" }, 403);
		const resolved = await resolvePendingAccessTwoFactor(ctx, "verify");
		if (!resolved) return jsonResponse({ error: "No pending verification" }, 428);
		const { site, session, user } = resolved;
		const { rpID } = webauthnRelyingParty(ctx.req);
		const credentials = await repository.accessWebauthnCredentialsForUserAndSite(user.id, site.id);
		if (credentials.length === 0) return jsonResponse({ error: "No security key registered" }, 400);
		const options = await buildAuthenticationOptions({
			rpID,
			allowCredentials: credentials.map((credential) => ({
				credentialId: credential.credential_id,
				transports: credential.transports_json ? (JSON.parse(credential.transports_json) as string[]) : [],
			})),
		});
		setPendingAccessWebauthnChallenge(session.id, options.challenge);
		return jsonResponse(options);
	});

	app.post("/_burrowgate/api/access/login/webauthn/authenticate/verify", async (ctx) => {
		if (!sameOriginRequest(ctx.req)) return jsonResponse({ error: "Request validation failed" }, 403);
		const resolved = await resolvePendingAccessTwoFactor(ctx, "verify");
		if (!resolved?.webauthnChallenge) return jsonResponse({ error: "No pending verification" }, 428);
		const { site, session, user, webauthnChallenge } = resolved;
		const retryAfterSeconds = accessTwoFactorRetryAfterSeconds(session.id);
		if (retryAfterSeconds > 0) return jsonResponse({ error: "Too many failed attempts" }, 429, { "retry-after": String(retryAfterSeconds) });
		let body: { response?: { id?: unknown } };
		try {
			body = (await ctx.req.json()) as any;
		} catch {
			return jsonResponse({ error: "Invalid JSON" }, 400);
		}
		const credentialIdHash = await sha256Hex(String(body.response?.id ?? ""));
		const credential = await repository.accessWebauthnCredentialByHashForSite(credentialIdHash, site.id);
		if (!credential || credential.user_id !== user.id) {
			recordAccessTwoFactorFailure(session.id);
			return jsonResponse({ error: "Unknown security key" }, 401);
		}
		const { rpID, origin } = webauthnRelyingParty(ctx.req);
		try {
			const result = await verifyAuthentication({
				response: body.response as any,
				expectedChallenge: webauthnChallenge,
				expectedOrigin: origin,
				expectedRPID: rpID,
				credential: {
					credentialId: credential.credential_id,
					publicKey: credential.public_key,
					signCount: credential.sign_count,
					transports: credential.transports_json ? (JSON.parse(credential.transports_json) as string[]) : [],
				},
			});
			await repository.touchAccessWebauthnCredential(credential.id, result.newCounter, Date.now());
		} catch (error) {
			recordAccessTwoFactorFailure(session.id);
			return jsonResponse({ error: error instanceof Error ? error.message : "Security key verification failed" }, 401);
		}
		clearAccessTwoFactorFailures(session.id);
		consumePendingAccessTwoFactor(session.id);
		const cookies = await issueAccessSession(ctx, site, session, user);
		await recordEvent({
			siteId: site.id,
			sessionId: session.id,
			ip: getClientIp(ctx) ?? "unknown",
			method: "POST",
			path: "/_burrowgate/api/access/login/webauthn/authenticate/verify",
			status: 200,
			decision: "access-authenticated",
			accessUsername: user.username,
			latencyMs: 0,
		});
		return appendSetCookies(jsonResponse({ authenticated: true, username: user.username }), cookies);
	});

	app.post("/_burrowgate/api/access/login", async (ctx) => {
		const started = performance.now();
		if (!sameOriginRequest(ctx.req)) return jsonResponse({ error: "Request validation failed" }, 403);
		const site = ctx.state?.site ?? (await resolveSiteForHost(normalizeHost(requestHost(ctx.req))));
		if (!site) return jsonResponse({ error: "No site configured" }, 421);
		const settings = await accessSettingsForSite(site.id);
		if (settings.enabled !== 1)
			return appendSetCookies(jsonResponse({ authenticated: false, error: "Access authentication is disabled" }, 409), clearAccessIdentityCookies(ctx.req));
		const ip = getClientIp(ctx) ?? "unknown";
		const session = await findAccessSession(ctx.req, site, ip);
		if (!session)
			return appendSetCookies(jsonResponse({ authenticated: false, error: "Complete browser verification first" }, 428), clearAccessIdentityCookies(ctx.req));
		let body: { username?: unknown; password?: unknown };
		try {
			body = (await ctx.req.json()) as any;
		} catch {
			return jsonResponse({ authenticated: false, error: "Invalid JSON" }, 400);
		}
		const result = await authenticateAccessUser(site.id, ip, body.username, body.password);
		if (!result.user) {
			await recordEvent({
				siteId: site.id,
				sessionId: session.id,
				ip,
				method: "POST",
				path: "/_burrowgate/api/access/login",
				status: result.retryAfterSeconds > 0 ? 429 : 401,
				decision: result.retryAfterSeconds > 0 ? "access-login-rate-limited" : "access-login-failed",
				latencyMs: Math.round(performance.now() - started),
			});
			return appendSetCookies(
				jsonResponse(
					{ authenticated: false, error: result.retryAfterSeconds > 0 ? "Too many failed attempts" : "Invalid username or password" },
					result.retryAfterSeconds > 0 ? 429 : 401,
					result.retryAfterSeconds > 0 ? { "retry-after": String(result.retryAfterSeconds) } : undefined,
				),
				clearAccessIdentityCookies(ctx.req),
			);
		}
		if (result.user.totp_required === 1) {
			const mode = await beginAccessTwoFactorChallenge(session.id, site.id, result.user);
			await recordEvent({
				siteId: site.id,
				sessionId: session.id,
				ip,
				method: "POST",
				path: "/_burrowgate/api/access/login",
				status: 200,
				decision: "access-login-required",
				latencyMs: Math.round(performance.now() - started),
			});
			const hasWebauthn = mode === "verify" && (await repository.accessWebauthnCredentialsForUserAndSite(result.user.id, site.id)).length > 0;
			return jsonResponse({
				authenticated: false,
				totpRequired: true,
				mode,
				methods: { totp: mode === "verify" ? result.user.totp_secret_encrypted !== null : false, webauthn: hasWebauthn },
			});
		}
		const cookies = await issueAccessSession(ctx, site, session, result.user);
		await recordEvent({
			siteId: site.id,
			sessionId: session.id,
			ip,
			method: "POST",
			path: "/_burrowgate/api/access/login",
			status: 200,
			decision: "access-authenticated",
			accessUsername: result.user.username,
			latencyMs: Math.round(performance.now() - started),
		});
		const response = jsonResponse({ authenticated: true, username: result.user.username });
		return appendSetCookies(response, cookies);
	});

	app.post("/_burrowgate/api/access/login/enroll", async (ctx) => {
		if (!sameOriginRequest(ctx.req)) return jsonResponse({ error: "Request validation failed" }, 403);
		const resolved = await resolvePendingAccessTwoFactor(ctx, "enroll");
		if (!resolved) return jsonResponse({ authenticated: false, error: "No pending enrollment" }, 428);
		const { site, session, user } = resolved;
		let body: { code?: unknown };
		try {
			body = (await ctx.req.json()) as any;
		} catch {
			body = {};
		}
		let secret = resolved.tentativeSecret;
		if (!secret) {
			secret = generateSecret();
			setPendingAccessTotpSecret(session.id, secret);
		}
		const code = String(body.code ?? "");
		if (!code) {
			const uri = enrollmentUri(user.username, secret, `BurrowGate (${site.name})`);
			return jsonResponse({ authenticated: false, totpRequired: true, mode: "enroll", methods: { totp: true, webauthn: true }, secret, uri });
		}
		if (!(await verifyTotpCode(secret, code))) return jsonResponse({ authenticated: false, error: "Invalid code" }, 401);
		await completeAccessTotpEnrollment(user.id, secret);
		consumePendingAccessTwoFactor(session.id);
		const cookies = await issueAccessSession(ctx, site, session, user);
		await recordEvent({
			siteId: site.id,
			sessionId: session.id,
			ip: getClientIp(ctx) ?? "unknown",
			method: "POST",
			path: "/_burrowgate/api/access/login/enroll",
			status: 200,
			decision: "access-authenticated",
			accessUsername: user.username,
			latencyMs: 0,
		});
		const response = jsonResponse({ authenticated: true, username: user.username });
		return appendSetCookies(response, cookies);
	});

	app.post("/_burrowgate/api/access/login/totp", async (ctx) => {
		if (!sameOriginRequest(ctx.req)) return jsonResponse({ error: "Request validation failed" }, 403);
		const resolved = await resolvePendingAccessTwoFactor(ctx, "verify");
		if (!resolved) return jsonResponse({ authenticated: false, error: "No pending verification" }, 428);
		const { site, session, user } = resolved;
		const retryAfterSeconds = accessTwoFactorRetryAfterSeconds(session.id);
		if (retryAfterSeconds > 0)
			return jsonResponse({ authenticated: false, error: "Too many failed attempts" }, 429, { "retry-after": String(retryAfterSeconds) });
		let body: { code?: unknown };
		try {
			body = (await ctx.req.json()) as any;
		} catch {
			return jsonResponse({ error: "Invalid JSON" }, 400);
		}
		const secret = user.totp_secret_encrypted ? await decryptAccessTotpSecret(user) : null;
		const code = String(body.code ?? "");
		if (!secret || !(await verifyTotpCode(secret, code))) {
			recordAccessTwoFactorFailure(session.id);
			return jsonResponse({ authenticated: false, error: "Invalid code" }, 401);
		}
		clearAccessTwoFactorFailures(session.id);
		consumePendingAccessTwoFactor(session.id);
		const cookies = await issueAccessSession(ctx, site, session, user);
		await recordEvent({
			siteId: site.id,
			sessionId: session.id,
			ip: getClientIp(ctx) ?? "unknown",
			method: "POST",
			path: "/_burrowgate/api/access/login/totp",
			status: 200,
			decision: "access-authenticated",
			accessUsername: user.username,
			latencyMs: 0,
		});
		const response = jsonResponse({ authenticated: true, username: user.username });
		return appendSetCookies(response, cookies);
	});
}
