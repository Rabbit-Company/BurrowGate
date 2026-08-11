import { getClientIp } from "@rabbit-company/web-middleware/ip-extract";
import type { Web } from "@rabbit-company/web";
import { repository } from "../db/repository.ts";
import {
	accessIdentitySetCookies,
	accessSettingsForSite,
	accessTotpRetryAfterSeconds,
	authenticateAccessUser,
	authenticatedAccessUser,
	beginAccessTotpChallenge,
	clearAccessIdentityCookies,
	clearAccessTotpFailures,
	completeAccessTotpEnrollment,
	consumePendingAccessTotp,
	decryptAccessTotpSecret,
	pendingAccessTotp,
	recordAccessTotpFailure,
	setPendingAccessTotpSecret,
} from "../services/access-list-service.ts";
import { beginAccessSsoLogin, completeAccessSsoLogin, handleAccessBackchannelLogout, siteSsoLoginInfo } from "../services/access-sso-service.ts";
import { createFlow } from "../services/challenge-service.ts";
import { recordEvent } from "../services/event-service.ts";
import { findAccessSession, userAgentHash } from "../services/session-service.ts";
import { resolveSiteForHost } from "../services/site-service.ts";
import { enrollmentUri, generateSecret, qrSvg, verifyCode as verifyTotpCode } from "../services/totp-service.ts";
import type { AccessSessionRecord, AccessUserRecord, SiteRecord } from "../types.ts";
import { accessLoginPage, accessTotpEnrollPage, accessTotpVerifyPage } from "../ui/access-login-page.ts";
import { appendSetCookies, htmlResponse, jsonResponse, normalizeHost, requestHost, safeReturnPath, sameOriginRequest } from "../utils/http.ts";

function loginPath(returnPath: string): string {
	return `/_burrowgate/access/login?return=${encodeURIComponent(returnPath)}`;
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

interface ResolvedPendingTotp {
	site: SiteRecord;
	session: AccessSessionRecord;
	user: AccessUserRecord;
	tentativeSecret: string | null;
}

async function resolvePendingAccessTotp(ctx: any, mode: "totp-enroll" | "totp-verify"): Promise<ResolvedPendingTotp | null> {
	const site = ctx.state?.site ?? (await resolveSiteForHost(normalizeHost(requestHost(ctx.req))));
	if (!site) return null;
	const ip = getClientIp(ctx) ?? "unknown";
	const session = await findAccessSession(ctx.req, site, ip);
	if (!session) return null;
	const entry = pendingAccessTotp(session.id, mode);
	if (!entry) return null;
	const user = await repository.accessUserForSite(site.id, entry.userId);
	if (!user) return null;
	return { site, session, user, tentativeSecret: entry.tentativeSecret };
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
			const mode = beginAccessTotpChallenge(session.id, result.user);
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
			const target = mode === "totp-enroll" ? "/_burrowgate/access/login/enroll" : "/_burrowgate/access/login/totp";
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
		const resolved = await resolvePendingAccessTotp(ctx, "totp-enroll");
		if (!resolved) return Response.redirect(new URL(loginPath(returnPath), ctx.req.url).href, 302);
		const { site, session, user } = resolved;
		let secret = resolved.tentativeSecret;
		if (!secret) {
			secret = generateSecret();
			setPendingAccessTotpSecret(session.id, secret);
		}
		const uri = enrollmentUri(user.username, secret, `BurrowGate (${site.name})`);
		return htmlResponse(accessTotpEnrollPage(site, uri, secret, await qrSvg(uri), returnPath));
	});

	app.post("/_burrowgate/access/login/enroll", async (ctx) => {
		const form = await ctx.req.formData();
		const returnPath = safeReturnPath(String(form.get("return") ?? "/"));
		if (!sameOriginRequest(ctx.req)) return htmlResponse("Request validation failed.", 403);
		const resolved = await resolvePendingAccessTotp(ctx, "totp-enroll");
		if (!resolved?.tentativeSecret) return Response.redirect(new URL(loginPath(returnPath), ctx.req.url).href, 302);
		const { site, session, user, tentativeSecret: secret } = resolved;
		const code = String(form.get("code") ?? "");
		if (!secret || !(await verifyTotpCode(secret, code))) {
			const uri = enrollmentUri(user.username, secret ?? "", `BurrowGate (${site.name})`);
			return htmlResponse(accessTotpEnrollPage(site, uri, secret ?? "", await qrSvg(uri), returnPath, "Invalid code, try again"), 401);
		}
		await completeAccessTotpEnrollment(user.id, secret);
		consumePendingAccessTotp(session.id);
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

	app.get("/_burrowgate/access/login/totp", async (ctx) => {
		const returnPath = safeReturnPath(new URL(ctx.req.url).searchParams.get("return"));
		const resolved = await resolvePendingAccessTotp(ctx, "totp-verify");
		if (!resolved) return Response.redirect(new URL(loginPath(returnPath), ctx.req.url).href, 302);
		return htmlResponse(accessTotpVerifyPage(resolved.site, returnPath));
	});

	app.post("/_burrowgate/access/login/totp", async (ctx) => {
		const form = await ctx.req.formData();
		const returnPath = safeReturnPath(String(form.get("return") ?? "/"));
		if (!sameOriginRequest(ctx.req)) return htmlResponse("Request validation failed.", 403);
		const resolved = await resolvePendingAccessTotp(ctx, "totp-verify");
		if (!resolved) return Response.redirect(new URL(loginPath(returnPath), ctx.req.url).href, 302);
		const { site, session, user } = resolved;
		const retryAfterSeconds = accessTotpRetryAfterSeconds(session.id);
		if (retryAfterSeconds > 0) return htmlResponse(accessTotpVerifyPage(site, returnPath, "Too many failed attempts. Try again later."), 429);
		const secret = await decryptAccessTotpSecret(user);
		const code = String(form.get("code") ?? "");
		if (!secret || !(await verifyTotpCode(secret, code))) {
			recordAccessTotpFailure(session.id);
			return htmlResponse(accessTotpVerifyPage(site, returnPath, "Invalid code"), 401);
		}
		clearAccessTotpFailures(session.id);
		consumePendingAccessTotp(session.id);
		const cookies = await issueAccessSession(ctx, site, session, user);
		await recordEvent({
			siteId: site.id,
			sessionId: session.id,
			ip: getClientIp(ctx) ?? "unknown",
			method: "POST",
			path: "/_burrowgate/access/login/totp",
			status: 302,
			decision: "access-authenticated",
			accessUsername: user.username,
			latencyMs: 0,
		});
		return appendSetCookies(Response.redirect(new URL(returnPath, ctx.req.url).href, 302), cookies);
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
			const mode = beginAccessTotpChallenge(session.id, result.user);
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
			return jsonResponse({ authenticated: false, totpRequired: true, mode });
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
		const resolved = await resolvePendingAccessTotp(ctx, "totp-enroll");
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
			return jsonResponse({ authenticated: false, totpRequired: true, mode: "totp-enroll", secret, uri });
		}
		if (!(await verifyTotpCode(secret, code))) return jsonResponse({ authenticated: false, error: "Invalid code" }, 401);
		await completeAccessTotpEnrollment(user.id, secret);
		consumePendingAccessTotp(session.id);
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
		const resolved = await resolvePendingAccessTotp(ctx, "totp-verify");
		if (!resolved) return jsonResponse({ authenticated: false, error: "No pending verification" }, 428);
		const { site, session, user } = resolved;
		const retryAfterSeconds = accessTotpRetryAfterSeconds(session.id);
		if (retryAfterSeconds > 0)
			return jsonResponse({ authenticated: false, error: "Too many failed attempts" }, 429, { "retry-after": String(retryAfterSeconds) });
		let body: { code?: unknown };
		try {
			body = (await ctx.req.json()) as any;
		} catch {
			return jsonResponse({ error: "Invalid JSON" }, 400);
		}
		const secret = await decryptAccessTotpSecret(user);
		const code = String(body.code ?? "");
		if (!secret || !(await verifyTotpCode(secret, code))) {
			recordAccessTotpFailure(session.id);
			return jsonResponse({ authenticated: false, error: "Invalid code" }, 401);
		}
		clearAccessTotpFailures(session.id);
		consumePendingAccessTotp(session.id);
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
