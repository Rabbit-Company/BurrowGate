import { getClientIp } from "@rabbit-company/web-middleware/ip-extract";
import type { Web } from "@rabbit-company/web";
import { repository } from "../db/repository.ts";
import {
	accessIdentitySetCookies,
	accessSettingsForSite,
	authenticateAccessUser,
	authenticatedAccessUser,
	clearAccessIdentityCookies,
} from "../services/access-list-service.ts";
import { createFlow } from "../services/challenge-service.ts";
import { recordEvent } from "../services/event-service.ts";
import { findAccessSession, userAgentHash } from "../services/session-service.ts";
import { resolveSiteForHost } from "../services/site-service.ts";
import { accessLoginPage } from "../ui/access-login-page.ts";
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
		return appendSetCookies(htmlResponse(accessLoginPage(site, returnPath)), clearAccessIdentityCookies(ctx.req));
	});

	app.post("/_burrowgate/access/login", async (ctx) => {
		const started = performance.now();
		const form = await ctx.req.formData();
		const returnPath = safeReturnPath(String(form.get("return") ?? "/"));
		const site = ctx.state?.site ?? (await resolveSiteForHost(normalizeHost(requestHost(ctx.req))));
		if (!site) return htmlResponse("No BurrowGate site is configured for this host.", 421);
		if (!sameOriginRequest(ctx.req)) return htmlResponse(accessLoginPage(site, returnPath, "Request validation failed."), 403);
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
					),
					limited ? 429 : 401,
					limited ? { "retry-after": String(result.retryAfterSeconds) } : undefined,
				),
				clearAccessIdentityCookies(ctx.req),
			);
		}
		await repository.authenticateSession(session.id, site.id, result.user.id, Date.now());
		await recordEvent({
			siteId: site.id,
			sessionId: session.id,
			ip,
			method: "POST",
			path: "/_burrowgate/access/login",
			status: 302,
			decision: "access-authenticated",
			latencyMs: Math.round(performance.now() - started),
		});
		const cookies =
			settings.send_username_to_upstream === 1
				? await accessIdentitySetCookies(ctx.req, site, session, result.user.username)
				: clearAccessIdentityCookies(ctx.req);
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
		await repository.authenticateSession(session.id, site.id, result.user.id, Date.now());
		await recordEvent({
			siteId: site.id,
			sessionId: session.id,
			ip,
			method: "POST",
			path: "/_burrowgate/api/access/login",
			status: 200,
			decision: "access-authenticated",
			latencyMs: Math.round(performance.now() - started),
		});
		const response = jsonResponse({ authenticated: true, username: result.user.username });
		const cookies =
			settings.send_username_to_upstream === 1
				? await accessIdentitySetCookies(ctx.req, site, session, result.user.username)
				: clearAccessIdentityCookies(ctx.req);
		return appendSetCookies(response, cookies);
	});
}
