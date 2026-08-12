import type { Web } from "@rabbit-company/web";
import { getClientIp } from "@rabbit-company/web-middleware/ip-extract";
import { challengeRegistry } from "../challenges/index.ts";
import {
	adminCookieName,
	adminCookieNames,
	config,
	cookieCanBeIssuedForRequest,
	insecureCookieConfigurationMessage,
	secureCookieForRequest,
} from "../config.ts";
import { repository, type SortDirection, type TabMetricsScope } from "../db/repository.ts";
import { addCountryRule, addIpRule, invalidateNetworkPolicy } from "../services/ip-rule-service.ts";
import {
	authenticateAdminPassword,
	beginPendingLogin,
	clearPendingLoginCookie,
	clearTotpFailures,
	consumePendingLogin,
	pendingLoginCookie,
	recordTotpFailure,
	resolvePendingLogin,
	setPendingLoginSecret,
	totpAttemptRetryAfterSeconds,
} from "../services/admin-auth-service.ts";
import { decryptSecret, encryptSecret } from "../services/secret-encryption-service.ts";
import { enrollmentUri, generateRecoveryCodes, generateSecret, normalizeRecoveryCode, qrSvg, verifyCode as verifyTotpCode } from "../services/totp-service.ts";
import { adminSessionTokens, createAdminSession, getAdminSession } from "../services/session-service.ts";
import { createSite, parseDefaultNetworkAction, siteView, updateSite, type SiteInput } from "../services/site-service.ts";
import {
	createRoutePolicy,
	deleteRoutePolicy,
	invalidateDeletedSiteRoutePolicies,
	routePolicyView,
	updateRoutePolicy,
	type RoutePolicyInput,
} from "../services/route-policy-service.ts";
import { invalidateRouteRateLimiter } from "../services/rate-limit-service.ts";
import { issueLetsEncryptCertificate, siteCertificateIssuanceActive } from "../services/acme-service.ts";
import { recordCertificateEvent, saveCertificate, tlsView, updateTlsSettings } from "../services/certificate-service.ts";
import { geoIpStatus } from "../services/geoip-service.ts";
import {
	DEFAULT_ERROR_HTML_TEMPLATE,
	DEFAULT_ERROR_JSON_FIELDS,
	ERROR_JSON_FIELD_OPTIONS,
	ERROR_TEMPLATE_PLACEHOLDERS,
} from "../services/error-response-service.ts";
import { DEFAULT_CHALLENGE_HTML_TEMPLATE, CHALLENGE_TEMPLATE_PLACEHOLDERS } from "../services/challenge-page-service.ts";
import { requestTlsReload } from "../services/tls-listener-service.ts";
import {
	accessListView,
	createAccessUser,
	generateAccessUserApiToken,
	importAccessUsers,
	invalidateAccessSite,
	removeAccessUser,
	resetAccessUserTotp,
	revokeAccessUserApiToken,
	setAccessUserTotpRequired,
	updateAccessSettings,
	updateAccessUser,
} from "../services/access-list-service.ts";
import { siteSsoSettingsView, updateSiteSsoSettings } from "../services/access-sso-service.ts";
import type { DefaultNetworkAction, IpRuleAction, SiteRecord } from "../types.ts";
import { adminPage, loginPage, totpEnrollPage, totpRecoveryCodesPage, totpVerifyPage } from "../ui/admin-page.ts";
import { serializeCookie } from "../utils/cookies.ts";
import { randomId, sha256Hex } from "../utils/crypto.ts";
import { appendSetCookies, htmlResponse, jsonResponse, sameOriginRequest } from "../utils/http.ts";
import { blockSiteBandwidth, flushBandwidthMetrics, resumeSiteBandwidth } from "../services/bandwidth-service.ts";
import { blockSiteEvents, resumeSiteEvents } from "../services/event-service.ts";
import { originHealthManager } from "../services/origin-health-service.ts";
import { loadBalancer } from "../services/load-balancer-service.ts";
import { createOrigin, deleteOrigin, originView, updateOrigin, type OriginInput } from "../services/origin-pool-service.ts";
import { instanceWebSocketDefaults } from "../services/websocket-policy-service.ts";
import { staticAssetCache } from "../services/static-cache-service.ts";
import { instanceStaticCacheDefaults } from "../services/http-policy-service.ts";
import { managedRuleSetCatalog } from "../services/managed-protection-service.ts";
import {
	isAdministrator,
	requireAdministrator,
	requireLevel,
	resolveAdminUser,
	siteAccessLevel,
	type AuthenticatedAdmin,
} from "../services/admin-permission-service.ts";
import {
	adminUserView,
	changeOwnPassword,
	createAdminUser,
	deleteAdminUser,
	listAdminUsers,
	regenerateOwnRecoveryCodes,
	resetAdminUserPassword,
	resetAdminUserTotp,
	updateAdminUser,
} from "../services/admin-user-service.ts";
import { pagedAdminAuditLog, purgeAdminAuditLog, recordAdminAudit } from "../services/admin-audit-service.ts";
import {
	adminSsoLoginInfo,
	adminSsoSettingsView,
	beginAdminSsoLogin,
	completeAdminSsoLogin,
	handleAdminBackchannelLogout,
	updateAdminSsoSettings,
} from "../services/admin-sso-service.ts";

async function guard(request: Request): Promise<Response | { user: AuthenticatedAdmin }> {
	const session = await getAdminSession(request);
	const user = session ? await resolveAdminUser(session) : null;
	return user ? { user } : jsonResponse({ error: "Unauthorized" }, 401);
}

function mutationGuard(request: Request): Response | null {
	if (!sameOriginRequest(request) || request.headers.get("x-burrowgate-admin") !== "1") {
		return jsonResponse({ error: "CSRF validation failed" }, 403);
	}
	return null;
}

function integerParam(url: URL, name: string, fallback: number, minimum: number, maximum: number): number {
	const value = Number(url.searchParams.get(name));
	if (!Number.isInteger(value)) return fallback;
	return Math.min(maximum, Math.max(minimum, value));
}

function stringParam(url: URL, name: string): string | undefined {
	const value = url.searchParams.get(name)?.trim();
	return value || undefined;
}

function numberParam(url: URL, name: string): number | undefined {
	const value = Number(url.searchParams.get(name));
	return Number.isFinite(value) && url.searchParams.has(name) ? value : undefined;
}

function enumParam<T extends string>(url: URL, name: string, allowed: readonly T[], fallback?: T): T | undefined {
	const value = url.searchParams.get(name) as T | null;
	return value && allowed.includes(value) ? value : fallback;
}

function sortDirection(url: URL): SortDirection {
	return url.searchParams.get("sortDirection") === "asc" ? "asc" : "desc";
}

function protectionMatches(value: string | null): unknown[] {
	if (!value) return [];
	try {
		const parsed = JSON.parse(value) as unknown;
		return Array.isArray(parsed) ? parsed : [];
	} catch {
		return [];
	}
}

const NO_ACCESS_SITE_ID = "__no-accessible-site__";

function metricsScopeSiteId(selection: { site: SiteRecord | null }, user: AuthenticatedAdmin): string | undefined {
	if (selection.site) return selection.site.id;
	return isAdministrator(user) ? undefined : NO_ACCESS_SITE_ID;
}

const TAB_METRICS_SCOPES: TabMetricsScope[] = ["requests", "blocked", "protection", "cache", "access", "routes", "sites", "bandwidth", "sessions"];

function tabMetricsScopeParam(url: URL): TabMetricsScope | null {
	const value = stringParam(url, "scope");
	return (TAB_METRICS_SCOPES as string[]).includes(value ?? "") ? (value as TabMetricsScope) : null;
}

async function tabScopeSiteIds(user: AuthenticatedAdmin): Promise<string[] | undefined> {
	if (isAdministrator(user)) return undefined;
	const sites = await sitesVisibleToUser(user);
	return sites.map((site) => site.id);
}

const DEFAULT_DATE_RANGE_MS = 24 * 3_600_000;
const MIN_DATE_RANGE_MS = 60_000;
const MAX_DATE_RANGE_MS = 366 * 24 * 3_600_000;
const METRIC_BUCKETS_MS = [
	60_000, 300_000, 900_000, 1_800_000, 3_600_000, 7_200_000, 10_800_000, 21_600_000, 43_200_000, 86_400_000, 172_800_000, 345_600_000, 604_800_000,
] as const;

function requestedDateRange(url: URL): { since: number; until: number; durationMs: number } {
	const now = Date.now();
	const rawUntil = Number(url.searchParams.get("to"));
	const rawSince = Number(url.searchParams.get("from"));
	let until = Number.isFinite(rawUntil) && rawUntil > 0 ? Math.min(rawUntil, now + 300_000) : now;
	let since = Number.isFinite(rawSince) && rawSince >= 0 ? rawSince : until - DEFAULT_DATE_RANGE_MS;
	if (until - since < MIN_DATE_RANGE_MS) since = until - MIN_DATE_RANGE_MS;
	if (until - since > MAX_DATE_RANGE_MS) since = until - MAX_DATE_RANGE_MS;
	if (since < 0) since = 0;
	return { since, until, durationMs: until - since };
}

function metricBucketSize(durationMs: number): number {
	const minimum = Math.max(60_000, Math.ceil(durationMs / 120));
	return METRIC_BUCKETS_MS.find((candidate) => candidate >= minimum) ?? 604_800_000;
}

async function sitesVisibleToUser(user: AuthenticatedAdmin): Promise<SiteRecord[]> {
	return isAdministrator(user) ? repository.allSites() : repository.adminSitesForUser(user.id);
}

async function selectedSite(url: URL, user: AuthenticatedAdmin): Promise<{ site: SiteRecord | null; error: Response | null }> {
	const requestedId = stringParam(url, "siteId");
	if (!requestedId) return { site: (await sitesVisibleToUser(user))[0] ?? null, error: null };
	const site = await repository.siteById(requestedId);
	if (!site) return { site: null, error: jsonResponse({ error: "Selected site was not found" }, 404) };
	if ((await siteAccessLevel(user, site.id)) === "none") return { site: null, error: jsonResponse({ error: "Forbidden" }, 403) };
	return { site, error: null };
}

async function requireSiteAccess(id: string, user: AuthenticatedAdmin, need: "view" | "manage"): Promise<{ site: SiteRecord } | { error: Response }> {
	const site = await repository.siteById(id);
	if (!site) return { error: jsonResponse({ error: "Site not found" }, 404) };
	const denied = requireLevel(await siteAccessLevel(user, site.id), need);
	if (denied) return { error: denied };
	return { site };
}

function providerViews() {
	return challengeRegistry.names().map((name) => {
		const provider = challengeRegistry.get(name);
		return { name: provider.name, title: provider.title, description: provider.description };
	});
}

async function parseSiteInput(request: Request): Promise<SiteInput> {
	const body = await request.json();
	if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("Site payload must be an object");
	return body as SiteInput;
}

async function parseRoutePolicyInput(request: Request): Promise<RoutePolicyInput> {
	const body = await request.json();
	if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("Route policy payload must be an object");
	return body as RoutePolicyInput;
}

async function parseOriginInput(request: Request): Promise<OriginInput> {
	const body = await request.json();
	if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("Origin payload must be an object");
	return body as OriginInput;
}

export function registerAdminRoutes(app: Web<any>): void {
	app.get("/_burrowgate/admin/login", async (ctx) =>
		(await getAdminSession(ctx.req))
			? Response.redirect(new URL("/_burrowgate/admin", ctx.req.url).href, 302)
			: htmlResponse(loginPage(cookieCanBeIssuedForRequest(ctx.req) ? undefined : insecureCookieConfigurationMessage(), await adminSsoLoginInfo())),
	);

	app.post("/_burrowgate/admin/login", async (ctx) => {
		const form = await ctx.req.formData();
		const username = String(form.get("username") ?? "");
		const password = String(form.get("password") ?? "");
		const ip = getClientIp(ctx) ?? "unknown";
		const { user, retryAfterSeconds } = await authenticateAdminPassword(ip, username, password);
		if (retryAfterSeconds > 0) return htmlResponse(loginPage("Too many failed attempts. Try again later.", await adminSsoLoginInfo()), 429);
		if (!user) return htmlResponse(loginPage("Invalid username or password", await adminSsoLoginInfo()), 401);
		if (!cookieCanBeIssuedForRequest(ctx.req)) {
			return htmlResponse(loginPage(insecureCookieConfigurationMessage(), await adminSsoLoginInfo()), 409);
		}
		const mode = user.must_enroll_totp === 1 ? "totp-enroll" : "totp-verify";
		const token = beginPendingLogin(mode, user.id);
		const location = mode === "totp-enroll" ? "/_burrowgate/admin/login/enroll" : "/_burrowgate/admin/login/totp";
		return new Response(null, { status: 302, headers: { location, "set-cookie": pendingLoginCookie(ctx.req, token) } });
	});

	app.get("/_burrowgate/admin/login/sso", async (ctx) => {
		if (await getAdminSession(ctx.req)) return Response.redirect(new URL("/_burrowgate/admin", ctx.req.url).href, 302);
		if (!cookieCanBeIssuedForRequest(ctx.req)) return htmlResponse(loginPage(insecureCookieConfigurationMessage(), await adminSsoLoginInfo()), 409);
		try {
			const redirectUri = new URL("/_burrowgate/admin/sso/callback", ctx.req.url).href;
			const url = await beginAdminSsoLogin(redirectUri);
			return Response.redirect(url, 302);
		} catch (error) {
			return htmlResponse(loginPage(error instanceof Error ? error.message : "Unable to start single sign-on", await adminSsoLoginInfo()), 400);
		}
	});

	app.get("/_burrowgate/admin/sso/callback", async (ctx) => {
		const url = new URL(ctx.req.url);
		const code = url.searchParams.get("code") ?? "";
		const state = url.searchParams.get("state") ?? "";
		const idpError = url.searchParams.get("error");
		if (idpError || !code || !state) {
			return htmlResponse(loginPage("Single sign-on was cancelled or failed.", await adminSsoLoginInfo()), 400);
		}
		if (!cookieCanBeIssuedForRequest(ctx.req)) return htmlResponse(loginPage(insecureCookieConfigurationMessage(), await adminSsoLoginInfo()), 409);
		try {
			const { user, provisioned, sid } = await completeAdminSsoLogin(code, state);
			const session = await createAdminSession(ctx.req, user.username, user.id, sid);
			const actor: AuthenticatedAdmin = { id: user.id, username: user.username, role: user.role };
			await recordAdminAudit({
				actor,
				action: provisioned ? "admin_user.sso_provisioned" : "admin_user.sso_login",
				resourceType: "admin_user",
				resourceId: user.id,
				summary: provisioned ? `Provisioned user ${user.username} via single sign-on` : `Signed in via single sign-on as ${user.username}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return appendSetCookies(new Response(null, { status: 302, headers: { location: "/_burrowgate/admin" } }), [session.cookie]);
		} catch (error) {
			return htmlResponse(loginPage(error instanceof Error ? error.message : "Single sign-on failed.", await adminSsoLoginInfo()), 400);
		}
	});

	app.get("/_burrowgate/admin/login/enroll", async (ctx) => {
		const loginUrl = new URL("/_burrowgate/admin/login", ctx.req.url).href;
		const pending = resolvePendingLogin(ctx.req, "totp-enroll");
		if (!pending) return Response.redirect(loginUrl, 302);
		const user = await repository.adminUserById(pending.entry.userId);
		if (!user) return Response.redirect(loginUrl, 302);
		let secret = pending.entry.tentativeSecret;
		if (!secret) {
			secret = generateSecret();
			setPendingLoginSecret(pending.token, secret);
		}
		const uri = enrollmentUri(user.username, secret);
		return htmlResponse(totpEnrollPage(uri, secret, await qrSvg(uri)));
	});

	app.post("/_burrowgate/admin/login/enroll", async (ctx) => {
		const loginUrl = new URL("/_burrowgate/admin/login", ctx.req.url).href;
		const pending = resolvePendingLogin(ctx.req, "totp-enroll");
		const secret = pending?.entry.tentativeSecret;
		if (!pending || !secret) return Response.redirect(loginUrl, 302);
		const user = await repository.adminUserById(pending.entry.userId);
		if (!user) return Response.redirect(loginUrl, 302);
		const form = await ctx.req.formData();
		const code = String(form.get("code") ?? "");
		const uri = enrollmentUri(user.username, secret);
		if (!(await verifyTotpCode(secret, code))) {
			return htmlResponse(totpEnrollPage(uri, secret, await qrSvg(uri), "Invalid code, try again"), 401);
		}
		const now = Date.now();
		await repository.updateAdminUser({
			...user,
			totp_secret_encrypted: await encryptSecret(secret),
			totp_enrolled_at: now,
			must_enroll_totp: 0,
			updated_at: now,
		});
		const recoveryCodes = await generateRecoveryCodes();
		await repository.replaceAdminRecoveryCodes(
			user.id,
			recoveryCodes.map((recoveryCode) => ({ id: randomId("rc"), user_id: user.id, code_hash: recoveryCode.hash, created_at: now, used_at: null })),
		);
		consumePendingLogin(pending.token);
		const session = await createAdminSession(ctx.req, user.username, user.id);
		return appendSetCookies(htmlResponse(totpRecoveryCodesPage(recoveryCodes.map((recoveryCode) => recoveryCode.plaintext))), [
			session.cookie,
			clearPendingLoginCookie(ctx.req),
		]);
	});

	app.get("/_burrowgate/admin/login/totp", async (ctx) => {
		const pending = resolvePendingLogin(ctx.req, "totp-verify");
		if (!pending) return Response.redirect(new URL("/_burrowgate/admin/login", ctx.req.url).href, 302);
		return htmlResponse(totpVerifyPage());
	});

	app.post("/_burrowgate/admin/login/totp", async (ctx) => {
		const loginUrl = new URL("/_burrowgate/admin/login", ctx.req.url).href;
		const pending = resolvePendingLogin(ctx.req, "totp-verify");
		if (!pending) return Response.redirect(loginUrl, 302);
		const user = await repository.adminUserById(pending.entry.userId);
		if (!user || !user.totp_secret_encrypted) return Response.redirect(loginUrl, 302);
		const retryAfterSeconds = totpAttemptRetryAfterSeconds(pending.token);
		if (retryAfterSeconds > 0) return htmlResponse(totpVerifyPage("Too many failed attempts. Try again later."), 429);
		const form = await ctx.req.formData();
		const code = String(form.get("code") ?? "").trim();
		const recoveryCodeInput = form.get("recoveryCode");
		let valid = false;
		if (recoveryCodeInput) {
			const hash = await sha256Hex(normalizeRecoveryCode(recoveryCodeInput));
			valid = await repository.consumeAdminRecoveryCodeByHash(user.id, hash, Date.now());
		} else if (code) {
			valid = await verifyTotpCode(await decryptSecret(user.totp_secret_encrypted), code);
		}
		if (!valid) {
			recordTotpFailure(pending.token);
			return htmlResponse(totpVerifyPage("Invalid code"), 401);
		}
		clearTotpFailures(pending.token);
		consumePendingLogin(pending.token);
		const session = await createAdminSession(ctx.req, user.username, user.id);
		return appendSetCookies(new Response(null, { status: 302, headers: { location: "/_burrowgate/admin" } }), [
			session.cookie,
			clearPendingLoginCookie(ctx.req),
		]);
	});

	app.post("/_burrowgate/admin/sso/backchannel-logout", async (ctx) => {
		try {
			const form = await ctx.req.formData();
			const logoutToken = String(form.get("logout_token") ?? "");
			if (!logoutToken) return jsonResponse({ error: "invalid_request", error_description: "logout_token is required" }, 400);
			await handleAdminBackchannelLogout(logoutToken);
			return new Response(null, { status: 200 });
		} catch (error) {
			return jsonResponse({ error: "invalid_request", error_description: error instanceof Error ? error.message : "Unable to process logout token" }, 400);
		}
	});

	app.get("/_burrowgate/admin", async (ctx) =>
		(await getAdminSession(ctx.req)) ? htmlResponse(adminPage()) : Response.redirect(new URL("/_burrowgate/admin/login", ctx.req.url).href, 302),
	);

	app.get(
		"/_burrowgate/static/chart.umd.js",
		() =>
			new Response(Bun.file("node_modules/chart.js/dist/chart.umd.js"), {
				headers: { "content-type": "text/javascript; charset=utf-8", "cache-control": "public, max-age=86400" },
			}),
	);

	app.get(
		"/_burrowgate/static/admin.js",
		() =>
			new Response(Bun.file("public/admin.js"), {
				headers: { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-store" },
			}),
	);

	app.get("/_burrowgate/static/world.svg", (ctx) => {
		const accepted = ctx.req.headers.get("accept-encoding") ?? "";
		const encoding = accepted.includes("br") ? "br" : accepted.includes("gzip") ? "gzip" : null;
		const file = encoding === "br" ? "public/world.svg.br" : encoding === "gzip" ? "public/world.svg.gz" : "public/world.svg";
		const headers: Record<string, string> = {
			"content-type": "image/svg+xml; charset=utf-8",
			"cache-control": "public, max-age=2592000, immutable",
			vary: "Accept-Encoding",
		};
		if (encoding) headers["content-encoding"] = encoding;
		return new Response(Bun.file(file), { headers });
	});

	app.get("/_burrowgate/api/admin/sites", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		return jsonResponse({
			items: (await sitesVisibleToUser(user)).map((site) => ({ ...siteView(site), originHealth: originHealthManager.summary(site.id) })),
			challengeProviders: providerViews(),
			defaultEventRetentionDays: config.eventRetentionDays,
			websocketDefaults: instanceWebSocketDefaults(),
			httpCacheDefaults: instanceStaticCacheDefaults(),
			managedProtection: managedRuleSetCatalog(),
			errorResponseDefaults: {
				mode: "json",
				htmlTemplate: DEFAULT_ERROR_HTML_TEMPLATE,
				jsonFields: DEFAULT_ERROR_JSON_FIELDS,
				jsonFieldOptions: ERROR_JSON_FIELD_OPTIONS,
				placeholders: ERROR_TEMPLATE_PLACEHOLDERS,
			},
			challengeDefaults: {
				htmlTemplate: DEFAULT_CHALLENGE_HTML_TEMPLATE,
				placeholders: CHALLENGE_TEMPLATE_PLACEHOLDERS,
			},
		});
	});

	app.post("/_burrowgate/api/admin/sites", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const forbidden = requireAdministrator(user);
		if (forbidden) return forbidden;
		try {
			const created = await createSite(await parseSiteInput(ctx.req));
			await loadBalancer.refreshSite(created.site.id);
			await originHealthManager.refreshSite(created.site.id);
			await recordAdminAudit({
				actor: user,
				action: "site.create",
				resourceType: "site",
				resourceId: created.site.id,
				summary: `Created site ${created.site.name}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse(
				{
					site: siteView(created.site),
					generatedSigningSecret: created.generatedSigningSecret,
				},
				201,
			);
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to create site" }, 400);
		}
	});

	app.addRoute("PUT", "/_burrowgate/api/admin/sites/:id", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const denied = requireLevel(await siteAccessLevel(user, ctx.params.id), "manage");
		if (denied) return denied;
		try {
			const site = await updateSite(ctx.params.id, await parseSiteInput(ctx.req));
			await loadBalancer.refreshSite(site.id);
			await originHealthManager.refreshSite(site.id);
			await requestTlsReload();
			await recordAdminAudit({
				actor: user,
				action: "site.update",
				resourceType: "site",
				resourceId: site.id,
				summary: `Updated site ${site.name}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse({ site: siteView(site) });
		} catch (error) {
			const message = error instanceof Error ? error.message : "Unable to update site";
			return jsonResponse({ error: message }, message === "Site not found" ? 404 : 400);
		}
	});

	app.delete("/_burrowgate/api/admin/sites/:id", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const forbidden = requireAdministrator(user);
		if (forbidden) return forbidden;
		const site = await repository.siteById(ctx.params.id);
		if (!site) return jsonResponse({ error: "Site not found" }, 404);
		if (siteCertificateIssuanceActive(site.id))
			return jsonResponse({ error: "Wait for the active certificate issuance to finish before deleting this site." }, 409);
		const certificate = await repository.certificateBySite(site.id);
		if (certificate) {
			const dependentStreams = await repository.streamsUsingCertificate(certificate.id);
			if (dependentStreams.length > 0) {
				const ports = dependentStreams.map((stream) => stream.incoming_port).join(", ");
				return jsonResponse(
					{
						error: `This site's TLS certificate is used by Stream port${dependentStreams.length === 1 ? "" : "s"} ${ports}. Change or remove that certificate from the Stream before deleting the site.`,
					},
					409,
				);
			}
		}
		const policies = await repository.routePolicies(site.id);
		await flushBandwidthMetrics();
		blockSiteBandwidth(site.id);
		blockSiteEvents(site.id);
		try {
			await repository.deleteSiteCascade(site.id);
		} catch (error) {
			resumeSiteBandwidth(site.id);
			resumeSiteEvents(site.id);
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to delete site" }, 500);
		}
		invalidateNetworkPolicy(site.id);
		invalidateAccessSite(site.id);
		invalidateDeletedSiteRoutePolicies(
			site.id,
			policies.map((policy) => policy.path_pattern),
		);
		for (const policy of policies) invalidateRouteRateLimiter(policy.id);
		loadBalancer.removeSite(site.id);
		originHealthManager.removeSite(site.id);
		staticAssetCache.removeSite(site.id);
		const tlsReload = await Promise.allSettled([requestTlsReload()]);
		const warning =
			tlsReload[0]?.status === "rejected" ? "The site was deleted, but TLS listener reload failed. Restart BurrowGate to refresh active certificates." : null;
		await recordAdminAudit({
			actor: user,
			action: "site.delete",
			resourceType: "site",
			resourceId: site.id,
			summary: `Deleted site ${site.name}`,
			ip: getClientIp(ctx) ?? "unknown",
		});
		return jsonResponse({ deleted: true, warning });
	});

	app.get("/_burrowgate/api/admin/sites/:id/health", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const access = await requireSiteAccess(ctx.params.id, user, "view");
		if ("error" in access) return access.error;
		const { site } = access;
		const originNames = new Map((await repository.originsForSite(site.id)).map((origin) => [origin.id, origin.name]));
		const limit = integerParam(new URL(ctx.req.url), "limit", 100, 1, 200);
		return jsonResponse({
			status: originHealthManager.summary(site.id),
			events: await originHealthManager.events(site.id, Math.min(50, limit)),
			backendEvents: (await originHealthManager.backendEvents(site.id, limit)).map((event) => ({
				...event,
				originName: originNames.get(event.origin_id) ?? event.origin_id,
			})),
			alerts: (await repository.healthAlerts(site.id, 25)).map((alert) => ({
				id: alert.id,
				type: alert.event_type,
				status: alert.status,
				attempts: Number(alert.attempts),
				lastError: alert.last_error,
				createdAt: Number(alert.created_at),
				deliveredAt: alert.delivered_at === null ? null : Number(alert.delivered_at),
			})),
		});
	});

	app.get("/_burrowgate/api/admin/sites/:id/origins", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const originsAccess = await requireSiteAccess(ctx.params.id, user, "view");
		if ("error" in originsAccess) return originsAccess.error;
		const summaries = new Map((originHealthManager.summary(ctx.params.id).origins ?? []).map((origin) => [origin.id, origin]));
		return jsonResponse({
			items: (await repository.originsForSite(ctx.params.id)).map((origin) => ({ ...originView(origin), health: summaries.get(origin.id) ?? null })),
		});
	});

	app.post("/_burrowgate/api/admin/sites/:id/origins", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const originsAccess = await requireSiteAccess(ctx.params.id, user, "manage");
		if ("error" in originsAccess) return originsAccess.error;
		try {
			const origin = await createOrigin(ctx.params.id, await parseOriginInput(ctx.req));
			staticAssetCache.purge({ siteId: ctx.params.id });
			await loadBalancer.refreshSite(ctx.params.id);
			await originHealthManager.refreshSite(ctx.params.id);
			await recordAdminAudit({
				actor: user,
				action: "origin.create",
				resourceType: "origin",
				resourceId: origin.id,
				summary: `Added origin ${origin.name} to site`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse({ origin: originView(origin) }, 201);
		} catch (error) {
			const message = error instanceof Error ? error.message : "Unable to create origin";
			return jsonResponse({ error: message }, message === "Site not found" ? 404 : 400);
		}
	});

	app.addRoute("PUT", "/_burrowgate/api/admin/origins/:id", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		try {
			const existing = await repository.originById(ctx.params.id);
			if (!existing) return jsonResponse({ error: "Origin not found" }, 404);
			const denied = requireLevel(await siteAccessLevel(user, existing.site_id), "manage");
			if (denied) return denied;
			const origin = await updateOrigin(existing.site_id, ctx.params.id, await parseOriginInput(ctx.req));
			staticAssetCache.purge({ siteId: existing.site_id });
			await loadBalancer.refreshSite(existing.site_id);
			await originHealthManager.refreshSite(existing.site_id);
			await recordAdminAudit({
				actor: user,
				action: "origin.update",
				resourceType: "origin",
				resourceId: origin.id,
				summary: `Updated origin ${origin.name}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse({ origin: originView(origin) });
		} catch (error) {
			const message = error instanceof Error ? error.message : "Unable to update origin";
			return jsonResponse({ error: message }, message === "Origin not found" ? 404 : 400);
		}
	});

	app.delete("/_burrowgate/api/admin/origins/:id", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		try {
			const existing = await repository.originById(ctx.params.id);
			if (!existing) return jsonResponse({ error: "Origin not found" }, 404);
			const denied = requireLevel(await siteAccessLevel(user, existing.site_id), "manage");
			if (denied) return denied;
			await deleteOrigin(existing.site_id, ctx.params.id);
			staticAssetCache.purge({ siteId: existing.site_id });
			await loadBalancer.refreshSite(existing.site_id);
			await originHealthManager.refreshSite(existing.site_id);
			await recordAdminAudit({
				actor: user,
				action: "origin.delete",
				resourceType: "origin",
				resourceId: existing.id,
				summary: `Deleted origin ${existing.name}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse({ deleted: true });
		} catch (error) {
			const message = error instanceof Error ? error.message : "Unable to delete origin";
			return jsonResponse({ error: message }, message === "Origin not found" ? 404 : 400);
		}
	});

	app.post("/_burrowgate/api/admin/origins/:id/check", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		try {
			const origin = await repository.originById(ctx.params.id);
			if (!origin) return jsonResponse({ error: "Origin not found" }, 404);
			const denied = requireLevel(await siteAccessLevel(user, origin.site_id), "manage");
			if (denied) return denied;
			return jsonResponse({ status: await originHealthManager.checkNow(origin.site_id, origin.id) });
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to check origin" }, 409);
		}
	});

	app.post("/_burrowgate/api/admin/sites/:id/health/check", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const healthCheckAccess = await requireSiteAccess(ctx.params.id, user, "manage");
		if ("error" in healthCheckAccess) return healthCheckAccess.error;
		try {
			return jsonResponse({ status: await originHealthManager.checkNow(ctx.params.id) });
		} catch (error) {
			const message = error instanceof Error ? error.message : "Unable to run origin health check";
			return jsonResponse({ error: message }, message === "Site not found" ? 404 : 409);
		}
	});

	app.get("/_burrowgate/api/admin/route-policies", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const selection = await selectedSite(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ items: [] });
		return jsonResponse({
			items: (await repository.routePolicies(selection.site.id)).map(routePolicyView),
			site: siteView(selection.site),
		});
	});

	app.post("/_burrowgate/api/admin/route-policies", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedSite(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "Create a site before adding route policies" }, 400);
		const routePolicyDenied = requireLevel(await siteAccessLevel(user, selection.site.id), "manage");
		if (routePolicyDenied) return routePolicyDenied;
		try {
			const policy = await createRoutePolicy(selection.site.id, await parseRoutePolicyInput(ctx.req));
			await recordAdminAudit({
				actor: user,
				action: "route_policy.create",
				resourceType: "route_policy",
				resourceId: policy.id,
				summary: `Created route policy ${policy.name} on ${selection.site.name}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse({ policy: routePolicyView(policy) }, 201);
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to create route policy" }, 400);
		}
	});

	app.addRoute("PUT", "/_burrowgate/api/admin/route-policies/:id", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedSite(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "Selected site was not found" }, 404);
		const routePolicyDenied = requireLevel(await siteAccessLevel(user, selection.site.id), "manage");
		if (routePolicyDenied) return routePolicyDenied;
		try {
			const policy = await updateRoutePolicy(selection.site.id, ctx.params.id, await parseRoutePolicyInput(ctx.req));
			invalidateRouteRateLimiter(policy.id);
			await recordAdminAudit({
				actor: user,
				action: "route_policy.update",
				resourceType: "route_policy",
				resourceId: policy.id,
				summary: `Updated route policy ${policy.name}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse({ policy: routePolicyView(policy) });
		} catch (error) {
			const message = error instanceof Error ? error.message : "Unable to update route policy";
			return jsonResponse({ error: message }, message === "Route policy not found" ? 404 : 400);
		}
	});

	app.addRoute("DELETE", "/_burrowgate/api/admin/route-policies/:id", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedSite(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "Selected site was not found" }, 404);
		const routePolicyDenied = requireLevel(await siteAccessLevel(user, selection.site.id), "manage");
		if (routePolicyDenied) return routePolicyDenied;
		try {
			await deleteRoutePolicy(selection.site.id, ctx.params.id);
			invalidateRouteRateLimiter(ctx.params.id);
			await recordAdminAudit({
				actor: user,
				action: "route_policy.delete",
				resourceType: "route_policy",
				resourceId: ctx.params.id,
				summary: `Deleted a route policy on ${selection.site.name}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse({ ok: true });
		} catch (error) {
			const message = error instanceof Error ? error.message : "Unable to delete route policy";
			return jsonResponse({ error: message }, message === "Route policy not found" ? 404 : 400);
		}
	});

	app.get("/_burrowgate/api/admin/cache", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const selection = await selectedSite(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ metrics: staticAssetCache.metrics(), site: null });
		return jsonResponse({ metrics: staticAssetCache.metrics(selection.site.id), site: siteView(selection.site) });
	});

	app.post("/_burrowgate/api/admin/cache/purge", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		try {
			const raw = (await ctx.req.json()) as unknown;
			if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("Cache purge payload must be an object");
			const body = raw as Record<string, unknown>;
			if (body.allSites === true) {
				const forbidden = requireAdministrator(user);
				if (forbidden) return forbidden;
				const purged = staticAssetCache.purge();
				return jsonResponse({ purged, metrics: staticAssetCache.metrics() });
			}
			const selection = await selectedSite(new URL(ctx.req.url), user);
			if (selection.error) return selection.error;
			if (!selection.site) return jsonResponse({ error: "Selected site was not found" }, 404);
			const cachePurgeDenied = requireLevel(await siteAccessLevel(user, selection.site.id), "manage");
			if (cachePurgeDenied) return cachePurgeDenied;
			const routePolicyId = String(body.routePolicyId ?? "").trim() || undefined;
			if (routePolicyId && !(await repository.routePolicyById(routePolicyId, selection.site.id))) {
				return jsonResponse({ error: "Route policy was not found for the selected site" }, 404);
			}
			const pathPrefix = String(body.pathPrefix ?? "").trim() || undefined;
			if (
				pathPrefix &&
				(!pathPrefix.startsWith("/") || pathPrefix.startsWith("//") || pathPrefix.length > 2_048 || pathPrefix.includes("?") || pathPrefix.includes("#"))
			) {
				throw new Error("Cache purge path must begin with one slash and be at most 2048 characters");
			}
			const purged = staticAssetCache.purge({ siteId: selection.site.id, routePolicyId, pathPrefix });
			return jsonResponse({ purged, metrics: staticAssetCache.metrics(selection.site.id) });
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to purge static cache" }, 400);
		}
	});

	app.get("/_burrowgate/api/admin/access-list", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const selection = await selectedSite(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "Create a site before configuring access authentication" }, 400);
		return jsonResponse(await accessListView(selection.site.id));
	});

	app.addRoute("PUT", "/_burrowgate/api/admin/access-list", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedSite(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "Create a site before configuring access authentication" }, 400);
		const accessSettingsDenied = requireLevel(await siteAccessLevel(user, selection.site.id), "manage");
		if (accessSettingsDenied) return accessSettingsDenied;
		try {
			const body = (await ctx.req.json()) as any;
			await updateAccessSettings(selection.site.id, body ?? {});
			await recordAdminAudit({
				actor: user,
				action: "access_list.settings.update",
				resourceType: "site",
				resourceId: selection.site.id,
				summary: `Updated access-list settings for ${selection.site.name}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse(await accessListView(selection.site.id));
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to update access-list settings" }, 400);
		}
	});

	app.get("/_burrowgate/api/admin/access-list/sso", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const selection = await selectedSite(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "Create a site before configuring single sign-on" }, 400);
		const denied = requireLevel(await siteAccessLevel(user, selection.site.id), "view");
		if (denied) return denied;
		return jsonResponse(await siteSsoSettingsView(selection.site.id));
	});

	app.addRoute("PUT", "/_burrowgate/api/admin/access-list/sso", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedSite(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "Create a site before configuring single sign-on" }, 400);
		const denied = requireLevel(await siteAccessLevel(user, selection.site.id), "manage");
		if (denied) return denied;
		try {
			const settings = await updateSiteSsoSettings(selection.site.id, (await ctx.req.json()) as any);
			await recordAdminAudit({
				actor: user,
				action: "access_list.sso.update",
				resourceType: "site",
				resourceId: selection.site.id,
				summary: `Updated single sign-on settings for ${selection.site.name}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse(settings);
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to update single sign-on settings" }, 400);
		}
	});

	app.post("/_burrowgate/api/admin/access-list/users", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedSite(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "Create a site before adding users" }, 400);
		const accessUserDenied = requireLevel(await siteAccessLevel(user, selection.site.id), "manage");
		if (accessUserDenied) return accessUserDenied;
		const actor = user;
		try {
			const user = await createAccessUser(selection.site.id, (await ctx.req.json()) as any);
			await recordAdminAudit({
				actor,
				action: "access_user.create",
				resourceType: "access_user",
				resourceId: user.id,
				summary: `Created access-list user ${user.username} on ${selection.site.name}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse({ user }, 201);
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to create access user" }, 400);
		}
	});

	app.addRoute("PUT", "/_burrowgate/api/admin/access-list/users/:id", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedSite(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "Selected site was not found" }, 404);
		const accessUserDenied = requireLevel(await siteAccessLevel(user, selection.site.id), "manage");
		if (accessUserDenied) return accessUserDenied;
		const actor = user;
		try {
			const user = await updateAccessUser(selection.site.id, ctx.params.id, (await ctx.req.json()) as any);
			await recordAdminAudit({
				actor,
				action: "access_user.update",
				resourceType: "access_user",
				resourceId: user.id,
				summary: `Updated access-list user ${user.username}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse({ user });
		} catch (error) {
			const message = error instanceof Error ? error.message : "Unable to update access user";
			return jsonResponse({ error: message }, message === "Access user not found" ? 404 : 400);
		}
	});

	app.addRoute("DELETE", "/_burrowgate/api/admin/access-list/users/:id", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedSite(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "Selected site was not found" }, 404);
		const accessUserDenied = requireLevel(await siteAccessLevel(user, selection.site.id), "manage");
		if (accessUserDenied) return accessUserDenied;
		try {
			const target = await repository.accessUserById(ctx.params.id);
			await removeAccessUser(selection.site.id, ctx.params.id);
			await recordAdminAudit({
				actor: user,
				action: "access_user.remove",
				resourceType: "access_user",
				resourceId: ctx.params.id,
				summary: `Removed access-list user ${target?.username ?? ctx.params.id} from ${selection.site.name}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse({ ok: true });
		} catch (error) {
			const message = error instanceof Error ? error.message : "Unable to remove access user";
			return jsonResponse({ error: message }, message === "Access user not found" ? 404 : 400);
		}
	});

	app.post("/_burrowgate/api/admin/access-list/users/:id/totp", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedSite(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "Selected site was not found" }, 404);
		const accessUserDenied = requireLevel(await siteAccessLevel(user, selection.site.id), "manage");
		if (accessUserDenied) return accessUserDenied;
		try {
			const body = (await ctx.req.json()) as { required?: unknown };
			const updated = await setAccessUserTotpRequired(selection.site.id, ctx.params.id, body.required === true);
			await recordAdminAudit({
				actor: user,
				action: "access_user.totp_required.update",
				resourceType: "access_user",
				resourceId: updated.id,
				summary: `${body.required === true ? "Required" : "No longer required"} two-factor authentication for access-list user ${updated.username}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse({ user: updated });
		} catch (error) {
			const message = error instanceof Error ? error.message : "Unable to update two-factor requirement";
			return jsonResponse({ error: message }, message === "Access user not found" ? 404 : 400);
		}
	});

	app.post("/_burrowgate/api/admin/access-list/users/:id/totp/reset", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedSite(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "Selected site was not found" }, 404);
		const accessUserDenied = requireLevel(await siteAccessLevel(user, selection.site.id), "manage");
		if (accessUserDenied) return accessUserDenied;
		try {
			const updated = await resetAccessUserTotp(selection.site.id, ctx.params.id);
			await recordAdminAudit({
				actor: user,
				action: "access_user.totp.reset",
				resourceType: "access_user",
				resourceId: updated.id,
				summary: `Reset two-factor authentication for access-list user ${updated.username}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse({ user: updated });
		} catch (error) {
			const message = error instanceof Error ? error.message : "Unable to reset two-factor authentication";
			return jsonResponse({ error: message }, message === "Access user not found" ? 404 : 400);
		}
	});

	app.post("/_burrowgate/api/admin/access-list/users/:id/api-token", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedSite(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "Selected site was not found" }, 404);
		const accessUserDenied = requireLevel(await siteAccessLevel(user, selection.site.id), "manage");
		if (accessUserDenied) return accessUserDenied;
		try {
			const { view, token } = await generateAccessUserApiToken(selection.site.id, ctx.params.id);
			await recordAdminAudit({
				actor: user,
				action: "access_user.api_token.generate",
				resourceType: "access_user",
				resourceId: view.id,
				summary: `Generated an API token for access-list user ${view.username}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse({ user: view, token }, 201);
		} catch (error) {
			const message = error instanceof Error ? error.message : "Unable to generate API token";
			return jsonResponse({ error: message }, message === "Access user not found" ? 404 : 400);
		}
	});

	app.addRoute("DELETE", "/_burrowgate/api/admin/access-list/users/:id/api-token", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedSite(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "Selected site was not found" }, 404);
		const accessUserDenied = requireLevel(await siteAccessLevel(user, selection.site.id), "manage");
		if (accessUserDenied) return accessUserDenied;
		try {
			const updated = await revokeAccessUserApiToken(selection.site.id, ctx.params.id);
			await recordAdminAudit({
				actor: user,
				action: "access_user.api_token.revoke",
				resourceType: "access_user",
				resourceId: updated.id,
				summary: `Revoked the API token for access-list user ${updated.username}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse({ user: updated });
		} catch (error) {
			const message = error instanceof Error ? error.message : "Unable to revoke API token";
			return jsonResponse({ error: message }, message === "Access user not found" ? 404 : 400);
		}
	});

	app.post("/_burrowgate/api/admin/access-list/import", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedSite(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "Selected site was not found" }, 404);
		const accessUserDenied = requireLevel(await siteAccessLevel(user, selection.site.id), "manage");
		if (accessUserDenied) return accessUserDenied;
		try {
			const body = (await ctx.req.json()) as { userIds?: unknown };
			const imported = await importAccessUsers(selection.site.id, body?.userIds);
			return jsonResponse({ imported }, 201);
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to import access users" }, 400);
		}
	});

	app.get("/_burrowgate/api/admin/geo-metrics-tab", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const url = new URL(ctx.req.url);
		const scope = tabMetricsScopeParam(url);
		if (!scope) return jsonResponse({ error: "Invalid scope" }, 400);
		const range = requestedDateRange(url);
		if (scope === "bandwidth") await flushBandwidthMetrics();
		if (scope === "sites") {
			const items = await repository.tabGeoMetrics(await tabScopeSiteIds(user), range.since, range.until, scope);
			return jsonResponse({ rangeFrom: range.since, rangeTo: range.until, rangeDurationMs: range.durationMs, status: geoIpStatus(), items });
		}
		const selection = await selectedSite(url, user);
		if (selection.error) return selection.error;
		const items = await repository.tabGeoMetrics(metricsScopeSiteId(selection, user), range.since, range.until, scope);
		return jsonResponse({
			rangeFrom: range.since,
			rangeTo: range.until,
			rangeDurationMs: range.durationMs,
			site: selection.site ? siteView(selection.site) : null,
			status: geoIpStatus(),
			items,
		});
	});

	app.get("/_burrowgate/api/admin/referer-metrics-tab", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const url = new URL(ctx.req.url);
		const scope = tabMetricsScopeParam(url);
		if (!scope || scope === "access" || scope === "bandwidth" || scope === "sessions") return jsonResponse({ error: "Invalid scope" }, 400);
		const range = requestedDateRange(url);
		if (scope === "sites") {
			const referrers = await repository.tabRefererMetrics(await tabScopeSiteIds(user), range.since, range.until, scope);
			return jsonResponse({ rangeFrom: range.since, rangeTo: range.until, rangeDurationMs: range.durationMs, referrers });
		}
		const selection = await selectedSite(url, user);
		if (selection.error) return selection.error;
		const referrers = await repository.tabRefererMetrics(metricsScopeSiteId(selection, user), range.since, range.until, scope);
		return jsonResponse({
			rangeFrom: range.since,
			rangeTo: range.until,
			rangeDurationMs: range.durationMs,
			site: selection.site ? siteView(selection.site) : null,
			referrers,
		});
	});

	app.get("/_burrowgate/api/admin/ip-metrics-tab", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const url = new URL(ctx.req.url);
		const scope = stringParam(url, "scope");
		if (scope !== "blocked" && scope !== "routes") return jsonResponse({ error: "Invalid scope" }, 400);
		const range = requestedDateRange(url);
		const selection = await selectedSite(url, user);
		if (selection.error) return selection.error;
		const ips = await repository.tabIpMetrics(metricsScopeSiteId(selection, user), range.since, range.until, scope);
		return jsonResponse({
			rangeFrom: range.since,
			rangeTo: range.until,
			rangeDurationMs: range.durationMs,
			site: selection.site ? siteView(selection.site) : null,
			ips,
		});
	});

	app.get("/_burrowgate/api/admin/path-metrics-tab", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const url = new URL(ctx.req.url);
		const scope = stringParam(url, "scope");
		if (scope !== "protection") return jsonResponse({ error: "Invalid scope" }, 400);
		const range = requestedDateRange(url);
		const selection = await selectedSite(url, user);
		if (selection.error) return selection.error;
		const paths = await repository.tabPathMetrics(metricsScopeSiteId(selection, user), range.since, range.until, scope);
		return jsonResponse({
			rangeFrom: range.since,
			rangeTo: range.until,
			rangeDurationMs: range.durationMs,
			site: selection.site ? siteView(selection.site) : null,
			paths,
		});
	});

	app.get("/_burrowgate/api/admin/access-username-metrics", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const url = new URL(ctx.req.url);
		const selection = await selectedSite(url, user);
		if (selection.error) return selection.error;
		const range = requestedDateRange(url);
		const usernames = await repository.accessUsernameMetrics(metricsScopeSiteId(selection, user), range.since, range.until);
		return jsonResponse({
			rangeFrom: range.since,
			rangeTo: range.until,
			rangeDurationMs: range.durationMs,
			site: selection.site ? siteView(selection.site) : null,
			usernames,
		});
	});

	app.get("/_burrowgate/api/admin/session-username-metrics", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const url = new URL(ctx.req.url);
		const selection = await selectedSite(url, user);
		if (selection.error) return selection.error;
		const range = requestedDateRange(url);
		const usernames = await repository.sessionUsernameMetrics(metricsScopeSiteId(selection, user), range.since, range.until);
		return jsonResponse({
			rangeFrom: range.since,
			rangeTo: range.until,
			rangeDurationMs: range.durationMs,
			site: selection.site ? siteView(selection.site) : null,
			usernames,
		});
	});

	app.get("/_burrowgate/api/admin/overview", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const url = new URL(ctx.req.url);
		const selection = await selectedSite(url, user);
		if (selection.error) return selection.error;
		const range = requestedDateRange(url);
		return jsonResponse({
			...(await repository.overview(metricsScopeSiteId(selection, user), range.since, range.until)),
			retentionDays: selection.site?.event_retention_days ?? config.eventRetentionDays,
			defaultPageSize: config.adminPageSize,
			site: selection.site ? siteView(selection.site) : null,
			originHealth: selection.site ? originHealthManager.summary(selection.site.id) : null,
		});
	});

	app.get("/_burrowgate/api/admin/metrics", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const url = new URL(ctx.req.url);
		const section =
			enumParam(url, "section", ["traffic", "bandwidth", "cache", "protection", "sessions", "rules", "routes", "access", "sites"] as const, "traffic") ??
			"traffic";
		if (section === "sites") {
			const forbidden = requireAdministrator(user);
			if (forbidden) return forbidden;
		}
		const selection = section === "sites" ? { site: null, error: null } : await selectedSite(url, user);
		if (selection.error) return selection.error;
		const scopeSiteId = metricsScopeSiteId(selection, user);
		const range = requestedDateRange(url);
		const bucketMs = metricBucketSize(range.durationMs);
		const since = range.since;
		const until = range.until;
		const firstBucket = Math.floor(since / bucketMs) * bucketMs;
		const finalBucket = Math.floor(until / bucketMs) * bucketMs;
		const bucketCount = Math.floor((finalBucket - firstBucket) / bucketMs) + 1;
		const base = {
			section,
			rangeFrom: range.since,
			rangeTo: range.until,
			rangeDurationMs: range.durationMs,
			bucketMs,
			bucketCount,
		};

		if (section === "cache") {
			const metrics = await repository.cacheMetrics(scopeSiteId, since, until, bucketMs);
			return jsonResponse({
				...base,
				primary: {
					title: "Cache outcomes",
					subtitle: "Hits, misses, and bypassed requests per interval",
					type: "line",
					timeSeries: true,
					valueFormat: "number",
					emptyMessage: "No cache activity in this range.",
					datasets: [
						{ key: "hits", label: "Hits" },
						{ key: "misses", label: "Misses" },
						{ key: "bypasses", label: "Bypasses" },
					],
					data: metrics.series,
				},
				secondary: {
					title: "Cache hit ratio",
					subtitle: "Hits as a percentage of cacheable lookups",
					type: "line",
					timeSeries: true,
					valueFormat: "percentage",
					emptyMessage: "No cacheable lookups in this range.",
					datasets: [{ key: "hitRatio", label: "Hit ratio" }],
					data: metrics.series,
				},
				breakdown: [
					{ label: "Hits", count: metrics.totals.hits },
					{ label: "Misses", count: metrics.totals.misses },
					{ label: "Bypasses", count: metrics.totals.bypasses },
				],
				cache: metrics,
			});
		}

		if (section === "protection") {
			const metrics = await repository.protectionMetrics(scopeSiteId, since, until, bucketMs);
			return jsonResponse({
				...base,
				primary: {
					title: "Request protection outcomes",
					subtitle: "Clean, monitored, and blocked inspected requests",
					type: "line",
					timeSeries: true,
					valueFormat: "number",
					emptyMessage: "No requests were inspected in this range.",
					datasets: [
						{ key: "clean", label: "Clean" },
						{ key: "monitored", label: "Would block" },
						{ key: "blocked", label: "Blocked" },
					],
					data: metrics.series,
				},
				secondary: {
					title: "Top matched rules",
					subtitle: "Most frequent managed-rule matches in this range",
					type: "bar",
					timeSeries: false,
					valueFormat: "number",
					emptyMessage: "No managed rules matched in this range.",
					datasets: [
						{ key: "monitored", label: "Would block" },
						{ key: "blocked", label: "Blocked" },
					],
					data: metrics.topRules.slice(0, 8).map((rule) => ({ label: rule.ruleId, monitored: rule.monitored, blocked: rule.blocked })),
				},
				breakdown: [
					{ label: "Inspected", count: metrics.totals.inspected },
					{ label: "Would block", count: metrics.totals.monitored },
					{ label: "Blocked", count: metrics.totals.blocked },
				],
				protection: metrics,
				rulesets: managedRuleSetCatalog(),
			});
		}

		if (section === "bandwidth") {
			await flushBandwidthMetrics();
			const metrics = await repository.bandwidthMetrics(scopeSiteId, since, until, bucketMs);
			return jsonResponse({
				...base,
				primary: {
					title: "Client-side bandwidth",
					subtitle: "Payload bytes crossing between users and BurrowGate",
					type: "line",
					timeSeries: true,
					valueFormat: "bytes",
					emptyMessage: "No client bandwidth in this range.",
					datasets: [
						{ key: "clientDownload", label: "Sent to clients" },
						{ key: "clientUpload", label: "Received from clients" },
					],
					data: metrics.series,
				},
				secondary: {
					title: "Upstream bandwidth",
					subtitle: "Payload bytes crossing between BurrowGate and origin servers",
					type: "line",
					timeSeries: true,
					valueFormat: "bytes",
					emptyMessage: "No upstream bandwidth in this range.",
					datasets: [
						{ key: "upstreamDownload", label: "Received from origins" },
						{ key: "upstreamUpload", label: "Sent to origins" },
					],
					data: metrics.series,
				},
				breakdown: [],
				protocols: metrics.protocols,
			});
		}

		if (section === "sessions") {
			const metrics = await repository.sessionMetrics(scopeSiteId, since, until, bucketMs);
			return jsonResponse({
				...base,
				primary: {
					title: "Session lifecycle",
					subtitle: "New, expired, and revoked visitor sessions per interval",
					type: "line",
					timeSeries: true,
					valueFormat: "number",
					emptyMessage: "No session changes in this range.",
					datasets: [
						{ key: "created", label: "Created" },
						{ key: "expired", label: "Expired" },
						{ key: "revoked", label: "Revoked" },
					],
					data: metrics.series,
				},
				secondary: {
					title: "Active sessions",
					subtitle: "Sessions that remained valid at the end of each interval",
					type: "line",
					timeSeries: true,
					valueFormat: "number",
					emptyMessage: "No active sessions in this range.",
					datasets: [{ key: "active", label: "Active sessions" }],
					data: metrics.series,
				},
				breakdown: metrics.states,
			});
		}

		if (section === "rules") {
			const metrics = await repository.ruleMetrics(scopeSiteId ?? "", since, until, bucketMs);
			return jsonResponse({
				...base,
				primary: {
					title: "Network rules created",
					subtitle: "IP and country rules added per interval",
					type: "line",
					timeSeries: true,
					valueFormat: "number",
					emptyMessage: "No network rules were created in this range.",
					datasets: [
						{ key: "pass", label: "Allow and follow route" },
						{ key: "allow", label: "Allow and bypass" },
						{ key: "block", label: "Block" },
						{ key: "challenge", label: "Challenge" },
					],
					data: metrics.series,
				},
				secondary: {
					title: "Current rule state",
					subtitle: "Active and expired rules grouped by action",
					type: "bar",
					timeSeries: false,
					valueFormat: "number",
					emptyMessage: "No network rules are configured.",
					datasets: [
						{ key: "active", label: "Active" },
						{ key: "expired", label: "Expired" },
					],
					data: metrics.states,
				},
				breakdown: [],
			});
		}

		if (section === "routes") {
			const metrics = await repository.routeMetrics(scopeSiteId ?? "", since, until, bucketMs);
			return jsonResponse({
				...base,
				primary: {
					title: "Route outcomes",
					subtitle: "How route policies handled HTTP and WebSocket requests",
					type: "line",
					timeSeries: true,
					valueFormat: "number",
					emptyMessage: "No route activity in this range.",
					datasets: [
						{ key: "verified", label: "Verified" },
						{ key: "bypassed", label: "Bypassed" },
						{ key: "challenged", label: "Challenged" },
						{ key: "rateLimited", label: "Rate limited" },
						{ key: "blocked", label: "Blocked" },
					],
					data: metrics.series,
				},
				secondary: {
					title: "Route policy configuration",
					subtitle: "Current policies by access mode and rate-limit usage",
					type: "bar",
					timeSeries: false,
					valueFormat: "number",
					emptyMessage: "No route policies are configured.",
					datasets: [{ key: "count", label: "Policies" }],
					data: metrics.policies,
				},
				breakdown: [
					{ label: "Enabled policies", count: metrics.enabledPolicies },
					{ label: "Disabled policies", count: metrics.disabledPolicies },
				],
			});
		}

		if (section === "access") {
			const metrics = await repository.accessListMetrics(scopeSiteId ?? "", since, until, bucketMs);
			return jsonResponse({
				...base,
				primary: {
					title: "Access authentication",
					subtitle: "Authenticated requests and login outcomes",
					type: "line",
					timeSeries: true,
					valueFormat: "number",
					emptyMessage: "No access authentication activity in this range.",
					datasets: [
						{ key: "authenticated", label: "Authenticated" },
						{ key: "loginRequired", label: "Login required" },
						{ key: "failed", label: "Failed" },
						{ key: "rateLimited", label: "Rate limited" },
					],
					data: metrics.series,
				},
				secondary: {
					title: "Assigned users",
					subtitle: "Current users by state",
					type: "bar",
					timeSeries: false,
					valueFormat: "number",
					emptyMessage: "No users are assigned to this site.",
					datasets: [{ key: "count", label: "Users" }],
					data: [
						{ label: "Active", count: metrics.activeUsers },
						{ label: "Disabled", count: metrics.disabledUsers },
					],
				},
				breakdown: [
					{ label: "Active users", count: metrics.activeUsers },
					{ label: "Disabled users", count: metrics.disabledUsers },
				],
			});
		}

		if (section === "sites") {
			const metrics = await repository.siteMetrics(since, until, bucketMs);
			return jsonResponse({
				...base,
				primary: {
					title: "Traffic by site",
					subtitle: "Request volume across the busiest configured sites",
					type: "line",
					timeSeries: true,
					valueFormat: "number",
					emptyMessage: "No site traffic in this range.",
					datasets: metrics.sites.map((site) => ({ key: site.key, label: site.label })),
					data: metrics.series.map((point) => ({ bucket: point.bucket, ...point.values })),
				},
				secondary: {
					title: "Origin latency by site",
					subtitle: "Average origin response time over the selected range",
					type: "bar",
					timeSeries: false,
					valueFormat: "duration",
					emptyMessage: "No site latency data in this range.",
					datasets: [{ key: "averageLatency", label: "Average latency" }],
					data: metrics.sites,
				},
				breakdown: [
					{ label: "Enabled sites", count: metrics.enabledSites },
					{ label: "Disabled sites", count: metrics.disabledSites },
				],
			});
		}

		const metrics = await repository.trafficMetrics(scopeSiteId, since, until, bucketMs);
		return jsonResponse({
			...base,
			primary: {
				title: "Traffic volume",
				subtitle: "Requests, blocked requests, and origin errors",
				type: "line",
				timeSeries: true,
				valueFormat: "number",
				emptyMessage: "No traffic in this range.",
				datasets: [
					{ key: "requests", label: "Requests" },
					{ key: "blocked", label: "Blocked" },
					{ key: "errors", label: "5xx errors" },
				],
				data: metrics.series,
			},
			secondary: {
				title: "Origin latency",
				subtitle: "Average proxy response time per interval",
				type: "line",
				timeSeries: true,
				valueFormat: "duration",
				emptyMessage: "No latency data in this range.",
				datasets: [{ key: "averageLatency", label: "Average latency" }],
				data: metrics.series,
			},
			breakdown: metrics.decisions.map((item) => ({ label: item.decision, count: item.count })),
		});
	});

	app.get("/_burrowgate/api/admin/events", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const url = new URL(ctx.req.url);
		const selection = await selectedSite(url, user);
		if (selection.error) return selection.error;
		const scopeSiteId = metricsScopeSiteId(selection, user);
		const range = requestedDateRange(url);
		const search = stringParam(url, "search");
		const decision = stringParam(url, "decision");
		const cacheStatus = enumParam(url, "cache", ["hit", "miss", "bypass"] as const);
		const protectionStatus = enumParam(url, "protection", ["clean", "monitored", "blocked"] as const);
		const originId = stringParam(url, "origin");
		const method = stringParam(url, "method");
		const statusGroup = enumParam(url, "status", ["1xx", "2xx", "3xx", "4xx", "5xx"] as const);
		const countryCode = stringParam(url, "country")?.toUpperCase();
		const [page, origins] = await Promise.all([
			repository.pagedEvents({
				...(scopeSiteId ? { siteId: scopeSiteId } : {}),
				...(originId ? { originId } : {}),
				page: integerParam(url, "page", 1, 1, 1_000_000),
				pageSize: integerParam(url, "pageSize", config.adminPageSize, 10, 200),
				...(search ? { search } : {}),
				...(decision ? { decision } : {}),
				...(cacheStatus ? { cacheStatus } : {}),
				...(protectionStatus ? { protectionStatus } : {}),
				...(method ? { method } : {}),
				...(statusGroup ? { statusGroup } : {}),
				...(countryCode && /^[A-Z]{2}$/u.test(countryCode) ? { countryCode } : {}),
				since: range.since,
				until: range.until,
				sortBy: enumParam(
					url,
					"sortBy",
					["created_at", "ip", "country_code", "method", "path", "status", "decision", "cache_status", "protection_status", "latency_ms"] as const,
					"created_at",
				)!,
				sortDirection: sortDirection(url),
			}),
			selection.site ? repository.originsForSite(selection.site.id) : Promise.resolve([]),
		]);
		const originNames = new Map(origins.map((origin) => [origin.id, origin.name]));
		return jsonResponse({
			...page,
			items: page.items.map((event) => ({
				...event,
				protection_matches: protectionMatches(event.protection_matches_json),
				origin_name: event.origin_id ? (originNames.get(event.origin_id) ?? null) : null,
			})),
			origins: origins.map((origin) => ({ id: origin.id, name: origin.name })),
		});
	});

	app.get("/_burrowgate/api/admin/bandwidth", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const url = new URL(ctx.req.url);
		const selection = await selectedSite(url, user);
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "No site configured" }, 400);
		const range = requestedDateRange(url);
		const search = stringParam(url, "search");
		const countryCode = stringParam(url, "country")?.toUpperCase();
		const protocol = enumParam(url, "protocol", ["http", "websocket"] as const);
		await flushBandwidthMetrics();
		return jsonResponse(
			await repository.pagedBandwidthIps({
				siteId: selection.site.id,
				page: integerParam(url, "page", 1, 1, 1_000_000),
				pageSize: integerParam(url, "pageSize", config.adminPageSize, 10, 200),
				...(search ? { search } : {}),
				...(countryCode && /^[A-Z]{2}$/u.test(countryCode) ? { countryCode } : {}),
				...(protocol ? { protocol } : {}),
				since: range.since,
				until: range.until,
				sortBy: enumParam(
					url,
					"sortBy",
					[
						"ip",
						"country_code",
						"client_received_bytes",
						"client_sent_bytes",
						"upstream_sent_bytes",
						"upstream_received_bytes",
						"client_total_bytes",
						"upstream_total_bytes",
					] as const,
					"client_total_bytes",
				)!,
				sortDirection: sortDirection(url),
			}),
		);
	});

	app.get("/_burrowgate/api/admin/sessions", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const url = new URL(ctx.req.url);
		const selection = await selectedSite(url, user);
		if (selection.error) return selection.error;
		const scopeSiteId = metricsScopeSiteId(selection, user);
		const range = requestedDateRange(url);
		const search = stringParam(url, "search");
		const state = enumParam(url, "state", ["active", "expired", "revoked"] as const);
		const countryCode = stringParam(url, "country")?.toUpperCase();
		return jsonResponse(
			await repository.pagedSessions({
				...(scopeSiteId ? { siteId: scopeSiteId } : {}),
				page: integerParam(url, "page", 1, 1, 1_000_000),
				pageSize: integerParam(url, "pageSize", config.adminPageSize, 10, 200),
				...(search ? { search } : {}),
				...(state ? { state } : {}),
				...(countryCode && /^[A-Z]{2}$/u.test(countryCode) ? { countryCode } : {}),
				since: range.since,
				until: range.until,
				sortBy: enumParam(url, "sortBy", ["last_seen_at", "created_at", "expires_at", "request_count", "last_ip", "country_code"] as const, "last_seen_at")!,
				sortDirection: sortDirection(url),
			}),
		);
	});

	app.get("/_burrowgate/api/admin/network-policy", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const selection = await selectedSite(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "No site configured" }, 400);
		return jsonResponse({
			defaultIpAction: selection.site.default_ip_action ?? "inherit",
			defaultCountryAction: selection.site.default_country_action ?? "inherit",
			countryRules: await repository.countryRules(selection.site.id),
			geoip: geoIpStatus(),
		});
	});

	app.addRoute("PUT", "/_burrowgate/api/admin/network-policy", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedSite(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "No site configured" }, 400);
		const networkPolicyDenied = requireLevel(await siteAccessLevel(user, selection.site.id), "manage");
		if (networkPolicyDenied) return networkPolicyDenied;
		try {
			const body = (await ctx.req.json()) as { defaultIpAction?: DefaultNetworkAction; defaultCountryAction?: DefaultNetworkAction };
			const defaultIpAction = parseDefaultNetworkAction(body.defaultIpAction, selection.site.default_ip_action ?? "inherit");
			const defaultCountryAction = parseDefaultNetworkAction(body.defaultCountryAction, selection.site.default_country_action ?? "inherit");
			await repository.updateSiteNetworkDefaults(selection.site.id, defaultIpAction, defaultCountryAction, Date.now());
			invalidateNetworkPolicy(selection.site.id);
			await recordAdminAudit({
				actor: user,
				action: "network_policy.update",
				resourceType: "site",
				resourceId: selection.site.id,
				summary: `Updated default network policy for ${selection.site.name}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse({ defaultIpAction, defaultCountryAction });
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to update network policy" }, 400);
		}
	});

	app.post("/_burrowgate/api/admin/country-rules", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedSite(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "No site configured" }, 400);
		const countryRuleDenied = requireLevel(await siteAccessLevel(user, selection.site.id), "manage");
		if (countryRuleDenied) return countryRuleDenied;
		const body = (await ctx.req.json()) as { countryCode?: string; action?: IpRuleAction; reason?: string; expiresAt?: number | string | null };
		if (!body.countryCode || !["allow", "pass", "block", "challenge"].includes(body.action ?? "")) {
			return jsonResponse({ error: "Invalid country rule" }, 400);
		}
		const expiresAt = body.expiresAt === null || body.expiresAt === undefined || body.expiresAt === "" ? null : Number(body.expiresAt);
		if (expiresAt !== null && (!Number.isFinite(expiresAt) || expiresAt <= Date.now())) {
			return jsonResponse({ error: "Expiration must be in the future" }, 400);
		}
		try {
			const rule = await addCountryRule(selection.site.id, body.countryCode, body.action!, body.reason ?? "", expiresAt);
			await recordAdminAudit({
				actor: user,
				action: "country_rule.create",
				resourceType: "country_rule",
				resourceId: rule.id,
				summary: `Added country rule (${rule.action}) for ${rule.country_code} on ${selection.site.name}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse(rule, 201);
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Invalid country rule" }, 400);
		}
	});

	app.delete("/_burrowgate/api/admin/country-rules/:id", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedSite(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "No site configured" }, 400);
		const countryRuleDenied = requireLevel(await siteAccessLevel(user, selection.site.id), "manage");
		if (countryRuleDenied) return countryRuleDenied;
		await repository.deleteCountryRuleForSite(ctx.params.id!, selection.site.id);
		invalidateNetworkPolicy(selection.site.id);
		await recordAdminAudit({
			actor: user,
			action: "country_rule.delete",
			resourceType: "country_rule",
			resourceId: ctx.params.id!,
			summary: `Deleted a country rule on ${selection.site.name}`,
			ip: getClientIp(ctx) ?? "unknown",
		});
		return jsonResponse({ deleted: true });
	});

	app.get("/_burrowgate/api/admin/rules", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const url = new URL(ctx.req.url);
		const selection = await selectedSite(url, user);
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ items: [], page: 1, pageSize: config.adminPageSize, total: 0, totalPages: 1 });
		const search = stringParam(url, "search");
		const action = enumParam(url, "action", ["allow", "pass", "block", "challenge"] as const);
		const state = enumParam(url, "state", ["active", "expired"] as const);
		return jsonResponse(
			await repository.pagedRules({
				siteId: selection.site.id,
				page: integerParam(url, "page", 1, 1, 1_000_000),
				pageSize: integerParam(url, "pageSize", config.adminPageSize, 10, 200),
				...(search ? { search } : {}),
				...(action ? { action } : {}),
				...(state ? { state } : {}),
				sortBy: enumParam(url, "sortBy", ["created_at", "expires_at", "network_cidr", "action"] as const, "created_at")!,
				sortDirection: sortDirection(url),
			}),
		);
	});

	app.post("/_burrowgate/api/admin/rules", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedSite(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "No site configured" }, 400);
		const ipRuleDenied = requireLevel(await siteAccessLevel(user, selection.site.id), "manage");
		if (ipRuleDenied) return ipRuleDenied;
		const body = (await ctx.req.json()) as { networkCidr?: string; action?: IpRuleAction; reason?: string; expiresAt?: number | string | null };
		if (!body.networkCidr || !["allow", "pass", "block", "challenge"].includes(body.action ?? "")) {
			return jsonResponse({ error: "Invalid rule" }, 400);
		}
		const parsedExpiresAt = body.expiresAt === null || body.expiresAt === undefined || body.expiresAt === "" ? null : Number(body.expiresAt);
		if (parsedExpiresAt !== null && (!Number.isFinite(parsedExpiresAt) || parsedExpiresAt <= Date.now())) {
			return jsonResponse({ error: "Expiration must be in the future" }, 400);
		}
		try {
			const rule = await addIpRule(selection.site.id, body.networkCidr, body.action!, body.reason ?? "", parsedExpiresAt);
			await recordAdminAudit({
				actor: user,
				action: "ip_rule.create",
				resourceType: "ip_rule",
				resourceId: rule.id,
				summary: `Added IP rule (${rule.action}) for ${rule.network_cidr} on ${selection.site.name}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse(rule, 201);
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Invalid rule" }, 400);
		}
	});

	app.delete("/_burrowgate/api/admin/rules/:id", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedSite(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "No site configured" }, 400);
		const ipRuleDenied = requireLevel(await siteAccessLevel(user, selection.site.id), "manage");
		if (ipRuleDenied) return ipRuleDenied;
		await repository.deleteRuleForSite(ctx.params.id!, selection.site.id);
		invalidateNetworkPolicy(selection.site.id);
		await recordAdminAudit({
			actor: user,
			action: "ip_rule.delete",
			resourceType: "ip_rule",
			resourceId: ctx.params.id!,
			summary: `Deleted an IP rule on ${selection.site.name}`,
			ip: getClientIp(ctx) ?? "unknown",
		});
		return jsonResponse({ deleted: true });
	});

	app.post("/_burrowgate/api/admin/rules/bulk-delete", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedSite(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "No site configured" }, 400);
		const ipRuleDenied = requireLevel(await siteAccessLevel(user, selection.site.id), "manage");
		if (ipRuleDenied) return ipRuleDenied;
		const body = (await ctx.req.json()) as { ids?: unknown };
		const ids = Array.isArray(body.ids) ? body.ids.filter((id): id is string => typeof id === "string") : [];
		if (ids.length === 0 || ids.length > 200) return jsonResponse({ error: "Provide 1 to 200 rule IDs" }, 400);
		const deleted = await repository.deleteRulesForSite(ids, selection.site.id);
		invalidateNetworkPolicy(selection.site.id);
		await recordAdminAudit({
			actor: user,
			action: "ip_rule.bulk_delete",
			resourceType: "site",
			resourceId: selection.site.id,
			summary: `Deleted ${deleted} IP rule(s) on ${selection.site.name}`,
			ip: getClientIp(ctx) ?? "unknown",
		});
		return jsonResponse({ deleted });
	});

	app.post("/_burrowgate/api/admin/sessions/:id/revoke", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedSite(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "No site configured" }, 400);
		const revokeDenied = requireLevel(await siteAccessLevel(user, selection.site.id), "manage");
		if (revokeDenied) return revokeDenied;
		await repository.revokeSessionForSite(ctx.params.id!, selection.site.id, Date.now());
		await recordAdminAudit({
			actor: user,
			action: "session.revoke",
			resourceType: "session",
			resourceId: ctx.params.id!,
			summary: `Revoked a visitor session on ${selection.site.name}`,
			ip: getClientIp(ctx) ?? "unknown",
		});
		return jsonResponse({ revoked: true });
	});

	app.get("/_burrowgate/api/admin/sites/:id/tls", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const access = await requireSiteAccess(ctx.params.id, user, "view");
		if ("error" in access) return access.error;
		return jsonResponse(await tlsView(access.site));
	});

	app.addRoute("PUT", "/_burrowgate/api/admin/sites/:id/tls", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const access = await requireSiteAccess(ctx.params.id, user, "manage");
		if ("error" in access) return access.error;
		const { site } = access;
		try {
			const body = (await ctx.req.json()) as Record<string, unknown>;
			const current = await repository.ensureTlsSettings(site.id);
			const requestedMode = body.mode === undefined ? current.mode : String(body.mode);
			if (requestedMode === "uploaded" || requestedMode === "letsencrypt") {
				const certificate = await repository.certificateBySite(site.id);
				const certificateUsable = certificate?.status === "active" && Number(certificate.expires_at ?? 0) > Date.now();
				const sourceMatches = certificate?.source === requestedMode;
				if (!certificateUsable || !sourceMatches) {
					return jsonResponse({ error: "The selected TLS mode requires a matching active certificate" }, 400);
				}
			}
			await updateTlsSettings(site, body);
			await requestTlsReload();
			await recordAdminAudit({
				actor: user,
				action: "tls.update",
				resourceType: "site",
				resourceId: site.id,
				summary: `Updated TLS settings for ${site.name}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse(await tlsView(site));
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to update TLS settings" }, 400);
		}
	});

	app.post("/_burrowgate/api/admin/sites/:id/certificate/upload", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const access = await requireSiteAccess(ctx.params.id, user, "manage");
		if ("error" in access) return access.error;
		const { site } = access;
		try {
			const body = (await ctx.req.json()) as { certificatePem?: string; privateKeyPem?: string; forceHttps?: boolean };
			if (!body.certificatePem || !body.privateKeyPem) throw new Error("Certificate and private-key PEM are required");
			const certificate = await saveCertificate({ site, source: "uploaded", certificatePem: body.certificatePem, privateKeyPem: body.privateKeyPem });
			await updateTlsSettings(site, { mode: "uploaded", forceHttps: Boolean(body.forceHttps) });
			await recordCertificateEvent(site.id, certificate.id, "info", "Uploaded certificate activated", { expiresAt: certificate.expires_at });
			await requestTlsReload();
			await recordAdminAudit({
				actor: user,
				action: "certificate.upload",
				resourceType: "site",
				resourceId: site.id,
				summary: `Uploaded a TLS certificate for ${site.name}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse(await tlsView(site), 201);
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to upload certificate" }, 400);
		}
	});

	app.post("/_burrowgate/api/admin/sites/:id/certificate/letsencrypt", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const access = await requireSiteAccess(ctx.params.id, user, "manage");
		if ("error" in access) return access.error;
		const { site } = access;
		try {
			const body = (await ctx.req.json()) as { email?: string; directoryUrl?: string; forceHttps?: boolean; termsAccepted?: boolean };
			await issueLetsEncryptCertificate(site, {
				...(body.email ? { email: body.email } : {}),
				...(body.directoryUrl ? { directoryUrl: body.directoryUrl } : {}),
				forceHttps: Boolean(body.forceHttps),
				termsAccepted: body.termsAccepted === true,
			});
			await recordAdminAudit({
				actor: user,
				action: "certificate.issue",
				resourceType: "site",
				resourceId: site.id,
				summary: `Issued a Let's Encrypt certificate for ${site.name}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse(await tlsView(site), 201);
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Certificate issuance failed" }, 400);
		}
	});

	app.post("/_burrowgate/api/admin/sites/:id/certificate/renew", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const access = await requireSiteAccess(ctx.params.id, user, "manage");
		if ("error" in access) return access.error;
		const { site } = access;
		const certificate = await repository.certificateBySite(site.id);
		if (!certificate || certificate.source !== "letsencrypt") return jsonResponse({ error: "This site does not have a Let's Encrypt certificate" }, 400);
		const settings = await repository.ensureTlsSettings(site.id);
		try {
			await issueLetsEncryptCertificate(site, {
				email: settings.acme_email,
				directoryUrl: settings.acme_directory_url,
				forceHttps: settings.force_https === 1,
				termsAccepted: true,
				renewal: true,
			});
			await recordAdminAudit({
				actor: user,
				action: "certificate.renew",
				resourceType: "site",
				resourceId: site.id,
				summary: `Renewed the Let's Encrypt certificate for ${site.name}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse(await tlsView(site));
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Certificate renewal failed" }, 400);
		}
	});

	app.delete("/_burrowgate/api/admin/sites/:id/certificate", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const access = await requireSiteAccess(ctx.params.id, user, "manage");
		if ("error" in access) return access.error;
		const { site } = access;
		const certificate = await repository.certificateBySite(site.id);
		if (certificate) {
			const streams = await repository.streamsUsingCertificate(certificate.id);
			if (streams.length) {
				return jsonResponse(
					{ error: `This certificate is used by stream port${streams.length === 1 ? "" : "s"} ${streams.map((stream) => stream.incoming_port).join(", ")}` },
					409,
				);
			}
		}
		await repository.deleteCertificate(site.id);
		await updateTlsSettings(site, { mode: "disabled", forceHttps: false });
		await recordCertificateEvent(site.id, certificate?.id ?? null, "warning", "Certificate removed");
		await requestTlsReload();
		await recordAdminAudit({
			actor: user,
			action: "certificate.remove",
			resourceType: "site",
			resourceId: site.id,
			summary: `Removed the TLS certificate for ${site.name}`,
			ip: getClientIp(ctx) ?? "unknown",
		});
		return jsonResponse(await tlsView(site));
	});

	app.get("/_burrowgate/api/admin/me", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		return jsonResponse(await adminUserView(user.id));
	});

	app.post("/_burrowgate/api/admin/me/password", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		try {
			const body = (await ctx.req.json()) as { currentPassword?: unknown; newPassword?: unknown };
			await changeOwnPassword(user.id, body.currentPassword, body.newPassword);
			return jsonResponse({ ok: true });
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to change password" }, 400);
		}
	});

	app.post("/_burrowgate/api/admin/me/recovery-codes/regenerate", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		try {
			const body = (await ctx.req.json()) as { code?: unknown };
			const codes = await regenerateOwnRecoveryCodes(user.id, body.code);
			return jsonResponse({ codes });
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to regenerate recovery codes" }, 400);
		}
	});

	app.get("/_burrowgate/api/admin/sso", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const forbidden = requireAdministrator(guarded.user);
		if (forbidden) return forbidden;
		return jsonResponse(await adminSsoSettingsView());
	});

	app.addRoute("PUT", "/_burrowgate/api/admin/sso", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const forbidden = requireAdministrator(user);
		if (forbidden) return forbidden;
		try {
			const settings = await updateAdminSsoSettings((await ctx.req.json()) as any);
			await recordAdminAudit({
				actor: user,
				action: "admin_sso.settings.update",
				summary: "Updated dashboard single sign-on settings",
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse(settings);
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to update single sign-on settings" }, 400);
		}
	});

	app.get("/_burrowgate/api/admin/users", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const forbidden = requireAdministrator(user);
		if (forbidden) return forbidden;
		const [items, sites, streams] = await Promise.all([listAdminUsers(), repository.allSites(), repository.allStreams()]);
		return jsonResponse({
			items,
			sites: sites.map((site) => ({ id: site.id, name: site.name })),
			streams: streams.map((stream) => ({
				id: stream.id,
				incomingPort: stream.incoming_port,
				forwardHost: stream.forward_host,
				forwardPort: stream.forward_port,
			})),
		});
	});

	app.post("/_burrowgate/api/admin/users", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const forbidden = requireAdministrator(user);
		if (forbidden) return forbidden;
		try {
			const created = await createAdminUser((await ctx.req.json()) as any, user.id);
			await recordAdminAudit({
				actor: user,
				action: "admin_user.create",
				resourceType: "admin_user",
				resourceId: created.id,
				summary: `Created user ${created.username} (${created.role})`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse({ user: created }, 201);
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to create user" }, 400);
		}
	});

	app.addRoute("PATCH", "/_burrowgate/api/admin/users/:id", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const forbidden = requireAdministrator(user);
		if (forbidden) return forbidden;
		try {
			const updated = await updateAdminUser(ctx.params.id, (await ctx.req.json()) as any);
			await recordAdminAudit({
				actor: user,
				action: "admin_user.update",
				resourceType: "admin_user",
				resourceId: updated.id,
				summary: `Updated user ${updated.username}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse({ user: updated });
		} catch (error) {
			const message = error instanceof Error ? error.message : "Unable to update user";
			return jsonResponse({ error: message }, message === "Admin user not found" ? 404 : 400);
		}
	});

	app.delete("/_burrowgate/api/admin/users/:id", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const forbidden = requireAdministrator(user);
		if (forbidden) return forbidden;
		if (ctx.params.id === user.id) return jsonResponse({ error: "You cannot delete your own account" }, 400);
		try {
			const target = await repository.adminUserById(ctx.params.id);
			await deleteAdminUser(ctx.params.id);
			await recordAdminAudit({
				actor: user,
				action: "admin_user.delete",
				resourceType: "admin_user",
				resourceId: ctx.params.id,
				summary: `Deleted user ${target?.username ?? ctx.params.id}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse({ deleted: true });
		} catch (error) {
			const message = error instanceof Error ? error.message : "Unable to delete user";
			return jsonResponse({ error: message }, message === "Admin user not found" ? 404 : 400);
		}
	});

	app.post("/_burrowgate/api/admin/users/:id/reset-password", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const forbidden = requireAdministrator(user);
		if (forbidden) return forbidden;
		try {
			const body = (await ctx.req.json()) as { password?: unknown };
			await resetAdminUserPassword(ctx.params.id, body.password);
			const target = await repository.adminUserById(ctx.params.id);
			await recordAdminAudit({
				actor: user,
				action: "admin_user.reset_password",
				resourceType: "admin_user",
				resourceId: ctx.params.id,
				summary: `Reset password for user ${target?.username ?? ctx.params.id}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse({ ok: true });
		} catch (error) {
			const message = error instanceof Error ? error.message : "Unable to reset password";
			return jsonResponse({ error: message }, message === "Admin user not found" ? 404 : 400);
		}
	});

	app.post("/_burrowgate/api/admin/users/:id/totp/reset", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const forbidden = requireAdministrator(user);
		if (forbidden) return forbidden;
		try {
			await resetAdminUserTotp(ctx.params.id);
			const target = await repository.adminUserById(ctx.params.id);
			await recordAdminAudit({
				actor: user,
				action: "admin_user.reset_totp",
				resourceType: "admin_user",
				resourceId: ctx.params.id,
				summary: `Reset two-factor authentication for user ${target?.username ?? ctx.params.id}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse({ ok: true });
		} catch (error) {
			const message = error instanceof Error ? error.message : "Unable to reset two-factor authentication";
			return jsonResponse({ error: message }, message === "Admin user not found" ? 404 : 400);
		}
	});

	app.get("/_burrowgate/api/admin/audit-log", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const forbidden = requireAdministrator(user);
		if (forbidden) return forbidden;
		const url = new URL(ctx.req.url);
		return jsonResponse(
			await pagedAdminAuditLog({
				page: integerParam(url, "page", 1, 1, 1_000_000),
				pageSize: integerParam(url, "pageSize", config.adminPageSize, 10, 200),
				...(stringParam(url, "search") ? { search: stringParam(url, "search") } : {}),
				...(stringParam(url, "actorUserId") ? { actorUserId: stringParam(url, "actorUserId") } : {}),
				...(stringParam(url, "action") ? { action: stringParam(url, "action") } : {}),
				...(stringParam(url, "resourceType") ? { resourceType: stringParam(url, "resourceType") } : {}),
				...(stringParam(url, "resourceId") ? { resourceId: stringParam(url, "resourceId") } : {}),
				...(numberParam(url, "since") !== undefined ? { since: numberParam(url, "since") } : {}),
				...(numberParam(url, "until") !== undefined ? { until: numberParam(url, "until") } : {}),
				sortBy: enumParam(url, "sortBy", ["created_at", "action", "actor_username", "resource_type"] as const, "created_at")!,
				sortDirection: sortDirection(url),
			}),
		);
	});

	app.post("/_burrowgate/api/admin/audit-log/purge", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const forbidden = requireAdministrator(user);
		if (forbidden) return forbidden;
		try {
			const body = (await ctx.req.json()) as { olderThanDays?: unknown; all?: unknown };
			const purged = await purgeAdminAuditLog(user, getClientIp(ctx) ?? "unknown", {
				all: body.all === true,
				...(body.all === true ? {} : { olderThanDays: Number(body.olderThanDays) }),
			});
			return jsonResponse({ purged });
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to purge audit log" }, 400);
		}
	});

	app.post("/_burrowgate/api/admin/logout", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		for (const token of adminSessionTokens(ctx.req)) {
			await repository.deleteAdmin(await sha256Hex(token));
		}
		const response = jsonResponse({ loggedOut: true });
		const secure = secureCookieForRequest(ctx.req);
		for (const name of adminCookieNames) {
			response.headers.append(
				"set-cookie",
				serializeCookie(name, "", {
					secure: name === adminCookieName(true) ? true : secure && name === adminCookieName(secure),
					maxAge: 0,
					sameSite: "Strict",
				}),
			);
		}
		return response;
	});
}
