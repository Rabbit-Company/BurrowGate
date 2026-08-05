import { Web } from "@rabbit-company/web";
import { logger } from "@rabbit-company/web-middleware/logger";
import { rateLimit } from "@rabbit-company/web-middleware/rate-limit";
import { getClientIp, ipExtract } from "@rabbit-company/web-middleware/ip-extract";
import { challengeRegistry } from "./challenges/index.ts";
import { config, requestIsSecure } from "./config.ts";
import { migrate } from "./db/migrate.ts";
import { repository } from "./db/repository.ts";
import { registerAdminRoutes } from "./routes/admin-routes.ts";
import { registerAcmeRoutes } from "./routes/acme-routes.ts";
import { registerChallengeRoutes } from "./routes/challenge-routes.ts";
import { registerAccessRoutes } from "./routes/access-routes.ts";
import { createFlow } from "./services/challenge-service.ts";
import { recordEvent } from "./services/event-service.ts";
import { siteErrorResponse } from "./services/error-response-service.ts";
import { evaluateIp } from "./services/ip-rule-service.ts";
import { runMaintenance, startMaintenance } from "./services/maintenance-service.ts";
import { geoIpStatus, initializeGeoIp, startGeoIpRetry } from "./services/geoip-service.ts";
import { initializeRuntimeSecrets } from "./services/runtime-bootstrap-service.ts";
import { proxyRequest, type OriginAccessStatus } from "./services/proxy-service.ts";
import { findAccessSession, userAgentHash } from "./services/session-service.ts";
import { resolveSiteForHost, seedDefaultSite } from "./services/site-service.ts";
import { resolveRoutePolicy } from "./services/route-policy-service.ts";
import { appendRateLimitHeaders, applyRouteRateLimit } from "./services/rate-limit-service.ts";
import {
	accessIdentityCookieNames,
	accessIdentitySetCookies,
	accessSettingsForSite,
	authenticatedAccessUser,
	clearAccessIdentityCookies,
} from "./services/access-list-service.ts";
import { siteHostname } from "./services/certificate-service.ts";
import { TlsListenerManager } from "./services/tls-listener-service.ts";
import type { GatewayState } from "./types.ts";
import { appendSetCookies, jsonResponse, normalizeHost, requestHost } from "./utils/http.ts";
import { Logger } from "./logger.ts";
import { startBandwidthMetrics } from "./services/bandwidth-service.ts";
import { startStreamMonitoring } from "./services/stream-monitoring-service.ts";
import { streamProxyManager } from "./services/stream-proxy-service.ts";
import { registerStreamAdminRoutes } from "./routes/stream-admin-routes.ts";
import { OPENMETRICS_PATH, openMetricsResponse } from "./services/openmetrics-service.ts";
import { originHealthManager } from "./services/origin-health-service.ts";

await initializeRuntimeSecrets();
await migrate();
await initializeGeoIp();
startGeoIpRetry();
await seedDefaultSite();
await originHealthManager.initialize();
await runMaintenance();
startMaintenance();
originHealthManager.start();
startBandwidthMetrics();
startStreamMonitoring();

if (config.http.enabled && config.cookieSecureMode === "always") {
	Logger.warn(
		"[BurrowGate] BG_COOKIE_SECURE=true/always disables admin and visitor sessions over HTTP. Use BG_COOKIE_SECURE=auto when any protected site must remain available through HTTP.",
	);
}
if (config.openMetrics.enabled && !config.openMetrics.token) {
	Logger.warn(`[BurrowGate] ${OPENMETRICS_PATH} is enabled without BG_OPENMETRICS_TOKEN; restrict it with network policy or configure a bearer token.`);
}

const app = new Web<GatewayState>();
app.use(ipExtract(config.proxyPreset));
app.use(
	logger({
		logger: Logger,
		preset: "standard",
		excludePaths: [
			"/_burrowgate/static/favicon.svg",
			"/_burrowgate/static/burrowgate.css",
			"/_burrowgate/static/pow-worker.js",
			"/_burrowgate/static/world.svg",
			...(config.openMetrics.enabled ? [OPENMETRICS_PATH] : []),
		],
	}),
);
app.use("/_burrowgate/api/challenge", rateLimit({ windowMs: 60_000, max: 30, headers: true }));
app.onError((error) => {
	Logger.error("Error", error);
	return jsonResponse({ error: "BurrowGate internal error" }, 500);
});

registerAcmeRoutes(app);
registerChallengeRoutes(app);
registerAccessRoutes(app);
registerAdminRoutes(app);
registerStreamAdminRoutes(app);
if (config.openMetrics.enabled) app.get(OPENMETRICS_PATH, (ctx) => openMetricsResponse(ctx.req));
app.get("/_burrowgate/health", () => {
	const geoip = geoIpStatus();
	return jsonResponse({
		status: "ok",
		challengeProviders: challengeRegistry.names(),
		geoip: { enabled: geoip.enabled, available: geoip.available },
	});
});

async function gateway(ctx: any): Promise<Response> {
	const started = performance.now();
	const request: Request = ctx.req;
	const host = normalizeHost(requestHost(request));
	const site = await resolveSiteForHost(host);
	if (!site) return jsonResponse({ error: `No BurrowGate site is configured for ${host}` }, 421);

	const ip = getClientIp(ctx) ?? "unknown";
	const url = new URL(request.url);
	const eventBase: {
		siteId: string;
		ip: string;
		method: string;
		path: string;
		countryCode?: string | null;
	} = {
		siteId: site.id,
		ip,
		method: request.method,
		path: url.pathname + url.search,
	};

	if (!requestIsSecure(request) && config.https.enabled) {
		const tlsSettings = await repository.ensureTlsSettings(site.id);
		if (tlsSettings.force_https === 1 && tlsSettings.mode !== "disabled") {
			const certificate = await repository.certificateBySite(site.id);
			if (certificate?.status === "active" && Number(certificate.expires_at ?? 0) > Date.now()) {
				const port = config.https.publicPort === 443 ? "" : `:${config.https.publicPort}`;
				const location = `https://${siteHostname(site)}${port}${url.pathname}${url.search}`;
				return new Response(null, { status: 308, headers: { location, "cache-control": "no-store" } });
			}
		}
	}

	if (originHealthManager.isMaintenanceMode(site.id)) {
		await recordEvent({
			...eventBase,
			sessionId: null,
			status: 503,
			decision: "origin-unhealthy",
			latencyMs: Math.round(performance.now() - started),
		});
		return siteErrorResponse(
			site,
			request,
			{
				status: 503,
				code: "origin_unhealthy",
				error: "Protected origin is temporarily unavailable",
				clientIp: ip,
				reason: "BurrowGate is online, but the configured origin did not pass its health checks.",
				retryAfterSeconds: Number(site.health_check_interval_seconds ?? 30),
			},
			{ "retry-after": String(site.health_check_interval_seconds ?? 30), "x-burrowgate-error-code": "origin_unhealthy" },
		);
	}

	const ipRule = await evaluateIp(site, ip);
	eventBase.countryCode = ipRule.countryCode;
	if (ipRule.action === "block") {
		await recordEvent({ ...eventBase, sessionId: null, status: 403, decision: "blocked", latencyMs: Math.round(performance.now() - started) });
		return siteErrorResponse(site, request, {
			status: 403,
			code: "network_blocked",
			error: "Access blocked by BurrowGate",
			clientIp: ip,
			reason: ipRule.reason || "This request was blocked by network policy.",
		});
	}

	const route = await resolveRoutePolicy(site, request.method, url.pathname);
	if (route.accessMode === "block") {
		await recordEvent({ ...eventBase, sessionId: null, status: 403, decision: "route-blocked", latencyMs: Math.round(performance.now() - started) });
		return siteErrorResponse(site, request, {
			status: 403,
			code: "route_blocked",
			error: "This route is blocked by BurrowGate",
			clientIp: ip,
			routePolicy: route.policy?.name,
			reason: route.policy?.name ? `Blocked by route policy ${route.policy.name}.` : "This route is not available.",
		});
	}
	const accessSettings = await accessSettingsForSite(site.id);
	const accessAuthenticationEnabled = accessSettings.enabled === 1;

	// A session is required for challenge-protected routes, access-list login,
	// and optionally as the route rate-limit identity.
	const needsSession =
		accessAuthenticationEnabled || route.accessMode === "challenge" || ipRule.action === "challenge" || route.policy?.rate_limit_key_mode === "session-or-ip";
	const candidateSession = needsSession ? await findAccessSession(request, site, ip) : null;

	const effectiveAccess = ipRule.action === "allow" ? "bypass" : ipRule.action === "challenge" ? "challenge" : route.accessMode;
	const session = effectiveAccess === "challenge" || accessAuthenticationEnabled ? candidateSession : null;

	if ((effectiveAccess === "challenge" || accessAuthenticationEnabled) && !session) {
		if (!["GET", "HEAD"].includes(request.method)) {
			const flow = await createFlow(site, url.pathname + url.search, ip, await userAgentHash(request), route.challengePolicy);
			const verificationUrl = `/_burrowgate/verify?flow=${encodeURIComponent(flow.id)}`;
			await recordEvent({ ...eventBase, sessionId: null, status: 428, decision: "challenge-required", latencyMs: Math.round(performance.now() - started) });
			const headers = new Headers();
			headers.set("burrowgate-verification", verificationUrl);
			return appendSetCookies(
				siteErrorResponse(
					site,
					request,
					{
						status: 428,
						code: "verification_required",
						error: "Verification required before replaying this request",
						clientIp: ip,
						routePolicy: route.policy?.name,
						reason: "Complete verification before sending this request again.",
						verificationUrl,
					},
					headers,
				),
				accessAuthenticationEnabled ? clearAccessIdentityCookies(request) : [],
			);
		}
		const flow = await createFlow(site, url.pathname + url.search, ip, await userAgentHash(request), route.challengePolicy);
		await recordEvent({ ...eventBase, sessionId: null, status: 302, decision: "challenge-required", latencyMs: Math.round(performance.now() - started) });
		return appendSetCookies(
			new Response(null, {
				status: 302,
				headers: {
					location: `/_burrowgate/verify?flow=${encodeURIComponent(flow.id)}`,
					"cache-control": "no-store",
				},
			}),
			accessAuthenticationEnabled ? clearAccessIdentityCookies(request) : [],
		);
	}

	const accessUser = accessAuthenticationEnabled ? await authenticatedAccessUser(site.id, session) : null;
	if (accessAuthenticationEnabled && !accessUser) {
		const loginUrl = `/_burrowgate/access/login?return=${encodeURIComponent(url.pathname + url.search)}`;
		await recordEvent({
			...eventBase,
			sessionId: session?.id ?? null,
			status: request.method === "GET" || request.method === "HEAD" ? 302 : 428,
			decision: "access-login-required",
			latencyMs: Math.round(performance.now() - started),
		});
		if (["GET", "HEAD"].includes(request.method)) {
			return appendSetCookies(
				new Response(null, { status: 302, headers: { location: loginUrl, "cache-control": "no-store" } }),
				clearAccessIdentityCookies(request),
			);
		}
		return appendSetCookies(
			siteErrorResponse(
				site,
				request,
				{
					status: 428,
					code: "access_login_required",
					error: "Sign-in required before replaying this request",
					clientIp: ip,
					routePolicy: route.policy?.name,
					reason: "Sign in to BurrowGate before sending this request again.",
					verificationUrl: loginUrl,
				},
				{ "burrowgate-login": loginUrl },
			),
			clearAccessIdentityCookies(request),
		);
	}

	const rateLimit = await applyRouteRateLimit(route.policy, request, ip, candidateSession);
	if (rateLimit.limited) {
		await recordEvent({
			...eventBase,
			sessionId: candidateSession?.id ?? null,
			status: 429,
			decision: "rate-limited",
			latencyMs: Math.round(performance.now() - started),
		});
		return siteErrorResponse(
			site,
			request,
			{
				status: 429,
				code: "rate_limited",
				error: "Too many requests",
				clientIp: ip,
				routePolicy: route.policy?.name,
				reason: "The request rate limit for this route was exceeded.",
				retryAfterSeconds: rateLimit.retryAfterSeconds,
			},
			rateLimit.headers,
		);
	}

	const accessStatus: OriginAccessStatus = accessAuthenticationEnabled
		? "verified"
		: ipRule.action === "allow"
			? "allowlisted"
			: effectiveAccess === "bypass"
				? "bypass"
				: "verified";
	const decision = accessUser
		? "proxied-authenticated"
		: accessStatus === "allowlisted"
			? "allowlisted"
			: accessStatus === "bypass"
				? "proxied-unprotected"
				: "proxied";

	try {
		let response = await proxyRequest(
			request,
			site,
			ip,
			session,
			accessStatus,
			accessUser?.username ?? null,
			accessSettings.send_username_to_upstream === 1,
			eventBase.countryCode ?? null,
		);
		if (accessUser && session && accessSettings.send_username_to_upstream === 1) {
			response = appendSetCookies(response, await accessIdentitySetCookies(request, site, session, accessUser.username));
		} else if (accessIdentityCookieNames.some((name) => request.headers.get("cookie")?.includes(`${name}=`))) {
			response = appendSetCookies(response, clearAccessIdentityCookies(request));
		}
		await recordEvent({ ...eventBase, sessionId: session?.id ?? null, status: response.status, decision, latencyMs: Math.round(performance.now() - started) });
		return appendRateLimitHeaders(response, rateLimit.headers);
	} catch (error) {
		await recordEvent({
			...eventBase,
			sessionId: session?.id ?? null,
			status: 502,
			decision: "origin-error",
			latencyMs: Math.round(performance.now() - started),
		});
		Logger.error("Origin proxy failed", { error });
		return siteErrorResponse(
			site,
			request,
			{
				status: 502,
				code: "origin_unavailable",
				error: "Protected origin is unavailable",
				clientIp: ip,
				routePolicy: route.policy?.name,
				reason: "BurrowGate could not connect to the configured origin.",
			},
			rateLimit.headers,
		);
	}
}

for (const method of ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] as const) {
	app.addRoute(method, "/", gateway);
	app.addRoute(method, "/*", gateway);
}

const listenerManager = new TlsListenerManager(app);
await listenerManager.start();
await streamProxyManager.start();
