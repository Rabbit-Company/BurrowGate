import { Web } from "@rabbit-company/web";
import { logger } from "@rabbit-company/web-middleware/logger";
import { rateLimit } from "@rabbit-company/web-middleware/rate-limit";
import { IP_EXTRACTION_PRESETS, getClientIp, ipExtract, type IpExtractionPreset } from "@rabbit-company/web-middleware/ip-extract";
import { challengeRegistry } from "./challenges/index.ts";
import { config, requestIsSecure } from "./config.ts";
import { migrate } from "./db/migrate.ts";
import { repository } from "./db/repository.ts";
import { registerAdminRoutes } from "./routes/admin-routes.ts";
import { registerAcmeRoutes } from "./routes/acme-routes.ts";
import { registerChallengeRoutes } from "./routes/challenge-routes.ts";
import { registerAccessRoutes } from "./routes/access-routes.ts";
import { createFlow } from "./services/challenge-service.ts";
import { recordEvent, refererFields } from "./services/event-service.ts";
import { resolveRequestId, siteErrorResponse } from "./services/error-response-service.ts";
import { banIpForProtectionMatch, formatBanExpiry } from "./services/ip-rule-service.ts";
import { resolveNetworkDecision } from "./services/route-ip-rule-service.ts";
import { runMaintenance, startMaintenance } from "./services/maintenance-service.ts";
import { geoIpStatus, initializeGeoIp, startGeoIpRetry } from "./services/geoip-service.ts";
import { initializeRuntimeSecrets } from "./services/runtime-bootstrap-service.ts";
import { ensureBootstrapAdministrator } from "./services/admin-user-service.ts";
import { proxyRequest, RequestBodyTooLargeError, type OriginAccessStatus } from "./services/proxy-service.ts";
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
	resolveApiTokenAccess,
} from "./services/access-list-service.ts";
import { siteHostname } from "./services/certificate-service.ts";
import { TlsListenerManager } from "./services/tls-listener-service.ts";
import type { GatewayState } from "./types.ts";
import { appendSetCookies, jsonResponse, normalizeHost, requestHost } from "./utils/http.ts";
import { Logger } from "./logger.ts";
import { meteredBody, recordBandwidth, startBandwidthMetrics } from "./services/bandwidth-service.ts";
import { recordBandwidthLimitBytes, startBandwidthLimitCleanup } from "./services/bandwidth-limit-service.ts";
import { startStreamMonitoring } from "./services/stream-monitoring-service.ts";
import { streamProxyManager } from "./services/stream-proxy-service.ts";
import { registerStreamAdminRoutes } from "./routes/stream-admin-routes.ts";
import { registerNotificationAdminRoutes } from "./routes/notification-admin-routes.ts";
import { OPENMETRICS_PATH, openMetricsResponse } from "./services/openmetrics-service.ts";
import { originHealthManager } from "./services/origin-health-service.ts";
import { streamHealthManager } from "./services/stream-health-service.ts";
import { connectivityMonitor } from "./services/connectivity-monitor-service.ts";
import { notificationService } from "./services/notification-service.ts";
import { loadBalancer } from "./services/load-balancer-service.ts";
import { isBodyCaptureActive, requestLimitViolation } from "./services/http-policy-service.ts";
import { tapBodyForCapture, type CapturedBody } from "./services/body-capture-service.ts";
import { staticAssetCache } from "./services/static-cache-service.ts";
import {
	inspectManagedRequest,
	type ManagedProtectionMatch,
	type ManagedProtectionSeverity,
	type ManagedProtectionStatus,
} from "./services/managed-protection-service.ts";
import { loadManagedRuleSets } from "./services/managed-ruleset-loader.ts";
import { loadStreamRuleSets } from "./services/stream-ruleset-loader.ts";

await initializeRuntimeSecrets();
await migrate();
await ensureBootstrapAdministrator();
await initializeGeoIp();
startGeoIpRetry();
await seedDefaultSite();
await loadManagedRuleSets();
await loadStreamRuleSets();
await loadBalancer.initialize();
await originHealthManager.initialize();
await streamHealthManager.initialize();
await runMaintenance();
startMaintenance();
originHealthManager.start();
streamHealthManager.start();
connectivityMonitor.start();
notificationService.start();
startBandwidthMetrics();
startBandwidthLimitCleanup();
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
const clientIpExtractors = new Map<IpExtractionPreset, ReturnType<typeof ipExtract>>(
	(Object.keys(IP_EXTRACTION_PRESETS) as IpExtractionPreset[]).map((preset) => [preset, ipExtract(preset)]),
);

function isDashboardRequest(request: Request): boolean {
	const path = new URL(request.url).pathname;
	return (
		path === "/_burrowgate/admin" ||
		path.startsWith("/_burrowgate/admin/") ||
		path === "/_burrowgate/api/admin" ||
		path.startsWith("/_burrowgate/api/admin/") ||
		["/_burrowgate/static/admin.js", "/_burrowgate/static/streams-admin.js", "/_burrowgate/static/chart.umd.js", "/_burrowgate/static/world.svg"].includes(path)
	);
}

app.use(async (ctx, next) => {
	let preset = config.dashboardProxyPreset;
	if (!isDashboardRequest(ctx.req)) {
		const site = await resolveSiteForHost(normalizeHost(requestHost(ctx.req)));
		if (site) ctx.state.site = site;
		preset = site?.ip_extraction_preset ?? "direct";
	}
	await clientIpExtractors.get(preset)!(ctx, next);
});
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
app.use("/_burrowgate/api/access/session/introspect", rateLimit({ windowMs: 60_000, max: 600, headers: true }));
app.onError((error) => {
	Logger.error("Error", error);
	return jsonResponse({ error: "BurrowGate internal error" }, 500);
});

registerAcmeRoutes(app);
registerChallengeRoutes(app);
registerAccessRoutes(app);
registerAdminRoutes(app);
registerStreamAdminRoutes(app);
registerNotificationAdminRoutes(app);
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
	const site = ctx.state.site ?? (await resolveSiteForHost(host));
	if (!site) return jsonResponse({ error: `No BurrowGate site is configured for ${host}` }, 421);

	const ip = getClientIp(ctx) ?? "unknown";
	const url = new URL(request.url);
	const requestId = resolveRequestId(request);
	const { referer, refererHost } = refererFields(request, site);
	const eventBase: {
		siteId: string;
		ip: string;
		method: string;
		path: string;
		requestId: string;
		referer: string | null;
		refererHost: string | null;
		countryCode?: string | null;
		protectionStatus?: ManagedProtectionStatus | null;
		protectionRuleId?: string | null;
		protectionCategory?: string | null;
		protectionSeverity?: ManagedProtectionSeverity | null;
		protectionRulesetId?: string | null;
		protectionRulesetVersion?: string | null;
		protectionMatches?: ManagedProtectionMatch[] | null;
	} = {
		siteId: site.id,
		ip,
		method: request.method,
		path: url.pathname + url.search,
		requestId,
		referer,
		refererHost,
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
				retryAfterSeconds: Number(site.health_check_interval_seconds ?? 10),
			},
			{ "retry-after": String(site.health_check_interval_seconds ?? 10), "x-burrowgate-error-code": "origin_unhealthy" },
		);
	}

	const route = await resolveRoutePolicy(site, request.method, url.pathname);
	const ipRule = await resolveNetworkDecision(site, route.policy, ip);
	eventBase.countryCode = ipRule.countryCode;
	if (ipRule.action === "block") {
		await recordEvent({ ...eventBase, sessionId: null, status: 403, decision: "blocked", latencyMs: Math.round(performance.now() - started) });
		const retryAfterSeconds = ipRule.expiresAt ? Math.max(1, Math.ceil((ipRule.expiresAt - Date.now()) / 1_000)) : null;
		const baseReason = ipRule.reason || "This request was blocked by network policy.";
		return siteErrorResponse(
			site,
			request,
			{
				status: 403,
				code: "network_blocked",
				error: "Access blocked by BurrowGate",
				clientIp: ip,
				routePolicy: route.policy?.name,
				reason: ipRule.expiresAt ? `${baseReason} This IP address will be automatically unblocked at ${formatBanExpiry(ipRule.expiresAt)}.` : baseReason,
				...(retryAfterSeconds !== null ? { retryAfterSeconds } : {}),
			},
			retryAfterSeconds !== null ? { "retry-after": String(retryAfterSeconds) } : undefined,
		);
	}

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
	const limitViolation = requestLimitViolation(request, route.http.limits);
	if (limitViolation) {
		await recordEvent({
			...eventBase,
			sessionId: null,
			status: limitViolation.status,
			decision: "request-limited",
			latencyMs: Math.round(performance.now() - started),
		});
		return siteErrorResponse(site, request, {
			status: limitViolation.status,
			code: limitViolation.code,
			error: "Request limit exceeded",
			clientIp: ip,
			routePolicy: route.policy?.name,
			reason: limitViolation.message,
		});
	}
	const protection = await inspectManagedRequest(request, route.http.protection);
	if (protection.status !== "disabled") {
		eventBase.protectionStatus = protection.status;
		eventBase.protectionRuleId = protection.primaryMatch?.ruleId ?? null;
		eventBase.protectionCategory = protection.primaryMatch?.category ?? null;
		eventBase.protectionSeverity = protection.primaryMatch?.severity ?? null;
		eventBase.protectionRulesetId = protection.rulesetId;
		eventBase.protectionRulesetVersion = protection.rulesetVersion;
		eventBase.protectionMatches = protection.matches;
	}
	if (protection.status === "blocked") {
		const ban = protection.primaryMatch ? await banIpForProtectionMatch(site, ip, protection.primaryMatch, route.http.banDurations) : null;
		await recordEvent({
			...eventBase,
			sessionId: null,
			status: 403,
			decision: "managed-protection-blocked",
			latencyMs: Math.round(performance.now() - started),
		});
		const retryAfterSeconds = ban?.expires_at ? Math.max(1, Math.ceil((ban.expires_at - Date.now()) / 1_000)) : null;
		const baseReason = "The request matched a managed request-protection rule.";
		return siteErrorResponse(
			site,
			request,
			{
				status: 403,
				code: "managed_request_blocked",
				error: "Request blocked by BurrowGate",
				clientIp: ip,
				routePolicy: route.policy?.name,
				reason: ban?.expires_at ? `${baseReason} This IP address will be automatically unblocked at ${formatBanExpiry(ban.expires_at)}.` : baseReason,
				...(retryAfterSeconds !== null ? { retryAfterSeconds } : {}),
			},
			retryAfterSeconds !== null ? { "retry-after": String(retryAfterSeconds) } : undefined,
		);
	}
	const accessSettings = await accessSettingsForSite(site.id);
	const accessAuthenticationEnabled = accessSettings.enabled === 1;

	// A valid API token authenticates the request outright, skipping both the
	// browser verification challenge and the access-list login form.
	const apiTokenAccess = accessAuthenticationEnabled ? await resolveApiTokenAccess(request, site, ip) : null;

	// A session is required for challenge-protected routes, access-list login,
	// and optionally as the route rate-limit identity.
	const needsSession =
		accessAuthenticationEnabled ||
		route.accessMode === "challenge" ||
		ipRule.action === "challenge" ||
		route.policy?.rate_limit_key_mode === "session-or-ip" ||
		site.load_balancing_affinity !== 0;
	const candidateSession = apiTokenAccess ? apiTokenAccess.session : needsSession ? await findAccessSession(request, site, ip) : null;

	const effectiveAccess = ipRule.action === "allow" ? "bypass" : ipRule.action === "challenge" ? "challenge" : route.accessMode;
	const session = apiTokenAccess ? apiTokenAccess.session : effectiveAccess === "challenge" || accessAuthenticationEnabled ? candidateSession : null;

	if (!apiTokenAccess && (effectiveAccess === "challenge" || accessAuthenticationEnabled) && !session) {
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

	const accessUser = apiTokenAccess ? apiTokenAccess.user : accessAuthenticationEnabled ? await authenticatedAccessUser(site.id, session) : null;
	if (!apiTokenAccess && accessAuthenticationEnabled && !accessUser) {
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
			accessUsername: accessUser?.username ?? null,
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
	const cacheLookup = staticAssetCache.lookup(request, site, route.policy, route.http.cache);
	const cacheStatus = cacheLookup.outcome === "disabled" ? null : cacheLookup.outcome;
	if (cacheLookup.outcome === "hit" && cacheLookup.response) {
		const cached = cacheLookup.response;
		const bodyCaptureActive = isBodyCaptureActive(route.http.bodyCapture);
		const { body: tappedCachedBody, captured: capturedResponseBody } = tapBodyForCapture(
			cached.body,
			cached.headers.get("content-type"),
			bodyCaptureActive ? route.http.bodyCapture.maxResponseBytes : 0,
			cached.headers.get("content-encoding"),
			route.http.bodyCapture.contentTypes,
		);
		const cachedBody = meteredBody(
			tappedCachedBody,
			{ siteId: site.id, ip, countryCode: eventBase.countryCode ?? null, protocol: "http" },
			(bytes) => ({ clientSentBytes: bytes }),
			(context, delta) => {
				recordBandwidth(context, delta);
				recordBandwidthLimitBytes(route.http.bandwidthLimit, site, ip, delta.clientSentBytes ?? 0);
			},
		);
		let response = new Response(cachedBody, { status: cached.status, statusText: cached.statusText, headers: cached.headers });
		if (accessUser && session && accessSettings.send_username_to_upstream === 1) {
			response = appendSetCookies(response, await accessIdentitySetCookies(request, site, session, accessUser.username));
		} else if (accessIdentityCookieNames.some((name) => request.headers.get("cookie")?.includes(`${name}=`))) {
			response = appendSetCookies(response, clearAccessIdentityCookies(request));
		}
		await recordEvent({
			...eventBase,
			sessionId: session?.id ?? null,
			status: response.status,
			decision,
			cacheStatus,
			originId: cacheLookup.originId ?? null,
			accessUsername: accessUser?.username ?? null,
			latencyMs: Math.round(performance.now() - started),
		});
		if (bodyCaptureActive && route.http.bodyCapture.maxResponseBytes > 0) {
			const requestId = eventBase.requestId;
			capturedResponseBody
				.then((captured) => captured && repository.updateEventResponseBody(requestId, captured.text, captured.truncated, captured.contentType))
				.catch((error) => Logger.error("Failed to persist captured response body", { error }));
		}
		return appendRateLimitHeaders(response, rateLimit.headers);
	}
	let selectedOrigin = await loadBalancer.selectOrigin(site, candidateSession, ip);
	if (!selectedOrigin) {
		await recordEvent({
			...eventBase,
			sessionId: session?.id ?? null,
			status: 503,
			decision: "origin-pool-unavailable",
			cacheStatus,
			accessUsername: accessUser?.username ?? null,
			latencyMs: Math.round(performance.now() - started),
		});
		return siteErrorResponse(site, request, {
			status: 503,
			code: "origin_pool_unavailable",
			error: "No origin is available",
			clientIp: ip,
			reason: "Every configured origin is unhealthy, disabled, or draining.",
			retryAfterSeconds: Number(site.health_check_interval_seconds ?? 10),
		});
	}

	try {
		const proxySelectedOrigin = async () =>
			await proxyRequest(
				request,
				site,
				ip,
				session,
				accessStatus,
				accessUser?.username ?? null,
				accessSettings.send_username_to_upstream === 1,
				eventBase.countryCode ?? null,
				selectedOrigin!.origin_url,
				route.http,
			);
		let response: Response;
		let capturedRequestBody: CapturedBody | null = null;
		let capturedResponseBody: Promise<CapturedBody | null> | null = null;
		try {
			const proxied = await proxySelectedOrigin();
			response = proxied.response;
			capturedRequestBody = proxied.capturedRequestBody;
			capturedResponseBody = proxied.capturedResponseBody;
			loadBalancer.clearPassiveFailure(selectedOrigin.id);
		} catch (firstError) {
			if (firstError instanceof RequestBodyTooLargeError) throw firstError;
			loadBalancer.reportPassiveFailure(selectedOrigin.id);
			if (!["GET", "HEAD"].includes(request.method)) throw firstError;
			const replacement = await loadBalancer.selectOrigin(site, candidateSession, ip, { excludeOriginIds: new Set([selectedOrigin.id]) });
			if (!replacement) throw firstError;
			selectedOrigin = replacement;
			const proxied = await proxySelectedOrigin();
			response = proxied.response;
			capturedRequestBody = proxied.capturedRequestBody;
			capturedResponseBody = proxied.capturedResponseBody;
			loadBalancer.clearPassiveFailure(selectedOrigin.id);
		}
		response = staticAssetCache.observeResponse(request, response, cacheLookup, site, route.policy, route.http.cache, selectedOrigin.id);
		if (accessUser && session && accessSettings.send_username_to_upstream === 1) {
			response = appendSetCookies(response, await accessIdentitySetCookies(request, site, session, accessUser.username));
		} else if (accessIdentityCookieNames.some((name) => request.headers.get("cookie")?.includes(`${name}=`))) {
			response = appendSetCookies(response, clearAccessIdentityCookies(request));
		}
		await recordEvent({
			...eventBase,
			sessionId: session?.id ?? null,
			status: response.status,
			decision,
			cacheStatus,
			originId: selectedOrigin.id,
			accessUsername: accessUser?.username ?? null,
			latencyMs: Math.round(performance.now() - started),
			requestBody: capturedRequestBody?.text ?? null,
			requestBodyTruncated: capturedRequestBody?.truncated ?? null,
			requestContentType: capturedRequestBody?.contentType ?? null,
		});
		if (capturedResponseBody) {
			const requestId = eventBase.requestId;
			capturedResponseBody
				.then((captured) => captured && repository.updateEventResponseBody(requestId, captured.text, captured.truncated, captured.contentType))
				.catch((error) => Logger.error("Failed to persist captured response body", { error }));
		}
		return appendRateLimitHeaders(response, rateLimit.headers);
	} catch (error) {
		if (error instanceof RequestBodyTooLargeError) {
			await recordEvent({
				...eventBase,
				sessionId: session?.id ?? null,
				status: 413,
				decision: "request-limited",
				cacheStatus,
				originId: selectedOrigin.id,
				accessUsername: accessUser?.username ?? null,
				latencyMs: Math.round(performance.now() - started),
			});
			return siteErrorResponse(site, request, {
				status: 413,
				code: "request_body_too_large",
				error: "Request limit exceeded",
				clientIp: ip,
				routePolicy: route.policy?.name,
				reason: `The request body exceeds this route's configured limit of ${error.maximumBytes} bytes.`,
			});
		}
		loadBalancer.reportPassiveFailure(selectedOrigin.id);
		await recordEvent({
			...eventBase,
			sessionId: session?.id ?? null,
			status: 502,
			decision: "origin-error",
			cacheStatus,
			originId: selectedOrigin.id,
			accessUsername: accessUser?.username ?? null,
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

async function gatewayWithRequestId(ctx: any): Promise<Response> {
	const requestId = resolveRequestId(ctx.req);
	const response = await gateway(ctx);
	response.headers.set("x-burrowgate-request-id", requestId);
	return response;
}

for (const method of ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] as const) {
	app.addRoute(method, "/", gatewayWithRequestId);
	app.addRoute(method, "/*", gatewayWithRequestId);
}

const listenerManager = new TlsListenerManager(app);
await listenerManager.start();
await streamProxyManager.start();
