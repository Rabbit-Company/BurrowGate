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
import { createFlow } from "./services/challenge-service.ts";
import { recordEvent } from "./services/event-service.ts";
import { evaluateIp } from "./services/ip-rule-service.ts";
import { runMaintenance, startMaintenance } from "./services/maintenance-service.ts";
import { geoIpStatus, initializeGeoIp, startGeoIpRetry } from "./services/geoip-service.ts";
import { initializeRuntimeSecrets } from "./services/runtime-bootstrap-service.ts";
import { proxyRequest, type OriginAccessStatus } from "./services/proxy-service.ts";
import { findAccessSession, userAgentHash } from "./services/session-service.ts";
import { resolveSiteForHost, seedDefaultSite } from "./services/site-service.ts";
import { resolveRoutePolicy } from "./services/route-policy-service.ts";
import { appendRateLimitHeaders, applyRouteRateLimit } from "./services/rate-limit-service.ts";
import { siteHostname } from "./services/certificate-service.ts";
import { TlsListenerManager } from "./services/tls-listener-service.ts";
import type { GatewayState } from "./types.ts";
import { jsonResponse, normalizeHost, requestHost } from "./utils/http.ts";

await initializeRuntimeSecrets();
await migrate();
await initializeGeoIp();
startGeoIpRetry();
await seedDefaultSite();
await runMaintenance();
startMaintenance();

if (config.http.enabled && config.cookieSecureMode === "always") {
	console.warn(
		"[BurrowGate] BG_COOKIE_SECURE=true/always disables admin and visitor sessions over HTTP. Use BG_COOKIE_SECURE=auto when any protected site must remain available through HTTP.",
	);
}

const app = new Web<GatewayState>();
app.use(ipExtract(config.proxyPreset));
app.use(
	logger({
		preset: "standard",
		excludePaths: [
			"/_burrowgate/static/favicon.svg",
			"/_burrowgate/static/burrowgate.css",
			"/_burrowgate/static/pow-worker.js",
			"/_burrowgate/static/world.svg",
		],
	}),
);
app.use("/_burrowgate/api/challenge", rateLimit({ windowMs: 60_000, max: 30, headers: true }));
app.onError((error) => {
	console.error(error);
	return jsonResponse({ error: "BurrowGate internal error" }, 500);
});

registerAcmeRoutes(app);
registerChallengeRoutes(app);
registerAdminRoutes(app);
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
	const eventBase = {
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

	const ipRule = ip === "unknown" ? { action: null, rule: null } : await evaluateIp(site.id, ip);
	if (ipRule.action === "block") {
		await recordEvent({ ...eventBase, sessionId: null, status: 403, decision: "blocked", latencyMs: Math.round(performance.now() - started) });
		return jsonResponse({ error: "Access blocked by BurrowGate", reason: ipRule.rule?.reason }, 403);
	}

	const route = await resolveRoutePolicy(site, request.method, url.pathname);
	if (route.accessMode === "block") {
		await recordEvent({ ...eventBase, sessionId: null, status: 403, decision: "route-blocked", latencyMs: Math.round(performance.now() - started) });
		return jsonResponse({ error: "This route is blocked by BurrowGate", routePolicy: route.policy?.name }, 403);
	}

	// A session is required for challenge-protected routes and can optionally be
	// used as the rate-limit identity. Bypass routes never require the session.
	const needsSession = route.accessMode === "challenge" || ipRule.action === "challenge" || route.policy?.rate_limit_key_mode === "session-or-ip";
	const candidateSession = needsSession ? await findAccessSession(request, site, ip) : null;

	const rateLimit = await applyRouteRateLimit(route.policy, request, ip, candidateSession);
	if (rateLimit.limited) {
		await recordEvent({
			...eventBase,
			sessionId: candidateSession?.id ?? null,
			status: 429,
			decision: "rate-limited",
			latencyMs: Math.round(performance.now() - started),
		});
		return rateLimit.response!;
	}

	const effectiveAccess = ipRule.action === "allow" ? "bypass" : ipRule.action === "challenge" ? "challenge" : route.accessMode;
	const session = effectiveAccess === "challenge" ? candidateSession : null;

	if (effectiveAccess === "challenge" && !session) {
		if (!["GET", "HEAD"].includes(request.method)) {
			const flow = await createFlow(site, url.pathname + url.search, ip, await userAgentHash(request), route.challengePolicy);
			const verificationUrl = `/_burrowgate/verify?flow=${encodeURIComponent(flow.id)}`;
			await recordEvent({ ...eventBase, sessionId: null, status: 428, decision: "challenge-required", latencyMs: Math.round(performance.now() - started) });
			return appendRateLimitHeaders(
				jsonResponse({ error: "Verification required before replaying this request", verificationUrl }, 428, { "burrowgate-verification": verificationUrl }),
				rateLimit.headers,
			);
		}
		const flow = await createFlow(site, url.pathname + url.search, ip, await userAgentHash(request), route.challengePolicy);
		await recordEvent({ ...eventBase, sessionId: null, status: 302, decision: "challenge-required", latencyMs: Math.round(performance.now() - started) });
		return appendRateLimitHeaders(
			new Response(null, {
				status: 302,
				headers: {
					location: `/_burrowgate/verify?flow=${encodeURIComponent(flow.id)}`,
					"cache-control": "no-store",
				},
			}),
			rateLimit.headers,
		);
	}

	const accessStatus: OriginAccessStatus = ipRule.action === "allow" ? "allowlisted" : effectiveAccess === "bypass" ? "bypass" : "verified";
	const decision = accessStatus === "allowlisted" ? "allowlisted" : accessStatus === "bypass" ? "proxied-unprotected" : "proxied";

	try {
		const response = await proxyRequest(request, site, ip, session, accessStatus);
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
		console.error("Origin proxy failed", error);
		return appendRateLimitHeaders(jsonResponse({ error: "Protected origin is unavailable" }, 502), rateLimit.headers);
	}
}

for (const method of ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] as const) {
	app.addRoute(method, "/", gateway);
	app.addRoute(method, "/*", gateway);
}

const listenerManager = new TlsListenerManager(app);
await listenerManager.start();
