import { BURROWGATE_SESSION_ASSERTION_HEADER, BurrowGateClient, BurrowGateError } from "../../packages/burrowgate-auth/src/mod.ts";
import { demoConfig } from "./config.ts";

let introspectionRequests = 0;
const auth = new BurrowGateClient({
	baseUrl: demoConfig.burrowGateUrl,
	siteId: demoConfig.frontendSiteId,
	verificationToken: demoConfig.verificationToken,
	cacheTtlMs: demoConfig.cacheTtlMs,
	maxCacheEntries: 1_000,
	fetch: async (input, init) => {
		introspectionRequests += 1;
		return await fetch(input, init);
	},
});

function corsHeaders(request: Request): Headers {
	const origin = request.headers.get("origin");
	const headers = new Headers({
		vary: "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
		"access-control-allow-methods": "GET, OPTIONS",
		"access-control-allow-headers": `${BURROWGATE_SESSION_ASSERTION_HEADER}, Content-Type`,
		"access-control-expose-headers": "X-Demo-Authentication-Cache",
		"access-control-max-age": "600",
	});
	if (origin && demoConfig.allowedFrontendOrigins.includes(origin)) headers.set("access-control-allow-origin", origin);
	return headers;
}

function originAllowed(request: Request): boolean {
	const origin = request.headers.get("origin");
	return !origin || demoConfig.allowedFrontendOrigins.includes(origin);
}

function json(request: Request, body: unknown, status = 200): Response {
	const headers = corsHeaders(request);
	headers.set("content-type", "application/json; charset=utf-8");
	headers.set("cache-control", "no-store");
	return new Response(JSON.stringify(body, null, 2), { status, headers });
}

export const backendServer = Bun.serve({
	port: demoConfig.backendPort,
	async fetch(request) {
		const url = new URL(request.url);
		if (!originAllowed(request)) {
			console.warn(`[cross-site-auth] Rejected CORS origin ${request.headers.get("origin")}; allowed origins: ${demoConfig.allowedFrontendOrigins.join(", ")}`);
			return json(request, { error: "This frontend origin is not allowed", allowedOrigins: demoConfig.allowedFrontendOrigins }, 403);
		}
		if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(request) });
		if (request.method === "GET" && url.pathname === "/health") return json(request, { status: "ok", service: "backend" });
		if (request.method !== "GET" || !["/api/me", "/api/private-data"].includes(url.pathname)) {
			return json(request, { error: "Not found" }, 404);
		}

		try {
			const session = await auth.authenticate(request);
			if (!session) return json(request, { error: "A valid BurrowGate session assertion is required" }, 401);
			return json(request, {
				message: url.pathname === "/api/me" ? "The backend verified this identity." : "This is protected application data.",
				user: session.user,
				session: {
					id: session.sessionId,
					authenticatedAt: new Date(session.authenticatedAt).toISOString(),
					expiresAt: new Date(session.expiresAt).toISOString(),
					assertionExpiresAt: new Date(session.assertionExpiresAt).toISOString(),
				},
				diagnostics: {
					introspectionRequests,
					cacheEntries: auth.cacheSize,
					cacheTtlMs: auth.cacheTtlMs,
				},
			});
		} catch (error) {
			console.error("[cross-site-auth] Authentication failed", error);
			return json(
				request,
				{
					error: "The backend could not contact or authenticate to BurrowGate",
					detail: error instanceof BurrowGateError ? error.message : "Unexpected authentication error",
				},
				503,
			);
		}
	},
});

console.log(`[cross-site-auth] Backend origin: http://127.0.0.1:${backendServer.port}`);
console.log(`[cross-site-auth] API through BurrowGate: ${demoConfig.backendPublicOrigin}`);
console.log(`[cross-site-auth] Allowed browser origins: ${demoConfig.allowedFrontendOrigins.join(", ")}`);
