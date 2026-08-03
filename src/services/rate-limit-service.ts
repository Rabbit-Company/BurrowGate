import { Algorithm, createRateLimiter } from "@rabbit-company/web-middleware/rate-limit";
import type { AccessSessionRecord, RoutePolicyRecord } from "../types.ts";
import { sha256Hex } from "../utils/crypto.ts";
import { jsonResponse } from "../utils/http.ts";

interface LimiterResult {
	limited: boolean;
	limit: number;
	remaining: number;
	reset: number;
	window?: number;
}

interface CachedLimiter {
	signature: string;
	limiter: ReturnType<typeof createRateLimiter>;
}

export interface RouteRateLimitResult {
	limited: boolean;
	headers: Headers;
	response: Response | null;
}

const limiters = new Map<string, CachedLimiter>();

function algorithmFor(policy: RoutePolicyRecord): Algorithm {
	switch (policy.rate_limit_algorithm) {
		case "sliding-window":
			return Algorithm.SLIDING_WINDOW;
		case "token-bucket":
			return Algorithm.TOKEN_BUCKET;
		default:
			return Algorithm.FIXED_WINDOW;
	}
}

function limiterSignature(policy: RoutePolicyRecord): string {
	return JSON.stringify([
		policy.rate_limit_algorithm,
		Number(policy.rate_limit_window_ms),
		Number(policy.rate_limit_max),
		Number(policy.rate_limit_refill_rate),
		Number(policy.rate_limit_refill_interval_ms),
		Number(policy.rate_limit_precision_ms),
	]);
}

function limiterFor(policy: RoutePolicyRecord): ReturnType<typeof createRateLimiter> {
	const signature = limiterSignature(policy);
	const cached = limiters.get(policy.id);
	if (cached?.signature === signature) return cached.limiter;
	cached?.limiter.clear();

	const limiter = createRateLimiter({
		algorithm: algorithmFor(policy),
		window: Number(policy.rate_limit_window_ms),
		max: Number(policy.rate_limit_max),
		refillRate: Number(policy.rate_limit_refill_rate),
		refillInterval: Number(policy.rate_limit_refill_interval_ms),
		precision: Number(policy.rate_limit_precision_ms),
		enableCleanup: true,
		cleanupInterval: Math.max(1_000, Math.min(Number(policy.rate_limit_window_ms), 60_000)),
	});
	limiters.set(policy.id, { signature, limiter });
	return limiter;
}

export function invalidateRouteRateLimiter(policyId: string): void {
	const cached = limiters.get(policyId);
	cached?.limiter.clear();
	limiters.delete(policyId);
}

async function identifierFor(policy: RoutePolicyRecord, request: Request, ip: string, session: AccessSessionRecord | null): Promise<string> {
	if (policy.rate_limit_key_mode === "session-or-ip" && session) return `session:${session.id}`;
	if (policy.rate_limit_key_mode === "header-or-ip" && policy.rate_limit_key_header) {
		const value = request.headers.get(policy.rate_limit_key_header)?.trim();
		if (value) return `header:${policy.rate_limit_key_header}:${await sha256Hex(value)}`;
	}
	return `ip:${ip}`;
}

function endpointFor(policy: RoutePolicyRecord, request: Request): string {
	const pathname = new URL(request.url).pathname;
	switch (policy.rate_limit_scope) {
		case "path":
			return `${policy.id}:${pathname}`;
		case "method-path":
			return `${policy.id}:${request.method.toUpperCase()}:${pathname}`;
		default:
			return policy.id;
	}
}

function rateHeaders(result: LimiterResult, algorithm: string): Headers {
	const headers = new Headers();
	headers.set("RateLimit-Limit", String(result.limit));
	headers.set("RateLimit-Remaining", String(Math.max(0, result.remaining)));
	headers.set("RateLimit-Reset", String(Math.ceil(result.reset / 1_000)));
	headers.set("RateLimit-Algorithm", algorithm);
	if (result.limited) {
		headers.set("Retry-After", String(Math.max(1, Math.ceil((result.reset - Date.now()) / 1_000))));
	}
	return headers;
}

export async function applyRouteRateLimit(
	policy: RoutePolicyRecord | null,
	request: Request,
	ip: string,
	session: AccessSessionRecord | null,
): Promise<RouteRateLimitResult> {
	if (!policy || policy.rate_limit_enabled !== 1) {
		return { limited: false, headers: new Headers(), response: null };
	}

	const result = limiterFor(policy).check(endpointFor(policy, request), await identifierFor(policy, request, ip, session)) as LimiterResult;
	const headers = rateHeaders(result, policy.rate_limit_algorithm);
	if (!result.limited) return { limited: false, headers, response: null };

	return {
		limited: true,
		headers,
		response: jsonResponse(
			{
				error: "Too many requests",
				policyId: policy.id,
				policyName: policy.name,
				retryAfterSeconds: Math.max(1, Math.ceil((result.reset - Date.now()) / 1_000)),
			},
			429,
			headers,
		),
	};
}

export function appendRateLimitHeaders(response: Response, headers: Headers): Response {
	if ([...headers].length === 0) return response;
	const merged = new Headers(response.headers);
	for (const [name, value] of headers) merged.set(name, value);
	return new Response(response.body, {
		status: response.status,
		statusText: response.statusText,
		headers: merged,
	});
}
