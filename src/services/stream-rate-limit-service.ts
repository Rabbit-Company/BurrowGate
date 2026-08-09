import { Algorithm, RateLimiter } from "@rabbit-company/web-middleware/rate-limit";
import type { StreamRecord } from "../types.ts";

interface CachedLimiter {
	signature: string;
	limiter: RateLimiter;
}

export interface StreamRateLimitResult {
	limited: boolean;
	retryAfterSeconds: number;
}

const limiters = new Map<string, CachedLimiter>();

function algorithmFor(record: StreamRecord): Algorithm {
	switch (record.connection_rate_limit_algorithm) {
		case "sliding-window":
			return Algorithm.SLIDING_WINDOW;
		case "token-bucket":
			return Algorithm.TOKEN_BUCKET;
		default:
			return Algorithm.FIXED_WINDOW;
	}
}

function limiterSignature(record: StreamRecord): string {
	return JSON.stringify([
		record.connection_rate_limit_algorithm,
		Number(record.connection_rate_limit_window_ms),
		Number(record.connection_rate_limit_max),
		Number(record.connection_rate_limit_refill_rate),
		Number(record.connection_rate_limit_refill_interval_ms),
		Number(record.connection_rate_limit_precision_ms),
	]);
}

function limiterFor(record: StreamRecord): RateLimiter {
	const signature = limiterSignature(record);
	const cached = limiters.get(record.id);
	if (cached?.signature === signature) return cached.limiter;
	cached?.limiter.clear();

	const limiter = new RateLimiter({
		algorithm: algorithmFor(record),
		window: Number(record.connection_rate_limit_window_ms),
		max: Number(record.connection_rate_limit_max),
		refillRate: Number(record.connection_rate_limit_refill_rate),
		refillInterval: Number(record.connection_rate_limit_refill_interval_ms),
		precision: Number(record.connection_rate_limit_precision_ms),
		enableCleanup: true,
		cleanupInterval: Math.max(1_000, Math.min(Number(record.connection_rate_limit_window_ms), 60_000)),
	});
	limiters.set(record.id, { signature, limiter });
	return limiter;
}

export function invalidateStreamRateLimiter(streamId: string): void {
	const cached = limiters.get(streamId);
	cached?.limiter.clear();
	limiters.delete(streamId);
}

export function checkStreamConnectionRate(record: StreamRecord, ip: string): StreamRateLimitResult {
	if (record.connection_rate_limit_enabled !== 1 || ip === "unknown") return { limited: false, retryAfterSeconds: 0 };
	const result = limiterFor(record).check(record.id, ip);
	return {
		limited: result.limited,
		retryAfterSeconds: result.limited ? Math.max(1, Math.ceil((result.reset - Date.now()) / 1_000)) : 0,
	};
}
