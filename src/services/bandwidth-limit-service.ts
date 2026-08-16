import type { SiteRecord } from "../types.ts";
import { Logger } from "../logger.ts";
import { banIpForBandwidthLimit } from "./ip-rule-service.ts";
import type { ResolvedBandwidthLimitPolicy } from "./http-policy-service.ts";

/**
 * Fixed-window per-(route-or-site, ip) byte counter used only to detect a
 * bandwidth-abuse ban trigger. Separate from BandwidthAccumulator (which is
 * per-site, DB-flush-oriented, and drives the reporting dashboard) so this
 * stays a cheap in-memory check with no route dimension added to persisted
 * bandwidth data.
 */
interface WindowEntry {
	windowStart: number;
	bytes: number;
	banned: boolean;
}

const STALE_ENTRY_MS = 2 * 60 * 60 * 1_000;

const windows = new Map<string, WindowEntry>();
let cleanupTimer: ReturnType<typeof setInterval> | null = null;

function key(scopeId: string, ip: string): string {
	return `${scopeId}-${ip}`;
}

export function recordBandwidthLimitBytes(policy: ResolvedBandwidthLimitPolicy, site: SiteRecord, ip: string, bytes: number, now = Date.now()): void {
	if (!policy.enabled || bytes <= 0 || ip === "unknown") return;
	const windowMs = policy.windowSeconds * 1_000;
	const windowStart = Math.floor(now / windowMs) * windowMs;
	const mapKey = key(policy.scopeId, ip);
	let entry = windows.get(mapKey);
	if (!entry || entry.windowStart !== windowStart) {
		entry = { windowStart, bytes: 0, banned: false };
		windows.set(mapKey, entry);
	}
	entry.bytes += bytes;
	if (!entry.banned && entry.bytes > policy.maxBytes) {
		entry.banned = true;
		void banIpForBandwidthLimit(site, ip, policy.maxBytes, policy.windowSeconds, policy.banSeconds).catch((error) => {
			Logger.error(`[BurrowGate] Unable to auto-ban ${ip} for bandwidth limit on site ${site.id}`, { error });
		});
	}
}

export function pruneStaleBandwidthLimitEntries(now = Date.now()): void {
	for (const [mapKey, entry] of windows) {
		if (now - entry.windowStart > STALE_ENTRY_MS) windows.delete(mapKey);
	}
}

export function startBandwidthLimitCleanup(): void {
	if (cleanupTimer) return;
	cleanupTimer = setInterval(() => pruneStaleBandwidthLimitEntries(), 10 * 60 * 1_000);
	(cleanupTimer as unknown as { unref?: () => void }).unref?.();
}

export function clearBandwidthLimitEntries(): void {
	windows.clear();
}

export function bandwidthLimitEntryCount(): number {
	return windows.size;
}
