import type { SiteRecord } from "../types.ts";
import { Logger } from "../logger.ts";
import { banIpForChallengeFailures } from "./ip-rule-service.ts";

interface FailureStreak {
	count: number;
	banned: boolean;
	lastFailureAt: number;
}

const STALE_ENTRY_MS = 2 * 60 * 60 * 1_000;

const streaks = new Map<string, FailureStreak>();
let cleanupTimer: ReturnType<typeof setInterval> | null = null;

function key(siteId: string, ip: string): string {
	return `${siteId}-${ip}`;
}

export function recordChallengeFailure(site: SiteRecord, ip: string, now = Date.now()): void {
	if (site.challenge_auto_ban_enabled !== 1 || ip === "unknown") return;
	const mapKey = key(site.id, ip);
	let entry = streaks.get(mapKey);
	if (!entry) {
		entry = { count: 0, banned: false, lastFailureAt: now };
		streaks.set(mapKey, entry);
	}
	entry.count += 1;
	entry.lastFailureAt = now;
	if (!entry.banned && entry.count >= site.challenge_auto_ban_max_failures) {
		entry.banned = true;
		void banIpForChallengeFailures(site, ip, entry.count, site.challenge_auto_ban_seconds).catch((error) => {
			Logger.error(`Unable to auto-ban ${ip} for repeated challenge failures on site ${site.id}`, { error });
		});
	}
}

export function recordChallengeSuccess(site: SiteRecord, ip: string): void {
	streaks.delete(key(site.id, ip));
}

export function pruneStaleChallengeFailureEntries(now = Date.now()): void {
	for (const [mapKey, entry] of streaks) {
		if (now - entry.lastFailureAt > STALE_ENTRY_MS) streaks.delete(mapKey);
	}
}

export function startChallengeFailureBanCleanup(): void {
	if (cleanupTimer) return;
	cleanupTimer = setInterval(() => pruneStaleChallengeFailureEntries(), 10 * 60 * 1_000);
	(cleanupTimer as unknown as { unref?: () => void }).unref?.();
}

export function clearChallengeFailureEntries(): void {
	streaks.clear();
}

export function challengeFailureEntryCount(): number {
	return streaks.size;
}
