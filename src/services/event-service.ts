import { repository } from "../db/repository.ts";
import { Logger } from "../logger.ts";
import { randomId } from "../utils/crypto.ts";
import { countryCodeForStorage } from "./geoip-service.ts";
import { openMetrics } from "./openmetrics-service.ts";
import type { HttpCacheStatus } from "../types.ts";
import type { ManagedProtectionMatch, ManagedProtectionSeverity, ManagedProtectionStatus } from "./managed-protection-service.ts";

const blockedSiteIds = new Set<string>();

export function blockSiteEvents(siteId: string): void {
	blockedSiteIds.add(siteId);
}

export function resumeSiteEvents(siteId: string): void {
	blockedSiteIds.delete(siteId);
}

export async function recordEvent(input: {
	siteId: string;
	sessionId: string | null;
	ip: string;
	method: string;
	path: string;
	status: number;
	decision: string;
	latencyMs: number;
	countryCode?: string | null;
	originId?: string | null;
	cacheStatus?: HttpCacheStatus | null;
	protectionStatus?: ManagedProtectionStatus | null;
	protectionRuleId?: string | null;
	protectionCategory?: string | null;
	protectionSeverity?: ManagedProtectionSeverity | null;
	protectionRulesetId?: string | null;
	protectionRulesetVersion?: string | null;
	protectionMatches?: ManagedProtectionMatch[] | null;
	requestId?: string | null;
}): Promise<void> {
	if (blockedSiteIds.has(input.siteId)) return;
	openMetrics.recordHttpRequest(input);
	if (input.protectionStatus) openMetrics.recordHttpProtectionRequest(input.siteId, input.protectionStatus);
	try {
		await repository.insertEvent({
			id: input.requestId || randomId("evt"),
			site_id: input.siteId,
			session_id: input.sessionId,
			ip: input.ip,
			method: input.method,
			path: input.path,
			status: input.status,
			decision: input.decision,
			latency_ms: input.latencyMs,
			country_code: input.countryCode === undefined ? countryCodeForStorage(input.ip) : input.countryCode,
			origin_id: input.originId ?? null,
			cache_status: input.cacheStatus ?? null,
			protection_status: input.protectionStatus ?? null,
			protection_rule_id: input.protectionRuleId ?? null,
			protection_category: input.protectionCategory ?? null,
			protection_severity: input.protectionSeverity ?? null,
			protection_ruleset_id: input.protectionRulesetId ?? null,
			protection_ruleset_version: input.protectionRulesetVersion ?? null,
			protection_matches_json: input.protectionMatches?.length ? JSON.stringify(input.protectionMatches) : null,
			created_at: Date.now(),
		});
	} catch (error) {
		Logger.error("Failed to record request event", { error });
	}
}
