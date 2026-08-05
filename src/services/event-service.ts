import { repository } from "../db/repository.ts";
import { Logger } from "../logger.ts";
import { randomId } from "../utils/crypto.ts";
import { countryCodeForStorage } from "./geoip-service.ts";
import { openMetrics } from "./openmetrics-service.ts";

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
}): Promise<void> {
	if (blockedSiteIds.has(input.siteId)) return;
	openMetrics.recordHttpRequest(input);
	try {
		await repository.insertEvent({
			id: randomId("evt"),
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
			created_at: Date.now(),
		});
	} catch (error) {
		Logger.error("Failed to record request event", { error });
	}
}
