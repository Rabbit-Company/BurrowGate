import { repository } from "../db/repository.ts";
import { Logger } from "../logger.ts";
import { normalizeHost } from "../utils/http.ts";
import { randomId } from "../utils/crypto.ts";
import { asnForStorage, countryCodeForStorage } from "./geoip-service.ts";
import { openMetrics } from "./openmetrics-service.ts";
import type { HttpCacheStatus, SiteRecord } from "../types.ts";
import type { ManagedProtectionMatch, ManagedProtectionSeverity, ManagedProtectionStatus } from "./managed-protection-service.ts";

const blockedSiteIds = new Set<string>();

const REFERER_MAX_LENGTH = 2048;
const SAME_SITE_REFERER = "(same site)";

export function refererFields(request: Request, site: SiteRecord): { referer: string | null; refererHost: string | null } {
	const header = request.headers.get("referer");
	if (!header) return { referer: null, refererHost: null };
	const referer = header.length > REFERER_MAX_LENGTH ? header.slice(0, REFERER_MAX_LENGTH) : header;
	let host: string | null;
	try {
		host = normalizeHost(new URL(header).hostname);
	} catch {
		host = null;
	}
	return { referer, refererHost: host ? (host === site.public_host ? SAME_SITE_REFERER : host) : null };
}

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
	asn?: number | null;
	asnOrg?: string | null;
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
	accessUsername?: string | null;
	referer?: string | null;
	refererHost?: string | null;
	botId?: string | null;
	botName?: string | null;
	botCategory?: string | null;
	botVerified?: boolean | null;
	networkPrivacy?: string[] | null;
	requestBody?: string | null;
	requestBodyTruncated?: boolean | null;
	requestContentType?: string | null;
	requestHeaders?: string | null;
	requestHeadersTruncated?: boolean | null;
	responseHeaders?: string | null;
	responseHeadersTruncated?: boolean | null;
}): Promise<void> {
	if (blockedSiteIds.has(input.siteId)) return;
	openMetrics.recordHttpRequest(input);
	if (input.protectionStatus) openMetrics.recordHttpProtectionRequest(input.siteId, input.protectionStatus);
	try {
		const resolvedAsn = input.asn === undefined || input.asnOrg === undefined ? asnForStorage(input.ip) : { asn: input.asn, org: input.asnOrg };
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
			asn: input.asn === undefined ? resolvedAsn.asn : input.asn,
			asn_org: input.asnOrg === undefined ? resolvedAsn.org : input.asnOrg,
			origin_id: input.originId ?? null,
			cache_status: input.cacheStatus ?? null,
			protection_status: input.protectionStatus ?? null,
			protection_rule_id: input.protectionRuleId ?? null,
			protection_category: input.protectionCategory ?? null,
			protection_severity: input.protectionSeverity ?? null,
			protection_ruleset_id: input.protectionRulesetId ?? null,
			protection_ruleset_version: input.protectionRulesetVersion ?? null,
			protection_matches_json: input.protectionMatches?.length ? JSON.stringify(input.protectionMatches) : null,
			access_username: input.accessUsername ?? null,
			referer: input.referer ?? null,
			referer_host: input.refererHost ?? null,
			bot_id: input.botId ?? null,
			bot_name: input.botName ?? null,
			bot_category: input.botCategory ?? null,
			bot_verified: input.botVerified === undefined || input.botVerified === null ? null : input.botVerified ? 1 : 0,
			network_privacy_json: input.networkPrivacy?.length ? JSON.stringify(input.networkPrivacy) : null,
			request_body: input.requestBody ?? null,
			request_body_truncated: input.requestBodyTruncated === undefined || input.requestBodyTruncated === null ? null : input.requestBodyTruncated ? 1 : 0,
			request_content_type: input.requestContentType ?? null,
			response_body: null,
			response_body_truncated: null,
			response_content_type: null,
			request_headers: input.requestHeaders ?? null,
			request_headers_truncated:
				input.requestHeadersTruncated === undefined || input.requestHeadersTruncated === null ? null : input.requestHeadersTruncated ? 1 : 0,
			response_headers: input.responseHeaders ?? null,
			response_headers_truncated:
				input.responseHeadersTruncated === undefined || input.responseHeadersTruncated === null ? null : input.responseHeadersTruncated ? 1 : 0,
			created_at: Date.now(),
		});
	} catch (error) {
		Logger.error("Failed to record request event", { error });
	}
}
