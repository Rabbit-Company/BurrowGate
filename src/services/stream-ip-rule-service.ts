import { repository } from "../db/repository.ts";
import type { StreamAsnRuleRecord, StreamCountryRuleRecord, StreamDefaultNetworkAction, StreamIpRuleRecord, StreamRecord, StreamRuleAction } from "../types.ts";
import { randomId } from "../utils/crypto.ts";
import { cidrContains, parseCidr, type ParsedCidr } from "../utils/ip.ts";
import { asnForStorage, countryCodeForStorage } from "./geoip-service.ts";
import type { BanDurationSeverity } from "./http-policy-service.ts";
import { notificationService } from "./notification-service.ts";
import type { StreamProtectionMatch } from "./stream-protection-service.ts";

interface CachedStreamIpRule {
	rule: StreamIpRuleRecord;
	cidr: ParsedCidr;
}

interface CachedStreamNetworkRules {
	ipRules: CachedStreamIpRule[];
	countryRules: Map<string, StreamCountryRuleRecord>;
	asnRules: Map<number, StreamAsnRuleRecord>;
}

const ruleCache = new Map<string, Promise<CachedStreamNetworkRules>>();

async function rulesForStream(streamId: string): Promise<CachedStreamNetworkRules> {
	let cached = ruleCache.get(streamId);
	if (!cached) {
		cached = Promise.all([repository.streamRules(streamId), repository.streamCountryRules(streamId), repository.streamAsnRules(streamId)])
			.then(([ipRules, countryRules, asnRules]) => ({
				ipRules: ipRules
					.map((rule) => ({ rule, cidr: parseCidr(rule.network_cidr) }))
					.filter((item): item is CachedStreamIpRule => item.cidr !== null)
					.sort((left, right) => right.cidr.prefix - left.cidr.prefix || right.rule.created_at - left.rule.created_at),
				countryRules: new Map(countryRules.map((rule) => [rule.country_code, rule])),
				asnRules: new Map(asnRules.map((rule) => [rule.asn, rule])),
			}))
			.catch((error) => {
				ruleCache.delete(streamId);
				throw error;
			});
		ruleCache.set(streamId, cached);
	}
	return await cached;
}

export function invalidateStreamNetworkPolicy(streamId: string): void {
	ruleCache.delete(streamId);
}

export type StreamNetworkDecisionSource = "ip-rule" | "asn-rule" | "country-rule" | "country-default" | "ip-default" | "route";

export interface StreamNetworkDecision {
	action: StreamRuleAction | null;
	source: StreamNetworkDecisionSource;
	ipRule: StreamIpRuleRecord | null;
	asnRule: StreamAsnRuleRecord | null;
	countryRule: StreamCountryRuleRecord | null;
	countryCode: string | null;
	asn: number | null;
	asnOrg: string | null;
	reason: string | null;
}

function active<T extends { expires_at: number | null }>(record: T, now: number): boolean {
	return record.expires_at === null || record.expires_at > now;
}

function configuredAction(action: StreamDefaultNetworkAction | null | undefined): StreamRuleAction | null {
	return action && action !== "inherit" ? action : null;
}

export async function evaluateStreamIp(stream: StreamRecord, ip: string): Promise<StreamNetworkDecision> {
	const now = Date.now();
	const rules = await rulesForStream(stream.id);
	const ipRule = ip === "unknown" ? null : (rules.ipRules.find((item) => active(item.rule, now) && cidrContains(item.cidr, ip))?.rule ?? null);
	const { asn, org: asnOrg } = ip === "unknown" ? { asn: null, org: null } : asnForStorage(ip);
	const countryCode = ip === "unknown" ? null : countryCodeForStorage(ip);

	if (ipRule) {
		return {
			action: ipRule.action,
			source: "ip-rule",
			ipRule,
			asnRule: null,
			countryRule: null,
			countryCode,
			asn,
			asnOrg,
			reason: ipRule.reason || `Matched IP rule ${ipRule.network_cidr}`,
		};
	}

	if (asn !== null) {
		const candidateAsnRule = rules.asnRules.get(asn) ?? null;
		const asnRule = candidateAsnRule && active(candidateAsnRule, now) ? candidateAsnRule : null;
		if (asnRule) {
			return {
				action: asnRule.action,
				source: "asn-rule",
				ipRule: null,
				asnRule,
				countryRule: null,
				countryCode,
				asn,
				asnOrg,
				reason: asnRule.reason || `Matched ASN rule AS${asn}`,
			};
		}
	}

	if (countryCode) {
		const candidateCountryRule = rules.countryRules.get(countryCode) ?? null;
		const countryRule = candidateCountryRule && active(candidateCountryRule, now) ? candidateCountryRule : null;
		if (countryRule) {
			return {
				action: countryRule.action,
				source: "country-rule",
				ipRule: null,
				asnRule: null,
				countryRule,
				countryCode,
				asn,
				asnOrg,
				reason: countryRule.reason || `Matched country rule ${countryCode}`,
			};
		}

		const countryDefault = configuredAction(stream.default_country_action);
		if (countryDefault) {
			return {
				action: countryDefault,
				source: "country-default",
				ipRule: null,
				asnRule: null,
				countryRule: null,
				countryCode,
				asn,
				asnOrg,
				reason: `Default country action for ${countryCode}`,
			};
		}
	}

	const ipDefault = configuredAction(stream.default_ip_action);
	if (ipDefault) {
		return {
			action: ipDefault,
			source: "ip-default",
			ipRule: null,
			asnRule: null,
			countryRule: null,
			countryCode,
			asn,
			asnOrg,
			reason: "Default IP action",
		};
	}

	return {
		action: null,
		source: "route",
		ipRule: null,
		asnRule: null,
		countryRule: null,
		countryCode,
		asn,
		asnOrg,
		reason: null,
	};
}

export async function addStreamIpRule(
	streamId: string,
	networkCidr: string,
	action: StreamRuleAction,
	reason: string,
	expiresAt: number | null,
): Promise<StreamIpRuleRecord> {
	if (!parseCidr(networkCidr)) throw new Error("Invalid IP address or CIDR");
	const record: StreamIpRuleRecord = {
		id: randomId("stream_rule"),
		stream_id: streamId,
		network_cidr: networkCidr,
		action,
		reason,
		created_at: Date.now(),
		expires_at: expiresAt,
	};
	await repository.insertStreamRule(record);
	invalidateStreamNetworkPolicy(streamId);
	return record;
}

function humanizeDurationSeconds(totalSeconds: number): string {
	if (totalSeconds < 60) return `${totalSeconds} second${totalSeconds === 1 ? "" : "s"}`;
	if (totalSeconds < 3_600) {
		const minutes = Math.round(totalSeconds / 60);
		return `${minutes} minute${minutes === 1 ? "" : "s"}`;
	}
	if (totalSeconds < 86_400) {
		const hours = Math.round(totalSeconds / 3_600);
		return `${hours} hour${hours === 1 ? "" : "s"}`;
	}
	const days = Math.round(totalSeconds / 86_400);
	return `${days} day${days === 1 ? "" : "s"}`;
}

export async function banStreamIpForProtectionMatch(
	stream: StreamRecord,
	ip: string,
	match: StreamProtectionMatch,
	banDurations: Record<BanDurationSeverity, number>,
): Promise<StreamIpRuleRecord | null> {
	if (ip === "unknown") return null;
	const banSeconds = banDurations[match.severity];
	if (!banSeconds || banSeconds <= 0) return null;
	const existing = await evaluateStreamIp(stream, ip);
	if (existing.source === "ip-rule" && existing.action === "block") return null;
	const reason = `Auto-banned for ${humanizeDurationSeconds(banSeconds)} after matching ${match.rulesetId} rule ${match.ruleId} (${match.category}, ${match.severity}).`;
	const expiresAt = Date.now() + banSeconds * 1_000;
	const rule = await addStreamIpRule(stream.id, ip, "block", reason, expiresAt);
	const summary = `IP ${ip} auto-banned for ${humanizeDurationSeconds(banSeconds)} after matching ${match.rulesetId} rule ${match.ruleId} (${match.category}, ${match.severity}).`;
	await notificationService.recordStreamEvent(stream, "stream_ip_banned", "warning", summary, { ip, reason, ruleId: match.ruleId, expiresAt }, Date.now());
	return rule;
}

function humanizeBytes(bytes: number): string {
	if (bytes < 1_024 * 1_024) return `${Math.round(bytes / 1_024)} KiB`;
	if (bytes < 1_024 * 1_024 * 1_024) return `${(bytes / (1_024 * 1_024)).toFixed(1)} MiB`;
	return `${(bytes / (1_024 * 1_024 * 1_024)).toFixed(1)} GiB`;
}

export async function banStreamIpForBandwidthLimit(
	stream: StreamRecord,
	ip: string,
	protocol: "tcp" | "udp",
	maxBytes: number,
	windowSeconds: number,
	banSeconds: number,
): Promise<StreamIpRuleRecord | null> {
	if (ip === "unknown" || !banSeconds || banSeconds <= 0) return null;
	const existing = await evaluateStreamIp(stream, ip);
	if (existing.source === "ip-rule" && existing.action === "block") return null;
	const reason = `Auto-banned for ${humanizeDurationSeconds(banSeconds)} after exceeding ${humanizeBytes(maxBytes)} of ${protocol.toUpperCase()} traffic in ${windowSeconds}s.`;
	const expiresAt = Date.now() + banSeconds * 1_000;
	const rule = await addStreamIpRule(stream.id, ip, "block", reason, expiresAt);
	const summary = `IP ${ip} auto-banned for ${humanizeDurationSeconds(banSeconds)} after exceeding ${humanizeBytes(maxBytes)} of ${protocol.toUpperCase()} traffic in ${windowSeconds}s.`;
	await notificationService.recordStreamEvent(stream, "stream_ip_banned", "warning", summary, { ip, reason, expiresAt }, Date.now());
	return rule;
}

export async function addStreamCountryRule(
	streamId: string,
	countryCodeInput: string,
	action: StreamRuleAction,
	reason: string,
	expiresAt: number | null,
): Promise<StreamCountryRuleRecord> {
	const countryCode = countryCodeInput.trim().toUpperCase();
	if (!/^[A-Z]{2}$/u.test(countryCode)) throw new Error("Country code must contain two letters");
	const existing = await repository.streamCountryRuleByCode(streamId, countryCode);
	if (existing && active(existing, Date.now())) {
		throw new Error(`An active rule for ${countryCode} already exists`);
	}
	if (existing) await repository.deleteStreamCountryRuleForStream(existing.id, streamId);
	const record: StreamCountryRuleRecord = {
		id: randomId("stream_country_rule"),
		stream_id: streamId,
		country_code: countryCode,
		action,
		reason,
		created_at: Date.now(),
		expires_at: expiresAt,
	};
	await repository.insertStreamCountryRule(record);
	invalidateStreamNetworkPolicy(streamId);
	return record;
}

export async function addStreamAsnRule(
	streamId: string,
	asnInput: unknown,
	action: StreamRuleAction,
	reason: string,
	expiresAt: number | null,
): Promise<StreamAsnRuleRecord> {
	const asn = Number(asnInput);
	if (!Number.isInteger(asn) || asn <= 0) throw new Error("ASN must be a positive whole number");
	const existing = await repository.streamAsnRuleByAsn(streamId, asn);
	if (existing && active(existing, Date.now())) {
		throw new Error(`An active rule for AS${asn} already exists`);
	}
	if (existing) await repository.deleteStreamAsnRuleForStream(existing.id, streamId);
	const record: StreamAsnRuleRecord = {
		id: randomId("stream_asn_rule"),
		stream_id: streamId,
		asn,
		action,
		reason,
		created_at: Date.now(),
		expires_at: expiresAt,
	};
	await repository.insertStreamAsnRule(record);
	invalidateStreamNetworkPolicy(streamId);
	return record;
}
