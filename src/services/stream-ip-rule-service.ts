import { repository } from "../db/repository.ts";
import type { StreamCountryRuleRecord, StreamDefaultNetworkAction, StreamIpRuleRecord, StreamRecord, StreamRuleAction } from "../types.ts";
import { randomId } from "../utils/crypto.ts";
import { cidrContains, parseCidr, type ParsedCidr } from "../utils/ip.ts";
import { countryCodeForStorage } from "./geoip-service.ts";
import type { BanDurationSeverity } from "./http-policy-service.ts";
import type { StreamProtectionMatch } from "./stream-protection-service.ts";

interface CachedStreamIpRule {
	rule: StreamIpRuleRecord;
	cidr: ParsedCidr;
}

interface CachedStreamNetworkRules {
	ipRules: CachedStreamIpRule[];
	countryRules: Map<string, StreamCountryRuleRecord>;
}

const ruleCache = new Map<string, Promise<CachedStreamNetworkRules>>();

async function rulesForStream(streamId: string): Promise<CachedStreamNetworkRules> {
	let cached = ruleCache.get(streamId);
	if (!cached) {
		cached = Promise.all([repository.streamRules(streamId), repository.streamCountryRules(streamId)])
			.then(([ipRules, countryRules]) => ({
				ipRules: ipRules
					.map((rule) => ({ rule, cidr: parseCidr(rule.network_cidr) }))
					.filter((item): item is CachedStreamIpRule => item.cidr !== null)
					.sort((left, right) => right.cidr.prefix - left.cidr.prefix || right.rule.created_at - left.rule.created_at),
				countryRules: new Map(countryRules.map((rule) => [rule.country_code, rule])),
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

export type StreamNetworkDecisionSource = "ip-rule" | "country-rule" | "country-default" | "ip-default" | "route";

export interface StreamNetworkDecision {
	action: StreamRuleAction | null;
	source: StreamNetworkDecisionSource;
	ipRule: StreamIpRuleRecord | null;
	countryRule: StreamCountryRuleRecord | null;
	countryCode: string | null;
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

	if (ipRule) {
		return {
			action: ipRule.action,
			source: "ip-rule",
			ipRule,
			countryRule: null,
			countryCode: null,
			reason: ipRule.reason || `Matched IP rule ${ipRule.network_cidr}`,
		};
	}

	const countryCode = ip === "unknown" ? null : countryCodeForStorage(ip);
	if (countryCode) {
		const candidateCountryRule = rules.countryRules.get(countryCode) ?? null;
		const countryRule = candidateCountryRule && active(candidateCountryRule, now) ? candidateCountryRule : null;
		if (countryRule) {
			return {
				action: countryRule.action,
				source: "country-rule",
				ipRule: null,
				countryRule,
				countryCode,
				reason: countryRule.reason || `Matched country rule ${countryCode}`,
			};
		}

		const countryDefault = configuredAction(stream.default_country_action);
		if (countryDefault) {
			return {
				action: countryDefault,
				source: "country-default",
				ipRule: null,
				countryRule: null,
				countryCode,
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
			countryRule: null,
			countryCode,
			reason: "Default IP action",
		};
	}

	return {
		action: null,
		source: "route",
		ipRule: null,
		countryRule: null,
		countryCode,
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
	return await addStreamIpRule(stream.id, ip, "block", reason, Date.now() + banSeconds * 1_000);
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
