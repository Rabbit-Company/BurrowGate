import { repository } from "../db/repository.ts";
import type { CountryRuleRecord, DefaultNetworkAction, IpRuleAction, IpRuleRecord, SiteRecord } from "../types.ts";
import { randomId } from "../utils/crypto.ts";
import { cidrContains, parseCidr, type ParsedCidr } from "../utils/ip.ts";
import { countryCodeForStorage } from "./geoip-service.ts";
import type { BanDurationSeverity } from "./http-policy-service.ts";
import type { ManagedProtectionMatch } from "./managed-protection-service.ts";

interface CachedIpRule {
	rule: IpRuleRecord;
	cidr: ParsedCidr;
}

interface CachedNetworkRules {
	ipRules: CachedIpRule[];
	countryRules: Map<string, CountryRuleRecord>;
}

const ruleCache = new Map<string, Promise<CachedNetworkRules>>();

async function rulesForSite(siteId: string): Promise<CachedNetworkRules> {
	let cached = ruleCache.get(siteId);
	if (!cached) {
		cached = Promise.all([repository.rules(siteId), repository.countryRules(siteId)])
			.then(([ipRules, countryRules]) => ({
				ipRules: ipRules
					.map((rule) => ({ rule, cidr: parseCidr(rule.network_cidr) }))
					.filter((item): item is CachedIpRule => item.cidr !== null)
					.sort((left, right) => right.cidr.prefix - left.cidr.prefix || right.rule.created_at - left.rule.created_at),
				countryRules: new Map(countryRules.map((rule) => [rule.country_code, rule])),
			}))
			.catch((error) => {
				ruleCache.delete(siteId);
				throw error;
			});
		ruleCache.set(siteId, cached);
	}
	return await cached;
}

export function invalidateNetworkPolicy(siteId: string): void {
	ruleCache.delete(siteId);
}

export type NetworkDecisionSource = "ip-rule" | "country-rule" | "country-default" | "ip-default" | "route";
export type NetworkDecisionScope = "site" | "route";

export interface NetworkDecision {
	action: IpRuleAction | null;
	source: NetworkDecisionSource;
	scope: NetworkDecisionScope;
	expiresAt: number | null;
	countryCode: string | null;
	reason: string | null;
	routePolicyId: string | null;
}

function active<T extends { expires_at: number | null }>(record: T, now: number): boolean {
	return record.expires_at === null || record.expires_at > now;
}

function configuredAction(action: DefaultNetworkAction | null | undefined): IpRuleAction | null {
	return action && action !== "inherit" ? action : null;
}

export async function evaluateIp(site: SiteRecord, ip: string): Promise<NetworkDecision> {
	const now = Date.now();
	const rules = await rulesForSite(site.id);
	const ipRule = ip === "unknown" ? null : (rules.ipRules.find((item) => active(item.rule, now) && cidrContains(item.cidr, ip))?.rule ?? null);

	if (ipRule) {
		return {
			action: ipRule.action,
			source: "ip-rule",
			scope: "site",
			expiresAt: ipRule.expires_at,
			countryCode: null,
			reason: ipRule.reason || `Matched IP rule ${ipRule.network_cidr}`,
			routePolicyId: null,
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
				scope: "site",
				expiresAt: countryRule.expires_at,
				countryCode,
				reason: countryRule.reason || `Matched country rule ${countryCode}`,
				routePolicyId: null,
			};
		}

		const countryDefault = configuredAction(site.default_country_action);
		if (countryDefault) {
			return {
				action: countryDefault,
				source: "country-default",
				scope: "site",
				expiresAt: null,
				countryCode,
				reason: `Default country action for ${countryCode}`,
				routePolicyId: null,
			};
		}
	}

	const ipDefault = configuredAction(site.default_ip_action);
	if (ipDefault) {
		return {
			action: ipDefault,
			source: "ip-default",
			scope: "site",
			expiresAt: null,
			countryCode,
			reason: "Default IP action",
			routePolicyId: null,
		};
	}

	return {
		action: null,
		source: "route",
		scope: "site",
		expiresAt: null,
		countryCode,
		reason: null,
		routePolicyId: null,
	};
}

export async function addIpRule(
	siteId: string,
	networkCidr: string,
	action: IpRuleAction,
	reason: string,
	expiresAt: number | null,
	ruleId: string | null = null,
): Promise<IpRuleRecord> {
	if (!parseCidr(networkCidr)) throw new Error("Invalid IP address or CIDR");
	const record: IpRuleRecord = {
		id: randomId("rule"),
		site_id: siteId,
		network_cidr: networkCidr,
		action,
		reason,
		created_at: Date.now(),
		expires_at: expiresAt,
		rule_id: ruleId,
	};
	await repository.insertRule(record);
	invalidateNetworkPolicy(siteId);
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

export function formatBanExpiry(expiresAt: number): string {
	const date = new Date(expiresAt);
	return date.toISOString().slice(0, 19).replace("T", " ") + " UTC";
}

export async function banIpForProtectionMatch(
	site: SiteRecord,
	ip: string,
	match: ManagedProtectionMatch,
	banDurations: Record<BanDurationSeverity, number>,
): Promise<IpRuleRecord | null> {
	if (ip === "unknown") return null;
	const banSeconds = banDurations[match.severity];
	if (!banSeconds || banSeconds <= 0) return null;
	const existing = await evaluateIp(site, ip);
	if (existing.source === "ip-rule" && existing.action === "block") return null;
	const reason = `Auto-banned for ${humanizeDurationSeconds(banSeconds)} after matching WAF rule ${match.ruleId} (${match.category}, ${match.severity}).`;
	return await addIpRule(site.id, ip, "block", reason, Date.now() + banSeconds * 1_000, match.ruleId);
}

export async function addCountryRule(
	siteId: string,
	countryCodeInput: string,
	action: IpRuleAction,
	reason: string,
	expiresAt: number | null,
): Promise<CountryRuleRecord> {
	const countryCode = countryCodeInput.trim().toUpperCase();
	if (!/^[A-Z]{2}$/u.test(countryCode)) throw new Error("Country code must contain two letters");
	const existing = await repository.countryRuleByCode(siteId, countryCode);
	if (existing && active(existing, Date.now())) {
		throw new Error(`An active rule for ${countryCode} already exists`);
	}
	if (existing) await repository.deleteCountryRuleForSite(existing.id, siteId);
	const record: CountryRuleRecord = {
		id: randomId("country-rule"),
		site_id: siteId,
		country_code: countryCode,
		action,
		reason,
		created_at: Date.now(),
		expires_at: expiresAt,
	};
	await repository.insertCountryRule(record);
	invalidateNetworkPolicy(siteId);
	return record;
}
