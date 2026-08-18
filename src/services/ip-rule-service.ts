import { repository } from "../db/repository.ts";
import type { AsnRuleRecord, CountryRuleRecord, DefaultNetworkAction, IpRuleAction, IpRuleRecord, SiteRecord } from "../types.ts";
import { randomId } from "../utils/crypto.ts";
import { cidrContains, parseCidr, type ParsedCidr } from "../utils/ip.ts";
import { asnForStorage, countryCodeForStorage } from "./geoip-service.ts";
import type { BanDurationSeverity } from "./http-policy-service.ts";
import type { ManagedProtectionMatch } from "./managed-protection-service.ts";
import { notificationService } from "./notification-service.ts";

interface CachedIpRule {
	rule: IpRuleRecord;
	cidr: ParsedCidr;
}

interface CachedNetworkRules {
	ipRules: CachedIpRule[];
	countryRules: Map<string, CountryRuleRecord>;
	asnRules: Map<number, AsnRuleRecord>;
}

const ruleCache = new Map<string, Promise<CachedNetworkRules>>();

async function rulesForSite(siteId: string): Promise<CachedNetworkRules> {
	let cached = ruleCache.get(siteId);
	if (!cached) {
		cached = Promise.all([repository.rules(siteId), repository.countryRules(siteId), repository.asnRules(siteId)])
			.then(([ipRules, countryRules, asnRules]) => ({
				ipRules: ipRules
					.map((rule) => ({ rule, cidr: parseCidr(rule.network_cidr) }))
					.filter((item): item is CachedIpRule => item.cidr !== null)
					.sort((left, right) => right.cidr.prefix - left.cidr.prefix || right.rule.created_at - left.rule.created_at),
				countryRules: new Map(countryRules.map((rule) => [rule.country_code, rule])),
				asnRules: new Map(asnRules.map((rule) => [rule.asn, rule])),
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

export type NetworkDecisionSource = "ip-rule" | "asn-rule" | "country-rule" | "country-default" | "ip-default" | "route";
export type NetworkDecisionScope = "site" | "route";

export interface NetworkDecision {
	action: IpRuleAction | null;
	source: NetworkDecisionSource;
	scope: NetworkDecisionScope;
	expiresAt: number | null;
	countryCode: string | null;
	asn: number | null;
	asnOrg: string | null;
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
	const { asn, org: asnOrg } = ip === "unknown" ? { asn: null, org: null } : asnForStorage(ip);
	const countryCode = ip === "unknown" ? null : countryCodeForStorage(ip);

	if (ipRule) {
		return {
			action: ipRule.action,
			source: "ip-rule",
			scope: "site",
			expiresAt: ipRule.expires_at,
			countryCode,
			asn,
			asnOrg,
			reason: ipRule.reason || `Matched IP rule ${ipRule.network_cidr}`,
			routePolicyId: null,
		};
	}

	if (asn !== null) {
		const candidateAsnRule = rules.asnRules.get(asn) ?? null;
		const asnRule = candidateAsnRule && active(candidateAsnRule, now) ? candidateAsnRule : null;
		if (asnRule) {
			return {
				action: asnRule.action,
				source: "asn-rule",
				scope: "site",
				expiresAt: asnRule.expires_at,
				countryCode,
				asn,
				asnOrg,
				reason: asnRule.reason || `Matched ASN rule AS${asn}`,
				routePolicyId: null,
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
				scope: "site",
				expiresAt: countryRule.expires_at,
				countryCode,
				asn,
				asnOrg,
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
				asn,
				asnOrg,
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
			asn,
			asnOrg,
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
		asn,
		asnOrg,
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
	const expiresAt = Date.now() + banSeconds * 1_000;
	const rule = await addIpRule(site.id, ip, "block", reason, expiresAt, match.ruleId);
	const summary = `IP ${ip} auto-banned for ${humanizeDurationSeconds(banSeconds)} after matching WAF rule ${match.ruleId} (${match.category}, ${match.severity}).`;
	await notificationService.recordSiteEvent(site, "ip_banned", "warning", summary, { ip, reason, ruleId: match.ruleId, expiresAt }, Date.now());
	return rule;
}

function humanizeBytes(bytes: number): string {
	if (bytes < 1_024 * 1_024) return `${Math.round(bytes / 1_024)} KiB`;
	if (bytes < 1_024 * 1_024 * 1_024) return `${(bytes / (1_024 * 1_024)).toFixed(1)} MiB`;
	return `${(bytes / (1_024 * 1_024 * 1_024)).toFixed(1)} GiB`;
}

export async function banIpForBandwidthLimit(
	site: SiteRecord,
	ip: string,
	maxBytes: number,
	windowSeconds: number,
	banSeconds: number,
): Promise<IpRuleRecord | null> {
	if (ip === "unknown" || !banSeconds || banSeconds <= 0) return null;
	const existing = await evaluateIp(site, ip);
	if (existing.source === "ip-rule" && existing.action === "block") return null;
	const reason = `Auto-banned for ${humanizeDurationSeconds(banSeconds)} after exceeding ${humanizeBytes(maxBytes)} in ${windowSeconds}s.`;
	const expiresAt = Date.now() + banSeconds * 1_000;
	const rule = await addIpRule(site.id, ip, "block", reason, expiresAt);
	const summary = `IP ${ip} auto-banned for ${humanizeDurationSeconds(banSeconds)} after exceeding ${humanizeBytes(maxBytes)} in ${windowSeconds}s.`;
	await notificationService.recordSiteEvent(site, "ip_banned", "warning", summary, { ip, reason, expiresAt }, Date.now());
	return rule;
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

export async function addAsnRule(siteId: string, asnInput: unknown, action: IpRuleAction, reason: string, expiresAt: number | null): Promise<AsnRuleRecord> {
	const asn = Number(asnInput);
	if (!Number.isInteger(asn) || asn <= 0) throw new Error("ASN must be a positive whole number");
	const existing = await repository.asnRuleByAsn(siteId, asn);
	if (existing && active(existing, Date.now())) {
		throw new Error(`An active rule for AS${asn} already exists`);
	}
	if (existing) await repository.deleteAsnRuleForSite(existing.id, siteId);
	const record: AsnRuleRecord = {
		id: randomId("asn-rule"),
		site_id: siteId,
		asn,
		action,
		reason,
		created_at: Date.now(),
		expires_at: expiresAt,
	};
	await repository.insertAsnRule(record);
	invalidateNetworkPolicy(siteId);
	return record;
}
