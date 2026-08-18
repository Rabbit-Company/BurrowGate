import { repository } from "../db/repository.ts";
import type {
	DefaultNetworkAction,
	IpRuleAction,
	RouteAsnRuleRecord,
	RouteCountryRuleRecord,
	RouteIpRuleRecord,
	RoutePolicyRecord,
	SiteRecord,
} from "../types.ts";
import { randomId } from "../utils/crypto.ts";
import { cidrContains, parseCidr, type ParsedCidr } from "../utils/ip.ts";
import { asnForStorage, countryCodeForStorage } from "./geoip-service.ts";
import { evaluateIp, type NetworkDecision } from "./ip-rule-service.ts";

interface CachedRouteIpRule {
	rule: RouteIpRuleRecord;
	cidr: ParsedCidr;
}

interface CachedRouteNetworkRules {
	ipRules: CachedRouteIpRule[];
	countryRules: Map<string, RouteCountryRuleRecord>;
	asnRules: Map<number, RouteAsnRuleRecord>;
}

const ruleCache = new Map<string, Promise<CachedRouteNetworkRules>>();

async function rulesForRoute(routePolicyId: string): Promise<CachedRouteNetworkRules> {
	let cached = ruleCache.get(routePolicyId);
	if (!cached) {
		cached = Promise.all([repository.routeIpRules(routePolicyId), repository.routeCountryRules(routePolicyId), repository.routeAsnRules(routePolicyId)])
			.then(([ipRules, countryRules, asnRules]) => ({
				ipRules: ipRules
					.map((rule) => ({ rule, cidr: parseCidr(rule.network_cidr) }))
					.filter((item): item is CachedRouteIpRule => item.cidr !== null)
					.sort((left, right) => right.cidr.prefix - left.cidr.prefix || right.rule.created_at - left.rule.created_at),
				countryRules: new Map(countryRules.map((rule) => [rule.country_code, rule])),
				asnRules: new Map(asnRules.map((rule) => [rule.asn, rule])),
			}))
			.catch((error) => {
				ruleCache.delete(routePolicyId);
				throw error;
			});
		ruleCache.set(routePolicyId, cached);
	}
	return await cached;
}

export function invalidateRouteNetworkPolicy(routePolicyId: string): void {
	ruleCache.delete(routePolicyId);
}

function active<T extends { expires_at: number | null }>(record: T, now: number): boolean {
	return record.expires_at === null || record.expires_at > now;
}

function configuredAction(action: DefaultNetworkAction | null | undefined): IpRuleAction | null {
	return action && action !== "inherit" ? action : null;
}

export async function evaluateRouteIp(route: RoutePolicyRecord, ip: string): Promise<NetworkDecision> {
	const now = Date.now();
	const rules = await rulesForRoute(route.id);
	const ipRule = ip === "unknown" ? null : (rules.ipRules.find((item) => active(item.rule, now) && cidrContains(item.cidr, ip))?.rule ?? null);
	const { asn, org: asnOrg } = ip === "unknown" ? { asn: null, org: null } : asnForStorage(ip);
	const countryCode = ip === "unknown" ? null : countryCodeForStorage(ip);

	if (ipRule) {
		return {
			action: ipRule.action,
			source: "ip-rule",
			scope: "route",
			expiresAt: ipRule.expires_at,
			countryCode,
			asn,
			asnOrg,
			reason: ipRule.reason || `Matched route IP rule ${ipRule.network_cidr}`,
			routePolicyId: route.id,
		};
	}

	if (asn !== null) {
		const candidateAsnRule = rules.asnRules.get(asn) ?? null;
		const asnRule = candidateAsnRule && active(candidateAsnRule, now) ? candidateAsnRule : null;
		if (asnRule) {
			return {
				action: asnRule.action,
				source: "asn-rule",
				scope: "route",
				expiresAt: asnRule.expires_at,
				countryCode,
				asn,
				asnOrg,
				reason: asnRule.reason || `Matched route ASN rule AS${asn}`,
				routePolicyId: route.id,
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
				scope: "route",
				expiresAt: countryRule.expires_at,
				countryCode,
				asn,
				asnOrg,
				reason: countryRule.reason || `Matched route country rule ${countryCode}`,
				routePolicyId: route.id,
			};
		}

		const countryDefault = configuredAction(route.default_country_action);
		if (countryDefault) {
			return {
				action: countryDefault,
				source: "country-default",
				scope: "route",
				expiresAt: null,
				countryCode,
				asn,
				asnOrg,
				reason: `Default route country action for ${countryCode}`,
				routePolicyId: route.id,
			};
		}
	}

	const ipDefault = configuredAction(route.default_ip_action);
	if (ipDefault) {
		return {
			action: ipDefault,
			source: "ip-default",
			scope: "route",
			expiresAt: null,
			countryCode,
			asn,
			asnOrg,
			reason: "Default route IP action",
			routePolicyId: route.id,
		};
	}

	return {
		action: null,
		source: "route",
		scope: "route",
		expiresAt: null,
		countryCode,
		asn,
		asnOrg,
		reason: null,
		routePolicyId: route.id,
	};
}

export async function resolveNetworkDecision(site: SiteRecord, routePolicy: RoutePolicyRecord | null, ip: string): Promise<NetworkDecision> {
	if (routePolicy) {
		const routeDecision = await evaluateRouteIp(routePolicy, ip);
		if (routeDecision.action !== null) return routeDecision;
	}
	return await evaluateIp(site, ip);
}

export async function addRouteIpRule(
	routePolicyId: string,
	networkCidr: string,
	action: IpRuleAction,
	reason: string,
	expiresAt: number | null,
): Promise<RouteIpRuleRecord> {
	if (!parseCidr(networkCidr)) throw new Error("Invalid IP address or CIDR");
	const record: RouteIpRuleRecord = {
		id: randomId("route_rule"),
		route_policy_id: routePolicyId,
		network_cidr: networkCidr,
		action,
		reason,
		created_at: Date.now(),
		expires_at: expiresAt,
	};
	await repository.insertRouteIpRule(record);
	invalidateRouteNetworkPolicy(routePolicyId);
	return record;
}

export async function addRouteCountryRule(
	routePolicyId: string,
	countryCodeInput: string,
	action: IpRuleAction,
	reason: string,
	expiresAt: number | null,
): Promise<RouteCountryRuleRecord> {
	const countryCode = countryCodeInput.trim().toUpperCase();
	if (!/^[A-Z]{2}$/u.test(countryCode)) throw new Error("Country code must contain two letters");
	const existing = await repository.routeCountryRuleByCode(routePolicyId, countryCode);
	if (existing && active(existing, Date.now())) {
		throw new Error(`An active rule for ${countryCode} already exists`);
	}
	if (existing) await repository.deleteRouteCountryRuleForRoute(existing.id, routePolicyId);
	const record: RouteCountryRuleRecord = {
		id: randomId("route_country_rule"),
		route_policy_id: routePolicyId,
		country_code: countryCode,
		action,
		reason,
		created_at: Date.now(),
		expires_at: expiresAt,
	};
	await repository.insertRouteCountryRule(record);
	invalidateRouteNetworkPolicy(routePolicyId);
	return record;
}

export async function addRouteAsnRule(
	routePolicyId: string,
	asnInput: unknown,
	action: IpRuleAction,
	reason: string,
	expiresAt: number | null,
): Promise<RouteAsnRuleRecord> {
	const asn = Number(asnInput);
	if (!Number.isInteger(asn) || asn <= 0) throw new Error("ASN must be a positive whole number");
	const existing = await repository.routeAsnRuleByAsn(routePolicyId, asn);
	if (existing && active(existing, Date.now())) {
		throw new Error(`An active rule for AS${asn} already exists`);
	}
	if (existing) await repository.deleteRouteAsnRuleForRoute(existing.id, routePolicyId);
	const record: RouteAsnRuleRecord = {
		id: randomId("route_asn_rule"),
		route_policy_id: routePolicyId,
		asn,
		action,
		reason,
		created_at: Date.now(),
		expires_at: expiresAt,
	};
	await repository.insertRouteAsnRule(record);
	invalidateRouteNetworkPolicy(routePolicyId);
	return record;
}
