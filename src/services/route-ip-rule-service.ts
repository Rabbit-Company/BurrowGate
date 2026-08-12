import { repository } from "../db/repository.ts";
import type { DefaultNetworkAction, IpRuleAction, RouteCountryRuleRecord, RouteIpRuleRecord, RoutePolicyRecord, SiteRecord } from "../types.ts";
import { randomId } from "../utils/crypto.ts";
import { cidrContains, parseCidr, type ParsedCidr } from "../utils/ip.ts";
import { countryCodeForStorage } from "./geoip-service.ts";
import { evaluateIp, type NetworkDecision } from "./ip-rule-service.ts";

interface CachedRouteIpRule {
	rule: RouteIpRuleRecord;
	cidr: ParsedCidr;
}

interface CachedRouteNetworkRules {
	ipRules: CachedRouteIpRule[];
	countryRules: Map<string, RouteCountryRuleRecord>;
}

const ruleCache = new Map<string, Promise<CachedRouteNetworkRules>>();

async function rulesForRoute(routePolicyId: string): Promise<CachedRouteNetworkRules> {
	let cached = ruleCache.get(routePolicyId);
	if (!cached) {
		cached = Promise.all([repository.routeIpRules(routePolicyId), repository.routeCountryRules(routePolicyId)])
			.then(([ipRules, countryRules]) => ({
				ipRules: ipRules
					.map((rule) => ({ rule, cidr: parseCidr(rule.network_cidr) }))
					.filter((item): item is CachedRouteIpRule => item.cidr !== null)
					.sort((left, right) => right.cidr.prefix - left.cidr.prefix || right.rule.created_at - left.rule.created_at),
				countryRules: new Map(countryRules.map((rule) => [rule.country_code, rule])),
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

	if (ipRule) {
		return {
			action: ipRule.action,
			source: "ip-rule",
			scope: "route",
			expiresAt: ipRule.expires_at,
			countryCode: null,
			reason: ipRule.reason || `Matched route IP rule ${ipRule.network_cidr}`,
			routePolicyId: route.id,
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
				scope: "route",
				expiresAt: countryRule.expires_at,
				countryCode,
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
