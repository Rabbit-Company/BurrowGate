import { repository } from "../db/repository.ts";
import type { IpRuleAction, IpRuleRecord } from "../types.ts";
import { cidrContains, parseCidr } from "../utils/ip.ts";
import { randomId } from "../utils/crypto.ts";

export interface IpDecision {
	action: IpRuleAction | null;
	rule: IpRuleRecord | null;
}

export async function evaluateIp(siteId: string, ip: string): Promise<IpDecision> {
	const now = Date.now();
	const matches = (await repository.rules(siteId))
		.filter((r) => (r.expires_at === null || r.expires_at > now) && cidrContains(r.network_cidr, ip))
		.map((r) => ({ r, p: parseCidr(r.network_cidr)?.prefix ?? -1 }))
		.sort((a, b) => b.p - a.p || b.r.created_at - a.r.created_at);
	return matches[0] ? { action: matches[0].r.action, rule: matches[0].r } : { action: null, rule: null };
}

export async function addIpRule(siteId: string, networkCidr: string, action: IpRuleAction, reason: string, expiresAt: number | null): Promise<IpRuleRecord> {
	if (!parseCidr(networkCidr)) throw new Error("Invalid IP address or CIDR");
	const record: IpRuleRecord = {
		id: randomId("rule"),
		site_id: siteId,
		network_cidr: networkCidr,
		action,
		reason,
		created_at: Date.now(),
		expires_at: expiresAt,
	};
	await repository.insertRule(record);
	return record;
}
