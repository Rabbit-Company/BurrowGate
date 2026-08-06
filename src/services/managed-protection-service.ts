import type { ResolvedManagedProtectionPolicy } from "./http-policy-service.ts";

export type ManagedProtectionSeverity = "low" | "medium" | "high" | "critical";
export type ManagedProtectionStatus = "clean" | "monitored" | "blocked";
export type ManagedProtectionLocation = "request-target" | "query" | "header";

export interface ManagedProtectionMatch {
	ruleId: string;
	title: string;
	category: string;
	severity: ManagedProtectionSeverity;
	location: ManagedProtectionLocation;
}

export interface ManagedProtectionResult {
	status: "disabled" | ManagedProtectionStatus;
	rulesetId: string | null;
	rulesetVersion: string | null;
	matches: ManagedProtectionMatch[];
	primaryMatch: ManagedProtectionMatch | null;
}

export interface ManagedRuleSetContext {
	request: Request;
	url: URL;
}

export interface ManagedRuleSet {
	id: string;
	title: string;
	version: string;
	description: string;
	inspect(context: ManagedRuleSetContext): ManagedProtectionMatch[] | Promise<ManagedProtectionMatch[]>;
}

const severityRank: Record<ManagedProtectionSeverity, number> = { low: 1, medium: 2, high: 3, critical: 4 };
const ruleSets = new Map<string, ManagedRuleSet>();
let defaultRuleSetId = "burrowgate-core";

export function registerManagedRuleSet(ruleSet: ManagedRuleSet, options: { makeDefault?: boolean } = {}): void {
	if (!/^[a-z0-9][a-z0-9._-]{0,127}$/u.test(ruleSet.id)) throw new Error("Managed ruleset ID is invalid");
	if (!ruleSet.title.trim() || !ruleSet.version.trim()) throw new Error("Managed ruleset title and version are required");
	ruleSets.set(ruleSet.id, ruleSet);
	if (options.makeDefault) defaultRuleSetId = ruleSet.id;
}

export function managedRuleSetCatalog(): { defaultRuleSetId: string; items: Array<Omit<ManagedRuleSet, "inspect">> } {
	return {
		defaultRuleSetId,
		items: [...ruleSets.values()].map(({ inspect: _inspect, ...metadata }) => metadata),
	};
}

export async function inspectManagedRequest(request: Request, policy: ResolvedManagedProtectionPolicy): Promise<ManagedProtectionResult> {
	if (policy.mode === "disabled") return { status: "disabled", rulesetId: null, rulesetVersion: null, matches: [], primaryMatch: null };
	const selectedId = policy.rulesetId === "default" ? defaultRuleSetId : policy.rulesetId;
	const ruleSet = ruleSets.get(selectedId) ?? ruleSets.get(defaultRuleSetId);
	if (!ruleSet) return { status: "disabled", rulesetId: null, rulesetVersion: null, matches: [], primaryMatch: null };
	const excluded = new Set(policy.excludedRuleIds);
	const matches = (await ruleSet.inspect({ request, url: new URL(request.url) }))
		.filter((item) => !excluded.has(item.ruleId))
		.sort((left, right) => severityRank[right.severity] - severityRank[left.severity] || left.ruleId.localeCompare(right.ruleId));
	const primaryMatch = matches[0] ?? null;
	return {
		status: primaryMatch ? (policy.mode === "block" ? "blocked" : "monitored") : "clean",
		rulesetId: ruleSet.id,
		rulesetVersion: ruleSet.version,
		matches,
		primaryMatch,
	};
}
