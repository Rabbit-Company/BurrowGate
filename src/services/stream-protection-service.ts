import type { BanDurationSeverity } from "./http-policy-service.ts";
import type { ManagedProtectionSeverity } from "./managed-protection-service.ts";
import type { StreamRuleLocation } from "./stream-ruleset-format.ts";

export type StreamProtectionMode = "disabled" | "monitor" | "block";

export interface StreamProtectionMatch {
	ruleId: string;
	rulesetId: string;
	title: string;
	category: string;
	severity: ManagedProtectionSeverity;
	location: StreamRuleLocation;
}

export type StreamRuleFieldValue = string | number | boolean | undefined;

export interface StreamRuleSetContext {
	fields: Readonly<Record<string, StreamRuleFieldValue>>;
}

export interface StreamRuleSetDecode {
	timeoutMs: number;
	maxBytes: number;
}

export interface StreamRuleSet {
	id: string;
	title: string;
	version: string;
	description: string;
	/** Which decoder populates this ruleset's fields: "generic" (connection metadata only) or an application protocol id. */
	protocol: string;
	decode: StreamRuleSetDecode;
	inspect(context: StreamRuleSetContext): StreamProtectionMatch[];
}

export interface StreamProtectionPolicy {
	mode: StreamProtectionMode;
	rulesetIds: string[];
	excludedRuleIds: string[];
	banDurations: Record<BanDurationSeverity, number>;
}

export interface StreamProtectionResult {
	status: "disabled" | "clean" | "monitored" | "blocked";
	matches: StreamProtectionMatch[];
	primaryMatch: StreamProtectionMatch | null;
}

const severityRank: Record<ManagedProtectionSeverity, number> = { low: 1, medium: 2, high: 3, critical: 4 };
const ruleSets = new Map<string, StreamRuleSet>();

export function registerStreamRuleSet(ruleSet: StreamRuleSet): void {
	if (!/^[a-z0-9][a-z0-9._-]{0,127}$/u.test(ruleSet.id)) throw new Error("Stream ruleset ID is invalid");
	if (!ruleSet.title.trim() || !ruleSet.version.trim()) throw new Error("Stream ruleset title and version are required");
	ruleSets.set(ruleSet.id, ruleSet);
}

export function clearStreamRuleSets(): void {
	ruleSets.clear();
}

export function streamRuleSetCatalog(): Array<Omit<StreamRuleSet, "inspect">> {
	return [...ruleSets.values()].map(({ inspect: _inspect, ...metadata }) => metadata);
}

export function streamRuleSetById(id: string): StreamRuleSet | null {
	return ruleSets.get(id) ?? null;
}

/** Distinct non-generic protocols among a stream's enabled rulesets - tells the proxy which payload decoders to run for new connections. */
export function streamDecodeProtocols(rulesetIds: string[]): string[] {
	const protocols = new Set<string>();
	for (const id of rulesetIds) {
		const ruleSet = ruleSets.get(id);
		if (ruleSet && ruleSet.protocol !== "generic") protocols.add(ruleSet.protocol);
	}
	return [...protocols];
}

/** Reconciles decode limits across every enabled ruleset that targets the given application protocol, taking the most permissive of each. */
export function streamDecodeConfigFor(rulesetIds: string[], protocol: string): StreamRuleSetDecode | null {
	let timeoutMs = 0;
	let maxBytes = 0;
	let found = false;
	for (const id of rulesetIds) {
		const ruleSet = ruleSets.get(id);
		if (!ruleSet || ruleSet.protocol !== protocol) continue;
		found = true;
		timeoutMs = Math.max(timeoutMs, ruleSet.decode.timeoutMs);
		maxBytes = Math.max(maxBytes, ruleSet.decode.maxBytes);
	}
	return found ? { timeoutMs, maxBytes } : null;
}

export function inspectStreamConnection(context: StreamRuleSetContext, policy: StreamProtectionPolicy): StreamProtectionResult {
	if (policy.mode === "disabled" || policy.rulesetIds.length === 0) return { status: "disabled", matches: [], primaryMatch: null };
	const excluded = new Set(policy.excludedRuleIds);
	const matches: StreamProtectionMatch[] = [];
	for (const id of policy.rulesetIds) {
		const ruleSet = ruleSets.get(id);
		if (!ruleSet) continue;
		for (const match of ruleSet.inspect(context)) {
			if (!excluded.has(match.ruleId)) matches.push(match);
		}
	}
	matches.sort((left, right) => severityRank[right.severity] - severityRank[left.severity] || left.ruleId.localeCompare(right.ruleId));
	const primaryMatch = matches[0] ?? null;
	return {
		status: primaryMatch ? (policy.mode === "block" ? "blocked" : "monitored") : "clean",
		matches,
		primaryMatch,
	};
}
