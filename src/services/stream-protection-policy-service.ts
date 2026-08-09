import type { BanDurationSeverity } from "./http-policy-service.ts";
import type { StreamProtectionMode, StreamProtectionPolicy } from "./stream-protection-service.ts";
import type { StreamRecord } from "../types.ts";

const MAX_BAN_DURATION_SECONDS = 2_592_000; // 30 days

function defaultStreamProtectionPolicy(): StreamProtectionPolicy {
	return {
		mode: "disabled",
		rulesetIds: [],
		excludedRuleIds: [],
		banDurations: { low: 0, medium: 600, high: 3_600, critical: 86_400 },
	};
}

function protectionMode(value: unknown, fallback: StreamProtectionMode): StreamProtectionMode {
	if (value === undefined) return fallback;
	const mode = String(value).trim().toLowerCase();
	if (mode === "disabled" || mode === "monitor" || mode === "block") return mode;
	throw new Error("Stream protection mode must be disabled, monitor, or block");
}

function rulesetIdList(value: unknown, fallback: readonly string[]): string[] {
	if (value === undefined) return [...fallback];
	if (!Array.isArray(value)) throw new Error("Stream protection ruleset selection must be an array");
	const ids = [...new Set(value.map((item) => String(item).trim().toLowerCase()).filter(Boolean))];
	if (ids.length > 32) throw new Error("Stream protection supports at most 32 enabled rulesets");
	for (const id of ids) if (!/^[a-z0-9][a-z0-9._-]{0,127}$/u.test(id)) throw new Error(`Invalid stream ruleset ID: ${id}`);
	return ids;
}

function excludedRuleIdList(value: unknown, fallback: readonly string[]): string[] {
	if (value === undefined) return [...fallback];
	if (value === null || value === "") return [];
	const raw = Array.isArray(value) ? value : String(value).split(/[\s,]+/u);
	const ids = [...new Set(raw.map((item) => String(item).trim().toUpperCase()).filter(Boolean))];
	if (ids.length > 256) throw new Error("Stream protection supports at most 256 excluded rule IDs");
	for (const id of ids) if (!/^[A-Z0-9][A-Z0-9._:-]{0,127}$/u.test(id)) throw new Error(`Invalid stream protection rule ID: ${id}`);
	return ids;
}

function banDurationValue(value: unknown, label: string, fallback: number): number {
	const result = value === undefined ? fallback : Number(value);
	if (!Number.isInteger(result) || result < 0 || result > MAX_BAN_DURATION_SECONDS) {
		throw new Error(`${label} must be an integer from 0 to ${MAX_BAN_DURATION_SECONDS}`);
	}
	return result;
}

function parseBanDurations(value: unknown, fallback: Record<BanDurationSeverity, number>): Record<BanDurationSeverity, number> {
	const input = value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
	return {
		low: banDurationValue(input.low, "Low severity ban duration", fallback.low),
		medium: banDurationValue(input.medium, "Medium severity ban duration", fallback.medium),
		high: banDurationValue(input.high, "High severity ban duration", fallback.high),
		critical: banDurationValue(input.critical, "Critical severity ban duration", fallback.critical),
	};
}

function parsePolicy(value: unknown, fallback: StreamProtectionPolicy): StreamProtectionPolicy {
	const input = value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
	return {
		mode: protectionMode(input.mode, fallback.mode),
		rulesetIds: rulesetIdList(input.rulesetIds, fallback.rulesetIds),
		excludedRuleIds: excludedRuleIdList(input.excludedRuleIds, fallback.excludedRuleIds),
		banDurations: parseBanDurations(input.banDurations, fallback.banDurations),
	};
}

function parseJson(value: string | null | undefined): Record<string, unknown> {
	if (!value) return {};
	try {
		const parsed = JSON.parse(value) as unknown;
		return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {};
	} catch {
		return {};
	}
}

function objectValue(value: unknown, label: string): Record<string, unknown> {
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
	return value as Record<string, unknown>;
}

export function storedStreamProtectionPolicy(value: string | null | undefined): StreamProtectionPolicy {
	try {
		return parsePolicy(parseJson(value), defaultStreamProtectionPolicy());
	} catch {
		return defaultStreamProtectionPolicy();
	}
}

export function serializeStreamProtectionPolicy(input: unknown, existing?: string | null): string {
	if (input === undefined) return JSON.stringify(storedStreamProtectionPolicy(existing));
	if (input === null) return JSON.stringify(defaultStreamProtectionPolicy());
	const current = storedStreamProtectionPolicy(existing);
	return JSON.stringify(parsePolicy(objectValue(input, "Stream protection policy"), current));
}

export function resolveStreamProtectionPolicy(stream: StreamRecord): StreamProtectionPolicy {
	return storedStreamProtectionPolicy(stream.protection_policy_json);
}
