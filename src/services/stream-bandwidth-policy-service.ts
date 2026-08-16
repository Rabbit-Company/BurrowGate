import type { StreamRecord } from "../types.ts";

export interface StreamBandwidthLimitPolicy {
	enabled: boolean;
	maxBytes: number;
	windowSeconds: number;
	banSeconds: number;
}

export interface StreamBandwidthPolicy {
	tcp: StreamBandwidthLimitPolicy;
	udp: StreamBandwidthLimitPolicy;
}

const MAX_BANDWIDTH_LIMIT_BYTES = 1_099_511_627_776; // 1 TiB
const MAX_BANDWIDTH_LIMIT_WINDOW_SECONDS = 3_600;
const MAX_BAN_DURATION_SECONDS = 2_592_000; // 30 days

function defaultStreamBandwidthLimitPolicy(): StreamBandwidthLimitPolicy {
	return { enabled: false, maxBytes: 50 * 1_024 * 1_024, windowSeconds: 60, banSeconds: 3_600 };
}

function defaultStreamBandwidthPolicy(): StreamBandwidthPolicy {
	return { tcp: defaultStreamBandwidthLimitPolicy(), udp: defaultStreamBandwidthLimitPolicy() };
}

function bandwidthLimitBoolean(value: unknown, fallback: boolean): boolean {
	if (value === undefined) return fallback;
	if (typeof value === "boolean") return value;
	if (value === "true" || value === "1" || value === 1) return true;
	if (value === "false" || value === "0" || value === 0 || value === "") return false;
	throw new Error("Bandwidth limit enabled must be a boolean");
}

function bandwidthLimitInteger(value: unknown, label: string, fallback: number, minimum: number, maximum: number): number {
	const result = value === undefined ? fallback : Number(value);
	if (!Number.isSafeInteger(result) || Number(result) < minimum || Number(result) > maximum) {
		throw new Error(`${label} must be an integer from ${minimum} to ${maximum}`);
	}
	return Number(result);
}

function parseLimit(value: unknown, fallback: StreamBandwidthLimitPolicy): StreamBandwidthLimitPolicy {
	const input = value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
	return {
		enabled: bandwidthLimitBoolean(input.enabled, fallback.enabled),
		maxBytes: bandwidthLimitInteger(input.maxBytes, "Bandwidth limit threshold", fallback.maxBytes, 1, MAX_BANDWIDTH_LIMIT_BYTES),
		windowSeconds: bandwidthLimitInteger(input.windowSeconds, "Bandwidth limit window", fallback.windowSeconds, 1, MAX_BANDWIDTH_LIMIT_WINDOW_SECONDS),
		banSeconds: bandwidthLimitInteger(input.banSeconds, "Bandwidth limit ban duration", fallback.banSeconds, 0, MAX_BAN_DURATION_SECONDS),
	};
}

function parsePolicy(value: unknown, fallback: StreamBandwidthPolicy): StreamBandwidthPolicy {
	const input = value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
	return {
		tcp: parseLimit(input.tcp, fallback.tcp),
		udp: parseLimit(input.udp, fallback.udp),
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

export function storedStreamBandwidthPolicy(value: string | null | undefined): StreamBandwidthPolicy {
	try {
		return parsePolicy(parseJson(value), defaultStreamBandwidthPolicy());
	} catch {
		return defaultStreamBandwidthPolicy();
	}
}

export function serializeStreamBandwidthPolicy(input: unknown, existing?: string | null): string {
	if (input === undefined) return JSON.stringify(storedStreamBandwidthPolicy(existing));
	if (input === null) return JSON.stringify(defaultStreamBandwidthPolicy());
	const current = storedStreamBandwidthPolicy(existing);
	return JSON.stringify(parsePolicy(objectValue(input, "Stream bandwidth limit policy"), current));
}

// Bandwidth policy is resolved on every byte written to a stream connection
// (see StreamProxyManager.recordTcpBytes/recordUdpBytes), so cache the parsed
// result per stream and only reparse when the stored JSON actually changes.
const resolvedCache = new Map<string, { raw: string | null; policy: StreamBandwidthPolicy }>();

export function resolveStreamBandwidthPolicy(stream: StreamRecord): StreamBandwidthPolicy {
	const cached = resolvedCache.get(stream.id);
	if (cached && cached.raw === stream.bandwidth_policy_json) return cached.policy;
	const policy = storedStreamBandwidthPolicy(stream.bandwidth_policy_json);
	resolvedCache.set(stream.id, { raw: stream.bandwidth_policy_json, policy });
	return policy;
}
