import type { ManagedProtectionSeverity } from "./managed-protection-service.ts";

export const STREAM_RULESET_SCHEMA_VERSION = "1";

export type StreamRuleTransform = "lowercase" | "uppercase" | "trim" | "collapse-whitespace";

/** gt/gte/lt/lte compare Number(value); every other operator compares the string form. */
export type StreamRuleOperator = "regex" | "contains" | "equals" | "starts-with" | "ends-with" | "exists" | "not-empty" | "gt" | "gte" | "lt" | "lte";

export type StreamRuleLocation = "connection" | "handshake" | "login";

export interface StreamRuleFieldSelector {
	field: string;
	transforms?: StreamRuleTransform[];
}

export interface StreamRuleLeafCondition extends StreamRuleFieldSelector {
	operator: StreamRuleOperator;
	pattern?: string;
	flags?: string;
	value?: string;
	caseInsensitive?: boolean;
	negate?: boolean;
}

export interface StreamRuleAllCondition {
	all: StreamRuleCondition[];
}
export interface StreamRuleAnyCondition {
	any: StreamRuleCondition[];
}
export interface StreamRuleNotCondition {
	not: StreamRuleCondition;
}

export type StreamRuleCondition = StreamRuleLeafCondition | StreamRuleAllCondition | StreamRuleAnyCondition | StreamRuleNotCondition;

export interface StreamRuleDefinition {
	id: string;
	title: string;
	category: string;
	severity: ManagedProtectionSeverity;
	location: StreamRuleLocation;
	/** Defaults to true. Disabled rules are dropped at compile time. */
	enabled?: boolean;
	match: StreamRuleCondition;
}

export interface StreamRuleSetDecodeConfig {
	/** How long to keep buffering payload bytes for a protocol decoder before giving up. */
	timeoutMs?: number;
	/** How many payload bytes to buffer before giving up. */
	maxBytes?: number;
}

export interface StreamRuleSetDocument {
	schemaVersion: string;
	id: string;
	title: string;
	version: string;
	description?: string;
	/** Which decoder populates the fields this ruleset's rules read. "generic" needs no payload decoding. */
	protocol: string;
	/** Only meaningful when protocol !== "generic". Ignored (but still validated) otherwise. */
	decode?: StreamRuleSetDecodeConfig;
	rules: StreamRuleDefinition[];
}

/** Hard limits enforced by the compiler against every (including untrusted) document. */
export const STREAM_RULESET_LIMITS = {
	maxRules: 500,
	maxConditionNodes: 64,
	maxConditionDepth: 8,
	maxPatternLength: 1000,
	maxValueLength: 2000,
	maxTransforms: 8,
	maxFieldLength: 4096,
	decodeTimeoutMsMin: 100,
	decodeTimeoutMsMax: 30_000,
	decodeTimeoutMsDefault: 3_000,
	decodeMaxBytesMin: 64,
	decodeMaxBytesMax: 65_536,
	decodeMaxBytesDefault: 2_048,
} as const;

/** g and y are rejected: a global/sticky RegExp carries lastIndex state and makes `.test()` non-idempotent. */
export const STREAM_ALLOWED_REGEX_FLAGS = new Set(["i", "m", "s", "u"]);

export const STREAM_RULE_TRANSFORMS = new Set<StreamRuleTransform>(["lowercase", "uppercase", "trim", "collapse-whitespace"]);
export const STREAM_RULE_OPERATORS = new Set<StreamRuleOperator>([
	"regex",
	"contains",
	"equals",
	"starts-with",
	"ends-with",
	"exists",
	"not-empty",
	"gt",
	"gte",
	"lt",
	"lte",
]);
export const STREAM_RULE_SEVERITIES = new Set<ManagedProtectionSeverity>(["low", "medium", "high", "critical"]);
export const STREAM_RULE_LOCATIONS = new Set<StreamRuleLocation>(["connection", "handshake", "login"]);

/** Fields available to every ruleset regardless of declared protocol - kept by stream-connection-tracker.ts. */
const GENERIC_STREAM_FIELDS = [
	"connection.protocol",
	"connection.attempts_60s",
	"connection.disconnects_60s",
	"connection.avg_session_ms_60s",
	"connection.upstream_failures_60s",
	"connection.bytes_per_second",
	"connection.packets_per_second",
	"connection.zero_byte_disconnect",
] as const;

/**
 * Field vocabulary per protocol. Adding a new application protocol means adding a decoder module
 * (stream-protocol-decoders/*.ts) plus an entry here - the compiler and loader need no other changes.
 */
export const STREAM_PROTOCOL_FIELDS: Readonly<Record<string, ReadonlySet<string>>> = {
	generic: new Set(GENERIC_STREAM_FIELDS),
	"minecraft-java": new Set([
		...GENERIC_STREAM_FIELDS,
		"handshake_valid",
		"protocol_version",
		"server_address",
		"server_address_length",
		"next_state",
		"username",
		"username_length",
	]),
};
