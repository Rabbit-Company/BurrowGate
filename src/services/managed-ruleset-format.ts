import type { ManagedProtectionLocation, ManagedProtectionSeverity } from "./managed-protection-service.ts";

/**
 * Wire format for declarative managed-protection rulesets.
 *
 * A ruleset document is plain JSON. It is compiled into a ManagedRuleSet
 * (see managed-ruleset-compiler.ts) so that built-in and user-supplied rulesets
 * run through the exact same inspection path. The format is intentionally a
 * closed vocabulary (enumerated fields, transforms and operators) so an
 * untrusted document can never express arbitrary code, only data.
 */

export const RULESET_SCHEMA_VERSION = "1";

/** Request part a condition reads from. */
export type RuleFieldSource = "method" | "path" | "query" | "request-target" | "header";

/** Value transforms applied left-to-right before the operator runs. */
export type RuleTransform = "url-decode" | "lowercase" | "uppercase" | "trim" | "collapse-whitespace";

/** Match operators. */
export type RuleOperator = "regex" | "contains" | "equals" | "starts-with" | "ends-with" | "exists" | "not-empty";

export interface RuleFieldSelector {
	field: RuleFieldSource;
	/** Required when field is "header"; the header name to read (case-insensitive). */
	header?: string;
	/** Transform pipeline applied in order before the operator runs. */
	transforms?: RuleTransform[];
}

export interface RuleLeafCondition extends RuleFieldSelector {
	operator: RuleOperator;
	/** Pattern source for "regex". */
	pattern?: string;
	/** Regex flags. Only i, m, s and u are permitted (see ALLOWED_REGEX_FLAGS). */
	flags?: string;
	/** Comparison value for contains / equals / starts-with / ends-with. */
	value?: string;
	/** Case-insensitive comparison for the string operators (has no effect on regex - use the i flag). */
	caseInsensitive?: boolean;
	/** Invert this single condition's result. */
	negate?: boolean;
}

export interface RuleAllCondition {
	all: RuleCondition[];
}
export interface RuleAnyCondition {
	any: RuleCondition[];
}
export interface RuleNotCondition {
	not: RuleCondition;
}

export type RuleCondition = RuleLeafCondition | RuleAllCondition | RuleAnyCondition | RuleNotCondition;

export interface RuleDefinition {
	id: string;
	title: string;
	category: string;
	severity: ManagedProtectionSeverity;
	location: ManagedProtectionLocation;
	/** Defaults to true. Disabled rules are dropped at compile time. */
	enabled?: boolean;
	match: RuleCondition;
}

export interface ManagedRuleSetDocument {
	schemaVersion: string;
	id: string;
	title: string;
	version: string;
	description?: string;
	rules: RuleDefinition[];
}

/** Hard limits enforced by the compiler against every (including untrusted) document. */
export const RULESET_LIMITS = {
	maxRules: 500,
	maxConditionNodes: 64,
	maxConditionDepth: 8,
	maxPatternLength: 1000,
	maxValueLength: 2000,
	maxTransforms: 8,
	/** Applied to every extracted field before transforms (mirrors the original `bounded`). */
	maxFieldLength: 16_384,
	/** Tighter bound for header values. */
	headerMaxFieldLength: 512,
} as const;

/** g and y are rejected on purpose: a global/sticky RegExp carries lastIndex state and makes `.test()` non-idempotent across requests. */
export const ALLOWED_REGEX_FLAGS = new Set(["i", "m", "s", "u"]);

export const RULE_FIELD_SOURCES = new Set<RuleFieldSource>(["method", "path", "query", "request-target", "header"]);
export const RULE_TRANSFORMS = new Set<RuleTransform>(["url-decode", "lowercase", "uppercase", "trim", "collapse-whitespace"]);
export const RULE_OPERATORS = new Set<RuleOperator>(["regex", "contains", "equals", "starts-with", "ends-with", "exists", "not-empty"]);
export const RULE_SEVERITIES = new Set<ManagedProtectionSeverity>(["low", "medium", "high", "critical"]);
export const RULE_LOCATIONS = new Set<ManagedProtectionLocation>(["request-target", "query", "header"]);
