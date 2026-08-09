import type { StreamProtectionMatch, StreamRuleSet, StreamRuleSetContext } from "./stream-protection-service.ts";
import {
	STREAM_ALLOWED_REGEX_FLAGS,
	STREAM_PROTOCOL_FIELDS,
	STREAM_RULE_LOCATIONS,
	STREAM_RULE_OPERATORS,
	STREAM_RULE_SEVERITIES,
	STREAM_RULE_TRANSFORMS,
	STREAM_RULESET_LIMITS,
	STREAM_RULESET_SCHEMA_VERSION,
	type StreamRuleOperator,
	type StreamRuleTransform,
} from "./stream-ruleset-format.ts";

const RULESET_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,127}$/u;
const RULE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

export class StreamRuleSetValidationError extends Error {
	readonly path: string;
	constructor(message: string, path: string) {
		super(`${path}: ${message}`);
		this.name = "StreamRuleSetValidationError";
		this.path = path;
	}
}

interface CompiledLeaf {
	kind: "leaf";
	field: string;
	transforms: StreamRuleTransform[];
	operator: StreamRuleOperator;
	regex: RegExp | null;
	value: string | null;
	caseInsensitive: boolean;
	negate: boolean;
}
interface CompiledAll {
	kind: "all";
	children: CompiledCondition[];
}
interface CompiledAny {
	kind: "any";
	children: CompiledCondition[];
}
interface CompiledNot {
	kind: "not";
	child: CompiledCondition;
}
type CompiledCondition = CompiledLeaf | CompiledAll | CompiledAny | CompiledNot;

interface CompiledRule {
	match: StreamProtectionMatch;
	condition: CompiledCondition;
}

function bounded(value: string, maximum: number): string {
	return value.slice(0, maximum);
}

function applyTransform(value: string, transform: StreamRuleTransform): string {
	switch (transform) {
		case "lowercase":
			return value.toLowerCase();
		case "uppercase":
			return value.toUpperCase();
		case "trim":
			return value.trim();
		case "collapse-whitespace":
			return value.replace(/\s+/gu, " ");
	}
}

function stringifyFieldValue(value: string | number | boolean | undefined): string {
	if (value === undefined) return "";
	if (typeof value === "boolean") return value ? "true" : "false";
	return String(value);
}

function resolveValue(leaf: CompiledLeaf, context: StreamRuleSetContext): string {
	let value = bounded(stringifyFieldValue(context.fields[leaf.field]), STREAM_RULESET_LIMITS.maxFieldLength);
	for (const transform of leaf.transforms) value = applyTransform(value, transform);
	return value;
}

function evaluateLeaf(leaf: CompiledLeaf, context: StreamRuleSetContext): boolean {
	const present = context.fields[leaf.field] !== undefined;
	if (leaf.operator === "exists") {
		return leaf.negate ? !present : present;
	}
	// A field that hasn't been decoded yet (e.g. "login" fields on a connection that never sent a login
	// packet) is unknown, not empty/zero - it must never be treated as a match, regardless of operator or
	// negate. Without this, e.g. gt/gte/lt/lte would coerce a missing numeric field to 0 via Number(""), and
	// a negated not-empty would treat "field absent" the same as "field present but empty".
	if (!present) return false;
	const value = resolveValue(leaf, context);
	let result: boolean;
	switch (leaf.operator) {
		case "regex":
			result = leaf.regex!.test(value);
			break;
		case "not-empty":
			result = value.length > 0;
			break;
		case "contains":
			result = leaf.caseInsensitive ? value.toLowerCase().includes(leaf.value!.toLowerCase()) : value.includes(leaf.value!);
			break;
		case "equals":
			result = leaf.caseInsensitive ? value.toLowerCase() === leaf.value!.toLowerCase() : value === leaf.value!;
			break;
		case "starts-with":
			result = leaf.caseInsensitive ? value.toLowerCase().startsWith(leaf.value!.toLowerCase()) : value.startsWith(leaf.value!);
			break;
		case "ends-with":
			result = leaf.caseInsensitive ? value.toLowerCase().endsWith(leaf.value!.toLowerCase()) : value.endsWith(leaf.value!);
			break;
		case "gt":
		case "gte":
		case "lt":
		case "lte": {
			const numericValue = Number(value);
			const comparand = Number(leaf.value);
			if (Number.isNaN(numericValue) || Number.isNaN(comparand)) {
				result = false;
			} else if (leaf.operator === "gt") {
				result = numericValue > comparand;
			} else if (leaf.operator === "gte") {
				result = numericValue >= comparand;
			} else if (leaf.operator === "lt") {
				result = numericValue < comparand;
			} else {
				result = numericValue <= comparand;
			}
			break;
		}
		default:
			result = false;
	}
	return leaf.negate ? !result : result;
}

function evaluateCondition(node: CompiledCondition, context: StreamRuleSetContext): boolean {
	switch (node.kind) {
		case "leaf":
			return evaluateLeaf(node, context);
		case "all":
			return node.children.every((child) => evaluateCondition(child, context));
		case "any":
			return node.children.some((child) => evaluateCondition(child, context));
		case "not":
			return !evaluateCondition(node.child, context);
	}
}

function isObject(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireString(value: unknown, path: string, { max = 4096, allowEmpty = false }: { max?: number; allowEmpty?: boolean } = {}): string {
	if (typeof value !== "string") throw new StreamRuleSetValidationError("expected a string", path);
	if (!allowEmpty && !value.trim()) throw new StreamRuleSetValidationError("must not be empty", path);
	if (value.length > max) throw new StreamRuleSetValidationError(`must be at most ${max} characters`, path);
	return value;
}

function compilePattern(pattern: string, flags: string | undefined, path: string): RegExp {
	if (pattern.length > STREAM_RULESET_LIMITS.maxPatternLength) {
		throw new StreamRuleSetValidationError(`pattern exceeds ${STREAM_RULESET_LIMITS.maxPatternLength} characters`, path);
	}
	const normalizedFlags = flags ?? "";
	for (const flag of normalizedFlags) {
		if (!STREAM_ALLOWED_REGEX_FLAGS.has(flag)) throw new StreamRuleSetValidationError(`regex flag "${flag}" is not allowed`, path);
	}
	try {
		return new RegExp(pattern, normalizedFlags);
	} catch (error) {
		throw new StreamRuleSetValidationError(`invalid regex: ${(error as Error).message}`, path);
	}
}

function compileTransforms(value: unknown, path: string): StreamRuleTransform[] {
	if (value === undefined) return [];
	if (!Array.isArray(value)) throw new StreamRuleSetValidationError("transforms must be an array", path);
	if (value.length > STREAM_RULESET_LIMITS.maxTransforms) {
		throw new StreamRuleSetValidationError(`at most ${STREAM_RULESET_LIMITS.maxTransforms} transforms allowed`, path);
	}
	return value.map((entry, index) => {
		if (!STREAM_RULE_TRANSFORMS.has(entry as StreamRuleTransform)) {
			throw new StreamRuleSetValidationError(`unknown transform "${String(entry)}"`, `${path}[${index}]`);
		}
		return entry as StreamRuleTransform;
	});
}

function compileLeaf(input: Record<string, unknown>, protocol: string, path: string): CompiledLeaf {
	const field = input.field;
	const knownFields = STREAM_PROTOCOL_FIELDS[protocol];
	if (typeof field !== "string" || !knownFields?.has(field)) {
		throw new StreamRuleSetValidationError(`unknown field "${String(field)}" for protocol "${protocol}"`, `${path}.field`);
	}
	const operator = input.operator;
	if (!STREAM_RULE_OPERATORS.has(operator as StreamRuleOperator))
		throw new StreamRuleSetValidationError(`unknown operator "${String(operator)}"`, `${path}.operator`);

	const transforms = compileTransforms(input.transforms, `${path}.transforms`);

	let regex: RegExp | null = null;
	let value: string | null = null;
	if (operator === "regex") {
		const flags = input.flags === undefined ? undefined : requireString(input.flags, `${path}.flags`, { max: 16, allowEmpty: true });
		regex = compilePattern(requireString(input.pattern, `${path}.pattern`), flags, `${path}.pattern`);
	} else if (
		operator === "contains" ||
		operator === "equals" ||
		operator === "starts-with" ||
		operator === "ends-with" ||
		operator === "gt" ||
		operator === "gte" ||
		operator === "lt" ||
		operator === "lte"
	) {
		value = requireString(input.value, `${path}.value`, { max: STREAM_RULESET_LIMITS.maxValueLength, allowEmpty: true });
	}

	return {
		kind: "leaf",
		field,
		transforms,
		operator: operator as StreamRuleOperator,
		regex,
		value,
		caseInsensitive: input.caseInsensitive === true,
		negate: input.negate === true,
	};
}

function compileCondition(input: unknown, protocol: string, path: string, depth: number, counter: { nodes: number }): CompiledCondition {
	if (depth > STREAM_RULESET_LIMITS.maxConditionDepth) {
		throw new StreamRuleSetValidationError(`condition nesting exceeds ${STREAM_RULESET_LIMITS.maxConditionDepth}`, path);
	}
	if (!isObject(input)) throw new StreamRuleSetValidationError("condition must be an object", path);
	counter.nodes += 1;
	if (counter.nodes > STREAM_RULESET_LIMITS.maxConditionNodes) {
		throw new StreamRuleSetValidationError(`rule has more than ${STREAM_RULESET_LIMITS.maxConditionNodes} condition nodes`, path);
	}

	const composite = ["all", "any", "not"].filter((key) => key in input);
	if (composite.length > 1) throw new StreamRuleSetValidationError(`condition may use only one of all/any/not`, path);

	if ("all" in input || "any" in input) {
		const key = "all" in input ? "all" : "any";
		const children = input[key];
		if (!Array.isArray(children) || children.length === 0) throw new StreamRuleSetValidationError(`"${key}" must be a non-empty array`, `${path}.${key}`);
		const compiled = children.map((child, index) => compileCondition(child, protocol, `${path}.${key}[${index}]`, depth + 1, counter));
		return key === "all" ? { kind: "all", children: compiled } : { kind: "any", children: compiled };
	}
	if ("not" in input) {
		return { kind: "not", child: compileCondition(input.not, protocol, `${path}.not`, depth + 1, counter) };
	}
	return compileLeaf(input, protocol, path);
}

function compileRule(input: unknown, protocol: string, rulesetId: string, index: number, seen: Set<string>): CompiledRule {
	const path = `rules[${index}]`;
	if (!isObject(input)) throw new StreamRuleSetValidationError("rule must be an object", path);

	const id = requireString(input.id, `${path}.id`, { max: 128 });
	if (!RULE_ID_PATTERN.test(id)) throw new StreamRuleSetValidationError("rule id has invalid characters", `${path}.id`);
	if (seen.has(id)) throw new StreamRuleSetValidationError(`duplicate rule id "${id}"`, `${path}.id`);
	seen.add(id);

	const severity = input.severity;
	if (!STREAM_RULE_SEVERITIES.has(severity as never))
		throw new StreamRuleSetValidationError("severity must be low, medium, high or critical", `${path}.severity`);
	const location = input.location;
	if (!STREAM_RULE_LOCATIONS.has(location as never))
		throw new StreamRuleSetValidationError("location must be connection, handshake or login", `${path}.location`);
	if (input.enabled !== undefined && typeof input.enabled !== "boolean") throw new StreamRuleSetValidationError("enabled must be a boolean", `${path}.enabled`);

	return {
		match: {
			ruleId: id,
			rulesetId,
			title: requireString(input.title, `${path}.title`, { max: 256 }),
			category: requireString(input.category, `${path}.category`, { max: 128 }),
			severity: severity as CompiledRule["match"]["severity"],
			location: location as CompiledRule["match"]["location"],
		},
		condition: compileCondition(input.match, protocol, `${path}.match`, 0, { nodes: 0 }),
	};
}

function compileDecode(value: unknown, path: string): { timeoutMs: number; maxBytes: number } {
	if (value === undefined) {
		return { timeoutMs: STREAM_RULESET_LIMITS.decodeTimeoutMsDefault, maxBytes: STREAM_RULESET_LIMITS.decodeMaxBytesDefault };
	}
	if (!isObject(value)) throw new StreamRuleSetValidationError("decode must be an object", path);
	const timeoutMs = value.timeoutMs === undefined ? STREAM_RULESET_LIMITS.decodeTimeoutMsDefault : Number(value.timeoutMs);
	if (!Number.isInteger(timeoutMs) || timeoutMs < STREAM_RULESET_LIMITS.decodeTimeoutMsMin || timeoutMs > STREAM_RULESET_LIMITS.decodeTimeoutMsMax) {
		throw new StreamRuleSetValidationError(
			`must be an integer from ${STREAM_RULESET_LIMITS.decodeTimeoutMsMin} to ${STREAM_RULESET_LIMITS.decodeTimeoutMsMax}`,
			`${path}.timeoutMs`,
		);
	}
	const maxBytes = value.maxBytes === undefined ? STREAM_RULESET_LIMITS.decodeMaxBytesDefault : Number(value.maxBytes);
	if (!Number.isInteger(maxBytes) || maxBytes < STREAM_RULESET_LIMITS.decodeMaxBytesMin || maxBytes > STREAM_RULESET_LIMITS.decodeMaxBytesMax) {
		throw new StreamRuleSetValidationError(
			`must be an integer from ${STREAM_RULESET_LIMITS.decodeMaxBytesMin} to ${STREAM_RULESET_LIMITS.decodeMaxBytesMax}`,
			`${path}.maxBytes`,
		);
	}
	return { timeoutMs, maxBytes };
}

/** Validate and compile a ruleset document into a StreamRuleSet. Throws StreamRuleSetValidationError on any problem. */
export function compileStreamRuleSet(document: unknown): StreamRuleSet {
	if (!isObject(document)) throw new StreamRuleSetValidationError("document must be an object", "$");

	const schemaVersion = requireString(document.schemaVersion, "schemaVersion");
	if (schemaVersion !== STREAM_RULESET_SCHEMA_VERSION) {
		throw new StreamRuleSetValidationError(`unsupported schemaVersion "${schemaVersion}" (expected "${STREAM_RULESET_SCHEMA_VERSION}")`, "schemaVersion");
	}

	const id = requireString(document.id, "id", { max: 128 });
	if (!RULESET_ID_PATTERN.test(id)) throw new StreamRuleSetValidationError("ruleset id has invalid characters", "id");

	const title = requireString(document.title, "title", { max: 256 });
	const version = requireString(document.version, "version", { max: 64 });
	const description = document.description === undefined ? "" : requireString(document.description, "description", { max: 4096, allowEmpty: true });

	const protocol = requireString(document.protocol, "protocol", { max: 64 });
	if (!STREAM_PROTOCOL_FIELDS[protocol]) {
		throw new StreamRuleSetValidationError(`unknown protocol "${protocol}" (no decoder registered for it)`, "protocol");
	}
	const decode = compileDecode(document.decode, "decode");

	if (!Array.isArray(document.rules)) throw new StreamRuleSetValidationError("rules must be an array", "rules");
	if (document.rules.length === 0) throw new StreamRuleSetValidationError("ruleset must contain at least one rule", "rules");
	if (document.rules.length > STREAM_RULESET_LIMITS.maxRules) {
		throw new StreamRuleSetValidationError(`ruleset has more than ${STREAM_RULESET_LIMITS.maxRules} rules`, "rules");
	}

	const seenIds = new Set<string>();
	const compiledRules: CompiledRule[] = [];
	document.rules.forEach((rule, index) => {
		const enabled = isObject(rule) ? rule.enabled !== false : true;
		const compiled = compileRule(rule, protocol, id, index, seenIds);
		if (enabled) compiledRules.push(compiled);
	});

	return {
		id,
		title,
		version,
		description,
		protocol,
		decode,
		inspect(context: StreamRuleSetContext): StreamProtectionMatch[] {
			const matches: StreamProtectionMatch[] = [];
			for (const rule of compiledRules) {
				if (evaluateCondition(rule.condition, context)) matches.push(rule.match);
			}
			return matches;
		},
	};
}

export function tryCompileStreamRuleSet(document: unknown): { ruleSet: StreamRuleSet; error: null } | { ruleSet: null; error: StreamRuleSetValidationError } {
	try {
		return { ruleSet: compileStreamRuleSet(document), error: null };
	} catch (error) {
		if (error instanceof StreamRuleSetValidationError) return { ruleSet: null, error };
		throw error;
	}
}
