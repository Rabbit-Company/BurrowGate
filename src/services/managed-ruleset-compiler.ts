import type { ManagedProtectionMatch, ManagedRuleSet, ManagedRuleSetContext } from "./managed-protection-service.ts";
import {
	ALLOWED_REGEX_FLAGS,
	RULE_FIELD_SOURCES,
	RULE_LOCATIONS,
	RULE_OPERATORS,
	RULE_SEVERITIES,
	RULE_TRANSFORMS,
	RULESET_LIMITS,
	RULESET_SCHEMA_VERSION,
	type RuleFieldSource,
	type RuleOperator,
	type RuleTransform,
} from "./managed-ruleset-format.ts";

const RULESET_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,127}$/u;
const RULE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

export class RuleSetValidationError extends Error {
	readonly path: string;
	constructor(message: string, path: string) {
		super(`${path}: ${message}`);
		this.name = "RuleSetValidationError";
		this.path = path;
	}
}

interface CompiledLeaf {
	kind: "leaf";
	source: RuleFieldSource;
	header: string | null;
	transforms: RuleTransform[];
	operator: RuleOperator;
	regex: RegExp | null;
	value: string | null;
	caseInsensitive: boolean;
	negate: boolean;
	cacheKey: string;
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
	match: ManagedProtectionMatch;
	condition: CompiledCondition;
}

function bounded(value: string, maximum: number): string {
	return value.slice(0, maximum);
}

function urlDecode(value: string): string {
	let result = value;
	for (let pass = 0; pass < 2; pass += 1) {
		try {
			const next = decodeURIComponent(result);
			if (next === result) break;
			result = next;
		} catch {
			break;
		}
	}
	return result;
}

function applyTransform(value: string, transform: RuleTransform): string {
	switch (transform) {
		case "url-decode":
			return urlDecode(value);
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

function rawField(context: ManagedRuleSetContext, source: RuleFieldSource, header: string | null): string | null {
	switch (source) {
		case "method":
			return context.request.method;
		case "path":
			return context.url.pathname;
		case "query":
			return context.url.search;
		case "request-target":
			return `${context.url.pathname}${context.url.search}`;
		case "header":
			return context.request.headers.get(header ?? "");
	}
}

function resolveValue(leaf: CompiledLeaf, context: ManagedRuleSetContext, cache: Map<string, string>): string {
	const cached = cache.get(leaf.cacheKey);
	if (cached !== undefined) return cached;
	const maxLength = leaf.source === "header" ? RULESET_LIMITS.headerMaxFieldLength : RULESET_LIMITS.maxFieldLength;
	let value = bounded(rawField(context, leaf.source, leaf.header) ?? "", maxLength);
	for (const transform of leaf.transforms) value = applyTransform(value, transform);
	cache.set(leaf.cacheKey, value);
	return value;
}

function evaluateLeaf(leaf: CompiledLeaf, context: ManagedRuleSetContext, cache: Map<string, string>): boolean {
	if (leaf.operator === "exists") {
		const present = leaf.source === "header" ? context.request.headers.has(leaf.header ?? "") : rawField(context, leaf.source, leaf.header) !== null;
		return leaf.negate ? !present : present;
	}
	const value = resolveValue(leaf, context, cache);
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
		default:
			result = false;
	}
	return leaf.negate ? !result : result;
}

function evaluateCondition(node: CompiledCondition, context: ManagedRuleSetContext, cache: Map<string, string>): boolean {
	switch (node.kind) {
		case "leaf":
			return evaluateLeaf(node, context, cache);
		case "all":
			return node.children.every((child) => evaluateCondition(child, context, cache));
		case "any":
			return node.children.some((child) => evaluateCondition(child, context, cache));
		case "not":
			return !evaluateCondition(node.child, context, cache);
	}
}

function isObject(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireString(value: unknown, path: string, { max = 4096, allowEmpty = false }: { max?: number; allowEmpty?: boolean } = {}): string {
	if (typeof value !== "string") throw new RuleSetValidationError("expected a string", path);
	if (!allowEmpty && !value.trim()) throw new RuleSetValidationError("must not be empty", path);
	if (value.length > max) throw new RuleSetValidationError(`must be at most ${max} characters`, path);
	return value;
}

function compilePattern(pattern: string, flags: string | undefined, path: string): RegExp {
	if (pattern.length > RULESET_LIMITS.maxPatternLength) {
		throw new RuleSetValidationError(`pattern exceeds ${RULESET_LIMITS.maxPatternLength} characters`, path);
	}
	const normalizedFlags = flags ?? "";
	for (const flag of normalizedFlags) {
		if (!ALLOWED_REGEX_FLAGS.has(flag)) throw new RuleSetValidationError(`regex flag "${flag}" is not allowed`, path);
	}
	try {
		return new RegExp(pattern, normalizedFlags);
	} catch (error) {
		throw new RuleSetValidationError(`invalid regex: ${(error as Error).message}`, path);
	}
}

function compileTransforms(value: unknown, path: string): RuleTransform[] {
	if (value === undefined) return [];
	if (!Array.isArray(value)) throw new RuleSetValidationError("transforms must be an array", path);
	if (value.length > RULESET_LIMITS.maxTransforms) throw new RuleSetValidationError(`at most ${RULESET_LIMITS.maxTransforms} transforms allowed`, path);
	return value.map((entry, index) => {
		if (!RULE_TRANSFORMS.has(entry as RuleTransform)) throw new RuleSetValidationError(`unknown transform "${String(entry)}"`, `${path}[${index}]`);
		return entry as RuleTransform;
	});
}

function compileLeaf(input: Record<string, unknown>, path: string): CompiledLeaf {
	const source = input.field;
	if (!RULE_FIELD_SOURCES.has(source as RuleFieldSource)) throw new RuleSetValidationError(`unknown field "${String(source)}"`, `${path}.field`);
	const operator = input.operator;
	if (!RULE_OPERATORS.has(operator as RuleOperator)) throw new RuleSetValidationError(`unknown operator "${String(operator)}"`, `${path}.operator`);

	let header: string | null = null;
	if (source === "header") {
		header = requireString(input.header, `${path}.header`, { max: 256 }).toLowerCase();
	} else if (input.header !== undefined) {
		throw new RuleSetValidationError('"header" is only valid when field is "header"', `${path}.header`);
	}

	const transforms = compileTransforms(input.transforms, `${path}.transforms`);

	let regex: RegExp | null = null;
	let value: string | null = null;
	if (operator === "regex") {
		const flags = input.flags === undefined ? undefined : requireString(input.flags, `${path}.flags`, { max: 16, allowEmpty: true });
		regex = compilePattern(requireString(input.pattern, `${path}.pattern`), flags, `${path}.pattern`);
	} else if (operator === "contains" || operator === "equals" || operator === "starts-with" || operator === "ends-with") {
		value = requireString(input.value, `${path}.value`, { max: RULESET_LIMITS.maxValueLength, allowEmpty: true });
	}

	return {
		kind: "leaf",
		source: source as RuleFieldSource,
		header,
		transforms,
		operator: operator as RuleOperator,
		regex,
		value,
		caseInsensitive: input.caseInsensitive === true,
		negate: input.negate === true,
		cacheKey: `${String(source)}\u0000${header ?? ""}\u0000${transforms.join(",")}`,
	};
}

function compileCondition(input: unknown, path: string, depth: number, counter: { nodes: number }): CompiledCondition {
	if (depth > RULESET_LIMITS.maxConditionDepth) throw new RuleSetValidationError(`condition nesting exceeds ${RULESET_LIMITS.maxConditionDepth}`, path);
	if (!isObject(input)) throw new RuleSetValidationError("condition must be an object", path);
	counter.nodes += 1;
	if (counter.nodes > RULESET_LIMITS.maxConditionNodes)
		throw new RuleSetValidationError(`rule has more than ${RULESET_LIMITS.maxConditionNodes} condition nodes`, path);

	const composite = ["all", "any", "not"].filter((key) => key in input);
	if (composite.length > 1) throw new RuleSetValidationError(`condition may use only one of all/any/not`, path);

	if ("all" in input || "any" in input) {
		const key = "all" in input ? "all" : "any";
		const children = input[key];
		if (!Array.isArray(children) || children.length === 0) throw new RuleSetValidationError(`"${key}" must be a non-empty array`, `${path}.${key}`);
		const compiled = children.map((child, index) => compileCondition(child, `${path}.${key}[${index}]`, depth + 1, counter));
		return key === "all" ? { kind: "all", children: compiled } : { kind: "any", children: compiled };
	}
	if ("not" in input) {
		return { kind: "not", child: compileCondition(input.not, `${path}.not`, depth + 1, counter) };
	}
	return compileLeaf(input, path);
}

function compileRule(input: unknown, index: number, seen: Set<string>): CompiledRule {
	const path = `rules[${index}]`;
	if (!isObject(input)) throw new RuleSetValidationError("rule must be an object", path);

	const id = requireString(input.id, `${path}.id`, { max: 128 });
	if (!RULE_ID_PATTERN.test(id)) throw new RuleSetValidationError("rule id has invalid characters", `${path}.id`);
	if (seen.has(id)) throw new RuleSetValidationError(`duplicate rule id "${id}"`, `${path}.id`);
	seen.add(id);

	const severity = input.severity;
	if (!RULE_SEVERITIES.has(severity as never)) throw new RuleSetValidationError("severity must be low, medium, high or critical", `${path}.severity`);
	const location = input.location;
	if (!RULE_LOCATIONS.has(location as never)) throw new RuleSetValidationError("location must be request-target, query or header", `${path}.location`);
	if (input.enabled !== undefined && typeof input.enabled !== "boolean") throw new RuleSetValidationError("enabled must be a boolean", `${path}.enabled`);

	return {
		match: {
			ruleId: id,
			title: requireString(input.title, `${path}.title`, { max: 256 }),
			category: requireString(input.category, `${path}.category`, { max: 128 }),
			severity: severity as CompiledRule["match"]["severity"],
			location: location as CompiledRule["match"]["location"],
		},
		condition: compileCondition(input.match, `${path}.match`, 0, { nodes: 0 }),
	};
}

/** Validate and compile a ruleset document into a ManagedRuleSet. Throws RuleSetValidationError on any problem. */
export function compileManagedRuleSet(document: unknown): ManagedRuleSet {
	if (!isObject(document)) throw new RuleSetValidationError("document must be an object", "$");

	const schemaVersion = requireString(document.schemaVersion, "schemaVersion");
	if (schemaVersion !== RULESET_SCHEMA_VERSION)
		throw new RuleSetValidationError(`unsupported schemaVersion "${schemaVersion}" (expected "${RULESET_SCHEMA_VERSION}")`, "schemaVersion");

	const id = requireString(document.id, "id", { max: 128 });
	if (!RULESET_ID_PATTERN.test(id)) throw new RuleSetValidationError("ruleset id has invalid characters", "id");

	const title = requireString(document.title, "title", { max: 256 });
	const version = requireString(document.version, "version", { max: 64 });
	const description = document.description === undefined ? "" : requireString(document.description, "description", { max: 4096, allowEmpty: true });

	if (!Array.isArray(document.rules)) throw new RuleSetValidationError("rules must be an array", "rules");
	if (document.rules.length === 0) throw new RuleSetValidationError("ruleset must contain at least one rule", "rules");
	if (document.rules.length > RULESET_LIMITS.maxRules) throw new RuleSetValidationError(`ruleset has more than ${RULESET_LIMITS.maxRules} rules`, "rules");

	const seenIds = new Set<string>();
	const compiledRules: CompiledRule[] = [];
	document.rules.forEach((rule, index) => {
		const enabled = isObject(rule) ? rule.enabled !== false : true;
		const compiled = compileRule(rule, index, seenIds);
		if (enabled) compiledRules.push(compiled);
	});

	return {
		id,
		title,
		version,
		description,
		inspect(context: ManagedRuleSetContext): ManagedProtectionMatch[] {
			const cache = new Map<string, string>();
			const matches: ManagedProtectionMatch[] = [];
			for (const rule of compiledRules) {
				if (evaluateCondition(rule.condition, context, cache)) matches.push(rule.match);
			}
			return matches;
		},
	};
}

export function tryCompileManagedRuleSet(document: unknown): { ruleSet: ManagedRuleSet; error: null } | { ruleSet: null; error: RuleSetValidationError } {
	try {
		return { ruleSet: compileManagedRuleSet(document), error: null };
	} catch (error) {
		if (error instanceof RuleSetValidationError) return { ruleSet: null, error };
		throw error;
	}
}
