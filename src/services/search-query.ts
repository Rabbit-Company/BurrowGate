export type SearchFieldType = "text" | "number" | "ip" | "country" | "status";

export interface SearchField {
	name: string;
	aliases?: readonly string[];
	type: SearchFieldType;
	sql?: string;
	get?: (row: never) => unknown;
	description: string;
	values?: readonly string[];
}

export interface SearchSchema {
	id: string;
	label: string;
	fields: readonly SearchField[];
	textSql?: readonly string[];
	exactSql?: readonly string[];
	text?: (row: never) => string;
	dynamic?: (row: never, path: string) => unknown;
}

export type Comparison = ">" | ">=" | "<" | "<=";

export type ValueMatch =
	| { op: "exists" }
	| { op: "equals"; value: string; glob: boolean }
	| { op: "compare"; comparison: Comparison; value: string }
	| { op: "range"; from: string; to: string };

export type SearchNode =
	| { kind: "and"; children: SearchNode[] }
	| { kind: "or"; children: SearchNode[] }
	| { kind: "not"; child: SearchNode }
	| { kind: "text"; value: string }
	| { kind: "field"; field: SearchField; path: string | null; match: ValueMatch };

export interface ParsedSearch {
	node: SearchNode | null;
	warnings: string[];
}

export class SearchSyntaxError extends Error {
	constructor(
		message: string,
		readonly position: number,
	) {
		super(message);
		this.name = "SearchSyntaxError";
	}
}

export const SEARCH_LIMITS = {
	maxLength: 2_000,
	maxTerms: 64,
	maxDepth: 8,
	maxValueLength: 512,
} as const;

export const GLOB_ANY = "\u0000";
export const GLOB_ONE = "\u0001";

type Token =
	| { type: "("; position: number }
	| { type: ")"; position: number }
	| { type: "word"; position: number; raw: string; value: string; quoted: boolean; negated: boolean };

const FIELD_PREFIX = /^([A-Za-z_][A-Za-z0-9_.]*):/u;

function tokenize(input: string): Token[] {
	const tokens: Token[] = [];
	let index = 0;
	while (index < input.length) {
		const char = input[index]!;
		if (/\s/u.test(char)) {
			index++;
			continue;
		}
		if (char === "(" || char === ")") {
			tokens.push({ type: char, position: index });
			index++;
			continue;
		}
		const start = index;
		let negated = false;
		if (char === "-" && index + 1 < input.length && !/\s/u.test(input[index + 1]!)) {
			negated = true;
			index++;
		}
		let raw = "";
		let value = "";
		let quoted = false;
		while (index < input.length) {
			const current = input[index]!;
			if (/\s/u.test(current) || current === "(" || current === ")") break;
			if (current === '"') {
				const prefixOnly = raw.length > 0 && FIELD_PREFIX.test(raw) && raw.endsWith(":");
				if (raw.length > 0 && !prefixOnly) throw new SearchSyntaxError('A quote can only start a value, as in path:"/a b"', index);
				const closing = readQuoted(input, index);
				raw += input.slice(index, closing.end);
				value += closing.value;
				quoted = true;
				index = closing.end;
				break;
			}
			if (current === "\\") {
				const next = input[index + 1];
				if (next === undefined) throw new SearchSyntaxError("A backslash must escape a character", index);
				raw += current + next;
				value += next;
				index += 2;
				continue;
			}
			raw += current;
			value += current === "*" ? GLOB_ANY : current === "?" ? GLOB_ONE : current;
			index++;
		}
		if (raw.length === 0 && !quoted) {
			tokens.push({ type: "word", position: start, raw: "-", value: "-", quoted: false, negated: false });
			continue;
		}
		tokens.push({ type: "word", position: start, raw, value, quoted, negated });
	}
	return tokens;
}

function readQuoted(input: string, start: number): { value: string; end: number } {
	let value = "";
	let index = start + 1;
	while (index < input.length) {
		const char = input[index]!;
		if (char === "\\") {
			const next = input[index + 1];
			if (next === undefined) break;
			value += next;
			index += 2;
			continue;
		}
		if (char === '"') return { value, end: index + 1 };
		value += char;
		index++;
	}
	throw new SearchSyntaxError("Unterminated quoted value", start);
}

function isOperator(token: Token | undefined, operator: "AND" | "OR" | "NOT"): boolean {
	return token?.type === "word" && !token.quoted && !token.negated && token.raw.toUpperCase() === operator;
}

class Parser {
	private index = 0;
	private terms = 0;
	readonly warnings: string[] = [];

	constructor(
		private readonly tokens: Token[],
		private readonly schema: SearchSchema,
	) {}

	parse(): SearchNode | null {
		if (this.tokens.length === 0) return null;
		const node = this.parseOr(0, null);
		const extra = this.tokens[this.index];
		if (extra) throw new SearchSyntaxError(extra.type === ")" ? "Unmatched closing parenthesis" : "Unexpected input", extra.position);
		return node;
	}

	private peek(): Token | undefined {
		return this.tokens[this.index];
	}

	private enter(depth: number, position: number): number {
		if (depth >= SEARCH_LIMITS.maxDepth) throw new SearchSyntaxError(`Queries can nest at most ${SEARCH_LIMITS.maxDepth} groups deep`, position);
		return depth + 1;
	}

	private parseOr(depth: number, bound: SearchField | null): SearchNode {
		const children = [this.parseAnd(depth, bound)];
		while (isOperator(this.peek(), "OR")) {
			const operator = this.tokens[this.index++]!;
			if (!this.startsTerm()) throw new SearchSyntaxError("OR must be followed by a term", operator.position);
			children.push(this.parseAnd(depth, bound));
		}
		return children.length === 1 ? children[0]! : { kind: "or", children };
	}

	private parseAnd(depth: number, bound: SearchField | null): SearchNode {
		const children = [this.parseUnary(depth, bound)];
		for (;;) {
			if (isOperator(this.peek(), "AND")) {
				const operator = this.tokens[this.index++]!;
				if (!this.startsTerm()) throw new SearchSyntaxError("AND must be followed by a term", operator.position);
				children.push(this.parseUnary(depth, bound));
				continue;
			}
			if (this.startsTerm() && !isOperator(this.peek(), "OR")) {
				children.push(this.parseUnary(depth, bound));
				continue;
			}
			break;
		}
		return children.length === 1 ? children[0]! : { kind: "and", children };
	}

	private startsTerm(): boolean {
		const token = this.peek();
		return token !== undefined && token.type !== ")" && !isOperator(token, "AND") && !isOperator(token, "OR");
	}

	private parseUnary(depth: number, bound: SearchField | null): SearchNode {
		const token = this.peek();
		if (!token) throw new SearchSyntaxError("Expected a term", this.tokens.at(-1)?.position ?? 0);
		if (isOperator(token, "NOT") || (token.type === "word" && token.raw === "-" && !token.quoted)) {
			this.index++;
			if (!this.startsTerm()) throw new SearchSyntaxError("NOT must be followed by a term", token.position);
			return { kind: "not", child: this.parseUnary(depth, bound) };
		}
		return this.parsePrimary(depth, bound);
	}

	private parsePrimary(depth: number, bound: SearchField | null): SearchNode {
		const token = this.tokens[this.index++]!;
		if (token.type === "(") {
			const inner = this.parseOr(this.enter(depth, token.position), bound);
			const closing = this.tokens[this.index++];
			if (closing?.type !== ")") throw new SearchSyntaxError("Missing closing parenthesis", token.position);
			return inner;
		}
		if (token.type === ")") throw new SearchSyntaxError("Unmatched closing parenthesis", token.position);
		const node = this.parseWord(token, depth, bound);
		return token.negated ? { kind: "not", child: node } : node;
	}

	private countTerm(position: number): void {
		if (++this.terms > SEARCH_LIMITS.maxTerms) throw new SearchSyntaxError(`Queries can have at most ${SEARCH_LIMITS.maxTerms} terms`, position);
	}

	private parseWord(token: Extract<Token, { type: "word" }>, depth: number, bound: SearchField | null): SearchNode {
		if (bound) {
			this.countTerm(token.position);
			return { kind: "field", field: bound, path: null, match: parseValue(bound, token.value, token.quoted, token.position) };
		}
		const prefix = FIELD_PREFIX.exec(token.raw);
		if (prefix) {
			const name = prefix[1]!;
			const resolved = resolveField(this.schema, name);
			const rest = token.raw.slice(prefix[0].length);
			if (resolved && !rest.startsWith(":") && !rest.startsWith("//")) {
				const valueStart = token.position + (token.negated ? 1 : 0) + prefix[0].length;
				const valueText = token.value.slice(prefix[0].length);
				if (rest.length === 0) {
					const next = this.peek();
					if (next?.type === "(") {
						this.index++;
						const inner = this.parseOr(this.enter(depth, next.position), resolved.field);
						const closing = this.tokens[this.index++];
						if (closing?.type !== ")") throw new SearchSyntaxError("Missing closing parenthesis", next.position);
						return withPath(inner, resolved.path);
					}
					if (!token.quoted) throw new SearchSyntaxError(`Missing value for ${name}`, valueStart);
				}
				this.countTerm(token.position);
				return { kind: "field", field: resolved.field, path: resolved.path, match: parseValue(resolved.field, valueText, token.quoted, valueStart) };
			}
			if (!resolved && !rest.startsWith(":") && !rest.startsWith("//")) {
				this.warnings.push(`"${name}" is not a field here, so "${token.raw}" was searched as text`);
			}
		}
		this.countTerm(token.position);
		const text = token.value.replaceAll(GLOB_ANY, "*").replaceAll(GLOB_ONE, "?");
		if (text.length > SEARCH_LIMITS.maxValueLength)
			throw new SearchSyntaxError(`Values can be at most ${SEARCH_LIMITS.maxValueLength} characters`, token.position);
		return { kind: "text", value: text };
	}
}

function withPath(node: SearchNode, path: string | null): SearchNode {
	if (path === null) return node;
	switch (node.kind) {
		case "field":
			return { ...node, path };
		case "not":
			return { kind: "not", child: withPath(node.child, path) };
		case "and":
		case "or":
			return { kind: node.kind, children: node.children.map((child) => withPath(child, path)) };
		default:
			return node;
	}
}

const DYNAMIC_FIELD: SearchField = { name: "*", type: "text", description: "" };

function resolveField(schema: SearchSchema, name: string): { field: SearchField; path: string | null } | null {
	const lower = name.toLowerCase();
	const field = schema.fields.find((candidate) => candidate.name === lower || candidate.aliases?.includes(lower));
	if (field) return { field, path: null };
	if (schema.dynamic) return { field: DYNAMIC_FIELD, path: name };
	return null;
}

const COMPARISON = /^(>=|<=|>|<)(.+)$/su;
const RANGE = /^([^.]+)\.\.([^.]+)$/u;

function parseValue(field: SearchField, value: string, quoted: boolean, position: number): ValueMatch {
	if (value.length > SEARCH_LIMITS.maxValueLength) throw new SearchSyntaxError(`Values can be at most ${SEARCH_LIMITS.maxValueLength} characters`, position);
	if (!quoted && value === GLOB_ANY) return { op: "exists" };
	if (!quoted && (field.type === "number" || field.type === "status")) {
		const comparison = COMPARISON.exec(value);
		if (comparison) return { op: "compare", comparison: comparison[1] as Comparison, value: numericValue(field, comparison[2]!, position) };
		const range = RANGE.exec(value);
		if (range) {
			const from = numericValue(field, range[1]!, position);
			const to = numericValue(field, range[2]!, position);
			if (Number(from) > Number(to)) throw new SearchSyntaxError(`The range for ${field.name} runs backwards`, position);
			return { op: "range", from, to };
		}
		if (field.type === "status" && /^[1-5]xx$/iu.test(value)) {
			const base = Number(value[0]) * 100;
			return { op: "range", from: String(base), to: String(base + 99) };
		}
		return { op: "equals", value: numericValue(field, value, position), glob: false };
	}
	if (field.type === "ip" && !quoted && value.includes("/")) return { op: "equals", value: cidrPattern(value, position), glob: true };
	const glob = !quoted && (value.includes(GLOB_ANY) || value.includes(GLOB_ONE));
	if (!glob && (field.type === "number" || field.type === "status")) return { op: "equals", value: numericValue(field, value, position), glob: false };
	if (glob && (field.type === "number" || field.type === "status")) throw new SearchSyntaxError(`${field.name} is a number and cannot use wildcards`, position);
	const literal = glob ? value : value.replaceAll(GLOB_ANY, "*").replaceAll(GLOB_ONE, "?");
	return { op: "equals", value: field.type === "country" ? literal.toUpperCase() : literal, glob };
}

function numericValue(field: SearchField, value: string, position: number): string {
	if (!/^-?\d+(\.\d+)?$/u.test(value)) throw new SearchSyntaxError(`${field.name} must be a number`, position);
	return value;
}

function cidrPattern(value: string, position: number): string {
	const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(8|16|24|32)$/u.exec(value);
	if (!match || match.slice(1, 5).some((octet) => Number(octet) > 255)) {
		throw new SearchSyntaxError("CIDR searches support IPv4 on /8, /16, /24 or /32. Use a wildcard such as 10.0.* otherwise", position);
	}
	const keep = Number(match[5]) / 8;
	const octets = match.slice(1, 1 + keep);
	return keep === 4 ? octets.join(".") : `${octets.join(".")}.${GLOB_ANY}`;
}

export function parseSearch(input: string | null | undefined, schema: SearchSchema): ParsedSearch {
	const source = (input ?? "").replaceAll(GLOB_ANY, "").replaceAll(GLOB_ONE, "");
	if (source.length > SEARCH_LIMITS.maxLength)
		throw new SearchSyntaxError(`Queries can be at most ${SEARCH_LIMITS.maxLength} characters`, SEARCH_LIMITS.maxLength);
	const parser = new Parser(tokenize(source), schema);
	const node = parser.parse();
	return { node, warnings: [...new Set(parser.warnings)] };
}

function globRegExp(value: string): RegExp {
	const source = [...value].map((char) => (char === GLOB_ANY ? ".*" : char === GLOB_ONE ? "." : char.replace(/[.*+?^${}()|[\]\\/]/gu, "\\$&"))).join("");
	return new RegExp(`^${source}$`, "isu");
}

function stringValue(value: unknown): string {
	if (value === null || value === undefined) return "";
	return typeof value === "string" ? value : typeof value === "object" ? JSON.stringify(value) : String(value);
}

function matchesValue(field: SearchField, raw: unknown, match: ValueMatch): boolean {
	if (field.type === "number" || field.type === "status") {
		const number = raw === null || raw === undefined || raw === "" ? null : Number(raw);
		if (match.op === "exists") return number !== null && Number.isFinite(number);
		if (number === null || !Number.isFinite(number)) return false;
		if (match.op === "range") return number >= Number(match.from) && number <= Number(match.to);
		if (match.op === "compare") {
			const target = Number(match.value);
			return match.comparison === ">"
				? number > target
				: match.comparison === ">="
					? number >= target
					: match.comparison === "<"
						? number < target
						: number <= target;
		}
		return number === Number(match.value);
	}
	const text = stringValue(raw);
	if (match.op === "exists") return text !== "";
	if (match.op !== "equals") return false;
	if (match.glob) return globRegExp(match.value).test(text);
	return text.toLowerCase() === match.value.toLowerCase();
}

export function evaluateSearch(node: SearchNode | null, schema: SearchSchema, row: unknown): boolean {
	if (!node) return true;
	switch (node.kind) {
		case "and":
			return node.children.every((child) => evaluateSearch(child, schema, row));
		case "or":
			return node.children.some((child) => evaluateSearch(child, schema, row));
		case "not":
			return !evaluateSearch(node.child, schema, row);
		case "text":
			return (schema.text?.(row as never) ?? "").toLowerCase().includes(node.value.toLowerCase());
		case "field": {
			const raw = node.path !== null ? schema.dynamic?.(row as never, node.path) : node.field.get?.(row as never);
			return matchesValue(node.field, raw, node.match);
		}
	}
}

export function describeSchema(schema: SearchSchema) {
	return {
		id: schema.id,
		label: schema.label,
		dynamicFields: Boolean(schema.dynamic),
		fields: schema.fields.map((field) => ({
			name: field.name,
			aliases: field.aliases ?? [],
			type: field.type,
			description: field.description,
			...(field.values ? { values: field.values } : {}),
		})),
	};
}
