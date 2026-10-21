import { db } from "./client.ts";
import { GLOB_ANY, GLOB_ONE, SearchSyntaxError, type SearchNode, type SearchSchema, type ValueMatch } from "../services/search-query.ts";

export type SqlFragment = ReturnType<typeof db.unsafe>;

export function searchSql(node: SearchNode | null, schema: SearchSchema): SqlFragment {
	return node ? db`AND (${compile(node, schema)})` : db``;
}

function joined(parts: SqlFragment[], operator: "AND" | "OR"): SqlFragment {
	return parts.slice(1).reduce((left, right) => (operator === "AND" ? db`${left} AND ${right}` : db`${left} OR ${right}`), parts[0]!);
}

function compile(node: SearchNode, schema: SearchSchema): SqlFragment {
	switch (node.kind) {
		case "and":
			return db`(${joined(
				node.children.map((child) => compile(child, schema)),
				"AND",
			)})`;
		case "or":
			return db`(${joined(
				node.children.map((child) => compile(child, schema)),
				"OR",
			)})`;
		case "not":
			return db`NOT (${compile(node.child, schema)})`;
		case "text":
			return freeText(node.value, schema);
		case "field": {
			if (!node.field.sql) throw new SearchSyntaxError(`${node.field.name} cannot be searched here`, 0);
			return fieldPredicate(node.field.sql, node.field.type === "number" || node.field.type === "status", node.match);
		}
	}
}

function lowerText(column: string): SqlFragment {
	return db.unsafe(`LOWER(COALESCE(${column},''))`);
}

export function likePattern(value: string): string {
	let pattern = "";
	for (const char of value.toLowerCase()) {
		if (char === GLOB_ANY) pattern += "%";
		else if (char === GLOB_ONE) pattern += "_";
		else if (char === "!" || char === "%" || char === "_") pattern += `!${char}`;
		else pattern += char;
	}
	return pattern;
}

function freeText(value: string, schema: SearchSchema): SqlFragment {
	const contains = `%${likePattern(value)}%`;
	const parts = [
		...(schema.textSql ?? []).map((column) => db`${lowerText(column)} LIKE ${contains} ESCAPE '!'`),
		...(schema.exactSql ?? []).map((column) => db`${db.unsafe(column)} = ${value}`),
	];
	if (parts.length === 0) throw new SearchSyntaxError("Free text is not supported here; search a field, as in name:value", 0);
	return db`(${joined(parts, "OR")})`;
}

function fieldPredicate(column: string, numeric: boolean, match: ValueMatch): SqlFragment {
	const expression = db.unsafe(column);
	if (numeric) {
		switch (match.op) {
			case "exists":
				return db`${expression} IS NOT NULL`;
			case "equals":
				return db`(${expression} IS NOT NULL AND ${expression} = ${Number(match.value)})`;
			case "range":
				return db`(${expression} IS NOT NULL AND ${expression} >= ${Number(match.from)} AND ${expression} <= ${Number(match.to)})`;
			case "compare":
				return db`(${expression} IS NOT NULL AND ${expression} ${db.unsafe(match.comparison)} ${Number(match.value)})`;
		}
	}
	switch (match.op) {
		case "exists":
			return db`COALESCE(${expression},'') <> ''`;
		case "equals":
			return match.glob ? db`${lowerText(column)} LIKE ${likePattern(match.value)} ESCAPE '!'` : db`${lowerText(column)} = ${match.value.toLowerCase()}`;
		default:
			throw new SearchSyntaxError("Comparisons only apply to number fields", 0);
	}
}
