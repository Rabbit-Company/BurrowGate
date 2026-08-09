import { describe, expect, test } from "bun:test";
import { compileStreamRuleSet } from "../src/services/stream-ruleset-compiler.ts";

function ruleSet(match: unknown) {
	return compileStreamRuleSet({
		schemaVersion: "1",
		id: "test-ruleset",
		title: "Test ruleset",
		version: "v1",
		protocol: "minecraft-java",
		rules: [{ id: "TEST-001", title: "Test rule", category: "test", severity: "low", location: "login", match }],
	});
}

describe("stream ruleset compiler - missing field semantics", () => {
	test("gt/gte/lt/lte never match when the field hasn't been decoded yet", () => {
		const compiled = ruleSet({ field: "protocol_version", operator: "lte", value: "0" });
		expect(compiled.inspect({ fields: {} })).toEqual([]);
		expect(compiled.inspect({ fields: { protocol_version: -1 } })).toHaveLength(1);
	});

	test("negated not-empty never matches an absent field, only a genuinely empty one", () => {
		const compiled = ruleSet({ field: "username", operator: "not-empty", negate: true });
		expect(compiled.inspect({ fields: {} })).toEqual([]);
		expect(compiled.inspect({ fields: { username: "" } })).toHaveLength(1);
		expect(compiled.inspect({ fields: { username: "Notch" } })).toEqual([]);
	});

	test("an absent field short-circuits to false even inside an any/all tree", () => {
		const compiled = ruleSet({
			any: [
				{ field: "username", operator: "not-empty", negate: true },
				{ field: "username_length", operator: "gt", value: "16" },
			],
		});
		expect(compiled.inspect({ fields: {} })).toEqual([]);
		expect(compiled.inspect({ fields: { username: "a".repeat(20), username_length: 20 } })).toHaveLength(1);
	});

	test("exists still distinguishes presence from emptiness", () => {
		const compiled = ruleSet({ field: "username", operator: "exists" });
		expect(compiled.inspect({ fields: {} })).toEqual([]);
		expect(compiled.inspect({ fields: { username: "" } })).toHaveLength(1);
	});
});
