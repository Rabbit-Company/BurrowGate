import { describe, expect, test } from "bun:test";
import { serializeStreamProtectionPolicy, storedStreamProtectionPolicy } from "../src/services/stream-protection-policy-service.ts";

describe("stream protection policy - excludedRuleIds", () => {
	test("clearing the textarea (empty string) actually clears excluded rule IDs", () => {
		const existing = serializeStreamProtectionPolicy({ mode: "block", rulesetIds: ["minecraft-java"], excludedRuleIds: "MC-025\nGEN-020" });
		expect(storedStreamProtectionPolicy(existing).excludedRuleIds).toEqual(["MC-025", "GEN-020"]);

		const cleared = serializeStreamProtectionPolicy({ excludedRuleIds: "" }, existing);
		expect(storedStreamProtectionPolicy(cleared).excludedRuleIds).toEqual([]);
	});

	test("omitting the field entirely preserves the existing excluded rule IDs", () => {
		const existing = serializeStreamProtectionPolicy({ mode: "block", rulesetIds: ["minecraft-java"], excludedRuleIds: "MC-025" });
		const updated = serializeStreamProtectionPolicy({ mode: "monitor" }, existing);
		expect(storedStreamProtectionPolicy(updated).excludedRuleIds).toEqual(["MC-025"]);
	});

	test("comma- and newline-separated IDs are parsed and normalized to uppercase", () => {
		const policy = serializeStreamProtectionPolicy({ excludedRuleIds: "mc-025, gen-020\nmc-010" });
		expect(storedStreamProtectionPolicy(policy).excludedRuleIds).toEqual(["MC-025", "GEN-020", "MC-010"]);
	});
});
