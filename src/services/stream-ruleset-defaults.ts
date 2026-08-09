import streamConnectionAbuse from "./rulesets/stream-connection-abuse.stream-ruleset.json" with { type: "json" };
import minecraftJava from "./rulesets/minecraft-java.stream-ruleset.json" with { type: "json" };
import { registerStreamRuleSet } from "./stream-protection-service.ts";
import { compileStreamRuleSet } from "./stream-ruleset-compiler.ts";

export interface BundledStreamRuleSet {
	/** File name written into the ruleset directory when absent. */
	filename: string;
	document: unknown;
}

export const bundledStreamRuleSets: BundledStreamRuleSet[] = [
	{ filename: "stream-connection-abuse.stream-ruleset.json", document: streamConnectionAbuse },
	{ filename: "minecraft-java.stream-ruleset.json", document: minecraftJava },
];

export interface RegisteredBundledStreamRuleSet {
	id: string;
	title: string;
	version: string;
	ruleCount: number;
	filename: string;
}

export function registerBundledStreamRuleSets(): RegisteredBundledStreamRuleSet[] {
	const registered: RegisteredBundledStreamRuleSet[] = [];
	for (const bundled of bundledStreamRuleSets) {
		const ruleSet = compileStreamRuleSet(bundled.document);
		registerStreamRuleSet(ruleSet);
		const ruleCount = Array.isArray((bundled.document as { rules?: unknown[] } | null)?.rules) ? (bundled.document as { rules: unknown[] }).rules.length : 0;
		registered.push({ id: ruleSet.id, title: ruleSet.title, version: ruleSet.version, ruleCount, filename: bundled.filename });
	}
	return registered;
}
