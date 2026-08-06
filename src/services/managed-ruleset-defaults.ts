import burrowgateCore from "./rulesets/burrowgate-core.ruleset.json" with { type: "json" };
import { registerManagedRuleSet } from "./managed-protection-service.ts";
import { compileManagedRuleSet } from "./managed-ruleset-compiler.ts";

/**
 * Default rulesets that ship with BurrowGate. They live in the source tree (under
 * services/rulesets) and are embedded in the build via this import, so they travel with every
 * deployment. At startup the loader seeds any that are missing from the on-disk ruleset directory
 * (data/rulesets) (copying, never overwriting) so a fresh install gets a working default that
 * operators can then read, edit, or fork, under Docker or bare-metal alike.
 */
export interface BundledRuleSet {
	/** File name written into the ruleset directory when absent. */
	filename: string;
	/** Parsed ruleset document (validated by the compiler when it is loaded, like any other file). */
	document: unknown;
}

export const DEFAULT_RULESET_ID = "burrowgate-core";

export const bundledRuleSets: BundledRuleSet[] = [{ filename: "burrowgate-core.ruleset.json", document: burrowgateCore }];

export interface RegisteredBundledRuleSet {
	id: string;
	title: string;
	version: string;
	ruleCount: number;
	filename: string;
}

/**
 * Compile and register the bundled default rulesets straight from memory (no filesystem access).
 *
 * Startup normally uses loadManagedRuleSets() so operators can edit rulesets on disk. This helper is
 * for contexts that need the defaults available synchronously without disk: unit tests, and the
 * loader's own last-resort fallback if the on-disk directory can't be read.
 */
export function registerBundledRuleSets(options: { defaultRulesetId?: string } = {}): RegisteredBundledRuleSet[] {
	const wantedDefault = options.defaultRulesetId ?? DEFAULT_RULESET_ID;
	const registered: RegisteredBundledRuleSet[] = [];
	for (const bundled of bundledRuleSets) {
		const ruleSet = compileManagedRuleSet(bundled.document);
		registerManagedRuleSet(ruleSet, { makeDefault: ruleSet.id === wantedDefault });
		const ruleCount = Array.isArray((bundled.document as { rules?: unknown[] } | null)?.rules) ? (bundled.document as { rules: unknown[] }).rules.length : 0;
		registered.push({ id: ruleSet.id, title: ruleSet.title, version: ruleSet.version, ruleCount, filename: bundled.filename });
	}
	return registered;
}
