import { access, mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { Logger } from "../logger.ts";
import { bundledRuleSets, registerBundledRuleSets } from "./managed-ruleset-defaults.ts";
import { registerManagedRuleSet } from "./managed-protection-service.ts";
import { compileManagedRuleSet, RuleSetValidationError } from "./managed-ruleset-compiler.ts";

/**
 * Managed-protection rulesets live on disk as plain JSON (data/rulesets/*.json), not as bundled
 * code, so operators can read, edit, and fork them. The shipped burrowgate-core file doubles as a
 * template. This loader is called once at startup: it compiles every ruleset in the directory and
 * registers it with the managed-protection service. A single broken file is logged and skipped
 * rather than crashing the gateway.
 */

const DEFAULT_DIRECTORY = "data/rulesets";
const DEFAULT_RULESET_ID = "burrowgate-core";

export interface LoadManagedRuleSetsOptions {
	/** Directory to scan, relative to the working directory. Defaults to "data/rulesets". */
	directory?: string;
	/** Ruleset id registered as the fallback for sites using rulesetId "default". Defaults to "burrowgate-core". */
	defaultRulesetId?: string;
}

export interface LoadedRuleSetInfo {
	id: string;
	file: string;
	title: string;
	version: string;
	ruleCount: number;
}

export interface FailedRuleSetInfo {
	file: string;
	error: string;
}

export interface LoadManagedRuleSetsResult {
	directory: string;
	loaded: LoadedRuleSetInfo[];
	failed: FailedRuleSetInfo[];
	defaultRulesetId: string | null;
}

/**
 * Write any bundled default ruleset that is not already present in the directory. Existing files are
 * left untouched so operator edits and forks are never overwritten. Also ensures the directory
 * exists, so a fresh install (or a fresh Docker volume) is ready to load on first boot.
 */
async function seedBundledRuleSets(directory: string): Promise<void> {
	await mkdir(directory, { recursive: true });
	for (const bundled of bundledRuleSets) {
		const path = `${directory}/${bundled.filename}`;
		try {
			await access(path);
			continue; // already present - never clobber
		} catch {
			// missing - seed it below
		}
		try {
			await writeFile(path, `${JSON.stringify(bundled.document, null, "\t")}\n`);
			Logger.info(`[BurrowGate] Seeded default managed-protection ruleset "${bundled.filename}" into "${directory}"`);
		} catch (error) {
			Logger.error(`[BurrowGate] Failed to seed default ruleset "${bundled.filename}" into "${directory}"`, { error });
		}
	}
}

export async function loadManagedRuleSets(options: LoadManagedRuleSetsOptions = {}): Promise<LoadManagedRuleSetsResult> {
	const directory = options.directory ?? DEFAULT_DIRECTORY;
	const wantedDefault = options.defaultRulesetId ?? DEFAULT_RULESET_ID;
	const result: LoadManagedRuleSetsResult = { directory, loaded: [], failed: [], defaultRulesetId: null };

	await seedBundledRuleSets(directory);

	let files: string[];
	try {
		files = (await readdir(directory)).filter((name) => name.endsWith(".json")).sort();
	} catch (error) {
		Logger.error(
			`[BurrowGate] Cannot read managed-protection ruleset directory "${directory}"; managed protection will fail open until rulesets are available`,
			{ error },
		);
		return result;
	}

	const registeredIds = new Set<string>();
	for (const file of files) {
		const path = `${directory}/${file}`;
		try {
			let document: unknown;
			try {
				document = JSON.parse(await readFile(path, "utf8"));
			} catch (error) {
				throw new Error(`invalid JSON: ${(error as Error).message}`);
			}
			const ruleCount = Array.isArray((document as { rules?: unknown[] } | null)?.rules) ? (document as { rules: unknown[] }).rules.length : 0;
			const ruleSet = compileManagedRuleSet(document);
			if (registeredIds.has(ruleSet.id)) throw new Error(`duplicate ruleset id "${ruleSet.id}" (already loaded from another file)`);

			registerManagedRuleSet(ruleSet, { makeDefault: ruleSet.id === wantedDefault });
			registeredIds.add(ruleSet.id);
			if (ruleSet.id === wantedDefault) result.defaultRulesetId = ruleSet.id;
			result.loaded.push({ id: ruleSet.id, file, title: ruleSet.title, version: ruleSet.version, ruleCount });
		} catch (error) {
			const message = error instanceof RuleSetValidationError ? error.message : (error as Error).message;
			result.failed.push({ file, error: message });
			Logger.error(`[BurrowGate] Failed to load managed-protection ruleset "${file}"`, { error: message });
		}
	}

	if (result.loaded.length === 0) {
		const fallback = registerBundledRuleSets({ defaultRulesetId: wantedDefault });
		for (const item of fallback) {
			result.loaded.push({ id: item.id, file: `${item.filename} (bundled fallback)`, title: item.title, version: item.version, ruleCount: item.ruleCount });
		}
		if (fallback.some((item) => item.id === wantedDefault)) result.defaultRulesetId = wantedDefault;
		Logger.error(
			`[BurrowGate] No managed-protection rulesets loaded from "${directory}"; registered ${fallback.length} bundled default(s) in memory as a fallback`,
		);
	} else {
		Logger.info(`[BurrowGate] Loaded ${result.loaded.length} managed-protection ruleset(s) from "${directory}"`, {
			rulesets: result.loaded.map((item) => `${item.id}@${item.version} (${item.ruleCount} rules)`),
			default: result.defaultRulesetId ?? "(none - sites using the default ruleset will fail open)",
		});
		if (!result.defaultRulesetId) {
			Logger.warn(
				`[BurrowGate] Default ruleset "${wantedDefault}" was not found in "${directory}"; sites referencing the default ruleset will fail open until it is present`,
			);
		}
	}
	return result;
}
