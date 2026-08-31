import { access, mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { Logger } from "../logger.ts";
import { bundledStreamRuleSets } from "./stream-ruleset-defaults.ts";
import { registerStreamRuleSet } from "./stream-protection-service.ts";
import { compileStreamRuleSet, StreamRuleSetValidationError } from "./stream-ruleset-compiler.ts";

const DEFAULT_DIRECTORY = "data/stream-rulesets";

export interface LoadedStreamRuleSetInfo {
	id: string;
	file: string;
	title: string;
	version: string;
	protocol: string;
	ruleCount: number;
}

export interface FailedStreamRuleSetInfo {
	file: string;
	error: string;
}

export interface LoadStreamRuleSetsResult {
	directory: string;
	loaded: LoadedStreamRuleSetInfo[];
	failed: FailedStreamRuleSetInfo[];
}

async function seedBundledRuleSets(directory: string): Promise<void> {
	await mkdir(directory, { recursive: true });
	for (const bundled of bundledStreamRuleSets) {
		const path = `${directory}/${bundled.filename}`;
		try {
			await access(path);
			continue;
		} catch {}
		try {
			await writeFile(path, `${JSON.stringify(bundled.document, null, "\t")}\n`);
			Logger.info(`Seeded default stream-protection ruleset "${bundled.filename}" into "${directory}"`);
		} catch (error) {
			Logger.error(`Failed to seed default stream ruleset "${bundled.filename}" into "${directory}"`, { error });
		}
	}
}

export async function loadStreamRuleSets(options: { directory?: string } = {}): Promise<LoadStreamRuleSetsResult> {
	const directory = options.directory ?? DEFAULT_DIRECTORY;
	const result: LoadStreamRuleSetsResult = { directory, loaded: [], failed: [] };

	await seedBundledRuleSets(directory);

	let files: string[];
	try {
		files = (await readdir(directory)).filter((name) => name.endsWith(".json")).sort();
	} catch (error) {
		Logger.error(`Cannot read stream-protection ruleset directory "${directory}"; stream protection will fail open until rulesets are available`, {
			error,
		});
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
			const ruleSet = compileStreamRuleSet(document);
			if (registeredIds.has(ruleSet.id)) throw new Error(`duplicate ruleset id "${ruleSet.id}" (already loaded from another file)`);

			registerStreamRuleSet(ruleSet);
			registeredIds.add(ruleSet.id);
			result.loaded.push({ id: ruleSet.id, file, title: ruleSet.title, version: ruleSet.version, protocol: ruleSet.protocol, ruleCount });
		} catch (error) {
			const message = error instanceof StreamRuleSetValidationError ? error.message : (error as Error).message;
			result.failed.push({ file, error: message });
			Logger.error(`Failed to load stream-protection ruleset "${file}"`, { error: message });
		}
	}

	Logger.info(`Loaded ${result.loaded.length} stream-protection ruleset(s) from "${directory}"`, {
		rulesets: result.loaded.map((item) => `${item.id}@${item.version} (${item.protocol}, ${item.ruleCount} rules)`),
	});
	return result;
}
