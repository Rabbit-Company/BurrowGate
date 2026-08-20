/**
 * Diffs bench/results/ files for two Bun versions (e.g. one from the
 * current bun release, one from `bun upgrade --canary`) and flags anything
 * that regressed beyond REGRESSION_THRESHOLD_PERCENT, so a future canary
 * that's "a lot slower" at something BurrowGate depends on shows up
 * immediately. Reads the per-suite files bench/run-all.ts writes, named
 * `<bunVersion>-<platform>-<arch>-<suiteSlug>.json`.
 *
 * Usage:
 *   bun bench/compare.ts                     # lists available versions
 *   bun bench/compare.ts 1.3.14 1.4.0        # compares all suites both versions share
 */
import { readdir } from "node:fs/promises";
import { loadRun, key, type BenchResult } from "./lib/harness.ts";
import { SUITES } from "./lib/suites.ts";

const REGRESSION_THRESHOLD_PERCENT = 10;
const RESULTS_DIR = `${import.meta.dir}/results`;

/** Splits `<prefix>-<suiteSlug>.json` into its prefix and slug using the known suite list, since `prefix` (bunVersion-platform-arch) may itself contain dashes. */
function splitFilename(filename: string): { prefix: string; slug: string } | null {
	if (!filename.endsWith(".json")) return null;
	const base = filename.slice(0, -".json".length);
	for (const suite of SUITES) {
		if (base.endsWith(`-${suite.slug}`)) return { prefix: base.slice(0, -(suite.slug.length + 1)), slug: suite.slug };
	}
	return null;
}

async function indexResultsDir(): Promise<Map<string, Map<string, string>>> {
	const files = await readdir(RESULTS_DIR).catch(() => [] as string[]);
	const byPrefix = new Map<string, Map<string, string>>();
	for (const file of files) {
		const split = splitFilename(file);
		if (!split) continue;
		if (!byPrefix.has(split.prefix)) byPrefix.set(split.prefix, new Map());
		byPrefix.get(split.prefix)!.set(split.slug, `${RESULTS_DIR}/${file}`);
	}
	return byPrefix;
}

function resolvePrefix(byPrefix: Map<string, Map<string, string>>, arg: string): string | null {
	if (byPrefix.has(arg)) return arg;
	const matches = [...byPrefix.keys()].filter((p) => p === arg || p.startsWith(`${arg}-`));
	if (matches.length === 1) return matches[0]!;
	return null;
}

function higherIsBetter(unit: BenchResult["unit"]): boolean {
	return unit !== "ms";
}

function fmt(n: number): string {
	if (!Number.isFinite(n)) return "n/a";
	if (Math.abs(n) >= 1000) return n.toFixed(0);
	if (Math.abs(n) >= 10) return n.toFixed(1);
	return n.toFixed(3);
}

async function main(): Promise<void> {
	const byPrefix = await indexResultsDir();

	if (byPrefix.size === 0) {
		console.error(`No result files found in ${RESULTS_DIR}. Run "bun bench/run-all.ts" first.`);
		process.exit(1);
	}

	const [baselineArg, candidateArg] = process.argv.slice(2);
	if (!baselineArg || !candidateArg) {
		console.log(`Usage: bun bench/compare.ts <baselineVersion> <candidateVersion>\n`);
		console.log("Available versions in bench/results/:");
		for (const [prefix, slugs] of byPrefix) console.log(`  ${prefix}  (${slugs.size} suite file(s))`);
		process.exit(1);
	}

	const baselinePrefix = resolvePrefix(byPrefix, baselineArg);
	const candidatePrefix = resolvePrefix(byPrefix, candidateArg);
	if (!baselinePrefix || !candidatePrefix) {
		if (!baselinePrefix) console.error(`No unambiguous match for baseline "${baselineArg}" in bench/results/.`);
		if (!candidatePrefix) console.error(`No unambiguous match for candidate "${candidateArg}" in bench/results/.`);
		console.error(`Available: ${[...byPrefix.keys()].join(", ")}`);
		process.exit(1);
	}

	const baselineFiles = byPrefix.get(baselinePrefix)!;
	const candidateFiles = byPrefix.get(candidatePrefix)!;
	const sharedSlugs = [...baselineFiles.keys()].filter((slug) => candidateFiles.has(slug));

	if (sharedSlugs.length === 0) {
		console.error(`"${baselinePrefix}" and "${candidatePrefix}" have no suites in common in bench/results/.`);
		process.exit(1);
	}

	console.log(`Baseline:  ${baselinePrefix}`);
	console.log(`Candidate: ${candidatePrefix}`);
	const skipped = [...baselineFiles.keys()].filter((slug) => !candidateFiles.has(slug));
	if (skipped.length > 0) console.log(`(skipping suites only present for the baseline: ${skipped.join(", ")})`);
	console.log();

	const rows: { name: string; unit: string; baseline: string; candidate: string; change: string; flag: string }[] = [];
	let regressions = 0;

	for (const slug of sharedSlugs) {
		const baseline = await loadRun(baselineFiles.get(slug)!);
		const candidate = await loadRun(candidateFiles.get(slug)!);
		const baselineByKey = new Map(baseline.results.map((r) => [key(r), r]));
		const candidateByKey = new Map(candidate.results.map((r) => [key(r), r]));
		const allKeys = new Set([...baselineByKey.keys(), ...candidateByKey.keys()]);

		for (const k of [...allKeys].sort()) {
			const b = baselineByKey.get(k);
			const c = candidateByKey.get(k);
			if (!b || !c) {
				rows.push({ name: k, unit: "", baseline: b ? fmt(b.stats.mean) : "-", candidate: c ? fmt(c.stats.mean) : "-", change: "", flag: "only in one run" });
				continue;
			}
			const pctChange = ((c.stats.mean - b.stats.mean) / b.stats.mean) * 100;
			const better = higherIsBetter(b.unit);
			const isRegression = better ? pctChange < -REGRESSION_THRESHOLD_PERCENT : pctChange > REGRESSION_THRESHOLD_PERCENT;
			if (isRegression) regressions++;
			rows.push({
				name: k,
				unit: b.unit,
				baseline: fmt(b.stats.mean),
				candidate: fmt(c.stats.mean),
				change: `${pctChange >= 0 ? "+" : ""}${pctChange.toFixed(1)}%`,
				flag: isRegression ? "REGRESSION" : "",
			});
		}
	}

	console.table(rows);

	if (regressions > 0) {
		console.log(`\n${regressions} benchmark(s) regressed by more than ${REGRESSION_THRESHOLD_PERCENT}% on the candidate run.`);
		process.exitCode = 1;
	} else {
		console.log(`\nNo regressions beyond ${REGRESSION_THRESHOLD_PERCENT}%.`);
	}
}

await main();
