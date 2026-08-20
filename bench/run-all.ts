/**
 * Runs every bench/*.bench.ts suite, each as its own `bun` subprocess
 * (sequentially - suites don't contend for CPU/network, and a fresh process
 * per suite/repeat avoids one suite's JIT warm-up or GC pressure leaking
 * into the next). Prints each suite's aggregated table as it finishes and
 * saves one JSON file per suite to bench/results/, named
 * `<bunVersion>-<platform>-<arch>-<suiteSlug>.json`. Compare two Bun
 * versions with bench/compare.ts or bench/report.html once you've run this
 * once per version.
 *
 * Usage:
 *   bun bench/run-all.ts                        # all suites, 1 run each
 *   bun bench/run-all.ts http tcp               # only suites whose tag/filename matches
 *   bun bench/run-all.ts --repeat 10            # every suite, 10 fresh-process repeats,
 *                                               # pooled into one aggregated result
 *   bun bench/run-all.ts --duration 2000        # every benchmark row gets a 2s time
 *                                               # budget instead of the 1s default
 *   bun bench/run-all.ts --repeat 10 sqlite     # flags combine with filters and each other
 */
import { currentMetadata, printResults, saveSuiteRun, type BenchResult } from "./lib/harness.ts";
import { parseBenchFlags, runSuiteRepeated } from "./lib/repeat.ts";
import { SUITES } from "./lib/suites.ts";

const { repeat, durationMs, rest: filters } = parseBenchFlags(process.argv.slice(2));
const selected = filters.length === 0 ? SUITES : SUITES.filter((s) => filters.some((f) => s.tag.includes(f) || s.file.includes(f)));

if (selected.length === 0) {
	console.error(`No suite matched filters: ${filters.join(", ")}`);
	console.error(`Available: ${SUITES.map((s) => s.tag).join(", ")}`);
	process.exit(1);
}

// Every benchmark row already runs for a shared time budget (BENCH_DURATION_MS
// in harness.ts, default 1000ms) instead of a fixed iteration count, which is
// what keeps suites roughly comparable in wall time regardless of how cheap or
// expensive their underlying op is. --duration overrides that budget for every
// subprocess spawned below.
if (durationMs !== undefined) process.env.BENCH_DURATION_MS = String(durationMs);

console.log(
	`BurrowGate bench suite - bun ${Bun.version} (${Bun.revision.slice(0, 12)}) on ${process.platform}/${process.arch}, repeat=${repeat}, duration=${durationMs ?? 1000}ms/row\n`,
);

const allResults: BenchResult[] = [];
const paths: string[] = [];
for (const suite of selected) {
	console.log(`\n=== ${suite.file} ===`);
	const start = Bun.nanoseconds();
	const results = await runSuiteRepeated(import.meta.dir, suite.file, repeat, (repeatIndex) => {
		if (repeat > 1) console.log(`  repeat ${repeatIndex + 1}/${repeat} done`);
	});
	printResults(results);
	allResults.push(...results);
	paths.push(await saveSuiteRun(results, `${import.meta.dir}/results`, suite.slug));
	console.log(`(${((Bun.nanoseconds() - start) / 1_000_000_000).toFixed(1)}s)`);
}

const metadata = currentMetadata();
console.log(`\nSaved ${allResults.length} results across ${paths.length} file(s) tagged bun ${metadata.bunVersion} (${metadata.platform}/${metadata.arch}):`);
for (const path of paths) console.log(`  ${path}`);
console.log(`\nRun this on another Bun version, then compare with: bun bench/compare.ts <versionA> <versionB>`);
console.log(`Or open bench/report.html in a browser and load bench/results/.`);
