/**
 * Shared harness for the bench/ suite: timing, throughput measurement, result
 * formatting, and JSON persistence so two runs (e.g. current bun vs. canary)
 * can be diffed by bench/compare.ts.
 *
 * Every measure* function below runs for a shared time budget rather than a
 * fixed iteration count, so a benchmark row's wall-clock cost is roughly the
 * same (~DEFAULT_DURATION_MS) whether the underlying op takes 10μs or 50ms -
 * a suite's total time then scales with its row count, not with per-suite
 * iteration counts someone hand-tuned. Override per-call with `durationMs`;
 * override the shared default for a whole run via BENCH_DURATION_MS (set by
 * `bun bench/run-all.ts --duration <ms>`).
 */

const DEFAULT_DURATION_MS = (() => {
	const fromEnv = Number(process.env.BENCH_DURATION_MS);
	return Number.isFinite(fromEnv) && fromEnv > 0 ? fromEnv : 1000;
})();

/** Safety cap on samples collected within the duration budget, for ops fast enough to otherwise produce huge arrays. */
const DEFAULT_MAX_ITERATIONS = 20_000;

export interface Stats {
	n: number;
	min: number;
	max: number;
	mean: number;
	median: number;
	p95: number;
	p99: number;
	stddev: number;
}

export interface BenchResult {
	suite: string;
	name: string;
	unit: "ops/sec" | "ms" | "MB/s" | "req/s" | "%";
	stats: Stats;
	/** Raw per-call measurements behind `stats`. Kept so bench/lib/repeat.ts can
	 * concatenate samples across repeated process runs and recompute Stats over
	 * the full pool, rather than averaging already-aggregated stats. */
	samples: number[];
	meta?: Record<string, unknown>;
}

export interface RunMetadata {
	bunVersion: string;
	bunRevision: string;
	platform: string;
	arch: string;
	cpus: number;
	timestamp: string;
}

export interface RunFile {
	metadata: RunMetadata;
	results: BenchResult[];
}

function percentile(sorted: number[], p: number): number {
	if (sorted.length === 0) return 0;
	const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
	return sorted[idx]!;
}

export function summarize(samples: number[]): Stats {
	const sorted = [...samples].sort((a, b) => a - b);
	const n = sorted.length;
	const mean = sorted.reduce((sum, v) => sum + v, 0) / n;
	const variance = sorted.reduce((sum, v) => sum + (v - mean) ** 2, 0) / n;
	return {
		n,
		min: sorted[0] ?? 0,
		max: sorted[n - 1] ?? 0,
		mean,
		median: percentile(sorted, 50),
		p95: percentile(sorted, 95),
		p99: percentile(sorted, 99),
		stddev: Math.sqrt(variance),
	};
}

export interface DurationBudgetOptions {
	/** Wall-clock budget for sample collection. Defaults to BENCH_DURATION_MS, or 1000ms. */
	durationMs?: number;
	/** Always collect at least this many samples, even if a single call overruns the budget. */
	minIterations?: number;
	/** Hard cap, for ops fast enough to otherwise collect an unbounded number of samples. */
	maxIterations?: number;
}

/**
 * Runs `fn` for `durationMs` (at least `minIterations` times regardless),
 * recording whatever numeric value `fn` returns per call. The shared core
 * behind measureLatency (fn times itself and returns void) and measureValue
 * (fn returns its own sample value, e.g. an MB/s or req/s reading).
 */
async function collectTimeBoxedSamples(fn: () => Promise<number> | number, opts: DurationBudgetOptions & { warmupRuns?: number }): Promise<number[]> {
	const durationMs = opts.durationMs ?? DEFAULT_DURATION_MS;
	const minIterations = opts.minIterations ?? 3;
	const maxIterations = opts.maxIterations ?? DEFAULT_MAX_ITERATIONS;

	for (let i = 0; i < (opts.warmupRuns ?? 0); i++) await fn();

	const samples: number[] = [];
	const end = Bun.nanoseconds() + durationMs * 1_000_000;
	while (samples.length < maxIterations && (samples.length < minIterations || Bun.nanoseconds() < end)) {
		samples.push(await fn());
	}
	return samples;
}

/**
 * Runs `fn` for a time budget, recording the wall time of each individual
 * call in milliseconds. Used for latency-shaped benchmarks (password
 * hashing, single queries, single requests).
 */
export async function measureLatency(
	suite: string,
	name: string,
	fn: () => Promise<void> | void,
	opts: { warmupMs?: number; meta?: Record<string, unknown> } & DurationBudgetOptions = {},
): Promise<BenchResult> {
	const warmupMs = opts.warmupMs ?? 200;
	const warmupEnd = Bun.nanoseconds() + warmupMs * 1_000_000;
	while (Bun.nanoseconds() < warmupEnd) await fn();

	const samples = await collectTimeBoxedSamples(async () => {
		const start = Bun.nanoseconds();
		await fn();
		return (Bun.nanoseconds() - start) / 1_000_000;
	}, opts);

	return { suite, name, unit: "ms", stats: summarize(samples), samples, meta: opts.meta };
}

/**
 * Runs `fn` for a time budget and reports operations/sec instead of raw
 * latency samples (useful when call overhead itself is the signal).
 */
export async function measureOpsPerSec(
	suite: string,
	name: string,
	fn: () => Promise<void> | void,
	opts: { batchesOf?: number; meta?: Record<string, unknown> } & DurationBudgetOptions = {},
): Promise<BenchResult> {
	const batchesOf = opts.batchesOf ?? 1;
	const samples = await collectTimeBoxedSamples(async () => {
		const start = Bun.nanoseconds();
		for (let i = 0; i < batchesOf; i++) await fn();
		const elapsedSec = (Bun.nanoseconds() - start) / 1_000_000_000;
		return batchesOf / elapsedSec;
	}, opts);

	return { suite, name, unit: "ops/sec", stats: summarize(samples), samples, meta: opts.meta };
}

/**
 * Runs `fn` for a time budget, recording whatever value it returns -
 * generic version of measureThroughput/measureRate for ad-hoc per-call
 * metrics (e.g. a delivered/attempted percentage) that don't fit either.
 */
export async function measureValue(
	suite: string,
	name: string,
	unit: BenchResult["unit"],
	fn: () => Promise<number> | number,
	opts: { warmupRuns?: number; meta?: Record<string, unknown> } & DurationBudgetOptions = {},
): Promise<BenchResult> {
	const samples = await collectTimeBoxedSamples(fn, opts);
	return { suite, name, unit, stats: summarize(samples), samples, meta: opts.meta };
}

/**
 * Runs `transfer` for a time budget; each call must return the number of
 * bytes it moved. Reports MB/s across the samples. Used for
 * bandwidth-shaped benchmarks (TCP/UDP relay, fetch streaming, file I/O,
 * compression).
 */
export function measureThroughput(
	suite: string,
	name: string,
	transfer: () => Promise<number> | number,
	opts: { warmupRuns?: number; meta?: Record<string, unknown> } & DurationBudgetOptions = {},
): Promise<BenchResult> {
	return measureValue(
		suite,
		name,
		"MB/s",
		async () => {
			const start = Bun.nanoseconds();
			const bytes = await transfer();
			const elapsedSec = (Bun.nanoseconds() - start) / 1_000_000_000;
			return bytes / 1_000_000 / elapsedSec;
		},
		{ warmupRuns: opts.warmupRuns ?? 1, ...opts },
	);
}

/**
 * Runs `fn` for a time budget; each call must return the number of discrete
 * items it processed (requests completed, datagrams sent, ...). Reports
 * items/sec across the samples. Shares measureThroughput's shape but
 * without the MB-scaling, for count-based rates like req/s.
 */
export function measureRate(
	suite: string,
	name: string,
	unit: "req/s" | "ops/sec",
	fn: () => Promise<number> | number,
	opts: { warmupRuns?: number; meta?: Record<string, unknown> } & DurationBudgetOptions = {},
): Promise<BenchResult> {
	return measureValue(
		suite,
		name,
		unit,
		async () => {
			const start = Bun.nanoseconds();
			const count = await fn();
			const elapsedSec = (Bun.nanoseconds() - start) / 1_000_000_000;
			return count / elapsedSec;
		},
		{ warmupRuns: opts.warmupRuns ?? 1, ...opts },
	);
}

export function currentMetadata(): RunMetadata {
	return {
		bunVersion: Bun.version,
		bunRevision: Bun.revision,
		platform: process.platform,
		arch: process.arch,
		cpus: navigator.hardwareConcurrency ?? 0,
		timestamp: new Date().toISOString(),
	};
}

function fmt(value: number): string {
	if (!Number.isFinite(value)) return "n/a";
	if (Math.abs(value) >= 1000) return value.toFixed(0);
	if (Math.abs(value) >= 10) return value.toFixed(1);
	return value.toFixed(3);
}

export function printResults(results: BenchResult[]): void {
	const rows = results.map((r) => ({
		suite: r.suite,
		name: r.name,
		unit: r.unit,
		mean: fmt(r.stats.mean),
		median: fmt(r.stats.median),
		p95: fmt(r.stats.p95),
		min: fmt(r.stats.min),
		max: fmt(r.stats.max),
		n: r.stats.n,
	}));
	console.table(rows);
}

/**
 * Writes one result file per suite, named `<bunVersion>-<platform>-<arch>-<suiteSlug>.json`
 * (e.g. `1.3.14-linux-x64-01-http-serve.json`). Re-running the same suite on
 * the same Bun build overwrites its file rather than accumulating timestamped
 * copies, so `bench/results/` always holds at most one result per
 * (version, platform, arch, suite) - exactly what compare.ts and
 * bench/report.html need to pair up two versions by filename.
 */
export async function saveSuiteRun(results: BenchResult[], outDir: string, suiteSlug: string): Promise<string> {
	const metadata = currentMetadata();
	const safeVersion = metadata.bunVersion.replace(/[^a-zA-Z0-9.+-]/g, "_");
	const path = `${outDir}/${safeVersion}-${metadata.platform}-${metadata.arch}-${suiteSlug}.json`;
	const payload: RunFile = { metadata, results };
	await Bun.write(path, JSON.stringify(payload, null, 2));
	return path;
}

export async function loadRun(path: string): Promise<RunFile> {
	return JSON.parse(await Bun.file(path).text()) as RunFile;
}

export function key(r: Pick<BenchResult, "suite" | "name">): string {
	return `${r.suite} :: ${r.name}`;
}
