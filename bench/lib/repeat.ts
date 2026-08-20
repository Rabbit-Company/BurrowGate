/**
 * Runs a bench/*.bench.ts suite as N separate `bun` subprocesses (not N
 * in-process calls to run()) and pools every repeat's raw samples before
 * recomputing Stats, so the aggregate isn't just an average of averages.
 *
 * A fresh process per repeat matters here: running everything in one long
 * bun process would let JIT warm-up, GC pressure, and memory fragmentation
 * from earlier suites/repeats bleed into later ones - exactly the kind of
 * noise --repeat exists to average out. Each subprocess is asked (via
 * BENCH_JSON_STDOUT) to print its BenchResult[] as one JSON line instead of
 * the usual pretty table + saved file, which run-all.ts still does once, on
 * the final pooled result.
 */
import { summarize, type BenchResult } from "./harness.ts";

export interface ParsedArgs {
	repeat: number;
	/** ms per benchmark row's time budget (see BENCH_DURATION_MS in harness.ts); undefined = harness default. */
	durationMs: number | undefined;
	rest: string[];
}

function readFlagValue(argv: string[], i: { index: number }, name: string): string {
	const arg = argv[i.index]!;
	if (arg === name) {
		i.index++;
		const value = argv[i.index];
		if (value === undefined) throw new Error(`${name} expects a value`);
		return value;
	}
	return arg.slice(`${name}=`.length);
}

/** Extracts `--repeat N` and `--duration N` (both accept `=N` too) from argv; everything else passes through unchanged. */
export function parseBenchFlags(argv: string[]): ParsedArgs {
	const rest: string[] = [];
	let repeat = 1;
	let durationMs: number | undefined;
	const i = { index: 0 };

	for (i.index = 0; i.index < argv.length; i.index++) {
		const arg = argv[i.index]!;
		if (arg === "--repeat" || arg.startsWith("--repeat=")) {
			const raw = readFlagValue(argv, i, "--repeat");
			const value = Number(raw);
			if (!Number.isFinite(value) || !Number.isInteger(value) || value < 1) {
				throw new Error(`--repeat expects a positive integer, got "${raw}"`);
			}
			repeat = value;
		} else if (arg === "--duration" || arg.startsWith("--duration=")) {
			const raw = readFlagValue(argv, i, "--duration");
			const value = Number(raw);
			if (!Number.isFinite(value) || value <= 0) {
				throw new Error(`--duration expects a positive number of milliseconds, got "${raw}"`);
			}
			durationMs = value;
		} else {
			rest.push(arg);
		}
	}

	return { repeat, durationMs, rest };
}

/**
 * Spawns `bun <file>` `repeat` times in `cwd`, pools all repeats' samples per
 * (suite, name), and returns one aggregated BenchResult per benchmark.
 * `onRepeatDone` fires after each subprocess exits, for progress logging.
 */
export async function runSuiteRepeated(
	cwd: string,
	file: string,
	repeat: number,
	onRepeatDone?: (repeatIndex: number, results: BenchResult[]) => void,
): Promise<BenchResult[]> {
	const pooled = new Map<string, { suite: string; name: string; unit: BenchResult["unit"]; samples: number[]; meta?: Record<string, unknown> }>();

	for (let i = 0; i < repeat; i++) {
		const proc = Bun.spawn(["bun", file], {
			cwd,
			env: { ...process.env, BENCH_JSON_STDOUT: "1" },
			stdout: "pipe",
			stderr: "inherit",
		});
		const stdout = await new Response(proc.stdout).text();
		const exitCode = await proc.exited;
		if (exitCode !== 0) throw new Error(`${file} exited with code ${exitCode} on repeat ${i + 1}/${repeat}`);

		let results: BenchResult[];
		try {
			results = JSON.parse(stdout.trim()) as BenchResult[];
		} catch (error) {
			throw new Error(`${file} repeat ${i + 1}/${repeat}: could not parse JSON stdout (${(error as Error).message})`);
		}

		for (const r of results) {
			const k = `${r.suite} :: ${r.name}`;
			if (!pooled.has(k)) pooled.set(k, { suite: r.suite, name: r.name, unit: r.unit, samples: [], meta: r.meta });
			pooled.get(k)!.samples.push(...r.samples);
		}
		onRepeatDone?.(i, results);
	}

	return [...pooled.values()].map((entry) => ({
		suite: entry.suite,
		name: entry.name,
		unit: entry.unit,
		stats: summarize(entry.samples),
		samples: entry.samples,
		meta: { ...entry.meta, repeats: repeat },
	}));
}
