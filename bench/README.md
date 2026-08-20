# bench/

Runtime benchmarks for the Bun APIs BurrowGate depends on most - `Bun.serve`,
`fetch()` proxying, raw TCP/UDP sockets (`Bun.listen`/`Bun.connect`/`Bun.udpSocket`),
WebSockets, TLS handshakes, `Bun.password` (argon2id), `Bun.file`/`Bun.write`,
the built-in `SQL` (sqlite) client, and `node:zlib` compression. Each one
mirrors how the corresponding `src/services/*.ts` file actually uses that API,
so a slowdown here is a real signal, not a synthetic microbenchmark.

## Running

```
bun bench/run-all.ts                       # every suite, 1 run each
bun bench/run-all.ts http tcp              # only suites matching a tag/filename
bun bench/run-all.ts --repeat 10           # every suite, 10 repeats, pooled into one result
bun bench/run-all.ts --duration 2000       # every benchmark row gets 2s instead of 1s
bun bench/run-all.ts --repeat 10 http      # flags combine with filters and each other
bun bench/01-http-serve.bench.ts           # a single suite directly, 1 run, no flags
```

Each suite prints its own table and, on completion, writes one JSON file per
suite to `bench/results/`, named:

```
<bunVersion>-<platform>-<arch>-<suiteSlug>.json
```

e.g. `1.3.14-linux-x64-01-http-serve.json`. Re-running a suite on the same
Bun build overwrites its file rather than piling up timestamped copies.

### Every benchmark row runs on a shared time budget

Each row in a suite's table (`measureLatency`, `measureThroughput`,
`measureRate`, `measureValue` in `bench/lib/harness.ts`) collects samples for
a fixed wall-clock budget - 1000ms by default - rather than a fixed iteration
count, always collecting at least 3 samples even if a single call overruns
the budget. That's what keeps suites in the same ballpark of total time
despite very different per-op costs (an argon2id hash vs. a UDP send vs. a
64KB file write): a suite's total time scales with its row count × the
budget, not with hand-tuned iteration counts that drift out of sync as
benchmarks are added. Override the budget for a whole run with `--duration`;
override it for one specific row from inside a `*.bench.ts` file with
`{ durationMs: N }` in that row's options (rare - only worth it if a
benchmark has a specific reason to need more/fewer samples than the rest of
its suite).

### `--repeat N` - trade time for accuracy

By default `run-all.ts` runs each suite once. `--repeat N` instead runs each
suite as **N separate fresh `bun` subprocesses** and pools every repeat's raw
samples before recomputing stats - not an average of N averages, but Stats
over the full combined sample set. A fresh process per repeat is deliberate:
it avoids one run's JIT warm-up, GC pressure, or memory fragmentation
leaking into the next, which an in-process loop wouldn't catch. This is
slower (N× the wall time, plus subprocess startup per repeat) but is the
right choice when you care about a stable number more than a fast one -
e.g. deciding whether a canary really regressed something, versus one noisy
run. `--repeat` and `--duration` only apply through `run-all.ts`; a suite
invoked directly (`bun bench/01-http-serve.bench.ts`) always does one run at
the 1000ms-per-row default (override with `BENCH_DURATION_MS=2000 bun
bench/01-http-serve.bench.ts` if needed).

## Comparing two Bun versions

1. Run the suite on your current Bun: `bun bench/run-all.ts`
2. Switch Bun versions (e.g. `bun upgrade --canary`, or `bun upgrade` back to
   stable afterward) and run it again: `bun bench/run-all.ts`
3. Compare, either:
   - **Terminal**: `bun bench/compare.ts <baselineVersion> <candidateVersion>`
     (e.g. `bun bench/compare.ts 1.3.14 1.4.0`). Flags anything that regressed
     more than 10% and exits non-zero if it finds one.
   - **Browser**: open `bench/report.html` directly (double-click it, or
     `file://.../bench/report.html`), select every file in `bench/results/`
     at once via the file picker, then pick a baseline/candidate build from
     the two dropdowns. It groups results by suite and unit and charts them
     with Chart.js. No server or build step needed - everything runs
     client-side off the files you select.

Both tools match results by `suite :: benchmark name`, so partial runs (e.g.
`bun bench/run-all.ts tcp udp`) compare fine as long as both versions ran the
same suites.
