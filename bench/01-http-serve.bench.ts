/**
 * Bun.serve request handling, the base of every HTTP path in BurrowGate
 * (src/services/tls-listener-service.ts hands every request to Bun.serve's
 * `fetch` callback). Measures request/sec at increasing concurrency for a
 * small JSON response (typical admin API reply) and a larger response body
 * (typical static-cache-service hit).
 */
import { measureRate, printResults, saveSuiteRun, type BenchResult } from "./lib/harness.ts";

const SUITE = "http-serve";
const SMALL_BODY = JSON.stringify({ ok: true, site: "example.com", decision: "allow" });
const LARGE_BODY = new Uint8Array(256 * 1024).fill(65);

function startServer() {
	return Bun.serve({
		hostname: "127.0.0.1",
		port: 0,
		fetch(request) {
			const url = new URL(request.url);
			if (url.pathname === "/large") return new Response(LARGE_BODY);
			return new Response(SMALL_BODY, { headers: { "content-type": "application/json" } });
		},
	});
}

async function fireConcurrent(url: string, concurrency: number): Promise<number> {
	await Promise.all(
		Array.from({ length: concurrency }, async () => {
			const res = await fetch(url);
			await res.arrayBuffer();
		}),
	);
	return concurrency;
}

export async function run(): Promise<BenchResult[]> {
	const server = startServer();
	const base = `http://127.0.0.1:${server.port}`;
	const results: BenchResult[] = [];

	try {
		for (const concurrency of [1, 8, 32]) {
			results.push(
				await measureRate(SUITE, `small JSON response, concurrency ${concurrency}`, "req/s", () => fireConcurrent(`${base}/`, concurrency), {
					meta: { concurrency, bodyBytes: SMALL_BODY.length },
				}),
			);
		}
		for (const concurrency of [1, 8, 32]) {
			results.push(
				await measureRate(SUITE, `256KB response, concurrency ${concurrency}`, "req/s", () => fireConcurrent(`${base}/large`, concurrency), {
					meta: { concurrency, bodyBytes: LARGE_BODY.length },
				}),
			);
		}
	} finally {
		server.stop(true);
	}

	return results;
}

if (import.meta.main) {
	const results = await run();
	if (process.env.BENCH_JSON_STDOUT) {
		console.log(JSON.stringify(results));
	} else {
		printResults(results);
		console.log(await saveSuiteRun(results, `${import.meta.dir}/results`, "01-http-serve"));
	}
}
