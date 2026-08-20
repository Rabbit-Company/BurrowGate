/**
 * HTTPS request rate over Bun.serve with `tls` set, the path every browser
 * request through src/services/tls-listener-service.ts takes once a
 * certificate is loaded (see reloadHttps()). Handshake cost dominates for
 * short-lived connections, so this measures fresh (non-keepalive-reused)
 * connections rather than a single warm connection's request rate.
 */
import { ensureBenchCertificate } from "./lib/cert.ts";
import { measureRate, printResults, saveSuiteRun, type BenchResult } from "./lib/harness.ts";

const SUITE = "tls-handshake";

async function run1(url: string): Promise<number> {
	// "Connection: close" forces a fresh TCP+TLS handshake per request instead
	// of reusing a pooled keep-alive connection, matching the docstring above.
	const res = await fetch(url, {
		tls: { rejectUnauthorized: false },
		headers: { connection: "close" },
	} as RequestInit);
	await res.arrayBuffer();
	return 1;
}

export async function run(): Promise<BenchResult[]> {
	const { cert, key } = await ensureBenchCertificate(`${import.meta.dir}/tmp/certs`);
	const server = Bun.serve({
		hostname: "127.0.0.1",
		port: 0,
		tls: { cert, key },
		fetch() {
			return new Response("ok");
		},
	});
	const url = `https://127.0.0.1:${server.port}/`;
	const results: BenchResult[] = [];

	try {
		results.push(
			await measureRate(SUITE, "fresh HTTPS connection, request/sec", "req/s", () => run1(url), {
				warmupRuns: 5,
			}),
		);
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
		console.log(await saveSuiteRun(results, `${import.meta.dir}/results`, "06-tls-handshake"));
	}
}
