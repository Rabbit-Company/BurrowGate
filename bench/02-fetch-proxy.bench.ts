/**
 * fetch()-based reverse proxying: src/services/proxy-service.ts forwards
 * every HTTP request with `await fetch(target, ...)` and streams the
 * response body back to the client. This is the single most-exercised
 * bandwidth path in BurrowGate, so it gets its own MB/s benchmark: a local
 * Bun.serve "origin" streams a body of a given size, and the benchmark does
 * exactly what proxy-service.ts does - fetch it and drain response.body
 * chunk by chunk, counting bytes like meteredBody() does.
 */
import { measureThroughput, printResults, saveSuiteRun, type BenchResult } from "./lib/harness.ts";

const SUITE = "fetch-proxy";
const CHUNK = new Uint8Array(64 * 1024).fill(66);

function startOrigin(totalBytes: number) {
	return Bun.serve({
		hostname: "127.0.0.1",
		port: 0,
		fetch() {
			let sent = 0;
			const stream = new ReadableStream<Uint8Array>({
				pull(controller) {
					if (sent >= totalBytes) {
						controller.close();
						return;
					}
					const remaining = totalBytes - sent;
					const piece = remaining >= CHUNK.length ? CHUNK : CHUNK.subarray(0, remaining);
					controller.enqueue(piece);
					sent += piece.length;
				},
			});
			return new Response(stream);
		},
	});
}

async function fetchAndDrain(url: string): Promise<number> {
	const response = await fetch(url);
	const reader = response.body!.getReader();
	let bytes = 0;
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		bytes += value.byteLength;
	}
	return bytes;
}

export async function run(): Promise<BenchResult[]> {
	const results: BenchResult[] = [];

	for (const sizeMb of [1, 10, 50]) {
		const origin = startOrigin(sizeMb * 1024 * 1024);
		const url = `http://127.0.0.1:${origin.port}/`;
		try {
			results.push(
				await measureThroughput(SUITE, `stream ${sizeMb}MB body through fetch()`, () => fetchAndDrain(url), {
					meta: { bodyMb: sizeMb },
				}),
			);
		} finally {
			origin.stop(true);
		}
	}

	return results;
}

if (import.meta.main) {
	const results = await run();
	if (process.env.BENCH_JSON_STDOUT) {
		console.log(JSON.stringify(results));
	} else {
		printResults(results);
		console.log(await saveSuiteRun(results, `${import.meta.dir}/results`, "02-fetch-proxy"));
	}
}
