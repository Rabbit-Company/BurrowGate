/**
 * node:zlib gzip/brotli, used by src/services/body-capture-service.ts to
 * decompress captured response bodies for storage/replay (the dashboard's
 * "Resend" action) before they're handed back over the wire compressed.
 */
import { brotliCompressSync, brotliDecompressSync, gzipSync, gunzipSync } from "node:zlib";
import { measureThroughput, printResults, saveSuiteRun, type BenchResult } from "./lib/harness.ts";

const SUITE = "compression";

function sampleBody(bytes: number): Uint8Array {
	// Semi-compressible JSON-ish payload, closer to real response bodies than
	// either pure-random (incompressible) or all-zero (unrealistically fast) data.
	const unit = JSON.stringify({ id: crypto.randomUUID(), status: "ok", path: "/api/v1/resource", nested: { a: 1, b: 2, c: [1, 2, 3] } });
	const buf = Buffer.alloc(bytes);
	let offset = 0;
	while (offset < bytes) {
		const chunk = Buffer.from(unit);
		const n = Math.min(chunk.length, bytes - offset);
		chunk.copy(buf, offset, 0, n);
		offset += n;
	}
	return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

export async function run(): Promise<BenchResult[]> {
	const results: BenchResult[] = [];

	for (const sizeKb of [64, 512]) {
		const body = sampleBody(sizeKb * 1024);
		const gzipped = gzipSync(body);
		const brotlied = brotliCompressSync(body);

		results.push(
			await measureThroughput(SUITE, `gzip compress ${sizeKb}KB`, () => {
				gzipSync(body);
				return body.byteLength;
			}),
		);
		results.push(
			await measureThroughput(SUITE, `gzip decompress ${sizeKb}KB`, () => {
				gunzipSync(gzipped);
				return body.byteLength;
			}),
		);
		results.push(
			await measureThroughput(SUITE, `brotli compress ${sizeKb}KB`, () => {
				brotliCompressSync(body);
				return body.byteLength;
			}),
		);
		results.push(
			await measureThroughput(SUITE, `brotli decompress ${sizeKb}KB`, () => {
				brotliDecompressSync(brotlied);
				return body.byteLength;
			}),
		);
	}

	return results;
}

if (import.meta.main) {
	const results = await run();
	if (process.env.BENCH_JSON_STDOUT) {
		console.log(JSON.stringify(results));
	} else {
		printResults(results);
		console.log(await saveSuiteRun(results, `${import.meta.dir}/results`, "10-compression"));
	}
}
