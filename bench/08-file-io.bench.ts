/**
 * Bun.file / Bun.write throughput, used by src/services/static-cache-service.ts
 * for cached response bodies and by certificate/bootstrap-tls storage for
 * reading PEM files off disk on every TLS reload.
 */
import { rm } from "node:fs/promises";
import { measureThroughput, printResults, saveSuiteRun, type BenchResult } from "./lib/harness.ts";

const SUITE = "file-io";
const DIR = `${import.meta.dir}/tmp/file-io`;

async function writeThenRead(path: string, bytes: Uint8Array): Promise<number> {
	await Bun.write(path, bytes);
	const read = await Bun.file(path).arrayBuffer();
	return bytes.byteLength + read.byteLength;
}

export async function run(): Promise<BenchResult[]> {
	await Bun.$`mkdir -p ${DIR}`.quiet();
	const results: BenchResult[] = [];

	for (const sizeKb of [4, 64, 1024]) {
		const bytes = new Uint8Array(sizeKb * 1024).fill(70);
		const path = `${DIR}/file-io-${sizeKb}kb.bin`;
		results.push(
			await measureThroughput(SUITE, `write+read ${sizeKb}KB`, () => writeThenRead(path, bytes), {
				meta: { sizeKb },
			}),
		);
	}

	await rm(DIR, { recursive: true, force: true });
	return results;
}

if (import.meta.main) {
	const results = await run();
	if (process.env.BENCH_JSON_STDOUT) {
		console.log(JSON.stringify(results));
	} else {
		printResults(results);
		console.log(await saveSuiteRun(results, `${import.meta.dir}/results`, "08-file-io"));
	}
}
