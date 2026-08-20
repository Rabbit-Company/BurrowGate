/**
 * Raw TCP relay throughput via Bun.listen/Bun.connect, the primitives
 * src/services/stream-proxy-service.ts uses to pass non-HTTP TCP traffic
 * straight through (databases, SSH, arbitrary TCP streams). This is the
 * closest thing to a pure "network bandwidth" test in the suite: one socket
 * writes as fast as backpressure allows, the other drains and counts bytes.
 */
import { measureThroughput, printResults, saveSuiteRun, type BenchResult } from "./lib/harness.ts";

const SUITE = "tcp-stream";

async function sendAndCount(totalBytes: number, chunkSize: number): Promise<number> {
	const chunk = new Uint8Array(chunkSize).fill(67);
	let received = 0;
	let resolveDone: (() => void) | null = null;
	const done = new Promise<void>((resolve) => {
		resolveDone = resolve;
	});

	const listener = Bun.listen({
		hostname: "127.0.0.1",
		port: 0,
		socket: {
			data(_socket, data) {
				received += data.byteLength;
				if (received >= totalBytes) resolveDone?.();
			},
			open() {},
			close() {},
			error() {},
		},
	});

	let resolveDrain: (() => void) | null = null;
	const socket = await Bun.connect({
		hostname: "127.0.0.1",
		port: listener.port,
		socket: {
			data() {},
			open() {},
			close() {},
			error() {},
			drain() {
				resolveDrain?.();
				resolveDrain = null;
			},
		},
	});

	let sent = 0;
	while (sent < totalBytes) {
		const remaining = totalBytes - sent;
		const piece = remaining >= chunk.length ? chunk : chunk.subarray(0, remaining);
		const wrote = socket.write(piece);
		if (wrote > 0) sent += wrote;
		if (wrote < piece.length) {
			await new Promise<void>((resolve) => {
				resolveDrain = resolve;
			});
		}
	}

	await done;
	socket.end();
	listener.stop(true);
	return received;
}

export async function run(): Promise<BenchResult[]> {
	const results: BenchResult[] = [];

	for (const chunkKb of [4, 64]) {
		for (const totalMb of [10, 100]) {
			results.push(
				await measureThroughput(SUITE, `relay ${totalMb}MB, ${chunkKb}KB writes`, () => sendAndCount(totalMb * 1024 * 1024, chunkKb * 1024), {
					meta: { totalMb, chunkKb },
				}),
			);
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
		console.log(await saveSuiteRun(results, `${import.meta.dir}/results`, "03-tcp-stream"));
	}
}
