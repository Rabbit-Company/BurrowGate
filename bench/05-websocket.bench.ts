/**
 * Bun's server WebSocket path (ServerWebSocket + Bun.serve's `websocket`
 * handler), which src/services/websocket-proxy-service.ts relays client
 * frames through. Echoes frames server-side and measures round-trip
 * message throughput (MB/s) for typical proxied frame sizes.
 */
import { measureThroughput, printResults, saveSuiteRun, type BenchResult } from "./lib/harness.ts";

const SUITE = "websocket";

function startServer() {
	return Bun.serve({
		hostname: "127.0.0.1",
		port: 0,
		fetch(request, server) {
			if (server.upgrade(request)) return undefined;
			return new Response("upgrade required", { status: 426 });
		},
		websocket: {
			message(ws, message) {
				ws.send(message);
			},
		},
	});
}

async function roundTrip(url: string, frameSize: number, frameCount: number): Promise<number> {
	const payload = new Uint8Array(frameSize).fill(69);
	const ws = new WebSocket(url);
	ws.binaryType = "arraybuffer";

	await new Promise<void>((resolve, reject) => {
		ws.addEventListener("open", () => resolve(), { once: true });
		ws.addEventListener("error", (event) => reject(event), { once: true });
	});

	let received = 0;
	let bytes = 0;
	const done = new Promise<void>((resolve) => {
		ws.addEventListener("message", (event) => {
			bytes += (event.data as ArrayBuffer).byteLength;
			received++;
			if (received >= frameCount) resolve();
			else ws.send(payload);
		});
	});

	ws.send(payload);
	await done;
	ws.close();
	return bytes;
}

export async function run(): Promise<BenchResult[]> {
	const server = startServer();
	const url = `ws://127.0.0.1:${server.port}/`;
	const results: BenchResult[] = [];

	try {
		for (const frameSize of [256, 16 * 1024]) {
			results.push(
				await measureThroughput(SUITE, `${frameSize}B frames, echo round-trip`, () => roundTrip(url, frameSize, 500), {
					warmupRuns: 2,
					meta: { frameSize, frameCount: 500 },
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
		console.log(await saveSuiteRun(results, `${import.meta.dir}/results`, "05-websocket"));
	}
}
