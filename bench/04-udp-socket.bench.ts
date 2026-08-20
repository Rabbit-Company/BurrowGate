/**
 * Bun.udpSocket throughput, used by src/services/stream-proxy-service.ts for
 * UDP passthrough and by src/services/connectivity-monitor-service.ts for
 * connectivity probing. Also reports delivery ratio under sustained load -
 * a real signal, since a scheduler regression here would show up as
 * dropped datagrams rather than just lower MB/s.
 */
import { measureThroughput, measureValue, printResults, saveSuiteRun, type BenchResult } from "./lib/harness.ts";

const SUITE = "udp-socket";

async function sendAndCount(datagramCount: number, payloadSize: number): Promise<{ received: number; bytes: number }> {
	const payload = new Uint8Array(payloadSize).fill(68);
	let received = 0;
	let resolveDone: (() => void) | null = null;
	const done = new Promise<void>((resolve) => {
		resolveDone = resolve;
	});

	const server = await Bun.udpSocket({
		hostname: "127.0.0.1",
		port: 0,
		socket: {
			data(_socket, buf) {
				received++;
				if (received >= datagramCount) resolveDone?.();
			},
		},
	});

	let resolveDrain: (() => void) | null = null;
	const client = await Bun.udpSocket({
		hostname: "127.0.0.1",
		port: 0,
		connect: { hostname: "127.0.0.1", port: server.port },
		socket: {
			data() {},
			drain() {
				resolveDrain?.();
				resolveDrain = null;
			},
		},
	});

	// send() returns false when the OS send buffer is full (the same signal
	// stream-proxy-service checks before relaying a UDP datagram); back off
	// until drain() fires instead of spraying datagrams the kernel would just
	// discard. A tight synchronous send loop would also never yield back to
	// Bun's single-threaded event loop, so the receiver's `data` callback
	// (and the kernel's own receive-buffer draining) would starve until the
	// whole burst finished - periodically yielding avoids that self-inflicted
	// loss and lets delivery ratio measure the runtime, not the test harness.
	let sent = 0;
	while (sent < datagramCount) {
		if (client.send(payload)) sent++;
		else {
			await new Promise<void>((resolve) => {
				resolveDrain = resolve;
			});
		}
		if (sent % 64 === 0) await new Promise<void>((resolve) => setTimeout(resolve, 0));
	}

	const timeout = new Promise<void>((resolve) => setTimeout(resolve, 1000));
	await Promise.race([done, timeout]);

	client.close();
	server.close();
	return { received, bytes: received * payloadSize };
}

function measureDeliveryRatio(name: string, datagramCount: number, payloadSize: number): Promise<BenchResult> {
	return measureValue(
		SUITE,
		name,
		"%",
		async () => {
			const { received } = await sendAndCount(datagramCount, payloadSize);
			return (received / datagramCount) * 100;
		},
		{ meta: { datagramCount, payloadSize } },
	);
}

export async function run(): Promise<BenchResult[]> {
	const results: BenchResult[] = [];

	for (const payloadSize of [512, 1200]) {
		for (const count of [5_000, 20_000]) {
			results.push(
				await measureThroughput(SUITE, `send ${count} datagrams of ${payloadSize}B`, async () => (await sendAndCount(count, payloadSize)).bytes, {
					warmupRuns: 2,
					meta: { datagramCount: count, payloadSize },
				}),
			);
			results.push(await measureDeliveryRatio(`delivery ratio, ${count} datagrams of ${payloadSize}B`, count, payloadSize));
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
		console.log(await saveSuiteRun(results, `${import.meta.dir}/results`, "04-udp-socket"));
	}
}
