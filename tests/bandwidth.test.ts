import { describe, expect, test } from "bun:test";
import { BandwidthAccumulator, meteredBody, type BandwidthDelta } from "../src/services/bandwidth-service.ts";
import type { BandwidthMinuteRecord } from "../src/types.ts";

describe("bandwidth accounting", () => {
	test("aggregates separate client and upstream counters into minute buckets", async () => {
		const persisted: BandwidthMinuteRecord[][] = [];
		const accumulator = new BandwidthAccumulator(async (records) => {
			persisted.push(records);
		}, 100);
		const at = Date.UTC(2026, 7, 4, 12, 34, 56);
		const context = { siteId: "site-a", ip: "203.0.113.8", countryCode: "si", protocol: "http" as const };

		accumulator.record(context, { clientReceivedBytes: 11, upstreamSentBytes: 10 }, at);
		accumulator.record(context, { upstreamReceivedBytes: 25, clientSentBytes: 23 }, at + 2_000);
		await accumulator.flush();

		expect(persisted).toHaveLength(1);
		expect(persisted[0]).toEqual([
			{
				site_id: "site-a",
				bucket_start: Date.UTC(2026, 7, 4, 12, 34),
				ip: "203.0.113.8",
				country_code: "SI",
				protocol: "http",
				client_received_bytes: 11,
				client_sent_bytes: 23,
				upstream_sent_bytes: 10,
				upstream_received_bytes: 25,
			},
		]);
	});

	test("preserves country totals by folding excess IP keys into overflow", async () => {
		let persisted: BandwidthMinuteRecord[] = [];
		const accumulator = new BandwidthAccumulator(async (records) => {
			persisted = records;
		}, 1);
		const now = Date.UTC(2026, 7, 4, 12, 0);

		accumulator.record({ siteId: "site-a", ip: "198.51.100.1", countryCode: "US", protocol: "http" }, { clientSentBytes: 5 }, now);
		accumulator.record({ siteId: "site-a", ip: "198.51.100.2", countryCode: "US", protocol: "http" }, { clientSentBytes: 7 }, now);
		accumulator.record({ siteId: "site-a", ip: "198.51.100.3", countryCode: "US", protocol: "http" }, { clientSentBytes: 9 }, now);
		await accumulator.flush();

		expect(persisted).toHaveLength(2);
		expect(persisted.find((record) => record.ip === "__other__")?.client_sent_bytes).toBe(16);
		expect(persisted.reduce((sum, record) => sum + record.client_sent_bytes, 0)).toBe(21);
	});

	test("counts each stream chunk without changing its bytes", async () => {
		const deltas: BandwidthDelta[] = [];
		const source = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(new Uint8Array([1, 2, 3]));
				controller.enqueue(new Uint8Array([4, 5]));
				controller.close();
			},
		});
		const metered = meteredBody(
			source,
			{ siteId: "site-a", ip: "203.0.113.8", countryCode: "SI", protocol: "http" },
			(bytes) => ({ upstreamReceivedBytes: bytes, clientSentBytes: bytes }),
			(_context, delta) => deltas.push(delta),
		);

		expect(new Uint8Array(await new Response(metered).arrayBuffer())).toEqual(new Uint8Array([1, 2, 3, 4, 5]));
		expect(deltas).toEqual([
			{ upstreamReceivedBytes: 3, clientSentBytes: 3 },
			{ upstreamReceivedBytes: 2, clientSentBytes: 2 },
		]);
	});
});
