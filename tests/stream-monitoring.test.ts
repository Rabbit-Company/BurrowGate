import { describe, expect, test } from "bun:test";
import { StreamMonitoringAccumulator } from "../src/services/stream-monitoring-service.ts";
import type { StreamBandwidthMinuteRecord, StreamEventRecord } from "../src/types.ts";

describe("stream monitoring", () => {
	test("aggregates data by stream, port, IP, country, protocol, and minute", async () => {
		let bandwidth: StreamBandwidthMinuteRecord[] = [];
		const accumulator = new StreamMonitoringAccumulator(
			{
				events: async () => undefined,
				bandwidth: async (records) => {
					bandwidth = records;
				},
			},
			100,
		);
		const now = Date.UTC(2026, 7, 5, 10, 12, 34);
		const context = { streamId: "stream-a", incomingPort: 25565, ip: "203.0.113.4", countryCode: "si", protocol: "tcp" as const };
		accumulator.recordTraffic(context, { clientToUpstreamBytes: 12 }, now);
		accumulator.recordTraffic(context, { upstreamToClientBytes: 30 }, now + 5_000);
		await accumulator.flush();

		expect(bandwidth).toEqual([
			{
				stream_id: "stream-a",
				incoming_port: 25565,
				bucket_start: Date.UTC(2026, 7, 5, 10, 12),
				ip: "203.0.113.4",
				country_code: "SI",
				protocol: "tcp",
				client_to_upstream_bytes: 12,
				upstream_to_client_bytes: 30,
			},
		]);
	});

	test("persists connection events alongside bandwidth", async () => {
		const persisted: StreamEventRecord[][] = [];
		const accumulator = new StreamMonitoringAccumulator({
			events: async (events) => {
				persisted.push(events);
			},
			bandwidth: async () => undefined,
		});
		const event: StreamEventRecord = {
			id: "event-a",
			stream_id: "stream-a",
			incoming_port: 53,
			connection_id: "peer-a",
			protocol: "udp",
			event_type: "connected",
			client_ip: "198.51.100.7",
			client_port: 50000,
			country_code: "US",
			reason: "first datagram",
			error: null,
			client_to_upstream_bytes: 0,
			upstream_to_client_bytes: 0,
			created_at: Date.now(),
		};
		accumulator.recordEvent(event);
		await accumulator.flush();
		expect(persisted).toEqual([[event]]);
	});

	test("caps queued lifecycle events while the database is unavailable", async () => {
		const persisted: StreamEventRecord[][] = [];
		const accumulator = new StreamMonitoringAccumulator(
			{
				events: async (events) => {
					persisted.push(events);
				},
				bandwidth: async () => undefined,
			},
			100,
			2,
		);
		const event = (id: string): StreamEventRecord => ({
			id,
			stream_id: "stream-a",
			incoming_port: 53,
			connection_id: id,
			protocol: "udp",
			event_type: "connected",
			client_ip: "198.51.100.7",
			client_port: 50_000,
			country_code: "US",
			reason: "first datagram",
			error: null,
			client_to_upstream_bytes: 0,
			upstream_to_client_bytes: 0,
			created_at: Date.now(),
		});
		accumulator.recordEvent(event("event-a"));
		accumulator.recordEvent(event("event-b"));
		accumulator.recordEvent(event("event-c"));
		await accumulator.flush();

		expect(persisted[0]?.map((item) => item.id)).toEqual(["event-a", "event-b"]);
		expect(accumulator.takeDroppedEventCount()).toBe(1);
	});

	test("includes an in-flight SQL batch in the event memory ceiling", async () => {
		const entered = Promise.withResolvers<void>();
		const release = Promise.withResolvers<void>();
		const persisted: StreamEventRecord[] = [];
		const accumulator = new StreamMonitoringAccumulator(
			{
				events: async (events) => {
					persisted.push(...events);
					entered.resolve();
					await release.promise;
				},
				bandwidth: async () => undefined,
			},
			100,
			1,
		);
		const event = (id: string): StreamEventRecord => ({
			id,
			stream_id: "stream-a",
			incoming_port: 53,
			connection_id: id,
			protocol: "udp",
			event_type: "connected",
			client_ip: "198.51.100.7",
			client_port: 50_000,
			country_code: "US",
			reason: "first datagram",
			error: null,
			client_to_upstream_bytes: 0,
			upstream_to_client_bytes: 0,
			created_at: Date.now(),
		});
		accumulator.recordEvent(event("event-a"));
		const flushing = accumulator.flush();
		await entered.promise;
		accumulator.recordEvent(event("event-b"));
		release.resolve();
		await flushing;

		expect(persisted.map((item) => item.id)).toEqual(["event-a"]);
		expect(accumulator.takeDroppedEventCount()).toBe(1);
	});
});
