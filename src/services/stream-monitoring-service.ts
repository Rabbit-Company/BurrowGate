import { config } from "../config.ts";
import { repository } from "../db/repository.ts";
import { Logger } from "../logger.ts";
import type { StreamBandwidthMinuteRecord, StreamEventRecord, StreamProtocol } from "../types.ts";
import { UNKNOWN_COUNTRY_CODE } from "./geoip-service.ts";
import { openMetrics } from "./openmetrics-service.ts";

export interface StreamTrafficContext {
	streamId: string;
	incomingPort: number;
	ip: string;
	countryCode?: string | null;
	protocol: StreamProtocol;
}

export interface StreamTrafficDelta {
	clientToUpstreamBytes?: number;
	upstreamToClientBytes?: number;
}

interface MonitoringPersister {
	events(events: StreamEventRecord[]): Promise<void>;
	bandwidth(records: StreamBandwidthMinuteRecord[]): Promise<void>;
}

function bytes(value: number | undefined): number {
	return Number.isFinite(value) && Number(value) > 0 ? Math.floor(Number(value)) : 0;
}

function country(value: string | null | undefined): string {
	const code = value?.trim().toUpperCase();
	return code && /^[A-Z]{2}$/u.test(code) ? code : UNKNOWN_COUNTRY_CODE;
}

function bandwidthKey(record: StreamBandwidthMinuteRecord): string {
	return JSON.stringify([record.stream_id, record.incoming_port, record.bucket_start, record.ip, record.country_code, record.protocol]);
}

export class StreamMonitoringAccumulator {
	private events: StreamEventRecord[] = [];
	private bandwidth = new Map<string, StreamBandwidthMinuteRecord>();
	private flushing: Promise<void> | null = null;
	private droppedEvents = 0;
	private inFlightEventCount = 0;

	constructor(
		private readonly persist: MonitoringPersister,
		private readonly maxPendingKeys = config.bandwidth.maxPendingKeys,
		private readonly maxPendingEvents = config.streams.maxPendingEvents,
	) {}

	recordEvent(event: StreamEventRecord): void {
		if (this.events.length + this.inFlightEventCount >= this.maxPendingEvents) {
			this.droppedEvents += 1;
			return;
		}
		this.events.push(event);
	}

	takeDroppedEventCount(): number {
		const count = this.droppedEvents;
		this.droppedEvents = 0;
		return count;
	}

	pendingEventCount(): number {
		return this.events.length + this.inFlightEventCount;
	}

	pendingBandwidthRecordCount(): number {
		return this.bandwidth.size;
	}

	recordTraffic(context: StreamTrafficContext, delta: StreamTrafficDelta, now = Date.now()): void {
		const clientToUpstream = bytes(delta.clientToUpstreamBytes);
		const upstreamToClient = bytes(delta.upstreamToClientBytes);
		if (clientToUpstream + upstreamToClient === 0) return;
		const bucketStart = Math.floor(now / 60_000) * 60_000;
		const countryCode = country(context.countryCode);
		let ip = context.ip || "unknown";
		let record: StreamBandwidthMinuteRecord = {
			stream_id: context.streamId,
			incoming_port: context.incomingPort,
			bucket_start: bucketStart,
			ip,
			country_code: countryCode,
			protocol: context.protocol,
			client_to_upstream_bytes: 0,
			upstream_to_client_bytes: 0,
		};
		let key = bandwidthKey(record);
		if (!this.bandwidth.has(key) && this.bandwidth.size >= this.maxPendingKeys) {
			ip = "__other__";
			record = { ...record, ip };
			key = bandwidthKey(record);
		}
		const current = this.bandwidth.get(key) ?? record;
		current.client_to_upstream_bytes += clientToUpstream;
		current.upstream_to_client_bytes += upstreamToClient;
		this.bandwidth.set(key, current);
	}

	async flush(): Promise<void> {
		if (this.flushing) return await this.flushing;
		if (this.events.length === 0 && this.bandwidth.size === 0) return;
		const events = this.events;
		const bandwidth = this.bandwidth;
		this.events = [];
		this.bandwidth = new Map();
		this.inFlightEventCount = events.length;
		this.flushing = (async () => {
			let eventsPersisted = false;
			try {
				await this.persist.events(events);
				eventsPersisted = true;
				this.inFlightEventCount = 0;
				await this.persist.bandwidth([...bandwidth.values()]);
			} catch (error) {
				if (!eventsPersisted) {
					this.inFlightEventCount = 0;
					const combined = [...events, ...this.events];
					if (combined.length > this.maxPendingEvents) this.droppedEvents += combined.length - this.maxPendingEvents;
					this.events = combined.slice(0, this.maxPendingEvents);
				}
				for (const record of bandwidth.values()) {
					const key = bandwidthKey(record);
					const current = this.bandwidth.get(key);
					if (current) {
						current.client_to_upstream_bytes += record.client_to_upstream_bytes;
						current.upstream_to_client_bytes += record.upstream_to_client_bytes;
					} else {
						this.bandwidth.set(key, record);
					}
				}
				throw error;
			}
		})().finally(() => {
			this.inFlightEventCount = 0;
			this.flushing = null;
		});
		return await this.flushing;
	}
}

const accumulator = new StreamMonitoringAccumulator({
	events: async (events) => await repository.insertStreamEvents(events),
	bandwidth: async (records) => await repository.addStreamBandwidthDeltas(records),
});

let timer: ReturnType<typeof setInterval> | null = null;

export function recordStreamEvent(event: StreamEventRecord): void {
	accumulator.recordEvent(event);
	openMetrics.recordStreamEvent(event);
	openMetrics.setMonitoringQueue("stream_events", accumulator.pendingEventCount());
}

export function recordStreamTraffic(context: StreamTrafficContext, delta: StreamTrafficDelta, now?: number): void {
	accumulator.recordTraffic(context, delta, now);
	openMetrics.recordStreamBandwidth(context, delta);
	openMetrics.setMonitoringQueue("stream_bandwidth", accumulator.pendingBandwidthRecordCount());
}

export async function flushStreamMonitoring(): Promise<void> {
	try {
		await accumulator.flush();
	} catch (error) {
		openMetrics.recordMonitoringPersistenceFailure("stream_monitoring");
		Logger.error("Failed to persist stream monitoring data", { error });
	} finally {
		const dropped = accumulator.takeDroppedEventCount();
		openMetrics.recordDroppedMonitoringEvents("stream_events", dropped);
		openMetrics.setMonitoringQueue("stream_events", accumulator.pendingEventCount());
		openMetrics.setMonitoringQueue("stream_bandwidth", accumulator.pendingBandwidthRecordCount());
		if (dropped > 0) Logger.warn(`Dropped ${dropped} stream monitoring event(s) after reaching the pending-event memory limit`);
	}
}

export function startStreamMonitoring(): void {
	if (timer) return;
	timer = setInterval(() => void flushStreamMonitoring(), config.bandwidth.flushIntervalMs);
	(timer as unknown as { unref?: () => void }).unref?.();
}
