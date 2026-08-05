import { config } from "../config.ts";
import { repository } from "../db/repository.ts";
import { Logger } from "../logger.ts";
import type { BandwidthMinuteRecord, BandwidthProtocol } from "../types.ts";
import { openMetrics } from "./openmetrics-service.ts";

export interface BandwidthContext {
	siteId: string;
	ip: string;
	countryCode?: string | null;
	protocol: BandwidthProtocol;
}

export interface BandwidthDelta {
	clientReceivedBytes?: number;
	clientSentBytes?: number;
	upstreamSentBytes?: number;
	upstreamReceivedBytes?: number;
}

type BandwidthPersister = (records: BandwidthMinuteRecord[]) => Promise<void>;

function positiveBytes(value: number | undefined): number {
	return Number.isFinite(value) && Number(value) > 0 ? Math.floor(Number(value)) : 0;
}

function storedCountryCode(value: string | null | undefined): string {
	const code = value?.trim().toUpperCase();
	return code && /^[A-Z]{2}$/u.test(code) ? code : "ZZ";
}

function recordKey(record: Pick<BandwidthMinuteRecord, "site_id" | "bucket_start" | "ip" | "country_code" | "protocol">): string {
	return JSON.stringify([record.site_id, record.bucket_start, record.ip, record.country_code, record.protocol]);
}

function addDelta(record: BandwidthMinuteRecord, delta: BandwidthDelta): void {
	record.client_received_bytes += positiveBytes(delta.clientReceivedBytes);
	record.client_sent_bytes += positiveBytes(delta.clientSentBytes);
	record.upstream_sent_bytes += positiveBytes(delta.upstreamSentBytes);
	record.upstream_received_bytes += positiveBytes(delta.upstreamReceivedBytes);
}

function hasBytes(delta: BandwidthDelta): boolean {
	return (
		positiveBytes(delta.clientReceivedBytes) +
			positiveBytes(delta.clientSentBytes) +
			positiveBytes(delta.upstreamSentBytes) +
			positiveBytes(delta.upstreamReceivedBytes) >
		0
	);
}

/**
 * Collects byte deltas in memory and persists one row per site/IP/country/
 * protocol/minute. New high-cardinality IPs are folded into a per-country
 * overflow row once the pending-key ceiling is reached, preserving site and
 * country totals during a distributed-source flood.
 */
export class BandwidthAccumulator {
	private pending = new Map<string, BandwidthMinuteRecord>();
	private flushPromise: Promise<void> | null = null;

	constructor(
		private readonly persist: BandwidthPersister,
		private readonly maxPendingKeys = config.bandwidth.maxPendingKeys,
	) {}

	pendingRecordCount(): number {
		return this.pending.size;
	}

	record(context: BandwidthContext, delta: BandwidthDelta, now = Date.now()): void {
		if (!hasBytes(delta)) return;
		const countryCode = storedCountryCode(context.countryCode);
		const bucketStart = Math.floor(now / 60_000) * 60_000;
		let ip = context.ip || "unknown";
		let key = recordKey({ site_id: context.siteId, bucket_start: bucketStart, ip, country_code: countryCode, protocol: context.protocol });
		if (!this.pending.has(key) && this.pending.size >= this.maxPendingKeys) {
			ip = "__other__";
			key = recordKey({ site_id: context.siteId, bucket_start: bucketStart, ip, country_code: countryCode, protocol: context.protocol });
		}
		let record = this.pending.get(key);
		if (!record) {
			record = {
				site_id: context.siteId,
				bucket_start: bucketStart,
				ip,
				country_code: countryCode,
				protocol: context.protocol,
				client_received_bytes: 0,
				client_sent_bytes: 0,
				upstream_sent_bytes: 0,
				upstream_received_bytes: 0,
			};
			this.pending.set(key, record);
		}
		addDelta(record, delta);
	}

	async flush(): Promise<void> {
		if (this.flushPromise) return this.flushPromise;
		if (this.pending.size === 0) return;
		const batch = this.pending;
		this.pending = new Map();
		this.flushPromise = this.persist([...batch.values()])
			.catch((error) => {
				for (const record of batch.values()) {
					const key = recordKey(record);
					const current = this.pending.get(key);
					if (current) {
						current.client_received_bytes += record.client_received_bytes;
						current.client_sent_bytes += record.client_sent_bytes;
						current.upstream_sent_bytes += record.upstream_sent_bytes;
						current.upstream_received_bytes += record.upstream_received_bytes;
					} else {
						this.pending.set(key, record);
					}
				}
				throw error;
			})
			.finally(() => {
				this.flushPromise = null;
			});
		return this.flushPromise;
	}
}

const accumulator = new BandwidthAccumulator((records) => repository.addBandwidthDeltas(records));
let flushTimer: ReturnType<typeof setInterval> | null = null;

export function recordBandwidth(context: BandwidthContext, delta: BandwidthDelta, now?: number): void {
	accumulator.record(context, delta, now);
	openMetrics.recordHttpBandwidth(context, delta);
	openMetrics.setMonitoringQueue("http_bandwidth", accumulator.pendingRecordCount());
}

export async function flushBandwidthMetrics(): Promise<void> {
	try {
		await accumulator.flush();
	} catch (error) {
		openMetrics.recordMonitoringPersistenceFailure("http_bandwidth");
		Logger.error("Failed to persist bandwidth metrics", { error });
	} finally {
		openMetrics.setMonitoringQueue("http_bandwidth", accumulator.pendingRecordCount());
	}
}

export function startBandwidthMetrics(): void {
	if (flushTimer) return;
	flushTimer = setInterval(() => void flushBandwidthMetrics(), config.bandwidth.flushIntervalMs);
	(flushTimer as unknown as { unref?: () => void }).unref?.();
}

export function byteLength(chunk: unknown): number {
	if (typeof chunk === "string") return Buffer.byteLength(chunk);
	if (chunk instanceof ArrayBuffer) return chunk.byteLength;
	if (ArrayBuffer.isView(chunk)) return chunk.byteLength;
	return 0;
}

export function meteredBody(
	body: ReadableStream<Uint8Array> | null,
	context: BandwidthContext,
	deltaForBytes: (bytes: number) => BandwidthDelta,
	recorder: (context: BandwidthContext, delta: BandwidthDelta) => void = recordBandwidth,
): ReadableStream<Uint8Array> | null {
	if (!body) return null;
	return body.pipeThrough(
		new TransformStream<Uint8Array, Uint8Array>({
			transform(chunk, controller) {
				const bytes = byteLength(chunk);
				if (bytes > 0) recorder(context, deltaForBytes(bytes));
				controller.enqueue(chunk);
			},
		}),
	);
}
