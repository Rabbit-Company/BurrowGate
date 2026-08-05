import { Counter, Gauge, Histogram, Info, Registry } from "@rabbit-company/openmetrics-client";
import packageMetadata from "../../package.json" with { type: "json" };
import { config } from "../config.ts";
import { repository } from "../db/repository.ts";
import type { OriginHealthState, StreamEventRecord, StreamProtocol } from "../types.ts";
import { timingSafeEqualText } from "../utils/crypto.ts";
import { geoIpStatus } from "./geoip-service.ts";
import type { BandwidthContext, BandwidthDelta } from "./bandwidth-service.ts";
import type { StreamTrafficContext, StreamTrafficDelta } from "./stream-monitoring-service.ts";

export const OPENMETRICS_PATH = "/_burrowgate/metrics";

const COMMON_HTTP_METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE"]);

function positive(value: number | undefined): number {
	return Number.isFinite(value) && Number(value) > 0 ? Number(value) : 0;
}

function methodLabel(value: string): string {
	const method = value.trim().toUpperCase();
	return COMMON_HTTP_METHODS.has(method) ? method : "OTHER";
}

function statusClass(status: number): string {
	const value = Math.floor(Number(status));
	return value >= 100 && value <= 599 ? `${Math.floor(value / 100)}xx` : "other";
}

export interface HttpRequestMetricInput {
	siteId: string;
	method: string;
	status: number;
	decision: string;
	latencyMs: number;
}

export interface StreamRuntimeMetricInput {
	id: string;
	tcp: "disabled" | "active" | "error";
	udp: "disabled" | "active" | "error";
	activeTcpConnections: number;
	activeUdpPeers: number;
}

export interface RetentionCleanupMetricInput {
	deleted: number;
	attemptedBatches: number;
	errors: number;
	durationMs: number;
}

interface ExporterOptions {
	enabled?: boolean;
	environment?: string;
	version?: string;
}

/**
 * In-process operational metrics. Labels intentionally use configured resource
 * IDs and bounded enums only; request paths, client identities, and IPs never
 * enter the registry.
 */
export class BurrowGateOpenMetrics {
	readonly registry = new Registry({ prefix: "burrowgate" });
	private readonly enabled: boolean;
	private readonly startedAt = performance.now();
	private readonly buildInfo: Info;
	private readonly httpRequests: Counter;
	private readonly httpRequestDuration: Histogram;
	private readonly httpTransferred: Counter;
	private readonly streamEvents: Counter;
	private readonly streamTransferred: Counter;
	private readonly streamActiveConnections: Gauge;
	private readonly streamListenerConfigured: Gauge;
	private readonly streamListenerUp: Gauge;
	private readonly monitoringQueueRecords: Gauge;
	private readonly monitoringPersistenceFailures: Counter;
	private readonly monitoringDroppedEvents: Counter;
	private readonly retentionRowsDeleted: Counter;
	private readonly retentionBatches: Counter;
	private readonly retentionErrors: Counter;
	private readonly retentionDuration: Histogram;
	private readonly retentionLastRun: Gauge;
	private readonly processUptime: Gauge;
	private readonly processMemory: Gauge;
	private readonly databaseUp: Gauge;
	private readonly configuredSites: Gauge;
	private readonly configuredStreams: Gauge;
	private readonly geoIp: Gauge;
	private readonly originHealthState: Gauge;
	private readonly originHealthChecks: Counter;
	private readonly originHealthDuration: Histogram;
	private readonly healthAlerts: Counter;
	private readonly exporterScrapes: Counter;
	private readonly exporterCollectionErrors: Counter;
	private readonly exporterDuration: Histogram;

	constructor(options: ExporterOptions = {}) {
		this.enabled = options.enabled ?? true;
		this.buildInfo = new Info({
			name: "build",
			help: "BurrowGate build information",
			labelNames: ["version", "environment"],
			registry: this.registry,
		});
		this.httpRequests = new Counter({
			name: "http_requests",
			help: "Protected HTTP and WebSocket requests processed",
			labelNames: ["site_id", "method", "status_class", "decision"],
			registry: this.registry,
		});
		this.httpRequestDuration = new Histogram({
			name: "http_request_duration",
			help: "Protected HTTP and WebSocket request processing duration",
			unit: "seconds",
			labelNames: ["site_id", "method", "status_class"],
			buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30],
			registry: this.registry,
		});
		this.httpTransferred = new Counter({
			name: "http_transferred",
			help: "HTTP and WebSocket payload bytes transferred",
			unit: "bytes",
			labelNames: ["site_id", "protocol", "direction"],
			registry: this.registry,
		});
		this.streamEvents = new Counter({
			name: "stream_events",
			help: "TCP and UDP stream lifecycle events",
			labelNames: ["stream_id", "protocol", "event"],
			registry: this.registry,
		});
		this.streamTransferred = new Counter({
			name: "stream_transferred",
			help: "TCP and UDP stream payload bytes transferred",
			unit: "bytes",
			labelNames: ["stream_id", "protocol", "direction"],
			registry: this.registry,
		});
		this.streamActiveConnections = new Gauge({
			name: "stream_active_connections",
			help: "Current active TCP connections or UDP peers",
			labelNames: ["stream_id", "protocol"],
			registry: this.registry,
		});
		this.streamListenerConfigured = new Gauge({
			name: "stream_listener_configured",
			help: "Whether the stream listener protocol is configured",
			labelNames: ["stream_id", "protocol"],
			registry: this.registry,
		});
		this.streamListenerUp = new Gauge({
			name: "stream_listener_up",
			help: "Whether the configured stream listener is active",
			labelNames: ["stream_id", "protocol"],
			registry: this.registry,
		});
		this.monitoringQueueRecords = new Gauge({
			name: "monitoring_queue_records",
			help: "Monitoring records waiting for database persistence",
			labelNames: ["queue"],
			registry: this.registry,
		});
		this.monitoringPersistenceFailures = new Counter({
			name: "monitoring_persistence_failures",
			help: "Monitoring persistence failures",
			labelNames: ["queue"],
			registry: this.registry,
		});
		this.monitoringDroppedEvents = new Counter({
			name: "monitoring_dropped_events",
			help: "Monitoring events dropped after reaching an in-memory limit",
			labelNames: ["queue"],
			registry: this.registry,
		});
		this.retentionRowsDeleted = new Counter({ name: "retention_cleanup_deleted_rows", help: "Rows deleted by retention cleanup", registry: this.registry });
		this.retentionBatches = new Counter({ name: "retention_cleanup_batches", help: "Retention cleanup batches attempted", registry: this.registry });
		this.retentionErrors = new Counter({ name: "retention_cleanup_errors", help: "Retention cleanup task errors", registry: this.registry });
		this.retentionDuration = new Histogram({
			name: "retention_cleanup_duration",
			help: "Retention cleanup pass duration",
			unit: "seconds",
			buckets: [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60],
			registry: this.registry,
		});
		this.retentionLastRun = new Gauge({
			name: "retention_cleanup_last_run_timestamp",
			help: "Unix timestamp of the last completed retention cleanup pass",
			unit: "seconds",
			registry: this.registry,
		});
		this.processUptime = new Gauge({ name: "process_uptime", help: "BurrowGate process uptime", unit: "seconds", registry: this.registry });
		this.processMemory = new Gauge({
			name: "process_memory",
			help: "BurrowGate process memory usage",
			unit: "bytes",
			labelNames: ["kind"],
			registry: this.registry,
		});
		this.databaseUp = new Gauge({ name: "database_up", help: "Whether operational metric collection can query the database", registry: this.registry });
		this.configuredSites = new Gauge({
			name: "configured_sites",
			help: "Configured website proxy count",
			labelNames: ["state"],
			registry: this.registry,
		});
		this.configuredStreams = new Gauge({
			name: "configured_streams",
			help: "Configured stream listener count by protocol",
			labelNames: ["protocol"],
			registry: this.registry,
		});
		this.geoIp = new Gauge({
			name: "geoip_database",
			help: "GeoIP feature and database availability",
			labelNames: ["state"],
			registry: this.registry,
		});
		this.originHealthState = new Gauge({
			name: "origin_health_state",
			help: "Current origin health state as a one-hot gauge",
			labelNames: ["site_id", "state"],
			registry: this.registry,
		});
		this.originHealthChecks = new Counter({
			name: "origin_health_checks",
			help: "Origin health checks by outcome",
			labelNames: ["site_id", "outcome"],
			registry: this.registry,
		});
		this.originHealthDuration = new Histogram({
			name: "origin_health_check_duration",
			help: "Origin health-check request duration",
			unit: "seconds",
			labelNames: ["site_id"],
			buckets: [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60],
			registry: this.registry,
		});
		this.healthAlerts = new Counter({
			name: "origin_health_alerts",
			help: "Origin health alert delivery outcomes",
			labelNames: ["site_id", "outcome"],
			registry: this.registry,
		});
		this.exporterScrapes = new Counter({ name: "openmetrics_scrapes", help: "OpenMetrics scrape requests served", registry: this.registry });
		this.exporterCollectionErrors = new Counter({
			name: "openmetrics_collection_errors",
			help: "Errors while refreshing scrape-time metrics",
			registry: this.registry,
		});
		this.exporterDuration = new Histogram({
			name: "openmetrics_collection_duration",
			help: "OpenMetrics scrape-time collection duration",
			unit: "seconds",
			buckets: [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5],
			registry: this.registry,
		});
		this.buildInfo.labels({ version: options.version ?? packageMetadata.version, environment: options.environment ?? config.environment }).set();
	}

	recordHttpRequest(input: HttpRequestMetricInput): void {
		if (!this.enabled) return;
		const labels = {
			site_id: input.siteId,
			method: methodLabel(input.method),
			status_class: statusClass(input.status),
		};
		this.httpRequests.labels({ ...labels, decision: input.decision }).inc();
		this.httpRequestDuration.labels(labels).observe(Math.max(0, input.latencyMs) / 1_000);
	}

	recordHttpBandwidth(context: BandwidthContext, delta: BandwidthDelta): void {
		if (!this.enabled) return;
		for (const [direction, value] of [
			["client_received", delta.clientReceivedBytes],
			["client_sent", delta.clientSentBytes],
			["upstream_sent", delta.upstreamSentBytes],
			["upstream_received", delta.upstreamReceivedBytes],
		] as const) {
			const amount = positive(value);
			if (amount > 0) this.httpTransferred.labels({ site_id: context.siteId, protocol: context.protocol, direction }).inc(amount);
		}
	}

	recordStreamEvent(event: StreamEventRecord): void {
		if (!this.enabled) return;
		this.streamEvents.labels({ stream_id: event.stream_id, protocol: event.protocol, event: event.event_type }).inc();
	}

	recordStreamBandwidth(context: StreamTrafficContext, delta: StreamTrafficDelta): void {
		if (!this.enabled) return;
		const toUpstream = positive(delta.clientToUpstreamBytes);
		const toClient = positive(delta.upstreamToClientBytes);
		if (toUpstream > 0)
			this.streamTransferred.labels({ stream_id: context.streamId, protocol: context.protocol, direction: "client_to_upstream" }).inc(toUpstream);
		if (toClient > 0) this.streamTransferred.labels({ stream_id: context.streamId, protocol: context.protocol, direction: "upstream_to_client" }).inc(toClient);
	}

	setStreamRuntime(status: StreamRuntimeMetricInput): void {
		if (!this.enabled) return;
		for (const protocol of ["tcp", "udp"] as StreamProtocol[]) {
			const state = status[protocol];
			const labels = { stream_id: status.id, protocol };
			this.streamListenerConfigured.labels(labels).set(state === "disabled" ? 0 : 1);
			this.streamListenerUp.labels(labels).set(state === "active" ? 1 : 0);
			this.streamActiveConnections.labels(labels).set(protocol === "tcp" ? status.activeTcpConnections : status.activeUdpPeers);
		}
	}

	clearStreamRuntime(streamId: string): void {
		if (!this.enabled) return;
		for (const protocol of ["tcp", "udp"] as StreamProtocol[]) {
			const labels = { stream_id: streamId, protocol };
			this.streamListenerConfigured.labels(labels).set(0);
			this.streamListenerUp.labels(labels).set(0);
			this.streamActiveConnections.labels(labels).set(0);
		}
	}

	setMonitoringQueue(queue: string, records: number): void {
		if (this.enabled) this.monitoringQueueRecords.labels({ queue }).set(Math.max(0, records));
	}

	recordMonitoringPersistenceFailure(queue: string): void {
		if (this.enabled) this.monitoringPersistenceFailures.labels({ queue }).inc();
	}

	recordDroppedMonitoringEvents(queue: string, count: number): void {
		if (this.enabled && count > 0) this.monitoringDroppedEvents.labels({ queue }).inc(count);
	}

	recordRetentionCleanup(input: RetentionCleanupMetricInput): void {
		if (!this.enabled) return;
		if (input.deleted > 0) this.retentionRowsDeleted.inc(input.deleted);
		if (input.attemptedBatches > 0) this.retentionBatches.inc(input.attemptedBatches);
		if (input.errors > 0) this.retentionErrors.inc(input.errors);
		this.retentionDuration.observe(Math.max(0, input.durationMs) / 1_000);
		this.retentionLastRun.set(Date.now() / 1_000);
	}

	refreshProcessMetrics(): void {
		if (!this.enabled) return;
		this.processUptime.set((performance.now() - this.startedAt) / 1_000);
		const memory = process.memoryUsage();
		this.processMemory.labels({ kind: "rss" }).set(memory.rss);
		this.processMemory.labels({ kind: "heap_used" }).set(memory.heapUsed);
		this.processMemory.labels({ kind: "heap_total" }).set(memory.heapTotal);
		this.processMemory.labels({ kind: "external" }).set(memory.external);
		this.processMemory.labels({ kind: "array_buffers" }).set(memory.arrayBuffers);
	}

	setDatabaseState(up: boolean): void {
		if (this.enabled) this.databaseUp.set(up ? 1 : 0);
	}

	setConfiguredResources(sites: Array<{ enabled: number }>, streams: Array<{ tcp_enabled: number; udp_enabled: number }>): void {
		if (!this.enabled) return;
		this.configuredSites.labels({ state: "enabled" }).set(sites.filter((site) => site.enabled === 1).length);
		this.configuredSites.labels({ state: "disabled" }).set(sites.filter((site) => site.enabled !== 1).length);
		this.configuredStreams.labels({ protocol: "tcp" }).set(streams.filter((stream) => stream.tcp_enabled === 1).length);
		this.configuredStreams.labels({ protocol: "udp" }).set(streams.filter((stream) => stream.udp_enabled === 1).length);
	}

	setGeoIpState(enabled: boolean, available: boolean): void {
		if (!this.enabled) return;
		this.geoIp.labels({ state: "enabled" }).set(enabled ? 1 : 0);
		this.geoIp.labels({ state: "available" }).set(available ? 1 : 0);
	}

	setOriginHealth(siteId: string, state: OriginHealthState): void {
		if (!this.enabled) return;
		for (const candidate of ["unknown", "healthy", "degraded", "unhealthy", "disabled"] as OriginHealthState[]) {
			this.originHealthState.labels({ site_id: siteId, state: candidate }).set(candidate === state ? 1 : 0);
		}
	}

	clearOriginHealth(siteId: string): void {
		if (!this.enabled) return;
		for (const state of ["unknown", "healthy", "degraded", "unhealthy", "disabled"] as OriginHealthState[]) {
			this.originHealthState.labels({ site_id: siteId, state }).set(0);
		}
	}

	recordOriginHealthCheck(siteId: string, healthy: boolean, durationMs: number): void {
		if (!this.enabled) return;
		this.originHealthChecks.labels({ site_id: siteId, outcome: healthy ? "success" : "failure" }).inc();
		this.originHealthDuration.labels({ site_id: siteId }).observe(Math.max(0, durationMs) / 1_000);
	}

	recordHealthAlert(siteId: string, outcome: "delivered" | "retry" | "failed"): void {
		if (this.enabled) this.healthAlerts.labels({ site_id: siteId, outcome }).inc();
	}

	beginScrape(): number {
		if (!this.enabled) return performance.now();
		this.exporterScrapes.inc();
		return performance.now();
	}

	finishScrape(startedAt: number, error = false): string {
		if (this.enabled) {
			if (error) this.exporterCollectionErrors.inc();
			this.exporterDuration.observe(Math.max(0, performance.now() - startedAt) / 1_000);
		}
		return this.registry.metricsText();
	}

	metricsText(): string {
		return this.registry.metricsText();
	}
}

export const openMetrics = new BurrowGateOpenMetrics({ enabled: config.openMetrics.enabled });

export async function metricsRequestAuthorized(request: Request, token = config.openMetrics.token): Promise<boolean> {
	if (!token) return true;
	const authorization = request.headers.get("authorization") ?? "";
	const supplied = authorization.startsWith("Bearer ") ? authorization.slice(7).trim() : "";
	return supplied.length > 0 && (await timingSafeEqualText(supplied, token));
}

export async function openMetricsResponse(request: Request): Promise<Response> {
	if (!(await metricsRequestAuthorized(request))) {
		return new Response("Unauthorized\n", {
			status: 401,
			headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store", "www-authenticate": 'Bearer realm="BurrowGate metrics"' },
		});
	}
	const startedAt = openMetrics.beginScrape();
	let collectionError = false;
	openMetrics.refreshProcessMetrics();
	const geoIp = geoIpStatus();
	openMetrics.setGeoIpState(geoIp.enabled, geoIp.available);
	try {
		const [sites, streams] = await Promise.all([repository.allSites(), repository.allStreams()]);
		openMetrics.setConfiguredResources(sites, streams);
		openMetrics.setDatabaseState(true);
	} catch {
		collectionError = true;
		openMetrics.setDatabaseState(false);
	}
	return new Response(openMetrics.finishScrape(startedAt, collectionError), {
		headers: { "content-type": openMetrics.registry.contentType, "cache-control": "no-store" },
	});
}
