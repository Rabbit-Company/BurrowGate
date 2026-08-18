import { config } from "../config.ts";
import { isIP } from "node:net";
import { repository } from "../db/repository.ts";
import type { RateLimitAlgorithm, StreamProxyProtocol, StreamRecord } from "../types.ts";
import { randomId } from "../utils/crypto.ts";
import { resolveStreamProtectionPolicy } from "./stream-protection-policy-service.ts";
import { streamHealthManager } from "./stream-health-service.ts";
import { streamProxyManager } from "./stream-proxy-service.ts";

export interface StreamInput {
	name?: unknown;
	incomingPort?: unknown;
	forwardHost?: unknown;
	forwardPort?: unknown;
	tcpEnabled?: unknown;
	udpEnabled?: unknown;
	proxyProtocol?: unknown;
	certificateId?: unknown;
	eventRetentionDays?: unknown;
	maxConnectionsPerIp?: unknown;
	connectionRateLimitEnabled?: unknown;
	connectionRateLimitAlgorithm?: unknown;
	connectionRateLimitWindowMs?: unknown;
	connectionRateLimitMax?: unknown;
	connectionRateLimitRefillRate?: unknown;
	connectionRateLimitRefillIntervalMs?: unknown;
	connectionRateLimitPrecisionMs?: unknown;
	udpAmplificationMaxRatio?: unknown;
	originHealthCheckEnabled?: unknown;
	originHealthCheckIntervalSeconds?: unknown;
	originHealthCheckTimeoutMs?: unknown;
	originHealthCheckFailureThreshold?: unknown;
	originHealthCheckRecoveryThreshold?: unknown;
	effectiveAt?: unknown;
}

/** Fields that force StreamProxyManager to stop and recreate the TCP/UDP listener when changed. */
export const STREAM_RESTART_FIELDS = [
	"tcp_enabled",
	"udp_enabled",
	"incoming_port",
	"forward_host",
	"forward_port",
	"certificate_id",
	"proxy_protocol",
] as const satisfies readonly (keyof StreamRecord)[];

export function streamRestartDiffers(a: StreamRecord, b: StreamRecord): boolean {
	return STREAM_RESTART_FIELDS.some((field) => a[field] !== b[field]);
}

export function pickStreamRestartFields(record: StreamRecord): Pick<StreamRecord, (typeof STREAM_RESTART_FIELDS)[number]> {
	return Object.fromEntries(STREAM_RESTART_FIELDS.map((field) => [field, record[field]])) as Pick<StreamRecord, (typeof STREAM_RESTART_FIELDS)[number]>;
}

function requiredString(value: unknown, label: string, maximum: number): string {
	const result = String(value ?? "").trim();
	if (!result) throw new Error(`${label} is required`);
	if (result.length > maximum) throw new Error(`${label} must be at most ${maximum} characters`);
	return result;
}

function port(value: unknown, label: string): number {
	const result = Number(value);
	if (!Number.isInteger(result) || result < 1 || result > 65_535) throw new Error(`${label} must be an integer from 1 to 65535`);
	return result;
}

function booleanValue(value: unknown, fallback: boolean): boolean {
	if (value === undefined) return fallback;
	if (typeof value === "boolean") return value;
	if (value === 1 || value === "1" || value === "true") return true;
	if (value === 0 || value === "0" || value === "false") return false;
	throw new Error("Protocol toggles must be booleans");
}

function forwardHost(value: unknown): string {
	let host = String(value ?? "").trim();
	if (!host) throw new Error("Forward host is required");
	if (host.length > 255) throw new Error("Forward host must be at most 255 characters");
	if (/[/?#\s]/u.test(host)) throw new Error("Forward host must be a hostname or IP address without a scheme, port, or path");
	if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
	if (host.includes(":") && isIP(host) !== 6) throw new Error("Forward host must not include a port");
	return host;
}

function retentionDays(value: unknown, fallback: number): number {
	const result = value === undefined ? fallback : Number(value);
	if (!Number.isInteger(result) || result < 1 || result > 365) throw new Error("Stream data retention must be an integer from 1 to 365 days");
	return result;
}

function maxConnectionsPerIp(value: unknown, fallback: number): number {
	const result = value === undefined ? fallback : Number(value);
	if (!Number.isInteger(result) || result < 0 || result > 100_000) {
		throw new Error("Max connections per IP must be an integer from 0 to 100000 (0 disables the limit)");
	}
	return result;
}

function integerValue(value: unknown, label: string, fallback: number, minimum: number, maximum: number): number {
	const result = value === undefined || value === "" ? fallback : Number(value);
	if (!Number.isInteger(result) || result < minimum || result > maximum) {
		throw new Error(`${label} must be an integer from ${minimum} to ${maximum}`);
	}
	return result;
}

function rateLimitAlgorithm(value: unknown, fallback: RateLimitAlgorithm): RateLimitAlgorithm {
	const result = value === undefined ? fallback : String(value).trim().toLowerCase();
	if (result === "fixed-window" || result === "sliding-window" || result === "token-bucket") return result;
	throw new Error("Connection rate-limit algorithm must be fixed-window, sliding-window, or token-bucket");
}

function proxyProtocol(value: unknown, fallback: StreamProxyProtocol, tcpEnabled: boolean): StreamProxyProtocol {
	const result = value === undefined ? fallback : String(value).trim().toLowerCase();
	if (result !== "disabled" && result !== "v1" && result !== "v2") {
		throw new Error("PROXY protocol must be disabled, v1, or v2");
	}
	if (result === "v1" && !tcpEnabled) throw new Error("PROXY protocol v1 is only available for TCP streams (use v2 for UDP)");
	return result;
}

function udpAmplificationMaxRatio(value: unknown, fallback: number): number {
	const result = value === undefined || value === "" ? fallback : Number(value);
	if (!Number.isInteger(result) || result < 0 || result > 10_000) {
		throw new Error("UDP amplification ratio must be an integer from 0 to 10000 (0 disables the guard)");
	}
	return result;
}

async function certificateId(value: unknown, tcpEnabled: boolean): Promise<string | null> {
	const id = String(value ?? "").trim() || null;
	if (!id) return null;
	if (!tcpEnabled) throw new Error("A TLS certificate can only be used when TCP is enabled");
	const certificate = await repository.certificateById(id);
	if (!certificate || certificate.status !== "active" || Number(certificate.expires_at ?? 0) <= Date.now()) {
		throw new Error("The selected certificate is unavailable or expired");
	}
	if (!certificate.certificate_pem || !certificate.encrypted_private_key) throw new Error("The selected certificate has no usable TLS material");
	return id;
}

export function streamView(stream: StreamRecord) {
	return {
		id: stream.id,
		name: stream.name,
		incomingPort: Number(stream.incoming_port),
		forwardHost: stream.forward_host,
		forwardPort: Number(stream.forward_port),
		tcpEnabled: stream.tcp_enabled === 1,
		udpEnabled: stream.udp_enabled === 1,
		proxyProtocol: stream.proxy_protocol ?? "disabled",
		certificateId: stream.certificate_id,
		eventRetentionDays: Number(stream.event_retention_days),
		defaultIpAction: stream.default_ip_action ?? "inherit",
		defaultCountryAction: stream.default_country_action ?? "inherit",
		maxConnectionsPerIp: Number(stream.max_connections_per_ip ?? 0),
		connectionRateLimit: {
			enabled: stream.connection_rate_limit_enabled === 1,
			algorithm: stream.connection_rate_limit_algorithm ?? "sliding-window",
			windowMs: Number(stream.connection_rate_limit_window_ms ?? 60_000),
			max: Number(stream.connection_rate_limit_max ?? 60),
			refillRate: Number(stream.connection_rate_limit_refill_rate ?? 10),
			refillIntervalMs: Number(stream.connection_rate_limit_refill_interval_ms ?? 1_000),
			precisionMs: Number(stream.connection_rate_limit_precision_ms ?? 100),
		},
		udpAmplificationMaxRatio: Number(stream.udp_amplification_max_ratio ?? 0),
		originHealthCheck: {
			enabled: stream.origin_health_check_enabled === 1,
			intervalSeconds: Number(stream.origin_health_check_interval_seconds ?? 10),
			timeoutMs: Number(stream.origin_health_check_timeout_ms ?? 3_000),
			failureThreshold: Number(stream.origin_health_check_failure_threshold ?? 3),
			recoveryThreshold: Number(stream.origin_health_check_recovery_threshold ?? 2),
		},
		protection: resolveStreamProtectionPolicy(stream),
		createdAt: Number(stream.created_at),
		updatedAt: Number(stream.updated_at),
	};
}

export async function buildStream(input: StreamInput, existing?: StreamRecord): Promise<StreamRecord> {
	const tcpEnabled = booleanValue(input.tcpEnabled, existing?.tcp_enabled === 1 || !existing);
	const udpEnabled = booleanValue(input.udpEnabled, existing?.udp_enabled === 1);
	if (!tcpEnabled && !udpEnabled) throw new Error("Enable at least one of TCP or UDP");
	const incomingPort = port(input.incomingPort ?? existing?.incoming_port, "Incoming port");
	if (tcpEnabled && config.http.enabled && incomingPort === config.http.port) throw new Error("Incoming TCP port conflicts with BurrowGate's HTTP listener");
	if (tcpEnabled && config.https.enabled && incomingPort === config.https.port) throw new Error("Incoming TCP port conflicts with BurrowGate's HTTPS listener");
	const now = Date.now();
	return {
		id: existing?.id ?? randomId("stream"),
		name: requiredString(input.name ?? existing?.name, "Stream name", 255),
		incoming_port: incomingPort,
		forward_host: forwardHost(input.forwardHost ?? existing?.forward_host),
		forward_port: port(input.forwardPort ?? existing?.forward_port, "Forward port"),
		tcp_enabled: tcpEnabled ? 1 : 0,
		udp_enabled: udpEnabled ? 1 : 0,
		proxy_protocol: proxyProtocol(input.proxyProtocol, existing?.proxy_protocol ?? "disabled", tcpEnabled),
		certificate_id: await certificateId(input.certificateId === undefined ? existing?.certificate_id : input.certificateId, tcpEnabled),
		event_retention_days: retentionDays(input.eventRetentionDays, existing?.event_retention_days ?? config.eventRetentionDays),
		default_ip_action: existing?.default_ip_action ?? "inherit",
		default_country_action: existing?.default_country_action ?? "inherit",
		max_connections_per_ip: maxConnectionsPerIp(input.maxConnectionsPerIp, existing?.max_connections_per_ip ?? 0),
		connection_rate_limit_enabled: booleanValue(input.connectionRateLimitEnabled, existing?.connection_rate_limit_enabled === 1) ? 1 : 0,
		connection_rate_limit_algorithm: rateLimitAlgorithm(input.connectionRateLimitAlgorithm, existing?.connection_rate_limit_algorithm ?? "sliding-window"),
		connection_rate_limit_window_ms: integerValue(
			input.connectionRateLimitWindowMs,
			"Connection rate-limit window",
			existing?.connection_rate_limit_window_ms ?? 60_000,
			100,
			86_400_000,
		),
		connection_rate_limit_max: integerValue(
			input.connectionRateLimitMax,
			"Connection rate-limit maximum",
			existing?.connection_rate_limit_max ?? 60,
			1,
			1_000_000,
		),
		connection_rate_limit_refill_rate: integerValue(
			input.connectionRateLimitRefillRate,
			"Connection token refill rate",
			existing?.connection_rate_limit_refill_rate ?? 10,
			1,
			1_000_000,
		),
		connection_rate_limit_refill_interval_ms: integerValue(
			input.connectionRateLimitRefillIntervalMs,
			"Connection token refill interval",
			existing?.connection_rate_limit_refill_interval_ms ?? 1_000,
			50,
			3_600_000,
		),
		connection_rate_limit_precision_ms: integerValue(
			input.connectionRateLimitPrecisionMs,
			"Connection rate-limit precision",
			existing?.connection_rate_limit_precision_ms ?? 100,
			10,
			60_000,
		),
		udp_amplification_max_ratio: udpAmplificationMaxRatio(input.udpAmplificationMaxRatio, existing?.udp_amplification_max_ratio ?? 0),
		origin_health_check_enabled: booleanValue(input.originHealthCheckEnabled, existing?.origin_health_check_enabled === 1) ? 1 : 0,
		origin_health_check_interval_seconds: integerValue(
			input.originHealthCheckIntervalSeconds,
			"Origin health-check interval",
			existing?.origin_health_check_interval_seconds ?? 10,
			3,
			3_600,
		),
		origin_health_check_timeout_ms: integerValue(
			input.originHealthCheckTimeoutMs,
			"Origin health-check timeout",
			existing?.origin_health_check_timeout_ms ?? 3_000,
			250,
			60_000,
		),
		origin_health_check_failure_threshold: integerValue(
			input.originHealthCheckFailureThreshold,
			"Origin health-check failure threshold",
			existing?.origin_health_check_failure_threshold ?? 3,
			1,
			20,
		),
		origin_health_check_recovery_threshold: integerValue(
			input.originHealthCheckRecoveryThreshold,
			"Origin health-check recovery threshold",
			existing?.origin_health_check_recovery_threshold ?? 2,
			1,
			20,
		),
		protection_policy_json: existing?.protection_policy_json ?? null,
		bandwidth_policy_json: existing?.bandwidth_policy_json ?? null,
		notification_policy_json: existing?.notification_policy_json ?? null,
		created_at: existing?.created_at ?? now,
		updated_at: now,
	};
}

export async function applyPendingStreamChange(streamId: string, changes: Record<string, unknown>): Promise<void> {
	const live = await repository.streamById(streamId);
	if (!live) return;
	const merged: StreamRecord = { ...live, ...(changes as Partial<StreamRecord>), updated_at: Date.now() };
	await repository.saveStream(merged);
	try {
		await streamProxyManager.apply(merged);
	} catch (error) {
		await repository.saveStream(live);
		throw error;
	}
	await streamHealthManager.refresh(merged.id);
}
