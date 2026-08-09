import { config } from "../config.ts";
import { isIP } from "node:net";
import { repository } from "../db/repository.ts";
import type { RateLimitAlgorithm, StreamRecord } from "../types.ts";
import { randomId } from "../utils/crypto.ts";

export interface StreamInput {
	incomingPort?: unknown;
	forwardHost?: unknown;
	forwardPort?: unknown;
	tcpEnabled?: unknown;
	udpEnabled?: unknown;
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
		incomingPort: Number(stream.incoming_port),
		forwardHost: stream.forward_host,
		forwardPort: Number(stream.forward_port),
		tcpEnabled: stream.tcp_enabled === 1,
		udpEnabled: stream.udp_enabled === 1,
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
		incoming_port: incomingPort,
		forward_host: forwardHost(input.forwardHost ?? existing?.forward_host),
		forward_port: port(input.forwardPort ?? existing?.forward_port, "Forward port"),
		tcp_enabled: tcpEnabled ? 1 : 0,
		udp_enabled: udpEnabled ? 1 : 0,
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
		created_at: existing?.created_at ?? now,
		updated_at: now,
	};
}
