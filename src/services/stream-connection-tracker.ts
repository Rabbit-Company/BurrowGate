import type { StreamRuleFieldValue } from "./stream-protection-service.ts";

/**
 * Rolling per-(stream, IP) connection-behavior counters that back the "connection.*" fields
 * available to every stream ruleset regardless of protocol (see stream-ruleset-format.ts). Unlike
 * the WAF, which evaluates one already-complete HTTP request, these signals are inherently
 * temporal - "rapid reconnects" or "repeated upstream failures" are only visible across multiple
 * connections over time, so this module keeps a small sliding window of recent events per IP.
 *
 * State here is intentionally coarse (event counts and durations, not raw events) and self-prunes
 * on every read/write, with a periodic sweep (pruneStaleEntries) evicting IPs that have gone quiet
 * so memory stays bounded under connection floods rather than growing with them.
 */

const WINDOW_MS = 60_000;

interface TrackerEntry {
	attempts: number[];
	disconnects: number[];
	sessionDurationsMs: number[];
	upstreamFailures: number[];
	lastZeroByteDisconnect: boolean;
	bytesSinceSweep: number;
	packetsSinceSweep: number;
	bytesPerSecond: number;
	packetsPerSecond: number;
	lastActivityAt: number;
}

const entries = new Map<string, TrackerEntry>();

function key(streamId: string, ip: string): string {
	return `${streamId} ${ip}`;
}

function entryFor(streamId: string, ip: string): TrackerEntry {
	const mapKey = key(streamId, ip);
	let entry = entries.get(mapKey);
	if (!entry) {
		entry = {
			attempts: [],
			disconnects: [],
			sessionDurationsMs: [],
			upstreamFailures: [],
			lastZeroByteDisconnect: false,
			bytesSinceSweep: 0,
			packetsSinceSweep: 0,
			bytesPerSecond: 0,
			packetsPerSecond: 0,
			lastActivityAt: Date.now(),
		};
		entries.set(mapKey, entry);
	}
	return entry;
}

function prune(timestamps: number[], now: number): void {
	while (timestamps.length > 0 && timestamps[0]! < now - WINDOW_MS) timestamps.shift();
}

export function recordStreamConnectionAttempt(streamId: string, ip: string): void {
	if (ip === "unknown") return;
	const entry = entryFor(streamId, ip);
	const now = Date.now();
	entry.attempts.push(now);
	prune(entry.attempts, now);
	entry.lastActivityAt = now;
}

export function recordStreamDisconnect(streamId: string, ip: string, sessionDurationMs: number, zeroByte: boolean): void {
	if (ip === "unknown") return;
	const entry = entryFor(streamId, ip);
	const now = Date.now();
	entry.disconnects.push(now);
	entry.sessionDurationsMs.push(Math.max(0, sessionDurationMs));
	prune(entry.disconnects, now);
	while (entry.sessionDurationsMs.length > entry.disconnects.length) entry.sessionDurationsMs.shift();
	entry.lastZeroByteDisconnect = zeroByte;
	entry.lastActivityAt = now;
}

export function recordStreamUpstreamFailure(streamId: string, ip: string): void {
	if (ip === "unknown") return;
	const entry = entryFor(streamId, ip);
	const now = Date.now();
	entry.upstreamFailures.push(now);
	prune(entry.upstreamFailures, now);
	entry.lastActivityAt = now;
}

export function recordStreamBytes(streamId: string, ip: string, byteCount: number): void {
	if (ip === "unknown" || byteCount <= 0) return;
	const entry = entryFor(streamId, ip);
	entry.bytesSinceSweep += byteCount;
	entry.packetsSinceSweep += 1;
	entry.lastActivityAt = Date.now();
}

/** Call once per sweep tick to turn accumulated byte/packet counts into a per-second rate for the interval just elapsed. */
export function computeStreamLiveRates(intervalSeconds: number): void {
	for (const entry of entries.values()) {
		entry.bytesPerSecond = entry.bytesSinceSweep / intervalSeconds;
		entry.packetsPerSecond = entry.packetsSinceSweep / intervalSeconds;
		entry.bytesSinceSweep = 0;
		entry.packetsSinceSweep = 0;
	}
}

export function streamConnectionMetrics(streamId: string, ip: string, protocol: "tcp" | "udp"): Record<string, StreamRuleFieldValue> {
	const entry = entries.get(key(streamId, ip));
	const now = Date.now();
	if (!entry) {
		return {
			"connection.protocol": protocol,
			"connection.attempts_60s": 0,
			"connection.disconnects_60s": 0,
			"connection.avg_session_ms_60s": 0,
			"connection.upstream_failures_60s": 0,
			"connection.bytes_per_second": 0,
			"connection.packets_per_second": 0,
			"connection.zero_byte_disconnect": false,
		};
	}
	prune(entry.attempts, now);
	prune(entry.disconnects, now);
	prune(entry.upstreamFailures, now);
	while (entry.sessionDurationsMs.length > entry.disconnects.length) entry.sessionDurationsMs.shift();
	const avgSessionMs =
		entry.sessionDurationsMs.length > 0 ? entry.sessionDurationsMs.reduce((sum, value) => sum + value, 0) / entry.sessionDurationsMs.length : 0;
	return {
		"connection.protocol": protocol,
		"connection.attempts_60s": entry.attempts.length,
		"connection.disconnects_60s": entry.disconnects.length,
		"connection.avg_session_ms_60s": Math.round(avgSessionMs),
		"connection.upstream_failures_60s": entry.upstreamFailures.length,
		"connection.bytes_per_second": Math.round(entry.bytesPerSecond),
		"connection.packets_per_second": Math.round(entry.packetsPerSecond),
		"connection.zero_byte_disconnect": entry.lastZeroByteDisconnect,
	};
}

/** Evicts IPs that have generated no tracked event in maxAgeMs, keeping memory bounded during floods. */
export function pruneStaleStreamConnectionEntries(maxAgeMs = 600_000): void {
	const now = Date.now();
	for (const [mapKey, entry] of entries) {
		if (now - entry.lastActivityAt > maxAgeMs) entries.delete(mapKey);
	}
}

export function clearStreamConnectionTracker(): void {
	entries.clear();
}
