import { repository } from "../db/repository.ts";
import { Logger } from "../logger.ts";
import type { LatencyCheckResult, StreamRecord } from "../types.ts";
import { notificationService } from "./notification-service.ts";
import { openMetrics } from "./openmetrics-service.ts";

type StreamHealthState = "unknown" | "up" | "down";

const TICK_MS = 1_000;

function jitter(intervalMs: number): number {
	return Math.round(intervalMs * (0.9 + Math.random() * 0.2));
}

function settingsKey(stream: StreamRecord): string {
	return [
		stream.tcp_enabled,
		stream.origin_health_check_enabled,
		stream.forward_host,
		stream.forward_port,
		stream.origin_health_check_interval_seconds,
		stream.origin_health_check_timeout_ms,
	].join("\n");
}

function tcpConnectLatency(host: string, port: number, timeoutMs: number): Promise<LatencyCheckResult> {
	const startedAt = performance.now();
	return new Promise<LatencyCheckResult>((resolve) => {
		let settled = false;
		const finish = (result: LatencyCheckResult) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			resolve(result);
		};
		const timer = setTimeout(() => finish({ latencyMs: null, timedOut: true }), timeoutMs);
		(timer as unknown as { unref?: () => void }).unref?.();
		Bun.connect({
			hostname: host,
			port,
			socket: {
				open: (socket) => {
					finish({ latencyMs: performance.now() - startedAt, timedOut: false });
					socket.end();
				},
				data: () => {},
				close: () => {},
				error: () => finish({ latencyMs: null, timedOut: true }),
				connectError: () => finish({ latencyMs: null, timedOut: true }),
			},
		}).catch(() => finish({ latencyMs: null, timedOut: true }));
	});
}

interface RuntimeStreamHealth {
	stream: StreamRecord;
	nextCheckAt: number;
	running: boolean;
	settingsKey: string;
	consecutiveFailures: number;
	consecutiveSuccesses: number;
	state: StreamHealthState;
}

class StreamHealthManager {
	private readonly runtime = new Map<string, RuntimeStreamHealth>();
	private timer: ReturnType<typeof setInterval> | null = null;

	async initialize(): Promise<void> {
		for (const stream of await repository.allStreams()) this.setRuntimeStream(stream, false);
	}

	start(): void {
		if (this.timer) return;
		this.timer = setInterval(() => void this.tick(), TICK_MS);
		(this.timer as unknown as { unref?: () => void }).unref?.();
		void this.tick();
	}

	async refresh(streamId: string): Promise<void> {
		const stream = await repository.streamById(streamId);
		if (!stream) {
			this.remove(streamId);
			return;
		}
		this.setRuntimeStream(stream, true);
	}

	remove(streamId: string): void {
		this.runtime.delete(streamId);
	}

	private setRuntimeStream(stream: StreamRecord, immediate: boolean): void {
		const key = settingsKey(stream);
		const existing = this.runtime.get(stream.id);
		if (existing && existing.settingsKey === key) {
			existing.stream = stream;
			return;
		}
		const enabled = stream.tcp_enabled === 1 && stream.origin_health_check_enabled === 1;
		this.runtime.set(stream.id, {
			stream,
			nextCheckAt: enabled ? Date.now() + (immediate ? 0 : Math.round(Math.random() * 1_000)) : Number.POSITIVE_INFINITY,
			running: false,
			settingsKey: key,
			consecutiveFailures: 0,
			consecutiveSuccesses: 0,
			state: "unknown",
		});
	}

	/** Down on any transition into it; up only counts as a recovery once a prior down was reported. */
	private advanceState(runtime: RuntimeStreamHealth, result: LatencyCheckResult): "down" | "up" | null {
		const failureThreshold = Number(runtime.stream.origin_health_check_failure_threshold ?? 3);
		const recoveryThreshold = Number(runtime.stream.origin_health_check_recovery_threshold ?? 2);
		let next = runtime.state;
		if (result.timedOut) {
			runtime.consecutiveSuccesses = 0;
			runtime.consecutiveFailures += 1;
			if (runtime.consecutiveFailures >= failureThreshold) next = "down";
		} else {
			runtime.consecutiveFailures = 0;
			runtime.consecutiveSuccesses += 1;
			if (runtime.consecutiveSuccesses >= recoveryThreshold) next = "up";
		}
		if (next === runtime.state) return null;
		const previous = runtime.state;
		runtime.state = next;
		if (next === "down") return "down";
		if (next === "up" && previous === "down") return "up";
		return null;
	}

	private async tick(): Promise<void> {
		const now = Date.now();
		for (const runtime of this.runtime.values()) {
			if (runtime.running || runtime.nextCheckAt > now) continue;
			if (runtime.stream.tcp_enabled !== 1 || runtime.stream.origin_health_check_enabled !== 1) continue;
			void this.runCheck(runtime);
		}
	}

	private async runCheck(runtime: RuntimeStreamHealth): Promise<void> {
		runtime.running = true;
		try {
			const result = await tcpConnectLatency(runtime.stream.forward_host, runtime.stream.forward_port, Number(runtime.stream.origin_health_check_timeout_ms));
			openMetrics.recordStreamOriginHealthCheck(runtime.stream.id, result.timedOut, result.latencyMs ?? Number(runtime.stream.origin_health_check_timeout_ms));
			const bucketStart = Math.floor(Date.now() / 60_000) * 60_000;
			await repository.addStreamOriginLatencyResult(runtime.stream.id, bucketStart, result);
			const transition = this.advanceState(runtime, result);
			if (transition) {
				const down = transition === "down";
				const summary = down
					? `BurrowGate: origin for ${runtime.stream.name} is unreachable (${runtime.stream.forward_host}:${runtime.stream.forward_port}).`
					: `BurrowGate: origin for ${runtime.stream.name} recovered.`;
				await notificationService.recordStreamEvent(
					runtime.stream,
					down ? "stream_origin_unhealthy" : "stream_origin_recovered",
					down ? "critical" : "info",
					summary,
					{ incomingPort: runtime.stream.incoming_port, forwardHost: runtime.stream.forward_host, forwardPort: runtime.stream.forward_port },
					Date.now(),
				);
			}
		} catch (error) {
			Logger.error("Unable to persist stream origin latency check", { streamId: runtime.stream.id, error });
		} finally {
			runtime.running = false;
			runtime.nextCheckAt = Date.now() + jitter(Number(runtime.stream.origin_health_check_interval_seconds ?? 10) * 1_000);
		}
	}
}

export const streamHealthManager = new StreamHealthManager();
