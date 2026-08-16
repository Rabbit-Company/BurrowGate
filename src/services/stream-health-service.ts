import { repository } from "../db/repository.ts";
import { Logger } from "../logger.ts";
import type { LatencyCheckResult, StreamRecord } from "../types.ts";
import { openMetrics } from "./openmetrics-service.ts";

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
		});
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
		} catch (error) {
			Logger.error("[BurrowGate] Unable to persist stream origin latency check", { streamId: runtime.stream.id, error });
		} finally {
			runtime.running = false;
			runtime.nextCheckAt = Date.now() + jitter(Number(runtime.stream.origin_health_check_interval_seconds ?? 10) * 1_000);
		}
	}
}

export const streamHealthManager = new StreamHealthManager();
