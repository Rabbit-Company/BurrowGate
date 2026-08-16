import { config } from "../config.ts";
import { repository } from "../db/repository.ts";
import { Logger } from "../logger.ts";
import type { LatencyCheckResult } from "../types.ts";
import { openMetrics } from "./openmetrics-service.ts";

const DNS_PORT = 53;
// A name under the IANA-reserved .invalid TLD (RFC 2606) so every resolver answers locally
// (NXDOMAIN or REFUSED) without recursing upstream - the reply, not its content, is the signal.
const PROBE_QUESTION_NAME = "burrowgate-connectivity-check.invalid";

function buildDnsQuery(transactionId: number): Uint8Array {
	const labels = PROBE_QUESTION_NAME.split(".");
	let questionLength = 1;
	for (const label of labels) questionLength += 1 + label.length;
	const buffer = new Uint8Array(12 + questionLength + 4);
	const view = new DataView(buffer.buffer);
	view.setUint16(0, transactionId, false);
	view.setUint16(2, 0x0100, false);
	view.setUint16(4, 1, false);
	let offset = 12;
	for (const label of labels) {
		buffer[offset] = label.length;
		offset += 1;
		for (let index = 0; index < label.length; index += 1) buffer[offset + index] = label.charCodeAt(index);
		offset += label.length;
	}
	buffer[offset] = 0;
	offset += 1;
	view.setUint16(offset, 1, false);
	offset += 2;
	view.setUint16(offset, 1, false);
	return buffer;
}

function jitter(intervalMs: number): number {
	return Math.round(intervalMs * (0.9 + Math.random() * 0.2));
}

async function pingTarget(target: string, timeoutMs: number): Promise<LatencyCheckResult> {
	const transactionId = Math.floor(Math.random() * 0xffff);
	const query = buildDnsQuery(transactionId);
	const startedAt = performance.now();
	return await new Promise<LatencyCheckResult>((resolve) => {
		let settled = false;
		let socket: { close(): void; send(data: Uint8Array): boolean } | null = null;
		const finish = (result: LatencyCheckResult) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			socket?.close();
			resolve(result);
		};
		const timer = setTimeout(() => finish({ latencyMs: null, timedOut: true }), timeoutMs);
		(timer as unknown as { unref?: () => void }).unref?.();
		Bun.udpSocket({
			binaryType: "buffer",
			connect: { hostname: target, port: DNS_PORT },
			socket: {
				data: (_socket, data) => {
					if (data.byteLength < 2) return;
					const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
					if (view.getUint16(0, false) !== transactionId) return;
					finish({ latencyMs: performance.now() - startedAt, timedOut: false });
				},
				error: () => finish({ latencyMs: null, timedOut: true }),
			},
		})
			.then((created) => {
				socket = created;
				if (settled) {
					created.close();
					return;
				}
				created.send(query);
			})
			.catch(() => finish({ latencyMs: null, timedOut: true }));
	});
}

interface TargetState {
	target: string;
	nextCheckAt: number;
	running: boolean;
}

class ConnectivityMonitor {
	private readonly targets = new Map<string, TargetState>();
	private timer: ReturnType<typeof setInterval> | null = null;

	start(): void {
		if (this.timer || !config.connectivityMonitor.enabled) return;
		for (const target of config.connectivityMonitor.targets) {
			this.targets.set(target, { target, nextCheckAt: Date.now() + Math.round(Math.random() * 1_000), running: false });
		}
		this.timer = setInterval(() => void this.tick(), 1_000);
		(this.timer as unknown as { unref?: () => void }).unref?.();
		void this.tick();
	}

	private async tick(): Promise<void> {
		const now = Date.now();
		for (const state of this.targets.values()) {
			if (state.running || state.nextCheckAt > now) continue;
			void this.check(state);
		}
	}

	private async check(state: TargetState): Promise<void> {
		state.running = true;
		try {
			const result = await pingTarget(state.target, config.connectivityMonitor.timeoutMs);
			openMetrics.recordConnectivityPing(state.target, result.timedOut, result.latencyMs ?? config.connectivityMonitor.timeoutMs);
			const bucketStart = Math.floor(Date.now() / 60_000) * 60_000;
			await repository.addConnectivityPingResult(state.target, bucketStart, result);
		} catch (error) {
			Logger.error("[BurrowGate] Unable to persist connectivity ping result", { target: state.target, error });
		} finally {
			state.running = false;
			state.nextCheckAt = Date.now() + jitter(config.connectivityMonitor.intervalSeconds * 1_000);
		}
	}
}

export const connectivityMonitor = new ConnectivityMonitor();
