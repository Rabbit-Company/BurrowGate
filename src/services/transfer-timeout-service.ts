import { config } from "../config.ts";
import { Logger } from "../logger.ts";
import type { ConnectionControl } from "./connection-control-service.ts";

export class RequestBodyTimeoutError extends Error {
	constructor() {
		super("The client sent the request body too slowly");
		this.name = "RequestBodyTimeoutError";
	}
}

export class RequestBodyIncompleteError extends Error {
	constructor(
		readonly expectedBytes: number,
		readonly receivedBytes: number,
	) {
		super(`The request body ended after ${receivedBytes} of ${expectedBytes} declared bytes`);
		this.name = "RequestBodyIncompleteError";
	}
}

export class UploadDeadline {
	private readonly startedAt = Date.now();
	private lastActivityAt = this.startedAt;
	private receivedBytes = 0;
	private timer: ReturnType<typeof setTimeout> | null = null;
	private finished = false;

	constructor(private readonly onExpire: () => void) {
		this.arm();
	}

	received(bytes: number): void {
		if (this.finished) return;
		this.receivedBytes += bytes;
		this.lastActivityAt = Date.now();
		this.arm();
	}

	stop(): void {
		this.finished = true;
		if (this.timer) clearTimeout(this.timer);
		this.timer = null;
	}

	private arm(): void {
		if (this.timer) clearTimeout(this.timer);
		const idleDeadline = this.lastActivityAt + config.client.timeoutMs;
		const rateDeadline = this.startedAt + config.client.timeoutMs + (this.receivedBytes * 1_000) / config.client.minRateBytesPerSecond;
		this.timer = setTimeout(
			() => {
				this.stop();
				this.onExpire();
			},
			Math.max(0, Math.min(idleDeadline, rateDeadline) - Date.now()),
		);
		this.timer.unref?.();
	}
}

export async function readBodyWithinDeadline(request: Request, expectedBytes: number, control: ConnectionControl | null): Promise<Uint8Array> {
	const reader = request.body!.getReader();
	const chunks: Uint8Array[] = [];
	let total = 0;
	let expired = false;
	let rejectTimeout: (error: Error) => void = () => {};
	const timedOut = new Promise<never>((_, reject) => (rejectTimeout = reject));
	timedOut.catch(() => {});
	const deadline = new UploadDeadline(() => {
		expired = true;
		rejectTimeout(new RequestBodyTimeoutError());
		control?.abort();
		void reader.cancel().catch(() => {});
	});
	try {
		for (;;) {
			const reading = reader.read();
			reading.catch(() => {});
			const { done, value } = await Promise.race([reading, timedOut]);
			if (expired) throw new RequestBodyTimeoutError();
			if (done) break;
			chunks.push(value);
			total += value.byteLength;
			deadline.received(value.byteLength);
		}
	} finally {
		deadline.stop();
	}
	if (expired) throw new RequestBodyTimeoutError();
	if (total < expectedBytes) throw new RequestBodyIncompleteError(expectedBytes, total);
	const body = new Uint8Array(total);
	let offset = 0;
	for (const chunk of chunks) {
		body.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return body;
}

export interface GuardedBodyContext {
	control: ConnectionControl | null;
	abortOrigin: (reason: unknown) => void;
	originIdleMs: number;
	describe: Record<string, unknown>;
}

export function guardResponseBody(body: ReadableStream<Uint8Array>, context: GuardedBodyContext): ReadableStream<Uint8Array> {
	const reader = body.getReader();
	let originTimer: ReturnType<typeof setTimeout> | null = null;
	let clientTimer: ReturnType<typeof setTimeout> | null = null;
	let streamController: ReadableStreamDefaultController<Uint8Array> | null = null;
	let closing = false;
	const clearTimers = () => {
		if (originTimer) clearTimeout(originTimer);
		if (clientTimer) clearTimeout(clientTimer);
		originTimer = null;
		clientTimer = null;
	};
	const closeConnection = (error: unknown) => {
		if (closing) return;
		closing = true;
		clearTimers();
		context.abortOrigin(error);
		if (!context.control?.abort()) streamController?.error(error);
	};
	const never = () => new Promise<void>(() => {});
	return new ReadableStream<Uint8Array>(
		{
			start(controller) {
				streamController = controller;
			},
			async pull(controller) {
				if (clientTimer) clearTimeout(clientTimer);
				clientTimer = null;
				if (closing) return await never();
				originTimer = setTimeout(() => {
					Logger.warn("Origin stopped sending the response body; closing the connection", { ...context.describe, idleMs: context.originIdleMs });
					closeConnection(new DOMException("The origin stopped sending the response body", "TimeoutError"));
				}, context.originIdleMs);
				originTimer.unref?.();
				let result: Awaited<ReturnType<typeof reader.read>>;
				try {
					result = await reader.read();
				} catch (error) {
					if (!closing) {
						Logger.warn("Origin response body failed; closing the connection", { ...context.describe, error });
						closeConnection(error);
					}
					return await never();
				} finally {
					if (originTimer) clearTimeout(originTimer);
					originTimer = null;
				}
				if (closing) return await never();
				if (result.done) {
					controller.close();
					return;
				}
				controller.enqueue(result.value);
				clientTimer = setTimeout(
					() => {
						Logger.debug("Closing a connection whose client read the response too slowly", context.describe);
						closeConnection(new Error("The client read the response too slowly"));
					},
					config.client.timeoutMs + (result.value.byteLength * 1_000) / config.client.minRateBytesPerSecond,
				);
				clientTimer.unref?.();
			},
			cancel(reason) {
				closing = true;
				clearTimers();
				void reader.cancel(reason).catch(() => {});
				context.abortOrigin(reason);
			},
		},
		{ highWaterMark: 0 },
	);
}
