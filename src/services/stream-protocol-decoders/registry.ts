import type { StreamRuleFieldValue } from "../stream-protection-service.ts";

export interface StreamDecodeAttempt {
	/** "incomplete" means call decode() again once more bytes have arrived. "done" means stop buffering now. */
	status: "incomplete" | "done";
	fields: Record<string, StreamRuleFieldValue>;
}

export interface StreamProtocolDecoder {
	protocol: string;
	decode(buffer: Uint8Array): StreamDecodeAttempt;
}

const decoders = new Map<string, StreamProtocolDecoder>();

export function registerStreamProtocolDecoder(decoder: StreamProtocolDecoder): void {
	decoders.set(decoder.protocol, decoder);
}

export function streamProtocolDecoder(protocol: string): StreamProtocolDecoder | null {
	return decoders.get(protocol) ?? null;
}
