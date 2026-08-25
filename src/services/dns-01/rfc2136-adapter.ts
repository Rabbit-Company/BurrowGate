import { fromBase64, hmacSha256Raw, randomToken } from "../../utils/crypto.ts";
import { decryptSecret } from "../secret-encryption-service.ts";

const DEFAULT_DNS_PORT = 53;
const DEFAULT_TTL_SECONDS = 120;
const DEFAULT_PROPAGATION_SECONDS = 30;
const TSIG_FUDGE_SECONDS = 300;
const TCP_RESPONSE_TIMEOUT_MS = 10_000;
const TSIG_ALGORITHM_NAME = "hmac-sha256.";

export interface Rfc2136ProviderConfig {
	server: string;
	port: number;
	zone: string;
	tsigKeyName: string;
	tsigAlgorithm: "hmac-sha256";
	tsigSecretEncrypted: string;
	propagationSeconds: number;
}
export function normalizeDnsName(value: string): string {
	const trimmed = value.trim().toLowerCase();
	if (!trimmed) return "";
	return trimmed.endsWith(".") ? trimmed : `${trimmed}.`;
}

export function parseRfc2136ProviderConfig(value: unknown): Rfc2136ProviderConfig {
	const raw = (value ?? {}) as Record<string, unknown>;
	const port = Number(raw.port);
	const propagationSeconds = Number(raw.propagationSeconds);
	return {
		server: typeof raw.server === "string" ? raw.server.trim() : "",
		port: Number.isFinite(port) && port > 0 && port <= 65_535 ? Math.trunc(port) : DEFAULT_DNS_PORT,
		zone: typeof raw.zone === "string" ? normalizeDnsName(raw.zone) : "",
		tsigKeyName: typeof raw.tsigKeyName === "string" ? normalizeDnsName(raw.tsigKeyName) : "",
		tsigAlgorithm: "hmac-sha256",
		tsigSecretEncrypted: typeof raw.tsigSecretEncrypted === "string" ? raw.tsigSecretEncrypted : "",
		propagationSeconds: Number.isFinite(propagationSeconds) && propagationSeconds >= 0 ? Math.trunc(propagationSeconds) : DEFAULT_PROPAGATION_SECONDS,
	};
}

// DNS wire format

const textEncoder = new TextEncoder();

/** Same Buffer-based binary assembly the Proxy Protocol header builder uses (src/services/stream-proxy-protocol.ts) - one idiom for wire-format encoding across the codebase. */
function concatBytes(parts: Uint8Array[]): Uint8Array {
	return Buffer.concat(parts.map((part) => Buffer.from(part.buffer, part.byteOffset, part.length)));
}

class DnsWriter {
	private readonly chunks: Buffer[] = [];

	uint8(value: number): this {
		const buffer = Buffer.alloc(1);
		buffer.writeUInt8(value & 0xff);
		this.chunks.push(buffer);
		return this;
	}

	uint16(value: number): this {
		const buffer = Buffer.alloc(2);
		buffer.writeUInt16BE(value & 0xffff);
		this.chunks.push(buffer);
		return this;
	}

	uint32(value: number): this {
		const buffer = Buffer.alloc(4);
		buffer.writeUInt32BE(value >>> 0);
		this.chunks.push(buffer);
		return this;
	}

	/** RFC 2845's Time Signed field is a 48-bit unsigned integer - past uint32 range but within what writeUIntBE supports directly. */
	uint48(value: number): this {
		const buffer = Buffer.alloc(6);
		buffer.writeUIntBE(value, 0, 6);
		this.chunks.push(buffer);
		return this;
	}

	bytes(value: Uint8Array): this {
		this.chunks.push(Buffer.from(value));
		return this;
	}

	toBytes(): Uint8Array {
		return Buffer.concat(this.chunks);
	}
}

/** RFC 1035 §3.1 wire encoding: length-prefixed labels terminated by a zero-length label. Accepts a name with or without a trailing dot. */
export function encodeDomainName(name: string): Uint8Array {
	const trimmed = name.endsWith(".") ? name.slice(0, -1) : name;
	const labels = trimmed.length === 0 ? [] : trimmed.split(".");
	const writer = new DnsWriter();
	for (const label of labels) {
		const bytes = textEncoder.encode(label);
		if (bytes.length === 0 || bytes.length > 63) throw new Error(`Invalid DNS label: "${label}"`);
		writer.uint8(bytes.length).bytes(bytes);
	}
	writer.uint8(0);
	return writer.toBytes();
}

/** QR=0, OPCODE=5 (UPDATE), all other header bits 0 - see RFC 2136 §2.2. */
const UPDATE_REQUEST_FLAGS = 0x2800;

function encodeHeader(id: number, zoCount: number, prCount: number, upCount: number, arCount: number): Uint8Array {
	return new DnsWriter().uint16(id).uint16(UPDATE_REQUEST_FLAGS).uint16(zoCount).uint16(prCount).uint16(upCount).uint16(arCount).toBytes();
}

/** RFC 2136 §2.3: the Zone Section identifies the zone being updated via a single SOA/IN entry (not an actual SOA query). */
function encodeZoneSection(zone: string): Uint8Array {
	return new DnsWriter().bytes(encodeDomainName(zone)).uint16(6).uint16(1).toBytes();
}

function encodeTxtRdata(value: string): Uint8Array {
	const bytes = textEncoder.encode(value);
	if (bytes.length > 255) throw new Error("TXT record value exceeds 255 bytes");
	return new DnsWriter().uint8(bytes.length).bytes(bytes).toBytes();
}

export type UpdateOperation = { kind: "add"; name: string; ttl: number; value: string } | { kind: "delete-rr"; name: string; value: string };

const TXT_TYPE = 16;
const CLASS_IN = 1;
/** RFC 2136 §2.5.4 "Delete An RR From An RRset" overloads CLASS=NONE to mean "remove exactly this RR" (as opposed to CLASS=ANY, which deletes the whole RRset regardless of RDATA). */
const CLASS_NONE = 254;

function encodeUpdateRR(operation: UpdateOperation): Uint8Array {
	const rdata = encodeTxtRdata(operation.value);
	return new DnsWriter()
		.bytes(encodeDomainName(operation.name))
		.uint16(TXT_TYPE)
		.uint16(operation.kind === "add" ? CLASS_IN : CLASS_NONE)
		.uint32(operation.kind === "add" ? operation.ttl : 0)
		.uint16(rdata.length)
		.bytes(rdata)
		.toBytes();
}

export interface EncodeUpdateMessageInput {
	id: number;
	zone: string;
	operations: UpdateOperation[];
}

/** Builds an RFC 2136 UPDATE message with no prerequisites: header, zone section, then one RR per operation in the Update section. */
export function encodeUpdateMessage(input: EncodeUpdateMessageInput): Uint8Array {
	const header = encodeHeader(input.id, 1, 0, input.operations.length, 0);
	const zoneSection = encodeZoneSection(input.zone);
	return concatBytes([header, zoneSection, ...input.operations.map(encodeUpdateRR)]);
}

// TSIG signing (RFC 2845)

export interface TsigKey {
	name: string;
	secret: Uint8Array;
	algorithm: "hmac-sha256";
}

/** RFC 2845 §3.4.2 "TSIG Variables": the fields MACed alongside the message, in this exact order. */
function encodeTsigVariables(key: TsigKey, timeSigned: number, fudge: number): Uint8Array {
	return new DnsWriter()
		.bytes(encodeDomainName(key.name))
		.uint16(255) // CLASS ANY
		.uint32(0) // TTL
		.bytes(encodeDomainName(TSIG_ALGORITHM_NAME))
		.uint48(timeSigned)
		.uint16(fudge)
		.uint16(0) // Error
		.uint16(0) // Other Len
		.toBytes();
}

/**
 * Appends a signed TSIG additional record per RFC 2845 §3. The MAC covers the message exactly as sent - before the
 * TSIG RR is appended and before ARCOUNT is incremented - concatenated with the TSIG Variables.
 */
export async function signWithTsig(message: Uint8Array, key: TsigKey, options?: { timeSigned?: number; fudge?: number }): Promise<Uint8Array> {
	const timeSigned = options?.timeSigned ?? Math.floor(Date.now() / 1_000);
	const fudge = options?.fudge ?? TSIG_FUDGE_SECONDS;
	const macData = concatBytes([message, encodeTsigVariables(key, timeSigned, fudge)]);
	const mac = await hmacSha256Raw(key.secret, macData);
	const originalId = ((message[0] ?? 0) << 8) | (message[1] ?? 0);

	const rdata = concatBytes([
		encodeDomainName(TSIG_ALGORITHM_NAME),
		new DnsWriter().uint48(timeSigned).uint16(fudge).uint16(mac.length).toBytes(),
		mac,
		new DnsWriter().uint16(originalId).uint16(0).uint16(0).toBytes(), // Original ID, Error, Other Len
	]);
	const tsigRR = concatBytes([encodeDomainName(key.name), new DnsWriter().uint16(250).uint16(255).uint32(0).uint16(rdata.length).toBytes(), rdata]);

	const signed = concatBytes([message, tsigRR]);
	const arCount = (((signed[10] ?? 0) << 8) | (signed[11] ?? 0)) + 1;
	signed[10] = (arCount >>> 8) & 0xff;
	signed[11] = arCount & 0xff;
	return signed;
}

// RCODE decoding

const RCODE_NAMES: Record<number, string> = {
	0: "NOERROR",
	1: "FORMERR",
	2: "SERVFAIL",
	3: "NXDOMAIN",
	4: "NOTIMP",
	5: "REFUSED",
	6: "YXDOMAIN",
	7: "YXRRSET",
	8: "NXRRSET",
	9: "NOTAUTH",
	10: "NOTZONE",
};

export function rcodeName(code: number): string {
	return RCODE_NAMES[code] ?? `RCODE ${code}`;
}

export function responseRcode(response: Uint8Array): number {
	if (response.length < 12) throw new Error("DNS response is shorter than a header");
	return (response[3] ?? 0) & 0x0f;
}

interface SendUpdateDependencies {
	connect?: (options: Parameters<typeof Bun.connect>[0]) => ReturnType<typeof Bun.connect>;
}

/**
 * TCP (not UDP) so a single signed request/response round trip needs no retry/duplicate-detection logic, and isn't
 * subject to the 512-byte unextended UDP message size limit some older nameservers still enforce.
 */
export async function sendUpdateOverTcp(
	server: string,
	port: number,
	message: Uint8Array,
	timeoutMs = TCP_RESPONSE_TIMEOUT_MS,
	deps: SendUpdateDependencies = {},
): Promise<Uint8Array> {
	const connect = deps.connect ?? ((options: Parameters<typeof Bun.connect>[0]) => Bun.connect(options));
	return await new Promise<Uint8Array>((resolve, reject) => {
		let settled = false;
		let received: Uint8Array = new Uint8Array(0);
		let expectedLength: number | null = null;
		let socketRef: { end: () => void; terminate: () => void } | undefined;

		const timer = setTimeout(() => {
			finish(() => reject(new Error(`Timed out waiting for a response from ${server}:${port}`)));
			socketRef?.terminate();
		}, timeoutMs);
		(timer as unknown as { unref?: () => void }).unref?.();

		function finish(action: () => void): void {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			action();
		}

		const framed = new Uint8Array(2 + message.length);
		framed[0] = (message.length >>> 8) & 0xff;
		framed[1] = message.length & 0xff;
		framed.set(message, 2);

		connect({
			hostname: server,
			port,
			socket: {
				open: (socket: { write: (data: Uint8Array) => void }) => {
					socketRef = socket as unknown as { end: () => void; terminate: () => void };
					socket.write(framed);
				},
				data: (socket: { end: () => void }, chunk: Uint8Array) => {
					received = concatBytes([received, new Uint8Array(chunk)]);
					if (expectedLength === null && received.length >= 2) expectedLength = ((received[0] ?? 0) << 8) + (received[1] ?? 0) + 2;
					if (expectedLength !== null && received.length >= expectedLength) {
						const body = received.slice(2, expectedLength);
						finish(() => resolve(body));
						socket.end();
					}
				},
				error: (_socket: unknown, error: unknown) => finish(() => reject(error instanceof Error ? error : new Error(String(error)))),
				connectError: (_socket: unknown, error: unknown) => finish(() => reject(error instanceof Error ? error : new Error(String(error)))),
				close: () => finish(() => reject(new Error(`Connection to ${server}:${port} closed before a complete response was received`))),
			},
		} as never).catch((error: unknown) => finish(() => reject(error instanceof Error ? error : new Error(String(error)))));
	});
}

function randomDnsId(): number {
	const bytes = crypto.getRandomValues(new Uint8Array(2));
	return ((bytes[0] ?? 0) << 8) | (bytes[1] ?? 0);
}

async function sendSignedUpdate(cfg: Rfc2136ProviderConfig, operations: UpdateOperation[]): Promise<void> {
	if (!cfg.server) throw new Error("DNS server is required");
	if (!cfg.zone) throw new Error("Zone is required");
	if (!cfg.tsigKeyName) throw new Error("TSIG key name is required");
	if (!cfg.tsigSecretEncrypted) throw new Error("TSIG secret is required");
	const secretBase64 = await decryptSecret(cfg.tsigSecretEncrypted);
	const key: TsigKey = { name: cfg.tsigKeyName, secret: fromBase64(secretBase64), algorithm: "hmac-sha256" };
	const message = encodeUpdateMessage({ id: randomDnsId(), zone: cfg.zone, operations });
	const signed = await signWithTsig(message, key);
	const response = await sendUpdateOverTcp(cfg.server, cfg.port, signed);
	const rcode = responseRcode(response);
	if (rcode !== 0) throw new Error(`${cfg.server}:${cfg.port} rejected the DNS update: ${rcodeName(rcode)}`);
}

export async function rfc2136CreateTxtRecord(configJson: string, recordName: string, value: string): Promise<void> {
	const cfg = parseRfc2136ProviderConfig(JSON.parse(configJson));
	await sendSignedUpdate(cfg, [{ kind: "add", name: recordName, ttl: DEFAULT_TTL_SECONDS, value }]);
	if (cfg.propagationSeconds > 0) await Bun.sleep(cfg.propagationSeconds * 1_000);
}

export async function rfc2136DeleteTxtRecord(configJson: string, recordName: string, value: string): Promise<void> {
	const cfg = parseRfc2136ProviderConfig(JSON.parse(configJson));
	await sendSignedUpdate(cfg, [{ kind: "delete-rr", name: recordName, value }]);
}

export async function rfc2136TestConnection(configJson: string): Promise<{ ok: boolean; message: string }> {
	const cfg = parseRfc2136ProviderConfig(JSON.parse(configJson));
	const probeName = `_burrowgate-test.${cfg.zone}`;
	const probeValue = randomToken(12);
	try {
		await sendSignedUpdate(cfg, [{ kind: "add", name: probeName, ttl: 30, value: probeValue }]);
		await sendSignedUpdate(cfg, [{ kind: "delete-rr", name: probeName, value: probeValue }]);
		return { ok: true, message: `Connected. ${cfg.server}:${cfg.port} accepted a signed update for zone ${cfg.zone}.` };
	} catch (error) {
		return { ok: false, message: error instanceof Error ? error.message : String(error) };
	}
}
