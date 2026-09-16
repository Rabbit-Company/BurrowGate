import { isIP } from "node:net";
import { cidrContains, parseCidr, parseIp, type ParsedCidr } from "../utils/ip.ts";
import { canonicalIpv6 } from "./stream-proxy-protocol.ts";

const V1_PREFIX = Buffer.from("PROXY ");
const V2_SIGNATURE = Buffer.from("\r\n\r\n\0\r\nQUIT\n", "ascii");
export const MAX_PROXY_HEADER_BYTES = 4096;

export interface IncomingProxyConnection {
	sourceAddress: string;
	sourcePort: number;
	destinationAddress: string;
	destinationPort: number;
	proxyProtocol?: boolean;
}

export interface ParsedProxyHeader {
	bytes: number;
	connection: IncomingProxyConnection | null;
}

export function normalizeProxyAddress(address: string): string {
	const parsed = parseIp(address);
	if (parsed?.version === 6 && parsed.value >> 32n === 0xffffn) {
		return [24n, 16n, 8n, 0n].map((shift) => Number((parsed.value >> shift) & 255n)).join(".");
	}
	return address;
}

export function parseTrustedProxyCidrs(value: unknown): string[] {
	if (!Array.isArray(value) || value.length > 256) throw new Error("Trusted proxy addresses must be an array of at most 256 IP addresses or CIDRs");
	return [
		...new Set(
			value.map((entry) => {
				if (typeof entry !== "string" || !/^[^/]+(?:\/[0-9]{1,3})?$/u.test(entry.trim()) || !parseCidr(entry.trim())) {
					throw new Error(`Invalid trusted proxy IP address or CIDR: ${String(entry)}`);
				}
				return entry.trim();
			}),
		),
	];
}

export function isTrustedProxy(address: string, trusted: readonly ParsedCidr[]): boolean {
	return trusted.some((cidr) => cidrContains(cidr, address) || cidrContains(cidr, normalizeProxyAddress(address)));
}

function invalid(): never {
	throw new Error("Invalid incoming PROXY protocol header");
}

function port(value: string): number {
	if (!/^(?:0|[1-9]\d{0,4})$/u.test(value) || Number(value) > 65535) invalid();
	return Number(value);
}

function prefixMatches(data: Buffer, prefix: Buffer): boolean {
	return data.subarray(0, Math.min(data.length, prefix.length)).equals(prefix.subarray(0, Math.min(data.length, prefix.length)));
}

/** Detects a PROXY header prefix, including an incomplete prefix. */
export function isProxyHeaderPrefix(input: Uint8Array): boolean | null {
	const data = Buffer.from(input.buffer, input.byteOffset, input.byteLength);
	const v1 = prefixMatches(data, V1_PREFIX);
	const v2 = prefixMatches(data, V2_SIGNATURE);
	if (!v1 && !v2) return false;
	if ((v1 && data.length >= V1_PREFIX.length) || (v2 && data.length >= V2_SIGNATURE.length)) return true;
	return null;
}

/** Reads one PROXY header. Returns null for incomplete input and throws for invalid input. */
export function parseIncomingProxyHeader(input: Uint8Array): ParsedProxyHeader | null {
	const data = Buffer.from(input.buffer, input.byteOffset, input.byteLength);
	if (prefixMatches(data, V1_PREFIX)) {
		const end = data.indexOf("\r\n");
		if (end < 0) {
			if (data.length >= 107) invalid();
			return null;
		}
		if (end + 2 > 107) invalid();
		const line = data.subarray(0, end).toString("latin1");
		if (line === "PROXY UNKNOWN" || line.startsWith("PROXY UNKNOWN ")) return { bytes: end + 2, connection: null };
		const fields = line.split(" ");
		if (fields.length !== 6 || fields[0] !== "PROXY") invalid();
		const family = fields[1] === "TCP4" ? 4 : fields[1] === "TCP6" ? 6 : invalid();
		if (isIP(fields[2]!) !== family || isIP(fields[3]!) !== family) invalid();
		return {
			bytes: end + 2,
			connection: {
				sourceAddress: fields[2]!,
				destinationAddress: fields[3]!,
				sourcePort: port(fields[4]!),
				destinationPort: port(fields[5]!),
			},
		};
	}
	if (!prefixMatches(data, V2_SIGNATURE)) invalid();
	if (data.length < 16) return null;
	if (data[12]! >> 4 !== 2) invalid();
	const command = data[12]! & 15;
	if (command !== 0 && command !== 1) invalid();
	const length = data.readUInt16BE(14);
	const bytes = 16 + length;
	if (bytes > MAX_PROXY_HEADER_BYTES) invalid();
	if (data.length < bytes) return null;
	if (command === 0) return { bytes, connection: null }; // LOCAL uses the socket address.
	const family = data[13]!;
	if (family === 0) return { bytes, connection: null }; // UNSPEC
	const addressLength = family === 0x11 ? 4 : family === 0x21 ? 16 : invalid();
	const addressBlockLength = addressLength * 2 + 4;
	if (length < addressBlockLength) invalid();
	// Check TLV lengths before skipping extensions.
	for (let offset = 16 + addressBlockLength; offset < bytes; ) {
		if (offset + 3 > bytes) invalid();
		offset += 3 + data.readUInt16BE(offset + 1);
		if (offset > bytes) invalid();
	}
	const address = (offset: number): string => {
		if (addressLength === 4) return [...data.subarray(offset, offset + 4)].join(".");
		let value = 0n;
		for (const byte of data.subarray(offset, offset + 16)) value = (value << 8n) | BigInt(byte);
		return canonicalIpv6(value);
	};
	return {
		bytes,
		connection: {
			sourceAddress: address(16),
			destinationAddress: address(16 + addressLength),
			sourcePort: data.readUInt16BE(16 + addressLength * 2),
			destinationPort: data.readUInt16BE(18 + addressLength * 2),
		},
	};
}

const requestConnections = new WeakMap<Request, IncomingProxyConnection>();
export function setIncomingProxyConnection(request: Request, connection: IncomingProxyConnection): void {
	requestConnections.set(request, connection);
}
export function incomingProxyConnection(request: Request): IncomingProxyConnection | undefined {
	return requestConnections.get(request);
}
