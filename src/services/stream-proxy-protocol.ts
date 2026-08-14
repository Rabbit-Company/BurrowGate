import type { StreamProtocol, StreamProxyProtocol } from "../types.ts";
import { parseIp } from "../utils/ip.ts";

const V2_SIGNATURE = Buffer.from([0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a]);

export interface ProxyProtocolEndpoints {
	sourceAddress: string;
	destinationAddress: string;
	sourcePort: number;
	destinationPort: number;
}

function validPort(value: number, label: string): number {
	if (!Number.isInteger(value) || value < 0 || value > 65_535) throw new Error(`${label} must be an integer from 0 to 65535`);
	return value;
}

function addressBytes(value: bigint, byteLength: number): Buffer {
	const result = Buffer.alloc(byteLength);
	let remaining = value;
	for (let index = byteLength - 1; index >= 0; index -= 1) {
		result[index] = Number(remaining & 0xffn);
		remaining >>= 8n;
	}
	return result;
}

function canonicalIpv6(value: bigint): string {
	const groups: number[] = [];
	for (let shift = 112n; shift >= 0n; shift -= 16n) groups.push(Number((value >> shift) & 0xffffn));
	let bestStart = -1;
	let bestLength = 0;
	for (let index = 0; index < groups.length; ) {
		if (groups[index] !== 0) {
			index += 1;
			continue;
		}
		let end = index + 1;
		while (end < groups.length && groups[end] === 0) end += 1;
		if (end - index > bestLength) {
			bestStart = index;
			bestLength = end - index;
		}
		index = end;
	}
	if (bestLength < 2) return groups.map((group) => group.toString(16)).join(":");
	const left = groups
		.slice(0, bestStart)
		.map((group) => group.toString(16))
		.join(":");
	const right = groups
		.slice(bestStart + bestLength)
		.map((group) => group.toString(16))
		.join(":");
	return `${left}::${right}`;
}

function endpoints(endpoints: ProxyProtocolEndpoints) {
	const source = parseIp(endpoints.sourceAddress);
	const destination = parseIp(endpoints.destinationAddress);
	if (!source) throw new Error(`Unable to encode invalid PROXY protocol source address: ${endpoints.sourceAddress}`);
	if (!destination) throw new Error(`Unable to encode invalid PROXY protocol destination address: ${endpoints.destinationAddress}`);
	if (source.version !== destination.version) throw new Error("PROXY protocol source and destination address families must match");
	return {
		source,
		destination,
		sourcePort: validPort(endpoints.sourcePort, "PROXY protocol source port"),
		destinationPort: validPort(endpoints.destinationPort, "PROXY protocol destination port"),
	};
}

export function proxyProtocolHeader(mode: Exclude<StreamProxyProtocol, "disabled">, transport: StreamProtocol, input: ProxyProtocolEndpoints): Buffer {
	const resolved = endpoints(input);
	if (mode === "v1") {
		if (transport !== "tcp") throw new Error("PROXY protocol v1 does not support UDP");
		const sourceAddress = resolved.source.version === 4 ? input.sourceAddress : canonicalIpv6(resolved.source.value);
		const destinationAddress = resolved.destination.version === 4 ? input.destinationAddress : canonicalIpv6(resolved.destination.value);
		return Buffer.from(
			`PROXY TCP${resolved.source.version} ${sourceAddress} ${destinationAddress} ${resolved.sourcePort} ${resolved.destinationPort}\r\n`,
			"ascii",
		);
	}

	const addressLength = resolved.source.version === 4 ? 4 : 16;
	const addressBlock = Buffer.alloc(addressLength * 2 + 4);
	addressBytes(resolved.source.value, addressLength).copy(addressBlock, 0);
	addressBytes(resolved.destination.value, addressLength).copy(addressBlock, addressLength);
	addressBlock.writeUInt16BE(resolved.sourcePort, addressLength * 2);
	addressBlock.writeUInt16BE(resolved.destinationPort, addressLength * 2 + 2);
	const family = resolved.source.version === 4 ? 0x10 : 0x20;
	const protocol = transport === "tcp" ? 0x01 : 0x02;
	const fixedHeader = Buffer.alloc(4);
	fixedHeader[0] = 0x21; // Version 2, PROXY command.
	fixedHeader[1] = family | protocol;
	fixedHeader.writeUInt16BE(addressBlock.byteLength, 2);
	return Buffer.concat([V2_SIGNATURE, fixedHeader, addressBlock]);
}

export function proxyProtocolDatagram(header: Uint8Array, payload: Uint8Array): Buffer {
	return Buffer.concat([header, payload]);
}
