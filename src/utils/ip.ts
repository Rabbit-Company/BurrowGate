import { isIP } from "node:net";

export interface ParsedCidr {
	version: 4 | 6;
	network: bigint;
	prefix: number;
	bits: number;
}

function parseIpv4(ip: string): bigint | null {
	const parts = ip.split(".");
	if (parts.length !== 4) return null;
	let result = 0n;
	for (const part of parts) {
		if (!/^\d{1,3}$/u.test(part)) return null;
		const value = Number(part);
		if (value < 0 || value > 255) return null;
		result = (result << 8n) | BigInt(value);
	}
	return result;
}

function parseIpv6(ip: string): bigint | null {
	let normalized = ip.toLowerCase();
	const zoneIndex = normalized.indexOf("%");
	if (zoneIndex >= 0) normalized = normalized.slice(0, zoneIndex);

	if (normalized.includes(".")) {
		const lastColon = normalized.lastIndexOf(":");
		const ipv4 = parseIpv4(normalized.slice(lastColon + 1));
		if (lastColon < 0 || ipv4 === null) return null;
		const high = Number((ipv4 >> 16n) & 0xffffn).toString(16);
		const low = Number(ipv4 & 0xffffn).toString(16);
		normalized = `${normalized.slice(0, lastColon)}:${high}:${low}`;
	}

	const halves = normalized.split("::");
	if (halves.length > 2) return null;
	const left = halves[0] ? halves[0].split(":") : [];
	const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
	const missing = 8 - left.length - right.length;
	if ((halves.length === 1 && missing !== 0) || missing < 0) return null;
	const groups = [...left, ...Array.from({ length: missing }, () => "0"), ...right];
	if (groups.length !== 8) return null;

	let result = 0n;
	for (const group of groups) {
		if (!/^[0-9a-f]{1,4}$/u.test(group)) return null;
		result = (result << 16n) | BigInt(`0x${group}`);
	}
	return result;
}

export function parseIp(ip: string): { version: 4 | 6; value: bigint; bits: number } | null {
	const version = isIP(ip);
	if (version === 4) {
		const value = parseIpv4(ip);
		return value === null ? null : { version: 4, value, bits: 32 };
	}
	if (version === 6) {
		const value = parseIpv6(ip);
		return value === null ? null : { version: 6, value, bits: 128 };
	}
	return null;
}

export function parseCidr(input: string): ParsedCidr | null {
	const [address, prefixText] = input.trim().split("/");
	if (!address) return null;
	const parsed = parseIp(address);
	if (!parsed) return null;
	const prefix = prefixText === undefined ? parsed.bits : Number(prefixText);
	if (!Number.isInteger(prefix) || prefix < 0 || prefix > parsed.bits) return null;
	const shift = BigInt(parsed.bits - prefix);
	const network = shift === 0n ? parsed.value : (parsed.value >> shift) << shift;
	return { version: parsed.version, network, prefix, bits: parsed.bits };
}

export function cidrContains(cidr: ParsedCidr | string, ip: string): boolean {
	const parsedCidr = typeof cidr === "string" ? parseCidr(cidr) : cidr;
	const parsedIp = parseIp(ip);
	if (!parsedCidr || !parsedIp || parsedCidr.version !== parsedIp.version) return false;
	const shift = BigInt(parsedCidr.bits - parsedCidr.prefix);
	const network = shift === 0n ? parsedIp.value : (parsedIp.value >> shift) << shift;
	return network === parsedCidr.network;
}
