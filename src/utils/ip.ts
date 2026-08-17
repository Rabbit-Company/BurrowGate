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

const PRIVATE_CIDRS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10"];

function ipv4FromMapped(value: bigint): string | null {
	if (value >> 32n !== 0xffffn) return null;
	const ipv4 = value & 0xffffffffn;
	return [24n, 16n, 8n, 0n].map((shift) => Number((ipv4 >> shift) & 0xffn)).join(".");
}

export function isPrivateIp(ip: string): boolean {
	const parsed = parseIp(ip);
	if (!parsed) return false;
	const candidates = parsed.version === 6 ? [ip, ipv4FromMapped(parsed.value)].filter((value): value is string => value !== null) : [ip];
	return candidates.some((candidate) => PRIVATE_CIDRS.some((cidr) => cidrContains(cidr, candidate)));
}

export function splitCidrsByFamily(cidrs: string[]): { v4: string[]; v6: string[] } {
	const v4: string[] = [];
	const v6: string[] = [];
	for (const cidr of cidrs) {
		const parsed = parseCidr(cidr);
		if (!parsed) continue;
		(parsed.version === 4 ? v4 : v6).push(cidr);
	}
	return { v4, v6 };
}
