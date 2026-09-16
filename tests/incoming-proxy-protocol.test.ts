import { describe, expect, test } from "bun:test";
import { isTrustedProxy, normalizeProxyAddress, parseIncomingProxyHeader, parseTrustedProxyCidrs } from "../src/services/incoming-proxy-protocol.ts";
import { proxyProtocolHeader } from "../src/services/stream-proxy-protocol.ts";
import { parseCidr } from "../src/utils/ip.ts";

const endpoints = { sourceAddress: "203.0.113.8", destinationAddress: "192.0.2.20", sourcePort: 45678, destinationPort: 443 };

describe("incoming PROXY protocol", () => {
	for (const version of ["v1", "v2"] as const) {
		test(`${version}: accepts every possible header fragmentation and leaves payload untouched`, () => {
			const header = proxyProtocolHeader(version, "tcp", endpoints);
			for (let length = 0; length < header.length; length++) expect(parseIncomingProxyHeader(header.subarray(0, length))).toBeNull();
			const input = Buffer.concat([header, Buffer.from("GET / HTTP/1.1\r\n")]);
			const parsed = parseIncomingProxyHeader(input)!;
			expect(parsed).toEqual({ bytes: header.length, connection: endpoints });
			expect(input.subarray(parsed.bytes).toString()).toBe("GET / HTTP/1.1\r\n");
		});
		test(`${version}: decodes IPv6 addresses`, () => {
			const ipv6 = { ...endpoints, sourceAddress: "2001:db8::8", destinationAddress: "2001:db8::20" };
			expect(parseIncomingProxyHeader(proxyProtocolHeader(version, "tcp", ipv6))?.connection).toEqual(ipv6);
		});
	}

	test("v1 UNKNOWN and v2 LOCAL discard their headers and use the socket address", () => {
		expect(parseIncomingProxyHeader(Buffer.from("PROXY UNKNOWN ignore this\r\nGET /"))).toEqual({ bytes: 27, connection: null });
		const local = proxyProtocolHeader("v2", "tcp", endpoints);
		local[12] = 0x20;
		local[13] = 0xff;
		expect(parseIncomingProxyHeader(local)).toEqual({ bytes: local.length, connection: null });
	});

	test("v2 consumes extension TLVs and rejects truncated extension lengths", () => {
		const header = proxyProtocolHeader("v2", "tcp", endpoints);
		header.writeUInt16BE(17, 14);
		const withTlv = Buffer.concat([header, Buffer.from([0xee, 0, 2, 1, 2])]);
		expect(parseIncomingProxyHeader(withTlv)).toEqual({ bytes: withTlv.length, connection: endpoints });
		withTlv[header.length + 2] = 3;
		expect(() => parseIncomingProxyHeader(withTlv)).toThrow("Invalid incoming");
	});

	test("preserves the IPv6 family of mapped source endpoints for a subsequent outgoing header", () => {
		const mixed = { ...endpoints, sourceAddress: "::ffff:203.0.113.8", destinationAddress: "2001:db8::20" };
		const decoded = parseIncomingProxyHeader(proxyProtocolHeader("v2", "tcp", mixed))!.connection!;
		expect(normalizeProxyAddress(decoded.sourceAddress)).toBe("203.0.113.8");
		expect(proxyProtocolHeader("v1", "tcp", decoded).toString()).toBe("PROXY TCP6 ::ffff:cb00:7108 2001:db8::20 45678 443\r\n");
	});

	test("rejects direct HTTP, invalid addresses/ports, overlong v1, unsupported v2 transports, and oversized v2 before buffering the body", () => {
		for (const text of [
			"GET / HTTP/1.1\r\n",
			"PROXY TCP4 999.1.1.1 192.0.2.2 1 2\r\n",
			"PROXY TCP4 ::1 192.0.2.2 1 2\r\n",
			"PROXY TCP4 1.1.1.1 2.2.2.2 65536 2\r\n",
			"PROXY " + "a".repeat(101),
		]) {
			expect(() => parseIncomingProxyHeader(Buffer.from(text))).toThrow("Invalid incoming");
		}
		const datagram = proxyProtocolHeader("v2", "udp", endpoints);
		expect(() => parseIncomingProxyHeader(datagram)).toThrow("Invalid incoming");
		const oversized = proxyProtocolHeader("v2", "tcp", endpoints);
		oversized.writeUInt16BE(65535, 14);
		expect(() => parseIncomingProxyHeader(oversized.subarray(0, 16))).toThrow("Invalid incoming");
		const invalidVersion = proxyProtocolHeader("v2", "tcp", endpoints);
		invalidVersion[12] = 0x31;
		expect(() => parseIncomingProxyHeader(invalidVersion)).toThrow("Invalid incoming");
	});

	test("trusts only configured socket peers, including IPv4 mapped peers", () => {
		const trusted = parseTrustedProxyCidrs(["10.0.0.2", "2001:db8::/64", "10.0.0.2"]).map((value) => parseCidr(value)!);
		expect(trusted).toHaveLength(2);
		expect(isTrustedProxy("::ffff:10.0.0.2", trusted)).toBe(true);
		expect(isTrustedProxy("2001:db8::123", trusted)).toBe(true);
		expect(isTrustedProxy("10.0.0.3", trusted)).toBe(false);
		expect(normalizeProxyAddress("::ffff:cb00:7108")).toBe("203.0.113.8");
		expect(() => parseTrustedProxyCidrs(["10.0.0.2/33"])).toThrow("Invalid trusted");
	});

	test("rejects malformed trusted CIDR prefixes that could broaden trust", () => {
		for (const value of ["10.0.0.2/", "10.0.0.2/32/junk", "10.0.0.2/0x10", "10.0.0.2/1.5", "10.0.0.2/ 0", "2001:db8::/"]) {
			expect(() => parseTrustedProxyCidrs([value])).toThrow("Invalid trusted");
		}
		expect(parseTrustedProxyCidrs([" 10.0.0.2/32 ", "2001:db8::/64"])).toEqual(["10.0.0.2/32", "2001:db8::/64"]);
	});
});
