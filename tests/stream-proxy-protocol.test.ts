import { describe, expect, test } from "bun:test";
import { proxyProtocolDatagram, proxyProtocolHeader } from "../src/services/stream-proxy-protocol.ts";

describe("PROXY protocol encoding", () => {
	test("encodes a v1 TCP/IPv4 header", () => {
		const header = proxyProtocolHeader("v1", "tcp", {
			sourceAddress: "203.0.113.8",
			destinationAddress: "192.0.2.20",
			sourcePort: 45_678,
			destinationPort: 25_565,
		});
		expect(header.toString()).toBe("PROXY TCP4 203.0.113.8 192.0.2.20 45678 25565\r\n");
	});

	test("encodes a canonical v1 TCP/IPv6 header", () => {
		const header = proxyProtocolHeader("v1", "tcp", {
			sourceAddress: "2001:0db8:0:0:0:0:0:8",
			destinationAddress: "2001:db8::20",
			sourcePort: 45_678,
			destinationPort: 25_565,
		});
		expect(header.toString()).toBe("PROXY TCP6 2001:db8::8 2001:db8::20 45678 25565\r\n");
	});

	test("encodes v2 TCP/IPv4 addresses and ports in network byte order", () => {
		const header = proxyProtocolHeader("v2", "tcp", {
			sourceAddress: "203.0.113.8",
			destinationAddress: "192.0.2.20",
			sourcePort: 45_678,
			destinationPort: 25_565,
		});
		expect(header.toString("hex")).toBe("0d0a0d0a000d0a515549540a2111000ccb007108c0000214b26e63dd");
	});

	test("encodes v2 TCP/IPv6 addresses and ports in network byte order", () => {
		const header = proxyProtocolHeader("v2", "tcp", {
			sourceAddress: "2001:db8::8",
			destinationAddress: "2001:db8::20",
			sourcePort: 45_678,
			destinationPort: 25_565,
		});
		expect(header.toString("hex")).toBe("0d0a0d0a000d0a515549540a2121002420010db800000000000000000000000820010db8000000000000000000000020b26e63dd");
	});

	test("uses the v2 DGRAM transport and keeps the header in the same UDP datagram", () => {
		const header = proxyProtocolHeader("v2", "udp", {
			sourceAddress: "203.0.113.9",
			destinationAddress: "192.0.2.20",
			sourcePort: 19_132,
			destinationPort: 19_133,
		});
		const datagram = proxyProtocolDatagram(header, Buffer.from("payload"));
		expect(header[13]).toBe(0x12);
		expect(datagram.subarray(0, header.byteLength)).toEqual(header);
		expect(datagram.subarray(header.byteLength).toString()).toBe("payload");
	});

	test("rejects v1 for UDP", () => {
		expect(() =>
			proxyProtocolHeader("v1", "udp", {
				sourceAddress: "203.0.113.9",
				destinationAddress: "192.0.2.20",
				sourcePort: 19_132,
				destinationPort: 19_133,
			}),
		).toThrow("does not support UDP");
	});
});
