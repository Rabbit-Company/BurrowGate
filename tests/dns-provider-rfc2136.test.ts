import { describe, expect, test } from "bun:test";
import { hmacSha256Raw } from "../src/utils/crypto.ts";
import {
	encodeDomainName,
	encodeUpdateMessage,
	normalizeDnsName,
	parseRfc2136ProviderConfig,
	rcodeName,
	responseRcode,
	signWithTsig,
	type TsigKey,
} from "../src/services/dns-01/rfc2136-adapter.ts";

describe("encodeDomainName", () => {
	test("encodes a two-label name as length-prefixed labels terminated by a zero byte", () => {
		expect(Array.from(encodeDomainName("example.com"))).toEqual([7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0]);
	});

	test("a trailing dot produces the same encoding as no trailing dot", () => {
		expect(encodeDomainName("example.com.")).toEqual(encodeDomainName("example.com"));
	});

	test("the root name encodes as a single zero byte", () => {
		expect(Array.from(encodeDomainName("."))).toEqual([0]);
		expect(Array.from(encodeDomainName(""))).toEqual([0]);
	});

	test("rejects a label over 63 bytes", () => {
		expect(() => encodeDomainName(`${"a".repeat(64)}.com`)).toThrow();
	});
});

describe("normalizeDnsName", () => {
	test("lowercases and appends a trailing dot", () => {
		expect(normalizeDnsName("Example.COM")).toBe("example.com.");
		expect(normalizeDnsName("example.com.")).toBe("example.com.");
	});

	test("empty input stays empty", () => {
		expect(normalizeDnsName("")).toBe("");
		expect(normalizeDnsName("   ")).toBe("");
	});
});

describe("encodeUpdateMessage", () => {
	test("builds a well-formed header: Opcode=UPDATE(5), one zone entry, one update RR, no additional records", () => {
		const message = encodeUpdateMessage({
			id: 0x1234,
			zone: "example.com.",
			operations: [{ kind: "add", name: "_acme-challenge.example.com.", ttl: 120, value: "abc" }],
		});
		expect(message[0]).toBe(0x12);
		expect(message[1]).toBe(0x34);
		expect(message[2]).toBe(0x28); // QR=0, Opcode=5 (UPDATE)
		expect(message[3]).toBe(0x00);
		expect([message[4], message[5]]).toEqual([0x00, 0x01]); // ZOCOUNT=1
		expect([message[6], message[7]]).toEqual([0x00, 0x00]); // PRCOUNT=0
		expect([message[8], message[9]]).toEqual([0x00, 0x01]); // UPCOUNT=1
		expect([message[10], message[11]]).toEqual([0x00, 0x00]); // ARCOUNT=0
	});

	test("the zone section is the zone name followed by TYPE=SOA(6) and CLASS=IN(1)", () => {
		const message = encodeUpdateMessage({ id: 1, zone: "example.com.", operations: [] });
		const zoneName = encodeDomainName("example.com.");
		const zoneSection = message.slice(12, 12 + zoneName.length + 4);
		expect(Array.from(zoneSection.slice(0, zoneName.length))).toEqual(Array.from(zoneName));
		expect(Array.from(zoneSection.slice(zoneName.length))).toEqual([0x00, 0x06, 0x00, 0x01]);
	});

	test("an 'add' RR uses CLASS=IN(1) with the given TTL and a length-prefixed TXT character-string", () => {
		const zone = "example.com.";
		const name = "_acme-challenge.example.com.";
		const message = encodeUpdateMessage({ id: 1, zone, operations: [{ kind: "add", name, ttl: 120, value: "abc" }] });
		const zoneSectionLength = encodeDomainName(zone).length + 4;
		const rr = message.slice(12 + zoneSectionLength);
		const encodedName = encodeDomainName(name);
		expect(Array.from(rr.slice(0, encodedName.length))).toEqual(Array.from(encodedName));
		const tail = rr.slice(encodedName.length);
		expect(Array.from(tail)).toEqual([
			0x00,
			0x10, // TYPE=TXT(16)
			0x00,
			0x01, // CLASS=IN(1)
			0x00,
			0x00,
			0x00,
			0x78, // TTL=120
			0x00,
			0x04, // RDLENGTH=4 (1 length byte + 3 value bytes)
			0x03,
			0x61,
			0x62,
			0x63, // "abc"
		]);
	});

	test("a 'delete-rr' RR overloads CLASS=NONE(254) and TTL=0, per RFC 2136 §2.5.4, instead of the add encoding", () => {
		const zone = "example.com.";
		const name = "_acme-challenge.example.com.";
		const message = encodeUpdateMessage({ id: 1, zone, operations: [{ kind: "delete-rr", name, value: "abc" }] });
		const zoneSectionLength = encodeDomainName(zone).length + 4;
		const rr = message.slice(12 + zoneSectionLength);
		const encodedName = encodeDomainName(name);
		const tail = rr.slice(encodedName.length);
		expect(Array.from(tail.slice(0, 2))).toEqual([0x00, 0x10]); // TYPE=TXT
		expect(Array.from(tail.slice(2, 4))).toEqual([0x00, 0xfe]); // CLASS=NONE(254)
		expect(Array.from(tail.slice(4, 8))).toEqual([0x00, 0x00, 0x00, 0x00]); // TTL=0
	});

	test("UPCOUNT tracks the number of operations", () => {
		const message = encodeUpdateMessage({
			id: 1,
			zone: "example.com.",
			operations: [
				{ kind: "add", name: "a.example.com.", ttl: 1, value: "x" },
				{ kind: "delete-rr", name: "a.example.com.", value: "x" },
			],
		});
		expect([message[8], message[9]]).toEqual([0x00, 0x02]);
	});
});

describe("signWithTsig", () => {
	const key: TsigKey = { name: "burrowgate-key.", secret: new TextEncoder().encode("shared-secret-bytes"), algorithm: "hmac-sha256" };

	test("appends exactly one additional record and increments ARCOUNT from 0 to 1", async () => {
		const message = encodeUpdateMessage({ id: 0xabcd, zone: "example.com.", operations: [] });
		expect([message[10], message[11]]).toEqual([0x00, 0x00]);
		const signed = await signWithTsig(message, key, { timeSigned: 1_700_000_000, fudge: 300 });
		expect([signed[10], signed[11]]).toEqual([0x00, 0x01]);
		expect(Array.from(signed.slice(0, message.length))).toEqual(Array.from(message.slice(0, 10)).concat([0x00, 0x01], Array.from(message.slice(12))));
	});

	test("the MAC matches an independently reconstructed RFC 2845 TSIG-variables digest", async () => {
		const message = encodeUpdateMessage({ id: 0xabcd, zone: "example.com.", operations: [] });
		const timeSigned = 1_700_000_000;
		const fudge = 300;
		const signed = await signWithTsig(message, key, { timeSigned, fudge });

		// Reconstruct the expected MAC input by hand, straight from RFC 2845 §3.4.2, independently of signWithTsig's internals.
		const variables = new Uint8Array([
			...encodeDomainName(key.name),
			0x00,
			0xff, // CLASS=ANY(255)
			0x00,
			0x00,
			0x00,
			0x00, // TTL=0
			...encodeDomainName("hmac-sha256."),
			// Time Signed (48-bit big-endian)
			...(() => {
				const bytes: number[] = [];
				const big = BigInt(timeSigned);
				for (let shift = 40; shift >= 0; shift -= 8) bytes.push(Number((big >> BigInt(shift)) & 0xffn));
				return bytes;
			})(),
			(fudge >> 8) & 0xff,
			fudge & 0xff,
			0x00,
			0x00, // Error=0
			0x00,
			0x00, // Other Len=0
		]);
		const macData = new Uint8Array([...message, ...variables]);
		const expectedMac = await hmacSha256Raw(key.secret, macData);

		// The MAC sits inside the appended TSIG RR's RDATA, immediately before the trailing Original ID(2) + Error(2) + Other Len(2).
		const macStart = signed.length - expectedMac.length - 6;
		const macBytes = signed.slice(macStart, macStart + expectedMac.length);
		expect(Array.from(macBytes)).toEqual(Array.from(expectedMac));
	});

	test("a different shared secret produces a different signature", async () => {
		const message = encodeUpdateMessage({ id: 1, zone: "example.com.", operations: [] });
		const otherKey: TsigKey = { ...key, secret: new TextEncoder().encode("a-completely-different-secret") };
		const signedA = await signWithTsig(message, key, { timeSigned: 1, fudge: 300 });
		const signedB = await signWithTsig(message, otherKey, { timeSigned: 1, fudge: 300 });
		expect(Array.from(signedA)).not.toEqual(Array.from(signedB));
	});
});

describe("responseRcode / rcodeName", () => {
	test("reads RCODE from the low 4 bits of the second flags byte", () => {
		const header = new Uint8Array(12);
		header[3] = 0x05; // REFUSED
		expect(responseRcode(header)).toBe(5);
		expect(rcodeName(5)).toBe("REFUSED");
		expect(rcodeName(0)).toBe("NOERROR");
		expect(rcodeName(99)).toBe("RCODE 99");
	});

	test("throws on a response shorter than a DNS header", () => {
		expect(() => responseRcode(new Uint8Array(4))).toThrow();
	});
});

describe("parseRfc2136ProviderConfig", () => {
	test("defaults port, propagation seconds, and normalizes zone/key name casing", () => {
		const cfg = parseRfc2136ProviderConfig({ server: " ns1.example.com ", zone: "Example.COM", tsigKeyName: "Burrowgate-Key" });
		expect(cfg.server).toBe("ns1.example.com");
		expect(cfg.port).toBe(53);
		expect(cfg.zone).toBe("example.com.");
		expect(cfg.tsigKeyName).toBe("burrowgate-key.");
		expect(cfg.tsigAlgorithm).toBe("hmac-sha256");
		expect(cfg.propagationSeconds).toBe(30);
	});

	test("preserves an explicit port and propagation window", () => {
		const cfg = parseRfc2136ProviderConfig({ server: "ns1.example.com", port: 5353, zone: "example.com", propagationSeconds: 5 });
		expect(cfg.port).toBe(5353);
		expect(cfg.propagationSeconds).toBe(5);
	});

	test("handles missing/empty input without throwing", () => {
		const cfg = parseRfc2136ProviderConfig(undefined);
		expect(cfg.server).toBe("");
		expect(cfg.zone).toBe("");
		expect(cfg.tsigSecretEncrypted).toBe("");
	});
});
