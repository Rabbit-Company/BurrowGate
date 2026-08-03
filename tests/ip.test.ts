import { describe, expect, test } from "bun:test";
import { cidrContains } from "../src/utils/ip.ts";

describe("CIDR matching", () => {
	test("matches IPv4", () => {
		expect(cidrContains("192.168.1.0/24", "192.168.1.25")).toBe(true);
		expect(cidrContains("192.168.1.0/24", "192.168.2.1")).toBe(false);
	});
	test("matches IPv6", () => {
		expect(cidrContains("2001:db8::/32", "2001:db8:1::5")).toBe(true);
		expect(cidrContains("2001:db8::/32", "2001:db9::1")).toBe(false);
	});
});
