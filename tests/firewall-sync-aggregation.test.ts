import { describe, expect, test } from "bun:test";
import { addIpRule } from "../src/services/ip-rule-service.ts";
import { addStreamIpRule } from "../src/services/stream-ip-rule-service.ts";
import { createSite } from "../src/services/site-service.ts";
import { addFirewallSyncWhitelistCidr, removeFirewallSyncWhitelistCidr } from "../src/services/firewall-sync-service.ts";
import {
	aggregateBannedCidrs,
	aggregateBannedCidrsDetailed,
	dedupeCidrsByRecency,
	filterBannableCidrs,
	filterBannableCidrsDetailed,
} from "../src/services/firewall-sync-service.ts";
import type { FirewallSyncWhitelistCidrRecord } from "../src/types.ts";

async function site() {
	return (await createSite({ name: "Firewall sync aggregation", publicHost: `fw-agg-${crypto.randomUUID()}.test`, originUrl: "http://origin.test" })).site;
}

function uniqueTestSubnet(): string {
	return `240.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
}

describe("dedupeCidrsByRecency", () => {
	test("keeps the most recent created_at per CIDR and sorts newest-first", () => {
		const result = dedupeCidrsByRecency([
			{ network_cidr: "1.1.1.1", created_at: 100 },
			{ network_cidr: "2.2.2.2", created_at: 300 },
			{ network_cidr: "1.1.1.1", created_at: 200 },
		]);
		expect(result).toEqual(["2.2.2.2", "1.1.1.1"]);
	});
});

describe("filterBannableCidrs", () => {
	function whitelist(cidr: string): FirewallSyncWhitelistCidrRecord {
		return { id: `wl_${crypto.randomUUID()}`, network_cidr: cidr, note: null, created_at: Date.now() };
	}

	test("excludes a candidate contained in a whitelist CIDR", () => {
		const result = filterBannableCidrs(["203.0.113.5", "203.0.113.9"], [whitelist("203.0.113.0/24")]);
		expect(result).toEqual([]);
	});

	test("keeps candidates outside the whitelist", () => {
		const result = filterBannableCidrs(["198.51.100.5"], [whitelist("203.0.113.0/24")]);
		expect(result).toEqual(["198.51.100.5"]);
	});

	test("excludes private ranges even with no whitelist configured", () => {
		const result = filterBannableCidrs(["10.0.0.5", "198.51.100.5"], []);
		expect(result).toEqual(["198.51.100.5"]);
	});
});

describe("filterBannableCidrsDetailed", () => {
	function whitelist(cidr: string): FirewallSyncWhitelistCidrRecord {
		return { id: `wl_${crypto.randomUUID()}`, network_cidr: cidr, note: null, created_at: Date.now() };
	}

	test("reports separate counts for private-range and whitelisted exclusions, e.g. a LAN auto-ban from an internal test client", () => {
		const result = filterBannableCidrsDetailed(["10.1.80.1", "203.0.113.5", "198.51.100.5"], [whitelist("203.0.113.0/24")]);
		expect(result.bannable).toEqual(["198.51.100.5"]);
		expect(result.excludedPrivateCount).toBe(1);
		expect(result.excludedWhitelistedCount).toBe(1);
	});
});

describe("aggregateBannedCidrs", () => {
	test("combines active site and stream blocks, excludes expired/non-block rows, and applies the whitelist", async () => {
		const s = await site();
		const streamId = `stream_${crypto.randomUUID()}`;
		const now = Date.now();
		const subnet = uniqueTestSubnet();
		await addIpRule(s.id, `${subnet}.1`, "block", "manual", null);
		await addIpRule(s.id, `${subnet}.2`, "block", "expired", now - 1_000);
		await addIpRule(s.id, `${subnet}.3`, "allow", "not a block", null);
		await addStreamIpRule(streamId, `${subnet}.4`, "block", "manual", null);
		const whitelisted = await addFirewallSyncWhitelistCidr(`${subnet}.8/29`, "protect the /29");
		await addIpRule(s.id, `${subnet}.10`, "block", "should be whitelisted", null);

		try {
			const result = await aggregateBannedCidrs(now);

			expect(result).toContain(`${subnet}.1`);
			expect(result).toContain(`${subnet}.4`);
			expect(result).not.toContain(`${subnet}.2`);
			expect(result).not.toContain(`${subnet}.3`);
			expect(result).not.toContain(`${subnet}.10`);
		} finally {
			await removeFirewallSyncWhitelistCidr(whitelisted.id);
		}
	});
});

describe("aggregateBannedCidrsDetailed", () => {
	test("surfaces total active count alongside the exclusion breakdown, so a private-range auto-ban isn't silently invisible", async () => {
		const s = await site();
		const now = Date.now();
		const subnet = uniqueTestSubnet();
		const privateSubnet = `10.${Math.floor(Math.random() * 200) + 1}.${Math.floor(Math.random() * 256)}`;
		await addIpRule(s.id, `${subnet}.1`, "block", "manual", null);
		await addIpRule(s.id, `${privateSubnet}.1`, "block", "auto-banned from a LAN test client", null);

		const detail = await aggregateBannedCidrsDetailed(now);

		expect(detail.bannable).toContain(`${subnet}.1`);
		expect(detail.bannable).not.toContain(`${privateSubnet}.1`);
		expect(detail.excludedPrivateCount).toBeGreaterThanOrEqual(1);
		expect(detail.totalActiveCount).toBeGreaterThanOrEqual(detail.bannable.length + detail.excludedPrivateCount);
	});
});
