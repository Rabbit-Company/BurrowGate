import { describe, expect, test } from "bun:test";
import {
	buildNftAddRuleScript,
	buildNftDeleteTableScript,
	buildNftReplaceScript,
	buildNftTableSetChainScript,
	NFT_CHAIN,
	NFT_SET_V4,
	NFT_SET_V6,
	NFT_TABLE,
	parseNftChainRulesJson,
	splitCidrsByFamily,
} from "../src/services/firewall-sync/nftables-adapter.ts";

describe("buildNftTableSetChainScript", () => {
	test("bootstraps the isolated table, both address-family sets, and the input chain", () => {
		const script = buildNftTableSetChainScript();
		expect(script).toContain(`add table inet ${NFT_TABLE}`);
		expect(script).toContain(`add set inet ${NFT_TABLE} ${NFT_SET_V4} { type ipv4_addr; flags interval; auto-merge; }`);
		expect(script).toContain(`add set inet ${NFT_TABLE} ${NFT_SET_V6} { type ipv6_addr; flags interval; auto-merge; }`);
		expect(script).toContain(`add chain inet ${NFT_TABLE} ${NFT_CHAIN} { type filter hook input priority -10; policy accept; }`);
	});
});

describe("buildNftDeleteTableScript", () => {
	test("deletes the whole isolated table, which drops its chain/sets/rule along with it", () => {
		expect(buildNftDeleteTableScript()).toBe(`delete table inet ${NFT_TABLE}\n`);
	});
});

describe("buildNftAddRuleScript", () => {
	test("emits nothing when both families already have the marker rule", () => {
		expect(buildNftAddRuleScript(false, false)).toBe("");
	});

	test("emits only the missing family's rule", () => {
		const script = buildNftAddRuleScript(true, false);
		expect(script).toContain(`ip saddr @${NFT_SET_V4}`);
		expect(script).not.toContain(`ip6 saddr @${NFT_SET_V6}`);
	});

	test("emits both rules when both are missing", () => {
		const script = buildNftAddRuleScript(true, true);
		expect(script).toContain(`ip saddr @${NFT_SET_V4}`);
		expect(script).toContain(`ip6 saddr @${NFT_SET_V6}`);
	});
});

describe("buildNftReplaceScript", () => {
	test("flushes both sets and only adds elements for non-empty families", () => {
		const script = buildNftReplaceScript(["203.0.113.1", "203.0.113.2"], []);
		expect(script).toContain(`flush set inet ${NFT_TABLE} ${NFT_SET_V4}`);
		expect(script).toContain(`add element inet ${NFT_TABLE} ${NFT_SET_V4} { 203.0.113.1, 203.0.113.2 }`);
		expect(script).toContain(`flush set inet ${NFT_TABLE} ${NFT_SET_V6}`);
		expect(script).not.toContain(`add element inet ${NFT_TABLE} ${NFT_SET_V6}`);
	});

	test("handles an empty desired set as flush-only for both families", () => {
		const script = buildNftReplaceScript([], []);
		expect(script).not.toContain("add element");
	});
});

describe("splitCidrsByFamily", () => {
	test("separates v4 and v6 entries and drops unparsable ones", () => {
		const result = splitCidrsByFamily(["203.0.113.1", "2001:db8::1", "not-an-ip"]);
		expect(result.v4).toEqual(["203.0.113.1"]);
		expect(result.v6).toEqual(["2001:db8::1"]);
	});
});

describe("parseNftChainRulesJson", () => {
	test("detects both marker rules present, discriminated by protocol not field name", () => {
		const json = JSON.stringify({
			nftables: [
				{ rule: { comment: "burrowgate-managed", expr: [{ match: { left: { payload: { protocol: "ip", field: "saddr" } } } }] } },
				{ rule: { comment: "burrowgate-managed", expr: [{ match: { left: { payload: { protocol: "ip6", field: "saddr" } } } }] } },
			],
		});
		expect(parseNftChainRulesJson(json)).toEqual({ hasV4Rule: true, hasV6Rule: true });
	});

	test("reports missing rules when only one family or no marker is present", () => {
		const onlyV4 = JSON.stringify({
			nftables: [{ rule: { comment: "burrowgate-managed", expr: [{ match: { left: { payload: { protocol: "ip", field: "saddr" } } } }] } }],
		});
		expect(parseNftChainRulesJson(onlyV4)).toEqual({ hasV4Rule: true, hasV6Rule: false });
		expect(parseNftChainRulesJson(JSON.stringify({ nftables: [] }))).toEqual({ hasV4Rule: false, hasV6Rule: false });
	});

	test("ignores rules without the burrowgate marker comment", () => {
		const json = JSON.stringify({
			nftables: [{ rule: { comment: "unrelated", expr: [{ match: { left: { payload: { protocol: "ip", field: "saddr" } } } }] } }],
		});
		expect(parseNftChainRulesJson(json)).toEqual({ hasV4Rule: false, hasV6Rule: false });
	});

	test("returns no rules for unparsable JSON instead of throwing", () => {
		expect(parseNftChainRulesJson("not json")).toEqual({ hasV4Rule: false, hasV6Rule: false });
	});
});
