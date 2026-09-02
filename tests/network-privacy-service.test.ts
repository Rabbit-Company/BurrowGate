import { describe, expect, test } from "bun:test";
import {
	type AsnListManifestCategory,
	blockedNetworkPrivacyCategory,
	evaluateNetworkPrivacy,
	identifyNetworkPrivacy,
	mergeAsnListCategories,
	networkPrivacyBlockIsBypassed,
	parseAsnList,
	parseNetworkPrivacyPolicy,
	parseTorExitList,
	serializeNetworkPrivacyPolicy,
	serializeRouteNetworkPrivacyPolicy,
	storedNetworkPrivacyPolicy,
} from "../src/services/network-privacy-service.ts";

function category(id: string): AsnListManifestCategory {
	return { id, label: id, description: "", file: `${id}.txt` };
}

describe("network privacy data", () => {
	test("parses and canonicalizes Tor exit addresses", () => {
		const result = parseTorExitList("203.0.113.4\n2001:db8::1\n2001:0db8:0:0:0:0:0:1\ninvalid\n");
		expect(result.size).toBe(2);
	});

	test("parses categorized ASN rows with organization names", () => {
		const result = parseAsnList("136787 PacketHub S.A.\n209103 Proton AG\ninvalid\nAS14061 DigitalOcean, LLC\n");
		expect([...result]).toEqual([136787, 209103]);
	});
});

describe("merging the CDN's ASN category list with what's cached locally", () => {
	test("keeps a hand-added local category the CDN doesn't publish", () => {
		const remote = [category("vpn"), category("datacenter")];
		const cached = [category("vpn"), category("datacenter"), category("my-custom-list")];
		expect(mergeAsnListCategories(remote, cached).map((c) => c.id)).toEqual(["vpn", "datacenter", "my-custom-list"]);
	});

	test("keeps a category the CDN used to publish but has since removed", () => {
		const remote = [category("vpn")];
		const cached = [category("vpn"), category("datacenter")];
		expect(mergeAsnListCategories(remote, cached).map((c) => c.id)).toEqual(["vpn", "datacenter"]);
	});

	test("always prefers the CDN's current definition for a category both sides have", () => {
		const remote = [{ ...category("vpn"), label: "Updated VPN label" }];
		const cached = [{ ...category("vpn"), label: "Stale cached label" }];
		expect(mergeAsnListCategories(remote, cached)).toEqual([{ ...category("vpn"), label: "Updated VPN label" }]);
	});

	test("starting from an empty local cache just takes the CDN's categories", () => {
		const remote = [category("vpn"), category("datacenter")];
		expect(mergeAsnListCategories(remote, [])).toEqual(remote);
	});
});

describe("network privacy policy", () => {
	const data = {
		tor: parseTorExitList("203.0.113.4\n"),
		asn: new Map([
			["vpn", new Set([136787])],
			["datacenter", new Set([14061])],
		]),
	};

	test("does no classification work for disabled categories", () => {
		const policy = parseNetworkPrivacyPolicy(undefined);
		expect(identifyNetworkPrivacy("203.0.113.4", 136787, policy, data)).toBeNull();
	});

	test("can identify several enabled categories and block only configured ones", () => {
		const policy = parseNetworkPrivacyPolicy({ tor: "monitor", vpn: "block", datacenter: "disabled" });
		const identity = identifyNetworkPrivacy("203.0.113.4", 136787, policy, data);
		expect(identity?.categories).toEqual(["tor", "vpn"]);
		expect(blockedNetworkPrivacyCategory(identity, policy)).toBe("vpn");
	});

	test("identifies categories unknown to the currently loaded manifest just the same", () => {
		const policy = parseNetworkPrivacyPolicy({ "isp-telecom": "block" });
		const withNewCategory = { tor: data.tor, asn: new Map([...data.asn, ["isp-telecom", new Set([64500])]]) };
		const identity = identifyNetworkPrivacy("203.0.113.4", 64500, policy, withNewCategory);
		expect(identity?.categories).toEqual(["isp-telecom"]);
		expect(blockedNetworkPrivacyCategory(identity, policy)).toBe("isp-telecom");
	});

	test("explicit IP and ASN allow rules override automatic blocking", () => {
		expect(networkPrivacyBlockIsBypassed("asn-rule", "pass")).toBe(true);
		expect(networkPrivacyBlockIsBypassed("asn-rule", "allow")).toBe(true);
		expect(networkPrivacyBlockIsBypassed("ip-rule", "allow")).toBe(true);
		expect(networkPrivacyBlockIsBypassed("asn-rule", "challenge")).toBe(false);
		expect(networkPrivacyBlockIsBypassed("country-rule", "allow")).toBe(false);
	});

	test("applies stream-style category blocks while preserving explicit network allow rules", () => {
		const policy = parseNetworkPrivacyPolicy({ vpn: "block" });
		expect(evaluateNetworkPrivacy("203.0.113.4", 136787, policy, "route", null, data).blockedCategory).toBe("vpn");
		expect(evaluateNetworkPrivacy("203.0.113.4", 136787, policy, "asn-rule", "allow", data).blockedCategory).toBeNull();
		expect(evaluateNetworkPrivacy("203.0.113.4", 136787, policy, "country-rule", "allow", data).blockedCategory).toBe("vpn");
	});

	test("rejects unknown modes", () => {
		expect(() => parseNetworkPrivacyPolicy({ tor: "maybe" })).toThrow("disabled, monitor, or block");
	});

	test("ignores malformed category keys instead of storing them", () => {
		const policy = parseNetworkPrivacyPolicy({ vpn: "block", "../etc/passwd": "block", "Has Spaces": "block" });
		expect(policy).toEqual({ vpn: "block" });
	});

	test("stores site policies and lets routes inherit or override them", () => {
		const stored = serializeNetworkPrivacyPolicy({ tor: "monitor", vpn: "block" });
		expect(storedNetworkPrivacyPolicy(stored)).toEqual({ tor: "monitor", vpn: "block" });
		expect(serializeRouteNetworkPrivacyPolicy(null, stored)).toBeNull();
		expect(serializeRouteNetworkPrivacyPolicy({ datacenter: "monitor" })).toBe(JSON.stringify({ datacenter: "monitor" }));
	});
});
