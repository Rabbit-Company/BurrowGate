import { describe, expect, test } from "bun:test";
import { sha1Hex } from "../src/utils/crypto.ts";
import {
	buildOvhRequest,
	computeOvhRuleDiff,
	isOvhManagedRule,
	normalizeOvhEndpoint,
	normalizeOvhIpv4Source,
	OVH_MAX_RULES,
	ovhApiRoot,
	ovhCredentialRequestBody,
	ovhEnableFirewallRequestBody,
	ovhFirewallIpAddress,
	ovhSignature,
	parseOvhProviderConfig,
	type OvhExistingRule,
} from "../src/services/firewall-sync/ovh-adapter.ts";

function managedRule(sequence: number, source: string): OvhExistingRule {
	return { sequence, source, action: "deny", protocol: "ipv4", sourcePort: null, destinationPort: null };
}

function allowRule(sequence: number, destinationPort: string): OvhExistingRule {
	return { sequence, source: null, action: "permit", protocol: "tcp", sourcePort: null, destinationPort };
}

describe("sha1Hex", () => {
	test("matches known SHA-1 test vectors", async () => {
		expect(await sha1Hex("")).toBe("da39a3ee5e6b4b0d3255bfef95601890afd80709");
		expect(await sha1Hex("abc")).toBe("a9993e364706816aba3e25717850c26c9cd0d89d");
	});
});

describe("ovhSignature", () => {
	test("matches OVH's documented $1$ + sha1(appSecret+consumerKey+method+url+body+timestamp) scheme", async () => {
		const signature = await ovhSignature("app-secret", "consumer-key", "GET", "https://eu.api.ovh.com/1.0/ip", "", 1_700_000_000);
		expect(signature).toBe("$1$f1d29d3b6e77863b919a4677ea1c2c4dd6ca2a29");
	});

	test("changes when the body changes, since the body is part of the signed string", async () => {
		const withoutBody = await ovhSignature("s", "c", "POST", "https://eu.api.ovh.com/1.0/ip/x/firewall/y/rule", "", 1);
		const withBody = await ovhSignature("s", "c", "POST", "https://eu.api.ovh.com/1.0/ip/x/firewall/y/rule", '{"a":1}', 1);
		expect(withBody).not.toBe(withoutBody);
	});
});

describe("normalizeOvhEndpoint / parseOvhProviderConfig", () => {
	test("defaults the endpoint to the EU root and trims trailing slashes", () => {
		expect(normalizeOvhEndpoint(undefined)).toBe("https://eu.api.ovh.com");
		expect(normalizeOvhEndpoint("")).toBe("https://eu.api.ovh.com");
		expect(normalizeOvhEndpoint("https://ca.api.ovh.com///")).toBe("https://ca.api.ovh.com");
	});

	test("parses a full config and defaults empty fields", () => {
		const cfg = parseOvhProviderConfig({ applicationKey: " AK ", ipBlock: " 51.75.1.2/32 " });
		expect(cfg.endpoint).toBe("https://eu.api.ovh.com");
		expect(cfg.applicationKey).toBe("AK");
		expect(cfg.ipBlock).toBe("51.75.1.2/32");
		expect(cfg.applicationSecretEncrypted).toBe("");
		expect(cfg.consumerKeyEncrypted).toBe("");
	});
});

describe("ovhApiRoot", () => {
	test("appends the required /1.0 version prefix - the bare domain 301-redirects and then 404s", () => {
		expect(ovhApiRoot("https://eu.api.ovh.com")).toBe("https://eu.api.ovh.com/1.0");
	});

	test("doesn't double up the version prefix if the admin already typed it", () => {
		expect(ovhApiRoot("https://eu.api.ovh.com/1.0")).toBe("https://eu.api.ovh.com/1.0");
		expect(ovhApiRoot("https://eu.api.ovh.com/1.0/")).toBe("https://eu.api.ovh.com/1.0");
	});
});

describe("ovhFirewallIpAddress", () => {
	test("strips a CIDR prefix, since {ipOnFirewall} is a bare address while {ip} is an ipBlock", () => {
		expect(ovhFirewallIpAddress("51.75.1.2/32")).toBe("51.75.1.2");
		expect(ovhFirewallIpAddress("51.75.1.2")).toBe("51.75.1.2");
	});
});

describe("ovhEnableFirewallRequestBody", () => {
	test("uses the real body parameter name (ipOnFirewall), not the OVH type name (ipv4) it's easily confused with", () => {
		expect(ovhEnableFirewallRequestBody("51.75.1.2")).toEqual({ ipOnFirewall: "51.75.1.2" });
	});
});

describe("normalizeOvhIpv4Source", () => {
	test("appends /32 to a bare address - OVH rejects a bare address for the ipv4Block-typed source field", () => {
		expect(normalizeOvhIpv4Source("15.169.249.14")).toBe("15.169.249.14/32");
	});

	test("leaves an already-prefixed CIDR untouched", () => {
		expect(normalizeOvhIpv4Source("203.0.113.0/24")).toBe("203.0.113.0/24");
		expect(normalizeOvhIpv4Source("15.169.249.14/32")).toBe("15.169.249.14/32");
	});
});

describe("buildOvhRequest", () => {
	test("builds the full URL and signing/identity headers for a GET request with no body", async () => {
		const spec = await buildOvhRequest({ endpoint: "https://eu.api.ovh.com", applicationKey: "AK" }, "AS", "CK", "GET", "/ip", 1_700_000_000);
		expect(spec.url).toBe("https://eu.api.ovh.com/1.0/ip");
		const headers = spec.init.headers as Record<string, string>;
		expect(headers["X-Ovh-Application"]).toBe("AK");
		expect(headers["X-Ovh-Consumer"]).toBe("CK");
		expect(headers["X-Ovh-Timestamp"]).toBe("1700000000");
		expect(headers["X-Ovh-Signature"]).toBe(await ovhSignature("AS", "CK", "GET", "https://eu.api.ovh.com/1.0/ip", "", 1_700_000_000));
		expect(headers["content-type"]).toBeUndefined();
		expect(spec.init.body).toBeUndefined();
	});

	test("serializes and signs a JSON body, and sets content-type", async () => {
		const spec = await buildOvhRequest(
			{ endpoint: "https://eu.api.ovh.com", applicationKey: "AK" },
			"AS",
			"CK",
			"POST",
			"/ip/51.75.1.2%2F32/firewall/51.75.1.2/rule",
			1_700_000_000,
			{ action: "deny", protocol: "ipv4", sequence: 0, source: "203.0.113.1" },
		);
		const headers = spec.init.headers as Record<string, string>;
		expect(headers["content-type"]).toBe("application/json");
		expect(JSON.parse(spec.init.body as string)).toEqual({ action: "deny", protocol: "ipv4", sequence: 0, source: "203.0.113.1" });
	});
});

describe("ovhCredentialRequestBody", () => {
	test("scopes access rules to just the /ip resource tree, not the whole account", () => {
		const body = ovhCredentialRequestBody(null);
		expect(body.redirection).toBeNull();
		expect(body.accessRules).toEqual([
			{ method: "GET", path: "/ip" },
			{ method: "GET", path: "/ip/*" },
			{ method: "POST", path: "/ip/*" },
			{ method: "PUT", path: "/ip/*" },
			{ method: "DELETE", path: "/ip/*" },
		]);
	});

	test("includes an explicit rule for the bare /ip path - OVH's /ip/* wildcard doesn't cover its own root", () => {
		const body = ovhCredentialRequestBody(null);
		expect(body.accessRules).toContainEqual({ method: "GET", path: "/ip" });
	});
});

describe("isOvhManagedRule", () => {
	test("only a plain ipv4 deny rule with no port restriction is BurrowGate's own", () => {
		expect(isOvhManagedRule(managedRule(0, "203.0.113.1"))).toBe(true);
		expect(isOvhManagedRule(allowRule(0, "22"))).toBe(false);
		expect(isOvhManagedRule({ sequence: 0, source: "203.0.113.1", action: "deny", protocol: "tcp", sourcePort: null, destinationPort: "22" })).toBe(false);
	});
});

describe("computeOvhRuleDiff", () => {
	test("creates rules at free sequences when the firewall starts empty", () => {
		const diff = computeOvhRuleDiff(["203.0.113.1", "203.0.113.2"], []);
		expect(diff.toDelete).toEqual([]);
		expect(diff.toCreate).toEqual([
			{ sequence: 0, source: "203.0.113.1" },
			{ sequence: 1, source: "203.0.113.2" },
		]);
	});

	test("keeps rules whose source is still desired, deletes the rest, and reuses freed sequences for new ones", () => {
		const existing = [managedRule(0, "203.0.113.1"), managedRule(1, "203.0.113.99"), managedRule(5, "203.0.113.2")];
		const diff = computeOvhRuleDiff(["203.0.113.1", "203.0.113.2", "203.0.113.3"], existing);
		expect(diff.toDelete).toEqual([1]);
		// sequence 1 is freed by the delete; 0 and 5 stay occupied by kept rules.
		expect(diff.toCreate).toEqual([{ sequence: 1, source: "203.0.113.3" }]);
	});

	test("produces no changes when the existing set already matches the desired set exactly", () => {
		const existing = [managedRule(0, "203.0.113.1"), managedRule(1, "203.0.113.2")];
		const diff = computeOvhRuleDiff(["203.0.113.1", "203.0.113.2"], existing);
		expect(diff.toDelete).toEqual([]);
		expect(diff.toCreate).toEqual([]);
	});

	test("hard-caps at the 20-slot limit even if the caller passes a larger desired list", () => {
		const desired = Array.from({ length: 30 }, (_, i) => `203.0.113.${i}`);
		const diff = computeOvhRuleDiff(desired, []);
		expect(diff.toCreate.length).toBe(OVH_MAX_RULES);
		expect(diff.toCreate.every((entry) => entry.sequence < OVH_MAX_RULES)).toBe(true);
	});

	test("deletes a duplicate rule for the same source, keeping only the first occurrence", () => {
		const existing = [managedRule(0, "203.0.113.1"), managedRule(3, "203.0.113.1")];
		const diff = computeOvhRuleDiff(["203.0.113.1"], existing);
		expect(diff.toDelete).toEqual([3]);
		expect(diff.toCreate).toEqual([]);
	});

	test("never deletes or reuses the sequence of an ALLOW rule the admin set up manually - this is what stops a lockout", () => {
		const existing = [allowRule(0, "22"), allowRule(1, "443"), managedRule(2, "203.0.113.1")];
		const diff = computeOvhRuleDiff(["203.0.113.1", "203.0.113.2"], existing);
		expect(diff.toDelete).not.toContain(0);
		expect(diff.toDelete).not.toContain(1);
		// the new ban must land on a genuinely free slot (3+), never slot 0 or 1.
		expect(diff.toCreate).toEqual([{ sequence: 3, source: "203.0.113.2" }]);
	});

	test("never touches a deny rule that has a port restriction, since that's not BurrowGate's shape", () => {
		const portScopedDeny: OvhExistingRule = { sequence: 0, source: "198.51.100.1", action: "deny", protocol: "tcp", sourcePort: null, destinationPort: "25" };
		const diff = computeOvhRuleDiff(["203.0.113.1"], [portScopedDeny]);
		expect(diff.toDelete).toEqual([]);
		expect(diff.toCreate).toEqual([{ sequence: 1, source: "203.0.113.1" }]);
	});

	test("reduces effective capacity by however many slots foreign rules occupy", () => {
		const foreign = Array.from({ length: 5 }, (_, i) => allowRule(i, String(1000 + i)));
		const desired = Array.from({ length: 30 }, (_, i) => `203.0.113.${i}`);
		const diff = computeOvhRuleDiff(desired, foreign);
		expect(diff.toCreate.length).toBe(OVH_MAX_RULES - 5);
		expect(diff.toCreate.every((entry) => entry.sequence >= 5)).toBe(true);
	});
});
