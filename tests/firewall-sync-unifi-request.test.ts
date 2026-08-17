import { describe, expect, test } from "bun:test";
import {
	buildTrafficMatchingListItem,
	buildTrafficMatchingListItems,
	parseUnifiListEnvelope,
	parseUnifiProviderConfig,
	parseUnifiSitesResponse,
	unifiCreateTrafficMatchingListRequest,
	unifiDeleteTrafficMatchingListRequest,
	unifiListSitesRequest,
	unifiListTrafficMatchingListsRequest,
	unifiTestConnection,
	unifiTrafficMatchingListName,
	unifiUpdateTrafficMatchingListRequest,
} from "../src/services/firewall-sync/unifi-adapter.ts";

const baseConfig = parseUnifiProviderConfig({
	controllerUrl: "https://192.168.1.1/",
	apiBasePath: "/proxy/network",
	site: "88f7af54-98f8-306a-a1c7-c9349722b1f6",
	listName: "BurrowGate-Banned-IPs",
	apiKeyEncrypted: "encrypted-value",
	verifyTls: false,
});

describe("parseUnifiProviderConfig", () => {
	test("trims trailing slashes and applies defaults", () => {
		const cfg = parseUnifiProviderConfig({ controllerUrl: "https://unifi.local///" });
		expect(cfg.controllerUrl).toBe("https://unifi.local");
		expect(cfg.apiBasePath).toBe("/proxy/network");
		expect(cfg.listName).toBe("BurrowGate-Banned-IPs");
		expect(cfg.verifyTls).toBe(true);
	});

	test("defaults apiBasePath to /proxy/network since API keys only work on UniFi OS consoles", () => {
		expect(parseUnifiProviderConfig({}).apiBasePath).toBe("/proxy/network");
		expect(parseUnifiProviderConfig({ apiBasePath: "" }).apiBasePath).toBe("/proxy/network");
		expect(parseUnifiProviderConfig({ apiBasePath: "/custom/" }).apiBasePath).toBe("/custom");
	});

	test('site has no fallback - the Integration API is ID-scoped, so a real site UUID from "Load sites" is required', () => {
		expect(parseUnifiProviderConfig({}).site).toBe("");
		expect(parseUnifiProviderConfig({ site: "  " }).site).toBe("");
		expect(parseUnifiProviderConfig({ site: "88f7af54-98f8-306a-a1c7-c9349722b1f6" }).site).toBe("88f7af54-98f8-306a-a1c7-c9349722b1f6");
	});

	test("verifyTls defaults to true unless explicitly false", () => {
		expect(parseUnifiProviderConfig({ verifyTls: false }).verifyTls).toBe(false);
		expect(parseUnifiProviderConfig({}).verifyTls).toBe(true);
	});
});

describe("buildTrafficMatchingListItem", () => {
	test("maps a full-width prefix (bare IP or /32, /128) to an IP_ADDRESS item", () => {
		expect(buildTrafficMatchingListItem("203.0.113.5")).toEqual({ type: "IP_ADDRESS", value: "203.0.113.5" });
		expect(buildTrafficMatchingListItem("203.0.113.5/32")).toEqual({ type: "IP_ADDRESS", value: "203.0.113.5" });
		expect(buildTrafficMatchingListItem("2001:db8::5/128")).toEqual({ type: "IP_ADDRESS", value: "2001:db8::5" });
	});

	test("maps a narrower prefix to a SUBNET item, keeping the CIDR notation", () => {
		expect(buildTrafficMatchingListItem("203.0.113.0/24")).toEqual({ type: "SUBNET", value: "203.0.113.0/24" });
	});
});

describe("buildTrafficMatchingListItems", () => {
	test("maps each CIDR to an item", () => {
		expect(buildTrafficMatchingListItems(["203.0.113.1", "203.0.113.0/24"], "192.0.2.255/32")).toEqual([
			{ type: "IP_ADDRESS", value: "203.0.113.1" },
			{ type: "SUBNET", value: "203.0.113.0/24" },
		]);
	});

	test("substitutes the placeholder when the list would otherwise be empty, since the API rejects an empty items array", () => {
		expect(buildTrafficMatchingListItems([], "192.0.2.255/32")).toEqual([{ type: "IP_ADDRESS", value: "192.0.2.255" }]);
	});
});

describe("unifiListTrafficMatchingListsRequest / unifiCreateTrafficMatchingListRequest / unifiUpdateTrafficMatchingListRequest", () => {
	test("builds the site-scoped traffic-matching-lists URL and sends the API key header", () => {
		const spec = unifiListTrafficMatchingListsRequest(baseConfig, "test-key");
		expect(spec.url).toBe("https://192.168.1.1/proxy/network/integration/v1/sites/88f7af54-98f8-306a-a1c7-c9349722b1f6/traffic-matching-lists");
		expect((spec.init.headers as Record<string, string>)["X-API-Key"]).toBe("test-key");
		expect(spec.init.tls).toEqual({ rejectUnauthorized: false });
	});

	test("create POSTs the given name, type, and items", () => {
		const spec = unifiCreateTrafficMatchingListRequest(baseConfig, "test-key", "BurrowGate-Banned-IPs", "IPV4_ADDRESSES", [
			{ type: "IP_ADDRESS", value: "203.0.113.1" },
		]);
		expect(spec.init.method).toBe("POST");
		expect(JSON.parse(spec.init.body as string)).toEqual({
			name: "BurrowGate-Banned-IPs",
			type: "IPV4_ADDRESSES",
			items: [{ type: "IP_ADDRESS", value: "203.0.113.1" }],
		});
	});

	test("update PUTs to the list's id with the given name", () => {
		const spec = unifiUpdateTrafficMatchingListRequest(baseConfig, "test-key", "list-123", "BurrowGate-Banned-IPs (IPv6)", "IPV6_ADDRESSES", [
			{ type: "SUBNET", value: "2001:db8::/64" },
		]);
		expect(spec.url).toBe("https://192.168.1.1/proxy/network/integration/v1/sites/88f7af54-98f8-306a-a1c7-c9349722b1f6/traffic-matching-lists/list-123");
		expect(spec.init.method).toBe("PUT");
		expect(JSON.parse(spec.init.body as string)).toEqual({
			name: "BurrowGate-Banned-IPs (IPv6)",
			type: "IPV6_ADDRESSES",
			items: [{ type: "SUBNET", value: "2001:db8::/64" }],
		});
	});
});

describe("unifiTrafficMatchingListName", () => {
	test("suffixes only the IPv6 list, keeping the IPv4 list's name unchanged - names must be unique per site regardless of type", () => {
		expect(unifiTrafficMatchingListName("BurrowGate-Banned-IPs", "IPV4_ADDRESSES")).toBe("BurrowGate-Banned-IPs");
		expect(unifiTrafficMatchingListName("BurrowGate-Banned-IPs", "IPV6_ADDRESSES")).toBe("BurrowGate-Banned-IPs (IPv6)");
	});
});

describe("unifiDeleteTrafficMatchingListRequest", () => {
	test("DELETEs the list's id", () => {
		const spec = unifiDeleteTrafficMatchingListRequest(baseConfig, "test-key", "list-123");
		expect(spec.url).toBe("https://192.168.1.1/proxy/network/integration/v1/sites/88f7af54-98f8-306a-a1c7-c9349722b1f6/traffic-matching-lists/list-123");
		expect(spec.init.method).toBe("DELETE");
		expect((spec.init.headers as Record<string, string>)["X-API-Key"]).toBe("test-key");
	});
});

describe("unifiListSitesRequest", () => {
	test("builds the integration API sites URL, separate from the site-scoped traffic-matching-lists path", () => {
		const spec = unifiListSitesRequest(baseConfig, "test-key");
		expect(spec.url).toBe("https://192.168.1.1/proxy/network/integration/v1/sites");
		expect((spec.init.headers as Record<string, string>)["X-API-Key"]).toBe("test-key");
	});
});

describe("parseUnifiSitesResponse", () => {
	test("extracts id/name pairs from a { data: [...] } envelope", () => {
		expect(parseUnifiSitesResponse({ data: [{ id: "abc-123", name: "Default" }] })).toEqual([{ id: "abc-123", name: "Default" }]);
	});

	test("falls back to desc/description when name is absent, and to id when both are absent", () => {
		expect(parseUnifiSitesResponse([{ id: "s1", desc: "Home" }])).toEqual([{ id: "s1", name: "Home" }]);
		expect(parseUnifiSitesResponse([{ id: "s2" }])).toEqual([{ id: "s2", name: "s2" }]);
	});
});

describe("unifiTestConnection", () => {
	test("fails fast with an actionable message when no site is selected, before any network call", async () => {
		const configJson = JSON.stringify({ controllerUrl: "https://192.168.1.1", apiBasePath: "/proxy/network", apiKeyEncrypted: "v1.a.b", site: "" });
		const result = await unifiTestConnection(configJson);
		expect(result.ok).toBe(false);
		expect(result.message).toContain("Load sites");
	});
});

describe("parseUnifiListEnvelope", () => {
	test("accepts a bare array response", () => {
		expect(parseUnifiListEnvelope([{ name: "a" }])).toEqual([{ name: "a" }]);
	});

	test("accepts a { data: [...] } envelope", () => {
		expect(parseUnifiListEnvelope({ data: [{ name: "b" }] })).toEqual([{ name: "b" }]);
	});

	test("returns an empty array for an unrecognized shape", () => {
		expect(parseUnifiListEnvelope({ unexpected: true })).toEqual([]);
		expect(parseUnifiListEnvelope(null)).toEqual([]);
	});
});
