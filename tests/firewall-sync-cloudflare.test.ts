import { afterEach, describe, expect, test } from "bun:test";
import {
	buildCloudflareRequest,
	canonicalCloudflareIp,
	cloudflareCreateItemsBody,
	cloudflareDeleteItemsBody,
	cloudflareErrorMessage,
	cloudflareListItemValue,
	CloudflareApiError,
	cloudflareOwnerComment,
	cloudflareReconcile,
	cloudflareRuleExpression,
	cloudflareTeardown,
	cloudflareTestConnection,
	computeCloudflareListDiff,
	isRetryableSubmitError,
	isValidCloudflareListName,
	parseCloudflareAccounts,
	parseCloudflareOperationStatus,
	parseCloudflareProviderConfig,
	resetCloudflareVerifiedLists,
} from "../src/services/firewall-sync/cloudflare-adapter.ts";
import { encryptSecret } from "../src/services/secret-encryption-service.ts";
import { formatIp, parseIp } from "../src/utils/ip.ts";

const ACCOUNT_ID = "0123456789abcdef0123456789abcdef";
const OWNER = "owner0000000000a";
const OTHER = "owner0000000000b";
const MINE = cloudflareOwnerComment(OWNER);
const THEIRS = cloudflareOwnerComment(OTHER);
const originalFetch = globalThis.fetch;

afterEach(() => {
	globalThis.fetch = originalFetch;
	resetCloudflareVerifiedLists();
});

async function providerConfigJson(): Promise<string> {
	return JSON.stringify({ accountId: ACCOUNT_ID, ownerId: OWNER, apiTokenEncrypted: await encryptSecret("secret-token") });
}

describe("formatIp", () => {
	test("formats IPv4 and compresses the longest IPv6 zero run", () => {
		expect(formatIp(4, parseIp("203.0.113.7")!.value)).toBe("203.0.113.7");
		expect(formatIp(6, parseIp("2001:0DB8:0000:0000:0001:0000:0000:0001")!.value)).toBe("2001:db8::1:0:0:1");
		expect(formatIp(6, parseIp("2001:db8:0:1:1:1:1:1")!.value)).toBe("2001:db8:0:1:1:1:1:1");
		expect(formatIp(6, 0n)).toBe("::");
		expect(formatIp(6, 1n)).toBe("::1");
	});
});

describe("parseCloudflareProviderConfig", () => {
	test("applies the default list name and lowercases the account ID", () => {
		const cfg = parseCloudflareProviderConfig({ accountId: ` ${ACCOUNT_ID.toUpperCase()} ` });
		expect(cfg.accountId).toBe(ACCOUNT_ID);
		expect(cfg.listName).toBe("burrowgate_banned_ips");
		expect(cfg.apiTokenEncrypted).toBe("");
	});

	test("validates list names against Cloudflare's naming rule", () => {
		expect(isValidCloudflareListName("burrowgate_banned_ips")).toBe(true);
		expect(isValidCloudflareListName("Banned-IPs")).toBe(false);
		expect(isValidCloudflareListName("a".repeat(51))).toBe(false);
	});
});

describe("cloudflareListItemValue", () => {
	test("sends host prefixes as bare addresses and masks host bits off ranges", () => {
		expect(cloudflareListItemValue("203.0.113.5")).toBe("203.0.113.5");
		expect(cloudflareListItemValue("203.0.113.5/32")).toBe("203.0.113.5");
		expect(cloudflareListItemValue("203.0.113.5/24")).toBe("203.0.113.0/24");
		expect(cloudflareListItemValue("2001:DB8::5/128")).toBe("2001:db8::5");
		expect(cloudflareListItemValue("2001:db8:1:2::/64")).toBe("2001:db8:1:2::/64");
	});

	test("drops ranges wider than Cloudflare accepts (IPv4 /8, IPv6 /12) and garbage", () => {
		expect(cloudflareListItemValue("10.0.0.0/7")).toBeNull();
		expect(cloudflareListItemValue("2000::/11")).toBeNull();
		expect(cloudflareListItemValue("not-an-ip")).toBeNull();
	});
});

describe("computeCloudflareListDiff", () => {
	test("keeps its own matching items, deletes its own stale and duplicate ones, and creates only what is missing", () => {
		const diff = computeCloudflareListDiff(
			["203.0.113.1", "203.0.113.2/32", "2001:db8::1", "198.51.100.0/24"],
			[
				{ id: "a", ip: "203.0.113.1/32", comment: MINE },
				{ id: "b", ip: "203.0.113.1", comment: MINE },
				{ id: "c", ip: "2001:0db8::0001", comment: MINE },
				{ id: "d", ip: "192.0.2.9", comment: MINE },
				{ id: "e", ip: "garbage", comment: MINE },
			],
			OWNER,
		);
		expect(diff.toDelete).toEqual(["b", "d", "e"]);
		expect(diff.toCreate).toEqual(["203.0.113.2", "198.51.100.0/24"]);
	});

	test("never deletes items owned by another instance or added by hand", () => {
		const diff = computeCloudflareListDiff(
			[],
			[
				{ id: "theirs", ip: "192.0.2.1", comment: THEIRS },
				{ id: "manual", ip: "192.0.2.2", comment: "office block" },
				{ id: "bare", ip: "192.0.2.3" },
				{ id: "mine", ip: "192.0.2.4", comment: MINE },
			],
			OWNER,
		);
		expect(diff).toEqual({ toDelete: ["mine"], toCreate: [] });
	});

	test("does not re-add an IP another instance already lists", () => {
		const diff = computeCloudflareListDiff(["192.0.2.1", "192.0.2.5"], [{ id: "theirs", ip: "192.0.2.1", comment: THEIRS }], OWNER);
		expect(diff).toEqual({ toDelete: [], toCreate: ["192.0.2.5"] });
	});

	test("deletes its own copy of an IP it no longer bans even when another instance also lists it", () => {
		const diff = computeCloudflareListDiff(
			[],
			[
				{ id: "theirs", ip: "192.0.2.1", comment: THEIRS },
				{ id: "mine", ip: "192.0.2.1", comment: MINE },
			],
			OWNER,
		);
		expect(diff).toEqual({ toDelete: ["mine"], toCreate: [] });
	});

	test("produces no changes when the list already matches", () => {
		expect(computeCloudflareListDiff(["203.0.113.1"], [{ id: "a", ip: "203.0.113.1", comment: MINE }], OWNER)).toEqual({ toDelete: [], toCreate: [] });
	});

	test("dedupes desired entries that canonicalize to the same value", () => {
		expect(computeCloudflareListDiff(["203.0.113.1", "203.0.113.1/32"], [], OWNER).toCreate).toEqual(["203.0.113.1"]);
	});
});

describe("request building and parsing", () => {
	test("uses a bearer token against the v4 API root", () => {
		const spec = buildCloudflareRequest("token-1", "POST", `/accounts/${ACCOUNT_ID}/rules/lists`, { name: "x" });
		expect(spec.url).toBe(`https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/rules/lists`);
		expect(spec.init.method).toBe("POST");
		const headers = spec.init.headers as Record<string, string>;
		expect(headers.authorization).toBe("Bearer token-1");
		expect(headers["content-type"]).toBe("application/json");
		expect(JSON.parse(spec.init.body as string)).toEqual({ name: "x" });
	});

	test("builds bulk item bodies in the shapes the Lists API expects", () => {
		expect(cloudflareDeleteItemsBody(["a", "b"])).toEqual({ items: [{ id: "a" }, { id: "b" }] });
		expect(cloudflareCreateItemsBody(["203.0.113.1"], OWNER)).toEqual([{ ip: "203.0.113.1", comment: "Managed by BurrowGate (owner0000000000a)" }]);
	});

	test("parses bulk operation states", () => {
		expect(parseCloudflareOperationStatus({ status: "pending" })).toEqual({ done: false });
		expect(parseCloudflareOperationStatus({ status: "running" })).toEqual({ done: false });
		expect(parseCloudflareOperationStatus({ status: "completed" })).toEqual({ done: true, error: null });
		expect(parseCloudflareOperationStatus({ status: "failed", error: "quota exceeded" })).toEqual({ done: true, error: "quota exceeded" });
	});

	test("formats API errors from the envelope", () => {
		expect(cloudflareErrorMessage(403, { success: false, errors: [{ code: 10000, message: "Authentication error" }] }, "")).toBe(
			"HTTP 403: Authentication error (10000)",
		);
		expect(cloudflareErrorMessage(502, null, "<html>bad gateway</html>")).toBe("HTTP 502: <html>bad gateway</html>");
	});

	test("retries bulk submits on conflicts, rate limits and outages but not on request or auth errors", () => {
		expect(isRetryableSubmitError(new CloudflareApiError("pending operation", 409))).toBe(true);
		expect(isRetryableSubmitError(new CloudflareApiError("rate limited", 429))).toBe(true);
		expect(isRetryableSubmitError(new CloudflareApiError("bad gateway", 502))).toBe(true);
		expect(isRetryableSubmitError(new TypeError("fetch failed"))).toBe(true);
		expect(isRetryableSubmitError(new CloudflareApiError("bad request", 400))).toBe(false);
		expect(isRetryableSubmitError(new CloudflareApiError("forbidden", 403))).toBe(false);
	});

	test("parses accounts and builds the rule expression", () => {
		expect(parseCloudflareAccounts([{ id: ACCOUNT_ID, name: "Acme" }, { id: "" }, { id: "x" }])).toEqual([
			{ id: ACCOUNT_ID, name: "Acme" },
			{ id: "x", name: "x" },
		]);
		expect(cloudflareRuleExpression("burrowgate_banned_ips")).toBe("(ip.src in $burrowgate_banned_ips)");
	});
});

describe("cloudflareTestConnection", () => {
	test("fails fast without a network call when the account ID is missing", async () => {
		globalThis.fetch = (async () => {
			throw new Error("unexpected network call");
		}) as unknown as typeof fetch;
		const result = await cloudflareTestConnection(JSON.stringify({ apiTokenEncrypted: "v1.a.b", accountId: "", ownerId: OWNER }));
		expect(result.ok).toBe(false);
		expect(result.message).toContain("Load accounts");
	});

	test("refuses to run without an owner ID", async () => {
		const result = await cloudflareTestConnection(JSON.stringify({ apiTokenEncrypted: "v1.a.b", accountId: ACCOUNT_ID }));
		expect(result.ok).toBe(false);
		expect(result.message).toContain("owner ID");
	});
});

describe("cloudflareReconcile", () => {
	function ok(result: unknown, resultInfo?: unknown): Response {
		return new Response(JSON.stringify({ success: true, errors: [], messages: [], result, ...(resultInfo ? { result_info: resultInfo } : {}) }), {
			status: 200,
		});
	}

	test("creates the list when missing, then diffs items with one delete and one create bulk operation", async () => {
		const calls: Array<{ method: string; path: string; body: unknown }> = [];
		globalThis.fetch = (async (input: unknown, init: RequestInit) => {
			const url = new URL(String(input));
			const path = url.pathname.replace("/client/v4", "");
			const method = init.method ?? "GET";
			calls.push({ method, path: `${path}${url.search}`, body: init.body ? JSON.parse(String(init.body)) : undefined });
			expect((init.headers as Record<string, string>).authorization).toBe("Bearer secret-token");
			if (method === "GET" && path === `/accounts/${ACCOUNT_ID}/rules/lists`)
				return ok([{ id: "list-1", name: "burrowgate_banned_ips", kind: "ip", num_items: 3 }]);
			if (method === "GET" && path === `/accounts/${ACCOUNT_ID}/rules/lists/list-1/items`) {
				if (!url.searchParams.get("cursor"))
					return ok(
						[
							{ id: "i1", ip: "203.0.113.1", comment: MINE },
							{ id: "i2", ip: "192.0.2.50", comment: MINE },
							{ id: "i4", ip: "192.0.2.60", comment: THEIRS },
						],
						{ cursors: { after: "page-2" } },
					);
				return ok([{ id: "i3", ip: "2001:db8::1", comment: MINE }], { cursors: {} });
			}
			if ((method === "DELETE" || method === "POST") && path === `/accounts/${ACCOUNT_ID}/rules/lists/list-1/items`)
				return ok({ operation_id: `op-${method}` });
			if (method === "GET" && path.startsWith(`/accounts/${ACCOUNT_ID}/rules/lists/bulk_operations/`)) return ok({ id: "op", status: "completed" });
			throw new Error(`unexpected ${method} ${path}`);
		}) as unknown as typeof fetch;

		const configJson = await providerConfigJson();
		await cloudflareReconcile(configJson, ["203.0.113.1", "2001:db8::1", "198.51.100.7", "10.0.0.0/7"]);

		const writes = calls.filter((call) => call.method !== "GET");
		expect(writes).toEqual([
			{ method: "DELETE", path: `/accounts/${ACCOUNT_ID}/rules/lists/list-1/items`, body: { items: [{ id: "i2" }] } },
			{ method: "POST", path: `/accounts/${ACCOUNT_ID}/rules/lists/list-1/items`, body: [{ ip: "198.51.100.7", comment: MINE }] },
		]);
		expect(calls.filter((call) => call.path.includes("bulk_operations")).map((call) => call.path)).toEqual([
			`/accounts/${ACCOUNT_ID}/rules/lists/bulk_operations/op-DELETE`,
			`/accounts/${ACCOUNT_ID}/rules/lists/bulk_operations/op-POST`,
		]);

		calls.length = 0;
		globalThis.fetch = (async (input: unknown, init: RequestInit) => {
			const path = new URL(String(input)).pathname.replace("/client/v4", "");
			const method = init.method ?? "GET";
			calls.push({ method, path, body: init.body ? JSON.parse(String(init.body)) : undefined });
			if (method === "GET" && path === `/accounts/${ACCOUNT_ID}/rules/lists`) return ok([]);
			if (method === "POST" && path === `/accounts/${ACCOUNT_ID}/rules/lists`) return ok({ id: "list-new", name: "burrowgate_banned_ips", kind: "ip" });
			if (method === "POST" && path === `/accounts/${ACCOUNT_ID}/rules/lists/list-new/items`) return ok({ operation_id: "op-1" });
			if (method === "GET" && path === `/accounts/${ACCOUNT_ID}/rules/lists/bulk_operations/op-1`) return ok({ id: "op-1", status: "completed" });
			throw new Error(`unexpected ${method} ${path}`);
		}) as unknown as typeof fetch;

		await cloudflareReconcile(configJson, ["203.0.113.1"]);
		expect(calls.map((call) => `${call.method} ${call.path}`)).toEqual([
			`GET /accounts/${ACCOUNT_ID}/rules/lists`,
			`POST /accounts/${ACCOUNT_ID}/rules/lists`,
			`POST /accounts/${ACCOUNT_ID}/rules/lists/list-new/items`,
			`GET /accounts/${ACCOUNT_ID}/rules/lists/bulk_operations/op-1`,
		]);
		expect(calls[1]!.body).toMatchObject({ name: "burrowgate_banned_ips", kind: "ip" });
	});

	test("surfaces a failed bulk operation as an error so the next tick retries", async () => {
		globalThis.fetch = (async (input: unknown, init: RequestInit) => {
			const path = new URL(String(input)).pathname.replace("/client/v4", "");
			const method = init.method ?? "GET";
			if (method === "GET" && path === `/accounts/${ACCOUNT_ID}/rules/lists`)
				return ok([{ id: "list-1", name: "burrowgate_banned_ips", kind: "ip", num_items: 0 }]);
			if (method === "POST") return ok({ operation_id: "op-1" });
			return ok({ id: "op-1", status: "failed", error: "list item limit reached" });
		}) as unknown as typeof fetch;
		const configJson = await providerConfigJson();
		await expect(cloudflareReconcile(configJson, ["203.0.113.1"])).rejects.toThrow("list item limit reached");
	});

	test("refuses to manage a same-named list that is not an IP list", async () => {
		globalThis.fetch = (async () => ok([{ id: "list-1", name: "burrowgate_banned_ips", kind: "hostname", num_items: 0 }])) as unknown as typeof fetch;
		const configJson = await providerConfigJson();
		await expect(cloudflareReconcile(configJson, ["203.0.113.1"])).rejects.toThrow("not IPs");
	});

	test("skips the item scan while the list is unchanged, and re-checks once another writer changes it", async () => {
		let list = { id: "list-1", name: "burrowgate_banned_ips", kind: "ip", num_items: 1, modified_on: "2026-11-19T10:00:00Z" };
		let items: unknown[] = [{ id: "i1", ip: "203.0.113.1", comment: THEIRS }];
		const calls: string[] = [];
		globalThis.fetch = (async (input: unknown, init: RequestInit) => {
			const path = new URL(String(input)).pathname.replace("/client/v4", "");
			const method = init.method ?? "GET";
			calls.push(`${method} ${path}`);
			if (method === "GET" && path === `/accounts/${ACCOUNT_ID}/rules/lists`) return ok([list]);
			if (method === "GET" && path.endsWith("/items")) return ok(items, { cursors: {} });
			if (method === "POST") return ok({ operation_id: "op-1" });
			if (method === "GET" && path.includes("bulk_operations")) return ok({ id: "op-1", status: "completed" });
			throw new Error(`unexpected ${method} ${path}`);
		}) as unknown as typeof fetch;
		const configJson = await providerConfigJson();

		await cloudflareReconcile(configJson, ["203.0.113.1"]);
		expect(calls.filter((call) => call.startsWith("POST"))).toEqual([]);
		calls.length = 0;

		await cloudflareReconcile(configJson, ["203.0.113.1"]);
		expect(calls).toEqual([`GET /accounts/${ACCOUNT_ID}/rules/lists`]);
		calls.length = 0;

		list = { ...list, num_items: 0, modified_on: "2026-11-19T10:05:00Z" };
		items = [];
		await cloudflareReconcile(configJson, ["203.0.113.1"]);
		expect(calls).toContain(`POST /accounts/${ACCOUNT_ID}/rules/lists/list-1/items`);
		calls.length = 0;

		list = { ...list, num_items: 1, modified_on: "2026-11-19T10:05:01Z" };
		items = [{ id: "i9", ip: "203.0.113.1", comment: MINE }];
		await cloudflareReconcile(configJson, ["203.0.113.1"]);
		await cloudflareReconcile(configJson, ["203.0.113.1"], { force: true });
		expect(calls.filter((call) => call.endsWith("/items"))).toHaveLength(2);
	});

	test("retries a bulk submit rejected while another instance's operation is pending", async () => {
		let submits = 0;
		globalThis.fetch = (async (input: unknown, init: RequestInit) => {
			const path = new URL(String(input)).pathname.replace("/client/v4", "");
			const method = init.method ?? "GET";
			if (method === "GET" && path === `/accounts/${ACCOUNT_ID}/rules/lists`)
				return ok([{ id: "list-1", name: "burrowgate_banned_ips", kind: "ip", num_items: 0, modified_on: "x" }]);
			if (method === "POST") {
				submits += 1;
				if (submits === 1)
					return new Response(JSON.stringify({ success: false, errors: [{ code: 10026, message: "pending bulk operation" }] }), { status: 409 });
				return ok({ operation_id: "op-1" });
			}
			return ok({ id: "op-1", status: "completed" });
		}) as unknown as typeof fetch;
		await cloudflareReconcile(await providerConfigJson(), ["203.0.113.1"]);
		expect(submits).toBe(2);
	});
});

describe("cloudflareTeardown", () => {
	function ok(result: unknown, resultInfo?: unknown): Response {
		return new Response(JSON.stringify({ success: true, errors: [], result, ...(resultInfo ? { result_info: resultInfo } : {}) }), { status: 200 });
	}

	test("removes only its own items and keeps the list while other instances still use it", async () => {
		const calls: Array<{ method: string; path: string; body: unknown }> = [];
		let numItems = 3;
		globalThis.fetch = (async (input: unknown, init: RequestInit) => {
			const path = new URL(String(input)).pathname.replace("/client/v4", "");
			const method = init.method ?? "GET";
			calls.push({ method, path, body: init.body ? JSON.parse(String(init.body)) : undefined });
			if (method === "GET" && path === `/accounts/${ACCOUNT_ID}/rules/lists`)
				return ok([{ id: "list-1", name: "burrowgate_banned_ips", kind: "ip", num_items: numItems, modified_on: "x" }]);
			if (method === "GET" && path.endsWith("/items"))
				return ok(
					[
						{ id: "mine", ip: "192.0.2.1", comment: MINE },
						{ id: "theirs", ip: "192.0.2.2", comment: THEIRS },
						{ id: "manual", ip: "192.0.2.3" },
					],
					{ cursors: {} },
				);
			if (method === "DELETE" && path.endsWith("/items")) {
				numItems = 2;
				return ok({ operation_id: "op-1" });
			}
			if (method === "GET" && path.includes("bulk_operations")) return ok({ id: "op-1", status: "completed" });
			throw new Error(`unexpected ${method} ${path}`);
		}) as unknown as typeof fetch;
		await cloudflareTeardown(await providerConfigJson());
		const writes = calls.filter((call) => call.method !== "GET");
		expect(writes).toEqual([{ method: "DELETE", path: `/accounts/${ACCOUNT_ID}/rules/lists/list-1/items`, body: { items: [{ id: "mine" }] } }]);
	});

	test("deletes the list once its own items were the last ones", async () => {
		const writes: string[] = [];
		let numItems = 1;
		globalThis.fetch = (async (input: unknown, init: RequestInit) => {
			const path = new URL(String(input)).pathname.replace("/client/v4", "");
			const method = init.method ?? "GET";
			if (method !== "GET") writes.push(`${method} ${path}`);
			if (method === "GET" && path === `/accounts/${ACCOUNT_ID}/rules/lists`)
				return ok([{ id: "list-1", name: "burrowgate_banned_ips", kind: "ip", num_items: numItems, modified_on: "x" }]);
			if (method === "GET" && path.endsWith("/items")) return ok([{ id: "mine", ip: "192.0.2.1", comment: MINE }], { cursors: {} });
			if (method === "DELETE" && path.endsWith("/items")) {
				numItems = 0;
				return ok({ operation_id: "op-1" });
			}
			if (method === "GET" && path.includes("bulk_operations")) return ok({ id: "op-1", status: "completed" });
			if (method === "DELETE" && path === `/accounts/${ACCOUNT_ID}/rules/lists/list-1`) return ok({ id: "list-1" });
			throw new Error(`unexpected ${method} ${path}`);
		}) as unknown as typeof fetch;
		await cloudflareTeardown(await providerConfigJson());
		expect(writes).toEqual([`DELETE /accounts/${ACCOUNT_ID}/rules/lists/list-1/items`, `DELETE /accounts/${ACCOUNT_ID}/rules/lists/list-1`]);
	});
});
