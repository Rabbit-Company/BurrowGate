import { beforeAll, describe, expect, test } from "bun:test";
import { db } from "../src/db/client.ts";
import { searchSql } from "../src/db/search-sql.ts";
import { evaluateSearch, parseSearch, SearchSyntaxError, type SearchSchema } from "../src/services/search-query.ts";
import { logSearchSchema } from "../src/services/search-schemas.ts";

interface Row {
	id: string;
	path: string;
	ip: string;
	username: string | null;
	status: number;
	latency: number | null;
	country: string | null;
}

const rows: Row[] = [
	{ id: "r1", path: "/health", ip: "10.0.0.5", username: null, status: 200, latency: 3, country: "SI" },
	{ id: "r2", path: "/healthz", ip: "10.0.1.9", username: "", status: 200, latency: 4, country: null },
	{ id: "r3", path: "/api/login", ip: "192.168.1.20", username: "alice", status: 401, latency: 120, country: "DE" },
	{ id: "r4", path: "/api/orders", ip: "192.168.1.21", username: "bob", status: 503, latency: null, country: "DE" },
	{ id: "r5", path: "/static/100%_off.png", ip: "2001:db8::1", username: "Alice", status: 404, latency: 9, country: "US" },
];

const schema: SearchSchema = {
	id: "test",
	label: "Test rows",
	fields: [
		{ name: "path", type: "text", sql: "path", get: (row: Row) => row.path, description: "" },
		{ name: "ip", type: "ip", sql: "ip", get: (row: Row) => row.ip, description: "" },
		{ name: "user", aliases: ["username"], type: "text", sql: "username", get: (row: Row) => row.username, description: "" },
		{ name: "status", type: "status", sql: "status", get: (row: Row) => row.status, description: "" },
		{ name: "latency", type: "number", sql: "latency", get: (row: Row) => row.latency, description: "" },
		{ name: "country", type: "country", sql: "COALESCE(country,'ZZ')", get: (row: Row) => row.country ?? "ZZ", description: "" },
	],
	textSql: ["path", "ip", "username"],
	exactSql: ["id"],
	text: (row: Row) => [row.id, row.path, row.ip, row.username ?? ""].join(" "),
};

beforeAll(async () => {
	await db`CREATE TABLE search_query_test_rows (id TEXT PRIMARY KEY, path TEXT, ip TEXT, username TEXT, status INTEGER, latency INTEGER, country TEXT)`;
	for (const row of rows) {
		await db`INSERT INTO search_query_test_rows (id, path, ip, username, status, latency, country) VALUES (${row.id}, ${row.path}, ${row.ip}, ${row.username}, ${row.status}, ${row.latency}, ${row.country})`;
	}
});

async function search(query: string): Promise<string[]> {
	const { node } = parseSearch(query, schema);
	const sqlIds = ((await db`SELECT id FROM search_query_test_rows WHERE 1=1 ${searchSql(node, schema)} ORDER BY id`) as Array<{ id: string }>).map(
		(row) => row.id,
	);
	const memoryIds = rows.filter((row) => evaluateSearch(node, schema, row)).map((row) => row.id);
	expect(memoryIds).toEqual(sqlIds);
	return sqlIds;
}

describe("dashboard search", () => {
	test("excludes values, including with wildcards", async () => {
		expect(await search("-path:/health")).toEqual(["r2", "r3", "r4", "r5"]);
		expect(await search("-path:/health*")).toEqual(["r3", "r4", "r5"]);
		expect(await search("NOT path:/health*")).toEqual(["r3", "r4", "r5"]);
	});

	test("finds rows with and without a value, keeping empty rows on negation", async () => {
		expect(await search("user:*")).toEqual(["r3", "r4", "r5"]);
		expect(await search("-user:*")).toEqual(["r1", "r2"]);
		expect(await search("-user:alice")).toEqual(["r1", "r2", "r4"]);
	});

	test("compares numbers and status classes, skipping missing numbers", async () => {
		expect(await search("status:>=500")).toEqual(["r4"]);
		expect(await search("status:4xx")).toEqual(["r3", "r5"]);
		expect(await search("status:400..404")).toEqual(["r3", "r5"]);
		expect(await search("latency:<10")).toEqual(["r1", "r2", "r5"]);
		expect(await search("-latency:*")).toEqual(["r4"]);
		expect(await search("-latency:>100")).toEqual(["r1", "r2", "r4", "r5"]);
	});

	test("combines terms with AND, OR and groups", async () => {
		expect(await search("path:/api/* -status:5xx")).toEqual(["r3"]);
		expect(await search("path:(/health OR /healthz)")).toEqual(["r1", "r2"]);
		expect(await search("-path:(/health OR /healthz) AND (user:bob OR status:404)")).toEqual(["r4", "r5"]);
		expect(await search("country:de OR country:zz")).toEqual(["r2", "r3", "r4"]);
	});

	test("matches IPv4 CIDR and wildcard addresses", async () => {
		expect(await search("ip:10.0.0.0/8")).toEqual(["r1", "r2"]);
		expect(await search("ip:10.0.0.0/24")).toEqual(["r1"]);
		expect(await search("ip:192.168.1.2?")).toEqual(["r3", "r4"]);
	});

	test("treats LIKE metacharacters and escaped wildcards literally", async () => {
		expect(await search("path:/static/100%_off.png")).toEqual(["r5"]);
		expect(await search("path:/static/100%*")).toEqual(["r5"]);
		expect(await search("path:/api/\\*")).toEqual([]);
		expect(await search("%_")).toEqual(["r5"]);
	});

	test("keeps free text compatible, including IPv6 and quoted phrases", async () => {
		expect(await search("health")).toEqual(["r1", "r2"]);
		expect(await search("2001:db8::1")).toEqual(["r5"]);
		expect(await search('"api/log"')).toEqual(["r3"]);
		expect(await search('path:"/api/login"')).toEqual(["r3"]);
		expect(await search("r4")).toEqual(["r4"]);
	});

	test("searches unknown field prefixes as text and warns", () => {
		const parsed = parseSearch("usr:alice", schema);
		expect(parsed.node).toEqual({ kind: "text", value: "usr:alice" });
		expect(parsed.warnings[0]).toContain('"usr" is not a field here');
		expect(parseSearch("https://example.test", schema).warnings).toEqual([]);
	});

	test("reports syntax errors with a position", () => {
		const cases: Array<[string, string]> = [
			["(path:/a", "Missing closing parenthesis"],
			["path:/a)", "Unmatched closing parenthesis"],
			["status:abc", "status must be a number"],
			["latency:5*", "status"],
			["ip:10.1.0.0/12", "CIDR"],
			["path:", "Missing value for path"],
			['user:"alice', "Unterminated quoted value"],
			["a OR", "OR must be followed by a term"],
			["status:500..400", "runs backwards"],
		];
		for (const [query, message] of cases) {
			let error: unknown;
			try {
				parseSearch(query, schema);
			} catch (caught) {
				error = caught;
			}
			expect(error).toBeInstanceOf(SearchSyntaxError);
			if (message !== "status") expect((error as Error).message).toContain(message);
		}
	});

	test("bounds query size and nesting", () => {
		expect(() => parseSearch("a ".repeat(65), schema)).toThrow("at most 64 terms");
		expect(() => parseSearch(`${"(".repeat(9)}a${")".repeat(9)}`, schema)).toThrow("nest at most");
		expect(() => parseSearch("x".repeat(2_001), schema)).toThrow("at most 2000 characters");
	});

	test("filters log entries by level, message and metadata paths", () => {
		const entries = [
			{ timestamp: 1, level: "info", message: "Health check passed", metadata: { metadata: { siteId: "s1", status: 200 } } },
			{ timestamp: 2, level: "warn", message: "Origin slow", metadata: { siteId: "s2", error: { code: "ETIMEDOUT" } } },
			{ timestamp: 3, level: "error", message: "Origin failed", metadata: { siteId: "s2" } },
		];
		const run = (query: string) =>
			entries.filter((entry) => evaluateSearch(parseSearch(query, logSearchSchema).node, logSearchSchema, entry)).map((entry) => entry.timestamp);
		expect(run("-message:health*")).toEqual([2, 3]);
		expect(run("siteId:s2 -level:error")).toEqual([2]);
		expect(run("error.code:*")).toEqual([2]);
		expect(run("status:200")).toEqual([1]);
		expect(run("metadata.siteId:(s1 OR s2) -level:warn")).toEqual([1, 3]);
	});
});
