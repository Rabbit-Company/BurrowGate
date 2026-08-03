import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { brotliDecompressSync, gunzipSync } from "node:zlib";

const source = readFileSync("public/world.svg");
const markup = source.toString("utf8");

describe("GeoIP world map", () => {
	test("contains unique country paths", () => {
		const ids = [...markup.matchAll(/\sid="([a-z]{2})"/gu)].map((match) => match[1]);
		expect(ids.length).toBeGreaterThan(240);
		expect(new Set(ids).size).toBe(ids.length);
		expect(ids).toContain("si");
		expect(ids).toContain("us");
	});

	test("compressed variants match the source", () => {
		expect(gunzipSync(readFileSync("public/world.svg.gz"))).toEqual(source);
		expect(brotliDecompressSync(readFileSync("public/world.svg.br"))).toEqual(source);
	});
});
