import { describe, expect, test } from "bun:test";
import { IP_EXTRACTION_PRESETS, ipExtract } from "@rabbit-company/web-middleware/ip-extract";
import { SUPPORTED_IP_EXTRACTION_PRESETS, parseIpExtractionPreset, supportedIpExtractionPreset } from "../src/config.ts";
import { buildOpenApiDocument } from "../src/services/openapi-service.ts";
import { adminPage } from "../src/ui/admin-page.ts";

const supported = [...SUPPORTED_IP_EXTRACTION_PRESETS] as string[];

function enumsInOpenApi(): string[][] {
	const document = buildOpenApiDocument("http://admin.test");
	const found: string[][] = [];
	for (const schema of Object.values(document.components.schemas)) {
		const preset = schema.properties?.ipExtractionPreset;
		if (preset?.enum) found.push([...preset.enum] as string[]);
	}
	return found;
}

describe("IP extraction presets", () => {
	test("every supported preset is a real preset the library ships", () => {
		const library = Object.keys(IP_EXTRACTION_PRESETS);
		expect(supported.filter((preset) => !library.includes(preset))).toEqual([]);
	});

	// A preset decides which forwarding headers are believed, so a library release that adds one
	// must not widen what this gateway accepts until someone has judged it safe to expose.
	test("a preset the library ships is not accepted until it is listed here", () => {
		const library = Object.keys(IP_EXTRACTION_PRESETS);
		const unlisted = library.filter((preset) => !supported.includes(preset));
		expect(unlisted.length).toBeGreaterThan(0);

		for (const preset of unlisted) {
			expect(() => parseIpExtractionPreset(preset)).toThrow(/Unsupported/u);
		}
	});

	test("the library's burrowgate preset stays out, because it trusts a client-supplied IP header", () => {
		expect(Object.keys(IP_EXTRACTION_PRESETS)).toContain("burrowgate");
		expect(supported).not.toContain("burrowgate");
		expect(() => parseIpExtractionPreset("burrowgate")).toThrow(/Unsupported/u);
	});

	test("unknown values are still rejected and the default still resolves", () => {
		expect(() => parseIpExtractionPreset("made-up")).toThrow(/Unsupported/u);
		expect(parseIpExtractionPreset(undefined)).toBe("direct");
		expect(parseIpExtractionPreset("CloudFlare ")).toBe("cloudflare");
	});

	// A site row can already hold a preset that was accepted by an earlier build. Serving it must
	// not throw, and it must degrade to trusting nothing rather than to trusting a header.
	test("a stored preset that is no longer supported degrades to direct", () => {
		expect(supportedIpExtractionPreset("burrowgate")).toBe("direct");
		expect(supportedIpExtractionPreset("made-up")).toBe("direct");
		expect(supportedIpExtractionPreset(null)).toBe("direct");
		expect(supportedIpExtractionPreset("cloudflare")).toBe("cloudflare");
	});

	test("every supported preset resolves to an extractor the request path can use", () => {
		const extractors = new Map(SUPPORTED_IP_EXTRACTION_PRESETS.map((preset) => [preset, ipExtract(preset)]));
		for (const preset of SUPPORTED_IP_EXTRACTION_PRESETS) expect(extractors.get(supportedIpExtractionPreset(preset))).toBeDefined();
		expect(extractors.get(supportedIpExtractionPreset("burrowgate"))).toBeDefined();
	});

	test("the OpenAPI schema offers exactly the supported presets", () => {
		const enums = enumsInOpenApi();
		expect(enums.length).toBeGreaterThan(0);
		for (const values of enums) expect([...values].sort()).toEqual([...supported].sort());
	});

	test("the dashboard site form offers exactly the supported presets", () => {
		const select = adminPage().match(/<select id="siteIpExtractionPreset"[^>]*>(.*?)<\/select>/su);
		expect(select).not.toBeNull();

		const offered = [...select![1]!.matchAll(/<option value="([^"]+)"/gu)].map((option) => option[1]!);
		expect([...offered].sort()).toEqual([...supported].sort());
	});
});
