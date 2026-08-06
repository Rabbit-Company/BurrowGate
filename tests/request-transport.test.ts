import { describe, expect, test } from "bun:test";
import { parseIpExtractionPreset, requestIsSecure, requestTransport, secureCookieForRequest, withRequestTransport } from "../src/config.ts";

describe("client IP extraction preset validation", () => {
	test("accepts every supported site preset", () => {
		for (const preset of ["direct", "cloudflare", "aws", "gcp", "azure", "vercel", "nginx", "development"] as const) {
			expect(parseIpExtractionPreset(preset)).toBe(preset);
		}
	});

	test("rejects unknown presets", () => {
		expect(() => parseIpExtractionPreset("untrusted-forwarder")).toThrow("Unsupported IP extraction preset");
	});
});

describe("listener transport context", () => {
	test("HTTP listener wins over a reconstructed HTTPS request URL", async () => {
		const request = new Request("https://example.com/_burrowgate/admin/login");

		await withRequestTransport("http", async () => {
			expect(requestTransport(request)).toBe("http");
			expect(requestIsSecure(request)).toBe(false);
			expect(secureCookieForRequest(request)).toBe(false);
			await Promise.resolve();
			expect(requestTransport(request)).toBe("http");
		});
	});

	test("HTTPS listener marks cookies secure", () => {
		const request = new Request("http://example.com/_burrowgate/admin/login");

		withRequestTransport("https", () => {
			expect(requestTransport(request)).toBe("https");
			expect(requestIsSecure(request)).toBe(true);
			expect(secureCookieForRequest(request)).toBe(true);
		});
	});
});
