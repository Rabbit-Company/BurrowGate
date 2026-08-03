import { describe, expect, test } from "bun:test";
import { requestIsSecure, requestTransport, secureCookieForRequest, withRequestTransport } from "../src/config.ts";

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
