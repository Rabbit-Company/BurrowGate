import { describe, expect, test } from "bun:test";
import { captureHeaders, parseCapturedHeaders } from "../src/services/header-capture-service.ts";

describe("captureHeaders", () => {
	test("returns null when there are no headers", () => {
		expect(captureHeaders(new Headers(), { redactAuthHeaders: true, redactedHeaders: [] })).toBeNull();
	});

	test("redacts authorization, cookie, and set-cookie by default when enabled", () => {
		const headers = new Headers({ authorization: "Bearer secret", cookie: "session=abc", "x-custom": "value" });
		const captured = captureHeaders(headers, { redactAuthHeaders: true, redactedHeaders: [] });
		const entries = parseCapturedHeaders(captured?.json);
		expect(entries).toContainEqual(["authorization", "[redacted]"]);
		expect(entries).toContainEqual(["cookie", "[redacted]"]);
		expect(entries).toContainEqual(["x-custom", "value"]);
	});

	test("leaves authorization and cookie intact when redaction is disabled", () => {
		const headers = new Headers({ authorization: "Bearer secret" });
		const captured = captureHeaders(headers, { redactAuthHeaders: false, redactedHeaders: [] });
		expect(parseCapturedHeaders(captured?.json)).toContainEqual(["authorization", "Bearer secret"]);
	});

	test("redacts additional configured header names case-insensitively", () => {
		const headers = new Headers({ "X-Api-Key": "top-secret" });
		const captured = captureHeaders(headers, { redactAuthHeaders: false, redactedHeaders: ["x-api-key"] });
		expect(parseCapturedHeaders(captured?.json)).toContainEqual(["x-api-key", "[redacted]"]);
	});

	test("truncates when the serialized headers exceed the byte ceiling", () => {
		const headers = new Headers();
		for (let index = 0; index < 500; index += 1) headers.set(`x-header-${index}`, "x".repeat(64));
		const captured = captureHeaders(headers, { redactAuthHeaders: true, redactedHeaders: [] });
		expect(captured?.truncated).toBe(true);
		expect(new TextEncoder().encode(captured!.json).byteLength).toBeLessThanOrEqual(8_192);
	});
});

describe("parseCapturedHeaders", () => {
	test("returns an empty array for null, invalid JSON, or malformed shapes", () => {
		expect(parseCapturedHeaders(null)).toEqual([]);
		expect(parseCapturedHeaders("not json")).toEqual([]);
		expect(parseCapturedHeaders('[["only-one-element"]]')).toEqual([]);
	});

	test("round-trips captured entries", () => {
		const captured = captureHeaders(new Headers({ "x-a": "1", "x-b": "2" }), { redactAuthHeaders: true, redactedHeaders: [] });
		expect(parseCapturedHeaders(captured?.json)).toEqual([
			["x-a", "1"],
			["x-b", "2"],
		]);
	});
});
