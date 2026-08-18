import { describe, expect, test } from "bun:test";
import { verifyOriginRequest } from "../src/mod.ts";

const secret = "origin-signing-secret";
const encoder = new TextEncoder();

async function hmacHex(key: string, value: string): Promise<string> {
	const cryptoKey = await crypto.subtle.importKey("raw", encoder.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
	const signature = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(value)));
	let hex = "";
	for (const byte of signature) hex += byte.toString(16).padStart(2, "0");
	return hex;
}

interface SignedRequestOptions {
	method?: string;
	url?: string;
	sessionId?: string;
	clientIp?: string;
	country?: string;
	timestamp?: number;
	authenticatedUser?: string;
	badSignature?: boolean;
	badIdentitySignature?: boolean;
	omit?: string[];
}

async function signedRequest(options: SignedRequestOptions = {}): Promise<Request> {
	const method = options.method ?? "GET";
	const url = options.url ?? "https://origin.example.test/path?x=1";
	const sessionId = options.sessionId ?? "sess_123";
	const clientIp = options.clientIp ?? "203.0.113.10";
	const country = options.country ?? "US";
	const timestamp = options.timestamp ?? Math.floor(Date.now() / 1_000);
	const { pathname, search } = new URL(url);
	const canonical = [method, pathname + search, sessionId, clientIp, country, String(timestamp)].join("\n");
	const signature = options.badSignature ? "0".repeat(64) : await hmacHex(secret, canonical);

	const headers = new Headers();
	headers.set("x-burrowgate-session-id", sessionId);
	headers.set("x-burrowgate-client-ip", clientIp);
	headers.set("x-burrowgate-country", country);
	headers.set("x-burrowgate-timestamp", String(timestamp));
	headers.set("x-burrowgate-signature", signature);
	headers.set("x-burrowgate-verified", "true");
	headers.set("x-burrowgate-access-mode", "verified");

	if (options.authenticatedUser) {
		const identityCanonical = [method, pathname + search, sessionId, clientIp, country, String(timestamp), options.authenticatedUser].join("\n");
		const identitySignature = options.badIdentitySignature ? "0".repeat(64) : await hmacHex(secret, identityCanonical);
		headers.set("x-burrowgate-authenticated-user", options.authenticatedUser);
		headers.set("x-burrowgate-identity-signature", identitySignature);
	}

	for (const name of options.omit ?? []) headers.delete(name);

	return new Request(url, { method, headers });
}

describe("verifyOriginRequest", () => {
	test("accepts a correctly signed request", async () => {
		const request = await signedRequest();
		const result = await verifyOriginRequest(request, secret);
		expect(result).toMatchObject({
			valid: true,
			sessionId: "sess_123",
			clientIp: "203.0.113.10",
			country: "US",
			accessMode: "verified",
			verified: true,
			authenticatedUser: null,
		});
	});

	test("rejects a request with a missing header", async () => {
		const request = await signedRequest({ omit: ["x-burrowgate-country"] });
		const result = await verifyOriginRequest(request, secret);
		expect(result).toEqual({ valid: false, reason: "missing-headers" });
	});

	test("rejects a request with no BurrowGate headers at all (direct/bypassed traffic)", async () => {
		const result = await verifyOriginRequest(new Request("https://origin.example.test/"), secret);
		expect(result).toEqual({ valid: false, reason: "missing-headers" });
	});

	test("rejects a tampered client IP (signature no longer matches)", async () => {
		const request = await signedRequest();
		const tampered = new Request(request, { headers: new Headers(request.headers) });
		tampered.headers.set("x-burrowgate-client-ip", "198.51.100.99");
		const result = await verifyOriginRequest(tampered, secret);
		expect(result).toEqual({ valid: false, reason: "invalid-signature" });
	});

	test("rejects a request signed with a different secret", async () => {
		const request = await signedRequest();
		const result = await verifyOriginRequest(request, "a-different-secret");
		expect(result).toEqual({ valid: false, reason: "invalid-signature" });
	});

	test("rejects a stale timestamp beyond maxAgeSeconds", async () => {
		const request = await signedRequest({ timestamp: Math.floor(Date.now() / 1_000) - 120 });
		const result = await verifyOriginRequest(request, secret, { maxAgeSeconds: 60 });
		expect(result).toEqual({ valid: false, reason: "stale-timestamp" });
	});

	test("accepts a stale timestamp when maxAgeSeconds is 0 (freshness check disabled)", async () => {
		const request = await signedRequest({ timestamp: Math.floor(Date.now() / 1_000) - 3_600 });
		const result = await verifyOriginRequest(request, secret, { maxAgeSeconds: 0 });
		expect(result.valid).toBe(true);
	});

	test("verifies the identity signature and exposes the authenticated user", async () => {
		const request = await signedRequest({ authenticatedUser: "ziga" });
		const result = await verifyOriginRequest(request, secret);
		expect(result).toMatchObject({ valid: true, authenticatedUser: "ziga" });
	});

	test("rejects a tampered authenticated-user claim", async () => {
		const request = await signedRequest({ authenticatedUser: "ziga" });
		const tampered = new Request(request, { headers: new Headers(request.headers) });
		tampered.headers.set("x-burrowgate-authenticated-user", "mallory");
		const result = await verifyOriginRequest(tampered, secret);
		expect(result).toEqual({ valid: false, reason: "invalid-identity-signature" });
	});

	test("rejects an authenticated-user header without a matching identity signature", async () => {
		const request = await signedRequest();
		const tampered = new Request(request, { headers: new Headers(request.headers) });
		tampered.headers.set("x-burrowgate-authenticated-user", "mallory");
		const result = await verifyOriginRequest(tampered, secret);
		expect(result).toEqual({ valid: false, reason: "invalid-identity-signature" });
	});

	test("throws for an empty origin signing secret", async () => {
		const request = await signedRequest();
		await expect(verifyOriginRequest(request, "")).rejects.toThrow(TypeError);
	});

	test("throws for a negative maxAgeSeconds", async () => {
		const request = await signedRequest();
		await expect(verifyOriginRequest(request, secret, { maxAgeSeconds: -1 })).rejects.toThrow(TypeError);
	});
});
