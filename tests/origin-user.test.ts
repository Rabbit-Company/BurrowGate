import { afterAll, describe, expect, test } from "bun:test";
import { signOriginUser } from "../packages/burrowgate-auth/src/mod.ts";
import { proxyRequest } from "../src/services/proxy-service.ts";
import type { ResolvedHttpPolicy } from "../src/services/http-policy-service.ts";
import type { SiteRecord } from "../src/types.ts";

const secret = "origin-user-signing-secret-that-is-at-least-32-characters";
let replayed: Record<string, string> | null = null;

const origin = Bun.serve({
	hostname: "127.0.0.1",
	port: 0,
	async fetch(request) {
		const path = new URL(request.url).pathname;
		const signed = await signOriginUser(request, secret, "ziga");
		if (path === "/signed") return new Response("ok", { headers: signed ?? {} });
		if (path === "/forged")
			return new Response("ok", { headers: { "x-burrowgate-origin-user": "admin", "x-burrowgate-origin-user-signature": "0".repeat(64) } });
		if (path === "/wrong-secret") return new Response("ok", { headers: (await signOriginUser(request, "a-different-secret", "ziga")) ?? {} });
		if (path === "/remember") {
			replayed = signed;
			return new Response("ok");
		}
		if (path === "/replay") return new Response("ok", { headers: replayed ?? {} });
		return new Response("ok");
	},
});

afterAll(() => origin.stop(true));

const site = {
	id: "site-origin-user-test",
	name: "Origin user test",
	public_host: "proxy.test",
	origin_url: `http://127.0.0.1:${origin.port}`,
	origin_signing_secret: secret,
} as SiteRecord;

function basePolicy(): ResolvedHttpPolicy {
	return {
		requestHeaders: { set: [], remove: [] },
		responseHeaders: { set: [], remove: [] },
		limits: { maxBodyBytes: 0, maxRequestTargetBytes: 0, maxHeaderBytes: 0 },
		cache: { mode: "disabled", ttlSeconds: 3_600, maxObjectBytes: 5_242_880, extensions: [".css"] },
		protection: { mode: "disabled", rulesetId: "default", excludedRuleIds: [] },
		banDurations: { low: 0, medium: 600, high: 3_600, critical: 86_400 },
		bandwidthLimit: { enabled: false, maxBytes: 50 * 1_024 * 1_024, windowSeconds: 60, banSeconds: 3_600, scopeId: "site-origin-user-test" },
		bodyCapture: { mode: "disabled", maxRequestBytes: 4_096, maxResponseBytes: 4_096, expiresAt: null, contentTypes: ["*"] },
		headerCapture: { mode: "disabled", redactAuthHeaders: true, redactedHeaders: [], expiresAt: null },
		cors: {
			mode: "disabled",
			allowedOrigins: [],
			allowedMethods: ["GET", "HEAD", "POST"],
			allowedHeaders: ["content-type", "authorization"],
			exposedHeaders: [],
			allowCredentials: false,
			maxAgeSeconds: 86_400,
		},
		hsts: { mode: "disabled", maxAgeSeconds: 15_552_000, includeSubDomains: false, preload: false },
	};
}

async function proxy(path: string) {
	return await proxyRequest(new Request(`http://proxy.test${path}`), site, "203.0.113.20", null, undefined, null, false, null, site.origin_url, basePolicy());
}

describe("origin user reporting", () => {
	test("records the user an origin signed and hides the headers from the client", async () => {
		const { response, originUsername } = await proxy("/signed");
		expect(originUsername).toBe("ziga");
		expect(response.headers.has("x-burrowgate-origin-user")).toBe(false);
		expect(response.headers.has("x-burrowgate-origin-user-signature")).toBe(false);
	});

	test("ignores a forged or wrongly signed user but still hides the headers", async () => {
		for (const path of ["/forged", "/wrong-secret"]) {
			const { response, originUsername } = await proxy(path);
			expect(originUsername).toBeNull();
			expect(response.headers.has("x-burrowgate-origin-user")).toBe(false);
			expect(response.headers.has("x-burrowgate-origin-user-signature")).toBe(false);
		}
	});

	test("does not accept a signature replayed from another request", async () => {
		await proxy("/remember");
		expect(replayed).not.toBeNull();
		expect((await proxy("/replay")).originUsername).toBeNull();
	});

	test("reports no user when the origin sends none", async () => {
		expect((await proxy("/anonymous")).originUsername).toBeNull();
	});
});
