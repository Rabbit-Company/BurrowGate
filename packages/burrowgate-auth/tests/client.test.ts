import { describe, expect, test } from "bun:test";
import { BurrowGateClient, BURROWGATE_SESSION_ASSERTION_HEADER, sessionAssertionFromRequest } from "../src/mod.ts";

describe("BurrowGateClient", () => {
	test("introspects an active session", async () => {
		const expiresAt = Date.now() + 60_000;
		const client = new BurrowGateClient({
			baseUrl: "https://app.example.test",
			siteId: "site_frontend",
			verificationToken: "server-secret",
			fetch: async (_input, init) => {
				expect(new Headers(init?.headers).get("authorization")).toBe("Bearer server-secret");
				expect(new Headers(init?.headers).get("x-burrowgate-site-id")).toBe("site_frontend");
				expect(JSON.parse(String(init?.body))).toEqual({ token: "assertion" });
				return Response.json({
					active: true,
					siteId: "site_frontend",
					sessionId: "sess_1",
					user: { id: "user_1", username: "ziga" },
					authenticatedAt: 1,
					expiresAt,
					assertionExpiresAt: expiresAt,
				});
			},
		});

		await expect(client.introspect("assertion")).resolves.toMatchObject({ active: true, user: { username: "ziga" } });
	});

	test("caches active sessions for a bounded time", async () => {
		let requests = 0;
		const expiresAt = Date.now() + 60_000;
		const client = new BurrowGateClient({
			baseUrl: "https://app.example.test",
			siteId: "site_frontend",
			verificationToken: "server-secret",
			cacheTtlMs: 5_000,
			fetch: async () => {
				requests += 1;
				return Response.json({
					active: true,
					siteId: "site_frontend",
					sessionId: "sess_1",
					user: { id: "user_1", username: "ziga" },
					authenticatedAt: 1,
					expiresAt,
					assertionExpiresAt: expiresAt,
				});
			},
		});

		await client.introspect("assertion");
		const cached = await client.introspect("assertion");
		expect(cached?.user.username).toBe("ziga");
		expect(requests).toBe(1);
		expect(client.cacheSize).toBe(1);
		client.clearCache("assertion");
		expect(client.cacheSize).toBe(0);
		await client.introspect("assertion");
		expect(requests).toBe(2);
	});

	test("caps cache lifetime at the assertion expiry", async () => {
		let requests = 0;
		const client = new BurrowGateClient({
			baseUrl: "https://app.example.test",
			siteId: "site_frontend",
			verificationToken: "server-secret",
			cacheTtlMs: 60_000,
			fetch: async () => {
				requests += 1;
				return Response.json({
					active: true,
					siteId: "site_frontend",
					sessionId: "sess_1",
					user: { id: "user_1", username: "ziga" },
					authenticatedAt: 1,
					expiresAt: Date.now() + 60_000,
					assertionExpiresAt: Date.now() + 5,
				});
			},
		});

		await client.introspect("assertion");
		await Bun.sleep(10);
		await client.introspect("assertion");
		expect(requests).toBe(2);
	});

	test("deduplicates concurrent introspection and bounds the cache", async () => {
		let requests = 0;
		const expiresAt = Date.now() + 60_000;
		const client = new BurrowGateClient({
			baseUrl: "https://app.example.test",
			siteId: "site_frontend",
			verificationToken: "server-secret",
			cacheTtlMs: 60_000,
			maxCacheEntries: 2,
			fetch: async () => {
				requests += 1;
				await Bun.sleep(2);
				return Response.json({
					active: true,
					siteId: "site_frontend",
					sessionId: `sess_${requests}`,
					user: { id: "user_1", username: "ziga" },
					authenticatedAt: 1,
					expiresAt,
					assertionExpiresAt: expiresAt,
				});
			},
		});

		await Promise.all([client.introspect("a"), client.introspect("a")]);
		expect(requests).toBe(1);
		await client.introspect("b");
		await client.introspect("a"); // refreshes a's LRU position
		await client.introspect("c"); // evicts b
		expect(client.cacheSize).toBe(2);
		await client.introspect("b");
		expect(requests).toBe(4);
	});

	test("returns null for an inactive session", async () => {
		const client = new BurrowGateClient({
			baseUrl: "https://app.example.test",
			siteId: "site_frontend",
			verificationToken: "server-secret",
			fetch: async () => Response.json({ active: false }),
		});
		await expect(client.introspect("assertion")).resolves.toBeNull();
	});

	test("reads the conventional assertion header", () => {
		const request = new Request("https://api.example.test/", { headers: { [BURROWGATE_SESSION_ASSERTION_HEADER]: "assertion" } });
		expect(sessionAssertionFromRequest(request)).toBe("assertion");
	});
});
