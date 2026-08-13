import { describe, expect, test } from "bun:test";
import {
	BrowserSessionAssertionClient,
	BurrowGateClient,
	BURROWGATE_SESSION_ASSERTION_HEADER,
	createBrowserSessionAssertion,
	sessionAssertionFromRequest,
} from "../src/mod.ts";

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

describe("browser session assertions", () => {
	test("binds the browser's global fetch to its required receiver", async () => {
		const originalFetch = globalThis.fetch;
		let requests = 0;
		globalThis.fetch = (async function (this: unknown, input: string | URL | Request) {
			if (this !== globalThis) throw new TypeError("Illegal invocation");
			requests += 1;
			const url = new URL(input instanceof Request ? input.url : input);
			if (url.pathname === "/_burrowgate/access/session-token") {
				return Response.json({
					token: "browser-token",
					expiresAt: Date.now() + 300_000,
					user: { id: "user_1", username: "ziga" },
				});
			}
			return Response.json({ ok: true });
		}) as typeof fetch;

		try {
			const client = new BrowserSessionAssertionClient({
				baseUrl: "https://app.example.test",
				apiBaseUrl: "https://api.example.test",
				autoStart: false,
			});
			const response = await client.fetch("/items");
			expect(await response.json()).toEqual({ ok: true });
			expect(requests).toBe(2);
		} finally {
			globalThis.fetch = originalFetch;
		}
	});

	test("mints an assertion using the authenticated browser endpoint", async () => {
		const expiresAt = Date.now() + 300_000;
		const assertion = await createBrowserSessionAssertion("https://app.example.test", async (input, init) => {
			expect(new URL(input instanceof Request ? input.url : input).pathname).toBe("/_burrowgate/access/session-token");
			expect(init?.method).toBe("POST");
			expect(init?.credentials).toBe("include");
			return Response.json({ token: "browser-token", expiresAt, user: { id: "user_1", username: "ziga" } });
		});
		expect(assertion).toEqual({ token: "browser-token", expiresAt, user: { id: "user_1", username: "ziga" } });
	});

	test("returns the in-memory token without another browser request", async () => {
		let requests = 0;
		const expiresAt = Date.now() + 300_000;
		const client = new BrowserSessionAssertionClient({
			baseUrl: "https://app.example.test",
			autoStart: false,
			fetch: async () => {
				requests += 1;
				return Response.json({ token: `browser-token-${requests}`, expiresAt, user: { id: "user_1", username: "ziga" } });
			},
		});

		expect(client.token).toBeNull();
		expect(await client.getToken()).toBe("browser-token-1");
		expect(client.token).toBe("browser-token-1");
		expect(await client.getToken()).toBe("browser-token-1");
		expect(requests).toBe(1);
		expect((await client.refresh()).token).toBe("browser-token-2");
		expect(requests).toBe(2);
	});

	test("adds the assertion to API requests while preserving existing headers", async () => {
		let assertionRequests = 0;
		const client = new BrowserSessionAssertionClient({
			baseUrl: "https://app.example.test",
			apiBaseUrl: "https://api.example.test/v1/",
			autoStart: false,
			fetch: async (input, init) => {
				const url = new URL(input instanceof Request ? input.url : input);
				if (url.origin === "https://app.example.test") {
					assertionRequests += 1;
					return Response.json({
						token: "browser-token",
						expiresAt: Date.now() + 300_000,
						user: { id: "user_1", username: "ziga" },
					});
				}
				expect(url.href).toBe("https://api.example.test/v1/items");
				const headers = new Headers(init?.headers);
				expect(headers.get("x-custom-header")).toBe("kept");
				expect(headers.get(BURROWGATE_SESSION_ASSERTION_HEADER)).toBe("browser-token");
				return Response.json({ ok: true });
			},
		});

		const response = await client.fetch("items", { headers: { "x-custom-header": "kept" } });
		expect(await response.json()).toEqual({ ok: true });
		expect(assertionRequests).toBe(1);
	});

	test("refuses to send assertions outside the configured API origin", async () => {
		let requests = 0;
		const client = new BrowserSessionAssertionClient({
			baseUrl: "https://app.example.test",
			apiBaseUrl: "https://api.example.test",
			autoStart: false,
			fetch: async () => {
				requests += 1;
				return new Response();
			},
		});

		await expect(client.fetch("https://untrusted.example.test/items")).rejects.toThrow("Refusing to send");
		expect(requests).toBe(0);
	});

	test("logs out and clears the browser assertion", async () => {
		const paths: string[] = [];
		const client = new BrowserSessionAssertionClient({
			baseUrl: "https://app.example.test",
			fetch: async (input, init) => {
				const url = new URL(input instanceof Request ? input.url : input);
				paths.push(url.pathname);
				if (url.pathname === "/_burrowgate/access/session-token") {
					return Response.json({
						token: "browser-token",
						expiresAt: Date.now() + 300_000,
						user: { id: "user_1", username: "ziga" },
					});
				}
				expect(url.pathname).toBe("/_burrowgate/access/logout");
				expect(init?.method).toBe("POST");
				expect(init?.credentials).toBe("include");
				return Response.json({ ok: true });
			},
		});

		await client.getToken();
		expect(client.token).toBe("browser-token");
		await client.logout();
		expect(client.token).toBeNull();
		expect(client.isRunning).toBe(false);
		expect(paths).toEqual(["/_burrowgate/access/session-token", "/_burrowgate/access/logout"]);
	});

	test("refreshes automatically before expiry and can be stopped", async () => {
		let requests = 0;
		const client = new BrowserSessionAssertionClient({
			baseUrl: "https://app.example.test",
			refreshAheadMs: 5_000,
			retryDelayMs: 5,
			fetch: async () => {
				requests += 1;
				return Response.json({
					token: `browser-token-${requests}`,
					expiresAt: Date.now() + 1_010,
					user: { id: "user_1", username: "ziga" },
				});
			},
		});

		await client.getAssertion();
		await Bun.sleep(1_025);
		expect(requests).toBeGreaterThanOrEqual(2);
		expect(client.isRunning).toBe(true);
		client.stop();
		expect(client.isRunning).toBe(false);
	});
});
