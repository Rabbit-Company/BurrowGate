# `@rabbit-company/burrowgate-auth`

Runtime-neutral TypeScript client for verifying BurrowGate browser sessions from a separate backend site. It uses standard `fetch`, `Request`, and `AbortController` APIs and supports Bun, Deno, and Node.js.

## Backend

Generate a session verification token from the frontend site's **Access List** settings. Keep it server-side.

```ts
import { BurrowGateClient } from "@rabbit-company/burrowgate-auth";

const auth = new BurrowGateClient({
	baseUrl: "https://app.example.com",
	siteId: "site_frontend",
	verificationToken: process.env.BURROWGATE_SESSION_VERIFICATION_TOKEN!,
	cacheTtlMs: 5_000,
});

const session = await auth.authenticate(request);
if (!session) return new Response("Unauthorized", { status: 401 });

console.log(session.user.id, session.user.username);
```

If the server does not expose a Web `Request`, pass its headers directly. `authenticateHeaders()` accepts a standard `Headers` object, any object with a `get(name)` method, or a plain header record:

```ts
const session = await auth.authenticateHeaders(incomingHeaders);
if (!session) {
	// Return the unauthorized response appropriate for your server.
}
```

By default the assertion is read from `X-BurrowGate-Session-Assertion`. `authenticate()` returns `null` for a missing, expired, logged-out, revoked, or disabled session. Connectivity and configuration failures throw `BurrowGateError` so applications do not accidentally treat an unavailable authority as an anonymous request.

The client sends the frontend site ID in `X-BurrowGate-Site-Id` and the server-only verification token as a Bearer credential. Never put the verification token in browser storage, or a public environment file.

## Caching and revocation

Successful introspection results are cached in memory for five seconds by default. The effective cache expiry is always the earliest of:

- `cacheTtlMs`
- the signed assertion expiry returned by BurrowGate
- the parent BurrowGate session expiry

The cache is bounded to 10,000 entries by default and evicts least-recently-used entries when full. Concurrent checks for the same assertion share one introspection request. Inactive assertions and network errors are never cached.

```ts
const auth = new BurrowGateClient({
	baseUrl: "https://app.example.com",
	siteId: "site_frontend",
	verificationToken: process.env.BURROWGATE_SESSION_VERIFICATION_TOKEN!,
	cacheTtlMs: 5_000, // 0 disables caching
	maxCacheEntries: 10_000,
});
```

Caching creates a deliberate revocation window: a logout, disabled user, or administrative revocation may remain accepted by a backend process until its cached entry expires. Keep `cacheTtlMs` short for sensitive applications. Use `clearCache(assertion)` or `clearCache()` for explicit local invalidation; `pruneCache()` removes expired entries and `cacheSize` reports the current live size.

## Browser

Mint a short-lived assertion from the authenticated frontend site, then attach it to the separate API request:

```ts
import { BURROWGATE_SESSION_ASSERTION_HEADER, createBrowserSessionAssertion } from "@rabbit-company/burrowgate-auth";

const assertion = await createBrowserSessionAssertion();

await fetch("https://api.example.com/items", {
	headers: {
		[BURROWGATE_SESSION_ASSERTION_HEADER]: assertion.token,
	},
});
```

The signed assertion is short-lived and is not the BurrowGate browser-session cookie. Introspection checks its parent session on every backend request, so logout and administrative revocation take effect immediately.
