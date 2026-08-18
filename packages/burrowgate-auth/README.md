# `@rabbit-company/burrowgate-auth`

Runtime-neutral TypeScript toolkit for BurrowGate: verifying cross-site browser sessions from a separate backend, and verifying that a request to a protected origin actually passed through BurrowGate. It uses standard `fetch`, `Request`, `AbortController`, and Web Crypto APIs and supports Bun, Deno, and Node.js.

## How verification works

![BurrowGate cross-site authentication flow](https://cdn.rabbit-company.com/burrowgate/burrowgate-auth-flow.svg)

BurrowGate authenticates the frontend with its Access List, password plus 2FA, or OIDC SSO. The browser client obtains a short-lived signed assertion and adds it to API calls automatically. The backend client then introspects that assertion with BurrowGate using a server-only verification token before trusting the user identity.

See the [complete cross-site authentication guide](https://github.com/Rabbit-Company/BurrowGate/blob/main/docs/CROSS_SITE_AUTH.md) for setup, trust boundaries, CORS, caching, and logout behavior.

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

Keep one `BrowserSessionAssertionClient` for the lifetime of the browser application. Configure the API URL once. Its `fetch()` method handles assertion creation, caching, refresh, and headers automatically:

```ts
import { BrowserSessionAssertionClient } from "@rabbit-company/burrowgate-auth";

export const auth = new BrowserSessionAssertionClient({
	apiBaseUrl: "https://api.example.com",
});

const response = await auth.fetch("/items");
const items = await response.json();

// Revokes the server session, stops refresh, and clears the local assertion.
await auth.logout();
```

Relative request URLs resolve against `apiBaseUrl`. Existing request options and headers are preserved. To protect credentials from accidental disclosure, `fetch()` rejects absolute URLs on a different origin. The first API call waits for assertion initialization. Subsequent calls reuse the in-memory assertion immediately.

By default, BurrowGate assertions last five minutes (`BG_ACCESS_SESSION_ASSERTION_TTL_SECONDS=300`) or until the parent browser session expires, whichever happens first. The browser client refreshes 30 seconds early and retries a failed background refresh after five seconds. Configure those timings when needed:

```ts
const auth = new BrowserSessionAssertionClient({
	apiBaseUrl: "https://api.example.com",
	refreshAheadMs: 30_000,
	retryDelayMs: 5_000,
	onError: (error) => console.error("Assertion refresh failed", error),
});
```

Only the assertion is kept in memory (it is never written to browser storage). Call `logout()` to revoke the BurrowGate browser session, stop background refresh, and clear the assertion. Call `stop()` only when background refresh should stop without logging out.

For low-level usage, `createBrowserSessionAssertion()`, `getToken()`, and the exported assertion header constant remain available, but normal browser integrations do not need them.

The browser refresh interval and backend cache are independent:

- Browser assertion lifetime: five minutes by default.
- Browser background refresh: approximately 30 seconds before assertion expiry.
- Backend successful-introspection cache: five seconds by default.

Each real introspection checks the parent session. With the default backend cache, logout and administrative revocation can take up to five seconds to reach a given backend process.

## Origin request verification

`verifyOriginRequest()` checks that a request actually passed through BurrowGate, using only the protected site's origin signing secret (no network call, no Access List required). Every request BurrowGate proxies is signed with `X-BurrowGate-Signature`, an HMAC-SHA256 over the method, path, session ID, client IP, country, and timestamp; this function recomputes and compares it in constant time. Use it in any protected origin, even one that does not use BurrowGate's Access Lists or cross-site session assertions at all:

```ts
import { verifyOriginRequest } from "@rabbit-company/burrowgate-auth";

// Call this first, before reading the request body.
const result = await verifyOriginRequest(request, process.env.BURROWGATE_ORIGIN_SECRET!);

if (!result.valid) {
	// result.reason is "missing-headers" | "stale-timestamp" | "invalid-signature" | "invalid-identity-signature"
	return new Response("Forbidden", { status: 403 });
}

console.log(result.clientIp, result.country, result.sessionId);
```

Call it before reading the request body. `X-BurrowGate-Timestamp` is stamped when BurrowGate signs the outgoing request, before the body is forwarded, so a large or slow upload does not affect the freshness check - but only if verification runs before the body is consumed. Verifying after buffering a large upload measures upload time against `maxAgeSeconds` and can fail spuriously.

The freshness check defaults to 60 seconds of allowed clock skew and rejects anything older (or, allowing for skew, anything from the future) than that:

```ts
const result = await verifyOriginRequest(request, secret, {
	maxAgeSeconds: 60, // 0 disables the check entirely (not recommended)
});
```

When the site's **Send authenticated username to upstream** toggle is enabled, `X-BurrowGate-Authenticated-User` and `X-BurrowGate-Identity-Signature` are also present and are verified automatically; `result.authenticatedUser` is `null` when identity forwarding was not used for this request, and the whole result is invalid if either identity header is tampered with or removed independently of the other.

`result.accessMode` and `result.verified` reflect BurrowGate's own access decision for the request but, unlike the other fields, are not themselves covered by the signature.
