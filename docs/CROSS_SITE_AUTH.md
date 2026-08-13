# Cross-site authentication

BurrowGate can authenticate a frontend with an Access List and let a separate backend API trust the same identity. This is useful when, for example, an Angular application is served from `app.example.com` while its API is served from `api.example.com`.

The application does not need to implement passwords, two-factor authentication, or OpenID Connect itself. BurrowGate handles sign-in and owns the browser session. [`@rabbit-company/burrowgate-auth`](https://www.npmjs.com/package/@rabbit-company/burrowgate-auth) carries that identity safely between the frontend and backend.

![BurrowGate cross-site authentication flow](https://cdn.rabbit-company.com/burrowgate/burrowgate-auth-flow.svg)

## Components and trust boundaries

- **BurrowGate frontend site** protects the frontend with an Access List and handles password, TOTP/WebAuthn 2FA, or OIDC SSO authentication.
- **Browser SDK** keeps a short-lived signed assertion in memory, refreshes it before expiry, adds it to API requests, and handles logout.
- **Backend SDK** sends assertions to BurrowGate for verification and returns the verified user to application code.
- **Session verification token** is a backend-only credential. It must never be included in frontend code, browser storage, or a public environment file.

The short-lived assertion is not the HTTP-only BurrowGate session cookie and cannot be used to recover it. Frontend code can transport an assertion, but only BurrowGate can establish whether its parent session and user are still active.

## Request flow

1. The browser opens the frontend through its BurrowGate public host.
2. BurrowGate requires authentication using the Access List's configured password and 2FA policy or OIDC identity provider.
3. After authentication, BurrowGate proxies the Angular or other static frontend to the browser and maintains an HTTP-only, site-scoped session cookie.
4. `BrowserSessionAssertionClient` asks the same frontend host for a signed session assertion. The SDK performs this automatically and stores the result only in memory.
5. Application code calls `auth.fetch("/api/...")`. The SDK reuses or refreshes the assertion and adds `X-BurrowGate-Session-Assertion` automatically.
6. The backend reads the assertion and `BurrowGateClient` introspects it using the frontend site ID and backend-only verification token.
7. BurrowGate validates the signature, assertion expiry, parent session, site membership, user state, and revocation status, then returns the verified identity.
8. The backend authorizes the request using that identity and returns the API response.

## Configure BurrowGate

### Frontend site

1. Enable the site's Access List.
2. Assign users and configure password plus TOTP/WebAuthn 2FA, OIDC SSO, or both.
3. Generate a **Cross-site session verification** token from the Access List settings.
4. Copy the frontend site ID and verification token to the backend's secret configuration.

### API site

The API can be a second BurrowGate site, but its own Access List should remain disabled for this flow because BurrowGate browser sessions are scoped to one site. Configure its route to bypass the ordinary browser challenge, including `OPTIONS` requests, and authenticate every protected backend handler with the SDK.

In production, keep the API origin reachable only through BurrowGate and use signed origin verification headers to prevent direct proxy bypass. Configure CORS with the exact frontend origin and allow `X-BurrowGate-Session-Assertion` (do not use a wildcard origin for authenticated requests).

## Browser integration

Keep one client for the lifetime of the frontend application. The first API request waits for assertion initialization. Later requests reuse the in-memory assertion immediately while background refresh keeps it current.

```ts
import { BrowserSessionAssertionClient } from "@rabbit-company/burrowgate-auth";

export const auth = new BrowserSessionAssertionClient({
	apiBaseUrl: "https://api.example.com",
});

const response = await auth.fetch("/items");
const items = await response.json();

await auth.logout();
```

`auth.fetch()` preserves normal fetch options and existing headers. It rejects destinations outside the configured API origin to prevent accidental assertion disclosure. `auth.logout()` stops background refresh, clears the in-memory assertion, and revokes the server-side BurrowGate session.

## Backend integration

Create one server-side client and reuse it across requests:

```ts
import { BurrowGateClient } from "@rabbit-company/burrowgate-auth";

const auth = new BurrowGateClient({
	baseUrl: "https://app.example.com",
	siteId: process.env.BURROWGATE_FRONTEND_SITE_ID!,
	verificationToken: process.env.BURROWGATE_SESSION_VERIFICATION_TOKEN!,
	cacheTtlMs: 5_000,
});

const session = await auth.authenticate(request);
if (!session) return new Response("Unauthorized", { status: 401 });

console.log(session.user.id, session.user.username);
```

The package is framework-neutral and uses standard Web APIs, so the same client works with Bun, Deno, Node.js, or any framework that exposes a `Request` or headers.

## Expiry, caching, and revocation

These are separate lifetimes:

- Assertions last `BG_ACCESS_SESSION_ASSERTION_TTL_SECONDS`, five minutes by default, but never outlive the parent session.
- The browser SDK refreshes approximately 30 seconds before assertion expiry by default.
- The backend SDK caches successful introspection for five seconds by default. Invalid sessions and network failures are not cached.

The short backend cache prevents an introspection call on every API request. It also creates a deliberate revocation window: after logout, disabling a user, or administrative revocation, an assertion can remain accepted by one backend process until its cached result expires. Set `cacheTtlMs` to `0` for requests that require immediate verification.

## Runnable example

The repository includes a complete frontend, backend, CORS configuration, SDK integration, caching demonstration, and logout test in [`examples/cross-site-auth`](../examples/cross-site-auth/README.md).
