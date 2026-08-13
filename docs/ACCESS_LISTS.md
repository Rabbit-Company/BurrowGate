# Access Lists

Access lists add user authentication at BurrowGate without consuming the application's `Authorization` header. Users are global identities that can be assigned to one or more protected sites.

## Request flow

When access authentication is enabled, BurrowGate evaluates a request in this order:

1. Site, IP/country, and route-block policies.
2. The site's browser challenge.
3. BurrowGate user authentication.
4. Route rate limiting.
5. The upstream proxy.

The challenge is completed before a password is checked. Password attempts are additionally limited per site, IP address, and username. Passwords are hashed with Argon2id and verification only runs on the login endpoint; proxied requests use the resulting opaque BurrowGate session.

For `GET` and `HEAD`, unauthenticated browsers are redirected through the challenge and login pages. Non-replayable methods and WebSocket handshakes receive `428` with a `BurrowGate-Verification` or `BurrowGate-Login` response header so the client can complete the prerequisite before retrying.

## Shared users

Creating a user creates one global identity and assigns it to the selected site. The **Add users from another site** control links an existing identity to another site (it does not copy a password hash).

- Password and enabled-state changes apply to every assigned site.
- Password changes and disabling a user revoke that user's current authenticated sessions.
- Removing a membership revokes that user's sessions for the selected site.
- Removing the final membership permanently removes the global identity.
- BurrowGate prevents an enabled access list from being left without an active user.

## Application authorization

BurrowGate user login uses the existing HTTP-only challenge session, not HTTP Basic Authentication. Application credentials therefore remain independent:

```http
Authorization: Bearer application-token
```

Application `Basic` and `Bearer` authorization values are forwarded unchanged. `Authorization: Burrow <token>` and `X-Burrow-Token` remain BurrowGate edge credentials and are removed before proxying. An API client that needs both an application `Authorization` value and a BurrowGate session should put the BurrowGate token in `X-Burrow-Token`.

## Authenticated identity headers

The **Send authenticated username to upstream** toggle adds:

```http
X-BurrowGate-Authenticated-User: ziga
X-BurrowGate-Identity-Signature: <HMAC-SHA256>
```

BurrowGate always removes client-provided copies of these headers. The identity signature uses the site's origin signing secret and this canonical value:

```text
<method>\n
<path-and-query>\n
<burrowgate-session-id>\n
<client-ip>\n
<x-burrowgate-timestamp>\n
<username>
```

The existing `X-BurrowGate-Signature` format remains unchanged. An origin that uses the username should verify the normal origin signature and the identity signature, require a recent timestamp, and prevent direct public access to the origin.

Passwords are never sent upstream.

The same toggle also sets two browser-readable cookies:

```text
bg_authenticated_user=ziga
bg_identity_signature=<HMAC-SHA256>
```

These cookies intentionally do not use `HttpOnly`, allowing frontend JavaScript to read them through `document.cookie`. They use `SameSite=Lax`, use `Secure` on HTTPS, and expire with the BurrowGate session. BurrowGate removes client-provided copies before proxying and supplies the validated values to the origin.

The cookie signature is stable for the authenticated session and signs:

```text
identity-cookie-v1\n
<site-id>\n
<burrowgate-session-id>\n
<username>
```

The origin can obtain the session ID from `X-BurrowGate-Session-Id`. Frontend JavaScript cannot independently verify an HMAC because it does not have the origin signing secret, so it should treat the username as display data rather than an authorization decision. Server-side code must verify the signature before trusting the cookie.

## Logout

An authenticated application can end the current BurrowGate browser session with a same-origin request:

```http
POST /_burrowgate/access/logout
Origin: https://app.example.com
```

The endpoint is idempotent. It revokes the current server-side session and expires both the HTTP-only session cookie and the browser-readable identity cookies. It returns `{ "ok": true }`. With OIDC, this ends the local BurrowGate session (it does not perform browser-based identity-provider logout).

## Separate frontend and API sites

BurrowGate sessions and cookies are scoped to one site. To authenticate a browser that signed in on `app.example.com` to a separate `api.example.com` backend:

![BurrowGate cross-site authentication flow](https://cdn.rabbit-company.com/burrowgate/burrowgate-auth-flow.svg)

1. Enable the Access List on the frontend site.
2. Generate a **Cross-site session verification** token from that frontend site's Access List settings. Store it only on the backend.
3. The authenticated browser sends `POST /_burrowgate/access/session-token` to the frontend site. BurrowGate returns a short-lived signed assertion and the current user.
4. The browser sends that assertion to the API in `X-BurrowGate-Session-Assertion`.
5. The backend uses `@rabbit-company/burrowgate-auth` to introspect the assertion against `POST /_burrowgate/api/access/session/introspect` with the frontend site ID and server-only verification token.

The assertion is not the HTTP-only browser session token and does not expose it. It is HMAC-signed, expires after `BG_ACCESS_SESSION_ASSERTION_TTL_SECONDS` (five minutes by default), and is limited by the parent session's expiry. Each BurrowGate introspection checks the parent session, site membership, user enabled state, expiry, and revocation. The SDK caches successful results for five seconds by default, so logout and administrative revocation can take up to that configured cache TTL to reach a backend process.

Browser applications can keep one `BrowserSessionAssertionClient` instance globally and configure `apiBaseUrl` once. Its `fetch()` method adds the assertion automatically, while `logout()` revokes the session, stops refresh, and clears local state. The client stores the assertion only in memory, refreshes 30 seconds before expiry by default, and deduplicates concurrent refreshes. The five-minute browser assertion lifetime and five-second backend introspection cache are independent settings.

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
```

The API site's own Access List should remain disabled for this browser flow because it has a different site-scoped cookie. Keep the API origin private, use BurrowGate's normal signed origin headers to prevent proxy bypass, and let the backend SDK authenticate the frontend site's assertion. Configure CORS to allow only the frontend origin and include `X-BurrowGate-Session-Assertion`.

The complete request flow, security boundaries, setup, CORS requirements, caching behavior, and SDK examples are documented in [CROSS_SITE_AUTH.md](CROSS_SITE_AUTH.md). The SDK lives in [`packages/burrowgate-auth`](../packages/burrowgate-auth/README.md) and is published on [NPM](https://www.npmjs.com/package/@rabbit-company/burrowgate-auth) and [JSR](https://jsr.io/@rabbit-company/burrowgate-auth).

## Two-factor authentication

Enabling **Require 2FA** for a user forces enrollment in either a TOTP authenticator app or a WebAuthn security key on their next login. WebAuthn credentials are scoped per site, so a user assigned to multiple sites registers a key separately on each. See [TWO_FACTOR_AUTH.md](TWO_FACTOR_AUTH.md) for enrollment flow, per-site credential scoping, and reset behavior.

## Single sign-on

Each site's access list can optionally accept sign-ins from an external OpenID Connect provider instead of, or alongside, local passwords. See [SSO.md](SSO.md) for setup and behavior details, including how it interacts with dashboard single sign-on.

## Transport security

Always use HTTPS for sites with access authentication. The login session cookie is HTTP-only and follows the site's configured session lifetime. Rotating a password or revoking the session invalidates access before that lifetime ends.
