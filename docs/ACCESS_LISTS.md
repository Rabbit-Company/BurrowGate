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

Creating a user creates one global identity and assigns it to the selected site. The **Add users from another site** control links an existing identity to another site; it does not copy a password hash.

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

## Single sign-on

Each site's access list can optionally accept sign-ins from an external OpenID Connect provider instead of, or alongside, local passwords. See [SSO.md](SSO.md) for setup and behavior details, including how it interacts with dashboard single sign-on.

## Transport security

Always use HTTPS for sites with access authentication. The login session cookie is HTTP-only and follows the site's configured session lifetime. Rotating a password or revoking the session invalidates access before that lifetime ends.
