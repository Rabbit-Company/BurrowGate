# Cross-site authentication example

This example runs two independent origins:

| Component   | Local origin            | Public BurrowGate site     |
| ----------- | ----------------------- | -------------------------- |
| Frontend    | `http://127.0.0.1:3100` | `https://app.example.test` |
| Backend API | `http://127.0.0.1:3200` | `https://api.example.test` |

The frontend site owns the Access List login and browser session. The API site's Access List remains disabled. Every protected API handler uses `@rabbit-company/burrowgate-auth` to validate the short-lived assertion against the frontend session.

## 1. Configure local names

Point the example hostnames at the machine running BurrowGate. For a local installation, add this to `/etc/hosts` or use equivalent local DNS:

```text
127.0.0.1 app.example.test api.example.test
```

You can use real DNS names instead. Update the two public origins in `.env` to match.

## 2. Create the frontend site

Create a BurrowGate site with:

```text
Public host: app.example.test
Origin URL: http://127.0.0.1:3100
```

Then:

1. Enable its Access List.
2. Assign at least one user and configure password + 2FA or OIDC SSO.
3. In **Cross-site session verification**, generate a verification token.
4. Copy the frontend site ID and generated token. The token is displayed only once.

## 3. Create the API site

Create a second BurrowGate site with:

```text
Public host: api.example.test
Origin URL: http://127.0.0.1:3200
```

Leave this site's Access List disabled and set its default access mode to **Bypass** (or add an equivalent bypass route policy covering the API and `OPTIONS` requests). Authentication belongs to the frontend site and is enforced in every protected backend route by the SDK. The bypass is necessary so BurrowGate's ordinary browser challenge does not intercept the cross-origin preflight or API call. Keep the backend origin reachable only by BurrowGate in a real deployment.

Configure working TLS for both public hosts. If BurrowGate uses a locally issued certificate, its CA must also be trusted by the browser and by the Bun process performing introspection.

## 4. Configure and start the origins

```sh
cp examples/cross-site-auth/example.env examples/cross-site-auth/.env
```

Edit `.env` and replace:

```text
BURROWGATE_FRONTEND_SITE_ID=...
BURROWGATE_SESSION_VERIFICATION_TOKEN=...
```

`DEMO_BACKEND_PUBLIC_ORIGIN` must be the URL the browser uses to reach the API site through BurrowGate - not the local `http://localhost:3200` origin when the frontend is loaded over HTTPS. A secure frontend cannot call a plain-HTTP API because browsers block it as mixed content before CORS is evaluated.

The backend allows the configured `DEMO_FRONTEND_PUBLIC_ORIGIN` plus `http://localhost:3100` and `http://127.0.0.1:3100` automatically. If you open the frontend from another origin, add it explicitly:

```text
DEMO_ALLOWED_FRONTEND_ORIGINS=http://localhost:4200,https://another-app.example.test
```

Origins must match exactly, including scheme and port. Do not use a wildcard for this authenticated workflow.

Build the browser SDK and start both origins from the repository root:

```sh
bun run example:cross-site-auth
```

Open `https://app.example.test` - never open port 3100 directly for the workflow test. BurrowGate will request login, 2FA, or SSO before serving the frontend.

## 5. Test the workflow

Use the buttons in order:

1. **Refresh session assertion** forces the global `BrowserSessionAssertionClient` to mint a new assertion. The client also initializes automatically and refreshes in the background before expiry.
2. **Call protected API** uses the SDK's authenticated `fetch()` method. It immediately reuses the in-memory assertion and adds the required header automatically.
3. **Call API three times** demonstrates the backend cache. The three results should show at most one additional BurrowGate introspection within the configured cache TTL.
4. **Log out** calls the SDK's `logout()` method, which revokes the frontend session, stops background refresh, and clears the in-memory assertion.
5. **Test previous assertion** deliberately resends the old assertion. It can succeed during the short backend cache window and must return `401` after that window.

Because successful introspections are cached for five seconds by default, an assertion may remain accepted by that backend process until the cache entry expires. After that delay, a call using the old assertion returns `401`. Reloading the frontend starts the BurrowGate login flow again.

## Request flow

```text
Browser ── frontend session cookie ──> app.example.test (BurrowGate)
Browser <── short-lived assertion ─── POST /_burrowgate/access/session-token
Browser ── assertion header ────────> api.example.test -> backend origin
Backend ── server-only token ───────> BurrowGate introspection endpoint
Backend <── active user/session ───── BurrowGate
```

The browser never receives the HTTP-only BurrowGate session cookie value or the server-only session verification token. The short-lived assertion is held only in memory and is not persisted in browser storage.

## CORS troubleshooting

Check the browser request's `Origin` header (not its `Referer`) and compare it with the origins printed by the backend at startup. A rejected origin is logged by the backend and receives `403`.

For the default local ports, this direct-development pair is accepted:

```text
Frontend: http://localhost:3100
API:      http://localhost:3200
```

The complete authentication workflow still requires opening the frontend through its BurrowGate site so `POST /_burrowgate/access/session-token` is handled by BurrowGate. In that setup, both `DEMO_FRONTEND_PUBLIC_ORIGIN` and `DEMO_BACKEND_PUBLIC_ORIGIN` should contain the public site URLs.
