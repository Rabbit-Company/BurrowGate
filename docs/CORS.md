# CORS

BurrowGate can answer cross-origin browser requests directly instead of
leaving CORS to the origin. It is disabled by default and must be turned on
explicitly per site, or per route.

## Modes

- Site: `disabled` or `enabled`.
- Route: `inherit`, `enabled`, or `disabled`. `inherit` uses the site's mode.

A route in `enabled` or `disabled` mode overrides the site's mode, and every
setting below (allowed origins, methods, headers, credentials, preflight
cache duration) for requests matching that route. A route left on `inherit`
follows the site in full - there is no field-by-field merge between a site
and a route once CORS is enabled at the route level.

## Preflight requests

A browser preflight is an `OPTIONS` request carrying
`Access-Control-Request-Method`. When CORS is enabled for the matching route,
BurrowGate answers it directly with a `204` and the appropriate
`Access-Control-*` headers, without forwarding it to the origin. This
short-circuit happens **after** maintenance mode, IP/route blocks, and
request-limit checks (so those still apply to preflight), but **before**
managed request protection, the browser-verification challenge, and
access-list sign-in. A challenge redirect or a login page is not a valid
preflight response, so without this a protected site's cross-origin
`fetch()` calls would fail even for a visitor who could otherwise complete
verification normally.

## Allowed origins

Each entry is either an exact origin (`https://app.example.com`, scheme and
host only, no path) or `*` for any origin. `*` cannot be combined with
specific origins, and cannot be used together with **Allow credentials** -
the Fetch spec forbids a wildcard origin on a credentialed response, and
browsers reject it outright, so BurrowGate rejects that combination when the
policy is saved rather than shipping a configuration that silently fails in
the browser.

## Allowed methods, allowed headers, exposed headers

- **Allowed methods** lists the HTTP methods a cross-origin request may use.
- **Allowed request headers** lists the headers browser JavaScript may set on
  the request (e.g. `content-type, authorization`).
- **Exposed response headers** lists response headers browser JavaScript is
  allowed to read; empty by default, since browsers can already read a small
  set of "simple" response headers without this. Framing and signed
  `X-BurrowGate-*` identity headers can never be exposed - the same
  proxy-owned boundary [header policies](ROUTE_POLICIES.md) enforce.

## Credentials

**Allow credentials** sends `Access-Control-Allow-Credentials: true` and
switches the `Access-Control-Allow-Origin` response header from a bare `*` to
an echo of the request's `Origin` (plus `Vary: Origin`), since a credentialed
response can never use the wildcard value.

## Security note

Enabling CORS with a broad allowed-origin list on a route that also serves
authenticated or sensitive data effectively lets any listed origin's
JavaScript read that data cross-origin, subject to **Allow credentials** and
**Exposed response headers**. Keep the allowed-origin list as narrow as the
integration requires, and only allow credentials when the calling origin is
one you trust with the same access the browser's own cookies would grant it.
