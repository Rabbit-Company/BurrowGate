# Route policies and API rate limiting

BurrowGate separates **access mode** from **rate limiting**. A route can therefore
skip browser verification while still enforcing an API request limit.

## Site default

Every site has one default access mode:

- `challenge`: visitors need the site's challenge chain before proxy access.
- `bypass`: requests are proxied without a browser challenge.

The default can be changed in **Dashboard -> Sites -> Default access mode**.

## Route matching

Route policies are evaluated for the selected site by:

1. Highest numeric priority.
2. Most specific path pattern.
3. Oldest policy when the previous values are equal.

Methods are optional. A blank method list applies to every method. Patterns use:

- `*` to match characters inside one path segment.
- `**` to match across path segments.

Examples:

- `/api/**` matches `/api`, `/api/users`, and `/api/v1/users/42`.
- `/assets/*` matches `/assets/app.js`, but not `/assets/js/app.js`.

Queries are not part of route matching.

## Access modes

- `inherit`: use the site default.
- `challenge`: require verification. A route can inherit the site challenge chain
  or provide its own ordered provider list.
- `bypass`: do not require browser JavaScript or a BurrowGate visitor session.
- `block`: return HTTP 403 without contacting the origin.

Network policy is evaluated before route access:

- A matching IP, CIDR, or country `block` rejects the request.
- A route `block` remains blocked regardless of an `allow` network rule.
- A network `challenge` forces a challenge on challenge or bypass routes.
- A network `allow` bypasses browser verification, but does not bypass route rate limiting.

See [`NETWORK_POLICIES.md`](NETWORK_POLICIES.md) for defaults, precedence, and whitelist examples.

## JSON API example

Create this route policy:

```text
Name: JSON API
Path: /api/**
Methods: blank
Access: Bypass browser verification
Rate limiting: Enabled
Algorithm: Sliding window
Maximum: 120
Window: 60000 ms
Identity: IP address
Scope: Shared across this policy
```

Clients receive standard response headers:

```http
RateLimit-Limit: 120
RateLimit-Remaining: 84
RateLimit-Reset: 1785715200
```

When the limit is exceeded, BurrowGate returns `429 Too Many Requests` with a
`Retry-After` header and a JSON error body.

## Algorithms

- **Fixed window** is inexpensive but permits bursts around a window boundary.
- **Sliding window** provides smoother, more accurate limits at a higher memory cost.
- **Token bucket** allows a configured burst capacity and then refills steadily.

## Client identity

- `IP address`: all requests from one client IP share a counter.
- `Verified session, otherwise IP`: use the BurrowGate session when available.
- `Header value, otherwise IP`: useful for API keys. Header values are hashed before
  being used as limiter keys and are not stored in SQL. Use this only for a stable
  credential that the protected application validates. A client-controlled header
  that accepts arbitrary values can be rotated to evade the counter; use IP identity
  until BurrowGate gains a first-class API-key authentication provider.

## Counter scope

- `policy`: one counter across every route matched by the policy.
- `path`: separate counters for each exact request path.
- `method-path`: separate counters for every method and exact path combination.

## Current storage behavior

The rate limiter from `@rabbit-company/web-middleware` is currently in-memory.
Counters reset when BurrowGate restarts and are local to each process. A future
Redis-backed limiter is required before horizontally scaled nodes can enforce one
shared global limit.

WebSocket policies apply to the HTTP upgrade request. They do not currently limit
individual WebSocket messages.

## Static asset cache overrides

The site HTTP policy defines the default static-cache mode, maximum TTL, maximum
object size, and allowed file extensions. A route can inherit, enable, or disable
caching and independently override the other values. A blank route value inherits
the site value.

Caching never bypasses network policy, browser verification, access authentication,
or route rate limiting. Only the origin fetch is skipped on a cache hit. Range,
conditional, authorized, and application-cookie requests bypass the cache, and
unsafe origin responses are never stored. Use the route editor's **Purge policy
cache** action after an application deployment when asset URLs are not content
hashed.

Historical outcomes and top paths, current in-memory usage, and site/path/global
purge controls are available in the dashboard's **Cache** tab. Recent Traffic
stores and filters cache status separately from its access decision: `hit`, `miss`,
or `bypass` is shown without replacing verified, authenticated, allowlisted, or
unprotected request classification.
