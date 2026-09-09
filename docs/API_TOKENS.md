# API tokens

Any signed-in user can create tokens in **Account -> API tokens**. Give each integration a separate name and copy the token when it is created: the plaintext is shown only once. Choose 30 days, 90 days, one year, or no expiry. Revoke a token from the same panel. Replace an expiring token in the integration before revoking the old one.

There are two scopes:

- **Full access** (`bgat_` prefix) - authenticates as the creating user, exactly as if they were signed in through the dashboard. It can call every admin API endpoint the user's own account can reach, with that same user's own site and stream permissions - a "member" account limited to one site gets a token limited to that one site; nothing is elevated. Any enabled user, administrator or member, can create one for themself.
- **Read-only monitoring** (`bgro_` prefix, fixed `monitoring:read` scope) - can only read aggregate metrics for all sites and the system, described below. Only administrators can create this scope.

BurrowGate stores only a SHA-256 hash of a cryptographically random 256-bit secret, never the plaintext. Creation and revocation are audited without the secret. Only the owner can list or revoke their own tokens. A token stops authenticating the moment its owner is disabled or deleted (and, for the monitoring scope specifically, if the owner loses the administrator role).

These admin API token types are separate from visitor sessions, access-list user tokens, session-verification tokens, the OpenMetrics exporter token, and HA credentials.

## Full-access tokens

Send a full-access token in the `Authorization: Bearer bgat_...` header against the normal dashboard API (`/_burrowgate/api/admin/...`) - the same endpoints and paths the admin dashboard itself calls. There is no separate "public" API surface: a full-access token is a drop-in replacement for a session cookie.

BurrowGate rejects requests that present a `bgat_` credential outside `/_burrowgate/api/admin/...`, and strips BurrowGate API-token prefixes from any request headers built for a protected origin as defense in depth. This prevents an accidentally misdirected admin credential from being disclosed to an upstream application.

Two things work differently than a browser session:

- **No CSRF header required.** The dashboard's CSRF check (same-origin plus a custom header) exists to stop a browser from replaying a signed-in user's cookie cross-site. It doesn't apply to an explicit bearer token, which a browser can't forge on a script's behalf - so a full-access token can call mutating endpoints (`POST`/`PUT`/`PATCH`/`DELETE`) without `Origin` matching the dashboard host or the `X-BurrowGate-Admin` header.
- **Works across HA replicas.** A mutation sent to a replica node is forwarded to the primary with the bearer token intact, the same way a session cookie is forwarded.

Because the token carries the real owner's role and permissions, everything else about authorization is unchanged: administrator-only endpoints (user management, DNS providers, firewall sync, HA cluster admin, and so on) still require the owning account to be an administrator, and site/stream-scoped endpoints still check that account's own per-site/per-stream permission level.

```sh
curl --fail 'https://gate.example.com/_burrowgate/api/admin/sites' \
  -H "Authorization: Bearer $BURROWGATE_FULL_TOKEN"

curl --fail -X PUT 'https://gate.example.com/_burrowgate/api/admin/sites/SITE_ID' \
  -H "Authorization: Bearer $BURROWGATE_FULL_TOKEN" -H 'content-type: application/json' \
  -d '{"name":"Renamed via API"}'
```

## OpenAPI document

The admin API has a live OpenAPI 3.2 document at:

```text
GET /_burrowgate/api/admin/openapi.json
```

Fetching it requires either a signed-in dashboard session or a full-access token. The document describes the normal `/_burrowgate/api/admin/...` API, including request and response schemas and both supported authentication methods. It does not include the deliberately narrower read-only monitoring API described below, which has a document of its own:

```text
GET /_burrowgate/api/v1/openapi.json
```

That one is fetched with a monitoring token, describes only the two `/_burrowgate/api/v1/...` endpoints, and advertises only the read-only monitoring credential. The two documents are kept separate because they address different callers and different credentials (neither one references the other's schemas).

```sh
curl --fail 'https://gate.example.com/_burrowgate/api/admin/openapi.json' \
  -H "Authorization: Bearer $BURROWGATE_FULL_TOKEN" \
  --output burrowgate-openapi.json
```

`servers[0].url` is the origin through which the document was requested, such as `https://gate.example.com`, including a non-default port when used. Every key under `paths` is a complete BurrowGate admin route beginning with `/_burrowgate/api/admin/`. API clients therefore form requests by joining that origin and path without needing a separately configured base-path prefix.

The document is generated from the running BurrowGate version, so retrieve it from the instance you intend to automate. Importing the document does not bypass authorization: every call made with a full-access token still receives exactly the owning user's current role and site/stream permissions.

## Reading monitoring data

A monitoring token can read aggregate metrics for **all sites and the system**. A request's `siteId` filters the returned data (it does not restrict the credential). Members cannot create these instance-wide credentials. Monitoring tokens cannot access dashboard APIs, configuration, captured requests, raw logs, sessions, credentials, or proxied applications. Every method except GET is denied. New endpoints are unavailable to these tokens unless explicitly added to the read allowlist.

Use the dashboard's HTTPS base URL and send the token in the Authorization header. Tokens in query parameters and dashboard cookies are not accepted for monitoring authentication. Responses include `Cache-Control: no-store`.

```sh
curl --fail 'https://gate.example.com/_burrowgate/api/v1/sites' \
  -H "Authorization: Bearer $BURROWGATE_READ_TOKEN"

curl --fail 'https://gate.example.com/_burrowgate/api/v1/monitoring?view=traffic&hours=24' \
  -H "Authorization: Bearer $BURROWGATE_READ_TOKEN"
```

`GET /_burrowgate/api/v1/sites` returns `{ "sites": [...] }` with only each site's `id`, `name`, `publicHost`, and `enabled` status.

`GET /_burrowgate/api/v1/monitoring` accepts:

| Parameter        | Values                                                                                                                                                 | Default    |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------- |
| `view`           | `overview`, `traffic`, `blocked`, `bandwidth`, `cache`, `protection`, `latency`, `geography`, `paths`, `referrers`, `cpu`, `memory`, `disk`, `network` | `overview` |
| `hours`          | Whole number, `1` to `8784` (366 days)                                                                                                                 | `24`       |
| `siteId`         | ID from the sites endpoint (omit for all sites)                                                                                                        | All sites  |
| `pathPrefix`     | Absolute path, matching it and everything beneath it                                                                                                   | Whole site |
| `path`           | Absolute path, matching that one page only                                                                                                             | Whole site |
| `successfulOnly` | `true` or `false`, dropping responses the origin refused                                                                                               | `false`    |

The window is a whole number of hours up to 366 days, the same cap the dashboard applies to its own date range. A wider window is not a more expensive answer: the series is bucketed to at most 49 points whatever it is, and the rows scanned are bounded by `BG_EVENT_RETENTION_DAYS` (7 by default) rather than by the range, so asking past retention returns a sparse result rather than a costly one. Responses are `no-store` and nothing is cached, so there is no reason to snap to fixed windows.

System views (`cpu`, `memory`, `disk`, `network`) require an empty `siteId`. Unknown sites, views, and unsupported ranges return 400. Missing, invalid, revoked, or expired credentials return 401. Disallowed endpoints or methods return 403 (unregistered routes may return 404). The application limits the monitoring API to 300 requests per minute per client IP, within an overall ceiling of 6000 requests per minute per client IP across `/_burrowgate/api`.

### Scoping to part of a site

`pathPrefix` and `path` let one origin that hosts many tenants, such as a multi-user blog, show each tenant only their own traffic. They are mutually exclusive, and sending both returns 400.

`pathPrefix` matches the path itself _or_ anything below it, so `/creator/alice` covers `/creator/alice` and `/creator/alice/post` but never the sibling `/creator/alice-blog`. LIKE wildcards in the value are escaped and cannot widen the scope. `path` matches a single page, and also its trailing-slash spelling, since `/x` and `/x/` are the same page to a reader. Both compare the path alone: a request recorded as `/creator/alice?page=2` counts under `/creator/alice`, and the `paths` view reports one row per page rather than one per query string.

Both apply only to views backed by `request_events`. The `bandwidth` view and the system views read minute-aggregate tables that carry no path, so asking for a scope there returns 400 rather than quietly answering with the whole site. `successfulOnly` is refused the same way on `blocked` and `protection`, whose entire subject is requests that were refused.

The response echoes `pathPrefix`, `path` and `successfulOnly` as applied. **Verify the echo.** A gateway older than these parameters ignores them and answers for the whole site, which for a multi-tenant caller means handing one tenant everyone else's numbers. Comparing the echo against what you asked for is how you tell that apart from success.

The version 1 response includes `schemaVersion`, `view`, `title`, `scope`, `pathPrefix`, `path`, `successfulOnly`, `unit`, `hours`, `generatedAt`, `from`, `to`, `bucketSeconds`, `hasData`, `maximum`, `stats`, `rows`, and `points`. Dates use ISO 8601 UTC. Each stat has a `label`, numeric or null `value`, and `unit`. Each point has a Unix millisecond `timestamp`, numeric or null `value`, and a normalized chart `height` (0–100). Series contain at most 49 intervals. Geography returns one row per country with at least one request in the range, ordered by request count, each with `label` (the country code, such as `DE`) and `value`. The list is complete rather than truncated, so clients decide how many rows to show. Unknown locations use `ZZ`. Private-network locations use `XX`. Clients map these codes to display names.

`paths` and `referrers` are the exception to that completeness. Both group by a value visitors control, so a single crawler can mint millions of distinct ones. Each returns at most the top 100 rows by request count. Their stats describe those rows rather than the whole site. `Requests in top paths` is the sum of the returned rows rather than the site total, so these views will disagree with `overview` whenever the cap is reached. Use `overview` for totals, and narrow with `pathPrefix` to see further down the tail of one subtree.

Bandwidth uses MiB per interval. Cache hit ratios and CPU use percentages. Request latency uses milliseconds. Memory and storage use GiB. Network charts show average download Mbps per interval, with average upload in the summary. Request counts include all recorded outcomes. Blocked counts follow the dashboard's blocked-decision definition. Latency summaries are weighted by requests, using the dashboard's rounded interval averages.

Reads use persisted metrics and do not flush queues or modify configuration, sessions, or tokens. Recent buffered samples appear after the normal background flush. Historical availability depends on retention and enabled collectors. Missing system or latency samples remain null. They are not reported as zero usage. Count series fill empty intervals with zero.

## High availability

Creation and revocation follow the existing primary forwarding, write barrier, and durability reporting. Token hashes (and their scope) are included in HA snapshots and replicated changes. A full-access token's mutating requests are forwarded to the primary with the bearer credential intact, the same way a session cookie is. Use the primary dashboard URL for integrations when revocation must be observed immediately. Replicas can accept previously valid credentials until their replication catches up. Metrics describe the node being polled, as in its dashboard. Upgrade all nodes before using the new token entity.

See [the TRMNL recipe](../trmnl/README.md) for device setup.
