# Read-only monitoring API tokens

Administrators can create tokens in **Account -> Read-only API tokens**. Give each integration a separate name and copy the token when it is created: the plaintext is shown only once. Choose 30 days, 90 days, one year, or no expiry. Revoke a token from the same panel. Replace an expiring token in the integration before revoking the old one.

Tokens have the fixed `monitoring:read` scope and a `bgro_` prefix. BurrowGate stores only a SHA-256 hash of a cryptographically random 256-bit secret. Creation and revocation are audited without the secret. Only the owner can list or revoke their tokens. Tokens stop authenticating if their owner is disabled, deleted, or loses the administrator role.

These tokens can read aggregate metrics for **all sites and the system**. A request's `siteId` filters the returned data (it does not restrict the credential). Members cannot create these instance-wide credentials. Tokens cannot access dashboard APIs, configuration, captured requests, raw logs, sessions, credentials, or proxied applications. Every method except GET is denied. New endpoints are unavailable to these tokens unless explicitly added to the read allowlist.

This token type is separate from visitor sessions, access-list user tokens, session-verification tokens, the OpenMetrics exporter token, and HA credentials.

## Reading data

Use the dashboard's HTTPS base URL and send the token in the Authorization header. Tokens in query parameters and dashboard cookies are not accepted for monitoring authentication. Responses include `Cache-Control: no-store`.

```sh
curl --fail 'https://gate.example.com/_burrowgate/api/v1/sites' \
  -H "Authorization: Bearer $BURROWGATE_READ_TOKEN"

curl --fail 'https://gate.example.com/_burrowgate/api/v1/monitoring?view=traffic&hours=24' \
  -H "Authorization: Bearer $BURROWGATE_READ_TOKEN"
```

`GET /_burrowgate/api/v1/sites` returns `{ "sites": [...] }` with only each site's `id`, `name`, `publicHost`, and `enabled` status.

`GET /_burrowgate/api/v1/monitoring` accepts:

| Parameter | Values                                                                                                                           | Default    |
| --------- | -------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `view`    | `overview`, `traffic`, `blocked`, `bandwidth`, `cache`, `protection`, `latency`, `geography`, `cpu`, `memory`, `disk`, `network` | `overview` |
| `hours`   | `1`, `6`, `24`, `168`                                                                                                            | `24`       |
| `siteId`  | ID from the sites endpoint (omit for all sites)                                                                                  | All sites  |

System views (`cpu`, `memory`, `disk`, `network`) require an empty `siteId`. Unknown sites, views, and unsupported ranges return 400. Missing, invalid, revoked, or expired credentials return 401. Disallowed endpoints or methods return 403 (unregistered routes may return 404). The application limits the monitoring API to 60 requests per minute per client IP.

The version 1 response includes `schemaVersion`, `view`, `title`, `scope`, `unit`, `hours`, `generatedAt`, `from`, `to`, `bucketSeconds`, `hasData`, `maximum`, `stats`, `rows`, and `points`. Dates use ISO 8601 UTC. Each stat has a `label`, numeric or null `value`, and `unit`. Each point has a Unix millisecond `timestamp`, numeric or null `value`, and a normalized chart `height` (0–100). Series contain at most 49 intervals. Geography returns up to six country rows with `label` (the country code, such as `DE`) and `value`. Unknown locations use `ZZ`. Private-network locations use `XX`. Clients map these codes to display names.

Bandwidth uses MiB per interval. Cache hit ratios and CPU use percentages. Request latency uses milliseconds. Memory and storage use GiB. Network charts show average download Mbps per interval, with average upload in the summary. Request counts include all recorded outcomes. Blocked counts follow the dashboard's blocked-decision definition. Latency summaries are weighted by requests, using the dashboard's rounded interval averages.

Reads use persisted metrics and do not flush queues or modify configuration, sessions, or tokens. Recent buffered samples appear after the normal background flush. Historical availability depends on retention and enabled collectors. Missing system or latency samples remain null. They are not reported as zero usage. Count series fill empty intervals with zero.

## High availability

Creation and revocation follow the existing primary forwarding, write barrier, and durability reporting. Token hashes are included in HA snapshots and replicated changes. Use the primary dashboard URL for integrations when revocation must be observed immediately. replicas can accept previously valid credentials until their replication catches up. Metrics describe the node being polled, as in its dashboard. Upgrade all nodes before using the new token entity.

See [the TRMNL recipe](../trmnl/README.md) for device setup.
