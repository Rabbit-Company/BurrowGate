# Bandwidth monitoring

BurrowGate records proxied payload bandwidth separately for its two network sides:

- **Client received**: payload bytes received by BurrowGate from a user.
- **Client sent**: payload bytes BurrowGate sends to a user.
- **Upstream sent**: payload bytes BurrowGate sends to an origin server.
- **Upstream received**: payload bytes BurrowGate receives from an origin server.

The dashboard's **Bandwidth** tab charts the client and upstream sides independently and provides a server-paginated client-IP table for the selected site and date range. The table supports search, country and protocol filters, sortable byte columns, configurable page sizes, and immediate addition of an IP to the site's existing network block rules with **Block IP**.

The geographic map has a **Client bandwidth** mode. It groups client-received plus client-sent bytes by the country resolved for each client IP. Upstream bandwidth is deliberately not used on this map because the country represents the visitor, not the origin server.

Switching to the **Traffic**, **Sessions**, or **Bandwidth** tab automatically selects the matching Requests, Sessions, or Client bandwidth map mode. The map dropdown remains available for manual comparisons.

## What is counted

For HTTP, BurrowGate counts body chunks as they pass through the proxy. Compressed origin responses stay compressed, so the compressed representation delivered to the browser is counted. For WebSockets, it counts application message payloads in both directions. Only proxied application traffic is included; dashboard, challenge, access-login, generated error responses, and other BurrowGate control-plane responses are not included.

The counters intentionally exclude HTTP headers, WebSocket framing, TCP/IP overhead, TLS overhead, retransmissions, and WebSocket compression effects. They are therefore stable per-site application-bandwidth measurements, not exact network-interface or hosting-provider billing counters.

## Storage and efficiency

Counting happens in streaming paths and does not buffer request or response bodies. Deltas are accumulated in memory by site, minute, IP, country, and protocol, then flushed to `bandwidth_minutes` in batches. The default flush interval is 10 seconds.

If the pending-key limit is reached during a high-cardinality attack, already tracked IPs remain exact while new IPs are folded into `__other__` rows for their country and protocol. Site and country totals remain complete, while unbounded unique source addresses cannot create unbounded pending memory. Configure this behavior with:

- `BG_BANDWIDTH_FLUSH_INTERVAL_MS`
- `BG_BANDWIDTH_MAX_PENDING_KEYS`

Bandwidth buckets use the same per-site retention period as request traffic events. Dashboard bandwidth queries flush pending counters first, so recent completed stream chunks appear without waiting for the periodic timer.

## Multiple BurrowGate instances

Each process aggregates its own live counters, while the database upserts safely add deltas from every instance. Reporting is shared when instances use the same database. The pending-key ceiling applies independently to each process.

## Bandwidth limit temp-bans

Independent of the reporting above, a site (with optional per-route override) can auto-ban a client IP that pushes more than a configured amount of bandwidth through in a time window. It is disabled by default. Configure it on the site's or route's **Protection** panel, next to Auto temp-ban durations:

- **Enforcement**: off by default.
- **Threshold**: bytes (entered in MiB) allowed per window before a ban triggers.
- **Window**: the fixed time window the threshold applies to, up to 3,600 seconds.
- **Ban duration**: how long the IP is added to the site's IP rules as a temporary `block`, the same mechanism used by managed protection auto-bans.

Detection uses a lightweight in-memory counter, separate from the reporting counters above, keyed per route (or the site when no route override applies) and IP. It is checked inline as request/response and WebSocket message bytes are already being counted, so it adds no extra I/O to the request path. Both directions count toward the threshold (bytes an IP sends to BurrowGate and bytes BurrowGate sends back to it), including cached responses (so an attacker cannot dodge the limit by requesting a large file in a loop instead of uploading). Because the counter is a fixed window checked per process, detection is not instantaneous and, like BurrowGate's other in-memory rate limiters, is not shared across multiple instances. Each process tracks its own traffic independently. The current request or connection that crosses the threshold is allowed to finish. The ban only affects subsequent requests, which are rejected by the same IP-rule check described in [NETWORK_POLICIES.md](NETWORK_POLICIES.md).

Use the per-route override to raise or disable the limit for routes that are expected to carry heavy legitimate traffic, such as a download API or a path pattern like `/assets/**`, without loosening the default everywhere else.

The equivalent setting for TCP/UDP streams is documented in [STREAMS.md](STREAMS.md).
