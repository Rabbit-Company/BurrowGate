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
