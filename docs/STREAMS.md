# BurrowGate TCP and UDP streams

BurrowGate can proxy arbitrary TCP and UDP services independently from HTTP sites. Open the **Streams** dashboard using the dashboard switcher.

## Configuration

Each stream contains:

- a name, used throughout the admin dashboard instead of a bare port number;
- an incoming port;
- a forward host and port;
- TCP, UDP, or both protocols;
- optional PROXY protocol client-address forwarding;
- an optional certificate for incoming TCP TLS termination;
- monitoring-data retention from 1 to 365 days.

TCP and UDP use separate operating-system port namespaces, so one stream may enable both on the same numeric port. Two streams cannot claim the same protocol and incoming port. TCP stream ports also cannot conflict with BurrowGate's HTTP or HTTPS listener.

Changing the incoming port, forward host/port, certificate, PROXY protocol mode, or a TCP/UDP toggle swaps the stream's listener. That can be scheduled for a chosen time instead of applying immediately, so it doesn't land in the middle of active connections. See [`SCHEDULED_CHANGES.md`](SCHEDULED_CHANGES.md).

## Client IP forwarding

TCP and UDP upstream sockets normally see BurrowGate as their network peer. A stream can prepend the standard HAProxy PROXY protocol so a compatible upstream can recover the original client IP and port:

- **Disabled** is the default and preserves raw byte forwarding.
- **PROXY protocol v1** sends a human-readable header at the start of each TCP connection. Version 1 does not support UDP.
- **PROXY protocol v2** sends a binary header at the start of each TCP connection and prepends a binary `DGRAM` header to every forwarded UDP datagram.

The upstream service must be configured to expect the selected format. A service without PROXY protocol support will treat the header as application data and usually reject the connection or datagram. Restrict the upstream port so it only accepts traffic from trusted BurrowGate hosts (otherwise a direct client could submit a forged header).

PROXY metadata is transport overhead and is not included in BurrowGate's client payload bandwidth totals. The wire formats follow the [HAProxy PROXY protocol specification](https://github.com/haproxy/haproxy/blob/master/doc/proxy-protocol.txt).

## TLS

Stream certificates reuse active certificates managed by HTTP sites:

- with a certificate, BurrowGate terminates incoming TCP TLS and forwards decrypted TCP payloads;
- without a certificate, BurrowGate forwards bytes unchanged, including TLS that will be terminated by the upstream;
- UDP remains raw because Bun does not provide DTLS through its UDP API.

Renewing a selected ACME certificate reloads the affected stream listener. A certificate cannot be removed while a stream references it.

## Monitoring

For every TCP connection BurrowGate records the client IP, country, and ASN when the socket opens and closes. It also records upstream failures, disconnect reason, and bytes successfully forwarded in both directions.

UDP has no native connection lifecycle. BurrowGate therefore creates a peer session for each client IP and source port when its first datagram arrives. The peer receives a dedicated connected upstream UDP socket so replies return to the correct client. After `BG_STREAM_UDP_PEER_IDLE_TIMEOUT_SECONDS` without activity, the peer is closed and a disconnect event is recorded.

Payload totals are accumulated in memory and persisted in one-minute buckets by stream, incoming port, IP, country, and protocol. The per-stream retention value removes both lifecycle events and bandwidth buckets. Lowering retention triggers immediate cleanup; regular maintenance performs subsequent cleanup.

## Tor and network category policy

Each stream can independently identify or block Tor exit nodes and any ASN-based network category (VPN, datacenter, ISP/telecom, and more) from the **Network rules** tab. The modes apply to both TCP connections and UDP peers and are disabled by default. ASN category classification requires GeoLite2 ASN enrichment.

Explicit IP/CIDR and ASN **Allow** rules override automatic category blocking, so a trusted network can be admitted without disabling the broader category. Country and default allows do not override category blocks. BurrowGate records classifications in stream events and exposes a hidden **Network type** column for live connections and the Traffic log. See [Tor and ASN network category detection](NETWORK_PRIVACY.md) for data sources, precedence, and limitations.

## Origin health checks

A TCP-enabled stream can opt into a periodic health check: BurrowGate opens, then immediately closes, a TCP connection to the stream's forward host and port on a timer and records the connect latency or a timeout. This is disabled by default - enabling it starts making connection attempts against your real backend (e.g. a game server) - and is configured per stream on the Streams dashboard's **Health** tab, alongside the check interval (minimum 3 seconds), timeout, and consecutive failure/recovery thresholds used to decide when the origin is actually considered down or recovered.

UDP-only streams cannot be health-checked this way. There is no generic UDP echo protocol to probe an arbitrary upstream with. Existing bandwidth and connection monitoring for UDP streams is unaffected.

Results are aggregated into one-minute buckets (minimum, maximum, and average latency, plus a count of timed-out checks) and shown as a graph on the Health tab, so a network blip between BurrowGate and the origin - even a brief one - shows up in the data instead of only being visible as scattered connection failures. The per-stream retention value also governs this history.

A state transition (origin becomes unhealthy, or recovers) can trigger a webhook - configured independently on the **Notifications** dashboard, alongside auto-ban notifications for this stream. See [`docs/NOTIFICATIONS.md`](NOTIFICATIONS.md).

## Bandwidth limit temp-bans

Each stream can independently auto-ban a client IP that pushes more than a configured amount of bandwidth through its TCP side and/or its UDP side within a time window - useful since one stream can carry both protocols on the same port. Configure it on the Streams dashboard's **Protection** tab, per selected stream. It is disabled by default for both protocols.

Both directions of traffic count toward the threshold, matching the existing live per-IP byte-rate tracking that feeds the `connection.bytes_per_second` protection field. Detection happens as bytes are already being forwarded, using a fixed-window counter kept separately from the WAF-facing counters described above, so it adds no extra I/O to the data path. Unlike the web bandwidth limit (see [BANDWIDTH.md](BANDWIDTH.md)), crossing the threshold both bans the IP - added to the stream's IP rules as a temporary `block`, the same mechanism managed stream-protection auto-bans use - and immediately closes the offending TCP connection or UDP peer session, since a single long-lived stream connection would otherwise keep flowing unchecked between admission checks.

An auto-ban can also trigger a `stream_ip_banned` webhook naming the banned IP, configured on the **Notifications** dashboard. See [`docs/NOTIFICATIONS.md`](NOTIFICATIONS.md).

## Docker networking

The default Compose file uses `network_mode: host`, so every port a stream binds on the host is immediately reachable with no Compose changes or container restart. Firewall the host to only expose the ports you intend to publish.

## Runtime limits

| Variable                                  |   Default | Purpose                                            |
| ----------------------------------------- | --------: | -------------------------------------------------- |
| `BG_STREAM_CONNECT_TIMEOUT_SECONDS`       |      `15` | Maximum upstream TCP connection establishment time |
| `BG_STREAM_IDLE_TIMEOUT_SECONDS`          |     `300` | TCP connection inactivity timeout                  |
| `BG_STREAM_UDP_PEER_IDLE_TIMEOUT_SECONDS` |      `60` | UDP peer-session inactivity timeout                |
| `BG_STREAM_MAX_BUFFERED_BYTES`            | `1048576` | Per-TCP-connection backpressure queue limit        |
| `BG_STREAM_MAX_UDP_PEERS`                 |   `10000` | Maximum live UDP peers per stream                  |
| `BG_STREAM_MAX_PENDING_DATAGRAMS`         |     `256` | Datagram queue limit during UDP backpressure       |
| `BG_STREAM_MAX_PENDING_EVENTS`            |  `100000` | Lifecycle-event queue limit during SQL outages     |
