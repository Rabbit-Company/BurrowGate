# BurrowGate TCP and UDP streams

BurrowGate can proxy arbitrary TCP and UDP services independently from HTTP sites. Open the **Streams** dashboard using the dashboard switcher.

## Configuration

Each stream contains:

- an incoming port;
- a forward host and port;
- TCP, UDP, or both protocols;
- an optional certificate for incoming TCP TLS termination;
- monitoring-data retention from 1 to 365 days.

TCP and UDP use separate operating-system port namespaces, so one stream may enable both on the same numeric port. Two streams cannot claim the same protocol and incoming port. TCP stream ports also cannot conflict with BurrowGate's HTTP or HTTPS listener.

## TLS

Stream certificates reuse active certificates managed by HTTP sites:

- with a certificate, BurrowGate terminates incoming TCP TLS and forwards decrypted TCP payloads;
- without a certificate, BurrowGate forwards bytes unchanged, including TLS that will be terminated by the upstream;
- UDP remains raw because Bun does not provide DTLS through its UDP API.

Renewing a selected ACME certificate reloads the affected stream listener. A certificate cannot be removed while a stream references it.

## Monitoring

For every TCP connection BurrowGate records the client IP and country when the socket opens and closes. It also records upstream failures, disconnect reason, and bytes successfully forwarded in both directions.

UDP has no native connection lifecycle. BurrowGate therefore creates a peer session for each client IP and source port when its first datagram arrives. The peer receives a dedicated connected upstream UDP socket so replies return to the correct client. After `BG_STREAM_UDP_PEER_IDLE_TIMEOUT_SECONDS` without activity, the peer is closed and a disconnect event is recorded.

Payload totals are accumulated in memory and persisted in one-minute buckets by stream, incoming port, IP, country, and protocol. The per-stream retention value removes both lifecycle events and bandwidth buckets. Lowering retention triggers immediate cleanup; regular maintenance performs subsequent cleanup.

## Docker networking

Docker cannot dynamically publish a new container port after the container has started. In bridge mode, add every stream protocol and port to Compose and recreate the container:

```yaml
services:
  burrowgate:
    ports:
      - "80:80/tcp"
      - "443:443/tcp"
      - "25565:25565/tcp"
      - "19132:19132/udp"
```

The stream editor generates the required Compose mapping. Linux deployments that require arbitrary dashboard-managed ports may instead use host networking and firewall the host appropriately.

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
