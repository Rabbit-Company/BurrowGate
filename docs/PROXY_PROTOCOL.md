# Incoming PROXY protocol

BurrowGate accepts PROXY protocol v1 and v2 from load balancers on the shared HTTP/HTTPS listeners and on TCP Streams. BurrowGate reads and removes the PROXY header before HTTP parsing or TLS negotiation. The original client address and port are used for policy checks, connection limits, rate limiting, monitoring, WebSocket upgrades, and client IP forwarding to upstream servers. Stream bandwidth totals exclude the PROXY header.

A Stream's **Client IP forwarding to upstream** setting sends a new PROXY header to the origin. Configure it separately. When both options are enabled, the outgoing header contains the original client and destination addresses and ports. Application data follows the outgoing header.

## Sites and the dashboard

Sites and the dashboard share HTTP/HTTPS listeners. Configure incoming PROXY protocol for each listener. Add these settings to each node's `.env` and replace the example address with the load balancer IP that connects to BurrowGate:

```dotenv
BG_HTTPS_PROXY_PROTOCOL=true
BG_HTTP_PROXY_PROTOCOL=false
BG_PROXY_PROTOCOL_TRUSTED_CIDRS=10.0.0.2/32
BG_PROXY_PROTOCOL_ALLOW_DIRECT=true
```

Restart BurrowGate after changing these settings. The trusted list accepts IPv4/IPv6 addresses and CIDRs, separated by commas or whitespace. Use the load balancer's private IP when it connects through the private network, or its public IP when using public targets. Specify each load balancer separately when there is more than one.

The PROXY client IP takes precedence over HTTP forwarding headers and the Site/dashboard IP extraction preset. Direct connections keep using their normal IP extraction preset. No client-controlled HTTP header can set PROXY connection metadata.

`BG_PROXY_PROTOCOL_ALLOW_DIRECT=true` preserves direct admin requests between HA members, browser access to individual nodes, and ordinary health checks. Any peer can connect directly. BurrowGate accepts PROXY headers from configured trusted peers and rejects them from other peers. This setting applies to all enabled incoming PROXY listeners, including Streams.

Set it to `false` to require a valid PROXY header from a trusted peer on every connection. Health checks and HA admin calls to those ports must then pass through a proxy that supplies the header. The HA mesh uses a separate listener.

## Load balancer configuration

Use a load balancer that sends standard PROXY protocol v1 or v2 headers. For HTTPS terminated by BurrowGate, configure TCP forwarding from port 443 to each node's HTTPS port. The load balancer must send the PROXY header before passing through the TLS handshake. Enable PROXY protocol on the load balancer after the BurrowGate settings are active.

If the load balancer terminates TLS, configure the BurrowGate listener to match the connection it forwards. Use the HTTP listener for plain HTTP or the HTTPS listener for an encrypted connection, and enable incoming PROXY support on that listener when the load balancer sends PROXY headers.

For an HTTP service sending PROXY headers to port 80, also set `BG_HTTP_PROXY_PROTOCOL=true`. Leave it disabled when that service forwards ordinary HTTP without a header. Secure cookies follow BurrowGate's listener transport. PROXY headers and HTTP forwarding headers do not make an HTTP listener secure.

For HA readiness, configure an HTTP health check of `/_burrowgate/health` on the node's HTTP port. With direct connections allowed, checks work whether or not the health checker supplies a PROXY header. The default Docker health check also continues to work.

## Streams

In the Stream form, enable **Accept PROXY protocol from a load balancer** and enter **Trusted load balancer addresses**. TCP must be enabled. The incoming listener accepts both v1 and v2 automatically. TLS termination and passthrough are both supported. These settings are persisted, replicated to HA nodes, and can be scheduled with other listener changes.

The API fields are `incomingProxyProtocol` (boolean, default `false`) and `trustedProxyCidrs` (array of IP addresses/CIDRs). Outgoing `proxyProtocol` retains its existing `disabled`, `v1`, and `v2` values. Incoming PROXY protocol requires TCP. UDP forwarding and outgoing v2 datagrams work as before.

## Transport behavior

Malformed headers, unsupported address families/transports, oversized v2 headers (more than 4096 bytes), and incomplete headers that exceed five seconds are rejected. IPv4, IPv6, v1 `UNKNOWN`, v2 `LOCAL`/`UNSPEC`, and well-formed unknown v2 TLVs are supported. `UNKNOWN`, `LOCAL`, and `UNSPEC` use the socket peer address. HTTP/2 over TCP is supported. Disable HTTP/3 on HTTPS listeners using incoming PROXY protocol.
