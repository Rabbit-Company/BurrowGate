# BurrowGate TLS and ACME

BurrowGate can terminate TLS itself and select a certificate by SNI for every protected hostname. It supports uploaded PEM certificates and ACME issuance through `acme-client`, using either HTTP-01 or DNS-01 (RFC 2136).

## Listener model

BurrowGate has separate HTTP and HTTPS listeners:

```env
BG_HTTP_ENABLED=true
BG_HTTP_PORT=8080
BG_HTTPS_ENABLED=true
BG_HTTPS_PORT=8443
```

Ports may be translated by Docker or a router. For example, Compose can expose public port 80 to container port 8080 and public port 443 to container port 8443:

```env
BG_HTTP_PUBLIC_PORT=80
BG_HTTPS_PUBLIC_PORT=443
BG_TLS_LISTENER_DRAIN_TIMEOUT_MS=5000
```

HTTP-01 validation always arrives at the public server on port 80. BurrowGate's internal HTTP port can differ when NAT or Docker forwards public port 80 to it.

## Encrypting private keys

Set one stable master key before uploading or issuing certificates:

```bash
openssl rand -base64 48
```

```env
BG_MASTER_KEY=<generated-value>
```

For containers, prefer a mounted secret file:

```env
BG_MASTER_KEY_FILE=/run/secrets/burrowgate-master-key
```

BurrowGate derives an AES-256-GCM key from this value and encrypts certificate and ACME account private keys before writing them to SQL. Back up the master key separately. Losing or changing it makes existing encrypted private keys unusable.

## Uploaded certificates

Open **Sites**, edit a site, then use **TLS certificate -> Uploaded certificate**. The certificate may contain a full PEM chain. BurrowGate validates that:

- the certificate is parseable and not expired;
- it covers the site's public hostname;
- the supplied private key matches the certificate public key.

Activating or replacing a certificate starts a replacement HTTPS SNI listener with `SO_REUSEPORT` before the current listener is drained. The old listener stops accepting new connections only after the replacement has bound successfully. Existing requests are allowed to finish during the configured drain period, while long-lived connections are closed when the drain timeout expires. Two enabled sites may use the same hostname on different ports for plain HTTP development, but TLS cannot be enabled for both because SNI selects by hostname rather than port. BurrowGate rejects that ambiguous configuration.

If a site already has a certificate, changing its public hostname is allowed only when the existing certificate covers the new hostname. Otherwise, remove or replace the certificate first. Since this rebuilds the HTTPS SNI listener, the hostname change can be scheduled for a chosen time instead of applying immediately - see [`SCHEDULED_CHANGES.md`](SCHEDULED_CHANGES.md). A site without a certificate is unaffected: its hostname is pure routing data and changes apply immediately.

## Let's Encrypt HTTP-01

1. Point the site's DNS record to BurrowGate's public IP.
2. Make public TCP port 80 reach BurrowGate's HTTP listener.
3. Make public TCP port 443 reach BurrowGate's HTTPS listener.
4. Configure a public host without a custom port, such as `sonarr.example.com`.
5. Start with the staging directory and request a certificate in the dashboard.
6. After staging works, switch to the production directory and issue the trusted certificate.

The ACME route is served directly at:

```text
/.well-known/acme-challenge/<token>
```

It bypasses proof-of-work, visitor sessions, origin proxying, IP rules, and force-HTTPS redirects.

## Let's Encrypt DNS-01 (RFC 2136)

Use DNS-01 instead of HTTP-01 when a site's public hostname can't have port 80 reachable from the internet - the origin is behind a firewall, on a LAN, or fronted by something else on port 80. DNS-01 proves control of the domain by publishing a TXT record instead, so no inbound port is required at all.

BurrowGate speaks DNS-01 through **RFC 2136 dynamic DNS updates**, signed with a TSIG key, against a self-hosted authoritative nameserver (BIND, PowerDNS, Technitium, Knot, ...). There is no built-in integration with a specific cloud DNS provider's API.

1. On the nameserver authoritative for the zone, generate a TSIG key (only `hmac-sha256` is supported):
   ```bash
   tsig-keygen -a hmac-sha256 burrowgate-key
   ```
2. Grant that key update rights, scoped to just the `_acme-challenge` records it needs. In BIND:

   ```
   key "burrowgate-key" {
     algorithm hmac-sha256;
     secret "<the generated secret>";
   };

   zone "example.com" {
     type master;
     ...
     update-policy { grant burrowgate-key name _acme-challenge.example.com. TXT; };
   };
   ```

3. In BurrowGate, open **DNS Providers** (next to Firewall Sync in the dashboard nav) and add a provider with the nameserver's address, the zone, the TSIG key name, and its secret.
4. On the site's TLS panel, set **Challenge type** to DNS-01 and pick the provider, then request the certificate as usual.

After publishing the TXT record, BurrowGate waits the provider's configured **propagation** window (default 30s) before asking the ACME server to validate - a fixed wait rather than active polling, so a secondary/hidden-master DNS setup with any replication lag needs a longer window. `docs/TLS.md`'s wildcard restriction still applies: DNS-01 issues the same single-hostname certificates as HTTP-01, not `*.example.com` wildcards.

If the nameserver rejects an update, the certificate event log shows the DNS RCODE - `REFUSED` or `NOTAUTH` almost always means the TSIG key name/secret or the `update-policy` grant doesn't match.

## Renewal

BurrowGate stores `next_renewal_at` for ACME-managed certificates. Maintenance checks due certificates automatically. A failed renewal does not overwrite the currently active certificate. Errors and issuance activity appear in the site's TLS panel.

## HTTP/2 (experimental)

BurrowGate can serve HTTP/2 (`h2`) over the same HTTPS listener, port, and TLS connection as HTTP/1.1 - unlike HTTP/3 below, this needs no separate listener or client-visible upgrade step, since the protocol is negotiated during the TLS handshake itself (ALPN). It's off by default and gated behind:

```toml
BG_HTTP2_ENABLED=true
```

When enabled, a client that offers `h2` in its TLS handshake gets served over HTTP/2. A client that doesn't (or that isn't using TLS) keeps getting HTTP/1.1 unchanged. This is an instance-wide toggle applying to every site, since all sites share the one HTTPS listener - there is no per-site setting. It's unrelated to the per-site "Outbound connection protocol" setting, which controls BurrowGate -> origin connections, not client -> BurrowGate ones.

Leave this off unless you specifically want to experiment with it.

## HTTP/3 (experimental)

BurrowGate can add a UDP HTTP/3 listener next to the existing HTTPS TCP listener. It's off by default and gated behind:

```toml
BG_HTTP3_ENABLED=true
```

When enabled, BurrowGate advertises HTTP/3 via the `Alt-Svc` response header and lets clients upgrade on their own - HTTP/1.1 keeps working over TCP unchanged, and this instance-wide toggle applies to every site since all sites share the one HTTPS listener (there is no per-site HTTP/3 setting). `BG_HTTP2_ENABLED` and `BG_HTTP3_ENABLED` are independent and can both be on at once.

Leave this off unless you specifically want to experiment with it.

## Current constraints

- HTTP-01 and DNS-01 both support public DNS hostnames, not `localhost`, `.local` names, IP literals, or wildcard names.
- DNS-01 only speaks RFC 2136 dynamic updates - there is no built-in Cloudflare/Route53/other cloud DNS API integration.
- If a replacement listener cannot bind or load its TLS material, BurrowGate keeps the existing HTTPS listener active and records the activation failure.
- Upstream WebSocket proxying remains a separate gateway feature.

## HTTP session cookies

TLS mode and cookie mode are separate settings. A site may have a certificate while still allowing HTTP when **Force HTTPS** is disabled. Keep:

```env
BG_COOKIE_SECURE=auto
```

when users must be able to complete BurrowGate verification on either HTTP or HTTPS. `BG_COOKIE_SECURE=true` deliberately prevents admin and visitor cookies from being issued over HTTP and should be used only for HTTPS-only deployments.
