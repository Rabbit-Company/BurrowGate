# BurrowGate TLS and ACME

BurrowGate can terminate TLS itself and select a certificate by SNI for every protected hostname. It supports uploaded PEM certificates and ACME HTTP-01 issuance through `acme-client`.

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

Activating or replacing a certificate rebuilds the HTTPS SNI listener. Two enabled sites may use the same hostname on different ports for plain HTTP development, but TLS cannot be enabled for both because SNI selects by hostname rather than port. BurrowGate rejects that ambiguous configuration.

If a site already has a certificate, changing its public hostname is allowed only when the existing certificate covers the new hostname. Otherwise, remove or replace the certificate first.

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

## Renewal

BurrowGate stores `next_renewal_at` for ACME-managed certificates. Maintenance checks due certificates automatically. A failed renewal does not overwrite the currently active certificate. Errors and issuance activity appear in the site's TLS panel.

## Current constraints

- HTTP-01 supports public DNS hostnames, not `localhost`, `.local` names, IP literals, or wildcard names.
- DNS-01 provider plugins are not implemented yet.
- Rebuilding the HTTPS listener can briefly interrupt new TLS connections.
- Upstream WebSocket proxying remains a separate gateway feature.

## HTTP session cookies

TLS mode and cookie mode are separate settings. A site may have a certificate while still allowing HTTP when **Force HTTPS** is disabled. Keep:

```env
BG_COOKIE_SECURE=auto
```

when users must be able to complete BurrowGate verification on either HTTP or HTTPS. `BG_COOKIE_SECURE=true` deliberately prevents admin and visitor cookies from being issued over HTTP and should be used only for HTTPS-only deployments.
