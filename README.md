# BurrowGate

BurrowGate is a self-hosted reverse proxy and access gateway built with Bun. It protects websites and APIs from bots and automated scrapers with route policies, rate limits, network rules, browser challenges, TLS termination, and traffic monitoring.

## Features

- Native HTTP and HTTPS listeners on ports 80 and 443
- Multi-site reverse proxy routing by hostname
- Automatic Let's Encrypt certificates using ACME HTTP-01
- Uploaded PEM certificate support
- SNI certificate selection for multiple domains
- Transparent HTTP, HTTPS, WebSocket, and secure WebSocket proxying
- Per-site and per-route access policies
- Fixed-window, sliding-window, and token-bucket rate limits
- Pluggable challenge providers and ordered challenge chains
- SHA-256 browser proof of work
- Opaque and revocable visitor sessions
- IPv4, IPv6, CIDR, and country pass, bypass, block, and challenge rules
- Site-wide default IP and country actions for allowlists and blocklists
- Signed origin verification headers
- Paginated traffic, session, route, rule, and site monitoring
- Per-site traffic retention
- Country-level GeoIP analytics with an interactive SVG world map
- Country codes, country filters, and country tooltips in traffic and session tables
- SQLite by default with PostgreSQL, MySQL, and MariaDB support
- Docker Compose deployment

## Quick Start

Requirements:

- A Linux VPS with Docker and Docker Compose
- Public TCP ports 80 and 443
- A domain pointing to the VPS for trusted TLS certificates

Clone and start BurrowGate:

```bash
git clone https://github.com/Rabbit-Company/BurrowGate.git
cd BurrowGate
docker compose up -d --build
docker compose logs burrowgate
```

BurrowGate generates a dashboard password, encryption key, and temporary self-signed certificate on the first startup. Read the generated dashboard password with:

```bash
docker compose exec burrowgate cat /app/data/bootstrap-admin-password.txt
```

Open the dashboard:

```text
https://SERVER_IP/_burrowgate/admin
```

The browser will warn about the temporary certificate until a trusted certificate is uploaded or issued.

Create a site from the **Sites** tab:

```text
Name: Sonarr
Public host: sonarr.example.com
Origin URL: http://10.0.0.20:8989
```

Point `sonarr.example.com` to the VPS, open the site's TLS settings, and request a Let's Encrypt certificate.

## Docker Deployment

The default Compose configuration is production ready:

- host port 80 maps to BurrowGate port 80
- host port 443 maps to BurrowGate port 443
- runtime data is stored in the `burrowgate-data` volume
- the process runs as the unprivileged `bun` user
- only `NET_BIND_SERVICE` is added for low-port binding

An `.env` file is optional. Copy the example file only when overriding defaults:

```bash
cp .env.example .env
nano .env
docker compose up -d --build --force-recreate
```

## Configuration

| Variable                            | Default                              | Description                                                                                |
| ----------------------------------- | ------------------------------------ | ------------------------------------------------------------------------------------------ |
| `BG_ENV`                            | `production`                         | Runtime environment                                                                        |
| `BG_HOST`                           | `0.0.0.0`                            | Listener address                                                                           |
| `BG_HTTP_ENABLED`                   | `true`                               | Enable the HTTP listener                                                                   |
| `BG_HTTP_PORT`                      | `80`                                 | Internal HTTP port                                                                         |
| `BG_HTTP_PUBLIC_PORT`               | `80`                                 | Public HTTP port used in redirects and ACME validation                                     |
| `BG_HTTPS_ENABLED`                  | `true`                               | Enable the HTTPS listener                                                                  |
| `BG_HTTPS_PORT`                     | `443`                                | Internal HTTPS port                                                                        |
| `BG_HTTPS_PUBLIC_PORT`              | `443`                                | Public HTTPS port used in redirects                                                        |
| `BG_TLS_LISTENER_DRAIN_TIMEOUT_MS`  | `5000`                               | Grace period before the previous HTTPS listener is force-closed after a certificate reload |
| `DATABASE_URL`                      | `sqlite://./data/burrowgate.db`      | Bun.SQL database URL                                                                       |
| `BG_ADMIN_USERNAME`                 | `admin`                              | Dashboard username                                                                         |
| `BG_ADMIN_PASSWORD`                 | generated                            | Dashboard password                                                                         |
| `BG_COOKIE_SECURE`                  | `auto`                               | Use secure cookies on HTTPS and ordinary cookies on HTTP                                   |
| `BG_MASTER_KEY`                     | generated                            | Encrypts certificate and ACME private keys                                                 |
| `BG_EVENT_RETENTION_DAYS`           | `7`                                  | Default retention assigned to new sites                                                    |
| `BG_GEOIP_ENABLED`                  | `true`                               | Enable country-level GeoIP enrichment                                                      |
| `BG_GEOIP_DATABASE_PATH`            | `./data/geoip/GeoLite2-Country.mmdb` | Local MaxMind database path                                                                |
| `BG_GEOIP_CACHE_ENTRIES`            | `4096`                               | Maximum GeoIP reader cache entries                                                         |
| `BG_GEOIP_RETRY_SECONDS`            | `30`                                 | Retry interval when the MMDB file is not available yet                                     |
| `BG_DEFAULT_POW_DIFFICULTY`         | `18`                                 | Default SHA-256 challenge difficulty                                                       |
| `BG_WEBSOCKET_ENABLED`              | `true`                               | Enable WebSocket proxying                                                                  |
| `BG_WEBSOCKET_IDLE_TIMEOUT_SECONDS` | `120`                                | WebSocket idle timeout from 10 to 960 seconds                                              |
| `BG_ACME_DIRECTORY_URL`             | Let's Encrypt production             | ACME directory URL                                                                         |
| `BG_ACME_EMAIL`                     | empty                                | Default ACME contact email                                                                 |

See [`.env.example`](.env.example) for every available setting.

### Database URLs

```env
DATABASE_URL=sqlite://./data/burrowgate.db
DATABASE_URL=postgres://user:password@postgres:5432/burrowgate
DATABASE_URL=mysql://user:password@mysql:3306/burrowgate
```

Bun.SQL selects the database adapter from the URL.

## Sites

Each site contains:

- a public hostname and optional port
- an HTTP or HTTPS origin URL
- an enabled state
- a default access mode
- default IP and country actions
- a visitor session lifetime
- a traffic retention period
- a challenge policy
- a signing secret for origin verification headers
- TLS and force-HTTPS settings

The selected site is stored in the dashboard URL. Traffic, sessions, network rules, route policies, and actions are scoped to that site.

Environment-based site seeding is disabled by default. It can be enabled for automated deployments:

```env
BG_SEED_DEFAULT_SITE=true
BG_DEFAULT_SITE_NAME=Sonarr
BG_DEFAULT_PUBLIC_HOST=sonarr.example.com
BG_DEFAULT_ORIGIN=http://10.0.0.20:8989
```

Environment settings only seed an empty database. Existing sites are managed from the dashboard.

## GeoIP Analytics

BurrowGate can store an ISO country code with each request event and visitor session. The dashboard renders an interactive SVG world map for request volume and newly created sessions.

Lookups use a local `GeoLite2-Country.mmdb` file. BurrowGate reuses one database reader, keeps a bounded LRU cache, and stores only the two-letter country code. It does not call an external GeoIP API for each request.

The included optional Compose profile runs MaxMind's official database updater:

```env
MAXMIND_ACCOUNT_ID=123456
MAXMIND_LICENSE_KEY=replace-with-license-key
```

```bash
docker compose --profile geoip up -d --build
```

See [`docs/GEOIP.md`](docs/GEOIP.md).

Third-party map and data attribution is documented in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

## Network Policies

Each site can define a default IP action, a default country action, explicit IP or CIDR rules, and explicit country rules. This supports blocklists, deny-by-default allowlists, and trusted clients that bypass browser verification.

Policy precedence is:

1. Longest matching IP or CIDR rule
2. Explicit country rule
3. Default country action
4. Default IP action
5. Route policy

Country policy fails open when the GeoIP database is unavailable. IP rules and the default IP action continue to apply.

See [`docs/NETWORK_POLICIES.md`](docs/NETWORK_POLICIES.md).

## Route Policies

Route policies can override a site's default behavior by path and HTTP method.

Available access modes:

- `inherit`: use the site default
- `challenge`: require the site or route challenge chain
- `bypass`: proxy without browser verification
- `block`: return HTTP 403 without contacting the origin

Example JSON API policy:

```text
Name: JSON API
Path: /api/**
Access mode: Bypass browser verification
Rate limiter: Sliding window
Maximum: 120
Window: 60000 ms
Identity: IP address
```

This allows non-browser API clients to work normally while BurrowGate applies request limits at the edge.

Rate limits can use the client IP, a verified BurrowGate session, or a selected application header. Counters can be shared across the policy or separated by path and method.

See [`docs/ROUTE_POLICIES.md`](docs/ROUTE_POLICIES.md).

## Challenge Providers

A site or route stores an ordered challenge policy:

```json
[
	{
		"provider": "pow-sha256",
		"config": {
			"difficulty": 18
		}
	}
]
```

The challenge registry is designed to support additional providers such as CAPTCHA services without changing the proxy or session flow.

See [`docs/ADDING_CHALLENGES.md`](docs/ADDING_CHALLENGES.md).

## TLS Certificates

Each site supports:

- disabled TLS
- an uploaded certificate chain and private key
- automatic Let's Encrypt certificates

BurrowGate serves ACME HTTP-01 challenges directly from port 80 before redirects, route policies, IP rules, sessions, or browser challenges.

Private keys are encrypted with AES-256-GCM before they are stored in SQL. The encryption key is read from `BG_MASTER_KEY`, `BG_MASTER_KEY_FILE`, or the generated `data/master.key` file.

Back up the database and master key together. Losing the master key makes stored private keys unusable.

See [`docs/TLS.md`](docs/TLS.md).

## WebSocket Proxying

WebSocket upgrades pass through the same site, route, IP, rate-limit, and session checks as normal HTTP requests.

Protocol mapping is automatic:

```text
http://origin.example.com  -> ws://origin.example.com
https://origin.example.com -> wss://origin.example.com
```

BurrowGate forwards application cookies, authentication headers, binary messages, text messages, and negotiated subprotocols. BurrowGate credentials are removed before the upstream handshake.

## Sessions and API Tokens

After a successful challenge, BurrowGate creates a random opaque token and stores only its SHA-256 hash. Browsers receive an HTTP-only cookie.

API clients can use:

```http
Authorization: Burrow <token>
```

or:

```http
X-Burrow-Token: <token>
```

Sessions can be monitored and revoked from the dashboard.

## Origin Verification

BurrowGate signs origin headers with the site's signing secret:

```http
X-BurrowGate-Verified: true
X-BurrowGate-Access-Mode: verified
X-BurrowGate-Session-Id: sess_...
X-BurrowGate-Client-Ip: 203.0.113.10
X-BurrowGate-Timestamp: 1785681000
X-BurrowGate-Signature: <HMAC-SHA256>
```

Origins should reject direct public traffic. Use a private network, firewall allowlist, WireGuard, or mutual TLS so requests cannot bypass BurrowGate.

## Monitoring

The dashboard includes:

- request volume, blocked requests, errors, and latency
- active, expired, and revoked sessions
- IP-rule activity and current rule state
- route-policy outcomes and configuration totals
- cross-site request and latency comparison
- interactive country map for requests and newly created sessions
- server-side pagination, search, filters, and sorting
- exact From and To date-time selection shared by statistics, graphs, maps, traffic, and sessions
- drag-to-select time ranges directly on time-series graphs

BurrowGate automatically selects a suitable graph bucket size for the chosen interval and limits the result to roughly 120 points. Missing intervals are returned as zero values so graphs remain stable during quiet periods. Dragging across a time-series graph applies the highlighted interval to the full dashboard.

Traffic retention is configured per site from 1 to 365 days. Maintenance removes expired events automatically.

## Development

Install dependencies:

```bash
bun install
```

Start BurrowGate in watch mode:

```bash
bun run dev
```

Start the example origin server:

```bash
bun run origin
```

Run tests and TypeScript checks:

```bash
bun test
bun run typecheck
```

Regenerate the compressed world map assets after changing `public/world.svg`:

```bash
bun run build:map
```

The project uses `.editorconfig` and `.prettierrc.json` with tabs and a width of 2. YAML files use two spaces.

## Current Limitations

- ACME supports HTTP-01 only. Wildcard certificates require DNS-01 support.
- Route rate-limit counters are stored in memory and reset when the process restarts.
- Multiple gateway nodes do not share rate-limit counters yet.
- Detailed request events are stored in SQL. Very high traffic deployments should use an external log store.

## License

BurrowGate is licensed under the GNU General Public License v3.0. See [`LICENSE`](LICENSE).
