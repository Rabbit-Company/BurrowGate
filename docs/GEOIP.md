# GeoIP Analytics

BurrowGate can enrich request events and visitor sessions with an ISO 3166-1 alpha-2 country code and an Autonomous System Number (ASN) identifying the network provider behind the client IP. The dashboard uses the country code to render an interactive SVG world map, and both dimensions get their own network-policy rules and "Top" list.

## Design

GeoIP lookups use local MaxMind DB files. No network request is made while proxying traffic.

BurrowGate loads one `GeoLite2-Country.mmdb` reader and, independently, one `GeoLite2-ASN.mmdb` reader, reusing each for every lookup. Both readers include a bounded LRU cache and watch their file for database updates. Only the two-letter country code, the ASN, and the ASN's organization name are stored with request events, sessions, and stream events. Coordinates, city names, and full GeoIP responses are not stored.

This design keeps the request path fast and memory usage predictable:

- one small country-level MMDB reader and one ASN MMDB reader per BurrowGate process, loaded and retried independently
- a constant-time in-memory availability check in the request path for each reader
- a configurable bounded lookup cache per reader
- one nullable two-character column, one nullable ASN number column, and one nullable organization-name column per event and session
- one GeoIP/ASN result pair reused by network policy and event logging
- indexed SQL aggregation for dashboard maps and lists
- a Brotli or gzip compressed static SVG downloaded once and cached by the browser
- SVG paths created once and recolored in place when metrics change

## Configuration

```env
BG_GEOIP_ENABLED=true
BG_GEOIP_DATABASE_PATH=./data/geoip/GeoLite2-Country.mmdb
BG_GEOIP_CACHE_ENTRIES=4096
BG_GEOIP_BACKFILL_BATCH_SIZE=500
BG_GEOIP_RETRY_SECONDS=30
BG_GEOIP_ASN_ENABLED=true
BG_GEOIP_ASN_DATABASE_PATH=./data/geoip/GeoLite2-ASN.mmdb
```

`BG_GEOIP_CACHE_ENTRIES` controls each reader's in-memory LRU cache. Reduce it on very small systems or increase it when many clients repeatedly connect from the same addresses.

`BG_GEOIP_BACKFILL_BATCH_SIZE` controls how many older request events and sessions are enriched during each maintenance pass, for country and ASN independently. Updates are written sequentially to avoid a burst of database work. Set it to `0` to disable backfilling.

`BG_GEOIP_ASN_ENABLED` defaults to the same value as `BG_GEOIP_ENABLED`. Set it independently to run one database without the other.

## Docker Compose updater

The included Compose file has an optional `geoipupdate` profile using MaxMind's official updater image, configured to fetch both `GeoLite2-Country` and `GeoLite2-ASN`.

Create a MaxMind account and license key, then add these values to `.env`:

```env
MAXMIND_ACCOUNT_ID=123456
MAXMIND_LICENSE_KEY=replace-with-license-key
GEOIPUPDATE_FREQUENCY=72
```

Start BurrowGate with the updater profile:

```bash
docker compose --profile geoip up -d --build
```

The updater writes `GeoLite2-Country.mmdb` and `GeoLite2-ASN.mmdb` into the shared `burrowgate-geoip` volume. BurrowGate retries loading a database that was missing during startup, then watches each loaded file and reloads it without a restart. Remove `GeoLite2-ASN` from `GEOIPUPDATE_EDITION_IDS` in `docker-compose.yml`/`docker-compose.override.yml` if you only want country data.

## Manual database installation

Place the databases at:

```text
data/geoip/GeoLite2-Country.mmdb
data/geoip/GeoLite2-ASN.mmdb
```

Or set custom paths with `BG_GEOIP_DATABASE_PATH` and `BG_GEOIP_ASN_DATABASE_PATH`. Either file can be present without the other; each dimension degrades independently (see below) when its database is missing.

## Client IP source

GeoIP uses the same normalized client IP as IP rules, rate limiting, sessions, and traffic logging. Configure each site's **Client IP source** in the Sites dashboard to match the proxy in front of that hostname. Keep `direct` for sites exposed by BurrowGate itself, and do not trust forwarded IP headers from arbitrary clients. `BG_PROXY_PRESET` applies only to dashboard requests.

## Existing data

New events and sessions are enriched when they are created. Existing records with no country code or ASN are backfilled independently in bounded batches during maintenance.

Private and loopback addresses (RFC 1918, link-local, and their IPv6 equivalents) are detected directly from the address itself, without a database lookup, and are labeled `Local / private network` (country code `XX`, ASN `0`). This works even when the GeoIP/ASN databases are disabled or unavailable. Invalid addresses or public addresses not present in a database remain `Unknown` (country code `ZZ`, ASN `0`).

## Dashboard map

The Geographic distribution panel supports:

- request counts by country
- newly created sessions by country
- the selected dashboard time range
- hover and keyboard tooltips
- logarithmic color scaling for large traffic differences
- a top-country list and unknown count

The map is rendered as an inline interactive SVG. The bundled geometry comes from `@svg-maps/world`, is cached as a static asset, and is licensed under CC BY 4.0. ASN has no equivalent map (there is no meaningful geometry for a network provider); it instead gets a "Top ASNs" list beside the map, following the same date range and metric mode.

## Accuracy and licensing

IP geolocation is approximate and should not be used to identify a household or precise physical address. Follow MaxMind's GeoLite license, attribution, and database update requirements.

## Dashboard tables and filters

Traffic and session tables show the two-letter country code and the ASN. Hovering the country code or IP address displays the full country name; hovering the ASN badge displays the network provider's organization name. Both tables can be filtered and sorted by country or ASN. Bandwidth tables and aggregation remain country-only; ASN is not tracked in the per-minute bandwidth rollup.

## Country and ASN access rules

The Network rules tab can allow, block, or challenge a country or an ASN. A site can also use a default country action to create a country allowlist or blocklist; there is no default ASN action; instead, add explicit ASN allow/block rules. Explicit IP rules take precedence over ASN rules, which take precedence over country rules, which take precedence over the defaults. See [NETWORK_POLICIES.md](NETWORK_POLICIES.md).

Country and ASN rules are held in the per-site (and per-route, per-stream) network-policy cache. Request processing uses the country code and ASN already returned by the shared local GeoIP readers and does not perform an additional database query.
