# GeoIP Analytics

BurrowGate can enrich request events and visitor sessions with an ISO 3166-1 alpha-2 country code. The dashboard uses these codes to render an interactive SVG world map for requests and sessions.

## Design

GeoIP lookups use a local MaxMind DB file. No network request is made while proxying traffic.

BurrowGate loads one `GeoLite2-Country.mmdb` reader and reuses it for every lookup. The reader includes a bounded LRU cache and watches the file for database updates. Only the two-letter country code is stored with request events and sessions. Coordinates, city names, and full GeoIP responses are not stored.

This design keeps the request path fast and memory usage predictable:

- one small country-level MMDB reader per BurrowGate process
- a constant-time in-memory availability check in the request path
- a configurable bounded lookup cache
- one nullable two-character column per event and session
- one GeoIP result reused by network policy and event logging
- indexed SQL aggregation for dashboard maps
- a Brotli or gzip compressed static SVG downloaded once and cached by the browser
- SVG paths created once and recolored in place when metrics change

## Configuration

```env
BG_GEOIP_ENABLED=true
BG_GEOIP_DATABASE_PATH=./data/geoip/GeoLite2-Country.mmdb
BG_GEOIP_CACHE_ENTRIES=4096
BG_GEOIP_BACKFILL_BATCH_SIZE=500
BG_GEOIP_RETRY_SECONDS=30
```

`BG_GEOIP_CACHE_ENTRIES` controls the reader's in-memory LRU cache. Reduce it on very small systems or increase it when many clients repeatedly connect from the same addresses.

`BG_GEOIP_BACKFILL_BATCH_SIZE` controls how many older request events and sessions are enriched during each maintenance pass. Updates are written sequentially to avoid a burst of database work. Set it to `0` to disable backfilling.

## Docker Compose updater

The included Compose file has an optional `geoipupdate` profile using MaxMind's official updater image.

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

The updater writes `GeoLite2-Country.mmdb` into the shared `burrowgate-geoip` volume. BurrowGate retries loading a database that was missing during startup, then watches the loaded file and reloads it without a restart.

## Manual database installation

Place a country database at:

```text
data/geoip/GeoLite2-Country.mmdb
```

Or set a custom path with `BG_GEOIP_DATABASE_PATH`.

## Client IP source

GeoIP uses the same normalized client IP as IP rules, rate limiting, sessions, and traffic logging. When BurrowGate is placed behind another proxy, configure the trusted proxy preset correctly. Do not trust forwarded IP headers from arbitrary clients.

## Existing data

New events and sessions are enriched when they are created. Existing records with no country code are backfilled in bounded batches during maintenance.

Records that use private addresses, loopback addresses, invalid addresses, or addresses not present in the database remain `Unknown`.

## Dashboard map

The Geographic distribution panel supports:

- request counts by country
- newly created sessions by country
- the selected dashboard time range
- hover and keyboard tooltips
- logarithmic color scaling for large traffic differences
- a top-country list and unknown count

The map is rendered as an inline interactive SVG. The bundled geometry comes from `@svg-maps/world`, is cached as a static asset, and is licensed under CC BY 4.0.

## Accuracy and licensing

IP geolocation is approximate and should not be used to identify a household or precise physical address. Follow MaxMind's GeoLite license, attribution, and database update requirements.

## Dashboard tables and filters

Traffic and session tables show the two-letter country code. Hovering the code or IP address displays the full country name. Both tables can be filtered and sorted by country.

## Country access rules

The Network rules tab can allow, block, or challenge a country. A site can also use a default country action to create a country allowlist or blocklist. See [NETWORK_POLICIES.md](NETWORK_POLICIES.md).

Country rules are held in the per-site network-policy cache. Request processing uses the country code already returned by the shared local GeoIP reader and does not perform an additional database query.
