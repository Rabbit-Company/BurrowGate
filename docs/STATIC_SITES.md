# Static file origins

Every origin in a site's pool - the primary origin created with the site, or
any additional origin added from the **Origins** tab - can be either type:

- **Reverse proxy** (the default): forwards to an HTTP/HTTPS backend
- **Static files**: BurrowGate serves files directly from a folder on disk.
  No backend process, no extra reverse-proxy hop -
  just a folder of built assets.

Static and proxy origins can be mixed in the same pool, so (for example) a
site's primary origin can serve a prebuilt marketing page as static files
while a secondary origin proxies `/api` to an application server, selected
by [route policy](ROUTE_POLICIES.md).

## Choosing a folder

Static folders are confined to BurrowGate's static-sites directory
(`BG_STATIC_ROOT_DIR`, default `<data dir>/static-sites`), created
automatically on startup. Copy or sync your site's built files there first -
BurrowGate does not upload files for you - then pick the folder from the
Origins tab's **Browse...** file picker, which lists only subdirectories of
that jail and shows which ones already contain an `index.html`.

An origin can never be pointed at a path outside this directory, whether
typed directly through the API or picked through the dashboard: every
static root is resolved and validated against the jail on save, and again
on every request.

## Configuring a static origin

- **Origin type**: `static`.
- **Static folder**: the picked directory (relative to the static-sites
  root).
- **Index file**: served for a directory request (default `index.html`).
- **SPA fallback**: when enabled, any request that doesn't match a real
  file serves the index file instead of a 404 - needed for client-side
  routed single-page apps (React Router, Vue Router...) so a deep-linked
  or refreshed route doesn't 404 at the edge.

A site's **General** tab also accepts `static` as the origin type when
creating a new site, as a one-step shortcut for the common case of a site
whose only origin is a static folder - it seeds the primary origin with the
chosen folder, index file, and SPA fallback in the same request. Changing
those settings afterward happens from the Origins tab, the same place any
other origin is edited.

## Request handling

- **Clean URLs**: a request for `/report` serves `report.html` when there
  is no file or directory at that exact path - skipped for a path ending in
  `/`, since that already means "look for the index file in this
  directory." An exact match always wins over this fallback.
- **Directory index**: a request ending in `/` (or matching a real
  directory) serves the configured index file from inside it.
- **SPA fallback**: only applies after the clean-URL and directory checks
  above both fail to find anything.
- **Range requests**: a single `Range: bytes=...` request returns `206`
  with `Content-Range`; a satisfiable-but-invalid range returns `416`.
- **Conditional requests**: every response carries `ETag` and
  `Last-Modified`. A matching `If-None-Match` (checked first, including
  `*`) or a satisfied `If-Modified-Since` returns `304 Not Modified` with
  no body. The `ETag` is a weak validator derived from file size and
  modification time (the same cheap scheme nginx uses by default), not a
  content hash, so it changes whenever the file is replaced but doesn't
  require reading the file to compute.
- Only `GET` and `HEAD` are served; anything else gets `405`.
- Path traversal (`..`, encoded or not) is rejected before touching the
  filesystem, independent of the folder-jail check performed when the
  origin was saved.

## Headers and caching

BurrowGate does not set `Cache-Control` (or any other freshness header) on
static responses - if you want browsers or BurrowGate's own edge cache to
cache them, configure that explicitly through the site or route's
[HTTP header policy and static-asset cache](ROUTE_POLICIES.md), the same
controls already used for proxied responses. `ETag` and `Last-Modified`
are sent unconditionally regardless of that policy - there's no separate
setting for them, since the existing response-header-removal policy
already lets you strip them if you don't want conditional requests
honored. Response header policy, CORS, and HSTS all still apply to static
responses exactly as they would to a proxied one.

## Load balancing and health

Static origins participate in the same priority/weight selection as proxy
origins in the pool. They are **never health-checked** - there's no backend
to probe - and are always treated as available (never reported
`unhealthy`), so they don't need a health-check path configured and won't
trigger unhealthy-pool alerts or maintenance mode on their own.

A WebSocket upgrade routed to a static origin has nothing to connect to.
BurrowGate falls back to a proxy origin elsewhere in the same pool if one
exists, or returns `503 origin_pool_unavailable` if every origin in the
pool is static.

## Limitations

- mTLS and origin-certificate trust don't apply to static origins - there's
  no outbound TLS connection to secure.
- The dashboard file picker only lists existing folders; it doesn't create
  them or upload files. Get your built site onto the host (e.g. `rsync`,
  a mounted volume, a CI deploy step) before picking its folder.

## Configuration

```
BG_STATIC_ROOT_DIR=./data/static-sites
```

All static folders must live under this directory. Changing it after
origins already point at folders under the old path requires moving the
files (or updating `BG_STATIC_ROOT_DIR` back) before those origins will
resolve again.
