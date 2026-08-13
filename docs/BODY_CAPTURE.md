# Body Capture

BurrowGate can optionally store the request and response bodies of proxied traffic
for inspection from the dashboard. It is disabled by default at every level and
must be turned on explicitly per site, or per route.

## Modes

- Site: `disabled` or `enabled`.
- Route: `inherit`, `enabled`, or `disabled`. `inherit` uses the site's mode.

A route in `enabled` or `disabled` mode overrides the site's mode for requests
matching that route. A route left on `inherit` follows the site.

## Size limits

Request and response bodies each have their own configurable maximum, in bytes:

- `0` disables capture for that direction only. For example, a maximum request
  size of `0` with a non-zero response maximum captures response bodies but never
  request bodies.
- A route's size fields are blank by default, which inherits the site's value. Set
  an explicit `0` on a route to disable a direction the site otherwise captures.
- Every configured size, site or route, is clamped to an instance-wide ceiling
  (`BG_BODY_CAPTURE_MAX_BYTES_CEILING`, 1 MiB by default) that no policy can exceed.

Keep these limits low. Body capture is meant for spot-checking requests during
debugging, not for archiving full payloads. A captured body is stored as-is
alongside the rest of that request's traffic event.

A body larger than its configured maximum is truncated to that many bytes and
flagged as truncated. The truncation only affects what's stored, never what's
forwarded to the client or origin.

## Content-type filtering

Only text-based content types are ever captured - binary bodies (images, video,
archives, arbitrary `application/octet-stream`, ...) are never stored, regardless
of configuration.

Within that safety floor, each site and route also has its own list of allowed
content types (comma or whitespace separated, e.g. `application/json,
text/plain`). A route's list is blank by default, which inherits the site's list.
Use `*` for any text-based content type (the default when a site is first
enabled).

To capture only JSON API traffic and skip HTML, CSS, and JavaScript responses,
set the content-type list to just `application/json`.

## Expiration

An optional expiration date/time can be set alongside the size and content-type
limits, site-wide or per route. Once it passes, capture behaves as if the mode
were `disabled` - no code path needs to run to "turn it off," and no restart is
required. This is meant for short, temporary investigations: enable capture with
an expiration an hour or a day out, reproduce the issue, and let it lapse on its
own.

An expiration only stops _new_ captures. Bodies already stored before it passed
are unaffected and follow the site's normal [traffic retention](../README.md#monitoring)
period like any other request event.

## Compressed bodies

A response compressed with `gzip`, `deflate`, `br` (Brotli), or `zstd` is
decompressed only for the copy being captured. The bytes actually sent to the
client are always the original compressed representation, untouched - decoding
failures on the captured copy can never affect what's proxied. A body compressed
with an unrecognized encoding, or a stream that turns out to be truncated or
corrupt, is simply never captured rather than stored as garbage.

## Viewing captured bodies

Click any row in the dashboard's **Recent Traffic** table to open its full detail:
timing, IP, decision, cache and protection status, origin, referrer, and when
present, the captured request and response bodies with their content type and a
truncation indicator. A row without a captured body (capture disabled, expired, or
the content type wasn't allowed) shows that explicitly rather than an empty box.

The traffic list itself never transfers captured body text. It's only fetched when
a row's detail is opened.

## Security note

Captured bodies are stored unredacted. Anyone with dashboard **view** access to a
site can read whatever was captured, including credentials or personal data if
capture is pointed at a login form or another endpoint carrying sensitive input.
Scope body capture to a specific route with a narrow content-type list (e.g. just
your API's `application/json` endpoints) rather than enabling it site-wide, and
prefer a short expiration over leaving it on indefinitely.
