# Header Capture

BurrowGate can optionally store the request and response headers of proxied
traffic for inspection from the dashboard, alongside [body capture](BODY_CAPTURE.md).
It is disabled by default at every level and must be turned on explicitly per
site, or per route.

## Modes

- Site: `disabled` or `enabled`.
- Route: `inherit`, `enabled`, or `disabled`. `inherit` uses the site's mode.

A route in `enabled` or `disabled` mode overrides the site's mode for requests
matching that route. A route left on `inherit` follows the site.

## Redaction

`Authorization`, `Cookie`, and `Set-Cookie` are redacted by default whenever
header capture is enabled - the header name is still stored so its presence is
visible, but the value is replaced with `[redacted]`. This can be turned off
per site or route to capture those headers in full, and an additional list of
header names (comma or whitespace separated, e.g. `x-api-key, x-internal-token`)
can be redacted the same way. A route's redaction settings are blank by
default, which inherits the site's.

## Expiration

An optional expiration date/time can be set alongside the redaction settings,
site-wide or per route, the same way as [body capture](BODY_CAPTURE.md#expiration).
Once it passes, capture behaves as if the mode were `disabled` - no restart is
required. An expiration only stops _new_ captures; headers already stored
before it passed are unaffected.

## Viewing captured headers

Click any row in the dashboard's **Recent Traffic** table to open its full
detail. Captured request and response headers are listed alongside the
captured body, if any, with redacted values shown as a badge instead of their
value. A row without captured headers (capture disabled, expired, or none
were sent) shows that explicitly.

## Security note

A non-redacted captured header is stored as-is. Anyone with dashboard **view**
access to a site can read whatever was captured, so keep the default
`Authorization`/`Cookie`/`Set-Cookie` redaction on unless you have a specific
reason to disable it, and add any other header carrying a secret (API keys,
signed tokens, ...) to the redacted list.

See also [Resend](RESEND.md), which lets a redacted header be filled in
manually when replaying a captured request.
