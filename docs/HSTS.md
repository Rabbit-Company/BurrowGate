# HSTS

BurrowGate can send `Strict-Transport-Security` on every HTTPS response for a
site, telling browsers to only reach it over HTTPS for a configured amount of
time. It is disabled by default and is configured per site only.

## Site-only scope

Unlike other HTTP policies, HSTS has no route-level override. HSTS is a
browser directive scoped to the whole hostname, not to a path - a browser
that has seen the header once applies it to every future request for that
host regardless of which path set it, so sending different values on
different routes would not achieve real per-path enforcement, only whatever
value the browser happened to see last. Keep it as one setting for the site.

## Settings

- **Max age** - how long, in seconds, a browser should remember to only use
  HTTPS for this site after seeing the header. Up to 63072000 (2 years).
- **Include subdomains** - also applies the policy to every subdomain of this
  site's hostname. Off by default, since it affects hosts BurrowGate isn't
  necessarily managing.
- **Preload** - marks the site as intending to submit to browser HSTS
  preload lists (e.g. hstspreload.org), which ship the policy inside the
  browser itself instead of waiting for a first HTTPS response. Requires
  include subdomains and a max age of at least 31536000 seconds (1 year) -
  BurrowGate rejects saving preload without both, since a submission
  wouldn't qualify anyway.

## Where the header is applied

The header is added once, at the point every response for a site passes
through on its way out, so it is present on proxied responses, cache hits,
blocked and error responses, and challenge responses alike - not just
successful proxied traffic. It is only ever sent when the inbound connection
is actually HTTPS.

## Security note

Preload is very hard to reverse. Once a site is accepted onto a browser's
preload list, removal can take months to reach users as browser updates
ship, and in the meantime every subdomain must serve valid HTTPS or become
unreachable in preload-aware browsers. Only enable preload once you are
certain every current and future subdomain will support HTTPS; leave it off
and rely on max age alone otherwise.
