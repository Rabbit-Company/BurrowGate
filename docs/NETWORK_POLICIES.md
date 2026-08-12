# Network Policies

BurrowGate can apply IP and country policy before route verification and rate limiting.

## Actions

- `inherit`: continue to the next policy layer
- `pass`: allow the request and continue to the matching route policy
- `allow`: allow the request and bypass browser verification
- `block`: reject the request with HTTP 403
- `challenge`: require the configured browser challenge

Site defaults support `inherit`, `allow`, `block`, and `challenge`. Explicit IP and country rules also support `pass`, which is the recommended action for allowlists that should keep route protection enabled.

## Precedence

Both the site and each route policy can define IP rules, country rules, and default actions. A route's network policy takes precedence over the site's for requests matching that route:

1. The longest matching IP or CIDR rule on the route
2. An explicit country rule on the route
3. The route's default country action
4. The route's default IP action
5. The longest matching IP or CIDR rule on the site
6. An explicit country rule on the site
7. The site's default country action
8. The site's default IP action
9. The matching route policy's access mode

A route with no IP rules, country rules, or default actions configured skips straight to the site's policy (steps 5-8).

A route with access mode `block` remains blocked even when an IP or country rule uses `pass` or `allow`.

## Route-level rules

Route policies have their own **Network** tab with the same shape as the site's network policy: a default IP action, a default country action, explicit IP/CIDR rules, and explicit country rules. Use it to carve out an exception for one route without touching the site's rules.

For example, to allow only one trusted IP on an internal API route and block everyone else, while leaving every other route on the site untouched:

```text
Route: /api/internal/**
Default IP action: Block all IPs
IP rule: 203.0.113.10/32 -> Allow and bypass verification
```

Requests to `/api/internal/**` from any other address are blocked with HTTP 403. Requests to every other path continue to follow the site's network policy as before.

Because route rules are checked before the site's, they can also loosen a site-wide block for one route - for example allowing a monitoring service's IP through to a health-check endpoint even though the site blocks that IP or its country everywhere else.

## IP whitelist

To allow only selected addresses or networks, site-wide or for one route:

1. Set **Default IP action** to **Block all IPs** (on the site's Network rules tab, or on a route policy's Network tab to scope it to that route only).
2. Add `pass` rules for trusted IP addresses or CIDR ranges. Use `allow` only when those clients should also bypass browser verification.

Example:

```text
Default IP action: Block
Pass: 203.0.113.10/32
Pass: 2001:db8:1234::/48
```

The longest matching CIDR wins when multiple IP rules overlap.

## Country blocklist

To block selected countries while keeping the normal route policy for all other traffic:

1. Set **Default country action** to **Use IP default** (site-wide) or **Use route IP default** (on a route policy's Network tab).
2. Add `block` rules for the selected countries.

## Country whitelist

To allow only selected countries:

1. Set **Default country action** to **Block all countries**.
2. Add `pass` rules for the selected countries. Use `allow` only when those countries should bypass browser verification.

An explicit IP rule has higher priority than country policy. This makes it possible to allow a trusted address from an otherwise blocked country.

## GeoIP availability

Country policy requires the local GeoIP database. BurrowGate fails open for the country layer when the database is disabled or unavailable. Explicit IP rules and the default IP action continue to work.

Private and loopback addresses (RFC 1918, link-local, and their IPv6 equivalents) are recognized directly and use the country code `XX`, without consulting the GeoIP database. Invalid and unmapped public addresses use `ZZ` when the GeoIP database is available. A rule for `XX` or `ZZ` can be created from the dashboard.

## Performance

Network rules are loaded into one cached snapshot per site and, separately, one cached snapshot per route policy:

- IP networks are parsed once and sorted by prefix length.
- Country rules are stored in a map keyed by the two-letter country code.
- Normal requests do not query the rule tables; a route's snapshot is only checked first, then the site's if it has nothing to decide.
- Changing an IP rule, country rule, or default action invalidates only the affected site's or route policy's snapshot.
- GeoIP uses the shared bounded country lookup cache described in [GEOIP.md](GEOIP.md).
