# Network Policies

BurrowGate can apply IP, ASN, and country policy before route verification and rate limiting.

## Actions

- `inherit`: continue to the next policy layer
- `pass`: allow the request and continue to the matching route policy
- `allow`: allow the request and bypass browser verification
- `block`: reject the request with HTTP 403
- `challenge`: require the configured browser challenge

Site defaults support `inherit`, `allow`, `block`, and `challenge`. Explicit IP, ASN, and country rules also support `pass`, which is the recommended action for allowlists that should keep route protection enabled.

## Precedence

Both the site and each route policy can define IP rules, ASN rules, country rules, and default actions. A route's network policy takes precedence over the site's for requests matching that route:

1. The longest matching IP or CIDR rule on the route
2. An explicit ASN rule on the route
3. An explicit country rule on the route
4. The route's default country action
5. The route's default IP action
6. The longest matching IP or CIDR rule on the site
7. An explicit ASN rule on the site
8. An explicit country rule on the site
9. The site's default country action
10. The site's default IP action
11. The matching route policy's access mode

A route with no IP, ASN, or country rules and no default actions configured skips straight to the site's policy (steps 6-10).

A route with access mode `block` remains blocked even when an IP, ASN, or country rule uses `pass` or `allow`.

There is no default ASN action, unlike IP and country. ASN space is as large and open as IP space, so a "default action once the ASN is known" would be redundant with the default IP action; use explicit ASN rules for blocklisting or allowlisting specific network providers.

## Route-level rules

Route policies have their own **Network** tab with the same shape as the site's network policy: a default IP action, a default country action, explicit IP/CIDR rules, explicit ASN rules, and explicit country rules. Use it to carve out an exception for one route without touching the site's rules.

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

## ASN blocklist

To block traffic from specific network providers (hosting, VPN, or scraper ASNs, for example) while keeping the normal route policy for everyone else:

1. Add a `block` rule for each ASN you want to block, entered as the number alone (e.g. `15169`, not `AS15169`).

There is no default ASN action to set first; explicit ASN rules apply directly, and traffic from every other ASN falls through to country policy and the defaults as usual.

An ASN allowlist works the same way with `pass` or `allow` rules, but since there is no default ASN action to flip to "block everything", pair it with **Default IP action: Block all IPs** (or a country blocklist) if the goal is "only these networks."

An explicit IP rule has higher priority than ASN policy, and ASN policy has higher priority than country policy. This makes it possible to allow one trusted address from an otherwise-blocked ASN, or a trusted ASN from an otherwise-blocked country.

## Country blocklist

To block selected countries while keeping the normal route policy for all other traffic:

1. Set **Default country action** to **Use IP default** (site-wide) or **Use route IP default** (on a route policy's Network tab).
2. Add `block` rules for the selected countries.

## Country whitelist

To allow only selected countries:

1. Set **Default country action** to **Block all countries**.
2. Add `pass` rules for the selected countries. Use `allow` only when those countries should bypass browser verification.

An explicit IP rule has higher priority than country policy. This makes it possible to allow a trusted address from an otherwise blocked country.

## GeoIP and ASN availability

Country policy requires the local GeoIP database; ASN policy requires the separate local ASN database. BurrowGate fails open for each layer independently when its database is disabled or unavailable: with the ASN database down, ASN rules simply never match and evaluation falls through to country policy, exactly as if no ASN rule existed. Explicit IP rules and the default IP action always continue to work regardless of either database's state.

Private and loopback addresses (RFC 1918, link-local, and their IPv6 equivalents) are recognized directly and use the country code `XX` and ASN `0`, without consulting either database. Invalid and unmapped public addresses use country code `ZZ` and ASN `0` when the corresponding database is available. A country rule for `XX` or `ZZ` can be created from the dashboard; ASN `0` is never a real, allocatable ASN, so it cannot be targeted by an ASN rule.

## Performance

Network rules are loaded into one cached snapshot per site and, separately, one cached snapshot per route policy:

- IP networks are parsed once and sorted by prefix length.
- ASN rules are stored in a map keyed by the ASN number.
- Country rules are stored in a map keyed by the two-letter country code.
- Normal requests do not query the rule tables; a route's snapshot is only checked first, then the site's if it has nothing to decide.
- Changing an IP rule, ASN rule, country rule, or default action invalidates only the affected site's or route policy's snapshot.
- GeoIP and ASN each use their own shared bounded lookup cache, described in [GEOIP.md](GEOIP.md).
