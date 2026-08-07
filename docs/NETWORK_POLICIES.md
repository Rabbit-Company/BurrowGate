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

BurrowGate evaluates network policy in this order:

1. The longest matching IP or CIDR rule
2. An explicit country rule
3. The default country action
4. The default IP action
5. The matching route policy

A route with access mode `block` remains blocked even when an IP or country rule uses `pass` or `allow`.

## IP whitelist

To allow only selected addresses or networks:

1. Set **Default IP action** to **Block all IPs**.
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

1. Set **Default country action** to **Use IP default**.
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

Network rules are loaded into one cached snapshot per site:

- IP networks are parsed once and sorted by prefix length.
- Country rules are stored in a map keyed by the two-letter country code.
- Normal requests do not query the rule tables.
- Changing an IP rule, country rule, or default action invalidates only that site's snapshot.
- GeoIP uses the shared bounded country lookup cache described in [GEOIP.md](GEOIP.md).
