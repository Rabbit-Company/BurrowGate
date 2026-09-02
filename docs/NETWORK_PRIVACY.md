# Tor and ASN network category detection

BurrowGate can identify and optionally block traffic in **Tor exit node** plus a dynamic set of ASN-based network categories (VPN, proxy, datacenter/hosting, ISP/telecom, mobile carrier, education, government, and more). Detection is disabled by default and is intended as a best-effort policy signal rather than proof that a visitor is using a proxy or VPN.

## Data sources

Tor detection uses the [official Tor bulk exit list](https://check.torproject.org/torbulkexitlist). BurrowGate compares the client address with the published exit addresses, including canonical IPv4 and IPv6 handling.

ASN category detection uses the [BurrowGate ASN Lists](https://github.com/Rabbit-Company/BurrowGate-ASN-Lists), published to `https://cdn.rabbit-company.com/burrowgate/asn-lists/`. BurrowGate fetches `manifest.json` from that CDN first to discover the current set of categories - their IDs, labels, descriptions, and list files - then fetches each category's ASN list. The set of available categories is therefore not fixed in BurrowGate's code: it tracks whatever the manifest currently publishes, and the admin UI's Network privacy settings render one Disabled/Identify only/Identify and block control per category automatically. Each row contains a decimal ASN followed by its organization name. The category files are policy signals and are not definitive inventories of every network of that type.

The last valid downloads are stored in `data/network-privacy/` and loaded from there first, on every startup, before anything is fetched over the network. A cache under a day old is used as is with no network request at all - this is what keeps a crash-restart loop from turning into a fetch loop against the Tor project or the CDN. Once a day, BurrowGate checks for updates: for the ASN lists, it fetches only the small manifest first and compares its generation timestamp against the cached one, downloading the (much larger) per-category lists only if something upstream actually changed; the Tor exit list, which has no such versioning to check, is simply re-downloaded once the cache turns a day old. A failed refresh (of the manifest, of an individual category file, or of the Tor list) keeps the previous in-memory and cached data for that piece and never interrupts proxy startup.

## Custom categories

Beyond what the CDN publishes, you can hand-add your own ASN category by editing the local cache directly:

1. Open `data/network-privacy/manifest.json` (create it, modeled on the shape below, if it doesn't exist yet - e.g. on a host with no network access to the CDN) and add an entry to `categories`:

   ```json
   { "id": "my-partners", "label": "My partner networks", "description": "ASNs operated by partner organizations.", "file": "my-partners.txt" }
   ```

   `id` must be lowercase letters, digits, and hyphens only (it becomes both the policy key and part of a cache filename). `file` is only meaningful for CDN-published categories - BurrowGate never fetches a custom category over the network - but the field is still required and conventionally set to `<id>.txt`.

2. Create `data/network-privacy/asn-my-partners.txt` (the same `asn-<id>.txt` naming every category uses) with one ASN per line, in the same format as the published lists: `<decimal ASN> <organization name>`.

3. Restart BurrowGate, or wait up to 24 hours for the next scheduled refresh to pick it up (an already-running instance only rereads `data/network-privacy/` from disk on startup or when its daily check decides the CDN manifest needs re-fetching, not on every check).

The custom category then shows up in the admin UI's Network privacy settings exactly like a published one, with its own Disabled/Identify only/Identify and block control.

A category ID present locally but absent from the CDN's manifest - whether it's one you added or one the CDN used to publish and has since removed - is never deleted by a refresh. BurrowGate only ever adds or updates the categories the CDN currently lists; anything else already in `data/network-privacy/manifest.json` is carried forward untouched. Removing a custom category is therefore also manual: delete its entry from `manifest.json` and its `asn-<id>.txt` file.

## Configuration

For HTTP traffic, open a site and select **Privacy networks**. For TCP/UDP traffic, open the Streams dashboard, select **Network rules**, and choose a stream. Each category supports:

- **Disabled**: do not look up or classify that category on the request path.
- **Identify only**: record matches without changing the request outcome.
- **Identify and block**: record matches and reject them with HTTP 403.

Route policies can inherit the site policy or replace it with their own modes for every category. Streams each have their own independent policy, shared by their TCP and UDP listeners. Setting a category to **Identify and block** is the one-control block for every ASN currently classified in that category.

ASN category detection requires ASN enrichment from `GeoLite2-ASN.mmdb`. Configure `BG_GEOIP_ASN_ENABLED=true` and see [GeoIP](GEOIP.md). When ASN enrichment is disabled or unavailable, those categories fail open and cannot match; Tor detection continues to work independently.

A site, route, or stream's stored policy can reference a category ID that BurrowGate hasn't loaded yet (e.g. right after a restart, before the first manifest fetch completes) or one that the CDN has since removed. That setting is preserved either way - it just can't match anything until (or unless) the category becomes available again.

## Allowlist precedence

Explicit matching IP/CIDR or ASN rules with either **Allow and follow route policy** (`pass`) or **Allow and bypass verification** (`allow`) override automatic category blocking. Classification is still recorded so the request remains visible under its matched categories.

Streams use a single **Allow** action for explicit IP/CIDR and ASN rules. It has the same precedence over automatic category blocking. Country and default stream allows do not bypass a category block.

The regular network policy is evaluated first. An explicit or default network block still rejects the request before privacy-network policy. Route network rules keep their existing precedence over site rules. Country allows and default allows do not override privacy-network blocking; use a specific IP/CIDR or ASN allow rule for that exception.

## Visibility

Matches are stored with request events. In **Recent traffic**, enable the hidden **Network type** column or open a request row to see all matched categories. Rejected requests use the decision `privacy-blocked` and the error code `network_privacy_blocked`.

For streams, matches are stored with connection events and shown in the hidden **Network type** column in both live connections and the Traffic log. Blocked TCP connections are closed before connecting to the origin. A blocked UDP address is rejected before its first datagram creates an upstream peer. Changing a stream policy also re-evaluates and closes active connections that newly match a blocked category.

## Limitations

- Tor detection identifies published exit relays, not Tor bridges or traffic that leaves through another intermediary.
- ASN classification applies to an entire network operator and is generated by keyword heuristics against the operator's registered legal name, not a hand-audited inventory; see the [BurrowGate-ASN-Lists methodology](https://github.com/Rabbit-Company/BurrowGate-ASN-Lists#classification-methodology-and-limitations) for details. Shared hosting, cloud, carrier, corporate, and mixed-use networks can produce false positives, and most small operators land in the `unknown` category rather than a specific one.
- Commercial VPNs frequently add providers and lease space from general-purpose hosts, so some VPN traffic appears only as datacenter traffic or is not identified.
- Residential and peer-to-peer proxies generally cannot be detected reliably from these lists.
- IP and ASN ownership changes over time. Start with **Identify only**, review real traffic, and add narrow allow rules before enabling broad blocks.
