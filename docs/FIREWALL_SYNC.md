# Firewall Sync

BurrowGate can push the same IPs it already blocks at the application layer out to an external firewall, so an attacker's traffic is dropped before it costs this host any bandwidth or CPU - instead of every packet still having to reach BurrowGate's own network stack just to be rejected.

Open the **Firewall Sync** dashboard from the switcher at the top of the control panel (`/_burrowgate/admin/firewall-sync`). It is a dedicated, instance-wide tab (not scoped to one site or stream) with a live preview of the currently-bannable IP set, a never-ban whitelist, and a list of configured providers.

## How it works

Every `BG_FIREWALL_SYNC_INTERVAL_MS` (default 10 seconds), BurrowGate recomputes the full set of active `block` rules across every site's and stream's network policies (see [`docs/NETWORK_POLICIES.md`](NETWORK_POLICIES.md)), deduplicates by CIDR, and pushes the result to every enabled provider. Country rules are not included - there is no practical way to expand a country block into a firewall-sized CIDR list.

Each provider has its own entry cap (`max_entries`). The deduplicated set is sorted newest-first before capping, so when a provider is full, the oldest bans are evicted to make room for new ones rather than rejecting new bans outright.

The automatic tick skips pushing to a provider whose desired set hasn't changed since the last successful push (compared by hash), so a quiet period doesn't generate needless API calls. The dashboard's **Sync now** button always pushes for real regardless of that cache, which is also the way to force a push immediately after fixing a misconfigured provider instead of waiting for the next tick.

## Never-ban whitelist

Because this feature can hand an external firewall a "drop all traffic from this IP" instruction, a false-positive ban has higher stakes here than an ordinary in-app block: it could lock you out of SSH or the VPS entirely, not just one stream. Two layers of protection apply before anything is pushed:

- **Private and loopback ranges are always excluded**, unconditionally, with no way to turn this off. An IP like `10.1.80.1` never reaches a provider even if BurrowGate's own auto-ban logic blocked it - a ban on a private-range address is almost always a device on your own network (e.g. a local test client tripping a bandwidth limit), not a real internet attacker.
- **The whitelist** is a global, admin-managed list of IPs/CIDRs (with an optional note) that are never pushed, checked in addition to the private-range exclusion. A "use my current IP" button pre-fills it with the request's own source IP as a starting point.

A provider's **Enabled** toggle is blocked, with an explanation, until either the whitelist has at least one entry or the admin explicitly acknowledges enabling without one. The preview card also reports how many currently-active bans were excluded and why (private range vs. whitelisted), so an empty push isn't silently confusing.

## Providers

### UniFi Controller

Requires a **UniFi OS console** (Dream Machine, Cloud Gateway, or UniFi OS Server) with the modern **Zone-Based Firewall** - API-key authentication is not available on the legacy self-hosted Network Application, and the older Firewall Rules + Groups model doesn't expose an API-key-authenticated way to manage its groups.

Generate a local API key from the UniFi console (profile icon -> API), then configure:

- **Controller URL** - e.g. `https://192.168.1.1`.
- **API base path** - almost always `/proxy/network`; this is where UniFi OS fronts the Network application's API.
- **API key**.
- **Site** - picked from a dropdown, not typed. Click **Load sites** to fetch the real site list and its IDs directly from the controller; the Integration API is ID-scoped, so a site's internal display name (which may not even be `Default`) isn't a valid value here.
- **Traffic matching list name** - BurrowGate creates and maintains one IPv4 and one IPv6 Traffic Matching List under this name (the IPv6 list gets a `(IPv6)` suffix automatically, since UniFi enforces list-name uniqueness per site regardless of type).
- **Verify TLS certificate** - uncheck for a self-signed local controller certificate.

BurrowGate only ever manages the traffic matching list's membership - it never creates, modifies, or deletes a Firewall Policy. You create that once, yourself, in the UniFi UI: a Policy with **Action: Block**, and a **Source** IP Address filter pointed at the Traffic Matching List by name. This keeps BurrowGate's blast radius limited to list membership rather than arbitrary firewall rule changes.

Because UniFi rejects an empty traffic matching list, an otherwise-empty list is populated with a single RFC 5737 / RFC 3849 documentation-range placeholder address (`192.0.2.255/32` / `2001:db8::1/128`) instead - addresses that can never appear as real traffic, so the block list is functionally empty without violating the API's non-empty requirement.

### Local nftables

Works on any Linux host, including the VPS BurrowGate itself runs on - useful specifically because [Hetzner Cloud Firewall and similar cloud "firewall" products are allow-list only](https://docs.hetzner.cloud/) and have no primitive for blocking a specific source IP, so local packet filtering is the only way to actually drop traffic before it reaches BurrowGate's process on those providers.

BurrowGate creates and owns an isolated `inet burrowgate` table with its own chain (hooked into `input`) and IPv4/IPv6 sets, entirely separate from any existing `ufw`, `firewalld`, or other nftables configuration on the host - it never touches rules outside its own table. Deleting the provider removes the whole table in one step.

The BurrowGate process needs permission to modify the nftables ruleset. Since running the whole application as root is undesirable, grant the capability to the `nft` binary specifically:

```bash
sudo setcap cap_net_admin+ep $(which nft)
```

Alternatively, enable **Run via sudo -n** with a narrow sudoers rule scoped to the `nft` binary. If BurrowGate runs under systemd, note that sandboxing directives like `NoNewPrivileges` can interfere with an inherited capability - check the unit file if `setcap` doesn't seem to take effect.

### OVH Edge Firewall

Every OVH public IP has its own **Edge Firewall**, filtering traffic at the OVH network edge before it reaches your service at all - independent of which OVH product (VPS, dedicated server, etc.) that IP is attached to. Find it in the OVH control panel under **Network > Public IP addresses**, then open the IP's **Edge firewall**. It has a hard limit of **20 rule slots per IP** and is **IPv4-only**.

Configure:

- **API endpoint** - the regional API root, e.g. `https://eu.api.ovh.com`, `https://ca.api.ovh.com`, or `https://api.us.ovhcloud.com`.
- **Application key** and **application secret** - created at `<endpoint>/auth/api/createToken` (e.g. [https://ca.ovh.com/auth/api/createToken](https://ca.ovh.com/auth/api/createToken)) or via the OVH API console.
- **Consumer key** - click **Request access** to have BurrowGate request one scoped to just the `/ip/*` resource tree (never your whole account). This returns a validation link you open once, in your browser, to approve it - after that the key is permanent until you revoke it. You can also paste in a consumer key obtained some other way.
- **Protected IP** - picked from a dropdown, not typed. Click **Load IPs** to fetch every IP on the account (labeled with the OVH service it's routed to, when known) and pick the one this BurrowGate instance is actually reachable on - the firewall applies only to that single IP, never anything else on the account.

BurrowGate enables the edge firewall for the selected IP if it isn't already, then manages rules as `{action: "deny", protocol: "ipv4", source: <banned CIDR>}` - one rule blocks all traffic from that source regardless of TCP/UDP/ICMP. OVH's rule API has no comment/label field to distinguish "BurrowGate's rules" from anything else, so **BurrowGate only ever touches a rule that exactly matches its own shape** (a plain `deny`/`ipv4` rule with no port restriction) - any `permit` (allow) rule, or any rule scoped to a specific port, is left completely alone: never deleted, and its slot is never reused for a ban. Effective ban capacity is therefore 20 minus however many slots your own rules occupy.

Because rules are addressed by a fixed slot number (0-19) rather than a replaceable list, reconciliation diffs against the existing 20 slots (keeping already-correct rules, freeing slots whose ban expired, filling free slots with new bans) instead of a full flush-and-recreate, so an unchanged ban list produces no API calls at all.

## Configuration

- `BG_FIREWALL_SYNC_ENABLED` (default `true`) - instance-wide kill switch, independent of each provider's own enabled state.
- `BG_FIREWALL_SYNC_INTERVAL_MS` (default `10000`) - automatic reconciliation interval.
- `BG_FIREWALL_SYNC_REQUEST_TIMEOUT_MS` (default `10000`) - timeout for UniFi and OVH API requests.
- `BG_FIREWALL_SYNC_NFT_TIMEOUT_MS` (default `5000`) - timeout for each `nft` invocation.
- `BG_FIREWALL_SYNC_UNIFI_DEFAULT_MAX_ENTRIES` (default `2000`) - default cap for new UniFi providers.
- `BG_FIREWALL_SYNC_NFTABLES_DEFAULT_MAX_ENTRIES` (default `100000`) - default cap for new nftables providers.
- OVH providers are always capped at 20 entries - the API's own hard limit, not configurable.

See [`docs/NETWORK_POLICIES.md`](NETWORK_POLICIES.md) for how block rules are created in the first place, and [`docs/BANDWIDTH.md`](BANDWIDTH.md) / [`docs/STREAMS.md`](STREAMS.md) for the bandwidth-limit auto-bans that most commonly feed this feature.
