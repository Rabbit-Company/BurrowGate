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

Works on any Linux host, including the VPS running BurrowGate. Local packet filtering can block specific source IPs before traffic reaches BurrowGate, even when an upstream firewall supports only allow rules.

BurrowGate creates and owns an isolated `inet burrowgate` table with its own chain (hooked into `input`) and IPv4/IPv6 sets, entirely separate from any existing `ufw`, `firewalld`, or other nftables configuration on the host - it never touches rules outside its own table. Deleting the provider removes the whole table in one step.

The BurrowGate process needs permission to modify the nftables ruleset. Since running the whole application as root is undesirable, grant the capability to the `nft` binary specifically:

```bash
sudo setcap cap_net_admin+ep $(which nft)
```

Alternatively, enable **Run via sudo -n** with a narrow sudoers rule scoped to the `nft` binary. If BurrowGate runs under systemd, note that sandboxing directives like `NoNewPrivileges` can interfere with an inherited capability - check the unit file if `setcap` doesn't seem to take effect.

**Docker Compose deployments**: the default `docker-compose.yml`/`docker-compose.override.yml` already install `nftables` in the image and grant the container `NET_ADMIN` (alongside the existing `NET_BIND_SERVICE`), with `setcap cap_net_admin+ep` applied to just the `nft` binary during the image build - the same scoped-capability pattern as above, just baked into the image instead of run manually. No extra setup is needed for this provider under the default Compose configuration. This relies on `network_mode: host`: since the container shares the host's actual network namespace, `nft` commands run inside it modify the host's real ruleset directly, exactly like running `nft` outside Docker would.

### OVH Edge Firewall

Every OVH public IP has its own **Edge Firewall**, filtering traffic at the OVH network edge before it reaches your service at all - independent of which OVH product (VPS, dedicated server, etc.) that IP is attached to. Find it in the OVH control panel under **Network > Public IP addresses**, then open the IP's **Edge firewall**. It has a hard limit of **20 rule slots per IP** and is **IPv4-only**.

Configure:

- **API endpoint** - the regional API root, e.g. `https://eu.api.ovh.com`, `https://ca.api.ovh.com`, or `https://api.us.ovhcloud.com`.
- **Application key** and **application secret** - created at `<endpoint>/auth/api/createToken` (e.g. [https://ca.ovh.com/auth/api/createToken](https://ca.ovh.com/auth/api/createToken)) or via the OVH API console.
- **Consumer key** - click **Request access** to have BurrowGate request one scoped to just the `/ip/*` resource tree (never your whole account). This returns a validation link you open once, in your browser, to approve it - after that the key is permanent until you revoke it. You can also paste in a consumer key obtained some other way.
- **Protected IP** - picked from a dropdown, not typed. Click **Load IPs** to fetch every IP on the account (labeled with the OVH service it's routed to, when known) and pick the one this BurrowGate instance is actually reachable on - the firewall applies only to that single IP, never anything else on the account.

BurrowGate enables the edge firewall for the selected IP if it isn't already, then manages rules as `{action: "deny", protocol: "ipv4", source: <banned CIDR>}` - one rule blocks all traffic from that source regardless of TCP/UDP/ICMP. OVH's rule API has no comment/label field to distinguish "BurrowGate's rules" from anything else, so **BurrowGate only ever touches a rule that exactly matches its own shape** (a plain `deny`/`ipv4` rule with no port restriction) - any `permit` (allow) rule, or any rule scoped to a specific port, is left completely alone: never deleted, and its slot is never reused for a ban. Effective ban capacity is therefore 20 minus however many slots your own rules occupy.

Because rules are addressed by a fixed slot number (0-19) rather than a replaceable list, reconciliation diffs against the existing 20 slots (keeping already-correct rules, freeing slots whose ban expired, filling free slots with new bans) instead of a full flush-and-recreate, so an unchanged ban list produces no API calls at all.

### AWS VPC Network ACL

Manages the inbound rules of a single VPC Network ACL - the stateless, subnet-level firewall that sits in front of a VPC's route table, independent of any Security Group. It has a hard limit of **20 rule slots reserved by BurrowGate** and is **IPv4-only**.

Configure:

- **Region** - e.g. `us-east-1`.
- **Access key ID** and **secret access key** - a long-term IAM user's credentials, or the access key/secret of a temporary STS session (pair with the optional **session token** field below).
- **Session token** - only needed for temporary (STS) credentials; leave blank for a long-term IAM user.
- **Network ACL** - picked from a dropdown, not typed. Click **Load Network ACLs** to fetch every Network ACL in the account/region (labeled with its VPC and default status) and pick the one associated with the subnet this BurrowGate instance actually runs in - the adapter applies only to that single Network ACL, never anything else on the account.
- **Rule number start** - the first of 20 consecutive inbound rule numbers BurrowGate reserves for itself (default `1`). Network ACL rules are evaluated lowest-number-first, so a low start ensures BurrowGate's deny rules are checked before any broader allow rule further down the list. Change this if you've already assigned rule numbers 1-20 to something else.

The IAM identity needs exactly three actions: `ec2:CreateNetworkAclEntry` and `ec2:DeleteNetworkAclEntry`, both scoped to just the target Network ACL's ARN, plus `ec2:DescribeNetworkAcls` - EC2's Describe\* actions don't support resource-level scoping, so that one needs `Resource: "*"`.

**Getting an access key**: find the target Network ACL's ID first (VPC console -> Subnets -> the subnet BurrowGate runs in -> Network ACL tab), then create a dedicated IAM user (IAM -> Users -> Create user, programmatic access only) and attach an inline policy scoped to that ACL:

```json
{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Sid": "BurrowGateModifyOwnAcl",
			"Effect": "Allow",
			"Action": ["ec2:CreateNetworkAclEntry", "ec2:DeleteNetworkAclEntry"],
			"Resource": "arn:aws:ec2:REGION:ACCOUNT_ID:network-acl/acl-XXXXXXXX"
		},
		{
			"Sid": "BurrowGateDescribe",
			"Effect": "Allow",
			"Action": "ec2:DescribeNetworkAcls",
			"Resource": "*"
		}
	]
}
```

Then generate the key from that user's **Security credentials** tab -> **Access keys** -> **Create access key** (use case: _Third-party service_) - the secret is shown once, so copy it immediately. A key scoped this way can only touch the one Network ACL BurrowGate is meant to manage, even if it ever leaked.

BurrowGate manages rules as `{ruleAction: "deny", protocol: "-1", egress: false, cidrBlock: <banned CIDR>}` - one rule blocks all inbound traffic from that source regardless of TCP/UDP/ICMP. A Network ACL entry has no comment/label field to distinguish "BurrowGate's rules" from anything else, so - the same reasoning as the OVH adapter - **BurrowGate only ever touches a rule that exactly matches its own shape** (a plain ingress `deny`/all-protocols rule with no port restriction) _and_ falls inside its reserved rule-number range; any `allow` rule, any port-scoped rule, or anything outside that reserved range (including the account's own default explicit-deny-all catch-all at rule 32767) is left completely alone. Effective ban capacity is therefore 20 minus however many of the reserved slots your own rules already occupy.

Because rules are addressed by a specific rule number rather than a replaceable list, reconciliation diffs against the 20 reserved slots (keeping already-correct rules, freeing slots whose ban expired, filling free slots with new bans) instead of a full flush-and-recreate, so an unchanged ban list produces no API calls at all.

### Cloudflare IP List

For sites proxied through Cloudflare (orange cloud). The other providers can't help here, because proxied traffic reaches your host from Cloudflare's own IPs and never from the visitor. Blocking at Cloudflare's edge stops a banned visitor before any request is forwarded to your origin, so a bandwidth abuser stops costing you bandwidth.

BurrowGate keeps one account-level [IP list](https://developers.cloudflare.com/waf/tools/lists/custom-lists/) in sync with the ban list. It does not create or change any WAF rule. You add one custom rule per zone yourself, and that rule does the blocking. Both IPv4 and IPv6 are supported.

Before you enable this provider, set each Cloudflare-proxied site's **Client IP source** to **Cloudflare**. Otherwise BurrowGate sees Cloudflare's edge addresses as the client, and the bans it pushes would never match a real visitor.

Configure:

- **API token**. Go to **My Profile > API Tokens > Create Token > Start from scratch** and choose **Start with an account policy**. Search for **Account Filter Lists**, give it **Read** and **Edit**, and limit the policy to the one account. The token can manage lists in that account and nothing else.
- **Account ID**. Click **Load accounts** to fetch the accounts the token can see, or paste the 32-character ID shown on any zone's **Overview** page in the Cloudflare dashboard. Some tokens are not allowed to list accounts. Pasting the ID works in that case.
- **List name**. Defaults to `burrowgate_banned_ips`. Cloudflare allows only lowercase letters, digits and underscores, up to 50 characters. BurrowGate creates the list on its first sync if it doesn't exist yet.

The list is account-level. It appears under **Settings > Configurations > Lists** in the account's dashboard, and **Edit** next to it shows its items with the comment that names the instance that added each one.

Then add the blocking rule in each zone you want protected. Open the zone, go to **Security > Security rules**, and select **Create rule > Custom rules**. Under **When incoming requests match**, either pick the field **IP Source Address**, the operator **is in list** and the list `burrowgate_banned_ips`, or switch to the Expression Editor and enter:

```
(ip.src in $burrowgate_banned_ips)
```

Set the action to **Block** and deploy the rule. **Test connection** checks the token and account and repeats the expression to use.

Each item BurrowGate adds carries the comment `Managed by BurrowGate (<owner ID>)`. The owner ID is generated when the provider is created and never changes. **Test connection** shows it. BurrowGate only removes items with its own comment. Items added by hand and items added by other BurrowGate instances are left alone, and an IP that is already in the list is not added a second time.

Each sync reads the current items and sends only the difference, as one bulk delete and one bulk add. Only one bulk operation can run per account at a time, so BurrowGate waits for each one to finish (up to 60 seconds) before it continues. When another instance's operation is still running, BurrowGate retries the request a few times with a short random delay. Cloudflare limits list changes to 1,000,000 item changes and 30,000 write requests per account every 12 hours, and sending only the difference keeps BurrowGate well under both.

Other writers can change the list, so BurrowGate checks it on every sync interval even when the local ban list is unchanged. That check is one request for the list's item count and modification time. The items are only read again when either has changed, when the local ban list has changed, or every 5 minutes as a safety net. **Sync now** always reads them.

#### Several instances sharing one list

Free accounts allow only one custom list, so every instance should use the same account and the same list name, with one WAF rule per zone. Create a separate provider on each instance. Each provider gets its own owner ID, and each instance only adds and removes its own bans. A visitor banned by any instance is blocked on every zone that has the rule. If two instances ban the same IP, the list holds it once. When the instance that added it lifts its ban, the other instance adds it back on its next sync, so the IP can be unblocked for a few seconds in between.

Nodes of one [HA cluster](HIGH_AVAILABILITY.md) share the provider and its owner ID, so the whole cluster acts as one instance.

The 10,000-item limit covers the whole account. Set **Max entries** on each instance so that the total across all instances, plus anything else in the account's lists, stays within it. Otherwise adds start failing once the account is full.

Delete the provider before you retire an instance. Its items are otherwise left in the list, because no other instance removes them. You can also delete them by their comment under **Settings > Configurations > Lists**.

Cloudflare rejects IPv4 ranges wider than `/8` and IPv6 ranges wider than `/12`, so BurrowGate skips bans that size. Single addresses are sent without a prefix, and a range's host bits are cleared before it is sent.

New providers default to a cap of 10,000 entries. That is the total item limit across all lists in an account on the Free, Pro and Business plans. Free accounts are also limited to one custom list, so if you already use your only list for something else, creating the BurrowGate list fails with an error from Cloudflare. Enterprise accounts can raise **Max entries** up to their own limit.

Deleting the provider removes its own items from the list. If the list is empty after that, BurrowGate also tries to delete the list. Cloudflare refuses to delete a list while a rule still references it. In that case the provider is still removed from BurrowGate, and the error asks you to remove the custom rules that reference the list. You can then delete the list under **Settings > Configurations > Lists** in the dashboard. The list is kept while items from other instances or manual entries remain in it.

## Configuration

- `BG_FIREWALL_SYNC_ENABLED` (default `true`) - instance-wide kill switch, independent of each provider's own enabled state.
- `BG_FIREWALL_SYNC_INTERVAL_MS` (default `10000`) - automatic reconciliation interval.
- `BG_FIREWALL_SYNC_REQUEST_TIMEOUT_MS` (default `10000`) - timeout for each UniFi, OVH, AWS and Cloudflare API request.
- `BG_FIREWALL_SYNC_NFT_TIMEOUT_MS` (default `5000`) - timeout for each `nft` invocation.
- `BG_FIREWALL_SYNC_UNIFI_DEFAULT_MAX_ENTRIES` (default `2000`) - default cap for new UniFi providers.
- `BG_FIREWALL_SYNC_NFTABLES_DEFAULT_MAX_ENTRIES` (default `100000`) - default cap for new nftables providers.
- OVH providers are always capped at 20 entries - the API's own hard limit, not configurable.
- AWS VPC Network ACL providers are always capped at 20 entries - the number of rule slots BurrowGate reserves, not configurable.
- Cloudflare providers default to 10,000 entries, the item limit on non-Enterprise plans. You can change it per provider.

See [`docs/NETWORK_POLICIES.md`](NETWORK_POLICIES.md) for how block rules are created in the first place, and [`docs/BANDWIDTH.md`](BANDWIDTH.md) / [`docs/STREAMS.md`](STREAMS.md) for the bandwidth-limit auto-bans that most commonly feed this feature.
