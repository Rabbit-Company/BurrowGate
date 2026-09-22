# CrowdSec

BurrowGate can act as a [CrowdSec](https://www.crowdsec.net/) **remediation component** (what CrowdSec's documentation also calls a bouncer). It pulls decisions from a CrowdSec Local API and enforces them on every HTTP request and every TCP/UDP stream connection, per site, per route, and per stream. The integration is disabled by default.

CrowdSec decides _who_ should be stopped. BurrowGate decides _what that means_ for each site. A `ban` ends the request with HTTP 403. A `captcha` hands the visitor to that site's existing challenge chain - proof of work, Turnstile, hCaptcha, Snake, or whatever else is configured - so a suspected-but-unproven bad actor can still get through by proving they are real.

## How decisions are fetched

BurrowGate uses the Local API's **streaming** endpoint, `GET /v1/decisions/stream`, not the per-request query endpoint.

- The first poll after startup asks for a full snapshot (`startup=true`) and replaces everything it holds.
- Later polls ask only for changes (`startup=false`) and apply the `new` and `deleted` lists.
- Every so often (the **full resync interval**, 30 minutes by default) BurrowGate discards the incremental cursor and pulls a fresh snapshot, correcting any drift.
- **Any failed poll forces the next one back to a full snapshot.** The Local API's delta cursor is state on its side, so a CrowdSec restart or a network blip can otherwise leave BurrowGate's copy subtly wrong.

The decisions live in memory, indexed so that a lookup costs the same whether CrowdSec is serving a thousand decisions or half a million. Nothing about a request waits on the Local API.

This matters for availability. If the Local API goes down, BurrowGate keeps enforcing the decisions it already has (they carry their own expiry, so they lapse on their own rather than sticking forever), keeps serving traffic at full speed, and does not block anyone new. Startup never waits on CrowdSec either.

## Setup

If you already run CrowdSec, skip to [Connecting BurrowGate](#connecting-burrowgate). If you don't, the bundled Compose profile is the quickest way to get one.

### Running CrowdSec with the bundled Compose profile

`docker-compose.yml` ships a `crowdsec` service behind an opt-in profile, the same way `geoipupdate` works. It is not started by a plain `docker compose up`.

```sh
docker compose --profile crowdsec up -d
```

That gives you a CrowdSec engine with its Local API on `127.0.0.1:8080`, **bound to loopback only**. Publishing that port publicly would expose the decision API, so leave the binding alone unless you know why you are changing it.

Its state lives in `./data/crowdsec-engine/` (`config/` and `data/`). That is deliberately separate from `./data/crowdsec/`, which is where BurrowGate keeps its own decision snapshot. Do not point one at the other.

Then register BurrowGate as a bouncer and copy the key it prints:

```sh
docker compose exec crowdsec cscli bouncers add burrowgate
```

Optional settings, via `.env`:

| Variable                        | Default               | Purpose                                                     |
| ------------------------------- | --------------------- | ----------------------------------------------------------- |
| `CROWDSEC_COLLECTIONS`          | `crowdsecurity/linux` | Hub collections to install.                                 |
| `CROWDSEC_ENROLL_KEY`           | empty                 | Enrolment key to attach the engine to the CrowdSec console. |
| `CROWDSEC_ENROLL_INSTANCE_NAME` | `burrowgate`          | Name the engine appears under in the console.               |

Out of the box that engine gives you the **community blocklist** plus any decisions you add yourself with `cscli decisions add`. It is not yet watching BurrowGate's own traffic: no CrowdSec parser understands BurrowGate's log format, so BurrowGate's WAF hits and auto-bans do not become CrowdSec alerts. To have the engine detect attacks against your own services, mount their logs and add an acquisition file under `./data/crowdsec-engine/config/acquis.d/`.

### Running CrowdSec yourself

Any reachable Local API works. Register a bouncer on that host:

```sh
cscli bouncers add burrowgate
```

If CrowdSec runs in Docker on a shared network with BurrowGate, the Local API URL is usually the service name, e.g. `http://crowdsec:8080`. Note that BurrowGate's own Compose service uses host networking, so it reaches a published loopback port as `http://127.0.0.1:8080` rather than by service name.

### Connecting BurrowGate

1. Open the **CrowdSec** dashboard tab and fill in:
   - **Local API URL** - `http://127.0.0.1:8080` for the bundled profile, or wherever your Local API listens.
   - **Bouncer API key** - the key from `cscli bouncers add`. It is encrypted at rest and never sent back to the browser.
2. Click **Test connection** to confirm the Local API answers and accepts the key, then tick **Enabled** and **Save**.

Enabling only starts loading decisions. Nothing is blocked until a site's policy says so - see [Per-site and per-route policy](#per-site-and-per-route-policy-http) and [TCP and UDP streams](#tcp-and-udp-streams).

### Settings

| Setting                  | Default        | Notes                                                                                                                                                                                                     |
| ------------------------ | -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Decision scopes**      | IP, Range      | Which scopes to request. Country and AS are matched against GeoIP data BurrowGate already resolves, so they cost nothing extra per request - but leave them off unless you actually issue such decisions. |
| **Poll interval**        | 10 seconds     | How often to pull changes. CrowdSec's own documented default.                                                                                                                                             |
| **Full resync interval** | 1800 seconds   | How often to reload everything instead of applying a delta.                                                                                                                                               |
| **Request timeout**      | 5000 ms        | Per-poll timeout. Off the request path, so it can be generous.                                                                                                                                            |
| **Verify TLS**           | On             | Only applies to an `https://` Local API. Turn off for a self-signed certificate.                                                                                                                          |
| **Unknown remediations** | Treat as a ban | What to do with a remediation that is neither `ban` nor `captcha`, such as `throttle`. Can also be treated as a captcha, or ignored.                                                                      |
| **Alert after**          | 15 minutes     | Raise a notification once the Local API has been unreachable this long. `0` disables it. See [Notifications](NOTIFICATIONS.md).                                                                           |

Environment variables, for operators who need them:

| Variable                          | Default   | Purpose                                                                    |
| --------------------------------- | --------- | -------------------------------------------------------------------------- |
| `BG_CROWDSEC_ENABLED`             | `true`    | Hard kill switch for the whole integration on this node.                   |
| `BG_CROWDSEC_MAX_DECISIONS`       | `1000000` | Ceiling on decisions held in memory, guarding against a runaway blocklist. |
| `BG_CROWDSEC_SNAPSHOT_CHUNK_SIZE` | `4000`    | Decisions processed per event-loop turn while rebuilding a snapshot.       |
| `BG_CROWDSEC_SWEEP_INTERVAL_MS`   | `300000`  | How often lapsed decisions are swept out of memory.                        |

## Per-site and per-route policy (HTTP)

Open a site and select **CrowdSec**. Each remediation is configured separately:

**Ban decisions**

- **Disabled** - ignore them entirely on this site.
- **Monitor** - record matches in Recent traffic without changing the outcome.
- **Block** - reject with HTTP 403 and the error code `crowdsec_blocked`.

**AppSec inspection**

- **Disabled** - do not send this site's requests to AppSec.
- **Identify only** - inspect and record the verdict without acting on it.
- **Identify and block** - refuse what AppSec rejects. See [AppSec](#appsec-the-crowdsec-waf).

**Captcha decisions**

- **Disabled** - ignore them.
- **Monitor** - record matches without challenging anyone.
- **Challenge** - send the visitor through the site's challenge chain. This applies even on a route whose access mode is bypass, since that is the point of the decision.

**Every site starts in monitor mode**, including sites that already existed before the upgrade. Switching the integration on therefore changes nothing a visitor experiences - it just makes matches visible. That is deliberate: the community blocklist is large, and meeting it for the first time in blocking mode is a good way to lock out a legitimate user without understanding why. Watch Recent traffic for a while, then switch sites to Block or Challenge.

Route policies inherit the site's policy or replace it outright with their own. Clearing a route's policy falls back to the site's.

## TCP and UDP streams

Streams enforce the same decisions. Open the Streams dashboard, select **Network rules**, choose a stream, and set its two CrowdSec modes next to the privacy-network controls.

A stream has no challenge chain, so a `captcha` decision cannot be served the way it is over HTTP. Its options are therefore **Disabled**, **Identify only**, and **Identify and block**. Both modes default to Identify only, so a captcha decision never silently escalates into a dropped connection.

This matters more on a stream than on a website. An HTTP request can be challenged, rate limited, or inspected by the WAF, so a blocklist is one tool among several. A TCP connection to a game server, a mail daemon, or a database has no challenge to offer, which makes a curated blocklist the strongest lever available.

### Live connections

An HTTP request is over in milliseconds, so a decision arriving mid-request changes nothing. A TCP connection can last hours. When a poll brings in decisions that newly cover a connected address, BurrowGate re-checks live connections and closes the ones that now match, the same way it does when you change a stream's own network rules. A blocked UDP address stops having its datagrams forwarded.

Only streams set to **Identify and block** are swept. A stream in Identify only keeps its connections open, and a poll that only removes decisions never triggers a sweep, since removing a decision cannot newly block anyone.

Stream matches are recorded on connection events and visible in the Traffic log, alongside the existing network-type column.

## Allowlist precedence

An explicit IP/CIDR or ASN rule set to **Allow and follow route policy** (`pass`) or **Allow and bypass verification** (`allow`) overrides CrowdSec, for both bans and captchas. A local rule is the more specific, more deliberate statement, and a false positive in a remote blocklist must not be able to lock you out of your own site.

The match is still recorded, flagged as bypassed, so the request stays visible with an explanation of why nothing happened.

Streams use a single **Allow** action for explicit IP/CIDR and ASN rules, with the same precedence over CrowdSec.

Country rules and default actions do **not** override CrowdSec, on sites or on streams. Use a specific IP/CIDR or ASN allow rule for that. This matches how [network privacy](NETWORK_PRIVACY.md) behaves.

Ordering within a request: BurrowGate's own network policy is evaluated first, so an explicit or default block still rejects the request before CrowdSec is consulted. CrowdSec is then evaluated ahead of bot policy, route blocks, request limits, and the managed WAF - a decision from a blocklist should not have to travel through the whole pipeline to be acted on.

## Scope precedence

When several decisions could cover one visitor, the most specific wins: an exact address beats a range, which beats an AS, which beats a country. If two decisions target the same value - say the community blocklist and a manual `cscli` ban on one address - the stronger remediation is enforced, and deleting it promotes the other rather than unblocking the address.

## High availability

**Decisions are node-local.** Every node in a cluster polls the Local API itself and keeps its own copy in memory. Decisions are never written to the database and never replicated. Two consequences:

- A replica keeps enforcing CrowdSec decisions even when the primary is unreachable.
- The connection settings _are_ replicated, so every node dials the same Local API and you configure it once.

Give each node its own bouncer key (`cscli bouncers add burrowgate-node-1`, and so on) so `cscli metrics` can tell them apart. The dashboard's counters and the **Resync now** button apply to whichever node answers the request.

## Visibility

Matches are stored with request events and shown in Recent traffic. Blocked requests use the decision `crowdsec-blocked` and the error code `crowdsec_blocked`, which can be filtered for in the decision dropdown. Each record keeps the decision's scenario, origin, scope, and matched value, so you can tell a community-blocklist hit from your own manual ban.

The CrowdSec dashboard tab shows what this node currently holds, broken down by scope, remediation, and origin, along with the last poll, the last error, and a lookup box that answers "is this address currently decided against, and by what?".

## AppSec (the CrowdSec WAF)

CrowdSec's Application Security component is a WAF. Unlike decisions, which are polled in the background and answered from memory, AppSec inspects the live request, so using it costs an HTTP round-trip inside every request it sees. That is why it is **off by default** and opted into per site or per route rather than switched on globally.

It is free and part of open-source CrowdSec. It does not replace BurrowGate's own [managed request protection](MANAGED_PROTECTION.md). Both can run, and BurrowGate's local ruleset is evaluated first so a request it already rejects never pays for the round-trip.

### Enabling AppSec in CrowdSec

AppSec is **not on by default**, and it is not a port you simply open. The engine has to be told to run it, and it needs rules. With the bundled Compose profile:

```bash
# 1. Install the rules. Without these AppSec runs but matches nothing.
docker compose --profile crowdsec exec crowdsec \
  cscli collections install crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules

# 2. Tell the engine to listen. Note 0.0.0.0, not the documented 127.0.0.1 - see below.
cat > ./data/crowdsec-engine/config/acquis.d/appsec.yaml <<'YAML'
appsec_configs:
  - crowdsecurity/appsec-default
labels:
  type: appsec
listen_addr: 0.0.0.0:7422
source: appsec
name: burrowgate-appsec
YAML

# 3. Restart so it picks both up.
docker compose --profile crowdsec restart crowdsec
```

CrowdSec's own documentation uses `listen_addr: 127.0.0.1:7422`. **That value does not work in Docker.** It binds AppSec to the container's own loopback, so the published port maps to nothing and BurrowGate gets a connection refused. Inside a container it has to be `0.0.0.0:7422`, with the publish restricted to the host's loopback, which is what the bundled profile does. The same trap applies to the Local API's `listen_uri`.

Confirm it is listening before configuring BurrowGate:

```bash
curl -i --max-time 3 http://127.0.0.1:7422/
```

Anything other than a connection error means AppSec is up.

### Setup

Point BurrowGate at the component on the **CrowdSec** tab:

| Setting                    | Default | Notes                                                                                                               |
| -------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------- |
| **AppSec URL**             | empty   | e.g. `http://127.0.0.1:7422`. Blank disables AppSec everywhere, whatever the site policies say.                     |
| **Timeout**                | 200 ms  | CrowdSec's own default. This is spent inside every inspected request.                                               |
| **Max inspected body**     | 65536   | Larger bodies are inspected on headers and URI only. See [Request bodies](#request-bodies).                         |
| **Allow when unavailable** | on      | Fail open. Turning it off refuses uninspectable requests with 503, which takes the site down together with the WAF. |

AppSec uses the same bouncer API key as the Local API, so leaving the key field blank reuses the stored one. Then open a site or a route policy, select its **CrowdSec** tab, and set **AppSec inspection** to Identify only or Identify and block.

Enable it on the routes that need it rather than site-wide. A login or checkout endpoint is worth the round-trip. Static assets are not.

### Request bodies

AppSec inspects request bodies, which BurrowGate's own ruleset does not. A body is only buffered and forwarded when its `content-length` says it fits under the configured limit.

A **chunked** request has no declared length, and measuring it would mean buffering an upload of arbitrary size into memory. Those requests are inspected on their headers and URI alone and their body is streamed to the origin untouched. The traffic log records which of these happened for each request, as `inspected`, `oversized`, `unknown-length`, or `none`.

### Failure handling

An AppSec component that is unreachable, slow, or rejecting the API key is reported as an error rather than a block, and the **Allow when unavailable** setting decides what happens next. Fail-open is the default because a WAF outage should not take the site with it.

## Monitoring

The CrowdSec dashboard tab shows this node's state, but the thing worth alerting on is the feed going stale, because the integration fails open: a Local API that stops answering produces no errors and no visible change in traffic.

Two signals cover it. The **Alert after** setting raises a `crowdsec_lapi_down` notification once polling has been failing for that long, delivered to the same webhooks as origin and connectivity alerts, and subscribable per site and per stream like any other event type. For Prometheus, `burrowgate_crowdsec_last_success_timestamp_seconds` is published raw so a rule can compute staleness:

```promql
burrowgate_crowdsec_enabled == 1
  and (time() - burrowgate_crowdsec_last_success_timestamp_seconds) > 900
```

`burrowgate_crowdsec_decisions` (labeled by scope) catches the other failure worth knowing about, a feed that answers but has silently emptied. Enforcement counts need no separate metric, since blocked requests carry `decision="crowdsec-blocked"` on `burrowgate_http_requests_total`. See [OPENMETRICS.md](OPENMETRICS.md).

## Where decisions come from

A freshly installed CrowdSec serves no decisions, and BurrowGate showing zero is the two agreeing rather than a fault. Decisions reach the Local API from three independent places, and a new engine has none of them running yet.

**The community blocklist.** Pulled from CrowdSec's Central API on an interval, with no configuration and nothing for you to feed it. Worth knowing how CrowdSec tiers this: a free engine that does not regularly contribute signals receives the **Community Blocklist (Lite)**, which is capped, while free engines that do contribute receive the full list. Since BurrowGate does not yet report its own detections back, an engine that only serves BurrowGate is a non-contributor unless something else on it is producing signals.

**The engine's own log analysis.** This needs an acquisition file pointing at logs it can parse, plus a matching collection. Out of the box the bundled profile watches nothing. No CrowdSec parser understands BurrowGate's log format, so pointing it at BurrowGate's logs will not work. Point it at the services behind BurrowGate instead, or at the host's SSH and system logs.

**AppSec.** Inspects live requests BurrowGate forwards, so it produces verdicts without any log parsing at all. This is the quickest way to get CrowdSec acting on your own traffic rather than on other people's reputation data. See [AppSec](#appsec-the-crowdsec-waf).

To prove the pipeline end to end without waiting for any of that, add a decision by hand and watch BurrowGate pick it up within one poll:

```bash
docker compose --profile crowdsec exec crowdsec \
  cscli decisions add --ip 203.0.113.99 --duration 10m --reason "burrowgate test"
```

## What this integration does not do

- It does not report BurrowGate's own traffic back to CrowdSec. BurrowGate's WAF, auto-bans, and challenge failures stay in BurrowGate, where CrowdSec's scenarios do not see them.
- It does not push CrowdSec's decisions to [firewall sync](FIREWALL_SYNC.md) providers. Those providers have small entry caps (20 rules on OVH and AWS), and a community blocklist would overrun them instantly.
