# Notifications

BurrowGate can send a webhook whenever something operationally significant happens: an origin going down or recovering, the entire origin pool becoming unavailable, the BurrowGate host itself losing internet connectivity, or an IP getting automatically banned. Sites and TCP/UDP Streams each configure their own destination and can subscribe to exactly the event types they care about.

Open the **Notifications** dashboard from the switcher at the top of the control panel (`/_burrowgate/admin/notifications`). It is a dedicated tab, separate from the Site and Stream editors, with a site picker and a stream picker side by side - each drives its own webhook configuration, event-type toggles, and a paginated, filterable, sortable log of every event recorded for that site or stream, whether or not delivery succeeded.

## Event types

**Sites** can subscribe to:

- `origin_unhealthy` / `origin_recovered` - an individual origin in the pool failed or passed its health check while another origin kept the pool available.
- `pool_unhealthy` / `pool_recovered` - every origin in the pool became unavailable, or the pool became available again.
- `internet_down` / `internet_up` - the BurrowGate host itself lost or regained internet connectivity (see [Connectivity monitoring](#connectivity-monitoring)).
- `ip_banned` - bandwidth-limit or managed-protection auto-ban blocked an IP.
- `system_resource_high` / `system_resource_normal` - host/container CPU, memory, disk, or network usage crossed (or recovered from) a configured alert threshold (see [System resource monitoring](SYSTEM_MONITORING.md)).

**Streams** can subscribe to:

- `stream_origin_unhealthy` / `stream_origin_recovered` - the stream's forward host/port stopped or resumed accepting TCP connections.
- `stream_ip_banned` - bandwidth-limit or stream-protection auto-ban blocked an IP.
- `internet_down` / `internet_up` - shared with sites; a stream can subscribe independently of any site.
- `system_resource_high` / `system_resource_normal` - shared with sites; a stream can subscribe independently of any site.

A missing event type in a site's or stream's saved configuration defaults to **enabled**, so upgrading BurrowGate never silently drops a notification you already relied on.

## Delivery

Each event is written once to a durable table, then fanned out to every subscribed destination as its own delivery row. A poller drains pending deliveries every two seconds and retries failures with exponential backoff (capped at one hour between attempts, up to eight attempts before a delivery is marked permanently failed).

Deliveries for the same destination are sent strictly in the order the underlying events happened: a newer event never overtakes an older one that is still retrying. This matters most for connectivity - during an outage a queued `internet_down` message keeps retrying and failing (the network is down, after all), so without ordering a later `internet_up` message could reach the webhook first once the network returns, since its first attempt has no backoff to wait out.

Every message includes the event's real occurrence time, not just when the webhook finally delivered - relevant because a message queued during an outage may not actually reach the destination until well after the event happened. ntfy and the generic JSON webhook show it as an explicit UTC timestamp in the message body; Discord and Slack use their native timestamp fields instead, which render in the viewer's own local time automatically.

## Providers

- **ntfy** - plain-text body with a title, `high`/`default` priority, and a warning/check-mark tag depending on whether the event represents a down or recovered state.
- **Slack** - a colored attachment (red/orange/green depending on severity) with a title, the event summary, structured fields pulled from the event (e.g. the banned IP and its expiry, or the affected origin and HTTP status), and a native timestamp.
- **Discord** - an equivalent rich embed: colored sidebar, title, description, the same structured fields, and a native timestamp footer.
- **Generic** - a signed JSON payload with `id`, `type`, `severity`, `summary`, `occurredAt`, and the full event `payload`, for anything else that can receive a webhook.

Webhook URLs and signing secrets are encrypted at rest. When a signing secret is configured, every delivery includes an `x-burrowgate-signature: sha256=<hmac>` header over the raw request body so the receiving endpoint can verify authenticity.

## Connectivity monitoring

BurrowGate pings a small set of public DNS resolvers directly from its own host (`1.1.1.1` and `8.8.8.8` by default) to distinguish "the origin is down" from "this server lost its own internet connection." Detection uses the same consecutive-failure/consecutive-success hysteresis as origin health checks, evaluated on each raw ping result as it happens - independent of the one-minute latency-graph buckets, which only aggregate for display. That is what lets an `internet_down`/`internet_up` pair carry a precise timestamp instead of only "this minute was N% packet loss."

The host is considered down only once every monitored target agrees, and up again as soon as any target responds - avoiding false alarms from a single resolver's own outage. Configure targets and thresholds with:

- `BG_CONNECTIVITY_MONITOR_TARGETS` (default `1.1.1.1,8.8.8.8`)
- `BG_CONNECTIVITY_MONITOR_INTERVAL_SECONDS` (default `3`, minimum `1`)
- `BG_CONNECTIVITY_MONITOR_FAILURE_THRESHOLD` / `BG_CONNECTIVITY_MONITOR_RECOVERY_THRESHOLD` (default `3` / `2`)

## System resource monitoring

BurrowGate also samples its host/container's CPU, memory, disk, and network usage on the same one-minute bucketed model used for the dashboard's charts, and can alert on `system_resource_high`/`system_resource_normal` the same way it does for connectivity. See [SYSTEM_MONITORING.md](SYSTEM_MONITORING.md) for what's tracked, how it adapts between bare-metal and Docker deployments, and its configuration.

## Origin and Stream health checks

Health-check settings themselves (path, interval, timeout, failure/recovery thresholds) still live on the Site editor's **Health** tab and the Streams dashboard's **Health** tab - only the webhook/event-type configuration moved to the Notifications tab. The minimum check interval is 3 seconds for both.

Because a short interval combined with a low failure threshold can flag an origin unhealthy after only a few seconds of any blip, both editors show a warning notice - updated live as you type - whenever `interval x failure threshold` drops under 15 seconds, suggesting a higher failure threshold for more reliable detection.

## Retention

Notification events and their delivery outbox follow the same retention setting as everything else for that site or stream (1-365 days). Global events - `internet_down`/`internet_up` and `system_resource_high`/`system_resource_normal`, which are not owned by any single site or stream - use the instance-wide `BG_EVENT_RETENTION_DAYS` default instead. This is separate from `BG_SYSTEM_MONITOR_RETENTION_DAYS`, which controls how long the underlying one-minute usage buckets behind the dashboard charts are kept.

See [`docs/STREAMS.md`](STREAMS.md) for Stream-specific health-check behavior and [`docs/BANDWIDTH.md`](BANDWIDTH.md) / [`docs/MANAGED_PROTECTION.md`](MANAGED_PROTECTION.md) for what triggers an auto-ban.
