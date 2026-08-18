# Scheduled changes

A handful of Site and Stream fields change what a live listener is doing rather than just data read per request: a Stream's incoming port, forward host/port, certificate, or PROXY protocol mode, and a Site's public hostname while it has an active certificate. BurrowGate can defer editing exactly those fields to an admin-chosen time instead of applying them the instant the form is saved, so a config change made during business hours doesn't land in the middle of active traffic. Every other field on a Site or Stream always applies immediately, exactly as before this existed - scheduling is opt-in and only ever touches the fields listed below.

## Which fields defer

**Streams**: the TCP/UDP enabled toggles, incoming port, forward host, forward port, TLS certificate, and PROXY protocol mode. Changing any of these makes `StreamProxyManager` stop and recreate the stream's TCP and/or UDP listener. See [`STREAMS.md`](STREAMS.md).

**Sites**: the public hostname, but only when the site currently has an active certificate - changing it rebuilds the HTTPS listener's SNI-to-certificate table. Without a certificate, a hostname change is pure routing data and always applies immediately. See [`TLS.md`](TLS.md).

Everything else - protection policy, rate limits, bandwidth limits, health checks, network rules, error responses, and so on - was already applied live before this feature existed and is unaffected by it.

## How it works

Edit a Stream or Site and set the **Schedule listener change for** / **Schedule hostname change for** field to a future date and time before saving. BurrowGate then:

- applies every other field from the same save immediately, as usual;
- keeps the listener-affecting fields at their current live values until the scheduled time, so already-connected clients are unaffected and new connections keep reaching the current target;
- shows a banner on the Stream or Site ("Scheduled change: ... at ...") with **Apply now** and **Cancel** actions.

Leaving the schedule field blank applies the change immediately - the same behavior as before this feature existed.

Only one change can be scheduled per Site or Stream at a time. Saving another edit to a deferred field while one is already pending is rejected with an error naming the existing scheduled time; cancel or apply it first.

## Applying, cancelling, and failures

A background poller checks for due changes every `BG_PENDING_CHANGE_POLL_INTERVAL_SECONDS` (default 15 seconds) and applies them the same way a normal save would. If applying a scheduled change fails - for example, another Stream took the target port in the meantime - BurrowGate retries with a fixed delay (`BG_PENDING_CHANGE_RETRY_BACKOFF_SECONDS`, default 60 seconds) up to `BG_PENDING_CHANGE_MAX_ATTEMPTS` times (default 5) before giving up and marking the change failed.

A failed change is logged (`Giving up on scheduled ... change ... after N attempts`) and stays visible on the Stream or Site as a red "Scheduled change failed" banner with the last error, instead of silently disappearing. From there, **Retry now** attempts it immediately, or **Dismiss** removes it. Scheduling a fresh change for the same field also clears a stale failed one automatically, so there's never more than one change - pending or failed - to look at per Site or Stream.

Deleting a Site or Stream removes any change still scheduled or failed for it.

## Runtime limits

| Variable                                  | Default | Purpose                                                   |
| ----------------------------------------- | ------: | --------------------------------------------------------- |
| `BG_PENDING_CHANGE_POLL_INTERVAL_SECONDS` |    `15` | How often the scheduler checks for changes that are due   |
| `BG_PENDING_CHANGE_MAX_ATTEMPTS`          |     `5` | Retry attempts before a scheduled change is marked failed |
| `BG_PENDING_CHANGE_RETRY_BACKOFF_SECONDS` |    `60` | Delay before retrying a scheduled change that just failed |
