# System resource monitoring

BurrowGate samples the CPU, memory, disk, and network usage of the machine (or container) it runs on and rolls the samples up into one-minute min/max/average buckets. The dashboard's **Host** page exposes them as **CPU usage**, **Memory usage**, **Storage usage**, **Network download**, and **Network upload** live-status tiles and chart options, alongside internet connectivity latency and timeouts - all readings that apply to the whole host rather than any single site or stream, which is why they live there instead of on the Web Proxy or Streams pages.

This is separate from the `process_uptime`/`process_memory` metrics BurrowGate already reports for its own Bun process (see [OPENMETRICS.md](OPENMETRICS.md)) - those track BurrowGate's own heap/RSS, while this feature tracks the whole machine or container BurrowGate is deployed on.

## What is tracked

- **CPU**: overall utilization percentage.
- **Memory**: bytes used and total capacity.
- **Disk**: bytes used and total capacity of the filesystem holding `BG_DATA_DIR` (the same volume that's bind-mounted in Docker deployments) - not every mounted filesystem.
- **Network**: download/upload throughput summed across all non-loopback interfaces.

### Host vs. container-scoped readings

Reading `/proc/stat`/`/proc/meminfo` from inside a container reports the whole physical/VM host, not just the container - the kernel doesn't scope these files to a cgroup. That's the right answer when BurrowGate is the primary service on a mostly-dedicated host (the shipped `docker-compose.yml` uses `network_mode: host` with no resource limits). But `/sys/fs/cgroup/memory.current`/`memory.max` (and their cgroup v1 equivalents) correctly scope to just the container, which is the right answer once a deployment sets an explicit memory/CPU limit - otherwise usage would look artificially low right up until the container is OOM-killed or throttled.

BurrowGate picks automatically: if cgroup v2 or v1 reports a _finite_ CPU/memory limit, it uses cgroup usage/limit (container-scoped). Otherwise it falls back to `/proc/stat` deltas and `/proc/meminfo` (host-wide). Disk and network readings are unambiguous either way and don't need this adaptation - disk always reads the data directory's filesystem, and network always reads `/proc/net/dev` (which is the host's own interfaces when using `network_mode: host`, or the container's own interfaces otherwise).

## Configuration

- `BG_SYSTEM_MONITOR_ENABLED` (default `true`)
- `BG_SYSTEM_MONITOR_INTERVAL_SECONDS` (default `3`, minimum `1`) - sampling cadence. The dashboard's live status tiles poll on their own schedule (down to 1 second) independent of this value, but they can only be as fresh as the last sample taken here.
- `BG_SYSTEM_MONITOR_RETENTION_DAYS` (default `30`)
- `BG_SYSTEM_MONITOR_CPU_THRESHOLD_PCT` (default `90`)
- `BG_SYSTEM_MONITOR_MEMORY_THRESHOLD_PCT` (default `90`)
- `BG_SYSTEM_MONITOR_DISK_THRESHOLD_PCT` (default `85`)
- `BG_SYSTEM_MONITOR_NETWORK_THRESHOLD_MBPS` (default `0`, disabled) - link capacity can't be auto-detected, so network alerting stays off until you set this explicitly.
- `BG_SYSTEM_MONITOR_FAILURE_THRESHOLD` (default `2`) - consecutive over-threshold samples before an alert fires.
- `BG_SYSTEM_MONITOR_RECOVERY_THRESHOLD` (default `2`) - consecutive under-threshold samples before the alert clears.

## Alerts

When a resource stays over its threshold for `BG_SYSTEM_MONITOR_FAILURE_THRESHOLD` consecutive samples, BurrowGate records a `system_resource_high` event; when it recovers for `BG_SYSTEM_MONITOR_RECOVERY_THRESHOLD` consecutive samples, it records `system_resource_normal`. Like internet connectivity, these are global events delivered through every site's and stream's configured webhook - see [NOTIFICATIONS.md](NOTIFICATIONS.md) for delivery providers and per-site/per-stream event-type toggles. Alert state resets on restart and is not shared across multiple BurrowGate instances; each process evaluates its own machine/container independently.

The failure/recovery thresholds count samples, not seconds - at the default 3-second interval, 2 consecutive samples means an alert can fire or clear after only ~6 seconds. If you lower `BG_SYSTEM_MONITOR_INTERVAL_SECONDS` further, consider raising the thresholds so a brief spike doesn't page you.
