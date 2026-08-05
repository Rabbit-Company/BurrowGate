# Prometheus and OpenTelemetry metrics

BurrowGate uses `@rabbit-company/openmetrics-client` to expose operational metrics in the OpenMetrics text format. The endpoint is disabled by default.

Enable it with:

```env
BG_OPENMETRICS_ENABLED=true
BG_OPENMETRICS_TOKEN=replace-with-a-long-random-token
```

Metrics are then available at:

```text
/_burrowgate/metrics
```

When a token is configured, scrapers must send `Authorization: Bearer <token>`. Leaving the token empty makes the endpoint unauthenticated, so only do that when network policy prevents untrusted access.

## Prometheus

```yaml
scrape_configs:
  - job_name: burrowgate
    metrics_path: /_burrowgate/metrics
    authorization:
      type: Bearer
      credentials: replace-with-a-long-random-token
    static_configs:
      - targets: ["burrowgate:80"]
```

Use the HTTPS service address and configure Prometheus TLS settings when scraping BurrowGate over HTTPS.

## OpenTelemetry Collector

The Collector's Prometheus receiver can scrape the same endpoint and forward the metrics through any configured OpenTelemetry exporter:

```yaml
receivers:
  prometheus:
    config:
      scrape_configs:
        - job_name: burrowgate
          metrics_path: /_burrowgate/metrics
          authorization:
            type: Bearer
            credentials: replace-with-a-long-random-token
          static_configs:
            - targets: ["burrowgate:80"]

service:
  pipelines:
    metrics:
      receivers: [prometheus]
      exporters: [otlp]
```

Define the referenced `otlp` exporter elsewhere in the Collector configuration.

## Metric groups

- `burrowgate_http_requests_total` and `burrowgate_http_request_duration_seconds`
- `burrowgate_http_transferred_bytes_total`
- `burrowgate_stream_events_total` and `burrowgate_stream_transferred_bytes_total`
- `burrowgate_stream_active_connections`
- `burrowgate_stream_listener_configured` and `burrowgate_stream_listener_up`
- `burrowgate_origin_health_state` for aggregate pool health and `burrowgate_origin_backend_health_state` for each configured origin
- `burrowgate_origin_health_checks_total` and `burrowgate_origin_health_check_duration_seconds`, labeled by site and origin
- `burrowgate_origin_health_alerts_total`
- `burrowgate_monitoring_queue_records`, persistence failures, and dropped events
- `burrowgate_retention_cleanup_*`
- `burrowgate_database_up`, configured site and Stream counts, and GeoIP availability
- `burrowgate_process_*` and `burrowgate_openmetrics_*`

Counters reset when the BurrowGate process restarts. Resource labels use stable site and Stream IDs. Request paths, hosts, client IPs, country codes, usernames, and session identifiers are intentionally excluded to avoid sensitive or unbounded label cardinality.
