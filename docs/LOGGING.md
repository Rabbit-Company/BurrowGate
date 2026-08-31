# File logging

BurrowGate always logs to the process console. Optional file logging adds one node-local file per calendar day under `BG_LOG_DIRECTORY` (default `./data/logs`):

```text
2026-10-15.txt
```

Each line uses the logger's NDJSON format, containing an ISO `time`, numeric `level`, `msg`, and optional `metadata`. Stack traces and metadata remain on one line, so entries can be searched and parsed reliably.

File output is buffered with the logger's `NDJsonTransport` and appended in batches every second or when the buffer reaches 64 KiB. A batch remains queued in memory until its file append succeeds; failed writes are retried rather than discarded.

The dashboard's **Logs** page is after **Cluster** in the top navigation. It provides:

- a searchable, paginated view of uncompressed logs;
- filters for date/time and log level;
- a stacked graph of entry counts by level, with drag-to-select range zoom;
- file logging, level, compression, and retention settings; and
- compressed archive download and deletion.

Logging settings are local to each node. This is intentional: clustered nodes have separate process output and log storage. Administrators can change settings and delete archives; other authenticated dashboard users can view logs and download archives.

## Rotation and retention

The current day is always kept as plain text. By default, files from previous days are compressed to `YYYY-MM-DD.txt.gz` after one calendar day. Compression and retention maintenance runs at startup, after a settings change, and hourly.

Compressed files are download-only and are not searched or graphed by the dashboard. Both plain-text files and compressed archives are deleted after the configured retention period (30 days by default). The compression age must be lower than the retention age.

## Environment defaults

```env
BG_FILE_LOGGING_ENABLED=false
BG_LOG_LEVEL=info
BG_LOG_DIRECTORY=./data/logs
BG_LOG_COMPRESS_AFTER_DAYS=1
BG_LOG_RETENTION_DAYS=30
```

Valid levels, from most restrictive to most detailed, are `error`, `warn`, `audit`, `info`, `http`, `debug`, `verbose`, and `silly`. Selecting a level includes that level and every more important level.

Once settings are saved in the Logs page, they are persisted in `BG_LOG_DIRECTORY/settings.json` and take precedence over the environment defaults on later starts. To return control to environment defaults, stop BurrowGate and remove only that settings file.
