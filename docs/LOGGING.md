# Logging and administrative audit trail

BurrowGate keeps two complementary kinds of logs:

- a structured administrative audit trail in the configured SQL database
- runtime logs written to the process console and, optionally, daily files.

They have different purposes and retention. The audit trail answers who changed gateway configuration; runtime logs explain authentication, startup, proxy, and operational behavior.

## Administrative audit trail

Successful administrative changes across sites, routes, streams, network rules, users, certificates, DNS providers, firewall sync, and HA topology create a structured audit record containing:

- the acting administrator's stable user ID and username
- source IP address and timestamp
- a stable action name such as `site.update`, `certificate.renew`, or `ha.promote_node`
- the affected resource type and ID when applicable
- a human-readable summary

The dashboard provides an administrator-only, searchable, paginated audit view. The API additionally supports actor, action, resource, and time-range filters. There is no application endpoint for editing an audit entry. Administrators can purge records, but the purge creates a new `audit_log.purge` entry after the deletion.

The database audit trail is separate from the `audit` runtime log level. Authentication successes, failures, rate limits, logging-setting changes, archive deletion, and other operational events are written through the runtime logger instead. In an HA deployment, audit and runtime logs remain node-local and are not replicated.

Audit records currently remain in the database until an administrator purges them (there is no automatic audit-retention policy). They are not cryptographically chained or written to WORM storage, a database administrator can alter them directly, and timestamps rely on the host clock. Deployments with strict assurance requirements should enforce time synchronization and retention operationally and regularly copy records to independently controlled, append-only or tamper-evident storage/SIEM.

### Compliance and control alignment

The administrative audit trail can contribute technical evidence toward:

- [NIST SP 800-53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) AU-2 Event Logging, AU-3 Content of Audit Records, and AU-6 Audit Record Review, Analysis, and Reporting;
- [ISO/IEC 27001:2022](https://www.iso.org/standard/27001) Annex A 8.15 Logging and 8.16 Monitoring Activities;
- [SOC 2 Trust Services Criteria](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022) evidence for monitoring and change-management controls;
- [PCI DSS 4.0.1](https://www.pcisecuritystandards.org/document_library/?class=pcidss&doc=pci_dss) Requirement 10, Log and Monitor All Access to System Components and Cardholder Data;
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/audit/protocol-edited/index.html) §164.312(b), Audit Controls; and
- [GDPR](https://eur-lex.europa.eu/eli/reg/2016/679/oj) accountability and security-of-processing evidence under Articles 5(2) and 32.

These are control-alignment references, not certifications or compliance claims. ISO/IEC 27001 certification applies to an organization's information security management system, SOC 2 is an independent attestation report, and PCI DSS, HIPAA, and GDPR compliance depend on the complete scoped environment plus organizational policies and procedures. Audit records can themselves contain personal data such as usernames and IP addresses, so operators must also apply appropriate access, minimization, and retention rules.

## Runtime file logging

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
