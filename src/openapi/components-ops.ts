import type { JsonSchema } from "./types.ts";

export const opsSchemas: Record<string, JsonSchema> = {
	HaSelfInfo: {
		type: "object",
		required: ["name", "version"],
		properties: {
			name: { type: "string", description: "This node's configured HA node name." },
			version: { type: "string", description: "BurrowGate version string." },
			selfAdminUrl: { type: ["string", "null"], description: "This node's own admin URL as known to the cluster, or null if unset." },
		},
	},
	HaClusterNode: {
		type: "object",
		description: "One member of the cluster, as tracked by the primary (or forwarded from the primary to a replica's status view).",
		required: ["nodeId", "name", "version", "connectedAt", "connected", "lastSeenAt", "adminUrl", "lastAckedSeq"],
		properties: {
			nodeId: { type: "string" },
			name: { type: "string" },
			version: { type: "string" },
			connectedAt: {
				type: ["integer", "null"],
				description: "Unix milliseconds this node's current mesh connection was established, or null if not connected.",
			},
			connected: { type: "boolean" },
			lastSeenAt: { type: "integer", description: "Unix milliseconds." },
			adminUrl: { type: "string" },
			lastAckedSeq: { type: ["integer", "null"], description: "Highest replication sequence number this node has acknowledged, or null if none yet." },
		},
	},
	HaVersionMismatch: {
		type: "object",
		required: ["nodeId", "name", "version"],
		properties: {
			nodeId: { type: "string" },
			name: { type: "string" },
			version: { type: "string" },
		},
	},
	HaAuthorityFence: {
		type: ["object", "null"],
		description: "Present when this node has observed a higher HA epoch than its own, fencing it from acting as primary until resolved.",
		required: ["observedEpoch", "sourceNodeId", "observedAt"],
		properties: {
			observedEpoch: { type: "integer" },
			sourceNodeId: { type: "string" },
			observedAt: { type: "integer", description: "Unix milliseconds." },
		},
	},
	HaStuckPromotionIntent: {
		type: ["object", "null"],
		description: "Present when a previously-started promotion never completed and is blocking new ones.",
		required: ["promotionId", "targetNodeId"],
		properties: {
			promotionId: { type: "string" },
			targetNodeId: { type: "string" },
		},
	},
	HaClusterStatus: {
		type: "object",
		description:
			"Shape depends on `enabled` and `role`. If HA is disabled instance-wide, only `enabled: false` is present. If enabled, `role` is `primary` or `replica`; a replica additionally mirrors most of the primary's own fields once it can reach the primary (forwarded through it), falling back to a bare local view (`connectionState`/`primaryReachable` only, no `nodes`) if it cannot.",
		required: ["enabled"],
		properties: {
			enabled: { type: "boolean" },
			role: { type: "string", enum: ["primary", "replica"] },
			self: { $ref: "#/components/schemas/HaSelfInfo" },
			connectionState: {
				type: "string",
				enum: ["unknown", "connected", "disconnected", "key_mismatch", "epoch_mismatch", "version_mismatch", "connection_rejected"],
				description: "Replica only: this node's mesh connection state to the primary.",
			},
			primaryReachable: { type: "boolean", description: "Replica only." },
			primary: {
				type: ["object", "null"],
				description: "Replica only: the primary's own identity, as last observed.",
				required: ["name", "version"],
				properties: { name: { type: "string" }, version: { type: "string" }, selfAdminUrl: { type: ["string", "null"] } },
			},
			nodes: { type: "array", items: { $ref: "#/components/schemas/HaClusterNode" }, description: "Every known cluster member, primary included." },
			latestSeq: { type: "integer", description: "Highest replication sequence number issued so far." },
			versionCompatible: { type: "boolean", description: "Whether every connected node's version is compatible with this cluster." },
			versionMismatches: { type: "array", items: { $ref: "#/components/schemas/HaVersionMismatch" } },
			fencedForPromotion: { type: "boolean", description: "Whether this primary is currently fenced from accepting a promotion." },
			authorityFence: { $ref: "#/components/schemas/HaAuthorityFence" },
			stuckPromotionIntent: { $ref: "#/components/schemas/HaStuckPromotionIntent" },
			quorumFenced: { type: "boolean", description: "Whether this primary has lost the connectivity majority required to accept new writes/enrollments." },
			autoFailoverEligible: { type: "boolean", description: "Whether current conditions would allow automatic failover to proceed." },
		},
	},
	HaDeadLetter: {
		type: "object",
		description:
			"A multi-writer replication event the primary could not apply and gave up on (not a transient failure - those retry on the originating replica). See docs/HIGH_AVAILABILITY.md, 'Dropped replication events'.",
		required: ["id", "node_id", "relay_id", "entity_type", "entity_id", "op", "payload_json", "reason", "occurred_at"],
		properties: {
			id: { type: "string" },
			node_id: { type: "string", description: "The replica node that originated the dropped event." },
			relay_id: { type: "integer" },
			entity_type: { type: "string" },
			entity_id: { type: "string" },
			op: { type: "string" },
			payload_json: { type: ["string", "null"] },
			reason: { type: "string" },
			occurred_at: { type: "integer", description: "Unix milliseconds." },
		},
	},

	HostConnectivityTarget: {
		type: "object",
		required: ["target", "latencyMs", "timedOut", "checkedAt", "state"],
		properties: {
			target: { type: "string", description: "The host/IP being pinged for outbound-connectivity monitoring." },
			latencyMs: { type: ["number", "null"] },
			timedOut: { type: ["boolean", "null"] },
			checkedAt: { type: ["integer", "null"], description: "Unix milliseconds of the last check, or null if never checked yet." },
			state: { type: "string", enum: ["unknown", "up", "down"] },
		},
	},
	HostSnapshot: {
		type: "object",
		description:
			"The most recently collected host resource sample. All numeric fields are null until the monitor has taken (and, for cpu, diffed) its first sample.",
		required: ["sampledAt", "cpu", "memory", "disk", "network", "connectivity"],
		properties: {
			sampledAt: { type: ["integer", "null"], description: "Unix milliseconds this sample was taken, or null if no sample exists yet." },
			cpu: { type: "object", required: ["pct"], properties: { pct: { type: ["number", "null"], description: "0-100." } } },
			memory: {
				type: "object",
				required: ["usedBytes", "totalBytes"],
				properties: { usedBytes: { type: ["integer", "null"] }, totalBytes: { type: ["integer", "null"] } },
			},
			disk: {
				type: "object",
				description: "Usage of the filesystem backing BurrowGate's configured data directory.",
				required: ["usedBytes", "totalBytes"],
				properties: { usedBytes: { type: ["integer", "null"] }, totalBytes: { type: ["integer", "null"] } },
			},
			network: {
				type: "object",
				required: ["rxBps", "txBps"],
				properties: { rxBps: { type: ["number", "null"] }, txBps: { type: ["number", "null"] } },
			},
			connectivity: { type: "array", items: { $ref: "#/components/schemas/HostConnectivityTarget" } },
		},
	},

	LogSettings: {
		type: "object",
		required: ["fileEnabled", "level", "compressAfterDays", "retentionDays"],
		properties: {
			fileEnabled: { type: "boolean" },
			level: { type: "string", enum: ["error", "warn", "audit", "info", "http", "debug", "verbose", "silly"] },
			compressAfterDays: { type: "integer", minimum: 1, maximum: 3_649, description: "Uncompressed daily log files older than this are gzipped." },
			retentionDays: {
				type: "integer",
				minimum: 2,
				maximum: 3_650,
				description: "Log files (compressed or not) older than this are deleted. Must exceed compressAfterDays.",
			},
		},
	},
	LogSettingsInput: {
		type: "object",
		description: "Partial update; omitted fields keep their current value.",
		properties: {
			fileEnabled: { type: "boolean" },
			level: { type: "string", enum: ["error", "warn", "audit", "info", "http", "debug", "verbose", "silly"] },
			compressAfterDays: { type: "integer", minimum: 1, maximum: 3_649 },
			retentionDays: { type: "integer", minimum: 2, maximum: 3_650 },
		},
	},
	LogEntry: {
		type: "object",
		required: ["timestamp", "level", "message"],
		properties: {
			timestamp: { type: "integer", description: "Unix milliseconds." },
			level: { type: "string", enum: ["error", "warn", "audit", "info", "http", "debug", "verbose", "silly"] },
			message: { type: "string" },
			metadata: { description: "Arbitrary structured metadata attached to the log call, if any." },
		},
	},
	LogQueryResult: {
		type: "object",
		required: ["items", "total", "page", "pageSize", "totalPages", "bucketMs", "rangeFrom", "rangeTo", "series", "uncompressedDates"],
		properties: {
			items: { type: "array", items: { $ref: "#/components/schemas/LogEntry" }, description: "Newest-first, one page's worth of matching entries." },
			total: { type: "integer", description: "Total matching entries across the whole range, not just this page." },
			page: { type: "integer" },
			pageSize: { type: "integer" },
			totalPages: { type: "integer" },
			bucketMs: { type: "integer", description: "Width of each `series` bucket, auto-selected from the requested range's duration." },
			rangeFrom: { type: "integer", description: "Unix milliseconds; echoes the request's `from`." },
			rangeTo: { type: "integer", description: "Unix milliseconds; echoes the request's `to`." },
			series: {
				type: "array",
				description: "Per-bucket counts of every entry in range (regardless of the `search`/`level` filters), for rendering a histogram.",
				items: {
					type: "object",
					required: ["bucket", "error", "warn", "audit", "info", "http", "debug", "verbose", "silly"],
					properties: {
						bucket: { type: "integer", description: "Unix milliseconds; the bucket's start." },
						error: { type: "integer" },
						warn: { type: "integer" },
						audit: { type: "integer" },
						info: { type: "integer" },
						http: { type: "integer" },
						debug: { type: "integer" },
						verbose: { type: "integer" },
						silly: { type: "integer" },
					},
				},
			},
			uncompressedDates: {
				type: "array",
				items: { type: "string" },
				description: "Dates (YYYY-MM-DD) that still have an uncompressed, searchable log file on disk.",
			},
		},
	},
	LogArchive: {
		type: "object",
		required: ["name", "date", "size", "modifiedAt"],
		properties: {
			name: { type: "string", description: "Filename, e.g. 2026-08-30.txt.gz." },
			date: { type: "string", description: "YYYY-MM-DD." },
			size: { type: "integer", description: "Bytes." },
			modifiedAt: { type: "integer", description: "Unix milliseconds." },
		},
	},
};
