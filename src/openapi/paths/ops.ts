import { errorResponse, jsonBody, jsonResponse, ref, type OperationObject, type PathItemObject, type ResponseObject } from "../types.ts";

const gzipResponse = (description: string): ResponseObject => ({
	description,
	content: { "application/gzip": { schema: { type: "string", format: "binary" } } },
});

const haPaths: Record<string, PathItemObject> = {
	"/ha/status": {
		get: {
			summary: "Get this node's HA cluster status",
			description:
				"If HA is disabled instance-wide, returns only `{ enabled: false }`. Otherwise returns this node's role and cluster view - a replica transparently mirrors the primary's own view (nodes, replication sequence, fencing state) when it can reach it, forwarding this request to the primary internally.",
			tags: ["HA cluster"],
			operationId: "getHaStatus",
			responses: {
				"200": jsonResponse("", ref("HaClusterStatus")),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required."),
			},
		},
	},
	"/ha/dead-letters": {
		get: {
			summary: "List recently dropped HA replication events",
			description:
				"A multi-writer event (a session, a ban, an identity change) the primary genuinely could not apply - not a transient failure, which the originating replica's own retry already covers - is dropped rather than retried forever. Returns the most recent 100. If HA is disabled, or this node is a replica that cannot reach the primary, `deadLetters` is empty.",
			tags: ["HA cluster"],
			operationId: "listHaDeadLetters",
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["enabled", "deadLetters"],
					properties: { enabled: { type: "boolean" }, deadLetters: { type: "array", items: ref("HaDeadLetter") } },
				}),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required."),
			},
		},
	},
	"/ha/identity": {
		put: {
			summary: "Update this node's HA identity",
			description: "Changes this node's own cluster-visible name and/or admin URL. Does not trigger a restart.",
			tags: ["HA cluster"],
			operationId: "updateHaIdentity",
			requestBody: jsonBody({
				type: "object",
				required: ["selfAdminUrl"],
				properties: {
					nodeName: { type: "string" },
					selfAdminUrl: { type: "string", description: "This node's own admin URL, as reachable by the rest of the cluster." },
				},
			}),
			responses: {
				"200": jsonResponse("", { type: "object", required: ["ok"], properties: { ok: { type: "boolean", const: true } } }),
				"400": errorResponse("selfAdminUrl is missing, or the update failed validation."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
			},
		},
	},
	"/ha/join": {
		post: {
			summary: "Join an existing HA cluster as a replica",
			description:
				"Redeems a join code minted by the primary (see POST .../ha/join-code) and enrolls this node as a replica. On success, this process schedules its own graceful restart shortly after responding to apply the new HA configuration - the response's `restarting: true` reflects this, not an error.",
			tags: ["HA cluster"],
			operationId: "joinHaCluster",
			requestBody: jsonBody({
				type: "object",
				required: ["joinCode", "selfAdminUrl"],
				properties: {
					joinCode: { type: "string", description: "One-time code produced by the primary's POST .../ha/join-code." },
					selfAdminUrl: { type: "string", description: "This node's own admin URL, as reachable by the rest of the cluster." },
					nodeName: { type: "string" },
				},
			}),
			responses: {
				"200": jsonResponse("Joined; this process will restart itself shortly.", {
					type: "object",
					required: ["ok", "restarting"],
					properties: { ok: { type: "boolean", const: true }, restarting: { type: "boolean", const: true } },
				}),
				"400": errorResponse(
					"Missing joinCode/selfAdminUrl, an invalid or expired join code, or the primary rejected enrollment (e.g. it lacks connectivity majority).",
				),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
			},
		},
	},
	"/ha/leave": {
		post: {
			summary: "Leave the HA cluster",
			description:
				"Removes this node from the cluster and reverts it to a standalone primary. On success, this process schedules its own graceful restart shortly after responding to apply the change - the response's `restarting: true` reflects this, not an error.",
			tags: ["HA cluster"],
			operationId: "leaveHaCluster",
			responses: {
				"200": jsonResponse("Left; this process will restart itself shortly.", {
					type: "object",
					required: ["ok", "restarting"],
					properties: { ok: { type: "boolean", const: true }, restarting: { type: "boolean", const: true } },
				}),
				"400": errorResponse("Unable to leave the cluster."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
			},
		},
	},
	"/ha/join-code": {
		post: {
			summary: "Generate a one-time HA join code",
			description:
				"Primary only. Produces a one-time code (embedding the primary's mesh address, pinned certificate, and epoch) for a new node to redeem via POST .../ha/join. The code expires after a short TTL.",
			tags: ["HA cluster"],
			operationId: "createHaJoinCode",
			responses: {
				"200": jsonResponse("", { type: "object", required: ["joinCode"], properties: { joinCode: { type: "string" } } }),
				"400": errorResponse("Only the primary can produce a join code, or this node has no admin URL/shared token configured."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
			},
		},
	},
	"/ha/promote/{nodeId}": {
		post: {
			summary: "Promote a replica to primary",
			description:
				"Primary only (a request received on a replica is forwarded to the primary automatically). Triggers failover, making the named node the new primary.",
			tags: ["HA cluster"],
			operationId: "promoteHaNode",
			parameters: [{ name: "nodeId", in: "path", required: true, schema: { type: "string" } }],
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["ok", "restarting"],
					properties: { ok: { type: "boolean", const: true }, restarting: { type: "boolean", const: true } },
				}),
				"400": errorResponse("Only the primary can promote a node, or the promotion failed."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
			},
		},
	},
	"/ha/nodes/{nodeId}": {
		delete: {
			summary: "Forget an offline HA cluster node",
			description:
				"Removes a node's record from the cluster membership (a request received on a replica is forwarded to the primary automatically). Intended for a node that is permanently gone - use POST .../ha/promote/{nodeId} instead if you want it replaced as primary.",
			tags: ["HA cluster"],
			operationId: "forgetHaNode",
			parameters: [{ name: "nodeId", in: "path", required: true, schema: { type: "string" } }],
			responses: {
				"200": jsonResponse("", { type: "object", required: ["ok"], properties: { ok: { type: "boolean", const: true } } }),
				"400": errorResponse("Unable to forget the node."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
			},
		},
	},
};

const hostPaths: Record<string, PathItemObject> = {
	"/host/current": {
		get: {
			summary: "Get the current host resource snapshot",
			description:
				"CPU, memory, disk, and network usage for the host (or container/cgroup) BurrowGate is running in, plus the latest outbound-connectivity check results.",
			tags: ["Host monitoring"],
			operationId: "getHostCurrent",
			responses: {
				"200": jsonResponse("", ref("HostSnapshot")),
				"401": errorResponse("Not signed in."),
			},
		},
	},
};

const logQueryOperation: OperationObject = {
	summary: "Query stored log entries",
	description:
		"Reads BurrowGate's own on-disk NDJSON log files (only entries within the still-uncompressed retention window are searchable). Returns one page of matching entries plus a per-bucket count series across the full range, for rendering a histogram.",
	tags: ["Logging"],
	operationId: "queryLogs",
	parameters: [
		{ name: "from", in: "query", required: true, description: "Unix milliseconds, range start.", schema: { type: "integer" } },
		{ name: "to", in: "query", required: true, description: "Unix milliseconds, range end. The range cannot exceed 366 days.", schema: { type: "integer" } },
		{ name: "search", in: "query", description: "Case-insensitive substring match against each entry's serialized JSON.", schema: { type: "string" } },
		{
			name: "level",
			in: "query",
			description: "Restrict to a single level. Omit (or leave blank) for every level.",
			schema: { type: "string", enum: ["error", "warn", "audit", "info", "http", "debug", "verbose", "silly"] },
		},
		{ name: "page", in: "query", description: "1-based. Default 1.", schema: { type: "integer", minimum: 1, maximum: 200 } },
		{ name: "pageSize", in: "query", description: "Default 50.", schema: { type: "integer", minimum: 10, maximum: 200 } },
	],
	responses: {
		"200": jsonResponse("", ref("LogQueryResult")),
		"400": errorResponse("Invalid or missing from/to, or a range exceeding 366 days."),
		"401": errorResponse("Not signed in."),
	},
};

const opsPathsSource: Record<string, PathItemObject> = {
	...haPaths,
	...hostPaths,
	"/logs/settings": {
		get: {
			summary: "Get file-logging settings",
			tags: ["Logging"],
			operationId: "getLogSettings",
			responses: {
				"200": jsonResponse("", {
					allOf: [ref("LogSettings")],
					type: "object",
					required: ["directory", "canManage"],
					properties: {
						directory: { type: "string", description: "Absolute path logs are written under." },
						canManage: { type: "boolean", description: "Whether the caller may change these settings (administrator only)." },
					},
				}),
				"401": errorResponse("Not signed in."),
			},
		},
		put: {
			summary: "Update file-logging settings",
			description: "Administrator only. Fields are merged onto the current settings; omitted fields keep their existing value.",
			tags: ["Logging"],
			operationId: "updateLogSettings",
			requestBody: jsonBody(ref("LogSettingsInput")),
			responses: {
				"200": jsonResponse("", ref("LogSettings")),
				"400": errorResponse("Invalid settings (e.g. compressAfterDays not less than retentionDays, or an out-of-range value)."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required."),
			},
		},
	},
	"/logs": { get: logQueryOperation },
	"/logs/archives": {
		get: {
			summary: "List compressed log archives",
			tags: ["Logging"],
			operationId: "listLogArchives",
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["items", "canManage"],
					properties: {
						items: { type: "array", items: ref("LogArchive") },
						canManage: { type: "boolean", description: "Whether the caller may delete archives (administrator only)." },
					},
				}),
				"401": errorResponse("Not signed in."),
			},
		},
	},
	"/logs/archives/{name}": {
		get: {
			summary: "Download a compressed log archive",
			description: "Returns the raw gzip file (`application/gzip`), not JSON.",
			tags: ["Logging"],
			operationId: "downloadLogArchive",
			parameters: [{ name: "name", in: "path", required: true, description: "Archive filename, e.g. 2026-08-30.txt.gz.", schema: { type: "string" } }],
			responses: {
				"200": gzipResponse("The gzip-compressed daily log file."),
				"401": errorResponse("Not signed in."),
				"404": errorResponse("No archive with this name."),
			},
		},
		delete: {
			summary: "Delete a compressed log archive",
			description: "Administrator only.",
			tags: ["Logging"],
			operationId: "deleteLogArchive",
			parameters: [{ name: "name", in: "path", required: true, schema: { type: "string" } }],
			responses: {
				"200": jsonResponse("", { type: "object", required: ["ok"], properties: { ok: { type: "boolean", const: true } } }),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required."),
				"404": errorResponse("No archive with this name."),
			},
		},
	},
};

export const opsPaths: Record<string, PathItemObject> = opsPathsSource;
