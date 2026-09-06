import { errorResponse, jsonBody, jsonResponse, ref, type ParameterObject, type PathItemObject } from "../types.ts";

const pendingChange = ref("PendingChange");

const DURABILITY_CONFIRMED = {
	durabilityConfirmed: { type: "boolean" as const, description: "True once a majority of HA replicas have durably persisted this change." },
};

const STREAM_ID_QUERY_PARAM: ParameterObject = {
	name: "streamId",
	in: "query",
	description:
		"Scope to a single stream. The caller must have at least viewer-level access to it (403 otherwise). Omitted scopes to every stream the caller can see.",
	schema: { type: "string" },
};

const REQUIRED_STREAM_ID_QUERY_PARAM: ParameterObject = { ...STREAM_ID_QUERY_PARAM, description: "The stream to operate on." };

const RANGE_PARAMS: readonly ParameterObject[] = [
	{
		name: "from",
		in: "query",
		description: "Range start, Unix milliseconds. Defaults to 24 hours before `to`, clamped to at least 60 seconds before it.",
		schema: { type: "integer" },
	},
	{ name: "to", in: "query", description: "Range end, Unix milliseconds. Defaults to now, capped at 5 minutes in the future.", schema: { type: "integer" } },
];

const SORT_DIRECTION_PARAM: ParameterObject = { name: "sortDirection", in: "query", schema: { type: "string", enum: ["asc", "desc"], default: "desc" } };

function pageParams(pageSizeDefault?: number): ParameterObject[] {
	return [
		{ name: "page", in: "query", schema: { type: "integer", minimum: 1, maximum: 1_000_000, default: 1 } },
		{
			name: "pageSize",
			in: "query",
			schema: { type: "integer", minimum: 10, maximum: 200, ...(pageSizeDefault ? { default: pageSizeDefault } : {}) },
		},
		{ name: "search", in: "query", schema: { type: "string" } },
	];
}

function rangeResponseProperties() {
	return {
		rangeFrom: { type: "integer" as const, description: "Unix milliseconds." },
		rangeTo: { type: "integer" as const, description: "Unix milliseconds." },
		rangeDurationMs: { type: "integer" as const },
	};
}

const pageResultRequired = ["items", "page", "pageSize", "total", "totalPages"] as const;

export const streamPaths: Record<string, PathItemObject> = {
	"/streams": {
		get: {
			summary: "List streams",
			description:
				"Returns every stream visible to the caller (administrators see all; other users see only streams they have been granted access to), plus catalog/default data the dashboard uses to render edit forms.",
			tags: ["Streams"],
			operationId: "listStreams",
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["items", "pendingChanges", "certificates", "statuses", "networkPrivacyCategories", "defaults"],
					properties: {
						items: { type: "array", items: ref("Stream") },
						pendingChanges: { type: "array", items: pendingChange },
						certificates: { type: "array", items: ref("StreamCertificateOption"), description: "Certificates available to assign to a stream's TLS listener." },
						statuses: { type: "array", items: ref("StreamRuntimeStatus") },
						networkPrivacyCategories: { type: "array", items: ref("NetworkPrivacyCategoryMeta") },
						defaults: {
							type: "object",
							required: ["retentionDays", "udpPeerIdleTimeoutSeconds"],
							properties: {
								retentionDays: { type: "integer", description: "The instance's default event-retention days, used to prefill new streams." },
								udpPeerIdleTimeoutSeconds: { type: "integer" },
							},
						},
					},
				}),
				"401": errorResponse("Not signed in."),
			},
		},
		post: {
			summary: "Create a stream",
			description: "Administrator only.",
			tags: ["Streams"],
			operationId: "createStream",
			requestBody: jsonBody(ref("StreamInput")),
			responses: {
				"201": jsonResponse("", {
					type: "object",
					required: ["stream", "statuses", "durabilityConfirmed"],
					properties: { stream: ref("Stream"), statuses: { type: "array", items: ref("StreamRuntimeStatus") }, ...DURABILITY_CONFIRMED },
				}),
				"400": errorResponse("Invalid input, or this protocol and incoming port are already assigned to another stream."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
			},
		},
	},
	"/streams/{id}": {
		put: {
			summary: "Update a stream",
			description:
				"Requires manager-level access to this stream. If the update changes a field that requires a listener restart (protocol toggle, port, forward host/port, certificate, or PROXY protocol) and an `effectiveAt` is supplied, that part of the change is scheduled instead of applied immediately - see `pendingChange` in the response. Only one change may be scheduled per stream at a time.",
			tags: ["Streams"],
			operationId: "updateStream",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			requestBody: jsonBody(ref("StreamInput")),
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["stream", "pendingChange", "statuses", "durabilityConfirmed"],
					properties: { stream: ref("Stream"), pendingChange, statuses: { type: "array", items: ref("StreamRuntimeStatus") }, ...DURABILITY_CONFIRMED },
				}),
				"400": errorResponse("Invalid input, a duplicate protocol/port, or a change was already scheduled for this stream."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (viewer-level access, or no access to this stream), or CSRF validation failed."),
				"404": errorResponse("Stream not found."),
			},
		},
		delete: {
			summary: "Delete a stream",
			description: "Administrator only. Stops the stream's listener and removes its events, bandwidth history, and network rules.",
			tags: ["Streams"],
			operationId: "deleteStream",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["deleted", "durabilityConfirmed"],
					properties: { deleted: { type: "boolean", const: true }, ...DURABILITY_CONFIRMED },
				}),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
				"404": errorResponse("Stream not found."),
			},
		},
	},
	"/streams/{id}/pending-change/apply-now": {
		post: {
			summary: "Apply a stream's scheduled change immediately",
			description: "Requires manager-level access to this stream.",
			tags: ["Streams"],
			operationId: "applyStreamPendingChangeNow",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["stream", "statuses"],
					properties: { stream: { oneOf: [{ type: "null" }, ref("Stream")] }, statuses: { type: "array", items: ref("StreamRuntimeStatus") } },
				}),
				"400": errorResponse("Unable to apply the pending change."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("No pending change for this stream."),
			},
		},
	},
	"/streams/{id}/pending-change": {
		delete: {
			summary: "Cancel a stream's scheduled change",
			description: "Requires manager-level access to this stream.",
			tags: ["Streams"],
			operationId: "cancelStreamPendingChange",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			responses: {
				"200": jsonResponse("", { type: "object", required: ["ok"], properties: { ok: { type: "boolean", const: true } } }),
				"400": errorResponse("Unable to cancel the pending change."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("No pending change for this stream."),
			},
		},
	},

	"/streams/active": {
		get: {
			summary: "List active stream connections",
			description: "Every currently-open TCP connection and UDP peer across streams visible to the caller.",
			tags: ["Streams"],
			operationId: "listActiveStreamConnections",
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["items", "statuses"],
					properties: { items: { type: "array", items: ref("StreamActiveConnection") }, statuses: { type: "array", items: ref("StreamRuntimeStatus") } },
				}),
				"401": errorResponse("Not signed in."),
			},
		},
	},

	"/streams/overview": {
		get: {
			summary: "Stream overview stats",
			description:
				"Aggregate connection/error/traffic counters and top countries/ASNs for the selected time range and stream scope, plus currently-active connections and GeoIP database status.",
			tags: ["Streams"],
			operationId: "getStreamsOverview",
			parameters: [STREAM_ID_QUERY_PARAM, ...RANGE_PARAMS],
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: [
						"connections",
						"disconnections",
						"errors",
						"blocked",
						"uniqueIps",
						"clientToUpstreamBytes",
						"upstreamToClientBytes",
						"countries",
						"asns",
						"active",
						"geoip",
						"rangeFrom",
						"rangeTo",
					],
					properties: {
						connections: { type: "integer" },
						disconnections: { type: "integer" },
						errors: { type: "integer" },
						blocked: { type: "integer" },
						uniqueIps: { type: "integer" },
						clientToUpstreamBytes: { type: "integer" },
						upstreamToClientBytes: { type: "integer" },
						countries: {
							type: "array",
							items: {
								type: "object",
								required: ["countryCode", "connections", "bytes", "blocked"],
								properties: { countryCode: { type: "string" }, connections: { type: "integer" }, bytes: { type: "integer" }, blocked: { type: "integer" } },
							},
						},
						asns: {
							type: "array",
							description: "Top 25 ASNs by connection count.",
							items: {
								type: "object",
								required: ["asn", "org", "connections", "blocked"],
								properties: { asn: { type: "integer" }, org: { type: "string" }, connections: { type: "integer" }, blocked: { type: "integer" } },
							},
						},
						active: { type: "array", items: ref("StreamActiveConnection") },
						geoip: ref("GeoIpStatus"),
						rangeFrom: { type: "integer", description: "Unix milliseconds." },
						rangeTo: { type: "integer", description: "Unix milliseconds." },
					},
				}),
				"400": errorResponse("The selected stream was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to the selected stream)."),
			},
		},
	},
	"/streams/metrics": {
		get: {
			summary: "Stream metrics time series",
			description:
				"The main metrics dashboard payload: a bucketed time series for the selected scope, a per-stream comparison, block-reason and protocol breakdowns, a long-lived-connection series, and an origin-latency/health series. The bucket size is chosen automatically from the selected range (60s up to 7 days).",
			tags: ["Streams"],
			operationId: "getStreamsMetrics",
			parameters: [STREAM_ID_QUERY_PARAM, ...RANGE_PARAMS],
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: [
						"series",
						"comparison",
						"blockReasons",
						"protocolBreakdown",
						"longLivedSeries",
						"healthSeries",
						"rangeFrom",
						"rangeTo",
						"rangeDurationMs",
						"bucketMs",
					],
					properties: {
						series: {
							type: "array",
							description: "The selected scope's own bucketed series.",
							items: {
								type: "object",
								required: ["bucket", "connected", "disconnected", "errors", "blocked", "clientToUpstreamBytes", "upstreamToClientBytes"],
								properties: {
									bucket: { type: "integer", description: "Unix milliseconds, start of the bucket." },
									connected: { type: "integer" },
									disconnected: { type: "integer" },
									errors: { type: "integer" },
									blocked: { type: "integer" },
									clientToUpstreamBytes: { type: "integer" },
									upstreamToClientBytes: { type: "integer" },
								},
							},
						},
						comparison: {
							type: "array",
							description: "Total connections/bytes per stream visible to the caller, for the same range (independent of the selected scope).",
							items: {
								type: "object",
								required: ["streamId", "connections", "bytes"],
								properties: { streamId: { type: "string" }, connections: { type: "integer" }, bytes: { type: "integer" } },
							},
						},
						blockReasons: {
							type: "array",
							description: "Top block reasons, most frequent first.",
							items: { type: "object", required: ["reason", "count"], properties: { reason: { type: "string" }, count: { type: "integer" } } },
						},
						protocolBreakdown: {
							type: "array",
							items: {
								type: "object",
								required: ["protocol", "connections", "bytes"],
								properties: { protocol: { type: "string", enum: ["tcp", "udp"] }, connections: { type: "integer" }, bytes: { type: "integer" } },
							},
						},
						longLivedSeries: {
							type: "array",
							description: `Bucketed counts of connections lasting at least 10 seconds. The current (still-open) bucket also folds in still-open connections that already exceed that threshold.`,
							items: {
								type: "object",
								required: ["bucket", "connected", "disconnected"],
								properties: { bucket: { type: "integer" }, connected: { type: "integer" }, disconnected: { type: "integer" } },
							},
						},
						healthSeries: {
							type: "array",
							description: "Bucketed origin health-check latency stats.",
							items: {
								type: "object",
								required: ["bucket", "minLatencyMs", "maxLatencyMs", "avgLatencyMs", "totalCount", "timeoutCount", "timeoutPct"],
								properties: {
									bucket: { type: "integer" },
									minLatencyMs: { type: ["number", "null"] },
									maxLatencyMs: { type: ["number", "null"] },
									avgLatencyMs: { type: ["number", "null"] },
									totalCount: { type: "integer" },
									timeoutCount: { type: "integer" },
									timeoutPct: { type: "number" },
								},
							},
						},
						rangeFrom: { type: "integer" },
						rangeTo: { type: "integer" },
						rangeDurationMs: { type: "integer" },
						bucketMs: { type: "integer", description: "The bucket size chosen for this response, one of 60s/5m/15m/30m/1h/2h/3h/6h/12h/1d/2d/4d/7d." },
					},
				}),
				"400": errorResponse("The selected stream was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to the selected stream)."),
			},
		},
	},
	"/streams/ip-metrics-tab": {
		get: {
			summary: "Top blocked IPs for the metrics dashboard",
			tags: ["Streams"],
			operationId: "getStreamsIpMetricsTab",
			parameters: [
				{
					name: "scope",
					in: "query",
					required: true,
					description: "Must be `blocked` - the only supported value.",
					schema: { type: "string", const: "blocked" },
				},
				STREAM_ID_QUERY_PARAM,
				...RANGE_PARAMS,
			],
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["rangeFrom", "rangeTo", "rangeDurationMs", "ips"],
					properties: {
						...rangeResponseProperties(),
						ips: { type: "array", items: { type: "object", required: ["ip", "count"], properties: { ip: { type: "string" }, count: { type: "integer" } } } },
					},
				}),
				"400": errorResponse("Invalid scope (must be `blocked`), or the selected stream was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to the selected stream)."),
			},
		},
	},
	"/streams/ip-bandwidth-metrics-tab": {
		get: {
			summary: "Top IPs by bandwidth for the metrics dashboard",
			tags: ["Streams"],
			operationId: "getStreamsIpBandwidthMetricsTab",
			parameters: [STREAM_ID_QUERY_PARAM, ...RANGE_PARAMS],
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["rangeFrom", "rangeTo", "rangeDurationMs", "ips"],
					properties: {
						...rangeResponseProperties(),
						ips: {
							type: "array",
							items: {
								type: "object",
								required: ["ip", "count"],
								properties: { ip: { type: "string" }, count: { type: "integer", description: "Total bytes transferred (despite the field name)." } },
							},
						},
					},
				}),
				"400": errorResponse("The selected stream was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to the selected stream)."),
			},
		},
	},
	"/streams/error-metrics-tab": {
		get: {
			summary: "Top error reasons for the metrics dashboard",
			tags: ["Streams"],
			operationId: "getStreamsErrorMetricsTab",
			parameters: [STREAM_ID_QUERY_PARAM, ...RANGE_PARAMS],
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["rangeFrom", "rangeTo", "rangeDurationMs", "errors"],
					properties: {
						...rangeResponseProperties(),
						errors: {
							type: "array",
							items: { type: "object", required: ["error", "count"], properties: { error: { type: "string" }, count: { type: "integer" } } },
						},
					},
				}),
				"400": errorResponse("The selected stream was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to the selected stream)."),
			},
		},
	},

	"/streams/events": {
		get: {
			summary: "Paged stream connection events",
			tags: ["Streams"],
			operationId: "listStreamEvents",
			parameters: [
				STREAM_ID_QUERY_PARAM,
				...pageParams(),
				{ name: "protocol", in: "query", schema: { type: "string", enum: ["tcp", "udp"] } },
				{
					name: "eventType",
					in: "query",
					schema: { type: "string", enum: ["connected", "disconnected", "upstream-error", "listener-error", "blocked", "throttled", "monitored"] },
				},
				{ name: "country", in: "query", description: "Two-letter country code, case-insensitive.", schema: { type: "string" } },
				{ name: "asn", in: "query", schema: { type: "integer", minimum: 1 } },
				{
					name: "sortBy",
					in: "query",
					schema: {
						type: "string",
						enum: [
							"created_at",
							"event_type",
							"protocol",
							"incoming_port",
							"client_ip",
							"country_code",
							"asn",
							"reason",
							"protection_rule_id",
							"connection_id",
							"client_to_upstream_bytes",
							"upstream_to_client_bytes",
						],
						default: "created_at",
					},
				},
				SORT_DIRECTION_PARAM,
				...RANGE_PARAMS,
			],
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: [...pageResultRequired],
					properties: {
						items: { type: "array", items: ref("StreamEventRecord") },
						page: { type: "integer" },
						pageSize: { type: "integer" },
						total: { type: "integer" },
						totalPages: { type: "integer" },
					},
				}),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to the selected stream)."),
				"404": errorResponse("The selected stream was not found."),
			},
		},
	},
	"/streams/bandwidth": {
		get: {
			summary: "Paged per-IP bandwidth usage",
			tags: ["Streams"],
			operationId: "listStreamBandwidth",
			parameters: [
				STREAM_ID_QUERY_PARAM,
				...pageParams(),
				{ name: "protocol", in: "query", schema: { type: "string", enum: ["tcp", "udp"] } },
				{ name: "country", in: "query", description: "Two-letter country code, case-insensitive.", schema: { type: "string" } },
				{
					name: "sortBy",
					in: "query",
					schema: {
						type: "string",
						enum: ["protocol", "incoming_port", "ip", "country_code", "client_to_upstream_bytes", "upstream_to_client_bytes", "total_bytes"],
						default: "total_bytes",
					},
				},
				SORT_DIRECTION_PARAM,
				...RANGE_PARAMS,
			],
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: [...pageResultRequired],
					properties: {
						items: { type: "array", items: ref("StreamBandwidthRow") },
						page: { type: "integer" },
						pageSize: { type: "integer" },
						total: { type: "integer" },
						totalPages: { type: "integer" },
					},
				}),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to the selected stream)."),
				"404": errorResponse("The selected stream was not found."),
			},
		},
	},

	"/streams/network-policy": {
		get: {
			summary: "Get a stream's default network policy",
			description: "Requires a stream to be selected via `streamId`.",
			tags: ["Streams"],
			operationId: "getStreamNetworkPolicy",
			parameters: [REQUIRED_STREAM_ID_QUERY_PARAM],
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["defaultIpAction", "defaultCountryAction", "networkPrivacyPolicy", "countryRules", "asnRules", "geoip"],
					properties: {
						defaultIpAction: { type: "string", enum: ["inherit", "allow", "block"] },
						defaultCountryAction: { type: "string", enum: ["inherit", "allow", "block"] },
						networkPrivacyPolicy: ref("NetworkPrivacyPolicy"),
						countryRules: { type: "array", items: ref("StreamCountryRuleRecord") },
						asnRules: { type: "array", items: ref("StreamAsnRuleRecord") },
						geoip: ref("GeoIpStatus"),
					},
				}),
				"400": errorResponse("No stream selected (streamId is required)."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to the selected stream)."),
				"404": errorResponse("The selected stream was not found."),
			},
		},
		put: {
			summary: "Update a stream's default network policy",
			description: "Requires manager-level access to this stream.",
			tags: ["Streams"],
			operationId: "updateStreamNetworkPolicy",
			parameters: [REQUIRED_STREAM_ID_QUERY_PARAM],
			requestBody: jsonBody({
				type: "object",
				description: "All fields optional; omitted fields keep their current value.",
				properties: {
					defaultIpAction: { type: "string", enum: ["inherit", "allow", "block"] },
					defaultCountryAction: { type: "string", enum: ["inherit", "allow", "block"] },
					networkPrivacyPolicy: ref("NetworkPrivacyPolicy"),
				},
			}),
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["defaultIpAction", "defaultCountryAction", "networkPrivacyPolicy", "durabilityConfirmed"],
					properties: {
						defaultIpAction: { type: "string", enum: ["inherit", "allow", "block"] },
						defaultCountryAction: { type: "string", enum: ["inherit", "allow", "block"] },
						networkPrivacyPolicy: ref("NetworkPrivacyPolicy"),
						...DURABILITY_CONFIRMED,
					},
				}),
				"400": errorResponse("Invalid input, or no stream selected."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (viewer-level access, or no access to this stream), or CSRF validation failed."),
				"404": errorResponse("The selected stream was not found."),
			},
		},
	},
	"/streams/country-rules": {
		post: {
			summary: "Add a country rule to a stream",
			description: "Requires manager-level access to this stream. Fails if an active rule for this country code already exists on the stream.",
			tags: ["Streams"],
			operationId: "createStreamCountryRule",
			parameters: [REQUIRED_STREAM_ID_QUERY_PARAM],
			requestBody: jsonBody({
				type: "object",
				required: ["countryCode", "action"],
				properties: {
					countryCode: { type: "string", minLength: 2, maxLength: 2 },
					action: { type: "string", enum: ["allow", "block"] },
					reason: { type: "string" },
					expiresAt: { type: ["integer", "string", "null"], description: "Unix milliseconds in the future, or null/omitted for no expiry." },
				},
			}),
			responses: {
				"201": jsonResponse("", {
					allOf: [ref("StreamCountryRuleRecord")],
					type: "object",
					required: ["durabilityConfirmed"],
					properties: DURABILITY_CONFIRMED,
				}),
				"400": errorResponse("Invalid country rule, an active rule for this country already exists, or no stream selected."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (viewer-level access, or no access to this stream), or CSRF validation failed."),
			},
		},
	},
	"/streams/country-rules/{id}": {
		delete: {
			summary: "Delete a stream's country rule",
			description: "Requires manager-level access to this stream.",
			tags: ["Streams"],
			operationId: "deleteStreamCountryRule",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }, REQUIRED_STREAM_ID_QUERY_PARAM],
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["deleted", "durabilityConfirmed"],
					properties: { deleted: { type: "boolean", const: true }, ...DURABILITY_CONFIRMED },
				}),
				"400": errorResponse("No stream selected."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (viewer-level access, or no access to this stream), or CSRF validation failed."),
			},
		},
	},
	"/streams/asn-rules": {
		post: {
			summary: "Add an ASN rule to a stream",
			description: "Requires manager-level access to this stream. Fails if an active rule for this ASN already exists on the stream.",
			tags: ["Streams"],
			operationId: "createStreamAsnRule",
			parameters: [REQUIRED_STREAM_ID_QUERY_PARAM],
			requestBody: jsonBody({
				type: "object",
				required: ["asn", "action"],
				properties: {
					asn: { type: ["integer", "string"], description: "A positive whole number." },
					action: { type: "string", enum: ["allow", "block"] },
					reason: { type: "string" },
					expiresAt: { type: ["integer", "string", "null"], description: "Unix milliseconds in the future, or null/omitted for no expiry." },
				},
			}),
			responses: {
				"201": jsonResponse("", { allOf: [ref("StreamAsnRuleRecord")], type: "object", required: ["durabilityConfirmed"], properties: DURABILITY_CONFIRMED }),
				"400": errorResponse("Invalid ASN rule, an active rule for this ASN already exists, or no stream selected."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (viewer-level access, or no access to this stream), or CSRF validation failed."),
			},
		},
	},
	"/streams/asn-rules/{id}": {
		delete: {
			summary: "Delete a stream's ASN rule",
			description: "Requires manager-level access to this stream.",
			tags: ["Streams"],
			operationId: "deleteStreamAsnRule",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }, REQUIRED_STREAM_ID_QUERY_PARAM],
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["deleted", "durabilityConfirmed"],
					properties: { deleted: { type: "boolean", const: true }, ...DURABILITY_CONFIRMED },
				}),
				"400": errorResponse("No stream selected."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (viewer-level access, or no access to this stream), or CSRF validation failed."),
			},
		},
	},
	"/streams/ip-rules": {
		get: {
			summary: "List a stream's IP rules",
			description: "Requires viewer-level access to this stream (implied by having selected it). Returns an empty page if no stream is selected.",
			tags: ["Streams"],
			operationId: "listStreamIpRules",
			parameters: [
				STREAM_ID_QUERY_PARAM,
				...pageParams(),
				{ name: "action", in: "query", schema: { type: "string", enum: ["allow", "block"] } },
				{ name: "state", in: "query", schema: { type: "string", enum: ["active", "expired"] } },
				{ name: "sortBy", in: "query", schema: { type: "string", enum: ["created_at", "expires_at", "network_cidr", "action"], default: "created_at" } },
				SORT_DIRECTION_PARAM,
			],
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: [...pageResultRequired],
					properties: {
						items: { type: "array", items: ref("StreamIpRuleRecord") },
						page: { type: "integer" },
						pageSize: { type: "integer" },
						total: { type: "integer" },
						totalPages: { type: "integer" },
					},
				}),
				"401": errorResponse("Not signed in."),
			},
		},
		post: {
			summary: "Add an IP rule to a stream",
			description: "Requires manager-level access to this stream.",
			tags: ["Streams"],
			operationId: "createStreamIpRule",
			parameters: [REQUIRED_STREAM_ID_QUERY_PARAM],
			requestBody: jsonBody({
				type: "object",
				required: ["networkCidr", "action"],
				properties: {
					networkCidr: { type: "string", description: "A single IP address or CIDR range." },
					action: { type: "string", enum: ["allow", "block"] },
					reason: { type: "string" },
					expiresAt: { type: ["integer", "string", "null"], description: "Unix milliseconds in the future, or null/omitted for no expiry." },
				},
			}),
			responses: {
				"201": jsonResponse("", { allOf: [ref("StreamIpRuleRecord")], type: "object", required: ["durabilityConfirmed"], properties: DURABILITY_CONFIRMED }),
				"400": errorResponse("Invalid rule, or no stream selected."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (viewer-level access, or no access to this stream), or CSRF validation failed."),
			},
		},
	},
	"/streams/ip-rules/{id}": {
		delete: {
			summary: "Delete a stream's IP rule",
			description: "Requires manager-level access to this stream.",
			tags: ["Streams"],
			operationId: "deleteStreamIpRule",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }, REQUIRED_STREAM_ID_QUERY_PARAM],
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["deleted", "durabilityConfirmed"],
					properties: { deleted: { type: "boolean", const: true }, ...DURABILITY_CONFIRMED },
				}),
				"400": errorResponse("No stream selected."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (viewer-level access, or no access to this stream), or CSRF validation failed."),
			},
		},
	},
	"/streams/ip-rules/bulk-delete": {
		post: {
			summary: "Delete multiple IP rules from a stream",
			description:
				"Requires manager-level access to this stream. Accepts 1 to 200 rule IDs; IDs that don't belong to the selected stream are silently ignored.",
			tags: ["Streams"],
			operationId: "bulkDeleteStreamIpRules",
			parameters: [REQUIRED_STREAM_ID_QUERY_PARAM],
			requestBody: jsonBody({
				type: "object",
				required: ["ids"],
				properties: { ids: { type: "array", minItems: 1, maxItems: 200, items: { type: "string" } } },
			}),
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["deleted", "durabilityConfirmed"],
					properties: { deleted: { type: "integer", description: "Number of rules actually deleted." }, ...DURABILITY_CONFIRMED },
				}),
				"400": errorResponse("Must provide 1 to 200 rule IDs, or no stream selected."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (viewer-level access, or no access to this stream), or CSRF validation failed."),
			},
		},
	},

	"/streams/protection-catalog": {
		get: {
			summary: "List the stream protection ruleset catalog",
			description: "Every registered stream-protection ruleset, available to enable via a stream's protection policy.",
			tags: ["Streams"],
			operationId: "getStreamProtectionCatalog",
			responses: {
				"200": jsonResponse("", { type: "object", required: ["items"], properties: { items: { type: "array", items: ref("StreamRuleSetCatalogEntry") } } }),
				"401": errorResponse("Not signed in."),
			},
		},
	},
	"/streams/protection-policy": {
		get: {
			summary: "Get a stream's protection policy",
			description: "Requires a stream to be selected via `streamId`.",
			tags: ["Streams"],
			operationId: "getStreamProtectionPolicy",
			parameters: [REQUIRED_STREAM_ID_QUERY_PARAM],
			responses: {
				"200": jsonResponse("", ref("StreamProtectionPolicy")),
				"400": errorResponse("No stream selected."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to the selected stream)."),
			},
		},
		put: {
			summary: "Update a stream's protection policy",
			description: "Requires manager-level access to this stream.",
			tags: ["Streams"],
			operationId: "updateStreamProtectionPolicy",
			parameters: [REQUIRED_STREAM_ID_QUERY_PARAM],
			requestBody: jsonBody(ref("StreamProtectionPolicyInput")),
			responses: {
				"200": jsonResponse("", {
					allOf: [ref("StreamProtectionPolicy")],
					type: "object",
					required: ["durabilityConfirmed"],
					properties: DURABILITY_CONFIRMED,
				}),
				"400": errorResponse("Invalid input, or no stream selected."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (viewer-level access, or no access to this stream), or CSRF validation failed."),
			},
		},
	},

	"/streams/bandwidth-limit-policy": {
		get: {
			summary: "Get a stream's bandwidth-limit policy",
			description: "Requires a stream to be selected via `streamId`.",
			tags: ["Streams"],
			operationId: "getStreamBandwidthLimitPolicy",
			parameters: [REQUIRED_STREAM_ID_QUERY_PARAM],
			responses: {
				"200": jsonResponse("", ref("StreamBandwidthPolicy")),
				"400": errorResponse("No stream selected."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to the selected stream)."),
			},
		},
		put: {
			summary: "Update a stream's bandwidth-limit policy",
			description: "Requires manager-level access to this stream.",
			tags: ["Streams"],
			operationId: "updateStreamBandwidthLimitPolicy",
			parameters: [REQUIRED_STREAM_ID_QUERY_PARAM],
			requestBody: jsonBody(ref("StreamBandwidthPolicyInput")),
			responses: {
				"200": jsonResponse("", { allOf: [ref("StreamBandwidthPolicy")], type: "object", required: ["durabilityConfirmed"], properties: DURABILITY_CONFIRMED }),
				"400": errorResponse("Invalid input, or no stream selected."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (viewer-level access, or no access to this stream), or CSRF validation failed."),
			},
		},
	},

	"/streams/notification-policy": {
		get: {
			summary: "Get a stream's notification policy",
			description: "Requires a stream to be selected via `streamId`. The webhook URL/secret are never returned - only whether one is configured.",
			tags: ["Streams"],
			operationId: "getStreamNotificationPolicy",
			parameters: [REQUIRED_STREAM_ID_QUERY_PARAM],
			responses: {
				"200": jsonResponse("", ref("StreamNotificationPolicy")),
				"400": errorResponse("No stream selected."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to the selected stream)."),
			},
		},
		put: {
			summary: "Update a stream's notification policy",
			description: "Requires manager-level access to this stream. A webhook URL is required (on this or a prior update) if enabled is set to true.",
			tags: ["Streams"],
			operationId: "updateStreamNotificationPolicy",
			parameters: [REQUIRED_STREAM_ID_QUERY_PARAM],
			requestBody: jsonBody(ref("StreamNotificationPolicyInput")),
			responses: {
				"200": jsonResponse("", ref("StreamNotificationPolicy")),
				"400": errorResponse("Invalid input, a webhook URL is required when enabling notifications, or no stream selected."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (viewer-level access, or no access to this stream), or CSRF validation failed."),
			},
		},
	},
	"/streams/notifications": {
		get: {
			summary: "Paged stream notification outbox",
			description: "Requires a stream to be selected via `streamId`.",
			tags: ["Streams"],
			operationId: "listStreamNotifications",
			parameters: [
				REQUIRED_STREAM_ID_QUERY_PARAM,
				...pageParams(25),
				{
					name: "type",
					in: "query",
					schema: {
						type: "string",
						enum: [
							"origin_unhealthy",
							"origin_recovered",
							"pool_unhealthy",
							"pool_recovered",
							"internet_down",
							"internet_up",
							"ip_banned",
							"stream_origin_unhealthy",
							"stream_origin_recovered",
							"stream_ip_banned",
						],
					},
				},
				{ name: "status", in: "query", schema: { type: "string", enum: ["pending", "delivered", "failed"] } },
				{ name: "sortBy", in: "query", schema: { type: "string", enum: ["created_at", "occurred_at", "type", "status"], default: "created_at" } },
				SORT_DIRECTION_PARAM,
			],
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: [...pageResultRequired],
					properties: {
						items: { type: "array", items: ref("StreamNotificationRecord") },
						page: { type: "integer" },
						pageSize: { type: "integer" },
						total: { type: "integer" },
						totalPages: { type: "integer" },
					},
				}),
				"400": errorResponse("No stream selected."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to the selected stream)."),
			},
		},
	},
};
