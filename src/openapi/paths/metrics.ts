import { errorResponse, jsonBody, jsonResponse, ref, type JsonSchema, type ParameterObject, type PathItemObject, type RequestBodyObject } from "../types.ts";

const site = ref("Site");
const rangeParams: readonly ParameterObject[] = [
	{ name: "from", in: "query", description: "Unix milliseconds. Defaults to `to` minus 24 hours.", schema: { type: "integer" } },
	{ name: "to", in: "query", description: "Unix milliseconds. Defaults to now.", schema: { type: "integer" } },
];
const siteIdParam = (description: string): ParameterObject => ({ name: "siteId", in: "query", description, schema: { type: "string" } });
const pageParams: readonly ParameterObject[] = [
	{ name: "page", in: "query", schema: { type: "integer", minimum: 1, default: 1 } },
	{
		name: "pageSize",
		in: "query",
		description: "10-200. Defaults to the instance's configured admin page size.",
		schema: { type: "integer", minimum: 10, maximum: 200 },
	},
	{ name: "sortDirection", in: "query", schema: { type: "string", enum: ["asc", "desc"], default: "desc" } },
];
const rangeEnvelope = { rangeFrom: { type: "integer" }, rangeTo: { type: "integer" }, rangeDurationMs: { type: "integer" } } as const;

const tabResponse = (itemsKey: string, itemsSchema: JsonSchema, extra?: Record<string, JsonSchema>): JsonSchema => ({
	type: "object",
	required: ["rangeFrom", "rangeTo", "rangeDurationMs", itemsKey],
	properties: { ...rangeEnvelope, site: { oneOf: [{ type: "null" }, site] }, ...extra, [itemsKey]: itemsSchema },
});

const paged = (itemsSchema: JsonSchema): JsonSchema => ({
	allOf: [ref("MetricsPageEnvelope")],
	type: "object",
	required: ["items"],
	properties: { items: { type: "array", items: itemsSchema } },
});

export const metricsPaths: Record<string, PathItemObject> = {
	"/geo-metrics-tab": {
		get: {
			summary: "Top countries for a metrics tab",
			tags: ["Metrics"],
			operationId: "geoMetricsTab",
			parameters: [
				siteIdParam("Omit to scope to every site the caller can view."),
				{
					name: "scope",
					in: "query",
					required: true,
					description: "Which subset of activity to aggregate.",
					schema: { type: "string", enum: ["requests", "blocked", "protection", "cache", "access", "routes", "sites", "bandwidth", "sessions"] },
				},
				...rangeParams,
			],
			responses: {
				"200": jsonResponse(
					"`site` is omitted when scope=sites (the result spans every site the caller can view).",
					tabResponse("items", { type: "array", items: ref("GeoMetricRow") }, { status: ref("GeoIpStatus") }),
				),
				"400": errorResponse("Missing or invalid scope, or the selected site was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to the selected site)."),
			},
		},
	},
	"/asn-metrics-tab": {
		get: {
			summary: "Top ASNs for a metrics tab",
			tags: ["Metrics"],
			operationId: "asnMetricsTab",
			parameters: [
				siteIdParam("Omit to scope to every site the caller can view."),
				{
					name: "scope",
					in: "query",
					required: true,
					description: "Which subset of activity to aggregate. Unlike geo-metrics-tab, `bandwidth` is not a valid scope here.",
					schema: { type: "string", enum: ["requests", "blocked", "protection", "cache", "access", "routes", "sites", "sessions"] },
				},
				...rangeParams,
			],
			responses: {
				"200": jsonResponse(
					"`site` is omitted when scope=sites.",
					tabResponse("items", { type: "array", items: ref("AsnMetricRow") }, { status: ref("GeoIpStatus") }),
				),
				"400": errorResponse("Missing or invalid scope, or the selected site was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to the selected site)."),
			},
		},
	},
	"/referer-metrics-tab": {
		get: {
			summary: "Top referrer hosts for a metrics tab",
			tags: ["Metrics"],
			operationId: "refererMetricsTab",
			parameters: [
				siteIdParam("Omit to scope to every site the caller can view."),
				{
					name: "scope",
					in: "query",
					required: true,
					description: "Which subset of activity to aggregate. `access`, `bandwidth`, and `sessions` are not valid scopes here.",
					schema: { type: "string", enum: ["requests", "blocked", "protection", "cache", "routes", "sites"] },
				},
				...rangeParams,
			],
			responses: {
				"200": jsonResponse(
					"`site` is omitted when scope=sites. Unlike the other metrics tabs, there is no `status` (GeoIP) field here.",
					tabResponse("referrers", { type: "array", items: ref("RefererMetricRow") }),
				),
				"400": errorResponse("Missing or invalid scope, or the selected site was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to the selected site)."),
			},
		},
	},
	"/bot-metrics-tab": {
		get: {
			summary: "Identified bot catalogue metrics",
			description:
				"Returns the complete known bot catalogue, with count=0 for bots that had no requests in the selected range; observed legacy IDs are retained. " +
				"Unlike the other metrics tabs, this endpoint has no `scope` parameter and always includes `site` (null when no site is selected).",
			tags: ["Metrics"],
			operationId: "botMetricsTab",
			parameters: [siteIdParam("Omit to scope to every site the caller can view."), ...rangeParams],
			responses: {
				"200": jsonResponse("", tabResponse("bots", { type: "array", items: ref("BotMetricRow") })),
				"400": errorResponse("The selected site was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to the selected site)."),
			},
		},
	},
	"/ip-metrics-tab": {
		get: {
			summary: "Top client IPs for a metrics tab",
			tags: ["Metrics"],
			operationId: "ipMetricsTab",
			parameters: [
				siteIdParam("Omit to scope to every site the caller can view."),
				{ name: "scope", in: "query", required: true, schema: { type: "string", enum: ["blocked", "routes"] } },
				...rangeParams,
			],
			responses: {
				"200": jsonResponse("", tabResponse("ips", { type: "array", items: ref("IpMetricRow") })),
				"400": errorResponse("Missing or invalid scope, or the selected site was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to the selected site)."),
			},
		},
	},
	"/ip-bandwidth-metrics-tab": {
		get: {
			summary: "Top client IPs by bandwidth for a metrics tab",
			description: "No `scope` parameter; always ranks by total client bandwidth (download + upload).",
			tags: ["Metrics"],
			operationId: "ipBandwidthMetricsTab",
			parameters: [siteIdParam("Omit to scope to every site the caller can view."), ...rangeParams],
			responses: {
				"200": jsonResponse("", tabResponse("ips", { type: "array", items: ref("IpMetricRow") })),
				"400": errorResponse("The selected site was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to the selected site)."),
			},
		},
	},
	"/path-metrics-tab": {
		get: {
			summary: "Top request paths for a metrics tab",
			tags: ["Metrics"],
			operationId: "pathMetricsTab",
			parameters: [
				siteIdParam("Omit to scope to every site the caller can view."),
				{ name: "scope", in: "query", required: true, schema: { type: "string", enum: ["protection", "requests"] } },
				...rangeParams,
			],
			responses: {
				"200": jsonResponse("", tabResponse("paths", { type: "array", items: ref("PathMetricRow") })),
				"400": errorResponse("Missing or invalid scope, or the selected site was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to the selected site)."),
			},
		},
	},
	"/access-username-metrics": {
		get: {
			summary: "Top access-list usernames by login activity",
			description: "No `scope` parameter. Counts access-list login/authentication decisions (login-required, login-failed, login-rate-limited, authenticated).",
			tags: ["Metrics"],
			operationId: "accessUsernameMetrics",
			parameters: [siteIdParam("Omit to scope to every site the caller can view."), ...rangeParams],
			responses: {
				"200": jsonResponse("", tabResponse("usernames", { type: "array", items: ref("UsernameMetricRow") })),
				"400": errorResponse("The selected site was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to the selected site)."),
			},
		},
	},
	"/session-username-metrics": {
		get: {
			summary: "Top access-list usernames by session count",
			description: "No `scope` parameter. Counts visitor sessions grouped by their access user's username (`(anonymous)` for sessions with none).",
			tags: ["Metrics"],
			operationId: "sessionUsernameMetrics",
			parameters: [siteIdParam("Omit to scope to every site the caller can view."), ...rangeParams],
			responses: {
				"200": jsonResponse("", tabResponse("usernames", { type: "array", items: ref("UsernameMetricRow") })),
				"400": errorResponse("The selected site was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to the selected site)."),
			},
		},
	},

	"/overview": {
		get: {
			summary: "Dashboard overview counters",
			tags: ["Metrics"],
			operationId: "adminOverview",
			parameters: [siteIdParam("Omit to scope to every site the caller can view."), ...rangeParams],
			responses: {
				"200": jsonResponse("", {
					allOf: [ref("MetricsOverview")],
					type: "object",
					required: ["retentionDays", "defaultPageSize", "site", "originHealth"],
					properties: {
						retentionDays: { type: "integer", description: "The selected site's event-retention setting, or the instance default when no site is selected." },
						defaultPageSize: { type: "integer" },
						site: { oneOf: [{ type: "null" }, site] },
						originHealth: {
							type: ["object", "null"],
							additionalProperties: true,
							description: "Live origin-pool health summary for the selected site; null when no site is selected.",
						},
					},
				}),
				"400": errorResponse("The selected site was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to the selected site)."),
			},
		},
	},
	"/update-status": {
		get: {
			summary: "Get the latest checked-for-updates status",
			description: "Reflects the instance's own periodic background check; does not perform a new check itself.",
			tags: ["Metrics"],
			operationId: "updateStatus",
			responses: {
				"200": jsonResponse("", ref("UpdateCheckStatus")),
				"401": errorResponse("Not signed in."),
			},
		},
	},

	"/metrics": {
		get: {
			summary: "Chart data for one dashboard metrics section",
			description:
				"section=sites requires administrator access. section=connectivity, sites, system-cpu, system-memory, system-disk, system-network-download, " +
				"and system-network-upload are instance-wide and ignore `siteId`; every other section is scoped by `siteId` (or every site the caller can " +
				"view, if omitted). For section=bots, the response includes the complete known bot catalogue and zero-filled totals and series for bots with no " +
				"requests in the selected range. For section=sites, every configured site is returned with zero-filled series where necessary; the dashboard may " +
				"condense that complete data for display. See MetricsChartResponse for exactly which fields are common to every section versus section-specific.",
			tags: ["Metrics"],
			operationId: "adminMetrics",
			parameters: [
				siteIdParam("Ignored for instance-wide sections. Omit to scope to every site the caller can view."),
				{
					name: "section",
					in: "query",
					description: "Defaults to traffic.",
					schema: {
						type: "string",
						default: "traffic",
						enum: [
							"traffic",
							"bandwidth",
							"cache",
							"protection",
							"bots",
							"sessions",
							"rules",
							"routes",
							"access",
							"sites",
							"connectivity",
							"health",
							"system-cpu",
							"system-memory",
							"system-disk",
							"system-network-download",
							"system-network-upload",
						],
					},
				},
				...rangeParams,
			],
			responses: {
				"200": jsonResponse("", ref("MetricsChartResponse")),
				"400": errorResponse("The selected site was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("section=sites was requested by a non-administrator, or no access to the selected site."),
			},
		},
	},

	"/events": {
		get: {
			summary: "List captured request events",
			description: "Rich filterable, sortable, paged event log. All filters are optional and combine with AND.",
			tags: ["Events"],
			operationId: "listEvents",
			parameters: [
				siteIdParam("Omit to scope to every site the caller can view."),
				...rangeParams,
				...pageParams,
				{ name: "search", in: "query", description: "Free-text match against IP, path, and similar fields.", schema: { type: "string" } },
				{ name: "decision", in: "query", description: "Exact decision label, e.g. verified, blocked, route-blocked.", schema: { type: "string" } },
				{ name: "cache", in: "query", schema: { type: "string", enum: ["hit", "miss", "bypass"] } },
				{ name: "protection", in: "query", schema: { type: "string", enum: ["clean", "monitored", "blocked"] } },
				{ name: "origin", in: "query", description: "Origin ID.", schema: { type: "string" } },
				{ name: "method", in: "query", schema: { type: "string" } },
				{ name: "status", in: "query", description: "HTTP status class.", schema: { type: "string", enum: ["1xx", "2xx", "3xx", "4xx", "5xx"] } },
				{ name: "country", in: "query", description: "Two-letter country code (case-insensitive).", schema: { type: "string", minLength: 2, maxLength: 2 } },
				{ name: "asn", in: "query", schema: { type: "integer", minimum: 1 } },
				{
					name: "sortBy",
					in: "query",
					schema: {
						type: "string",
						default: "created_at",
						enum: ["created_at", "ip", "country_code", "asn", "method", "path", "status", "decision", "cache_status", "protection_status", "latency_ms"],
					},
				},
			],
			responses: {
				"200": jsonResponse(
					"`items[].origin_name` is resolved server-side; `origins` lists every origin of the selected site (id/name only), or is empty when no site is selected.",
					{
						allOf: [ref("MetricsPageEnvelope")],
						type: "object",
						required: ["items", "origins"],
						properties: {
							items: { type: "array", items: ref("RequestEvent") },
							origins: { type: "array", items: { type: "object", required: ["id", "name"], properties: { id: { type: "string" }, name: { type: "string" } } } },
						},
					},
				),
				"400": errorResponse("The selected site was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to the selected site)."),
			},
		},
	},
	"/events/{id}": {
		get: {
			summary: "Get a single captured request event",
			tags: ["Events"],
			operationId: "getEvent",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			responses: {
				"200": jsonResponse("", ref("RequestEvent")),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to this event's site)."),
				"404": errorResponse("Event not found."),
			},
		},
	},
	"/events/{id}/resend": {
		post: {
			summary: "Resend a captured request to its site",
			description:
				"Replays the captured request against the site's own public hostname (not the origin directly), following same-site redirects up to " +
				"10 hops. Requires manager-level access to the event's site. Redacted headers (from header capture with redaction enabled) are dropped " +
				"unless overridden in the request body.",
			tags: ["Events"],
			operationId: "resendEvent",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			requestBody: {
				required: false,
				description: "Both fields are optional; omitted headers/body are replayed as originally captured. A missing or unparsable body is treated as {}.",
				content: {
					"application/json": {
						schema: {
							type: "object",
							properties: {
								headers: {
									type: "object",
									additionalProperties: { type: "string" },
									description: "Overrides merged onto the captured request headers, by lower-cased name.",
								},
								body: { type: "string", description: "Overrides the captured request body. Ignored for GET/HEAD." },
							},
						},
					},
				},
			} satisfies RequestBodyObject,
			responses: {
				"200": jsonResponse("", ref("ResendResult")),
				"400": errorResponse("Invalid request body, or the resend otherwise failed for a reason other than reaching the target."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("Event not found."),
				"502": errorResponse(
					"The resend request could not reach the site (see ResendTargetError in src/services/resend-service.ts) - for example, neither HTTP nor HTTPS is enabled.",
				),
			},
		},
	},

	"/bandwidth": {
		get: {
			summary: "Paged bandwidth usage by client IP",
			tags: ["Bandwidth"],
			operationId: "listBandwidthIps",
			parameters: [
				siteIdParam("Omit to scope to every site the caller can view."),
				...rangeParams,
				...pageParams,
				{ name: "search", in: "query", description: "Free-text match against the IP address.", schema: { type: "string" } },
				{ name: "country", in: "query", description: "Two-letter country code.", schema: { type: "string", minLength: 2, maxLength: 2 } },
				{ name: "protocol", in: "query", schema: { type: "string", enum: ["http", "websocket"] } },
				{
					name: "sortBy",
					in: "query",
					schema: {
						type: "string",
						default: "client_total_bytes",
						enum: [
							"ip",
							"country_code",
							"client_received_bytes",
							"client_sent_bytes",
							"upstream_sent_bytes",
							"upstream_received_bytes",
							"client_total_bytes",
							"upstream_total_bytes",
						],
					},
				},
			],
			responses: {
				"200": jsonResponse("", paged(ref("BandwidthIpRow"))),
				"400": errorResponse("The selected site was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to the selected site)."),
			},
		},
	},

	"/sessions": {
		get: {
			summary: "List visitor sessions",
			tags: ["Sessions"],
			operationId: "listSessions",
			parameters: [
				siteIdParam("Omit to scope to every site the caller can view."),
				...rangeParams,
				...pageParams,
				{ name: "search", in: "query", description: "Free-text match against IP and similar fields.", schema: { type: "string" } },
				{ name: "state", in: "query", schema: { type: "string", enum: ["active", "expired", "revoked"] } },
				{ name: "country", in: "query", schema: { type: "string", minLength: 2, maxLength: 2 } },
				{ name: "asn", in: "query", schema: { type: "integer", minimum: 1 } },
				{
					name: "sortBy",
					in: "query",
					schema: {
						type: "string",
						default: "last_seen_at",
						enum: ["last_seen_at", "created_at", "expires_at", "request_count", "last_ip", "country_code", "asn"],
					},
				},
			],
			responses: {
				"200": jsonResponse("", paged(ref("AccessSession"))),
				"400": errorResponse("The selected site was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to the selected site)."),
			},
		},
	},
	"/sessions/{id}/revoke": {
		post: {
			summary: "Revoke a visitor session",
			description: "Requires manager-level access to the selected site. `siteId` is required (unlike the GET endpoints, there is no all-sites fallback).",
			tags: ["Sessions"],
			operationId: "revokeSession",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }, siteIdParam("Required.")],
			responses: {
				"200": jsonResponse("", { type: "object", required: ["revoked"], properties: { revoked: { type: "boolean", const: true } } }),
				"400": errorResponse("No site selected, or the selected site was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
			},
		},
	},

	"/network-policy": {
		get: {
			summary: "Get a site's default network policy and country/ASN rules",
			description: "`siteId` is required.",
			tags: ["Network policy"],
			operationId: "getNetworkPolicy",
			parameters: [siteIdParam("Required.")],
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["defaultIpAction", "defaultCountryAction", "countryRules", "asnRules", "geoip"],
					properties: {
						defaultIpAction: { type: "string", enum: ["inherit", "allow", "block", "challenge"] },
						defaultCountryAction: { type: "string", enum: ["inherit", "allow", "block", "challenge"] },
						countryRules: { type: "array", items: ref("CountryRule") },
						asnRules: { type: "array", items: ref("AsnRule") },
						geoip: ref("GeoIpStatus"),
					},
				}),
				"400": errorResponse("No siteId given, or the selected site was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to the selected site)."),
			},
		},
		put: {
			summary: "Update a site's default network policy",
			description: "Requires manager-level access to the selected site.",
			tags: ["Network policy"],
			operationId: "updateNetworkPolicy",
			parameters: [siteIdParam("Required.")],
			requestBody: jsonBody({
				type: "object",
				properties: {
					defaultIpAction: { type: "string", enum: ["inherit", "allow", "block", "challenge"], description: "Omitted keeps the current value." },
					defaultCountryAction: { type: "string", enum: ["inherit", "allow", "block", "challenge"], description: "Omitted keeps the current value." },
				},
			}),
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["defaultIpAction", "defaultCountryAction", "durabilityConfirmed"],
					properties: {
						defaultIpAction: { type: "string", enum: ["inherit", "allow", "block", "challenge"] },
						defaultCountryAction: { type: "string", enum: ["inherit", "allow", "block", "challenge"] },
						durabilityConfirmed: {
							type: "boolean",
							description: "HA only: whether a majority of replicas confirmed durability before responding. Always true on a non-HA instance.",
						},
					},
				}),
				"400": errorResponse("Invalid action value, no siteId given, or the selected site was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
			},
		},
	},
	"/country-rules": {
		post: {
			summary: "Add a site-level country rule",
			description: "Requires manager-level access to the selected site. Replaces any existing (even active) rule for the same country code.",
			tags: ["Network policy"],
			operationId: "createCountryRule",
			parameters: [siteIdParam("Required.")],
			requestBody: jsonBody({
				type: "object",
				required: ["countryCode", "action"],
				properties: {
					countryCode: { type: "string", minLength: 2, maxLength: 2, description: "Case-insensitive; normalized to upper case." },
					action: { type: "string", enum: ["allow", "pass", "block", "challenge"] },
					reason: { type: "string", default: "" },
					expiresAt: { type: ["integer", "string", "null"], description: "Unix milliseconds in the future, or null/omitted for no expiry." },
				},
			}),
			responses: {
				"201": jsonResponse("", {
					allOf: [ref("CountryRule")],
					type: "object",
					required: ["durabilityConfirmed"],
					properties: { durabilityConfirmed: { type: "boolean" } },
				}),
				"400": errorResponse("Invalid country code/action, an expiry not in the future, no siteId given, or the selected site was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
			},
		},
	},
	"/country-rules/{id}": {
		delete: {
			summary: "Delete a site-level country rule",
			description: "Requires manager-level access to the selected site.",
			tags: ["Network policy"],
			operationId: "deleteCountryRule",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }, siteIdParam("Required.")],
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["deleted", "durabilityConfirmed"],
					properties: { deleted: { type: "boolean", const: true }, durabilityConfirmed: { type: "boolean" } },
				}),
				"400": errorResponse("No siteId given, or the selected site was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
			},
		},
	},
	"/asn-rules": {
		post: {
			summary: "Add a site-level ASN rule",
			description: "Requires manager-level access to the selected site. Replaces any existing (even active) rule for the same ASN.",
			tags: ["Network policy"],
			operationId: "createAsnRule",
			parameters: [siteIdParam("Required.")],
			requestBody: jsonBody({
				type: "object",
				required: ["asn", "action"],
				properties: {
					asn: { type: ["integer", "string"], description: "A positive whole number." },
					action: { type: "string", enum: ["allow", "pass", "block", "challenge"] },
					reason: { type: "string", default: "" },
					expiresAt: { type: ["integer", "string", "null"], description: "Unix milliseconds in the future, or null/omitted for no expiry." },
				},
			}),
			responses: {
				"201": jsonResponse("", {
					allOf: [ref("AsnRule")],
					type: "object",
					required: ["durabilityConfirmed"],
					properties: { durabilityConfirmed: { type: "boolean" } },
				}),
				"400": errorResponse("Invalid ASN/action, an expiry not in the future, no siteId given, or the selected site was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
			},
		},
	},
	"/asn-rules/{id}": {
		delete: {
			summary: "Delete a site-level ASN rule",
			description: "Requires manager-level access to the selected site.",
			tags: ["Network policy"],
			operationId: "deleteAsnRule",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }, siteIdParam("Required.")],
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["deleted", "durabilityConfirmed"],
					properties: { deleted: { type: "boolean", const: true }, durabilityConfirmed: { type: "boolean" } },
				}),
				"400": errorResponse("No siteId given, or the selected site was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
			},
		},
	},

	"/rules": {
		get: {
			summary: "List a site's IP rules",
			description: "`siteId` is required to get any rules; without it (or for an unknown site) this returns an empty page rather than an error.",
			tags: ["Network policy"],
			operationId: "listIpRules",
			parameters: [
				siteIdParam("Without it, an empty page is returned."),
				...pageParams,
				{ name: "search", in: "query", description: "Free-text match against the CIDR and reason.", schema: { type: "string" } },
				{ name: "action", in: "query", schema: { type: "string", enum: ["allow", "pass", "block", "challenge"] } },
				{ name: "state", in: "query", schema: { type: "string", enum: ["active", "expired"] } },
				{ name: "sortBy", in: "query", schema: { type: "string", default: "created_at", enum: ["created_at", "expires_at", "network_cidr", "action"] } },
			],
			responses: {
				"200": jsonResponse("", paged(ref("IpRule"))),
				"401": errorResponse("Not signed in."),
			},
		},
		post: {
			summary: "Add a site-level IP rule",
			description: "Requires manager-level access to the selected site.",
			tags: ["Network policy"],
			operationId: "createIpRule",
			parameters: [siteIdParam("Required.")],
			requestBody: jsonBody({
				type: "object",
				required: ["networkCidr", "action"],
				properties: {
					networkCidr: { type: "string", description: "A single IP address or CIDR block." },
					action: { type: "string", enum: ["allow", "pass", "block", "challenge"] },
					reason: { type: "string", default: "" },
					expiresAt: { type: ["integer", "string", "null"], description: "Unix milliseconds in the future, or null/omitted for no expiry." },
				},
			}),
			responses: {
				"201": jsonResponse("Unlike country/ASN rules, this response has no durabilityConfirmed field.", ref("IpRule")),
				"400": errorResponse("Invalid CIDR/action, an expiry not in the future, no siteId given, or the selected site was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
			},
		},
	},
	"/rules/{id}": {
		delete: {
			summary: "Delete a site-level IP rule",
			description: "Requires manager-level access to the selected site.",
			tags: ["Network policy"],
			operationId: "deleteIpRule",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }, siteIdParam("Required.")],
			responses: {
				"200": jsonResponse("Unlike country/ASN rule deletion, this response has no durabilityConfirmed field.", {
					type: "object",
					required: ["deleted"],
					properties: { deleted: { type: "boolean", const: true } },
				}),
				"400": errorResponse("No siteId given, or the selected site was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
			},
		},
	},
	"/rules/bulk-delete": {
		post: {
			summary: "Delete up to 200 site-level IP rules at once",
			description: "Requires manager-level access to the selected site.",
			tags: ["Network policy"],
			operationId: "bulkDeleteIpRules",
			parameters: [siteIdParam("Required.")],
			requestBody: jsonBody({
				type: "object",
				required: ["ids"],
				properties: { ids: { type: "array", minItems: 1, maxItems: 200, items: { type: "string" } } },
			}),
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["deleted"],
					properties: { deleted: { type: "integer", description: "Count of rules actually deleted." } },
				}),
				"400": errorResponse("Provide 1 to 200 rule IDs, no siteId given, or the selected site was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
			},
		},
	},
};
