import { errorResponse, jsonBody, jsonResponse, ref, type PathItemObject } from "../types.ts";

const pendingChange = ref("PendingChange");

export const sitePaths: Record<string, PathItemObject> = {
	"/sites": {
		get: {
			summary: "List sites",
			description:
				"Returns every site visible to the caller, plus catalog/default data the dashboard uses to render edit forms (challenge providers, bot catalog, managed-protection rulesets, and so on).",
			tags: ["Sites"],
			operationId: "listSites",
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["items", "pendingChanges", "challengeProviders", "defaultEventRetentionDays"],
					properties: {
						items: {
							type: "array",
							items: {
								allOf: [ref("Site")],
								type: "object",
								properties: {
									originHealth: { type: "object", additionalProperties: true, description: "Live health summary for the site's origin pool." },
								},
							},
						},
						pendingChanges: { type: "array", items: pendingChange },
						challengeProviders: {
							type: "array",
							items: { type: "object", additionalProperties: true },
							description: "Metadata for every registered challenge provider.",
						},
						defaultEventRetentionDays: { type: "integer" },
						websocketDefaults: { $ref: "#/components/schemas/SiteWebSocketPolicy" },
						httpCacheDefaults: { type: "object", additionalProperties: true },
						bodyCaptureDefaults: { type: "object", additionalProperties: true },
						headerCaptureDefaults: { type: "object", additionalProperties: true },
						managedProtection: { type: "object", additionalProperties: true, description: "The managed WAF ruleset catalog." },
						botCatalog: { type: "array", items: { type: "object", additionalProperties: true } },
						networkPrivacyCategories: { type: "array", items: { type: "object", additionalProperties: true } },
						errorResponseDefaults: { type: "object", additionalProperties: true },
						challengeDefaults: { type: "object", additionalProperties: true },
					},
				}),
				"401": errorResponse("Not signed in."),
			},
		},
		post: {
			summary: "Create a site",
			description: "Administrator only.",
			tags: ["Sites"],
			operationId: "createSite",
			requestBody: jsonBody(ref("SiteInput")),
			responses: {
				"201": jsonResponse("", {
					type: "object",
					required: ["site", "generatedSigningSecret"],
					properties: {
						site: ref("Site"),
						generatedSigningSecret: {
							type: ["string", "null"],
							description: "Present only if originSigningSecret was omitted from the request; shown once and never again.",
						},
					},
				}),
				"400": errorResponse("Invalid input, or a site with this publicHost already exists."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
			},
		},
	},
	"/sites/{id}": {
		put: {
			summary: "Update a site",
			description:
				"Requires manager-level access to this site. If the update changes the public hostname while TLS is active and an `effectiveAt` is supplied, the hostname change is scheduled rather than applied immediately - see `pendingChange` in the response.",
			tags: ["Sites"],
			operationId: "updateSite",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			requestBody: jsonBody(ref("SiteInput")),
			responses: {
				"200": jsonResponse("", { type: "object", required: ["site", "pendingChange"], properties: { site: ref("Site"), pendingChange } }),
				"400": errorResponse("Invalid input, a hostname conflict, or a certificate that doesn't cover the new hostname."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (viewer-level access, or no access to this site), or CSRF validation failed."),
				"404": errorResponse("Site not found."),
			},
		},
		delete: {
			summary: "Delete a site",
			description:
				"Administrator only. Cascades to the site's origins, route policies, rules, and access list. Blocked while a certificate issuance is in progress, or while a stream still depends on this site's certificate.",
			tags: ["Sites"],
			operationId: "deleteSite",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			responses: {
				"200": jsonResponse("", { type: "object", required: ["ok"], properties: { ok: { type: "boolean", const: true } } }),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
				"404": errorResponse("Site not found."),
				"409": errorResponse("A certificate issuance is in progress, or a stream still depends on this site's certificate."),
			},
		},
	},
	"/sites/{id}/pending-change/apply-now": {
		post: {
			summary: "Apply a site's scheduled change immediately",
			tags: ["Sites"],
			operationId: "applySitePendingChangeNow",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			responses: {
				"200": jsonResponse("", { type: "object", required: ["site"], properties: { site: { oneOf: [{ type: "null" }, ref("Site")] } } }),
				"400": errorResponse("Unable to apply the pending change."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("No pending change for this site."),
			},
		},
	},
	"/sites/{id}/pending-change": {
		delete: {
			summary: "Cancel a site's scheduled change",
			tags: ["Sites"],
			operationId: "cancelSitePendingChange",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			responses: {
				"200": jsonResponse("", { type: "object", required: ["ok"], properties: { ok: { type: "boolean", const: true } } }),
				"400": errorResponse("Unable to cancel the pending change."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("No pending change for this site."),
			},
		},
	},

	"/sites/{id}/origins": {
		get: {
			summary: "List a site's origins",
			description: "Requires viewer-level access to this site.",
			tags: ["Origins"],
			operationId: "listOrigins",
			parameters: [{ name: "id", in: "path", required: true, description: "Site ID.", schema: { type: "string" } }],
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["items"],
					properties: {
						items: {
							type: "array",
							items: { allOf: [ref("Origin")], type: "object", properties: { health: { type: ["object", "null"], additionalProperties: true } } },
						},
					},
				}),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to this site)."),
			},
		},
		post: {
			summary: "Add an origin to a site",
			description: "Requires manager-level access to this site.",
			tags: ["Origins"],
			operationId: "createOrigin",
			parameters: [{ name: "id", in: "path", required: true, description: "Site ID.", schema: { type: "string" } }],
			requestBody: jsonBody(ref("OriginInput")),
			responses: {
				"201": jsonResponse("", { type: "object", required: ["origin"], properties: { origin: ref("Origin") } }),
				"400": errorResponse("Invalid input, or an origin with this name already exists on the site."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("Site not found."),
			},
		},
	},
	"/origins/{id}": {
		put: {
			summary: "Update an origin",
			description: "Requires manager-level access to the origin's site.",
			tags: ["Origins"],
			operationId: "updateOrigin",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			requestBody: jsonBody(ref("OriginInput")),
			responses: {
				"200": jsonResponse("", { type: "object", required: ["origin"], properties: { origin: ref("Origin") } }),
				"400": errorResponse("Invalid input."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("Origin not found."),
			},
		},
		delete: {
			summary: "Delete an origin",
			description: "Requires manager-level access to the origin's site. The primary origin cannot be deleted - edit it through the site instead.",
			tags: ["Origins"],
			operationId: "deleteOrigin",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			responses: {
				"200": jsonResponse("", { type: "object", required: ["ok"], properties: { ok: { type: "boolean", const: true } } }),
				"400": errorResponse("This is the site's primary origin and cannot be deleted."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("Origin not found."),
			},
		},
	},

	"/route-policies": {
		get: {
			summary: "List a site's route policies",
			description: "Requires viewer-level access to the selected site.",
			tags: ["Route policies"],
			operationId: "listRoutePolicies",
			parameters: [{ name: "siteId", in: "query", required: true, schema: { type: "string" } }],
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["items"],
					properties: { items: { type: "array", items: ref("RoutePolicy") }, site: ref("Site") },
				}),
				"400": errorResponse("Unknown siteId."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to this site)."),
			},
		},
		post: {
			summary: "Create a route policy",
			description: "Requires manager-level access to the selected site.",
			tags: ["Route policies"],
			operationId: "createRoutePolicy",
			parameters: [{ name: "siteId", in: "query", required: true, schema: { type: "string" } }],
			requestBody: jsonBody(ref("RoutePolicyInput")),
			responses: {
				"201": jsonResponse("", { type: "object", required: ["policy"], properties: { policy: ref("RoutePolicy") } }),
				"400": errorResponse("Invalid input, unknown siteId, or no site selected."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
			},
		},
	},
	"/route-policies/{id}": {
		put: {
			summary: "Update a route policy",
			description: "Requires manager-level access to the selected site.",
			tags: ["Route policies"],
			operationId: "updateRoutePolicy",
			parameters: [
				{ name: "id", in: "path", required: true, schema: { type: "string" } },
				{ name: "siteId", in: "query", required: true, schema: { type: "string" } },
			],
			requestBody: jsonBody(ref("RoutePolicyInput")),
			responses: {
				"200": jsonResponse("", { type: "object", required: ["policy"], properties: { policy: ref("RoutePolicy") } }),
				"400": errorResponse("Invalid input, or the selected site was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("Route policy not found."),
			},
		},
		delete: {
			summary: "Delete a route policy",
			description: "Requires manager-level access to the selected site.",
			tags: ["Route policies"],
			operationId: "deleteRoutePolicy",
			parameters: [
				{ name: "id", in: "path", required: true, schema: { type: "string" } },
				{ name: "siteId", in: "query", required: true, schema: { type: "string" } },
			],
			responses: {
				"200": jsonResponse("", { type: "object", required: ["ok"], properties: { ok: { type: "boolean", const: true } } }),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("Route policy not found, or the selected site was not found."),
			},
		},
	},

	"/route-policies/{id}/network-rules": {
		get: {
			summary: "List a route policy's network rules",
			description: "Requires viewer-level access to the selected site.",
			tags: ["Route policies"],
			operationId: "listRouteNetworkRules",
			parameters: [
				{ name: "id", in: "path", required: true, schema: { type: "string" } },
				{ name: "siteId", in: "query", required: true, schema: { type: "string" } },
			],
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["ipRules", "countryRules", "asnRules", "geoip"],
					properties: {
						ipRules: { type: "array", items: ref("RouteIpRule") },
						countryRules: { type: "array", items: ref("RouteCountryRule") },
						asnRules: { type: "array", items: ref("RouteAsnRule") },
						geoip: ref("GeoIpStatus"),
					},
				}),
				"401": errorResponse("Not signed in."),
				"404": errorResponse("Route policy not found, or the selected site was not found."),
			},
		},
	},
	"/route-policies/{id}/rules": {
		post: {
			summary: "Add an IP rule to a route policy",
			description: "Requires manager-level access to the selected site.",
			tags: ["Route policies"],
			operationId: "createRouteIpRule",
			parameters: [
				{ name: "id", in: "path", required: true, schema: { type: "string" } },
				{ name: "siteId", in: "query", required: true, schema: { type: "string" } },
			],
			requestBody: jsonBody(ref("RouteIpRuleInput")),
			responses: {
				"201": jsonResponse("", ref("RouteIpRule")),
				"400": errorResponse("Invalid CIDR, action, or expiry."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("Route policy not found, or the selected site was not found."),
			},
		},
	},
	"/route-policies/{id}/rules/{ruleId}": {
		delete: {
			summary: "Delete a route policy's IP rule",
			description: "Requires manager-level access to the selected site.",
			tags: ["Route policies"],
			operationId: "deleteRouteIpRule",
			parameters: [
				{ name: "id", in: "path", required: true, schema: { type: "string" } },
				{ name: "ruleId", in: "path", required: true, schema: { type: "string" } },
				{ name: "siteId", in: "query", required: true, schema: { type: "string" } },
			],
			responses: {
				"200": jsonResponse("", { type: "object", required: ["deleted"], properties: { deleted: { type: "boolean", const: true } } }),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("Route policy not found, or the selected site was not found."),
			},
		},
	},
	"/route-policies/{id}/country-rules": {
		post: {
			summary: "Add a country rule to a route policy",
			description: "Requires manager-level access to the selected site.",
			tags: ["Route policies"],
			operationId: "createRouteCountryRule",
			parameters: [
				{ name: "id", in: "path", required: true, schema: { type: "string" } },
				{ name: "siteId", in: "query", required: true, schema: { type: "string" } },
			],
			requestBody: jsonBody(ref("RouteCountryRuleInput")),
			responses: {
				"201": jsonResponse("", ref("RouteCountryRule")),
				"400": errorResponse("Invalid country code, action, or expiry."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("Route policy not found, or the selected site was not found."),
			},
		},
	},
	"/route-policies/{id}/country-rules/{ruleId}": {
		delete: {
			summary: "Delete a route policy's country rule",
			description: "Requires manager-level access to the selected site.",
			tags: ["Route policies"],
			operationId: "deleteRouteCountryRule",
			parameters: [
				{ name: "id", in: "path", required: true, schema: { type: "string" } },
				{ name: "ruleId", in: "path", required: true, schema: { type: "string" } },
				{ name: "siteId", in: "query", required: true, schema: { type: "string" } },
			],
			responses: {
				"200": jsonResponse("", { type: "object", required: ["deleted"], properties: { deleted: { type: "boolean", const: true } } }),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("Route policy not found, or the selected site was not found."),
			},
		},
	},
	"/route-policies/{id}/asn-rules": {
		post: {
			summary: "Add an ASN rule to a route policy",
			description: "Requires manager-level access to the selected site.",
			tags: ["Route policies"],
			operationId: "createRouteAsnRule",
			parameters: [
				{ name: "id", in: "path", required: true, schema: { type: "string" } },
				{ name: "siteId", in: "query", required: true, schema: { type: "string" } },
			],
			requestBody: jsonBody(ref("RouteAsnRuleInput")),
			responses: {
				"201": jsonResponse("", ref("RouteAsnRule")),
				"400": errorResponse("Invalid ASN, action, or expiry."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("Route policy not found, or the selected site was not found."),
			},
		},
	},
	"/route-policies/{id}/asn-rules/{ruleId}": {
		delete: {
			summary: "Delete a route policy's ASN rule",
			description: "Requires manager-level access to the selected site.",
			tags: ["Route policies"],
			operationId: "deleteRouteAsnRule",
			parameters: [
				{ name: "id", in: "path", required: true, schema: { type: "string" } },
				{ name: "ruleId", in: "path", required: true, schema: { type: "string" } },
				{ name: "siteId", in: "query", required: true, schema: { type: "string" } },
			],
			responses: {
				"200": jsonResponse("", { type: "object", required: ["deleted"], properties: { deleted: { type: "boolean", const: true } } }),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("Route policy not found, or the selected site was not found."),
			},
		},
	},

	"/origins/{id}/check": {
		post: {
			summary: "Run a health check for one origin now",
			description: "Requires manager-level access to the origin's site.",
			tags: ["Origins"],
			operationId: "checkOriginHealthNow",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			responses: {
				"200": jsonResponse("", { type: "object", required: ["status"], properties: { status: ref("OriginHealthSummary") } }),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("Origin not found."),
				"409": errorResponse("Unable to run the health check right now."),
			},
		},
	},
	"/origins/{id}/mtls/generate": {
		post: {
			summary: "Generate a client mTLS certificate for an origin",
			description: "Requires manager-level access to the origin's site. Replaces any existing client certificate/key for this origin and enables mTLS.",
			tags: ["Origins"],
			operationId: "generateOriginMtlsCertificate",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			responses: {
				"200": jsonResponse("", { type: "object", required: ["origin"], properties: { origin: ref("Origin") } }),
				"400": errorResponse("Unable to generate a client certificate."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("Origin not found."),
			},
		},
	},
	"/origins/{id}/mtls/certificate": {
		get: {
			summary: "Download an origin's client mTLS certificate",
			description: "Requires viewer-level access to the origin's site. Returns the PEM file as an attachment.",
			tags: ["Origins"],
			operationId: "downloadOriginMtlsCertificate",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			responses: {
				"200": { description: "The client certificate PEM.", content: { "application/x-pem-file": { schema: { type: "string" } } } },
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden."),
				"404": errorResponse("Origin not found, or no client certificate is configured for it."),
			},
		},
	},
	"/origins/{id}/mtls/generate-origin-certificate": {
		post: {
			summary: "Generate an origin-facing server certificate and CA",
			description:
				"Requires manager-level access to the origin's site. Generates a CA and a server certificate BurrowGate can present when acting as the mTLS client's counterpart; the private key is returned once and not stored.",
			tags: ["Origins"],
			operationId: "generateOriginServerCertificate",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["origin", "certificatePem", "privateKeyPem"],
					properties: { origin: ref("Origin"), certificatePem: { type: "string" }, privateKeyPem: { type: "string", description: "Shown once; not stored." } },
				}),
				"400": errorResponse("Unable to generate an origin certificate."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("Origin not found, or its site was not found."),
			},
		},
	},
	"/origins/{id}/mtls/trusted-ca": {
		get: {
			summary: "Download an origin's trusted CA bundle",
			description: "Requires viewer-level access to the origin's site. Returns the PEM file as an attachment.",
			tags: ["Origins"],
			operationId: "downloadOriginTrustedCa",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			responses: {
				"200": { description: "The trusted CA bundle PEM.", content: { "application/x-pem-file": { schema: { type: "string" } } } },
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden."),
				"404": errorResponse("Origin not found, or no trusted CA is configured for it."),
			},
		},
	},
	"/static-roots": {
		get: {
			summary: "Browse folders under the static-sites root",
			description:
				"Used to build a folder picker for static-site origins. `path` is relative to the instance's configured static-sites root directory; results are jailed inside it.",
			tags: ["Sites"],
			operationId: "listStaticRoots",
			parameters: [{ name: "path", in: "query", required: false, schema: { type: "string" }, description: "Relative path to list; omit for the root." }],
			responses: {
				"200": jsonResponse("", ref("StaticRootListing")),
				"400": errorResponse("Path does not exist, is not a directory, or escapes the static-sites root."),
				"401": errorResponse("Not signed in."),
			},
		},
	},

	"/sites/{id}/health": {
		get: {
			summary: "Get a site's origin health status and recent events",
			description: "Requires viewer-level access to this site.",
			tags: ["Sites"],
			operationId: "getSiteHealth",
			parameters: [
				{ name: "id", in: "path", required: true, schema: { type: "string" } },
				{ name: "limit", in: "query", required: false, schema: { type: "integer", minimum: 1, maximum: 200, default: 100 } },
			],
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["status", "events", "backendEvents"],
					properties: {
						status: ref("OriginHealthSummary"),
						events: { type: "array", items: ref("OriginHealthEvent"), description: "At most 50, regardless of `limit`." },
						backendEvents: { type: "array", items: ref("OriginBackendHealthEvent") },
					},
				}),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to this site)."),
			},
		},
	},
	"/sites/{id}/health/check": {
		post: {
			summary: "Run a health check for every origin on a site now",
			description: "Requires manager-level access to this site.",
			tags: ["Sites"],
			operationId: "checkSiteHealthNow",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			responses: {
				"200": jsonResponse("", { type: "object", required: ["status"], properties: { status: ref("OriginHealthSummary") } }),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("Site not found."),
				"409": errorResponse("Unable to run the health check right now."),
			},
		},
	},
	"/sites/{id}/notifications": {
		get: {
			summary: "List a site's notification outbox",
			description: "Requires viewer-level access to this site. Paged; supports search and filtering by event type/delivery status.",
			tags: ["Sites"],
			operationId: "listSiteNotifications",
			parameters: [
				{ name: "id", in: "path", required: true, schema: { type: "string" } },
				{ name: "page", in: "query", required: false, schema: { type: "integer", minimum: 1, default: 1 } },
				{ name: "pageSize", in: "query", required: false, schema: { type: "integer", minimum: 10, maximum: 200, default: 25 } },
				{ name: "search", in: "query", required: false, schema: { type: "string" } },
				{
					name: "type",
					in: "query",
					required: false,
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
							"system_resource_high",
							"system_resource_normal",
							"ha_node_down",
							"ha_node_up",
						],
					},
				},
				{ name: "status", in: "query", required: false, schema: { type: "string", enum: ["pending", "delivered", "failed"] } },
				{ name: "sortBy", in: "query", required: false, schema: { type: "string" } },
				{ name: "sortDirection", in: "query", required: false, schema: { type: "string", enum: ["asc", "desc"] } },
			],
			responses: {
				"200": jsonResponse("", {
					allOf: [ref("MetricsPageEnvelope")],
					type: "object",
					required: ["items"],
					properties: { items: { type: "array", items: ref("SiteNotificationOutboxItem") } },
				}),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to this site)."),
			},
		},
	},
};
