import { MONITORING_VIEWS, PATH_FILTERABLE_VIEWS } from "../services/monitoring-service.ts";
import { errorResponse, jsonResponse, ref, type JsonSchema, type PathItemObject } from "./types.ts";

export const MONITORING_TOKEN_SECURITY: readonly Record<string, readonly string[]>[] = [{ ApiTokenMonitoring: [] }];

export const monitoringSchemas: Record<string, JsonSchema> = {
	ErrorResponse: {
		type: "object",
		required: ["error"],
		properties: { error: { type: "string", description: "Human-readable error message. Not a fixed enum, so treat it as free text for display." } },
	},
	MonitoringSite: {
		type: "object",
		required: ["id", "name", "publicHost", "enabled"],
		properties: {
			id: { type: "string", description: "Pass as `siteId` to the monitoring endpoint." },
			name: { type: "string" },
			publicHost: { type: "string" },
			enabled: { type: "boolean" },
		},
	},
	MonitoringStat: {
		type: "object",
		required: ["label", "value", "unit"],
		properties: {
			label: { type: "string" },
			value: { type: ["number", "null"], description: "Null when the range holds no data for this stat." },
			unit: { type: "string" },
		},
	},
	MonitoringRow: {
		type: "object",
		description: "One row of a tabular view. Geography rows use a country code as the label. Unknown locations are `ZZ` and private-network locations `XX`.",
		required: ["label", "value"],
		properties: { label: { type: "string" }, value: { type: "number" } },
	},
	MonitoringPoint: {
		type: "object",
		required: ["timestamp", "value", "height"],
		properties: {
			timestamp: { type: "integer", description: "Unix milliseconds at the start of the bucket." },
			value: { type: ["number", "null"], description: "Null where the bucket holds no data." },
			height: { type: "integer", minimum: 0, maximum: 100, description: "Value normalized against `maximum`, for drawing a chart without rescaling." },
		},
	},
	MonitoringResponse: {
		type: "object",
		required: [
			"schemaVersion",
			"view",
			"title",
			"scope",
			"pathPrefix",
			"path",
			"successfulOnly",
			"unit",
			"hours",
			"generatedAt",
			"from",
			"to",
			"bucketSeconds",
			"hasData",
			"maximum",
			"stats",
			"rows",
			"points",
		],
		properties: {
			schemaVersion: { type: "integer", const: 1, description: "Increments only on a breaking change to this shape." },
			view: { type: "string", enum: [...MONITORING_VIEWS] },
			title: { type: "string", description: "Human-readable name of the view, for a chart heading." },
			scope: { type: "string", description: 'The site name, "All sites", or "System".' },
			pathPrefix: {
				type: ["string", "null"],
				description:
					"The prefix actually applied. Verify this matches what you asked for: a gateway older than this parameter ignores it and answers for the whole site.",
			},
			path: { type: ["string", "null"], description: "The exact path actually applied. Verify it the same way as `pathPrefix`." },
			successfulOnly: { type: "boolean", description: "Whether refused responses were dropped." },
			unit: { type: "string" },
			hours: { type: "integer" },
			generatedAt: { type: "string", format: "date-time" },
			from: { type: "string", format: "date-time" },
			to: { type: "string", format: "date-time" },
			bucketSeconds: { type: "number", description: "Width of one point in `points`." },
			hasData: { type: "boolean" },
			maximum: { type: "number", description: "Largest value in `points`, the basis for each point's `height`." },
			stats: { type: "array", items: ref("MonitoringStat"), description: "Headline numbers for the view." },
			rows: { type: "array", items: ref("MonitoringRow"), description: "Tabular results. Empty for views that are purely a series." },
			points: { type: "array", maxItems: 49, items: ref("MonitoringPoint"), description: "The time series. At most 49 points whatever the range." },
		},
	},
};

const MAX_HOURS = 366 * 24;

export const monitoringPaths: Record<string, PathItemObject> = {
	"/sites": {
		get: {
			summary: "Sites visible to a monitoring token",
			description: "Instance-wide: monitoring tokens are not scoped to particular sites.",
			tags: ["Monitoring"],
			operationId: "monitoringSites",
			security: MONITORING_TOKEN_SECURITY,
			responses: {
				"200": jsonResponse("The sites on this instance.", {
					type: "object",
					required: ["sites"],
					properties: { sites: { type: "array", items: ref("MonitoringSite") } },
				}),
				"401": errorResponse("Missing, invalid, revoked, or expired credentials."),
				"403": errorResponse("A non-GET method, or an endpoint not available to monitoring tokens."),
			},
		},
	},
	"/monitoring": {
		get: {
			summary: "One aggregate metrics view",
			description:
				"Responses are `no-store` and nothing is cached, so there is no reason to snap to fixed windows. A wider window is not a more expensive answer: the series is bucketed to at most 49 points whatever the range, and rows scanned are bounded by the instance's event retention rather than by the range.",
			tags: ["Monitoring"],
			operationId: "monitoringView",
			security: MONITORING_TOKEN_SECURITY,
			parameters: [
				{
					name: "view",
					in: "query",
					description: "Defaults to `overview`. The system views (`cpu`, `memory`, `disk`, `network`) require an empty `siteId`.",
					schema: { type: "string", enum: [...MONITORING_VIEWS], default: "overview" },
				},
				{
					name: "hours",
					in: "query",
					description: "Whole hours to look back. Defaults to 24.",
					schema: { type: "integer", minimum: 1, maximum: MAX_HOURS, default: 24 },
				},
				{ name: "siteId", in: "query", description: "From the sites endpoint. Omit for all sites.", schema: { type: "string" } },
				{
					name: "pathPrefix",
					in: "query",
					description: `Absolute path, matching it and everything beneath it, so \`/creator/alice\` covers \`/creator/alice/post\` but never the sibling \`/creator/alice-blog\`. LIKE wildcards are escaped and cannot widen the scope. Mutually exclusive with \`path\`. Honoured only by: ${PATH_FILTERABLE_VIEWS.join(", ")}.`,
					schema: { type: "string", maxLength: 256, pattern: "^/" },
				},
				{
					name: "path",
					in: "query",
					description:
						"Absolute path, matching that one page only, and also its trailing-slash spelling. Both this and `pathPrefix` compare the path alone, so a request recorded as `/creator/alice?page=2` counts under `/creator/alice`. Mutually exclusive with `pathPrefix`.",
					schema: { type: "string", maxLength: 256, pattern: "^/" },
				},
				{
					name: "successfulOnly",
					in: "query",
					description: "Drop responses the origin refused. Refused on `blocked` and `protection`, whose entire subject is requests that were refused.",
					schema: { type: "string", enum: ["true", "false", "1", "0"] },
				},
			],
			responses: {
				"200": jsonResponse("The requested view.", ref("MonitoringResponse")),
				"400": errorResponse(
					"Unknown site or view, an unsupported range, both `pathPrefix` and `path`, or a scope asked of a view that cannot honour it. The `bandwidth` and system views read minute-aggregate tables that carry no path, so they refuse a scope rather than quietly answering for the whole site.",
				),
				"401": errorResponse("Missing, invalid, revoked, or expired credentials."),
				"403": errorResponse("A non-GET method, or an endpoint not available to monitoring tokens."),
			},
		},
	},
};
