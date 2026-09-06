import { schemas } from "../openapi/components.ts";
import { streamSchemas } from "../openapi/components-streams.ts";
import { integrationSchemas } from "../openapi/components-integrations.ts";
import { opsSchemas } from "../openapi/components-ops.ts";
import { siteAdminSchemas } from "../openapi/components-site-admin.ts";
import { metricsSchemas } from "../openapi/components-metrics.ts";
import { identitySchemas } from "../openapi/components-identity.ts";
import { apiTokenPaths } from "../openapi/paths/api-tokens.ts";
import { sitePaths } from "../openapi/paths/sites.ts";
import { streamPaths } from "../openapi/paths/streams.ts";
import { integrationPaths } from "../openapi/paths/integrations.ts";
import { opsPaths } from "../openapi/paths/ops.ts";
import { siteAdminPaths } from "../openapi/paths/site-admin.ts";
import { metricsPaths } from "../openapi/paths/metrics.ts";
import { identityPaths } from "../openapi/paths/identity.ts";
import type { JsonSchema, PathItemObject } from "../openapi/types.ts";

export interface OpenApiDocument {
	openapi: string;
	info: { title: string; version: string; description: string };
	servers: Array<{ description: string; url: string }>;
	security: ReadonlyArray<Record<string, readonly string[]>>;
	components: {
		securitySchemes: Record<string, Record<string, unknown>>;
		schemas: Record<string, JsonSchema>;
	};
	paths: Record<string, PathItemObject>;
}

const PATH_FRAGMENTS: Array<Record<string, PathItemObject>> = [
	apiTokenPaths,
	sitePaths,
	streamPaths,
	integrationPaths,
	opsPaths,
	siteAdminPaths,
	metricsPaths,
	identityPaths,
];

const SCHEMA_FRAGMENTS: Array<Record<string, JsonSchema>> = [
	schemas,
	streamSchemas,
	integrationSchemas,
	opsSchemas,
	siteAdminSchemas,
	metricsSchemas,
	identitySchemas,
];

const BASE = "/_burrowgate/api/admin";

type OpenApiDocumentTemplate = Omit<OpenApiDocument, "servers">;

let cached: OpenApiDocumentTemplate | null = null;

export function buildOpenApiDocument(serverOrigin: string): OpenApiDocument {
	if (cached) {
		return { ...cached, servers: [{ description: "This BurrowGate instance", url: serverOrigin }] };
	}
	const paths: Record<string, PathItemObject> = {};
	for (const fragment of PATH_FRAGMENTS) {
		for (const [path, item] of Object.entries(fragment)) {
			if (paths[path]) throw new Error(`OpenAPI document has a duplicate path: ${path}`);
			paths[path] = item;
		}
	}
	const prefixed: Record<string, PathItemObject> = {};
	for (const [path, item] of Object.entries(paths)) prefixed[`${BASE}${path}`] = item;

	const mergedSchemas: Record<string, JsonSchema> = {};
	for (const fragment of SCHEMA_FRAGMENTS) {
		for (const [name, schema] of Object.entries(fragment)) {
			if (mergedSchemas[name]) throw new Error(`OpenAPI document has a duplicate schema name: ${name}`);
			mergedSchemas[name] = schema;
		}
	}

	cached = {
		openapi: "3.2.0",
		info: {
			title: "BurrowGate admin API",
			version: "1",
			description:
				"BurrowGate's own admin dashboard API. A full-access API token (see /me/api-tokens) authenticates exactly as the token's owning user would through a signed-in session (same endpoints, same permissions).",
		},
		security: [{ AdminSession: [] }, { AdminSessionHttp: [] }, { ApiTokenFull: [] }],
		components: {
			securitySchemes: {
				AdminSession: {
					type: "apiKey",
					in: "cookie",
					name: "__Host-bg_admin",
					description: "The dashboard's secure session cookie. Browser-only; programmatic API clients should use ApiTokenFull.",
				},
				AdminSessionHttp: {
					type: "apiKey",
					in: "cookie",
					name: "bg_admin",
					description:
						"The dashboard's non-Secure fallback session cookie when BurrowGate is deliberately served over HTTP. Browser-only; bearer tokens must be used over HTTPS.",
				},
				ApiTokenFull: {
					type: "http",
					scheme: "bearer",
					bearerFormat: "bgat_...",
					description:
						"A full-access API token (Account -> API tokens -> Full access). Authenticates as the token's owning user, with that user's own role and site/stream permissions. Not subject to the CSRF checks a session cookie requires.",
				},
				HaSharedToken: {
					type: "http",
					scheme: "bearer",
					description:
						"A per-node High Availability credential, unrelated to dashboard sessions or user API tokens. Used only for node-to-node calls within an HA cluster (see docs/HIGH_AVAILABILITY.md). Not something an external API client would ever hold.",
				},
			},
			schemas: mergedSchemas,
		},
		paths: prefixed,
	};
	return { ...cached, servers: [{ description: "This BurrowGate instance", url: serverOrigin }] };
}
