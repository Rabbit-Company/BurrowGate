import type { Web } from "@rabbit-company/web";
import { repository } from "../db/repository.ts";
import { authenticateApiToken, fullAccessTokenBoundaryResponse } from "../services/api-token-service.ts";
import { monitoringData, MONITORING_VIEWS, type MonitoringView } from "../services/monitoring-service.ts";
import { buildMonitoringOpenApiDocument } from "../services/openapi-service.ts";
import { requestTransport } from "../config.ts";
import { jsonResponse, requestHost } from "../utils/http.ts";

const BASE = "/_burrowgate/api/v1";

const MAX_HOURS = 366 * 24;
const MAX_PATH_PREFIX = 256;
const PATH_PREFIX_PATTERN = /^\/[\w\-./~:@%]*$/;
const READ_PATHS = new Set([`${BASE}/monitoring`, `${BASE}/sites`, `${BASE}/openapi.json`]);

function response(data: unknown, status = 200) {
	const result = jsonResponse(data, status);
	result.headers.set("cache-control", "no-store");
	return result;
}

export function registerMonitoringRoutes(app: Web<any>): void {
	app.use(async (ctx, next) => {
		const path = new URL(ctx.req.url).pathname;
		const monitoringCredential = /^Bearer\s+bgro_/i.test(ctx.req.headers.get("authorization") ?? "");
		const fullAccessBoundary = fullAccessTokenBoundaryResponse(ctx.req);
		if (fullAccessBoundary) return fullAccessBoundary;
		const apiPath = path === BASE || path.startsWith(`${BASE}/`);
		if (!apiPath && !monitoringCredential) return await next();
		if (ctx.req.method !== "GET") return response({ error: "Monitoring API tokens are read-only" }, 403);
		if (!READ_PATHS.has(path)) return response({ error: "Endpoint is not available to monitoring API tokens" }, 403);
		if (!(await authenticateApiToken(ctx.req))) {
			const result = response({ error: "Invalid, expired, or revoked API token" }, 401);
			result.headers.set("www-authenticate", "Bearer");
			return result;
		}
		await next();
	});
	app.get(`${BASE}/openapi.json`, async (ctx) => response(buildMonitoringOpenApiDocument(`${requestTransport(ctx.req)}://${requestHost(ctx.req)}`)));
	app.get(`${BASE}/sites`, async () =>
		response({
			sites: (await repository.allSites()).map((site) => ({ id: site.id, name: site.name, publicHost: site.public_host, enabled: site.enabled === 1 })),
		}),
	);
	app.get(`${BASE}/monitoring`, async (ctx) => {
		const url = new URL(ctx.req.url);
		const view = url.searchParams.get("view") ?? "overview";
		const hours = Number(url.searchParams.get("hours") ?? 24);
		if (!(MONITORING_VIEWS as readonly string[]).includes(view)) return response({ error: "Unknown view", views: MONITORING_VIEWS }, 400);
		if (!Number.isInteger(hours) || hours < 1 || hours > MAX_HOURS) return response({ error: `Hours must be a whole number between 1 and ${MAX_HOURS}` }, 400);

		const readPath = (name: string): string | undefined | Response => {
			const raw = url.searchParams.get(name)?.trim() ?? "";
			if (raw.length === 0) return undefined;
			if (raw.length > MAX_PATH_PREFIX) return response({ error: `${name} must be at most ${MAX_PATH_PREFIX} characters` }, 400);
			if (!PATH_PREFIX_PATTERN.test(raw)) return response({ error: `${name} must be an absolute path` }, 400);
			return raw;
		};

		const prefix = readPath("pathPrefix");
		if (prefix instanceof Response) return prefix;
		const exact = readPath("path");
		if (exact instanceof Response) return exact;

		const successfulOnlyRaw = url.searchParams.get("successfulOnly");
		if (successfulOnlyRaw !== null && !["true", "false", "1", "0"].includes(successfulOnlyRaw))
			return response({ error: "successfulOnly must be true or false" }, 400);
		const successfulOnly = successfulOnlyRaw === "true" || successfulOnlyRaw === "1";

		const requestScope =
			prefix === undefined && exact === undefined && !successfulOnly ? undefined : { prefix, exact, successfulOnly: successfulOnly || undefined };

		try {
			return response(await monitoringData(view as MonitoringView, hours, url.searchParams.get("siteId")?.trim() || undefined, undefined, requestScope));
		} catch (error) {
			if (!(error instanceof Error)) throw error;
			if (
				["Unknown site ID", "System views apply to the whole instance (leave Site ID empty)"].includes(error.message) ||
				/pathPrefix|successfulOnly/.test(error.message)
			)
				return response({ error: error.message }, 400);
			throw error;
		}
	});
}
