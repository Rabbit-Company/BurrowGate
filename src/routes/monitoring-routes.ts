import type { Web } from "@rabbit-company/web";
import { repository } from "../db/repository.ts";
import { authenticateApiToken } from "../services/api-token-service.ts";
import { monitoringData, MONITORING_VIEWS, type MonitoringView } from "../services/monitoring-service.ts";
import { jsonResponse } from "../utils/http.ts";

const BASE = "/_burrowgate/api/v1";
const READ_PATHS = new Set([`${BASE}/monitoring`, `${BASE}/sites`]);

function response(data: unknown, status = 200) {
	const result = jsonResponse(data, status);
	result.headers.set("cache-control", "no-store");
	return result;
}

export function registerMonitoringRoutes(app: Web<any>): void {
	app.use(async (ctx, next) => {
		const path = new URL(ctx.req.url).pathname;
		const monitoringCredential = /^Bearer\s+bgro_/i.test(ctx.req.headers.get("authorization") ?? "");
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
		if (![1, 6, 24, 168].includes(hours)) return response({ error: "Hours must be 1, 6, 24, or 168" }, 400);
		try {
			return response(await monitoringData(view as MonitoringView, hours, url.searchParams.get("siteId")?.trim() || undefined));
		} catch (error) {
			if (error instanceof Error && ["Unknown site ID", "System views apply to the whole instance (leave Site ID empty)"].includes(error.message))
				return response({ error: error.message }, 400);
			throw error;
		}
	});
}
