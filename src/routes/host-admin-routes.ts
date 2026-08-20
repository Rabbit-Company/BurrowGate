import type { Web } from "@rabbit-company/web";
import { resolveAdminUser } from "../services/admin-permission-service.ts";
import { connectivityMonitor } from "../services/connectivity-monitor-service.ts";
import { getAdminSession } from "../services/session-service.ts";
import { systemMonitor } from "../services/system-monitor-service.ts";
import { hostPage } from "../ui/host-page.ts";
import { htmlResponse, jsonResponse } from "../utils/http.ts";

async function guard(request: Request): Promise<Response | true> {
	const session = await getAdminSession(request);
	const user = session ? await resolveAdminUser(session) : null;
	return user ? true : jsonResponse({ error: "Unauthorized" }, 401);
}

export function registerHostAdminRoutes(app: Web<any>): void {
	app.get("/_burrowgate/admin/host", async (ctx) =>
		(await getAdminSession(ctx.req)) ? htmlResponse(hostPage()) : Response.redirect(new URL("/_burrowgate/admin/login", ctx.req.url).href, 302),
	);

	app.get(
		"/_burrowgate/static/host-admin.js",
		() =>
			new Response(Bun.file("public/host-admin.js"), {
				headers: { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-store" },
			}),
	);

	app.get("/_burrowgate/api/admin/host/current", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded !== true) return guarded;
		const latest = systemMonitor.getLatestSample();
		return jsonResponse({
			sampledAt: latest?.sampledAt ?? null,
			cpu: { pct: latest?.sample.cpuPct ?? null },
			memory: { usedBytes: latest?.sample.memoryUsedBytes ?? null, totalBytes: latest?.sample.memoryTotalBytes ?? null },
			disk: { usedBytes: latest?.sample.diskUsedBytes ?? null, totalBytes: latest?.sample.diskTotalBytes ?? null },
			network: { rxBps: latest?.sample.networkRxBps ?? null, txBps: latest?.sample.networkTxBps ?? null },
			connectivity: connectivityMonitor.getLatestPings(),
		});
	});
}
