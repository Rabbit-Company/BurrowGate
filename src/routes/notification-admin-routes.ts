import type { Web } from "@rabbit-company/web";
import { getAdminSession } from "../services/session-service.ts";
import { notificationsPage } from "../ui/notifications-page.ts";
import { htmlResponse } from "../utils/http.ts";

export function registerNotificationAdminRoutes(app: Web<any>): void {
	app.get("/_burrowgate/admin/notifications", async (ctx) =>
		(await getAdminSession(ctx.req)) ? htmlResponse(notificationsPage()) : Response.redirect(new URL("/_burrowgate/admin/login", ctx.req.url).href, 302),
	);

	app.get(
		"/_burrowgate/static/notifications-admin.js",
		() =>
			new Response(Bun.file("public/notifications-admin.js"), { headers: { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-store" } }),
	);
}
