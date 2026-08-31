import type { Web } from "@rabbit-company/web";
import { Logger } from "../logger.ts";
import { resolveAdminUser, requireAdministrator, type AuthenticatedAdmin } from "../services/admin-permission-service.ts";
import { dailyFileLogs, type FileLogSettings, type LogLevelName } from "../services/daily-file-log-service.ts";
import { getAdminSession } from "../services/session-service.ts";
import { logPage } from "../ui/log-page.ts";
import { htmlResponse, jsonResponse } from "../utils/http.ts";

async function authenticated(request: Request): Promise<AuthenticatedAdmin | Response> {
	const session = await getAdminSession(request);
	const user = session ? await resolveAdminUser(session) : null;
	return user ?? jsonResponse({ error: "Unauthorized" }, 401);
}

export function registerLogAdminRoutes(app: Web<any>): void {
	app.get("/_burrowgate/admin/logs", async (ctx) =>
		(await getAdminSession(ctx.req)) ? htmlResponse(logPage()) : Response.redirect(new URL("/_burrowgate/admin/login", ctx.req.url).href, 302),
	);

	app.get(
		"/_burrowgate/static/log-admin.js",
		() => new Response(Bun.file("public/log-admin.js"), { headers: { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-store" } }),
	);

	app.get("/_burrowgate/api/admin/logs/settings", async (ctx) => {
		const user = await authenticated(ctx.req);
		if (user instanceof Response) return user;
		return jsonResponse({ ...dailyFileLogs.settings(), directory: dailyFileLogs.directory, canManage: user.role === "administrator" });
	});

	app.put("/_burrowgate/api/admin/logs/settings", async (ctx) => {
		const user = await authenticated(ctx.req);
		if (user instanceof Response) return user;
		const forbidden = requireAdministrator(user);
		if (forbidden) return forbidden;
		try {
			const body = await ctx.body<Partial<FileLogSettings>>();
			const settings = await dailyFileLogs.updateSettings(body);
			Logger.audit("File logging settings changed", { actor: user.username, ...settings });
			return jsonResponse(settings);
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Invalid logging settings" }, 400);
		}
	});

	app.get("/_burrowgate/api/admin/logs", async (ctx) => {
		const user = await authenticated(ctx.req);
		if (user instanceof Response) return user;
		const query = ctx.query();
		try {
			return jsonResponse(
				await dailyFileLogs.query({
					from: Number(query.get("from")),
					to: Number(query.get("to")),
					search: query.get("search") ?? "",
					level: (query.get("level") ?? "") as LogLevelName | "",
					page: Number(query.get("page") ?? 1),
					pageSize: Number(query.get("pageSize") ?? 50),
				}),
			);
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to read logs" }, 400);
		}
	});

	app.get("/_burrowgate/api/admin/logs/archives", async (ctx) => {
		const user = await authenticated(ctx.req);
		if (user instanceof Response) return user;
		return jsonResponse({ items: await dailyFileLogs.archives(), canManage: user.role === "administrator" });
	});

	app.get("/_burrowgate/api/admin/logs/archives/:name", async (ctx) => {
		const user = await authenticated(ctx.req);
		if (user instanceof Response) return user;
		const name = ctx.params.name ?? "";
		const path = await dailyFileLogs.archivePath(name);
		if (!path) return jsonResponse({ error: "Log archive not found" }, 404);
		return new Response(Bun.file(path), {
			headers: { "content-type": "application/gzip", "content-disposition": `attachment; filename="${name}"`, "cache-control": "no-store" },
		});
	});

	app.delete("/_burrowgate/api/admin/logs/archives/:name", async (ctx) => {
		const user = await authenticated(ctx.req);
		if (user instanceof Response) return user;
		const forbidden = requireAdministrator(user);
		if (forbidden) return forbidden;
		const name = ctx.params.name ?? "";
		const deleted = await dailyFileLogs.deleteArchive(name);
		if (!deleted) return jsonResponse({ error: "Log archive not found" }, 404);
		Logger.audit("Compressed log archive deleted", { actor: user.username, archive: name });
		return jsonResponse({ ok: true });
	});
}
