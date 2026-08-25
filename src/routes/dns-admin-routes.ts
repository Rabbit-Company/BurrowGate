import type { Web } from "@rabbit-company/web";
import { getClientIp } from "@rabbit-company/web-middleware/ip-extract";
import { recordAdminAudit } from "../services/admin-audit-service.ts";
import { requireAdministrator, resolveAdminUser, type AuthenticatedAdmin } from "../services/admin-permission-service.ts";
import { createDnsProvider, deleteDnsProvider, dnsProviderView, testDnsProvider, updateDnsProvider } from "../services/dns-provider-service.ts";
import { getAdminSession } from "../services/session-service.ts";
import { dnsProvidersPage } from "../ui/dns-providers-page.ts";
import { repository } from "../db/repository.ts";
import { htmlResponse, jsonResponse, sameOriginRequest } from "../utils/http.ts";

async function guard(request: Request): Promise<Response | { user: AuthenticatedAdmin }> {
	const session = await getAdminSession(request);
	const user = session ? await resolveAdminUser(session) : null;
	return user ? { user } : jsonResponse({ error: "Unauthorized" }, 401);
}

function mutationGuard(request: Request): Response | null {
	if (!sameOriginRequest(request) || request.headers.get("x-burrowgate-admin") !== "1") {
		return jsonResponse({ error: "CSRF validation failed" }, 403);
	}
	return null;
}

export function registerDnsAdminRoutes(app: Web<any>): void {
	app.get("/_burrowgate/admin/dns-providers", async (ctx) =>
		(await getAdminSession(ctx.req)) ? htmlResponse(dnsProvidersPage()) : Response.redirect(new URL("/_burrowgate/admin/login", ctx.req.url).href, 302),
	);

	app.get(
		"/_burrowgate/static/dns-providers-admin.js",
		() =>
			new Response(Bun.file("public/dns-providers-admin.js"), {
				headers: { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-store" },
			}),
	);

	app.get("/_burrowgate/api/admin/dns-providers", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const forbidden = requireAdministrator(guarded.user);
		if (forbidden) return forbidden;
		const providers = await repository.allDnsProviders();
		return jsonResponse({ items: providers.map(dnsProviderView) });
	});

	app.post("/_burrowgate/api/admin/dns-providers", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const forbidden = requireAdministrator(user);
		if (forbidden) return forbidden;
		try {
			const record = await createDnsProvider((await ctx.req.json()) as never);
			await recordAdminAudit({
				actor: user,
				action: "dns_provider.create",
				resourceType: "dns_provider",
				resourceId: record.id,
				summary: `Added DNS provider "${record.name}" (${record.type})`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse(dnsProviderView(record), 201);
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to create DNS provider" }, 400);
		}
	});

	app.addRoute("PUT", "/_burrowgate/api/admin/dns-providers/:id", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const forbidden = requireAdministrator(user);
		if (forbidden) return forbidden;
		try {
			const record = await updateDnsProvider(ctx.params.id, (await ctx.req.json()) as never);
			await recordAdminAudit({
				actor: user,
				action: "dns_provider.update",
				resourceType: "dns_provider",
				resourceId: record.id,
				summary: `Updated DNS provider "${record.name}"`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse(dnsProviderView(record));
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to update DNS provider" }, 400);
		}
	});

	app.delete("/_burrowgate/api/admin/dns-providers/:id", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const forbidden = requireAdministrator(user);
		if (forbidden) return forbidden;
		try {
			await deleteDnsProvider(ctx.params.id);
			await recordAdminAudit({
				actor: user,
				action: "dns_provider.delete",
				resourceType: "dns_provider",
				resourceId: ctx.params.id,
				summary: "Deleted DNS provider",
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse({ ok: true });
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to delete DNS provider" }, 400);
		}
	});

	app.post("/_burrowgate/api/admin/dns-providers/:id/test", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const forbidden = requireAdministrator(guarded.user);
		if (forbidden) return forbidden;
		try {
			return jsonResponse(await testDnsProvider(ctx.params.id));
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to test connection" }, 400);
		}
	});
}
