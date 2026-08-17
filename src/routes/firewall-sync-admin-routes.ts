import type { Web } from "@rabbit-company/web";
import { getClientIp } from "@rabbit-company/web-middleware/ip-extract";
import { recordAdminAudit } from "../services/admin-audit-service.ts";
import { requireAdministrator, resolveAdminUser, type AuthenticatedAdmin } from "../services/admin-permission-service.ts";
import {
	addFirewallSyncWhitelistCidr,
	aggregateBannedCidrsDetailed,
	createFirewallSyncProvider,
	firewallSyncProviderView,
	firewallSyncService,
	listFirewallSyncWhitelistCidrs,
	removeFirewallSyncWhitelistCidr,
	updateFirewallSyncProvider,
} from "../services/firewall-sync-service.ts";
import { awsListNacls } from "../services/firewall-sync/aws-nacl-adapter.ts";
import { ovhListIps, ovhRequestCredential } from "../services/firewall-sync/ovh-adapter.ts";
import { unifiListSites } from "../services/firewall-sync/unifi-adapter.ts";
import { getAdminSession } from "../services/session-service.ts";
import { firewallSyncPage } from "../ui/firewall-sync-page.ts";
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

export function registerFirewallSyncAdminRoutes(app: Web<any>): void {
	app.get("/_burrowgate/admin/firewall-sync", async (ctx) =>
		(await getAdminSession(ctx.req)) ? htmlResponse(firewallSyncPage()) : Response.redirect(new URL("/_burrowgate/admin/login", ctx.req.url).href, 302),
	);

	app.get(
		"/_burrowgate/static/firewall-sync-admin.js",
		() =>
			new Response(Bun.file("public/firewall-sync-admin.js"), {
				headers: { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-store" },
			}),
	);

	app.get("/_burrowgate/api/admin/firewall-sync/whoami", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const forbidden = requireAdministrator(guarded.user);
		if (forbidden) return forbidden;
		return jsonResponse({ ip: getClientIp(ctx) ?? null });
	});

	app.post("/_burrowgate/api/admin/firewall-sync/providers/unifi/sites", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const forbidden = requireAdministrator(guarded.user);
		if (forbidden) return forbidden;
		try {
			const body = (await ctx.req.json()) as { controllerUrl?: string; apiBasePath?: string; verifyTls?: boolean; apiKey?: string; providerId?: string };
			const existing = body.providerId ? await repository.firewallSyncProviderById(body.providerId) : null;
			const sites = await unifiListSites({
				controllerUrl: String(body.controllerUrl ?? ""),
				apiBasePath: String(body.apiBasePath ?? ""),
				verifyTls: body.verifyTls !== false,
				apiKey: body.apiKey,
				existingConfigJson: existing?.config_json ?? null,
			});
			return jsonResponse({ items: sites });
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to list sites" }, 400);
		}
	});

	app.post("/_burrowgate/api/admin/firewall-sync/providers/ovh/ips", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const forbidden = requireAdministrator(guarded.user);
		if (forbidden) return forbidden;
		try {
			const body = (await ctx.req.json()) as {
				endpoint?: string;
				applicationKey?: string;
				applicationSecret?: string;
				consumerKey?: string;
				providerId?: string;
			};
			const existing = body.providerId ? await repository.firewallSyncProviderById(body.providerId) : null;
			const ips = await ovhListIps({
				endpoint: String(body.endpoint ?? ""),
				applicationKey: String(body.applicationKey ?? ""),
				applicationSecret: body.applicationSecret,
				consumerKey: body.consumerKey,
				existingConfigJson: existing?.config_json ?? null,
			});
			return jsonResponse({ items: ips });
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to list IPs" }, 400);
		}
	});

	app.post("/_burrowgate/api/admin/firewall-sync/providers/ovh/credential", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const forbidden = requireAdministrator(guarded.user);
		if (forbidden) return forbidden;
		try {
			const body = (await ctx.req.json()) as { endpoint?: string; applicationKey?: string };
			const result = await ovhRequestCredential(String(body.endpoint ?? ""), String(body.applicationKey ?? ""));
			return jsonResponse(result);
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to request a consumer key" }, 400);
		}
	});

	app.post("/_burrowgate/api/admin/firewall-sync/providers/aws-nacl/network-acls", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const forbidden = requireAdministrator(guarded.user);
		if (forbidden) return forbidden;
		try {
			const body = (await ctx.req.json()) as {
				region?: string;
				accessKeyId?: string;
				secretAccessKey?: string;
				sessionToken?: string;
				providerId?: string;
			};
			const existing = body.providerId ? await repository.firewallSyncProviderById(body.providerId) : null;
			const items = await awsListNacls({
				region: String(body.region ?? ""),
				accessKeyId: String(body.accessKeyId ?? ""),
				secretAccessKey: body.secretAccessKey,
				sessionToken: body.sessionToken,
				existingConfigJson: existing?.config_json ?? null,
			});
			return jsonResponse({ items });
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to list Network ACLs" }, 400);
		}
	});

	app.get("/_burrowgate/api/admin/firewall-sync/preview", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const forbidden = requireAdministrator(guarded.user);
		if (forbidden) return forbidden;
		const detail = await aggregateBannedCidrsDetailed();
		return jsonResponse({
			totalCount: detail.bannable.length,
			sample: detail.bannable.slice(0, 20),
			totalActiveCount: detail.totalActiveCount,
			excludedPrivateCount: detail.excludedPrivateCount,
			excludedWhitelistedCount: detail.excludedWhitelistedCount,
		});
	});

	app.get("/_burrowgate/api/admin/firewall-sync/providers", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const forbidden = requireAdministrator(guarded.user);
		if (forbidden) return forbidden;
		const providers = await repository.allFirewallSyncProviders();
		return jsonResponse({ items: providers.map(firewallSyncProviderView) });
	});

	app.post("/_burrowgate/api/admin/firewall-sync/providers", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const forbidden = requireAdministrator(user);
		if (forbidden) return forbidden;
		try {
			const record = await createFirewallSyncProvider((await ctx.req.json()) as never);
			await recordAdminAudit({
				actor: user,
				action: "firewall_sync_provider.create",
				resourceType: "firewall_sync_provider",
				resourceId: record.id,
				summary: `Added firewall sync provider "${record.name}" (${record.type})`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse(firewallSyncProviderView(record), 201);
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to create provider" }, 400);
		}
	});

	app.addRoute("PUT", "/_burrowgate/api/admin/firewall-sync/providers/:id", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const forbidden = requireAdministrator(user);
		if (forbidden) return forbidden;
		try {
			const record = await updateFirewallSyncProvider(ctx.params.id, (await ctx.req.json()) as never);
			await recordAdminAudit({
				actor: user,
				action: "firewall_sync_provider.update",
				resourceType: "firewall_sync_provider",
				resourceId: record.id,
				summary: `Updated firewall sync provider "${record.name}"`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse(firewallSyncProviderView(record));
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to update provider" }, 400);
		}
	});

	app.delete("/_burrowgate/api/admin/firewall-sync/providers/:id", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const forbidden = requireAdministrator(user);
		if (forbidden) return forbidden;
		const { teardownError } = await firewallSyncService.deleteProvider(ctx.params.id);
		await recordAdminAudit({
			actor: user,
			action: "firewall_sync_provider.delete",
			resourceType: "firewall_sync_provider",
			resourceId: ctx.params.id,
			summary: teardownError ? `Deleted firewall sync provider (remote cleanup failed: ${teardownError})` : "Deleted firewall sync provider",
			ip: getClientIp(ctx) ?? "unknown",
		});
		return jsonResponse({ ok: true, teardownError });
	});

	app.post("/_burrowgate/api/admin/firewall-sync/providers/:id/test", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const forbidden = requireAdministrator(guarded.user);
		if (forbidden) return forbidden;
		try {
			return jsonResponse(await firewallSyncService.testConnection(ctx.params.id));
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to test connection" }, 400);
		}
	});

	app.post("/_burrowgate/api/admin/firewall-sync/providers/:id/sync-now", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const forbidden = requireAdministrator(guarded.user);
		if (forbidden) return forbidden;
		try {
			await firewallSyncService.syncNow(ctx.params.id);
			return jsonResponse({ ok: true });
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to sync now" }, 400);
		}
	});

	app.get("/_burrowgate/api/admin/firewall-sync/whitelist", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const forbidden = requireAdministrator(guarded.user);
		if (forbidden) return forbidden;
		return jsonResponse({ items: await listFirewallSyncWhitelistCidrs() });
	});

	app.post("/_burrowgate/api/admin/firewall-sync/whitelist", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const forbidden = requireAdministrator(user);
		if (forbidden) return forbidden;
		try {
			const body = (await ctx.req.json()) as { networkCidr?: string; note?: string };
			const entry = await addFirewallSyncWhitelistCidr(String(body.networkCidr ?? ""), body.note ?? null);
			await recordAdminAudit({
				actor: user,
				action: "firewall_sync_whitelist.create",
				resourceType: "firewall_sync_whitelist_cidr",
				resourceId: entry.id,
				summary: `Added firewall sync whitelist entry ${entry.networkCidr}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse(entry, 201);
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to add whitelist entry" }, 400);
		}
	});

	app.delete("/_burrowgate/api/admin/firewall-sync/whitelist/:id", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const forbidden = requireAdministrator(user);
		if (forbidden) return forbidden;
		await removeFirewallSyncWhitelistCidr(ctx.params.id);
		await recordAdminAudit({
			actor: user,
			action: "firewall_sync_whitelist.delete",
			resourceType: "firewall_sync_whitelist_cidr",
			resourceId: ctx.params.id,
			summary: "Removed firewall sync whitelist entry",
			ip: getClientIp(ctx) ?? "unknown",
		});
		return jsonResponse({ ok: true });
	});
}
