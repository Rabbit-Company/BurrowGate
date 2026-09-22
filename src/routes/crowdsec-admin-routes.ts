import type { Web } from "@rabbit-company/web";
import { getClientIp } from "@rabbit-company/web-middleware/ip-extract";
import { recordAdminAudit } from "../services/admin-audit-service.ts";
import { requireAdministrator, resolveRequestAdmin, type AuthenticatedAdmin } from "../services/admin-permission-service.ts";
import { isFullAccessTokenRequest } from "../services/api-token-service.ts";
import { crowdSecService, saveCrowdSecSettings } from "../services/crowdsec-service.ts";
import { testAppSecConnection } from "../services/crowdsec-appsec-service.ts";
import { asnForStorage, countryCodeForStorage } from "../services/geoip-service.ts";
import { withDurability } from "../services/ha-mesh-service.ts";
import { getAdminSession } from "../services/session-service.ts";
import { crowdSecPage } from "../ui/crowdsec-page.ts";
import { htmlResponse, jsonResponse, sameOriginRequest } from "../utils/http.ts";
import { forwardToPrimaryIfReplica } from "./ha-forward.ts";

async function guard(request: Request): Promise<Response | { user: AuthenticatedAdmin }> {
	const user = await resolveRequestAdmin(request);
	return user ? { user } : jsonResponse({ error: "Unauthorized" }, 401);
}

function mutationGuard(request: Request): Response | null {
	if (isFullAccessTokenRequest(request)) return null;
	if (!sameOriginRequest(request) || request.headers.get("x-burrowgate-admin") !== "1") {
		return jsonResponse({ error: "CSRF validation failed" }, 403);
	}
	return null;
}

export function registerCrowdSecAdminRoutes(app: Web<any>): void {
	app.get("/_burrowgate/admin/crowdsec", async (ctx) =>
		(await getAdminSession(ctx.req)) ? htmlResponse(crowdSecPage()) : Response.redirect(new URL("/_burrowgate/admin/login", ctx.req.url).href, 302),
	);

	app.get(
		"/_burrowgate/static/crowdsec-admin.js",
		() =>
			new Response(Bun.file("public/crowdsec-admin.js"), {
				headers: { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-store" },
			}),
	);

	/** The bouncer API key is never returned, only whether one is stored. */
	app.get("/_burrowgate/api/admin/crowdsec/status", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const forbidden = requireAdministrator(guarded.user);
		if (forbidden) return forbidden;
		return jsonResponse(crowdSecService.status());
	});

	app.put("/_burrowgate/api/admin/crowdsec/settings", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const forbidden = requireAdministrator(user);
		if (forbidden) return forbidden;
		const forwarded = await forwardToPrimaryIfReplica(ctx.req);
		if (forwarded) return forwarded;
		try {
			const body = (await ctx.req.json()) as Record<string, unknown>;
			const status = await saveCrowdSecSettings(body);
			await recordAdminAudit({
				actor: user,
				action: "crowdsec.settings.update",
				resourceType: "crowdsec_settings",
				resourceId: "instance",
				summary: status.enabled ? `Enabled the CrowdSec integration against ${status.lapiUrl}` : "Disabled the CrowdSec integration",
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse(await withDurability(status));
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to save the CrowdSec settings" }, 400);
		}
	});

	/** Validates a candidate LAPI URL and key without storing either. */
	app.post("/_burrowgate/api/admin/crowdsec/test", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const forbidden = requireAdministrator(guarded.user);
		if (forbidden) return forbidden;
		try {
			const body = (await ctx.req.json()) as { lapiUrl?: string; apiKey?: string; verifyTls?: boolean };
			// Omitting the key falls back to the stored one, so editing a saved connection does not
			// require retyping a credential the server already has.
			const result = await crowdSecService.testConnection(String(body.lapiUrl ?? ""), body.apiKey ?? null, body.verifyTls !== false);
			return jsonResponse(result);
		} catch (error) {
			return jsonResponse({ ok: false, message: error instanceof Error ? error.message : "Unable to reach the Local API" }, 400);
		}
	});

	/** Validates a candidate AppSec endpoint without storing it. */
	app.post("/_burrowgate/api/admin/crowdsec/appsec/test", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const forbidden = requireAdministrator(guarded.user);
		if (forbidden) return forbidden;
		try {
			const body = (await ctx.req.json()) as { appsecUrl?: string; apiKey?: string; verifyTls?: boolean };
			if (!body.appsecUrl) return jsonResponse({ ok: false, message: "Enter the AppSec URL to test it" }, 400);
			const apiKey = await crowdSecService.resolveApiKey(body.apiKey);
			if (!apiKey) return jsonResponse({ ok: false, message: "No bouncer API key is configured yet. AppSec uses the same key as the Local API." }, 400);
			return jsonResponse(await testAppSecConnection(String(body.appsecUrl), apiKey, body.verifyTls !== false));
		} catch (error) {
			return jsonResponse({ ok: false, message: error instanceof Error ? error.message : "Unable to reach AppSec" }, 400);
		}
	});

	/** Not forwarded to the primary: decisions are node-local, so this refreshes whichever node answers. */
	app.post("/_burrowgate/api/admin/crowdsec/refresh", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const forbidden = requireAdministrator(guarded.user);
		if (forbidden) return forbidden;
		await crowdSecService.refreshNow();
		return jsonResponse(crowdSecService.status());
	});

	/** Answers "is this address currently decided against?" for the admin lookup box. */
	app.get("/_burrowgate/api/admin/crowdsec/lookup", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const forbidden = requireAdministrator(guarded.user);
		if (forbidden) return forbidden;
		const ip = new URL(ctx.req.url).searchParams.get("ip")?.trim();
		if (!ip) return jsonResponse({ error: "Provide an ip query parameter" }, 400);
		const { asn } = asnForStorage(ip);
		const countryCode = countryCodeForStorage(ip);
		const decision = crowdSecService.lookup(ip, countryCode, asn);
		return jsonResponse({ ip, countryCode, asn, decision });
	});
}
