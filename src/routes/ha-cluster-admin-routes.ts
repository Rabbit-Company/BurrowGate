import type { Web } from "@rabbit-company/web";
import { getClientIp } from "@rabbit-company/web-middleware/ip-extract";
import { config } from "../config.ts";
import { repository } from "../db/repository.ts";
import { Logger } from "../logger.ts";
import { recordAdminAudit } from "../services/admin-audit-service.ts";
import { requireAdministrator, resolveAdminUser, type AuthenticatedAdmin } from "../services/admin-permission-service.ts";
import { joinCluster, leaveCluster, updateNodeIdentity, viewJoinCode } from "../services/ha-config-service.ts";
import { haMeshService, type HaClusterNode } from "../services/ha-mesh-service.ts";
import { processLifecycle } from "../services/process-lifecycle-service.ts";
import { getAdminSession } from "../services/session-service.ts";
import { APP_VERSION } from "../ui/layout.ts";
import { haClusterPage } from "../ui/ha-cluster-page.ts";
import { htmlResponse, jsonResponse, sameOriginRequest } from "../utils/http.ts";
import { forwardToPrimaryIfReplica, tryForwardToPrimary } from "./ha-forward.ts";

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

function scheduleRestartAfterResponse(reason: string): void {
	setTimeout(() => {
		void processLifecycle.gracefulRestart(reason);
	}, 300);
}

export function registerHaClusterAdminRoutes(app: Web<any>): void {
	app.get("/_burrowgate/admin/cluster", async (ctx) =>
		(await getAdminSession(ctx.req)) ? htmlResponse(haClusterPage()) : Response.redirect(new URL("/_burrowgate/admin/login", ctx.req.url).href, 302),
	);

	app.get(
		"/_burrowgate/static/ha-cluster-admin.js",
		() =>
			new Response(Bun.file("public/ha-cluster-admin.js"), {
				headers: { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-store" },
			}),
	);

	app.get("/_burrowgate/api/admin/ha/status", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const forbidden = requireAdministrator(guarded.user);
		if (forbidden) return forbidden;
		if (!config.ha.enabled) return jsonResponse({ enabled: false });
		const forwarded = await tryForwardToPrimary(ctx.req);
		if (forwarded) {
			if (!forwarded.ok) return forwarded;
			const primaryStatus = (await forwarded.json()) as {
				role?: string;
				self: { name: string; version: string; selfAdminUrl: string | null };
				nodes?: HaClusterNode[];
				latestSeq?: number;
				versionCompatible?: boolean;
				versionMismatches?: Array<{ nodeId: string; name: string; version: string }>;
				fencedForPromotion?: boolean;
				authorityFence?: { observedEpoch: number; sourceNodeId: string; observedAt: number } | null;
				stuckPromotionIntent?: { promotionId: string; targetNodeId: string } | null;
				quorumFenced?: boolean;
				autoFailoverEligible?: boolean;
			};

			if (primaryStatus.role !== "primary" || !Array.isArray(primaryStatus.nodes)) {
				Logger.warn("[BurrowGate] HA: this node's configured primary did not answer as a primary - falling back to a local view", {
					primaryAdminUrl: config.ha.primaryAdminUrl,
				});
			} else {
				return jsonResponse({
					enabled: true,
					role: "replica",
					self: { name: config.ha.nodeName, version: APP_VERSION, selfAdminUrl: config.ha.selfAdminUrl },
					connectionState: haMeshService.connectionState(),
					primaryReachable: true,
					primary: primaryStatus.self,
					nodes: primaryStatus.nodes,
					latestSeq: primaryStatus.latestSeq,
					versionCompatible: primaryStatus.versionCompatible,
					versionMismatches: primaryStatus.versionMismatches,
					fencedForPromotion: primaryStatus.fencedForPromotion,
					authorityFence: primaryStatus.authorityFence,
					stuckPromotionIntent: primaryStatus.stuckPromotionIntent,
					quorumFenced: primaryStatus.quorumFenced,
					autoFailoverEligible: primaryStatus.autoFailoverEligible,
				});
			}
		}
		return jsonResponse({ enabled: true, ...(await haMeshService.clusterStatus()) });
	});

	app.get("/_burrowgate/api/admin/ha/dead-letters", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const forbidden = requireAdministrator(guarded.user);
		if (forbidden) return forbidden;
		if (!config.ha.enabled) return jsonResponse({ enabled: false, deadLetters: [] });
		if (config.ha.role === "primary") return jsonResponse({ enabled: true, deadLetters: await repository.recentDeadLetteredRelays(100) });
		const forwarded = await tryForwardToPrimary(ctx.req);
		if (forwarded) return forwarded;
		return jsonResponse({ enabled: true, deadLetters: [] });
	});

	app.addRoute("PUT", "/_burrowgate/api/admin/ha/identity", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const forbidden = requireAdministrator(user);
		if (forbidden) return forbidden;
		try {
			const body = (await ctx.req.json()) as { nodeName?: string; selfAdminUrl?: string };
			if (!body.selfAdminUrl) return jsonResponse({ error: "selfAdminUrl is required" }, 400);
			await updateNodeIdentity({ nodeName: body.nodeName, selfAdminUrl: body.selfAdminUrl });
			await recordAdminAudit({
				actor: user,
				action: "ha.update_identity",
				resourceType: "ha_cluster_config",
				resourceId: "self",
				summary: "Updated this node's HA identity",
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse({ ok: true });
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to update this node's identity" }, 400);
		}
	});

	app.post("/_burrowgate/api/admin/ha/join", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const forbidden = requireAdministrator(user);
		if (forbidden) return forbidden;
		try {
			const body = (await ctx.req.json()) as { joinCode?: string; selfAdminUrl?: string; nodeName?: string };
			if (!body.joinCode || !body.selfAdminUrl) return jsonResponse({ error: "joinCode and selfAdminUrl are required" }, 400);
			await joinCluster({ joinCode: body.joinCode, selfAdminUrl: body.selfAdminUrl, nodeName: body.nodeName });
			await recordAdminAudit({
				actor: user,
				action: "ha.join_cluster",
				resourceType: "ha_cluster_config",
				resourceId: "self",
				summary: "Joined an HA cluster as a replica",
				ip: getClientIp(ctx) ?? "unknown",
			});
			scheduleRestartAfterResponse("ha-config-changed");
			return jsonResponse({ ok: true, restarting: true });
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to join the cluster" }, 400);
		}
	});

	app.post("/_burrowgate/api/admin/ha/leave", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const forbidden = requireAdministrator(user);
		if (forbidden) return forbidden;
		try {
			await leaveCluster();
			await recordAdminAudit({
				actor: user,
				action: "ha.leave_cluster",
				resourceType: "ha_cluster_config",
				resourceId: "self",
				summary: "Left its HA cluster and became a standalone primary",
				ip: getClientIp(ctx) ?? "unknown",
			});
			scheduleRestartAfterResponse("ha-config-changed");
			return jsonResponse({ ok: true, restarting: true });
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to leave the cluster" }, 400);
		}
	});

	app.post("/_burrowgate/api/admin/ha/join-code", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const forbidden = requireAdministrator(guarded.user);
		if (forbidden) return forbidden;
		try {
			return jsonResponse({ joinCode: await viewJoinCode() });
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to produce a join code" }, 400);
		}
	});

	app.addRoute("POST", "/_burrowgate/api/admin/ha/promote/:nodeId", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const forbidden = requireAdministrator(user);
		if (forbidden) return forbidden;
		const forwarded = await forwardToPrimaryIfReplica(ctx.req);
		if (forwarded) return forwarded;
		if (config.ha.role !== "primary") return jsonResponse({ error: "Only the primary can promote a node" }, 400);
		try {
			await haMeshService.promoteNode(ctx.params.nodeId);
			await recordAdminAudit({
				actor: user,
				action: "ha.promote_node",
				resourceType: "ha_cluster_node",
				resourceId: ctx.params.nodeId,
				summary: `Promoted node ${ctx.params.nodeId} to primary`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse({ ok: true, restarting: true });
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to promote node" }, 400);
		}
	});

	app.addRoute("DELETE", "/_burrowgate/api/admin/ha/nodes/:nodeId", async (ctx: any) => {
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
			await haMeshService.forgetNode(ctx.params.nodeId);
			await recordAdminAudit({
				actor: user,
				action: "ha.forget_node",
				resourceType: "ha_cluster_node",
				resourceId: ctx.params.nodeId,
				summary: `Forgot offline HA node ${ctx.params.nodeId}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse({ ok: true });
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to forget cluster node" }, 400);
		}
	});
}
