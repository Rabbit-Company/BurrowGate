import type { Web } from "@rabbit-company/web";
import { challengeRegistry } from "../challenges/index.ts";
import { cookieCanBeIssuedForRequest, insecureCookieConfigurationMessage } from "../config.ts";
import { repository } from "../db/repository.ts";
import { currentStep, verifyFlow } from "../services/challenge-service.ts";
import { challengePage } from "../ui/challenge-page.ts";
import { htmlResponse, jsonResponse } from "../utils/http.ts";

export function registerChallengeRoutes(app: Web<any>): void {
	app.get("/_burrowgate/verify", async (ctx) => {
		if (!cookieCanBeIssuedForRequest(ctx.req)) {
			return htmlResponse(insecureCookieConfigurationMessage(), 409);
		}
		const flowId = new URL(ctx.req.url).searchParams.get("flow");
		if (!flowId) return htmlResponse("Missing challenge flow.", 400);
		const flow = await repository.flow(flowId);
		if (!flow || flow.status !== "pending" || flow.expires_at <= Date.now())
			return htmlResponse("This challenge expired. Return to the website and try again.", 410);
		const step = await currentStep(flow);
		return htmlResponse(challengePage(flow, step, challengeRegistry.get(step.provider)));
	});

	app.post("/_burrowgate/api/challenge/verify", async (ctx) => {
		if (!cookieCanBeIssuedForRequest(ctx.req)) {
			return jsonResponse({ reason: insecureCookieConfigurationMessage() }, 409);
		}
		let body: { flowId?: string; answer?: unknown };
		try {
			body = (await ctx.req.json()) as any;
		} catch {
			return jsonResponse({ reason: "Invalid JSON" }, 400);
		}
		if (!body.flowId) return jsonResponse({ reason: "Missing flowId" }, 400);
		const result = await verifyFlow(ctx.req, body.flowId, body.answer);
		const headers = result.cookie ? { "set-cookie": result.cookie } : undefined;
		return jsonResponse(
			{ done: result.done, redirect: result.redirect, next: Boolean(result.next), reason: result.reason },
			result.reason ? 400 : 200,
			headers,
		);
	});

	app.get(
		"/_burrowgate/static/favicon.svg",
		() =>
			new Response(Bun.file("public/favicon.svg"), { headers: { "content-type": "image/svg+xml; charset=utf-8", "cache-control": "public, max-age=86400" } }),
	);
	app.get(
		"/_burrowgate/static/burrowgate.css",
		() => new Response(Bun.file("public/burrowgate.css"), { headers: { "content-type": "text/css; charset=utf-8", "cache-control": "public, max-age=3600" } }),
	);
	app.get(
		"/_burrowgate/static/pow-worker.js",
		() =>
			new Response(Bun.file("public/pow-worker.js"), {
				headers: { "content-type": "text/javascript; charset=utf-8", "cache-control": "public, max-age=3600" },
			}),
	);
	app.get(
		"/_burrowgate/static/challenges/pow-sha256.js",
		() =>
			new Response(Bun.file("public/challenges/pow-sha256.js"), {
				headers: { "content-type": "text/javascript; charset=utf-8", "cache-control": "public, max-age=3600" },
			}),
	);
}
