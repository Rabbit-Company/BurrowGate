import type { Web } from "@rabbit-company/web";
import { repository } from "../db/repository.ts";
import { normalizeHost, requestHost } from "../utils/http.ts";

function challengeResponse(value: string): Response {
	return new Response(value, {
		status: 200,
		headers: {
			"content-type": "text/plain; charset=utf-8",
			"cache-control": "no-store",
			"x-content-type-options": "nosniff",
		},
	});
}

export function registerAcmeRoutes(app: Web<any>): void {
	const handler = async (ctx: any): Promise<Response> => {
		const hostname = normalizeHost(requestHost(ctx.req).replace(/:\d+$/u, ""));
		const token = String(ctx.params.token ?? "");
		if (!token || token.length > 512) return new Response("Not found", { status: 404 });
		const challenge = await repository.acmeChallenge(token, hostname);
		if (!challenge) return new Response("Not found", { status: 404 });
		return challengeResponse(challenge.key_authorization);
	};
	app.get("/.well-known/acme-challenge/:token", handler);
	app.head("/.well-known/acme-challenge/:token", handler);
}
