import { demoConfig } from "./config.ts";

const directory = import.meta.dir;
const index = Bun.file(`${directory}/public/index.html`);
const application = Bun.file(`${directory}/public/app.js`);

export const frontendServer = Bun.serve({
	port: demoConfig.frontendPort,
	async fetch(request) {
		const url = new URL(request.url);
		if (request.method === "GET" && url.pathname === "/") {
			return new Response(index, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
		}
		if (request.method === "GET" && url.pathname === "/app.js") {
			return new Response(application, { headers: { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-store" } });
		}
		if (request.method === "GET" && url.pathname === "/demo-config") {
			return Response.json(
				{
					backendOrigin: demoConfig.backendPublicOrigin,
					cacheTtlMs: demoConfig.cacheTtlMs,
					allowedFrontendOrigins: demoConfig.allowedFrontendOrigins,
				},
				{ headers: { "cache-control": "no-store" } },
			);
		}
		if (request.method === "GET" && url.pathname === "/health") return Response.json({ status: "ok", service: "frontend" });
		return Response.json({ error: "Not found" }, { status: 404 });
	},
});

console.log(`[cross-site-auth] Frontend origin: http://127.0.0.1:${frontendServer.port}`);
console.log(`[cross-site-auth] Open through BurrowGate: ${demoConfig.frontendPublicOrigin}`);
