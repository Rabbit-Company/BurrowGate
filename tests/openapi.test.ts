import { describe, expect, test } from "bun:test";
import { Web } from "@rabbit-company/web";
import { registerAdminRoutes } from "../src/routes/admin-routes.ts";
import { registerStreamAdminRoutes } from "../src/routes/stream-admin-routes.ts";
import { registerFirewallSyncAdminRoutes } from "../src/routes/firewall-sync-admin-routes.ts";
import { registerDnsAdminRoutes } from "../src/routes/dns-admin-routes.ts";
import { registerHaClusterAdminRoutes } from "../src/routes/ha-cluster-admin-routes.ts";
import { registerLogAdminRoutes } from "../src/routes/log-admin-routes.ts";
import { registerHostAdminRoutes } from "../src/routes/host-admin-routes.ts";
import { createAdminUser } from "../src/services/admin-user-service.ts";
import { createAdminSession } from "../src/services/session-service.ts";
import { buildOpenApiDocument } from "../src/services/openapi-service.ts";
import { withRequestTransport } from "../src/config.ts";

const app = new Web();
registerAdminRoutes(app);
registerStreamAdminRoutes(app);
registerFirewallSyncAdminRoutes(app);
registerDnsAdminRoutes(app);
registerHaClusterAdminRoutes(app);
registerLogAdminRoutes(app);
registerHostAdminRoutes(app);
const BASE = "http://admin.test/_burrowgate/api";

function collectRefs(node: unknown, refs: Set<string>): void {
	if (Array.isArray(node)) {
		for (const item of node) collectRefs(item, refs);
		return;
	}
	if (node && typeof node === "object") {
		for (const [key, value] of Object.entries(node)) {
			if (key === "$ref" && typeof value === "string") refs.add(value);
			else collectRefs(value, refs);
		}
	}
}

describe("OpenAPI admin document", () => {
	test("requires authentication", async () => {
		expect((await app.handle(new Request(`${BASE}/admin/openapi.json`))).status).toBe(401);
	});

	test("is well-formed and self-consistent", async () => {
		const user = await createAdminUser({ username: `openapi-${crypto.randomUUID()}`, password: "password123", role: "administrator" }, "test-suite");
		const { cookie } = await createAdminSession(new Request("http://admin.test/"), user.username, user.id);
		const response = await app.handle(new Request(`${BASE}/admin/openapi.json`, { headers: { cookie: cookie.split(";")[0]! } }));
		expect(response.status).toBe(200);
		const doc = (await response.json()) as ReturnType<typeof buildOpenApiDocument>;
		expect(doc.openapi).toBe("3.2.0");
		expect(doc.servers).toEqual([{ description: "This BurrowGate instance", url: "http://admin.test" }]);
		expect(doc.security).toEqual([{ AdminSession: [] }, { AdminSessionHttp: [] }, { ApiTokenFull: [] }]);
		expect(doc.components.securitySchemes.AdminSession?.name).toBe("__Host-bg_admin");
		expect(doc.components.securitySchemes.AdminSessionHttp?.name).toBe("bg_admin");
		expect(Object.keys(doc.paths).length).toBeGreaterThan(100);
		expect(JSON.stringify(doc)).not.toContain('"nullable"');

		const refs = new Set<string>();
		collectRefs(doc.paths, refs);
		collectRefs(doc.components.schemas, refs);
		for (const pointer of refs) {
			const name = pointer.replace("#/components/schemas/", "");
			expect(doc.components.schemas[name], `Dangling $ref: ${pointer}`).toBeDefined();
		}

		const schemeNames = new Set(Object.keys(doc.components.securitySchemes));
		for (const [path, methods] of Object.entries(doc.paths)) {
			for (const [method, operation] of Object.entries(methods)) {
				for (const requirement of operation.security ?? []) {
					for (const name of Object.keys(requirement)) {
						expect(schemeNames.has(name), `${method.toUpperCase()} ${path} references unknown security scheme ${name}`).toBe(true);
					}
				}
			}
		}
	});

	test("advertises the request's host and listener transport without caching either", async () => {
		const user = await createAdminUser({ username: `openapi-origin-${crypto.randomUUID()}`, password: "password123", role: "administrator" }, "test-suite");
		const { cookie } = await createAdminSession(new Request("http://admin.test/"), user.username, user.id);
		const headers = { cookie: cookie.split(";")[0]! };

		const secureResponse = await withRequestTransport("https", () =>
			app.handle(new Request("http://api.example.test:8443/_burrowgate/api/admin/openapi.json", { headers })),
		);
		const secureDoc = (await secureResponse.json()) as ReturnType<typeof buildOpenApiDocument>;
		expect(secureDoc.servers[0]?.url).toBe("https://api.example.test:8443");

		const otherResponse = await app.handle(new Request("http://other.example.test/_burrowgate/api/admin/openapi.json", { headers }));
		const otherDoc = (await otherResponse.json()) as ReturnType<typeof buildOpenApiDocument>;
		expect(otherDoc.servers[0]?.url).toBe("http://other.example.test");
		expect(Object.keys(otherDoc.paths)[0]).toStartWith("/_burrowgate/api/admin/");
	});

	test("covers every registered admin JSON endpoint - and nothing else", () => {
		const registered = (app as unknown as { getRoutes(): Array<{ method: string; path: string }> }).getRoutes();
		const liveRoutes = new Set<string>();
		for (const route of registered) {
			if (!route.path.startsWith("/_burrowgate/api/admin")) continue;
			liveRoutes.add(`${route.method} ${route.path.replace(/:([A-Za-z0-9_]+)/g, "{$1}")}`);
		}
		liveRoutes.delete("GET /_burrowgate/api/admin/openapi.json");

		const doc = buildOpenApiDocument("http://admin.test");
		const docRoutes = new Set<string>();
		for (const [path, methods] of Object.entries(doc.paths)) {
			for (const method of Object.keys(methods)) docRoutes.add(`${method.toUpperCase()} ${path}`);
		}

		const missing = [...liveRoutes].filter((route) => !docRoutes.has(route)).sort();
		const extra = [...docRoutes].filter((route) => !liveRoutes.has(route)).sort();
		expect(missing, "Registered routes with no OpenAPI documentation - add them to src/openapi/paths/*.ts").toEqual([]);
		expect(extra, "OpenAPI paths that don't match a registered route - stale or typo'd").toEqual([]);
	});
});
