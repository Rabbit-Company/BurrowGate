import { beforeAll, describe, expect, test } from "bun:test";
import { Web } from "@rabbit-company/web";
import { registerMonitoringRoutes } from "../src/routes/monitoring-routes.ts";
import { buildMonitoringOpenApiDocument } from "../src/services/openapi-service.ts";
import { MONITORING_VIEWS } from "../src/services/monitoring-service.ts";
import { createAdminUser } from "../src/services/admin-user-service.ts";
import { createApiToken } from "../src/services/api-token-service.ts";

const app = new Web();
registerMonitoringRoutes(app);

const URL_PATH = "http://gateway.test/_burrowgate/api/v1/openapi.json";

describe("OpenAPI monitoring document", () => {
	let headers: Record<string, string>;

	beforeAll(async () => {
		const admin = await createAdminUser({ username: `mon-doc-${crypto.randomUUID()}`, password: "password123", role: "administrator" }, "test-suite");
		const { token } = await createApiToken(admin.id, { name: "Doc reader", expiresInDays: null, scope: "monitoring" });
		headers = { authorization: `Bearer ${token}` };
	});

	test("the document needs a monitoring token, like the endpoints it describes", async () => {
		expect((await app.handle(new Request(URL_PATH))).status).toBe(401);
	});

	test("a monitoring token can fetch it, and the server URL follows the request origin", async () => {
		const response = await app.handle(new Request(URL_PATH, { headers }));
		expect(response.status).toBe(200);

		const doc = (await response.json()) as ReturnType<typeof buildMonitoringOpenApiDocument>;
		expect(doc.openapi).toBe("3.2.0");
		expect(doc.info.title).toBe("BurrowGate monitoring API");
		expect(doc.servers).toEqual([{ description: "This BurrowGate instance", url: "http://gateway.test" }]);
	});

	test("it advertises only the read-only monitoring credential", async () => {
		const doc = buildMonitoringOpenApiDocument("http://gateway.test");

		expect(Object.keys(doc.components.securitySchemes)).toEqual(["ApiTokenMonitoring"]);
		expect(doc.components.securitySchemes.ApiTokenMonitoring?.bearerFormat).toBe("bgro_...");
		expect(JSON.stringify(doc)).not.toContain("bgat_");
		expect(JSON.stringify(doc)).not.toContain("__Host-bg_admin");
	});

	test("covers every registered v1 endpoint - and nothing else", () => {
		const registered = (app as unknown as { getRoutes(): Array<{ method: string; path: string }> }).getRoutes();
		const liveRoutes = new Set<string>();
		for (const route of registered) {
			if (!route.path.startsWith("/_burrowgate/api/v1")) continue;
			liveRoutes.add(`${route.method} ${route.path.replace(/:([A-Za-z0-9_]+)/g, "{$1}")}`);
		}
		liveRoutes.delete("GET /_burrowgate/api/v1/openapi.json");

		const doc = buildMonitoringOpenApiDocument("http://gateway.test");
		const docRoutes = new Set<string>();
		for (const [path, methods] of Object.entries(doc.paths)) {
			for (const method of Object.keys(methods)) docRoutes.add(`${method.toUpperCase()} ${path}`);
		}

		const missing = [...liveRoutes].filter((route) => !docRoutes.has(route)).sort();
		const extra = [...docRoutes].filter((route) => !liveRoutes.has(route)).sort();
		expect(missing, "Registered v1 routes with no OpenAPI documentation - add them to src/openapi/monitoring.ts").toEqual([]);
		expect(extra, "OpenAPI paths that don't match a registered route - stale or typo'd").toEqual([]);
	});

	test("every $ref resolves to a schema the document defines", () => {
		const doc = buildMonitoringOpenApiDocument("http://gateway.test");
		const defined = new Set(Object.keys(doc.components.schemas));
		const referenced = [...JSON.stringify(doc).matchAll(/"#\/components\/schemas\/([A-Za-z0-9_]+)"/g)].map((match) => match[1]!);

		expect(referenced.length).toBeGreaterThan(0);
		expect([...new Set(referenced)].filter((name) => !defined.has(name)).sort()).toEqual([]);
	});

	test("the documented view list cannot drift from the one the service accepts", () => {
		const doc = buildMonitoringOpenApiDocument("http://gateway.test");
		const parameters = doc.paths["/_burrowgate/api/v1/monitoring"]?.get?.parameters ?? [];
		const view = parameters.find((parameter) => parameter.name === "view");

		expect(view?.schema.enum).toEqual([...MONITORING_VIEWS]);
	});

	test("the document is not writable", async () => {
		const response = await app.handle(new Request(URL_PATH, { method: "POST", headers }));
		expect(response.status).toBe(404);
	});
});
