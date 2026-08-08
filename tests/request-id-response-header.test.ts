import { describe, expect, test } from "bun:test";
import { Web } from "@rabbit-company/web";

function nonPropagatingMiddleware(_ctx: unknown, next: () => Promise<Response | void>) {
	return next().then(() => undefined);
}

describe("request ID header survives a non-propagating middleware", () => {
	test("an app.use() middleware placed before it cannot rely on next()'s return value", async () => {
		const app = new Web();
		app.use(async (_ctx, next) => {
			const response = await next();
			if (response) response.headers.set("x-request-id", "should-not-appear");
			return response;
		});
		app.use(nonPropagatingMiddleware);
		app.addRoute("GET", "/broken", async () => new Response("ok"));

		const response = await app.handle(new Request("http://example.test/broken"));
		expect(response.status).toBe(200);
		expect(response.headers.get("x-request-id")).toBeNull();
	});

	test("wrapping the handler directly at registration sets the header reliably", async () => {
		const app = new Web();
		app.use(nonPropagatingMiddleware);
		async function handler() {
			return new Response("ok");
		}
		async function withRequestId() {
			const response = await handler();
			response.headers.set("x-request-id", "generated-id");
			return response;
		}
		app.addRoute("GET", "/fixed", withRequestId);

		const response = await app.handle(new Request("http://example.test/fixed"));
		expect(response.status).toBe(200);
		expect(response.headers.get("x-request-id")).toBe("generated-id");
	});
});
