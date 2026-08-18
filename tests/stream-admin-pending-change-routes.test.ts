import { describe, expect, test } from "bun:test";
import { Web } from "@rabbit-company/web";
import { repository } from "../src/db/repository.ts";
import { registerStreamAdminRoutes } from "../src/routes/stream-admin-routes.ts";
import { createAdminUser } from "../src/services/admin-user-service.ts";
import { registerPendingChangeApplier } from "../src/services/pending-change-service.ts";
import { createAdminSession } from "../src/services/session-service.ts";
import { applyPendingStreamChange } from "../src/services/stream-service.ts";

const app = new Web();
registerStreamAdminRoutes(app);
registerPendingChangeApplier("stream", applyPendingStreamChange);

async function administratorCookie(): Promise<string> {
	const user = await createAdminUser({ username: `stream-admin-${crypto.randomUUID()}`, password: "password123", role: "administrator" }, "test-suite");
	const { cookie } = await createAdminSession(new Request("http://admin.test/"), user.username, user.id);
	return cookie.split(";")[0]!;
}

function req(path: string, cookie: string, init: RequestInit = {}): Request {
	const headers: Record<string, string> = { cookie, ...(init.headers as Record<string, string>) };
	if (init.method && init.method !== "GET") headers["x-burrowgate-admin"] = "1";
	return new Request(`http://admin.test/_burrowgate/api/admin/streams${path}`, { ...init, headers });
}

async function createStream(cookie: string, overrides: Record<string, unknown> = {}): Promise<{ id: string; incomingPort: number }> {
	const port = 50_000 + Math.floor(Math.random() * 10_000);
	const response = await app.handle(
		req("", cookie, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ name: "Test stream", incomingPort: port, forwardHost: "localhost", forwardPort: port + 1, ...overrides }),
		}),
	);
	expect(response.status).toBe(201);
	const body = (await response.json()) as { stream: { id: string; incomingPort: number } };
	return body.stream;
}

describe("stream pending-change routes", () => {
	test("a live-appliable edit applies immediately with no pending change", async () => {
		const cookie = await administratorCookie();
		const stream = await createStream(cookie);

		const response = await app.handle(
			req(`/${stream.id}`, cookie, {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ name: "Renamed", incomingPort: stream.incomingPort, forwardHost: "localhost", forwardPort: 1, maxConnectionsPerIp: 7 }),
			}),
		);
		expect(response.status).toBe(200);
		const body = (await response.json()) as { stream: { name: string; maxConnectionsPerIp: number }; pendingChange: unknown };
		expect(body.pendingChange).toBeNull();
		expect(body.stream.maxConnectionsPerIp).toBe(7);
	});

	test("a restart-required edit with a future effectiveAt stages it and leaves the live port unchanged", async () => {
		const cookie = await administratorCookie();
		const stream = await createStream(cookie);
		const newPort = stream.incomingPort + 1;
		const effectiveAt = Date.now() + 3_600_000;

		const putResponse = await app.handle(
			req(`/${stream.id}`, cookie, {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ name: "Test stream", incomingPort: newPort, forwardHost: "localhost", forwardPort: newPort + 1, effectiveAt }),
			}),
		);
		expect(putResponse.status).toBe(200);
		const putBody = (await putResponse.json()) as { stream: { incomingPort: number }; pendingChange: { applyAt: number; changes: Record<string, unknown> } };
		expect(putBody.stream.incomingPort).toBe(stream.incomingPort);
		expect(putBody.pendingChange.applyAt).toBe(effectiveAt);
		expect(putBody.pendingChange.changes.incoming_port).toBe(newPort);

		const live = await repository.streamById(stream.id);
		expect(live?.incoming_port).toBe(stream.incomingPort);

		const listResponse = await app.handle(req("", cookie));
		const listBody = (await listResponse.json()) as { pendingChanges: Array<{ entityId: string }> };
		expect(listBody.pendingChanges.some((change) => change.entityId === stream.id)).toBe(true);
	});

	test("rejects a second scheduled change while one is already pending", async () => {
		const cookie = await administratorCookie();
		const stream = await createStream(cookie);
		const effectiveAt = Date.now() + 3_600_000;
		await app.handle(
			req(`/${stream.id}`, cookie, {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					name: "Test stream",
					incomingPort: stream.incomingPort + 1,
					forwardHost: "localhost",
					forwardPort: stream.incomingPort + 2,
					effectiveAt,
				}),
			}),
		);

		const secondResponse = await app.handle(
			req(`/${stream.id}`, cookie, {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					name: "Test stream",
					incomingPort: stream.incomingPort + 2,
					forwardHost: "localhost",
					forwardPort: stream.incomingPort + 3,
					effectiveAt: effectiveAt + 60_000,
				}),
			}),
		);
		expect(secondResponse.status).toBe(400);
		const body = (await secondResponse.json()) as { error: string };
		expect(body.error).toMatch(/already scheduled/);
	});

	test("apply-now applies the change immediately and clears the pending row", async () => {
		const cookie = await administratorCookie();
		const stream = await createStream(cookie);
		const newPort = stream.incomingPort + 1;
		await app.handle(
			req(`/${stream.id}`, cookie, {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					name: "Test stream",
					incomingPort: newPort,
					forwardHost: "localhost",
					forwardPort: newPort + 1,
					effectiveAt: Date.now() + 3_600_000,
				}),
			}),
		);

		const applyNowResponse = await app.handle(req(`/${stream.id}/pending-change/apply-now`, cookie, { method: "POST" }));
		expect(applyNowResponse.status).toBe(200);
		const live = await repository.streamById(stream.id);
		expect(live?.incoming_port).toBe(newPort);

		const listResponse = await app.handle(req("", cookie));
		const listBody = (await listResponse.json()) as { pendingChanges: Array<{ entityId: string }> };
		expect(listBody.pendingChanges.some((change) => change.entityId === stream.id)).toBe(false);
	});

	test("a failed change is visible in the list and can be retried or dismissed via the routes", async () => {
		const cookie = await administratorCookie();
		const stream = await createStream(cookie);
		const newPort = stream.incomingPort + 1;
		const putResponse = await app.handle(
			req(`/${stream.id}`, cookie, {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					name: "Test stream",
					incomingPort: newPort,
					forwardHost: "localhost",
					forwardPort: newPort + 1,
					effectiveAt: Date.now() + 3_600_000,
				}),
			}),
		);
		const putBody = (await putResponse.json()) as { pendingChange: { id: string } };
		await repository.updatePendingChangeStatus(putBody.pendingChange.id, "failed", 5, Date.now(), "port already in use", null);

		const listResponse = await app.handle(req("", cookie));
		const listBody = (await listResponse.json()) as { pendingChanges: Array<{ entityId: string; status: string }> };
		const listed = listBody.pendingChanges.find((change) => change.entityId === stream.id);
		expect(listed?.status).toBe("failed");

		// A fresh scheduled edit isn't blocked by the stale failed row.
		const secondPut = await app.handle(
			req(`/${stream.id}`, cookie, {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					name: "Test stream",
					incomingPort: newPort + 2,
					forwardHost: "localhost",
					forwardPort: newPort + 3,
					effectiveAt: Date.now() + 3_600_000,
				}),
			}),
		);
		expect(secondPut.status).toBe(200);

		const cancelResponse = await app.handle(req(`/${stream.id}/pending-change`, cookie, { method: "DELETE" }));
		expect(cancelResponse.status).toBe(200);
		const afterCancel = await app.handle(req("", cookie));
		const afterCancelBody = (await afterCancel.json()) as { pendingChanges: Array<{ entityId: string }> };
		expect(afterCancelBody.pendingChanges.some((change) => change.entityId === stream.id)).toBe(false);
	});

	test("cancelling a pending change leaves the live stream unchanged", async () => {
		const cookie = await administratorCookie();
		const stream = await createStream(cookie);
		const newPort = stream.incomingPort + 1;
		await app.handle(
			req(`/${stream.id}`, cookie, {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					name: "Test stream",
					incomingPort: newPort,
					forwardHost: "localhost",
					forwardPort: newPort + 1,
					effectiveAt: Date.now() + 3_600_000,
				}),
			}),
		);

		const cancelResponse = await app.handle(req(`/${stream.id}/pending-change`, cookie, { method: "DELETE" }));
		expect(cancelResponse.status).toBe(200);
		const live = await repository.streamById(stream.id);
		expect(live?.incoming_port).toBe(stream.incomingPort);
	});
});
