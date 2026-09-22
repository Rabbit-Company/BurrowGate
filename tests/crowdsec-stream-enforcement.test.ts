import { afterEach, describe, expect, test } from "bun:test";
import { createConnection, type Socket } from "node:net";
import { repository } from "../src/db/repository.ts";
import { crowdSecDecisions, type RawCrowdSecDecision } from "../src/services/crowdsec-decision-store.ts";
import { serializeStreamCrowdSecPolicy } from "../src/services/crowdsec-policy-service.ts";
import { StreamProxyManager } from "../src/services/stream-proxy-service.ts";
import { flushStreamMonitoring } from "../src/services/stream-monitoring-service.ts";
import { buildStream } from "../src/services/stream-service.ts";
import type { StreamRecord } from "../src/types.ts";

const managers: Array<{ manager: StreamProxyManager; id: string }> = [];
const origins: Array<{ stop(force?: boolean): void | Promise<void> }> = [];
const sockets = new Set<Socket>();

afterEach(async () => {
	for (const socket of sockets) socket.destroy();
	sockets.clear();
	for (const { manager, id } of managers.splice(0)) await manager.remove(id);
	for (const origin of origins.splice(0)) await origin.stop(true);
	crowdSecDecisions.clear();
});

function load(...decisions: Array<Partial<RawCrowdSecDecision> & { value: string }>): void {
	crowdSecDecisions.applySnapshot(
		decisions.map((entry, index) => ({
			id: index + 1,
			type: "ban",
			scope: "Ip",
			duration: "4h",
			origin: "CAPI",
			scenario: "crowdsecurity/ssh-bf",
			...entry,
		})),
	);
}

/** An origin that greets every connection, so a successful proxy hop is observable. */
function startOrigin(): { port: number } {
	const server = Bun.listen({
		hostname: "127.0.0.1",
		port: 0,
		socket: {
			open(socket) {
				socket.write("hello\n");
			},
			data() {},
			close() {},
			error() {},
		},
	});
	origins.push(server as unknown as { stop(force?: boolean): void | Promise<void> });
	return { port: server.port };
}

async function freePort(): Promise<number> {
	const probe = Bun.listen({ hostname: "127.0.0.1", port: 0, socket: { data() {}, open() {}, close() {}, error() {} } });
	const port = probe.port;
	probe.stop(true);
	return port;
}

async function startStream(crowdSecPolicy: unknown): Promise<{ manager: StreamProxyManager; record: StreamRecord; port: number }> {
	const origin = startOrigin();
	const port = await freePort();
	const record = await buildStream({ name: `cs-stream-${crypto.randomUUID()}`, incomingPort: port, forwardHost: "127.0.0.1", forwardPort: origin.port });
	record.crowdsec_policy_json = serializeStreamCrowdSecPolicy(crowdSecPolicy);
	await repository.saveStream(record);
	const manager = new StreamProxyManager();
	managers.push({ manager, id: record.id });
	await manager.apply(record);
	return { manager, record, port };
}

/** Connects and reports whether the origin's greeting arrived before the connection closed. */
function attempt(port: number): Promise<{ greeted: boolean }> {
	return new Promise((resolve) => {
		let greeted = false;
		const socket = createConnection({ host: "127.0.0.1", port });
		sockets.add(socket);
		const finish = () => {
			socket.destroy();
			sockets.delete(socket);
			resolve({ greeted });
		};
		socket.on("data", (chunk) => {
			if (chunk.toString().includes("hello")) greeted = true;
			finish();
		});
		socket.on("close", finish);
		socket.on("error", finish);
		setTimeout(finish, 1_500);
	});
}

describe("CrowdSec enforcement on a TCP stream", () => {
	test("a banned address is refused in block mode", async () => {
		load({ value: "127.0.0.1" });
		const { port } = await startStream({ ban: "block" });
		expect((await attempt(port)).greeted).toBe(false);
	});

	test("the same address connects normally in monitor mode", async () => {
		load({ value: "127.0.0.1" });
		const { port } = await startStream({ ban: "monitor" });
		expect((await attempt(port)).greeted).toBe(true);
	});

	test("an address with no decision connects in block mode", async () => {
		load({ value: "203.0.113.5" });
		const { port } = await startStream({ ban: "block" });
		expect((await attempt(port)).greeted).toBe(true);
	});

	test("a captcha decision does not block unless captcha mode says so", async () => {
		load({ value: "127.0.0.1", type: "captcha" });
		const blocked = await startStream({ ban: "block", captcha: "monitor" });
		expect((await attempt(blocked.port)).greeted).toBe(true);

		load({ value: "127.0.0.1", type: "captcha" });
		const enforced = await startStream({ ban: "block", captcha: "block" });
		expect((await attempt(enforced.port)).greeted).toBe(false);
	});

	test("a range decision covering the client blocks it", async () => {
		load({ scope: "Range", value: "127.0.0.0/8" });
		const { port } = await startStream({ ban: "block" });
		expect((await attempt(port)).greeted).toBe(false);
	});

	test("the block is recorded with the decision's scenario", async () => {
		load({ value: "127.0.0.1", origin: "cscli", scenario: "manual-ban" });
		const { record, port } = await startStream({ ban: "block" });
		await attempt(port);
		await flushStreamMonitoring();
		const events = await repository.pagedStreamEvents({
			streamId: record.id,
			page: 1,
			pageSize: 20,
			since: Date.now() - 60_000,
			until: Date.now() + 60_000,
			sortBy: "created_at",
			sortDirection: "desc",
		});
		const blocked = events.items.find((event) => event.event_type === "blocked");
		expect(blocked?.reason).toContain("CrowdSec");
		expect(blocked?.crowdsec_json ?? "").toContain("manual-ban");
	});
});

describe("live connection sweep after a poll", () => {
	test("an established connection is closed once its address becomes banned", async () => {
		const { manager, port } = await startStream({ ban: "block" });

		const socket = createConnection({ host: "127.0.0.1", port });
		sockets.add(socket);
		const greeted = await new Promise<boolean>((resolve) => {
			socket.on("data", (chunk) => resolve(chunk.toString().includes("hello")));
			socket.on("error", () => resolve(false));
			setTimeout(() => resolve(false), 1_500);
		});
		expect(greeted).toBe(true);

		const closed = new Promise<boolean>((resolve) => {
			socket.on("close", () => resolve(true));
			setTimeout(() => resolve(false), 2_000);
		});

		// What a poll does: new decisions land, then live connections are re-checked.
		load({ value: "127.0.0.1" });
		await manager.enforceCrowdSecDecisions();

		expect(await closed).toBe(true);
	});

	test("a stream in monitor mode keeps its connection open", async () => {
		const { manager, port } = await startStream({ ban: "monitor" });

		const socket = createConnection({ host: "127.0.0.1", port });
		sockets.add(socket);
		await new Promise<void>((resolve) => {
			socket.on("data", () => resolve());
			setTimeout(resolve, 1_000);
		});

		const closed = new Promise<boolean>((resolve) => {
			socket.on("close", () => resolve(true));
			setTimeout(() => resolve(false), 1_000);
		});

		load({ value: "127.0.0.1" });
		await manager.enforceCrowdSecDecisions();

		expect(await closed).toBe(false);
	});
});
