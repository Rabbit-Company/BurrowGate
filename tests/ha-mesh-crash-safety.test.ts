import { afterEach, describe, expect, test } from "bun:test";
import { repository } from "../src/db/repository.ts";
import { haMeshService } from "../src/services/ha-mesh-service.ts";
import { APP_VERSION } from "../src/ui/layout.ts";
import { config } from "../src/config.ts";
import { db } from "../src/db/client.ts";

const mesh = haMeshService as unknown as {
	drainSessionRelayOutbox(): Promise<void>;
	broadcastNewChanges(): Promise<void>;
	handleMessage(event: MessageEvent, generation: number): Promise<void>;
	handlePrimaryMessage(ws: unknown, data: string): Promise<void>;
	state: string;
	replicaSocket: unknown;
	replicas: Set<unknown>;
	nodes: Map<unknown, unknown>;
	registeredMembers: Map<unknown, unknown>;
	cursor: number;
	relayInFlightId: number | null;
	relayInFlightSentAt: number;
	connectionGeneration: number;
};

function fakeOpenSocket() {
	return { readyState: WebSocket.OPEN, send: () => {}, close: () => {} };
}

describe("HA mesh service: fire-and-forget methods never reject", () => {
	afterEach(async () => {
		mesh.state = "unknown";
		mesh.replicaSocket = null;
		mesh.replicas.clear();
		mesh.nodes.clear();
		mesh.registeredMembers.clear();
		config.ha.versionMismatchNodes = [];
		await db`DELETE FROM ha_cluster_members`;
		mesh.cursor = 0;
		mesh.relayInFlightId = null;
		mesh.relayInFlightSentAt = 0;
	});

	test("drainSessionRelayOutbox resolves even when repository.pendingSessionRelayRows rejects", async () => {
		const original = repository.pendingSessionRelayRows;
		repository.pendingSessionRelayRows = async () => {
			throw new Error("simulated DB failure");
		};
		mesh.state = "connected";
		mesh.replicaSocket = fakeOpenSocket();
		try {
			await expect(mesh.drainSessionRelayOutbox()).resolves.toBeUndefined();
		} finally {
			repository.pendingSessionRelayRows = original;
		}
	});

	test("drainSessionRelayOutbox resolves even when repository.deleteSessionRelayRows rejects", async () => {
		const originalPending = repository.pendingSessionRelayRows;
		const originalDelete = repository.deleteSessionRelayRows;
		repository.pendingSessionRelayRows = async () => [
			{ id: 1, entity_type: "admin_session", entity_id: "sess_1", op: "insert", payload_json: null, created_at: Date.now() },
		];
		repository.deleteSessionRelayRows = async () => {
			throw new Error("simulated DB failure");
		};
		mesh.state = "connected";
		mesh.replicaSocket = fakeOpenSocket();
		try {
			await expect(mesh.drainSessionRelayOutbox()).resolves.toBeUndefined();
		} finally {
			repository.pendingSessionRelayRows = originalPending;
			repository.deleteSessionRelayRows = originalDelete;
		}
	});

	test("broadcastNewChanges resolves even when repository.changelogSince rejects", async () => {
		const original = repository.changelogSince;
		repository.changelogSince = async () => {
			throw new Error("simulated DB failure");
		};
		mesh.replicas.add(fakeOpenSocket());
		try {
			await expect(mesh.broadcastNewChanges()).resolves.toBeUndefined();
		} finally {
			repository.changelogSince = original;
		}
	});

	test("the regular broadcast tick expires a silent half-open replica even when no election quorum is eligible", async () => {
		const originalRole = config.ha.role;
		const closes: unknown[] = [];
		const socket = { readyState: WebSocket.OPEN, send: () => 1, close: (...args: unknown[]) => closes.push(args) };
		config.ha.role = "primary";
		mesh.replicas.add(socket);
		mesh.nodes.set(socket, {
			nodeId: "silent-two-node-replica",
			name: "silent-two-node-replica",
			lastSeenAt: Date.now() - 60_000,
		});
		try {
			await mesh.broadcastNewChanges();
			expect(closes).toEqual([[4000, "replica heartbeat acknowledgement timeout"]]);
			expect(mesh.nodes.has(socket)).toBe(false);
			expect(mesh.replicas.has(socket)).toBe(false);
		} finally {
			config.ha.role = originalRole;
		}
	});

	test("handleMessage resolves (closing the socket to reconnect) when applyReplicatedChange rejects", async () => {
		const original = repository.applyReplicatedChange;
		repository.applyReplicatedChange = async () => {
			throw new Error("simulated apply failure");
		};
		mesh.state = "connected";
		mesh.cursor = 0;
		const socket = fakeOpenSocket();
		mesh.replicaSocket = socket;
		const event = {
			data: JSON.stringify({ type: "change", row: { seq: 1, entity_type: "site", entity_id: "s1", op: "insert", payload_json: "{}", created_at: Date.now() } }),
		} as MessageEvent;
		try {
			await expect(mesh.handleMessage(event, mesh.connectionGeneration)).resolves.toBeUndefined();
		} finally {
			repository.applyReplicatedChange = original;
		}
	});

	test("handleMessage resolves when the incoming payload is malformed JSON", async () => {
		const event = { data: "not json" } as MessageEvent;
		await expect(mesh.handleMessage(event, mesh.connectionGeneration)).resolves.toBeUndefined();
	});

	test("handlePrimaryMessage resolves even when applyReplicatedSessionRelay rejects", async () => {
		const original = repository.applyReplicatedSessionRelay;
		repository.applyReplicatedSessionRelay = async () => {
			throw new Error("simulated apply failure");
		};
		const socket = { ...fakeOpenSocket(), data: { authenticatedNodeId: "crash-test-node", authenticatedActive: true } };
		const data = JSON.stringify({ type: "relay", relayId: 1, entityType: "admin_session", entityId: "sess_1", op: "insert", payloadJson: "{}" });
		try {
			await mesh.handlePrimaryMessage(
				socket,
				JSON.stringify({ type: "announce", nodeId: "crash-test-node", name: "crash-test", version: APP_VERSION, adminUrl: "https://crash-test.test" }),
			);
			await expect(mesh.handlePrimaryMessage(socket, data)).resolves.toBeUndefined();
		} finally {
			repository.applyReplicatedSessionRelay = original;
		}
	});

	test("handlePrimaryMessage resolves when the incoming payload is malformed JSON", async () => {
		await expect(mesh.handlePrimaryMessage(fakeOpenSocket(), "not json")).resolves.toBeUndefined();
	});
});
