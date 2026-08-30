import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { config } from "../src/config.ts";
import { db } from "../src/db/client.ts";
import { repository, type ReplicatedEntityType } from "../src/db/repository.ts";
import { sha256Hex } from "../src/utils/crypto.ts";
import {
	APPLY_FAILURE_REBOOTSTRAP_THRESHOLD,
	authenticateHaRequest,
	HA_REPLICA_LIVENESS_TIMEOUT_MS,
	haMeshService,
	isAuthorized,
	readWithIdleTimeout,
	RUNTIME_CONVERGENCE_RESTART_THRESHOLD,
	withDurability,
} from "../src/services/ha-mesh-service.ts";
import { HaPrimaryAuthorityFenceError, HaPromotionWriteFenceError, HaQuorumLossFenceError, haPrimaryWriteBarrier } from "../src/services/ha-write-barrier.ts";
import { loadBalancer } from "../src/services/load-balancer-service.ts";
import { processLifecycle } from "../src/services/process-lifecycle-service.ts";
import { APP_VERSION } from "../src/ui/layout.ts";
import { HA_FORGET_MIN_OFFLINE_FLOOR_MS, HA_FORGET_MIN_OFFLINE_RECONNECT_MULTIPLIER } from "../src/ha-timing.ts";
import { decryptSecret, encryptSecret, resetMasterKeyCache } from "../src/services/secret-encryption-service.ts";
import type { SiteOriginRecord } from "../src/types.ts";

let restartCalls: string[] = [];
processLifecycle.gracefulRestart = (async (reason: string) => {
	restartCalls.push(reason);
}) as typeof processLifecycle.gracefulRestart;

const mesh = haMeshService as unknown as {
	start(): Promise<void>;
	prepareForRuntimeAtBoot(): Promise<void>;
	startPrimary(): Promise<void>;
	handleIncomingMessage(event: MessageEvent): void;
	handlePrimaryMessage(ws: unknown, data: string): Promise<void>;
	enqueuePrimaryMessage(ws: unknown, data: string): void;
	primaryMessageQueue: Promise<void>;
	handleHello(message: { type: "hello"; keyCheck: string; epoch: number; version: string; primaryFenced?: boolean }): Promise<void>;
	handleMessage(event: MessageEvent, generation: number): Promise<void>;
	handlePromote(message: {
		type: "promote";
		promotionId: string;
		newPrimaryNodeId: string;
		newPrimaryUrl: string;
		newPrimaryAdminUrl: string;
		newEpoch: number;
	}): Promise<void>;
	handlePrimaryRedirect(message: { type: "primary_redirect"; primaryUrl: string; primaryAdminUrl: string; epoch: number }): Promise<void>;
	handlePreparePromote(message: { type: "prepare_promote"; barrierSeq: number; promotionId: string }): Promise<void>;
	handleEnrollRequest(request: Request): Promise<Response>;
	handlePrimaryClose(ws: unknown): void;
	handleReplicaClose(event: { code: number; reason: string }): void;
	checkHeartbeatWatchdog(): void;
	promoteNode(targetNodeId: string): Promise<void>;
	drainSessionRelayOutbox(): Promise<void>;
	runCatchUp(): Promise<void>;
	bootstrapSnapshot(): Promise<void>;
	applyRow(row: {
		seq: number;
		entity_type: ReplicatedEntityType;
		entity_id: string;
		op: "insert" | "update" | "delete";
		payload_json: string | null;
		created_at: number;
	}): Promise<void>;
	retryRuntimeConvergenceIfFenced(): Promise<void>;
	runtimeConvergenceFenced: boolean;
	consecutiveRuntimeConvergenceFailures: number;
	ready(): boolean;
	versionMismatches(): Array<{ nodeId: string; name: string; version: string }>;
	forgetNode(nodeId: string): Promise<void>;
	offlineSince: Map<string, number>;
	waitForMajorityDurability(timeoutMs?: number): Promise<{ confirmed: boolean; seq: number }>;
	resolveCaCertificate(): Promise<string>;
	waitForMembershipActivationDurability(oldMembers: Array<{ node_id: string }>, timeoutMs?: number): Promise<boolean>;
	loadRegisteredMembers(): Promise<void>;
	messageQueue: Promise<void>;
	state: string;
	replicaSocket: unknown;
	cursor: number;
	relayInFlightId: number | null;
	relayInFlightSentAt: number;
	hasBootstrapped: boolean;
	disconnectedSince: number;
	verifiedConnectionThisProcess: boolean;
	lastVerifiedSyncAt: number;
	primaryAuthorityAmbiguous: boolean;
	connectionGeneration: number;
	stopped: boolean;
	server: unknown;
	nodeId: string | null;
	caCertificate: string | null;
	replicas: Set<{ send: (data: string) => void }>;
	nodes: Map<
		unknown,
		{
			nodeId: string;
			name: string;
			version: string;
			connectedAt: number | null;
			connected: boolean;
			lastSeenAt: number;
			adminUrl: string;
			lastAckedSeq: number | null;
		}
	>;
	registeredMembers: Map<string, unknown>;
	revokedNodeIds: Set<string>;
	lastBroadcastSeq: number;
	pendingPreparePromoteAck: { ws: unknown; promotionId: string; resolve: () => void; reject: (error: Error) => void } | null;
	pendingPromotionFenceAck: unknown;
	pendingPromoteAppliedAck: { ws: unknown; promotionId: string; resolve: () => void; reject: (error: Error) => void } | null;
	consecutiveApplyFailureSeq: number | null;
	consecutiveApplyFailureCount: number;
	runtimePrepared: boolean;
};

afterEach(async () => {
	mesh.registeredMembers.clear();
	mesh.revokedNodeIds.clear();
	mesh.runtimePrepared = false;
	config.ha.versionMismatchNodes = [];
	config.ha.authorityFence = null;
	mesh.offlineSince.clear();
	await db`DELETE FROM ha_cluster_members`;
});

function fakeSocket(onSend?: (data: string) => void) {
	return { readyState: WebSocket.OPEN, send: (data: string) => onSend?.(data), close: () => {} };
}

function markLongOffline(nodeId: string): void {
	mesh.offlineSince.set(nodeId, Date.now() - 3_600_000);
}

function changeEvent(seq: number, entityType: ReplicatedEntityType = "site"): MessageEvent {
	return {
		data: JSON.stringify({
			type: "change",
			row: { seq, entity_type: entityType, entity_id: `entity-${seq}`, op: "insert", payload_json: "{}", created_at: Date.now() },
		}),
	} as MessageEvent;
}

describe("HA mesh service: serialized message application", () => {
	afterEach(() => {
		mesh.state = "unknown";
		mesh.replicaSocket = null;
		mesh.cursor = 0;
		mesh.messageQueue = Promise.resolve();
	});

	test("rows are applied strictly in order, and cursor lands on the higher seq, even when the slower row is queued first", async () => {
		const applyOrder: number[] = [];
		const originalApply = repository.applyReplicatedChange;
		const originalUpdateCursor = repository.updateReplicationCursor;
		repository.applyReplicatedChange = async (row) => {
			if (row.seq === 1) await new Promise((resolve) => setTimeout(resolve, 20));
			applyOrder.push(row.seq);
		};
		repository.updateReplicationCursor = async () => {};
		mesh.state = "connected";
		mesh.cursor = 0;
		mesh.replicaSocket = fakeSocket();
		try {
			mesh.handleIncomingMessage(changeEvent(1));
			mesh.handleIncomingMessage(changeEvent(2));
			await mesh.messageQueue;

			expect(applyOrder).toEqual([1, 2]);
			expect(mesh.cursor).toBe(2);
		} finally {
			repository.applyReplicatedChange = originalApply;
			repository.updateReplicationCursor = originalUpdateCursor;
		}
	});
});

describe("HA mesh service: acknowledged relay outbox", () => {
	afterEach(() => {
		mesh.state = "unknown";
		mesh.replicaSocket = null;
		mesh.relayInFlightId = null;
		mesh.relayInFlightSentAt = 0;
	});

	test("drainSessionRelayOutbox sends the row but does not delete it - only a relay_ack does", async () => {
		const originalPending = repository.pendingSessionRelayRows;
		const originalDelete = repository.deleteSessionRelayRows;
		let deleteCalled = false;
		repository.pendingSessionRelayRows = async () => [
			{ id: 7, entity_type: "admin_session", entity_id: "sess_1", op: "insert", payload_json: null, created_at: Date.now() },
		];
		repository.deleteSessionRelayRows = async () => {
			deleteCalled = true;
		};
		const sent: string[] = [];
		mesh.state = "connected";
		mesh.replicaSocket = fakeSocket((data) => sent.push(data));
		try {
			await mesh.drainSessionRelayOutbox();
			expect(deleteCalled).toBe(false);
			expect(sent).toHaveLength(1);
			expect((JSON.parse(sent[0]!) as { relayId: number }).relayId).toBe(7);
		} finally {
			repository.pendingSessionRelayRows = originalPending;
			repository.deleteSessionRelayRows = originalDelete;
		}
	});

	test("a relay_ack message deletes exactly the acked outbox row", async () => {
		const originalDelete = repository.deleteSessionRelayRows;
		let deletedIds: number[] = [];
		repository.deleteSessionRelayRows = async (ids: number[]) => {
			deletedIds = ids;
		};
		try {
			mesh.handleIncomingMessage({ data: JSON.stringify({ type: "relay_ack", relayId: 7 }) } as MessageEvent);
			await mesh.messageQueue;
			expect(deletedIds).toEqual([7]);
		} finally {
			repository.deleteSessionRelayRows = originalDelete;
		}
	});

	test("only one relay is in flight, preserving per-node watermark order", async () => {
		const originalPending = repository.pendingSessionRelayRows;
		repository.pendingSessionRelayRows = async () => [
			{ id: 11, entity_type: "admin_session", entity_id: "sess_11", op: "insert", payload_json: null, created_at: Date.now() },
			{ id: 12, entity_type: "admin_session", entity_id: "sess_12", op: "insert", payload_json: null, created_at: Date.now() },
		];
		const sent: string[] = [];
		mesh.state = "connected";
		mesh.replicaSocket = fakeSocket((data) => sent.push(data));
		try {
			await mesh.drainSessionRelayOutbox();
			await mesh.drainSessionRelayOutbox();
			expect(sent).toHaveLength(1);
			expect((JSON.parse(sent[0]!) as { relayId: number }).relayId).toBe(11);
		} finally {
			repository.pendingSessionRelayRows = originalPending;
		}
	});
});

describe("HA mesh service: handlePreparePromote", () => {
	afterEach(() => {
		mesh.state = "unknown";
		mesh.replicaSocket = null;
		mesh.relayInFlightId = null;
		mesh.relayInFlightSentAt = 0;
	});

	test("acks immediately with its current cursor when there is nothing queued to relay and it's already at the barrier", async () => {
		const originalPending = repository.pendingSessionRelayRows;
		repository.pendingSessionRelayRows = async () => [];
		const sent: string[] = [];
		mesh.state = "connected";
		mesh.cursor = 0;
		mesh.replicaSocket = fakeSocket((data) => sent.push(data));
		try {
			await mesh.handlePreparePromote({ type: "prepare_promote", barrierSeq: 0, promotionId: "test-promotion-1" });
			expect(sent).toEqual([JSON.stringify({ type: "prepare_promote_ack", cursor: 0, promotionId: "test-promotion-1" })]);
		} finally {
			repository.pendingSessionRelayRows = originalPending;
		}
	});

	test("waits for its own cursor to reach the barrier before acking, not just an empty outbox", async () => {
		const originalPending = repository.pendingSessionRelayRows;
		repository.pendingSessionRelayRows = async () => [];
		const sent: string[] = [];
		mesh.state = "connected";
		mesh.cursor = 5;
		mesh.replicaSocket = fakeSocket((data) => sent.push(data));
		const wait = mesh.handlePreparePromote({ type: "prepare_promote", barrierSeq: 6, promotionId: "test-promotion-2" });
		await new Promise((resolve) => setTimeout(resolve, 150));
		expect(sent).toHaveLength(0);
		mesh.cursor = 6;
		try {
			await wait;
			expect(sent).toEqual([JSON.stringify({ type: "prepare_promote_ack", cursor: 6, promotionId: "test-promotion-2" })]);
		} finally {
			repository.pendingSessionRelayRows = originalPending;
		}
	});

	test("drains a queued relay event before acking, without deadlocking against the relay_ack it's waiting for", async () => {
		const originalPending = repository.pendingSessionRelayRows;
		const originalDelete = repository.deleteSessionRelayRows;
		let outboxHasRow = true;
		repository.pendingSessionRelayRows = async () =>
			outboxHasRow ? [{ id: 99, entity_type: "admin_session", entity_id: "sess_99", op: "insert", payload_json: null, created_at: Date.now() }] : [];
		repository.deleteSessionRelayRows = async () => {
			outboxHasRow = false;
		};
		const sent: string[] = [];
		mesh.state = "connected";
		mesh.cursor = 0;
		mesh.messageQueue = Promise.resolve();
		mesh.replicaSocket = fakeSocket((data) => {
			sent.push(data);
			const message = JSON.parse(data) as { type: string; relayId?: number };
			if (message.type === "relay") {
				mesh.handleIncomingMessage({ data: JSON.stringify({ type: "relay_ack", relayId: message.relayId }) } as MessageEvent);
			}
		});

		mesh.handleIncomingMessage({ data: JSON.stringify({ type: "prepare_promote", barrierSeq: 0, promotionId: "test-promotion-3" }) } as MessageEvent);

		const deadline = Date.now() + 1_000;
		while (!sent.some((data) => (JSON.parse(data) as { type: string }).type === "prepare_promote_ack") && Date.now() < deadline) {
			await new Promise((resolve) => setTimeout(resolve, 10));
		}

		try {
			const types = sent.map((data) => (JSON.parse(data) as { type: string }).type);
			expect(types).toEqual(["relay", "prepare_promote_ack"]);
		} finally {
			repository.pendingSessionRelayRows = originalPending;
			repository.deleteSessionRelayRows = originalDelete;
		}
	});
});

describe("HA mesh service: handleEnrollRequest (/_ha/enroll)", () => {
	const originalSharedToken = config.ha.sharedToken;
	const originalRole = config.ha.role;

	beforeEach(() => {
		config.ha.sharedToken = "enrollment-test-cluster-token";
		config.ha.role = "primary";
	});

	afterEach(() => {
		config.ha.sharedToken = originalSharedToken;
		config.ha.role = originalRole;
	});

	function enrollRequest(
		bearer?: string,
		nodeId: unknown = "enrolling-node-id",
		identity: { name?: unknown; version?: unknown; adminUrl?: unknown } = {},
	): Request {
		const headers: Record<string, string> = bearer !== undefined ? { authorization: `Bearer ${bearer}`, "content-type": "application/json" } : {};
		const body = { nodeId, name: "enrolling-node", version: APP_VERSION, adminUrl: "https://enrolling-node.test", ...identity };
		return new Request("https://primary.test/_ha/enroll", { method: "POST", headers, body: JSON.stringify(body) });
	}

	test("rejects a request with no bearer credential", async () => {
		const response = await mesh.handleEnrollRequest(enrollRequest());
		expect(response.status).toBe(401);
	});

	test("rejects a code that was never issued", async () => {
		const response = await mesh.handleEnrollRequest(enrollRequest("never-issued-code"));
		expect(response.status).toBe(401);
	});

	test("rejects enrollment without a valid immutable node identity before consuming the code", async () => {
		const code = "test-enroll-code-malformed-node";
		await repository.createHaEnrollmentCode(await sha256Hex(code), Date.now() + 60_000);
		expect((await mesh.handleEnrollRequest(enrollRequest(code, ""))).status).toBe(400);
		expect((await mesh.handleEnrollRequest(enrollRequest(code, "valid-node-id"))).status).toBe(200);
	});

	test("redeems a valid, unexpired code exactly once - the second attempt with the same code is rejected", async () => {
		const code = "test-enroll-code-single-use";
		await repository.createHaEnrollmentCode(await sha256Hex(code), Date.now() + 60_000);

		const first = await mesh.handleEnrollRequest(enrollRequest(code));
		expect(first.status).toBe(200);

		const { sharedToken: issuedCredential } = (await first.json()) as { sharedToken: string };
		expect(issuedCredential).toBeTruthy();
		expect(issuedCredential).not.toBe(config.ha.sharedToken);

		const second = await mesh.handleEnrollRequest(enrollRequest(code));
		expect(second.status).toBe(401);
	});

	test("rejects a code that has already expired", async () => {
		const code = "test-enroll-code-expired";
		await repository.createHaEnrollmentCode(await sha256Hex(code), Date.now() - 1);
		const response = await mesh.handleEnrollRequest(enrollRequest(code));
		expect(response.status).toBe(401);
	});

	describe("majority-connectivity precondition (mirrors forgetNode's own)", () => {
		async function seedThreeActivatedMembers(): Promise<string> {
			const selfNodeId = await repository.haNodeId();
			const now = Date.now();
			for (const nodeId of [selfNodeId, "enroll-guard-peer-1", "enroll-guard-peer-2"]) {
				await repository.upsertHaClusterMember({
					node_id: nodeId,
					name: nodeId,
					version: APP_VERSION,
					admin_url: `https://${nodeId}.test`,
					first_seen_at: now,
					last_seen_at: now,
					credential_hash: await sha256Hex(`${nodeId}-credential`),
					activated_at: now,
				});
			}
			return selfNodeId;
		}

		afterEach(async () => {
			mesh.nodes.clear();
			await db`DELETE FROM ha_cluster_members`;
		});

		test("refuses to enroll a new node when this primary lacks majority connectivity to the existing cluster", async () => {
			await seedThreeActivatedMembers();
			mesh.nodes.clear();
			const code = "test-enroll-code-minority-primary";
			await repository.createHaEnrollmentCode(await sha256Hex(code), Date.now() + 60_000);

			const response = await mesh.handleEnrollRequest(enrollRequest(code, "would-be-recruited-node"));

			expect(response.status).toBe(503);
			const retry = await mesh.handleEnrollRequest(enrollRequest(code, "would-be-recruited-node"));
			expect(retry.status).not.toBe(401);
		});

		test("allows enrollment once this primary has proven majority connectivity to the existing cluster", async () => {
			await seedThreeActivatedMembers();
			mesh.nodes.set(
				{ close: () => {} },
				{
					nodeId: "enroll-guard-peer-1",
					name: "enroll-guard-peer-1",
					version: APP_VERSION,
					connectedAt: Date.now(),
					connected: true,
					lastSeenAt: Date.now(),
					adminUrl: "https://enroll-guard-peer-1.test",
					lastAckedSeq: 0,
				},
			);
			const code = "test-enroll-code-majority-primary";
			await repository.createHaEnrollmentCode(await sha256Hex(code), Date.now() + 60_000);

			const response = await mesh.handleEnrollRequest(enrollRequest(code, "legitimately-recruited-node"));

			expect(response.status).toBe(200);
		});

		test("does not apply below the auto-failover member floor, matching forgetNode's own decommissioning escape hatch", async () => {
			const selfNodeId = await repository.haNodeId();
			await repository.upsertHaClusterMember({
				node_id: selfNodeId,
				name: "self",
				version: APP_VERSION,
				admin_url: "https://self.test",
				first_seen_at: Date.now(),
				last_seen_at: Date.now(),
				credential_hash: await sha256Hex("self-credential"),
				activated_at: Date.now(),
			});
			mesh.nodes.clear();
			const code = "test-enroll-code-below-floor";
			await repository.createHaEnrollmentCode(await sha256Hex(code), Date.now() + 60_000);

			const response = await mesh.handleEnrollRequest(enrollRequest(code, "second-node-joining"));

			expect(response.status).toBe(200);
		});

		describe("the matching precondition at actual activation (announce), not just credential issuance", () => {
			async function insertPendingMember(nodeId: string): Promise<void> {
				const now = Date.now();
				await db`INSERT INTO ha_cluster_members (node_id,name,version,admin_url,first_seen_at,last_seen_at,credential_hash,activated_at,revoked_at)
					VALUES (${nodeId},${nodeId},${APP_VERSION},${`https://${nodeId}.test`},${now},${now},${await sha256Hex(`${nodeId}-credential`)},NULL,NULL)`;
			}

			test("refuses to activate a pending member - credential already issued while the cluster was healthy - once this primary is isolated", async () => {
				await seedThreeActivatedMembers();
				const pendingNodeId = "pending-since-before-partition";
				await insertPendingMember(pendingNodeId);
				await mesh.loadRegisteredMembers();
				mesh.nodes.clear();

				const closes: unknown[] = [];
				const ws = {
					send: () => {},
					close: (...args: unknown[]) => closes.push(args),
					data: { authenticatedNodeId: pendingNodeId, authenticatedActive: false },
				};
				await mesh.handlePrimaryMessage(
					ws,
					JSON.stringify({ type: "announce", nodeId: pendingNodeId, name: pendingNodeId, version: APP_VERSION, adminUrl: `https://${pendingNodeId}.test` }),
				);

				expect(closes).toHaveLength(1);
				expect((closes[0] as [number, string])[0]).toBe(1011);
				expect((closes[0] as [number, string])[1]).toContain("majority connectivity");
				expect(mesh.registeredMembers.has(pendingNodeId)).toBe(false);
				const row = await db`SELECT activated_at FROM ha_cluster_members WHERE node_id = ${pendingNodeId}`;
				expect(row[0]?.activated_at).toBeNull();
			});

			test("activates a pending member once this primary has genuinely regained majority connectivity", async () => {
				await seedThreeActivatedMembers();
				const pendingNodeId = "pending-then-reconnects-once-healthy";
				await insertPendingMember(pendingNodeId);
				await mesh.loadRegisteredMembers();

				mesh.nodes.set(
					{ send: () => {}, close: () => {} },
					{
						nodeId: "enroll-guard-peer-1",
						name: "enroll-guard-peer-1",
						version: APP_VERSION,
						connectedAt: Date.now(),
						connected: true,
						lastSeenAt: Date.now(),
						adminUrl: "https://enroll-guard-peer-1.test",
						lastAckedSeq: Number.MAX_SAFE_INTEGER,
					},
				);

				const ws = { send: () => {}, close: () => {}, data: { authenticatedNodeId: pendingNodeId, authenticatedActive: false } };
				await mesh.handlePrimaryMessage(
					ws,
					JSON.stringify({ type: "announce", nodeId: pendingNodeId, name: pendingNodeId, version: APP_VERSION, adminUrl: `https://${pendingNodeId}.test` }),
				);

				expect(mesh.registeredMembers.has(pendingNodeId)).toBe(true);
				const row = await db`SELECT activated_at FROM ha_cluster_members WHERE node_id = ${pendingNodeId}`;
				expect(row[0]?.activated_at).not.toBeNull();
			});

			test("never blocks an ALREADY-active member's ordinary reconnect, even while this primary lacks majority connectivity - that would perversely stop the one thing that could restore it", async () => {
				await seedThreeActivatedMembers();
				mesh.nodes.clear();

				const closes: unknown[] = [];
				const ws = {
					send: () => {},
					close: (...args: unknown[]) => closes.push(args),
					data: { authenticatedNodeId: "enroll-guard-peer-1", authenticatedActive: true },
				};
				await mesh.handlePrimaryMessage(
					ws,
					JSON.stringify({
						type: "announce",
						nodeId: "enroll-guard-peer-1",
						name: "enroll-guard-peer-1",
						version: APP_VERSION,
						adminUrl: "https://enroll-guard-peer-1.test",
					}),
				);

				expect(closes).toHaveLength(0);
				expect(mesh.registeredMembers.has("enroll-guard-peer-1")).toBe(true);
			});
		});

		describe("wiring: the announce handler reverts an activation it cannot durably confirm", () => {
			async function insertPendingMember(nodeId: string): Promise<void> {
				const now = Date.now();
				await db`INSERT INTO ha_cluster_members (node_id,name,version,admin_url,first_seen_at,last_seen_at,credential_hash,activated_at,revoked_at)
					VALUES (${nodeId},${nodeId},${APP_VERSION},${`https://${nodeId}.test`},${now},${now},${await sha256Hex(`${nodeId}-credential`)},NULL,NULL)`;
			}

			afterEach(async () => {
				mesh.nodes.clear();
				await db`DELETE FROM ha_cluster_members`;
			});

			test("reverts the activation back to pending and refuses the connection when durable confirmation fails", async () => {
				await seedThreeActivatedMembers();
				const pendingNodeId = "pending-durability-not-confirmed";
				await insertPendingMember(pendingNodeId);
				await mesh.loadRegisteredMembers();

				mesh.nodes.set(
					{ send: () => {}, close: () => {} },
					{
						nodeId: "enroll-guard-peer-1",
						name: "enroll-guard-peer-1",
						version: APP_VERSION,
						connectedAt: Date.now(),
						connected: true,
						lastSeenAt: Date.now(),
						adminUrl: "https://enroll-guard-peer-1.test",
						lastAckedSeq: null,
					},
				);
				const originalWait = mesh.waitForMembershipActivationDurability;
				mesh.waitForMembershipActivationDurability = async () => false;

				const closes: unknown[] = [];
				const ws = {
					send: () => {},
					close: (...args: unknown[]) => closes.push(args),
					data: { authenticatedNodeId: pendingNodeId, authenticatedActive: false },
				};
				try {
					await mesh.handlePrimaryMessage(
						ws,
						JSON.stringify({ type: "announce", nodeId: pendingNodeId, name: pendingNodeId, version: APP_VERSION, adminUrl: `https://${pendingNodeId}.test` }),
					);
				} finally {
					mesh.waitForMembershipActivationDurability = originalWait;
				}

				expect(closes).toHaveLength(1);
				expect((closes[0] as [number, string])[0]).toBe(1011);

				expect(mesh.registeredMembers.has(pendingNodeId)).toBe(false);
				const row = (await db`SELECT activated_at, credential_hash FROM ha_cluster_members WHERE node_id = ${pendingNodeId}`) as Array<{
					activated_at: number | null;
					credential_hash: string | null;
				}>;
				expect(row[0]?.activated_at).toBeNull();
				expect(row[0]?.credential_hash).not.toBeNull();
			});

			test("keeps the activation once durable confirmation succeeds", async () => {
				await seedThreeActivatedMembers();
				const pendingNodeId = "pending-durability-confirmed";
				await insertPendingMember(pendingNodeId);
				await mesh.loadRegisteredMembers();
				mesh.nodes.set(
					{ send: () => {}, close: () => {} },
					{
						nodeId: "enroll-guard-peer-1",
						name: "enroll-guard-peer-1",
						version: APP_VERSION,
						connectedAt: Date.now(),
						connected: true,
						lastSeenAt: Date.now(),
						adminUrl: "https://enroll-guard-peer-1.test",
						lastAckedSeq: Number.MAX_SAFE_INTEGER,
					},
				);

				const ws = { send: () => {}, close: () => {}, data: { authenticatedNodeId: pendingNodeId, authenticatedActive: false } };
				await mesh.handlePrimaryMessage(
					ws,
					JSON.stringify({ type: "announce", nodeId: pendingNodeId, name: pendingNodeId, version: APP_VERSION, adminUrl: `https://${pendingNodeId}.test` }),
				);

				expect(mesh.registeredMembers.has(pendingNodeId)).toBe(true);
				const row = await db`SELECT activated_at FROM ha_cluster_members WHERE node_id = ${pendingNodeId}`;
				expect(row[0]?.activated_at).not.toBeNull();
			});

			test("a quorum-loss fence engaging during the durability wait does not block the compensating revert - the database and in-memory cache stay consistent", async () => {
				await seedThreeActivatedMembers();
				const pendingNodeId = "pending-fence-during-wait";
				await insertPendingMember(pendingNodeId);
				await mesh.loadRegisteredMembers();
				mesh.nodes.set(
					{ send: () => {}, close: () => {} },
					{
						nodeId: "enroll-guard-peer-1",
						name: "enroll-guard-peer-1",
						version: APP_VERSION,
						connectedAt: Date.now(),
						connected: true,
						lastSeenAt: Date.now(),
						adminUrl: "https://enroll-guard-peer-1.test",
						lastAckedSeq: Number.MAX_SAFE_INTEGER,
					},
				);

				const originalWait = mesh.waitForMembershipActivationDurability;
				mesh.waitForMembershipActivationDurability = async () => {
					config.ha.quorumFenced = true;
					return false;
				};

				const closes: unknown[] = [];
				const ws = {
					send: () => {},
					close: (...args: unknown[]) => closes.push(args),
					data: { authenticatedNodeId: pendingNodeId, authenticatedActive: false },
				};
				try {
					await mesh.handlePrimaryMessage(
						ws,
						JSON.stringify({ type: "announce", nodeId: pendingNodeId, name: pendingNodeId, version: APP_VERSION, adminUrl: `https://${pendingNodeId}.test` }),
					);
				} finally {
					mesh.waitForMembershipActivationDurability = originalWait;
					config.ha.quorumFenced = false;
				}

				expect(closes).toHaveLength(1);

				expect(mesh.registeredMembers.has(pendingNodeId)).toBe(false);
				const row = await db`SELECT activated_at FROM ha_cluster_members WHERE node_id = ${pendingNodeId}`;
				expect(row[0]?.activated_at).toBeNull();
			});

			test("two overlapping waitForMembershipActivationDurability calls share no state and resolve independently", async () => {
				await seedThreeActivatedMembers();
				mesh.nodes.set(
					{ send: () => {}, close: () => {} },
					{
						nodeId: "enroll-guard-peer-1",
						name: "enroll-guard-peer-1",
						version: APP_VERSION,
						connectedAt: Date.now(),
						connected: true,
						lastSeenAt: Date.now(),
						adminUrl: "https://enroll-guard-peer-1.test",
						lastAckedSeq: null,
					},
				);

				const oldMembers = [{ node_id: "self" }, { node_id: "enroll-guard-peer-1" }, { node_id: "enroll-guard-peer-2" }];
				const first = mesh.waitForMembershipActivationDurability(oldMembers, 1_000);
				await new Promise((resolve) => setTimeout(resolve, 30));
				const secondNodeEntry = [...mesh.nodes.values()][0] as { lastAckedSeq: number | null };
				secondNodeEntry.lastAckedSeq = Number.MAX_SAFE_INTEGER;
				const second = await mesh.waitForMembershipActivationDurability(oldMembers, 1_000);

				expect(second).toBe(true);
				expect(await first).toBe(true);
			});

			test("enqueuePrimaryMessage serializes two genuinely concurrent announces so neither hits the transaction-collision the direct call is still vulnerable to", async () => {
				await seedThreeActivatedMembers();
				const firstNodeId = "pending-queued-first";
				const secondNodeId = "pending-queued-second";
				await insertPendingMember(firstNodeId);
				await insertPendingMember(secondNodeId);
				await mesh.loadRegisteredMembers();

				mesh.nodes.set(
					{ send: () => {}, close: () => {} },
					{
						nodeId: "enroll-guard-peer-1",
						name: "enroll-guard-peer-1",
						version: APP_VERSION,
						connectedAt: Date.now(),
						connected: true,
						lastSeenAt: Date.now(),
						adminUrl: "https://enroll-guard-peer-1.test",
						lastAckedSeq: Number.MAX_SAFE_INTEGER,
					},
				);
				mesh.nodes.set(
					{ send: () => {}, close: () => {} },
					{
						nodeId: "enroll-guard-peer-2",
						name: "enroll-guard-peer-2",
						version: APP_VERSION,
						connectedAt: Date.now(),
						connected: true,
						lastSeenAt: Date.now(),
						adminUrl: "https://enroll-guard-peer-2.test",
						lastAckedSeq: Number.MAX_SAFE_INTEGER,
					},
				);

				const firstWs = { send: () => {}, close: () => {}, data: { authenticatedNodeId: firstNodeId, authenticatedActive: false } };
				const secondWs = { send: () => {}, close: () => {}, data: { authenticatedNodeId: secondNodeId, authenticatedActive: false } };
				mesh.enqueuePrimaryMessage(
					firstWs,
					JSON.stringify({ type: "announce", nodeId: firstNodeId, name: firstNodeId, version: APP_VERSION, adminUrl: `https://${firstNodeId}.test` }),
				);
				mesh.enqueuePrimaryMessage(
					secondWs,
					JSON.stringify({ type: "announce", nodeId: secondNodeId, name: secondNodeId, version: APP_VERSION, adminUrl: `https://${secondNodeId}.test` }),
				);
				await mesh.primaryMessageQueue;

				expect(mesh.registeredMembers.has(firstNodeId)).toBe(true);
				expect(mesh.registeredMembers.has(secondNodeId)).toBe(true);
				const rows = (await db`SELECT node_id, activated_at FROM ha_cluster_members WHERE node_id IN (${firstNodeId}, ${secondNodeId})`) as Array<{
					node_id: string;
					activated_at: number | null;
				}>;
				expect(rows).toHaveLength(2);
				for (const row of rows) expect(row.activated_at).not.toBeNull();
			});

			test("a cursor message is never blocked behind an in-flight announce's own durability wait", async () => {
				await seedThreeActivatedMembers();
				const pendingNodeId = "pending-cursor-not-blocked";
				await insertPendingMember(pendingNodeId);
				await mesh.loadRegisteredMembers();
				const peerWs = { send: () => {}, close: () => {} };
				mesh.nodes.set(peerWs, {
					nodeId: "enroll-guard-peer-1",
					name: "enroll-guard-peer-1",
					version: APP_VERSION,
					connectedAt: Date.now(),
					connected: true,
					lastSeenAt: Date.now(),
					adminUrl: "https://enroll-guard-peer-1.test",
					lastAckedSeq: null,
				});

				const announceWs = { send: () => {}, close: () => {}, data: { authenticatedNodeId: pendingNodeId, authenticatedActive: false } };
				mesh.enqueuePrimaryMessage(
					announceWs,
					JSON.stringify({ type: "announce", nodeId: pendingNodeId, name: pendingNodeId, version: APP_VERSION, adminUrl: `https://${pendingNodeId}.test` }),
				);

				await new Promise((resolve) => setTimeout(resolve, 30));
				const seq = await repository.latestChangelogSeq();
				mesh.enqueuePrimaryMessage(peerWs, JSON.stringify({ type: "cursor", seq }));

				await mesh.primaryMessageQueue;

				expect(mesh.registeredMembers.has(pendingNodeId)).toBe(true);
			});

			test("a message handler that throws does not permanently poison the primary queue - a later message still processes", async () => {
				const selfNodeId = await repository.haNodeId();
				const now = Date.now();
				for (const nodeId of [selfNodeId, "queue-recovery-peer-1", "queue-recovery-peer-2"]) {
					await repository.upsertHaClusterMember({
						node_id: nodeId,
						name: nodeId,
						version: APP_VERSION,
						admin_url: `https://${nodeId}.test`,
						first_seen_at: now,
						last_seen_at: now,
						credential_hash: await sha256Hex(`${nodeId}-credential`),
						activated_at: now,
					});
				}
				await mesh.loadRegisteredMembers();
				mesh.nodes.set(
					{ send: () => {}, close: () => {} },
					{
						nodeId: "queue-recovery-peer-1",
						name: "queue-recovery-peer-1",
						version: APP_VERSION,
						connectedAt: now,
						connected: true,
						lastSeenAt: now,
						adminUrl: "https://queue-recovery-peer-1.test",
						lastAckedSeq: Number.MAX_SAFE_INTEGER,
					},
				);
				mesh.nodes.set(
					{ send: () => {}, close: () => {} },
					{
						nodeId: "queue-recovery-peer-2",
						name: "queue-recovery-peer-2",
						version: APP_VERSION,
						connectedAt: now,
						connected: true,
						lastSeenAt: now,
						adminUrl: "https://queue-recovery-peer-2.test",
						lastAckedSeq: Number.MAX_SAFE_INTEGER,
					},
				);
				const pendingA = "pending-queue-recovery-a";
				const pendingB = "pending-queue-recovery-b";
				await insertPendingMember(pendingA);
				await insertPendingMember(pendingB);

				const originalHaClusterMembers = repository.haClusterMembers;
				let calls = 0;
				repository.haClusterMembers = async () => {
					calls += 1;
					if (calls === 1) throw new Error("simulated transient database failure");
					return await originalHaClusterMembers.call(repository);
				};

				const closesA: unknown[] = [];
				const wsA = { send: () => {}, close: (...args: unknown[]) => closesA.push(args), data: { authenticatedNodeId: pendingA, authenticatedActive: false } };
				mesh.enqueuePrimaryMessage(
					wsA,
					JSON.stringify({ type: "announce", nodeId: pendingA, name: pendingA, version: APP_VERSION, adminUrl: `https://${pendingA}.test` }),
				);
				const wsB = { send: () => {}, close: () => {}, data: { authenticatedNodeId: pendingB, authenticatedActive: false } };
				mesh.enqueuePrimaryMessage(
					wsB,
					JSON.stringify({ type: "announce", nodeId: pendingB, name: pendingB, version: APP_VERSION, adminUrl: `https://${pendingB}.test` }),
				);

				try {
					await mesh.primaryMessageQueue;
				} finally {
					repository.haClusterMembers = originalHaClusterMembers;
				}

				expect(closesA).toHaveLength(1);
				expect(mesh.registeredMembers.has(pendingA)).toBe(false);
				expect(mesh.registeredMembers.has(pendingB)).toBe(true);
			});
		});
	});
});

describe("HA mesh service: revertHaClusterMemberActivation is protected by the primary write barrier", () => {
	afterEach(async () => {
		await db`DELETE FROM ha_cluster_members`;
	});

	test("refuses to run while a promotion has closed the write barrier", async () => {
		const nodeId = "revert-barrier-promotion-fence";
		const now = Date.now();
		await db`INSERT INTO ha_cluster_members (node_id,name,version,admin_url,first_seen_at,last_seen_at,credential_hash,activated_at,revoked_at)
			VALUES (${nodeId},${nodeId},${APP_VERSION},${"https://revert-barrier.test"},${now},${now},${await sha256Hex("revert-barrier-credential")},${now},NULL)`;
		config.ha.fencedForPromotion = true;
		try {
			await expect(repository.revertHaClusterMemberActivation(nodeId)).rejects.toBeInstanceOf(HaPromotionWriteFenceError);
		} finally {
			config.ha.fencedForPromotion = false;
		}
		const row = await db`SELECT activated_at FROM ha_cluster_members WHERE node_id = ${nodeId}`;
		expect(row[0]?.activated_at).not.toBeNull();
	});

	test("refuses to run while durably authority-fenced", async () => {
		const nodeId = "revert-barrier-authority-fence";
		const now = Date.now();
		await db`INSERT INTO ha_cluster_members (node_id,name,version,admin_url,first_seen_at,last_seen_at,credential_hash,activated_at,revoked_at)
			VALUES (${nodeId},${nodeId},${APP_VERSION},${"https://revert-barrier.test"},${now},${now},${await sha256Hex("revert-barrier-credential-2")},${now},NULL)`;
		config.ha.authorityFence = { observedEpoch: 5, sourceNodeId: "some-other-node", observedAt: now };
		try {
			await expect(repository.revertHaClusterMemberActivation(nodeId)).rejects.toBeInstanceOf(HaPrimaryAuthorityFenceError);
		} finally {
			config.ha.authorityFence = null;
		}
	});

	test("succeeds normally outside any fence", async () => {
		const nodeId = "revert-barrier-normal";
		const now = Date.now();
		await db`INSERT INTO ha_cluster_members (node_id,name,version,admin_url,first_seen_at,last_seen_at,credential_hash,activated_at,revoked_at)
			VALUES (${nodeId},${nodeId},${APP_VERSION},${"https://revert-barrier.test"},${now},${now},${await sha256Hex("revert-barrier-credential-3")},${now},NULL)`;

		await repository.revertHaClusterMemberActivation(nodeId);

		const row = await db`SELECT activated_at FROM ha_cluster_members WHERE node_id = ${nodeId}`;
		expect(row[0]?.activated_at).toBeNull();
	});
});

describe("HA mesh service: waitForMembershipActivationDurability", () => {
	afterEach(async () => {
		mesh.nodes.clear();
		await db`DELETE FROM ha_cluster_members`;
	});

	function memberRecord(nodeId: string): { node_id: string } {
		return { node_id: nodeId };
	}

	function setAcked(nodeId: string, acked: boolean): void {
		mesh.nodes.set(
			{ send: () => {}, close: () => {} },
			{
				nodeId,
				name: nodeId,
				version: APP_VERSION,
				connectedAt: Date.now(),
				connected: true,
				lastSeenAt: Date.now(),
				adminUrl: `https://${nodeId}.test`,
				lastAckedSeq: acked ? Number.MAX_SAFE_INTEGER : null,
			},
		);
	}

	test("confirms true once self plus a majority of the OLD membership has durably applied at least this write", async () => {
		const oldMembers = [memberRecord("self"), memberRecord("old-peer-1"), memberRecord("old-peer-2")];
		setAcked("old-peer-1", true);

		const result = await mesh.waitForMembershipActivationDurability(oldMembers, 50);

		expect(result).toBe(true);
	});

	test("returns false once the timeout elapses without a majority of the OLD membership confirming", async () => {
		const oldMembers = [memberRecord("self"), memberRecord("old-peer-1"), memberRecord("old-peer-2")];
		setAcked("old-peer-1", false);
		setAcked("old-peer-2", false);

		const result = await mesh.waitForMembershipActivationDurability(oldMembers, 75);

		expect(result).toBe(false);
	});

	test("resolves true once a lagging OLD member's ack catches up mid-wait", async () => {
		const oldMembers = [memberRecord("self"), memberRecord("old-peer-1"), memberRecord("old-peer-2")];
		setAcked("old-peer-1", false);
		setAcked("old-peer-2", false);
		setTimeout(() => setAcked("old-peer-1", true), 40);

		const result = await mesh.waitForMembershipActivationDurability(oldMembers, 1_000);

		expect(result).toBe(true);
	});

	test("is a no-op (always true) below the auto-failover member floor - nothing left to durably confirm", async () => {
		const oldMembers = [memberRecord("self")];

		const start = Date.now();
		const result = await mesh.waitForMembershipActivationDurability(oldMembers, 5_000);

		expect(result).toBe(true);
		expect(Date.now() - start).toBeLessThan(1_000);
	});

	test("computes majority against the given OLD membership, not the current (already-larger) one", async () => {
		const oldMembers = [memberRecord("self"), memberRecord("old-peer-1"), memberRecord("old-peer-2")];

		setAcked("just-activated-node", true);
		setAcked("another-new-node", true);

		const result = await mesh.waitForMembershipActivationDurability(oldMembers, 75);

		expect(result).toBe(false);
	});
});

describe("HA mesh service: master key auto-provisioning over the mesh handshake", () => {
	const originalMasterKey = config.masterKey;
	const originalMasterKeyFile = config.masterKeyFile;
	const originalMasterKeyAutoGenerated = config.masterKeyAutoGenerated;
	const originalSharedToken = config.ha.sharedToken;
	const originalEpoch = config.ha.epoch;
	const originalNeedsBootstrap = repository.needsBootstrap;
	const originalBootstrapSnapshot = mesh.bootstrapSnapshot;
	const originalRunCatchUp = mesh.runCatchUp;
	let tempDir: string | null = null;

	afterEach(async () => {
		config.masterKey = originalMasterKey;
		config.masterKeyFile = originalMasterKeyFile;
		config.masterKeyAutoGenerated = originalMasterKeyAutoGenerated;
		config.ha.sharedToken = originalSharedToken;
		config.ha.epoch = originalEpoch;
		repository.needsBootstrap = originalNeedsBootstrap;
		mesh.bootstrapSnapshot = originalBootstrapSnapshot;
		mesh.runCatchUp = originalRunCatchUp;
		resetMasterKeyCache();
		mesh.state = "unknown";
		mesh.replicaSocket = null;
		await db`DELETE FROM ha_cluster_config`;
		if (tempDir) {
			await rm(tempDir, { recursive: true, force: true });
			tempDir = null;
		}
	});

	test("primary responds to a request_master_key message with its own resolved master key", async () => {
		const sent: string[] = [];
		const ws = { send: (data: string) => sent.push(data), close: () => {} };
		await mesh.handlePrimaryMessage(ws, JSON.stringify({ type: "request_master_key" }));
		expect(sent).toHaveLength(1);
		expect(JSON.parse(sent[0]!)).toEqual({ type: "master_key", key: config.masterKey });
	});

	test("a replica with no master key of its own requests one instead of attempting the normal key check, then installs it and proceeds once it arrives", async () => {
		tempDir = await mkdtemp(join(tmpdir(), "bg-mesh-master-key-test-"));
		const keyPath = join(tempDir, "master.key");
		await Bun.write(keyPath, "throwaway-auto-generated-key-at-least-32-chars");
		config.masterKey = null;
		config.masterKeyFile = keyPath;
		config.masterKeyAutoGenerated = true;
		resetMasterKeyCache();
		repository.needsBootstrap = async () => true;
		mesh.bootstrapSnapshot = async () => {};
		mesh.runCatchUp = async () => {};

		const sent: string[] = [];
		mesh.state = "unknown";
		mesh.replicaSocket = fakeSocket((data) => sent.push(data));

		mesh.handleIncomingMessage({
			data: JSON.stringify({ type: "hello", keyCheck: "irrelevant-with-no-local-key-to-verify-it-against", version: APP_VERSION }),
		} as MessageEvent);
		await mesh.messageQueue;
		expect(sent).toHaveLength(1);
		expect(JSON.parse(sent[0]!)).toEqual({ type: "request_master_key" });
		expect(mesh.state).not.toBe("connected");

		const primaryKey = "d".repeat(40);
		mesh.handleIncomingMessage({ data: JSON.stringify({ type: "master_key", key: primaryKey }) } as MessageEvent);
		await mesh.messageQueue;

		expect((await Bun.file(keyPath).text()).trim()).toBe(primaryKey);
		expect(mesh.state).toBe("connected");

		const types = sent.map((data) => (JSON.parse(data) as { type: string }).type);
		expect(types[0]).toBe("request_master_key");
		expect(types).toContain("announce");
		expect(types).toContain("cursor");
		const cursorMessage = sent.map((data) => JSON.parse(data) as { type: string; seq?: number }).find((message) => message.type === "cursor");
		expect(cursorMessage).toEqual({ type: "cursor", seq: 0 });
	});

	test("refuses a stale-epoch primary even on the path that has to request a master key first", async () => {
		tempDir = await mkdtemp(join(tmpdir(), "bg-mesh-master-key-test-"));
		const keyPath = join(tempDir, "master.key");
		await Bun.write(keyPath, "throwaway-auto-generated-key-at-least-32-chars");
		config.masterKey = null;
		config.masterKeyFile = keyPath;
		config.masterKeyAutoGenerated = true;
		resetMasterKeyCache();
		repository.needsBootstrap = async () => true;
		config.ha.epoch = 5;

		const sent: string[] = [];
		mesh.state = "unknown";
		mesh.replicaSocket = fakeSocket((data) => sent.push(data));

		mesh.handleIncomingMessage({ data: JSON.stringify({ type: "hello", keyCheck: "irrelevant", epoch: 2, version: APP_VERSION }) } as MessageEvent);
		await mesh.messageQueue;

		expect(sent.map((data) => (JSON.parse(data) as { type: string }).type)).toEqual(["announce"]);
		expect(mesh.state).toBe("epoch_mismatch");
		expect(config.ha.epoch).toBe(5);
	});

	test("re-encrypts and persists this node's shared token under the newly-installed key, so a future boot can still decrypt it", async () => {
		tempDir = await mkdtemp(join(tmpdir(), "bg-mesh-master-key-test-"));
		const keyPath = join(tempDir, "master.key");
		await Bun.write(keyPath, "throwaway-auto-generated-key-at-least-32-chars");
		config.masterKey = null;
		config.masterKeyFile = keyPath;
		config.masterKeyAutoGenerated = true;
		resetMasterKeyCache();
		mesh.bootstrapSnapshot = async () => {};
		mesh.runCatchUp = async () => {};

		const plaintextToken = "the-cluster-shared-token";
		await repository.insertHaClusterConfig({
			enabled: true,
			role: "replica",
			nodeName: "reencrypt-test-node",
			primaryUrl: "https://primary.test:7443",
			primaryAdminUrl: "https://primary.test",
			sharedTokenEncrypted: await encryptSecret(plaintextToken),
			selfAdminUrl: null,
			clusterEpoch: 0,
		});
		config.ha.sharedToken = plaintextToken;
		mesh.state = "unknown";
		mesh.replicaSocket = fakeSocket();

		const primaryKey = "e".repeat(40);
		mesh.handleIncomingMessage({ data: JSON.stringify({ type: "master_key", key: primaryKey }) } as MessageEvent);
		await mesh.messageQueue;

		const row = await repository.haClusterConfigRow();

		expect(await decryptSecret(row!.shared_token_encrypted!)).toBe(plaintextToken);
	});

	test("a replica with an operator-configured master key never auto-requests one, even mid-bootstrap - a real mismatch still surfaces as key_mismatch", async () => {
		config.masterKey = "an-operator-set-key-that-does-not-match-the-primary";
		config.masterKeyFile = null;
		config.masterKeyAutoGenerated = false;
		repository.needsBootstrap = async () => true;

		const sent: string[] = [];
		mesh.state = "unknown";
		mesh.replicaSocket = fakeSocket((data) => sent.push(data));

		mesh.handleIncomingMessage({ data: JSON.stringify({ type: "hello", keyCheck: "v1.bogus.bogus", version: APP_VERSION }) } as MessageEvent);
		await mesh.messageQueue;

		expect(sent).toHaveLength(0);
		expect(mesh.state).toBe("key_mismatch");
	});
});

describe("HA mesh service: cluster epoch handshake", () => {
	const originalMasterKey = config.masterKey;
	const originalMasterKeyFile = config.masterKeyFile;
	const originalMasterKeyAutoGenerated = config.masterKeyAutoGenerated;
	const originalEpoch = config.ha.epoch;
	const originalNeedsBootstrap = repository.needsBootstrap;
	const originalBootstrapSnapshot = mesh.bootstrapSnapshot;
	const originalRunCatchUp = mesh.runCatchUp;
	const originalUpdateHaClusterConfig = repository.updateHaClusterConfig;

	afterEach(() => {
		config.masterKey = originalMasterKey;
		config.masterKeyFile = originalMasterKeyFile;
		config.masterKeyAutoGenerated = originalMasterKeyAutoGenerated;
		config.ha.epoch = originalEpoch;
		repository.needsBootstrap = originalNeedsBootstrap;
		mesh.bootstrapSnapshot = originalBootstrapSnapshot;
		mesh.runCatchUp = originalRunCatchUp;
		repository.updateHaClusterConfig = originalUpdateHaClusterConfig;
		mesh.state = "unknown";
		mesh.replicaSocket = null;
		resetMasterKeyCache();
	});

	test("refuses a primary reporting an epoch older than one this node has already seen", async () => {
		config.masterKey = "a-consistent-key-for-this-epoch-test-at-least-32-chars";
		config.masterKeyFile = null;
		config.masterKeyAutoGenerated = false;
		resetMasterKeyCache();
		repository.needsBootstrap = async () => false;
		config.ha.epoch = 5;

		const keyCheck = await encryptSecret("burrowgate-ha-key-check");
		mesh.state = "unknown";
		const sent: string[] = [];
		mesh.replicaSocket = fakeSocket((data) => sent.push(data));

		mesh.handleIncomingMessage({ data: JSON.stringify({ type: "hello", keyCheck, epoch: 3, version: APP_VERSION }) } as MessageEvent);
		await mesh.messageQueue;

		expect(mesh.state).toBe("epoch_mismatch");
		expect(config.ha.epoch).toBe(5);
		expect(JSON.parse(sent[0]!)).toMatchObject({ type: "announce", epoch: 5 });
	});

	test("adopts a newer epoch from the primary and persists it, without refusing the connection", async () => {
		config.masterKey = "a-consistent-key-for-this-epoch-test-at-least-32-chars";
		config.masterKeyFile = null;
		config.masterKeyAutoGenerated = false;
		resetMasterKeyCache();
		repository.needsBootstrap = async () => false;
		mesh.bootstrapSnapshot = async () => {};
		mesh.runCatchUp = async () => {};
		let persistedEpoch: number | undefined;
		repository.updateHaClusterConfig = async (patch) => {
			persistedEpoch = patch.clusterEpoch;
		};
		config.ha.epoch = 2;

		const keyCheck = await encryptSecret("burrowgate-ha-key-check");
		mesh.state = "unknown";
		mesh.replicaSocket = fakeSocket();

		mesh.handleIncomingMessage({ data: JSON.stringify({ type: "hello", keyCheck, epoch: 4, version: APP_VERSION }) } as MessageEvent);
		await mesh.messageQueue;

		expect(mesh.state).toBe("connected");
		expect(config.ha.epoch).toBe(4);
		expect(persistedEpoch).toBe(4);
	});
});

describe("HA mesh service: pruning-safe catch-up", () => {
	const originalFetch = globalThis.fetch;
	const originalPrimaryUrl = config.ha.primaryUrl;
	const originalSharedToken = config.ha.sharedToken;

	afterEach(() => {
		globalThis.fetch = originalFetch;
		config.ha.primaryUrl = originalPrimaryUrl;
		config.ha.sharedToken = originalSharedToken;
		mesh.cursor = 0;
	});

	function mockSnapshotFetch(changelogResponse: unknown): { snapshotFetched: () => boolean } {
		let snapshotFetched = false;
		globalThis.fetch = (async (url: unknown) => {
			const path = new URL(String(url)).pathname;
			if (path === "/_ha/changelog") return Response.json(changelogResponse);
			if (path === "/_ha/snapshot") {
				snapshotFetched = true;
				return Response.json({ seq: 50, rows: [] });
			}
			throw new Error(`unexpected fetch to ${path}`);
		}) as unknown as typeof fetch;
		return { snapshotFetched: () => snapshotFetched };
	}

	function stubBootstrapDependencies(onReconcile?: (rows: unknown[]) => void) {
		const originals = {
			reconcileToSnapshot: repository.reconcileToSnapshot,
			updateReplicationCursor: repository.updateReplicationCursor,
			markBootstrapped: repository.markBootstrapped,
		};
		repository.reconcileToSnapshot = async (rows) => {
			onReconcile?.(rows);
		};
		repository.updateReplicationCursor = async () => {};
		repository.markBootstrapped = async () => {};
		return () => {
			repository.reconcileToSnapshot = originals.reconcileToSnapshot;
			repository.updateReplicationCursor = originals.updateReplicationCursor;
			repository.markBootstrapped = originals.markBootstrapped;
		};
	}

	test("a visible gap (returned rows jump past cursor+1) triggers a full re-bootstrap via reconcileToSnapshot", async () => {
		config.ha.primaryUrl = "https://primary.test";
		config.ha.sharedToken = "test-token";
		mesh.cursor = 5;

		const { snapshotFetched } = mockSnapshotFetch({
			rows: [{ seq: 50, entity_type: "site", entity_id: "s1", op: "insert", payload_json: "{}", created_at: Date.now() }],
			latestSeq: 50,
		});
		let reconciledWith: unknown[] = ["not yet called"];
		const restore = stubBootstrapDependencies((rows) => {
			reconciledWith = rows;
		});
		try {
			await mesh.runCatchUp();
			expect(snapshotFetched()).toBe(true);
			expect(reconciledWith).toEqual([]);
			expect(mesh.cursor).toBe(50);
		} finally {
			restore();
		}
	});

	test("an invisible gap (empty page, but the primary's latestSeq is past cursor) also triggers a re-bootstrap", async () => {
		config.ha.primaryUrl = "https://primary.test";
		config.ha.sharedToken = "test-token";
		mesh.cursor = 5;

		const { snapshotFetched } = mockSnapshotFetch({ rows: [], latestSeq: 200 });
		const restore = stubBootstrapDependencies();
		try {
			await mesh.runCatchUp();
			expect(snapshotFetched()).toBe(true);
			expect(mesh.cursor).toBe(50);
		} finally {
			restore();
		}
	});

	test("an empty page with latestSeq no higher than cursor is genuinely caught up - no re-bootstrap", async () => {
		config.ha.primaryUrl = "https://primary.test";
		config.ha.sharedToken = "test-token";
		mesh.cursor = 5;
		const { snapshotFetched } = mockSnapshotFetch({ rows: [], latestSeq: 5 });
		const restore = stubBootstrapDependencies();
		try {
			await mesh.runCatchUp();
			expect(snapshotFetched()).toBe(false);
			expect(mesh.cursor).toBe(5);
		} finally {
			restore();
		}
	});
});

describe("HA mesh service: repeated apply failures force a re-bootstrap", () => {
	afterEach(() => {
		mesh.cursor = 0;
		mesh.consecutiveApplyFailureSeq = null;
		mesh.consecutiveApplyFailureCount = 0;
		mesh.hasBootstrapped = false;
	});

	test("forcing a re-bootstrap after the threshold clears hasBootstrapped immediately, not on the next reconnect", async () => {
		const originalApply = repository.applyReplicatedChange;
		const originalForceRebootstrap = repository.forceRebootstrap;
		const previousEnabled = config.ha.enabled;
		const previousRole: typeof config.ha.role = config.ha.role;
		config.ha.enabled = true;
		config.ha.role = "replica";
		repository.applyReplicatedChange = async () => {
			throw new Error("simulated apply failure");
		};
		repository.forceRebootstrap = async () => {};
		mesh.hasBootstrapped = true;
		const row = { seq: 1, entity_type: "site" as ReplicatedEntityType, entity_id: "s1", op: "insert" as const, payload_json: "{}", created_at: Date.now() };
		try {
			for (let attempt = 1; attempt < APPLY_FAILURE_REBOOTSTRAP_THRESHOLD; attempt++) {
				await expect(mesh.applyRow(row)).rejects.toThrow("simulated apply failure");
				expect(mesh.hasBootstrapped).toBe(true);
			}
			await expect(mesh.applyRow(row)).rejects.toThrow("simulated apply failure");
			expect(mesh.hasBootstrapped).toBe(false);
			expect(mesh.ready()).toBe(false);
		} finally {
			repository.applyReplicatedChange = originalApply;
			repository.forceRebootstrap = originalForceRebootstrap;
			config.ha.enabled = previousEnabled;
			config.ha.role = previousRole;
		}
	});

	test("the same seq failing repeatedly forces a re-bootstrap after the threshold, then resets", async () => {
		const originalApply = repository.applyReplicatedChange;
		const originalForceRebootstrap = repository.forceRebootstrap;
		repository.applyReplicatedChange = async () => {
			throw new Error("simulated apply failure");
		};
		let forceRebootstrapCalls = 0;
		repository.forceRebootstrap = async () => {
			forceRebootstrapCalls += 1;
		};
		const row = { seq: 1, entity_type: "site" as ReplicatedEntityType, entity_id: "s1", op: "insert" as const, payload_json: "{}", created_at: Date.now() };
		try {
			for (let attempt = 1; attempt < APPLY_FAILURE_REBOOTSTRAP_THRESHOLD; attempt++) {
				await expect(mesh.applyRow(row)).rejects.toThrow("simulated apply failure");
				expect(forceRebootstrapCalls).toBe(0);
			}
			await expect(mesh.applyRow(row)).rejects.toThrow("simulated apply failure");
			expect(forceRebootstrapCalls).toBe(1);

			expect(mesh.consecutiveApplyFailureCount).toBe(0);
		} finally {
			repository.applyReplicatedChange = originalApply;
			repository.forceRebootstrap = originalForceRebootstrap;
		}
	});

	test("a different seq failing resets the counter instead of accumulating across unrelated rows", async () => {
		const originalApply = repository.applyReplicatedChange;
		const originalForceRebootstrap = repository.forceRebootstrap;
		repository.applyReplicatedChange = async () => {
			throw new Error("simulated apply failure");
		};
		let forceRebootstrapCalls = 0;
		repository.forceRebootstrap = async () => {
			forceRebootstrapCalls += 1;
		};
		try {
			for (let seq = 1; seq < APPLY_FAILURE_REBOOTSTRAP_THRESHOLD + 5; seq++) {
				await expect(
					mesh.applyRow({ seq, entity_type: "site", entity_id: `s${seq}`, op: "insert", payload_json: "{}", created_at: Date.now() }),
				).rejects.toThrow("simulated apply failure");
			}
			expect(forceRebootstrapCalls).toBe(0);
		} finally {
			repository.applyReplicatedChange = originalApply;
			repository.forceRebootstrap = originalForceRebootstrap;
		}
	});

	test("a successful apply resets the counter", async () => {
		const originalApply = repository.applyReplicatedChange;
		const originalUpdateCursor = repository.updateReplicationCursor;
		let shouldFail = true;
		repository.applyReplicatedChange = async () => {
			if (shouldFail) throw new Error("simulated apply failure");
		};
		repository.updateReplicationCursor = async () => {};
		try {
			const row = { seq: 1, entity_type: "site" as ReplicatedEntityType, entity_id: "s1", op: "insert" as const, payload_json: "{}", created_at: Date.now() };
			await expect(mesh.applyRow(row)).rejects.toThrow("simulated apply failure");
			expect(mesh.consecutiveApplyFailureCount).toBe(1);
			shouldFail = false;
			await mesh.applyRow(row);
			expect(mesh.consecutiveApplyFailureCount).toBe(0);
			expect(mesh.consecutiveApplyFailureSeq).toBeNull();
		} finally {
			repository.applyReplicatedChange = originalApply;
			repository.updateReplicationCursor = originalUpdateCursor;
		}
	});
});

describe("HA mesh service: runtime invalidation on a replicated write", () => {
	afterEach(() => {
		mesh.cursor = 0;
	});

	test("applyRow completes without throwing for every entity type that now triggers extra invalidation", async () => {
		const originalApply = repository.applyReplicatedChange;
		const originalUpdateCursor = repository.updateReplicationCursor;
		repository.applyReplicatedChange = async () => {};
		repository.updateReplicationCursor = async () => {};
		const entityTypes: ReplicatedEntityType[] = [
			"site",
			"site_origin",
			"certificate",
			"site_tls_settings",
			"ip_rule",
			"country_rule",
			"asn_rule",
			"route_ip_rule",
			"route_country_rule",
			"route_asn_rule",
			"route_policy",
		];
		try {
			let seq = 0;
			for (const entityType of entityTypes) {
				seq += 1;
				mesh.cursor = seq - 1;
				await mesh.applyRow({ seq, entity_type: entityType, entity_id: `entity-${seq}`, op: "insert", payload_json: "{}", created_at: Date.now() });
				expect(mesh.cursor).toBe(seq);
			}
		} finally {
			repository.applyReplicatedChange = originalApply;
			repository.updateReplicationCursor = originalUpdateCursor;
		}
	});
});

describe("HA mesh service: runtime convergence fencing", () => {
	const originalInitialize = loadBalancer.initialize;
	const originalRole = config.ha.role;
	const originalEnabled = config.ha.enabled;

	afterEach(() => {
		loadBalancer.initialize = originalInitialize;
		config.ha.role = originalRole;
		config.ha.enabled = originalEnabled;
		mesh.cursor = 0;
		mesh.hasBootstrapped = false;
		mesh.verifiedConnectionThisProcess = false;
		mesh.state = "unknown";
		mesh.runtimeConvergenceFenced = false;
		mesh.consecutiveRuntimeConvergenceFailures = 0;
	});

	function primeReadyReplica(): void {
		config.ha.enabled = true;
		config.ha.role = "replica";
		mesh.hasBootstrapped = true;
		mesh.verifiedConnectionThisProcess = true;
		mesh.state = "connected";
		mesh.lastVerifiedSyncAt = Date.now();
		mesh.primaryAuthorityAmbiguous = false;
	}

	test("a replicated write that applies to the DB but fails to refresh runtime state marks the node unhealthy without throwing", async () => {
		const originalApply = repository.applyReplicatedChange;
		const originalUpdateCursor = repository.updateReplicationCursor;
		repository.applyReplicatedChange = async () => {};
		repository.updateReplicationCursor = async () => {};
		loadBalancer.initialize = async () => {
			throw new Error("simulated load-balancer refresh failure");
		};
		primeReadyReplica();
		try {
			expect(mesh.ready()).toBe(true);
			await expect(
				mesh.applyRow({ seq: 1, entity_type: "site", entity_id: "s1", op: "insert", payload_json: "{}", created_at: Date.now() }),
			).resolves.toBeUndefined();
			expect(mesh.runtimeConvergenceFenced).toBe(true);
			expect(mesh.ready()).toBe(false);
		} finally {
			repository.applyReplicatedChange = originalApply;
			repository.updateReplicationCursor = originalUpdateCursor;
		}
	});

	test("clears the fence and restores readiness once a retry succeeds", async () => {
		const originalApply = repository.applyReplicatedChange;
		const originalUpdateCursor = repository.updateReplicationCursor;
		repository.applyReplicatedChange = async () => {};
		repository.updateReplicationCursor = async () => {};
		loadBalancer.initialize = async () => {
			throw new Error("simulated load-balancer refresh failure");
		};
		primeReadyReplica();
		try {
			await mesh.applyRow({ seq: 1, entity_type: "site", entity_id: "s1", op: "insert", payload_json: "{}", created_at: Date.now() });
			expect(mesh.ready()).toBe(false);

			loadBalancer.initialize = originalInitialize;
			await mesh.retryRuntimeConvergenceIfFenced();

			expect(mesh.runtimeConvergenceFenced).toBe(false);
			expect(mesh.consecutiveRuntimeConvergenceFailures).toBe(0);
			expect(mesh.ready()).toBe(true);
		} finally {
			repository.applyReplicatedChange = originalApply;
			repository.updateReplicationCursor = originalUpdateCursor;
		}
	});

	test("restarts after repeated retries keep failing, instead of staying fenced forever", async () => {
		restartCalls = [];
		loadBalancer.initialize = async () => {
			throw new Error("simulated load-balancer refresh failure");
		};
		primeReadyReplica();
		mesh.runtimeConvergenceFenced = true;
		mesh.consecutiveRuntimeConvergenceFailures = 0;

		for (let attempt = 1; attempt < RUNTIME_CONVERGENCE_RESTART_THRESHOLD; attempt++) {
			await mesh.retryRuntimeConvergenceIfFenced();
			expect(mesh.runtimeConvergenceFenced).toBe(true);
			expect(restartCalls).not.toContain("ha-runtime-convergence-failure");
		}
		await mesh.retryRuntimeConvergenceIfFenced();

		expect(mesh.consecutiveRuntimeConvergenceFailures).toBe(0);
		await new Promise((resolve) => setTimeout(resolve, 350));
		expect(restartCalls).toContain("ha-runtime-convergence-failure");
	});
});

describe("HA mesh service: bootstrap refreshes runtime state", () => {
	const originalFetch = globalThis.fetch;
	const originalPrimaryUrl = config.ha.primaryUrl;
	const originalSharedToken = config.ha.sharedToken;

	afterEach(() => {
		globalThis.fetch = originalFetch;
		config.ha.primaryUrl = originalPrimaryUrl;
		config.ha.sharedToken = originalSharedToken;
		mesh.cursor = 0;
	});

	test("bootstrapSnapshot leaves the load balancer's origin map reflecting a snapshot-delivered origin, with no other trigger", async () => {
		config.ha.primaryUrl = "https://primary.test";
		config.ha.sharedToken = "test-token";
		const now = Date.now();
		const origin: SiteOriginRecord = {
			id: "origin_bootstrap_refresh_test",
			site_id: "site_bootstrap_refresh_test",
			name: "snapshot-delivered origin",
			origin_type: "proxy",
			origin_url: "https://snapshot-origin.test",
			static_index_file: null,
			static_spa_fallback: 0,
			enabled: 1,
			draining: 0,
			priority: 0,
			weight: 1,
			health_check_path: null,
			is_primary: 1,
			mtls_enabled: 0,
			mtls_certificate_pem: null,
			mtls_encrypted_private_key: null,
			mtls_ca_pem: null,
			created_at: now,
			updated_at: now,
		};
		globalThis.fetch = (async (url: unknown) => {
			const path = new URL(String(url)).pathname;
			if (path === "/_ha/snapshot") {
				const body = [
					JSON.stringify({ type: "meta", seq: 10 }),
					JSON.stringify({ type: "row", row: { entity_type: "site_origin", entity_id: origin.id, payload_json: JSON.stringify(origin) } }),
					"",
				].join("\n");
				return new Response(body, { headers: { "content-type": "application/x-ndjson" } });
			}
			throw new Error(`unexpected fetch to ${path}`);
		}) as unknown as typeof fetch;

		expect(loadBalancer.origins(origin.site_id)).toHaveLength(0);

		await mesh.bootstrapSnapshot();

		expect(loadBalancer.origins(origin.site_id)).toHaveLength(1);
		expect(loadBalancer.origins(origin.site_id)[0]!.id).toBe(origin.id);
	});

	test("an interrupted streaming snapshot never swaps in partially staged state", async () => {
		config.ha.primaryUrl = "https://primary.test";
		config.ha.sharedToken = "test-token";
		globalThis.fetch = (async () =>
			new Response(
				`${JSON.stringify({ type: "meta", seq: 20 })}\n${JSON.stringify({ type: "row", row: { entity_type: "site", entity_id: "partial", payload_json: "{}" } })}\n{truncated`,
				{
					headers: { "content-type": "application/x-ndjson" },
				},
			)) as unknown as typeof fetch;
		const originalReconcile = repository.reconcileStagedSnapshot;
		let reconciled = false;
		repository.reconcileStagedSnapshot = async () => {
			reconciled = true;
		};
		try {
			await expect(mesh.bootstrapSnapshot()).rejects.toThrow();
			expect(reconciled).toBe(false);
		} finally {
			repository.reconcileStagedSnapshot = originalReconcile;
		}
	});

	test("bootstrapSnapshot collapses concurrent callers onto a single in-flight attempt", async () => {
		config.ha.primaryUrl = "https://primary.test";
		config.ha.sharedToken = "test-token";
		let fetchCallCount = 0;
		globalThis.fetch = (async () => {
			fetchCallCount += 1;
			const body = [JSON.stringify({ type: "meta", seq: 30 }), ""].join("\n");
			return new Response(body, { headers: { "content-type": "application/x-ndjson" } });
		}) as unknown as typeof fetch;

		const first = mesh.bootstrapSnapshot();
		const second = mesh.bootstrapSnapshot();
		await Promise.all([first, second]);

		expect(fetchCallCount).toBe(1);
	});

	test("a later bootstrapSnapshot call after one completes still performs a fresh fetch", async () => {
		config.ha.primaryUrl = "https://primary.test";
		config.ha.sharedToken = "test-token";
		let fetchCallCount = 0;
		globalThis.fetch = (async () => {
			fetchCallCount += 1;
			const body = [JSON.stringify({ type: "meta", seq: 40 }), ""].join("\n");
			return new Response(body, { headers: { "content-type": "application/x-ndjson" } });
		}) as unknown as typeof fetch;

		await mesh.bootstrapSnapshot();
		await mesh.bootstrapSnapshot();

		expect(fetchCallCount).toBe(2);
	});
});

describe("HA mesh service: replica readiness", () => {
	const originalNodeName = config.ha.nodeName;
	const originalSelfAdminUrl = config.ha.selfAdminUrl;
	const originalDisconnectedGrace = config.ha.disconnectedReadyGraceSeconds;
	const originalMaxSyncStaleness = config.ha.maxSyncStalenessSeconds;

	afterEach(() => {
		mesh.hasBootstrapped = false;
		mesh.state = "unknown";
		mesh.disconnectedSince = Date.now();
		mesh.verifiedConnectionThisProcess = false;
		mesh.lastVerifiedSyncAt = 0;
		mesh.primaryAuthorityAmbiguous = false;
		mesh.replicaSocket = null;
		config.ha.enabled = false;
		config.ha.role = "primary";

		config.ha.nodeName = originalNodeName;
		config.ha.selfAdminUrl = originalSelfAdminUrl;
		config.ha.disconnectedReadyGraceSeconds = originalDisconnectedGrace;
		config.ha.maxSyncStalenessSeconds = originalMaxSyncStaleness;
		config.ha.fencedForPromotion = false;
		mesh.primaryAuthorityAmbiguous = false;
		mesh.server = null;
	});

	test("HA disabled is always ready", () => {
		config.ha.enabled = false;
		expect(mesh.ready()).toBe(true);
	});

	test("a primary with an active promotion fence is removed from load-balancer readiness", () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		config.ha.fencedForPromotion = true;
		mesh.server = {};
		expect(mesh.ready()).toBe(false);
		config.ha.fencedForPromotion = false;
		mesh.server = null;
	});

	test("a primary with a durable stale-authority fence is removed from load-balancer readiness", () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		config.ha.authorityFence = { observedEpoch: 8, sourceNodeId: "newer-node", observedAt: Date.now() };
		mesh.server = {};
		expect(mesh.ready()).toBe(false);
	});

	test("a replica that has never bootstrapped is not ready", () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		mesh.hasBootstrapped = false;
		expect(mesh.ready()).toBe(false);
	});

	test("a bootstrapped replica stays ready during the short disconnect grace period", () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		mesh.hasBootstrapped = true;
		mesh.verifiedConnectionThisProcess = true;
		mesh.state = "disconnected";
		mesh.disconnectedSince = Date.now();
		expect(mesh.ready()).toBe(true);
	});

	test("a bootstrapped replica is not ready after process restart until it freshly verifies the primary", () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		mesh.hasBootstrapped = true;
		mesh.verifiedConnectionThisProcess = false;
		mesh.state = "unknown";
		mesh.disconnectedSince = Date.now();
		expect(mesh.ready()).toBe(false);
	});

	test("a replica leaves readiness after its disconnected grace period expires", () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		config.ha.disconnectedReadyGraceSeconds = 60;
		mesh.hasBootstrapped = true;
		mesh.verifiedConnectionThisProcess = true;
		mesh.state = "disconnected";
		mesh.disconnectedSince = Date.now() - 60_001;
		expect(mesh.ready()).toBe(false);
	});

	test("an open but heartbeat-stalled replica ages out of readiness", () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		config.ha.maxSyncStalenessSeconds = 30;
		mesh.hasBootstrapped = true;
		mesh.verifiedConnectionThisProcess = true;
		mesh.state = "connected";
		mesh.lastVerifiedSyncAt = Date.now() - 30_001;
		expect(mesh.ready()).toBe(false);
	});

	test("a successfully processed heartbeat is acknowledged even when the cursor did not change", async () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		mesh.hasBootstrapped = true;
		mesh.verifiedConnectionThisProcess = true;
		mesh.state = "connected";
		mesh.cursor = 12;
		const sent: string[] = [];
		mesh.replicaSocket = fakeSocket((data) => sent.push(data));

		await mesh.handleMessage({ data: JSON.stringify({ type: "heartbeat", latestSeq: 12, primaryFenced: false }) } as MessageEvent, mesh.connectionGeneration);

		expect(sent.map((value) => JSON.parse(value))).toContainEqual({ type: "cursor", seq: 12 });
		expect(mesh.lastVerifiedSyncAt).toBeGreaterThan(0);
	});

	test("a caught-up replica is unready while its connected primary advertises an ambiguous promotion fence", async () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		mesh.hasBootstrapped = true;
		mesh.verifiedConnectionThisProcess = true;
		mesh.state = "connected";
		mesh.cursor = 0;
		mesh.lastVerifiedSyncAt = Date.now();
		mesh.primaryAuthorityAmbiguous = false;
		const sent: string[] = [];
		mesh.replicaSocket = { send: (data: string) => sent.push(data) };

		await mesh.handleMessage(
			{ data: JSON.stringify({ type: "heartbeat", latestSeq: 0, primaryFenced: true, promotionId: "readiness-fence" }) } as MessageEvent,
			mesh.connectionGeneration,
		);
		expect(mesh.ready()).toBe(false);
		expect(JSON.parse(sent[0]!)).toEqual({ type: "promotion_fence_ack", promotionId: "readiness-fence" });

		await mesh.handleMessage({ data: JSON.stringify({ type: "heartbeat", latestSeq: 0, primaryFenced: false }) } as MessageEvent, mesh.connectionGeneration);
		expect(mesh.ready()).toBe(true);
	});

	test("key and epoch mismatches are never ready even during the disconnect grace period", () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		mesh.hasBootstrapped = true;
		mesh.disconnectedSince = Date.now();
		mesh.state = "key_mismatch";
		expect(mesh.ready()).toBe(false);
		mesh.state = "epoch_mismatch";
		expect(mesh.ready()).toBe(false);
	});

	test("closing a stale-epoch connection never converts it into a fresh readiness grace period", () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		mesh.hasBootstrapped = true;
		mesh.verifiedConnectionThisProcess = true;
		mesh.state = "epoch_mismatch";
		mesh.disconnectedSince = Date.now();
		mesh.stopped = true;
		mesh.handleReplicaClose({ code: 4000, reason: "stale primary epoch" });
		mesh.stopped = false;
		expect(mesh.state).toBe("epoch_mismatch");
		expect(mesh.ready()).toBe(false);
	});

	test("a policy-rejected replica is unready instead of repeatedly receiving disconnect grace", () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		mesh.hasBootstrapped = true;
		mesh.verifiedConnectionThisProcess = true;
		mesh.state = "connected";
		mesh.stopped = true;
		mesh.handleReplicaClose({ code: 1008, reason: "a node with this identity is already connected" });
		mesh.stopped = false;
		expect(mesh.state).toBe("connection_rejected");
		expect(mesh.ready()).toBe(false);
	});

	// Found in production: a primary that regenerates its own certificate independently of any role
	// change (e.g. self-healing a stale SAN on a later restart) leaves an already-pinned replica
	// stuck retrying forever against a CA that no longer matches anything the primary serves, since
	// resolveCaCertificate only ever re-fetches when NOTHING is pinned yet. A 1015 close (Bun's code
	// for a failed TLS handshake) is the exact symptom this produces.
	test("a TLS handshake failure while a certificate is pinned clears the pin so the next attempt re-fetches", () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		mesh.hasBootstrapped = true;
		mesh.stopped = true;
		mesh.caCertificate = "stale-primary-certificate";
		mesh.handleReplicaClose({ code: 1015, reason: "TLS handshake failed" });
		mesh.stopped = false;
		expect(mesh.caCertificate).toBeNull();
	});

	test("a TLS handshake failure with nothing pinned yet is a no-op for the pin itself", () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		mesh.hasBootstrapped = true;
		mesh.stopped = true;
		mesh.caCertificate = null;
		mesh.handleReplicaClose({ code: 1015, reason: "TLS handshake failed" });
		mesh.stopped = false;
		expect(mesh.caCertificate).toBeNull();
	});

	test("a close for any other reason does not clear an already-pinned certificate", () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		mesh.hasBootstrapped = true;
		mesh.stopped = true;
		mesh.caCertificate = "still-good-primary-certificate";
		mesh.handleReplicaClose({ code: 1006, reason: "connection lost" });
		mesh.stopped = false;
		expect(mesh.caCertificate).toBe("still-good-primary-certificate");
	});

	test("a replica with a primary-version mismatch is removed from readiness", () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		mesh.hasBootstrapped = true;
		mesh.state = "version_mismatch";
		expect(mesh.ready()).toBe(false);
	});

	test("a version-mismatched replica refuses replication but announces its real version to fence the primary", async () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		config.ha.nodeName = "upgrade-replica";
		config.ha.selfAdminUrl = "https://upgrade-replica.test";
		mesh.nodeId = "upgrade-replica-id";
		mesh.hasBootstrapped = true;
		const sent: string[] = [];
		mesh.replicaSocket = fakeSocket((data) => sent.push(data));

		await mesh.handleHello({ type: "hello", keyCheck: "unused-on-version-mismatch", epoch: 0, version: "0.0.1" });

		expect(mesh.state).toBe("version_mismatch");
		expect(mesh.ready()).toBe(false);
		expect(sent.map((value) => JSON.parse(value))).toContainEqual({
			type: "announce",
			nodeId: "upgrade-replica-id",
			name: "upgrade-replica",
			version: APP_VERSION,
			adminUrl: "https://upgrade-replica.test",
			epoch: 0,
		});
	});
});

describe("HA mesh service: replica heartbeat watchdog", () => {
	const originalRole = config.ha.role;

	afterEach(() => {
		mesh.state = "unknown";
		mesh.replicaSocket = null;
		mesh.lastVerifiedSyncAt = 0;
		mesh.disconnectedSince = Date.now();
		mesh.stopped = false;
		config.ha.role = originalRole;
	});

	test("does nothing while heartbeats are still within the liveness timeout", () => {
		const closes: unknown[] = [];
		mesh.state = "connected";
		mesh.lastVerifiedSyncAt = Date.now() - (HA_REPLICA_LIVENESS_TIMEOUT_MS - 1000);
		mesh.replicaSocket = fakeSocket();
		(mesh.replicaSocket as { close: unknown }).close = (...args: unknown[]) => closes.push(args);
		const generationBefore = mesh.connectionGeneration;

		mesh.checkHeartbeatWatchdog();

		expect(closes).toEqual([]);
		expect(mesh.connectionGeneration).toBe(generationBefore);
	});

	test("does nothing while not in the connected state (an ordinary disconnect already covers itself)", () => {
		const closes: unknown[] = [];
		mesh.state = "disconnected";
		mesh.lastVerifiedSyncAt = Date.now() - (HA_REPLICA_LIVENESS_TIMEOUT_MS + 1000);
		mesh.replicaSocket = { readyState: WebSocket.OPEN, send: () => {}, close: (...args: unknown[]) => closes.push(args) };

		mesh.checkHeartbeatWatchdog();

		expect(closes).toEqual([]);
	});

	test("actively closes a half-open connection once heartbeats stop for longer than the liveness timeout", () => {
		const closes: unknown[] = [];
		mesh.state = "connected";
		mesh.lastVerifiedSyncAt = Date.now() - (HA_REPLICA_LIVENESS_TIMEOUT_MS + 1000);
		mesh.replicaSocket = { readyState: WebSocket.OPEN, send: () => {}, close: (...args: unknown[]) => closes.push(args) };
		const generationBefore = mesh.connectionGeneration;

		mesh.checkHeartbeatWatchdog();

		expect(closes).toEqual([[4000, "no heartbeat received from the primary within the liveness timeout"]]);

		expect(mesh.connectionGeneration).toBe(generationBefore + 1);
	});

	test("transitions to disconnected synchronously, letting disconnectedDurationMs start counting immediately - not just after close() and its own async event", () => {
		mesh.state = "connected";
		config.ha.role = "replica";
		mesh.lastVerifiedSyncAt = Date.now() - (HA_REPLICA_LIVENESS_TIMEOUT_MS + 1000);
		mesh.replicaSocket = { readyState: WebSocket.OPEN, send: () => {}, close: () => {} };
		expect(haMeshService.disconnectedDurationMs()).toBeNull();
		mesh.stopped = true;

		mesh.checkHeartbeatWatchdog();

		expect(mesh.state).toBe("disconnected");
		expect(haMeshService.disconnectedDurationMs()).not.toBeNull();
	});

	test("a real close event firing afterward is a harmless no-op, not a double transition", () => {
		mesh.state = "connected";
		config.ha.role = "replica";
		mesh.lastVerifiedSyncAt = Date.now() - (HA_REPLICA_LIVENESS_TIMEOUT_MS + 1000);
		mesh.replicaSocket = { readyState: WebSocket.OPEN, send: () => {}, close: () => {} };
		mesh.stopped = true;

		mesh.checkHeartbeatWatchdog();
		const disconnectedSinceAfterWatchdog = mesh.disconnectedSince;

		mesh.handleReplicaClose({ code: 4000, reason: "no heartbeat received from the primary within the liveness timeout" });

		expect(mesh.state).toBe("disconnected");
		expect(mesh.disconnectedSince).toBe(disconnectedSinceAfterWatchdog);
	});
});

describe("HA mesh service: per-node credential revocation", () => {
	afterEach(() => {
		mesh.nodes.clear();
	});

	test("forgetting one node revokes only that node's credential, leaving a still-active node's own credential working", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		const now = Date.now();
		const credentialA = "credential-belonging-to-node-a";
		const credentialB = "credential-belonging-to-node-b";
		await repository.upsertHaClusterMember({
			node_id: "revocation-node-a",
			name: "node-a",
			version: APP_VERSION,
			admin_url: "https://node-a.test",
			first_seen_at: now,
			last_seen_at: now,
			credential_hash: await sha256Hex(credentialA),
			activated_at: now,
		});
		await repository.upsertHaClusterMember({
			node_id: "revocation-node-b",
			name: "node-b",
			version: APP_VERSION,
			admin_url: "https://node-b.test",
			first_seen_at: now,
			last_seen_at: now,
			credential_hash: await sha256Hex(credentialB),
			activated_at: now,
		});
		await mesh.loadRegisteredMembers();

		const requestWith = (token: string) => new Request("https://primary.test/_ha/changelog", { headers: { authorization: `Bearer ${token}` } });
		expect(await isAuthorized(requestWith(credentialA))).toBe(true);
		expect(await isAuthorized(requestWith(credentialB))).toBe(true);

		markLongOffline("revocation-node-a");
		await mesh.forgetNode("revocation-node-a");

		expect(await isAuthorized(requestWith(credentialA))).toBe(false);
		expect(await isAuthorized(requestWith(credentialB))).toBe(true);
	});

	test("enrollment mints a distinct credential per node, not this primary's own shared token", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		config.ha.sharedToken = "primary-own-shared-token";

		const codeA = "enroll-code-node-a";
		const codeB = "enroll-code-node-b";
		await repository.createHaEnrollmentCode(await sha256Hex(codeA), Date.now() + 60_000);
		await repository.createHaEnrollmentCode(await sha256Hex(codeB), Date.now() + 60_000);

		const enrollBody = (nodeId: string) => JSON.stringify({ nodeId, name: nodeId, version: APP_VERSION, adminUrl: `https://${nodeId}.test` });
		const responseA = await mesh.handleEnrollRequest(
			new Request("https://primary.test/_ha/enroll", {
				method: "POST",
				headers: { authorization: `Bearer ${codeA}`, "content-type": "application/json" },
				body: enrollBody("enroll-node-a"),
			}),
		);
		const responseB = await mesh.handleEnrollRequest(
			new Request("https://primary.test/_ha/enroll", {
				method: "POST",
				headers: { authorization: `Bearer ${codeB}`, "content-type": "application/json" },
				body: enrollBody("enroll-node-b"),
			}),
		);
		const { sharedToken: credentialA } = (await responseA.json()) as { sharedToken: string };
		const { sharedToken: credentialB } = (await responseB.json()) as { sharedToken: string };

		expect(credentialA).not.toBe(credentialB);
		expect(credentialA).not.toBe(config.ha.sharedToken);
		expect(credentialB).not.toBe(config.ha.sharedToken);

		const requestWith = (token: string) => new Request("https://primary.test/_ha/changelog", { headers: { authorization: `Bearer ${token}` } });
		expect(await authenticateHaRequest(requestWith(credentialA), true)).not.toBeNull();
		expect(await authenticateHaRequest(requestWith(credentialB), true)).not.toBeNull();

		markLongOffline("enroll-node-a");
		await mesh.forgetNode("enroll-node-a");

		expect(await authenticateHaRequest(requestWith(credentialA), true)).toBeNull();
		expect(await authenticateHaRequest(requestWith(credentialB), true)).not.toBeNull();
	});

	test("an announce cannot claim a different node's identity than the one that authenticated the connection", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		const now = Date.now();
		await repository.upsertHaClusterMember({
			node_id: "spoof-victim",
			name: "victim",
			version: APP_VERSION,
			admin_url: "https://victim.test",
			first_seen_at: now,
			last_seen_at: now,
			credential_hash: await sha256Hex("victim-credential"),
			activated_at: now,
		});
		await mesh.loadRegisteredMembers();

		const closes: unknown[] = [];

		const attackerWs = {
			send: () => {},
			close: (...args: unknown[]) => closes.push(args),
			data: { authenticatedNodeId: "spoof-attacker", authenticatedActive: true },
		};
		await mesh.handlePrimaryMessage(
			attackerWs,
			JSON.stringify({ type: "announce", nodeId: "spoof-victim", name: "hijacked", version: APP_VERSION, adminUrl: "https://attacker.test" }),
		);
		expect(closes).toHaveLength(1);
		expect(mesh.nodes.has(attackerWs)).toBe(false);
		const victim = (await repository.haClusterMembers()).find((member) => member.node_id === "spoof-victim");
		expect(victim?.name).toBe("victim");
	});

	test("a minority primary cannot forget members and shrink its local quorum universe during the pre-fence window", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		config.ha.quorumFenced = false;
		const selfNodeId = await repository.haNodeId();
		const now = Date.now();
		for (const nodeId of [selfNodeId, "partition-peer-1", "partition-peer-2", "partition-peer-3", "partition-peer-4"]) {
			await repository.upsertHaClusterMember({
				node_id: nodeId,
				name: nodeId,
				version: APP_VERSION,
				admin_url: `https://${nodeId}.test`,
				first_seen_at: now,
				last_seen_at: now,
				credential_hash: await sha256Hex(`${nodeId}-credential`),
				activated_at: now,
			});
		}
		await mesh.loadRegisteredMembers();

		mesh.nodes.set(
			{ close: () => {} },
			{
				nodeId: "partition-peer-1",
				name: "partition-peer-1",
				version: APP_VERSION,
				connectedAt: now,
				connected: true,
				lastSeenAt: now,
				adminUrl: "https://partition-peer-1.test",
				lastAckedSeq: 0,
			},
		);

		markLongOffline("partition-peer-2");
		await expect(mesh.forgetNode("partition-peer-2")).rejects.toThrow(/without current majority connectivity/);
		expect((await repository.haClusterMembers()).some((member) => member.node_id === "partition-peer-2")).toBe(true);
	});

	describe("forgetNode's conservative offline-duration guard", () => {
		const originalReconnectMaxDelayMs = config.ha.reconnectMaxDelayMs;

		afterEach(() => {
			config.ha.reconnectMaxDelayMs = originalReconnectMaxDelayMs;
		});

		async function seedMember(nodeId: string): Promise<void> {
			const now = Date.now();
			await repository.upsertHaClusterMember({
				node_id: nodeId,
				name: nodeId,
				version: APP_VERSION,
				admin_url: `https://${nodeId}.test`,
				first_seen_at: now,
				last_seen_at: now,
				credential_hash: await sha256Hex(`${nodeId}-credential`),
				activated_at: now,
			});
			await mesh.loadRegisteredMembers();
		}

		test("refuses to forget a node that was only just seen disconnecting", async () => {
			config.ha.enabled = true;
			config.ha.role = "primary";
			await seedMember("blip-node");
			mesh.offlineSince.set("blip-node", Date.now() - 1_000);

			await expect(mesh.forgetNode("blip-node")).rejects.toThrow(/only recently seen disconnecting/);
			expect((await repository.haClusterMembers()).some((member) => member.node_id === "blip-node")).toBe(true);
		});

		test("a node this process has never seen connect/disconnect (e.g. right after a primary restart) is treated as freshly offline, not indefinitely forgettable", async () => {
			config.ha.enabled = true;
			config.ha.role = "primary";
			await seedMember("never-observed-node");

			await expect(mesh.forgetNode("never-observed-node")).rejects.toThrow(/only recently seen disconnecting/);
		});

		test("allows forgetting once the node has been offline past the conservative threshold", async () => {
			config.ha.enabled = true;
			config.ha.role = "primary";
			await seedMember("long-gone-node");
			markLongOffline("long-gone-node");

			await expect(mesh.forgetNode("long-gone-node")).resolves.toBeUndefined();
			expect((await repository.haClusterMembers()).some((member) => member.node_id === "long-gone-node")).toBe(false);
		});

		test("the threshold scales with this cluster's own configured reconnect ceiling, not just the fixed floor", async () => {
			config.ha.enabled = true;
			config.ha.role = "primary";
			config.ha.reconnectMaxDelayMs = 200_000;
			await seedMember("slow-reconnect-node");

			mesh.offlineSince.set("slow-reconnect-node", Date.now() - (HA_FORGET_MIN_OFFLINE_FLOOR_MS + 5_000));
			expect(HA_FORGET_MIN_OFFLINE_FLOOR_MS + 5_000).toBeLessThan(config.ha.reconnectMaxDelayMs * HA_FORGET_MIN_OFFLINE_RECONNECT_MULTIPLIER);

			await expect(mesh.forgetNode("slow-reconnect-node")).rejects.toThrow(/only recently seen disconnecting/);
		});

		test("handlePrimaryClose records the disconnect and a fresh announce clears it again, without any test poking offlineSince directly", async () => {
			config.ha.enabled = true;
			config.ha.role = "primary";
			await seedMember("real-lifecycle-node");
			const ws = { close: () => {} };
			mesh.nodes.set(ws, {
				nodeId: "real-lifecycle-node",
				name: "real-lifecycle-node",
				version: APP_VERSION,
				connectedAt: Date.now(),
				connected: true,
				lastSeenAt: Date.now(),
				adminUrl: "https://real-lifecycle-node.test",
				lastAckedSeq: 0,
			});

			mesh.handlePrimaryClose(ws);
			expect(mesh.offlineSince.has("real-lifecycle-node")).toBe(true);
			await expect(mesh.forgetNode("real-lifecycle-node")).rejects.toThrow(/only recently seen disconnecting/);

			await mesh.handlePrimaryMessage(
				{ send: () => {}, close: () => {}, data: { authenticatedNodeId: "real-lifecycle-node", authenticatedActive: true } },
				JSON.stringify({
					type: "announce",
					nodeId: "real-lifecycle-node",
					name: "real-lifecycle-node",
					version: APP_VERSION,
					adminUrl: "https://real-lifecycle-node.test",
				}),
			);
			expect(mesh.offlineSince.has("real-lifecycle-node")).toBe(false);
		});
	});

	test("a pending member whose activation write fails is removed from live quorum state and forced to reconnect", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		const nodeId = "non-durable-pending-node";
		const now = Date.now();
		await db`INSERT INTO ha_cluster_members (node_id,name,version,admin_url,first_seen_at,last_seen_at,credential_hash,activated_at,revoked_at) VALUES (${nodeId},${nodeId},${APP_VERSION},${"https://pending.test"},${now},${now},${await sha256Hex("pending-credential")},NULL,NULL)`;
		await mesh.loadRegisteredMembers();
		expect(mesh.registeredMembers.has(nodeId)).toBe(false);

		const originalUpsert = repository.upsertHaClusterMember;
		let activationStarted!: () => void;
		let rejectActivation!: () => void;
		const started = new Promise<void>((resolve) => {
			activationStarted = resolve;
		});
		const activationGate = new Promise<void>((_resolve, reject) => {
			rejectActivation = () => reject(new Error("simulated activation commit failure"));
		});
		repository.upsertHaClusterMember = async () => {
			activationStarted();
			await activationGate;
		};
		const closes: unknown[] = [];
		const ws = { send: () => {}, close: (...args: unknown[]) => closes.push(args), data: { authenticatedNodeId: nodeId, authenticatedActive: false } };
		try {
			const announce = mesh.handlePrimaryMessage(
				ws,
				JSON.stringify({ type: "announce", nodeId, name: nodeId, version: APP_VERSION, adminUrl: "https://pending.test" }),
			);
			await started;

			expect(mesh.registeredMembers.has(nodeId)).toBe(false);
			rejectActivation();
			await announce;
		} finally {
			repository.upsertHaClusterMember = originalUpsert;
		}

		expect(mesh.registeredMembers.has(nodeId)).toBe(false);
		expect(mesh.nodes.has(ws)).toBe(false);
		expect(closes).toHaveLength(1);
		const persisted = (await db`SELECT activated_at FROM ha_cluster_members WHERE node_id=${nodeId}`) as Array<{ activated_at: number | null }>;
		expect(persisted[0]?.activated_at).toBeNull();
	});
});

describe("HA mesh service: waitForMajorityDurability", () => {
	const originalRole = config.ha.role;
	const originalEnabled = config.ha.enabled;

	afterEach(async () => {
		config.ha.role = originalRole;
		config.ha.enabled = originalEnabled;
		mesh.nodes.clear();
		await db`DELETE FROM ha_cluster_members`;
	});

	async function seedThreeMembers(): Promise<string> {
		const selfNodeId = await repository.haNodeId();
		const now = Date.now();
		for (const nodeId of [selfNodeId, "durability-peer-1", "durability-peer-2"]) {
			await repository.upsertHaClusterMember({
				node_id: nodeId,
				name: nodeId,
				version: APP_VERSION,
				admin_url: `https://${nodeId}.test`,
				first_seen_at: now,
				last_seen_at: now,
				credential_hash: await sha256Hex(`${nodeId}-credential`),
				activated_at: now,
			});
		}
		await mesh.loadRegisteredMembers();
		return selfNodeId;
	}

	function setAcked(nodeId: string, acked: boolean): void {
		mesh.nodes.set(
			{ send: () => {}, close: () => {} },
			{
				nodeId,
				name: nodeId,
				version: APP_VERSION,
				connectedAt: Date.now(),
				connected: true,
				lastSeenAt: Date.now(),
				adminUrl: `https://${nodeId}.test`,

				lastAckedSeq: acked ? Number.MAX_SAFE_INTEGER : null,
			},
		);
	}

	test("confirms immediately once self plus a majority of acked replicas is reached, with no polling needed", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		await seedThreeMembers();
		setAcked("durability-peer-1", true);

		const result = await mesh.waitForMajorityDurability(50);

		expect(result.confirmed).toBe(true);
	});

	test("returns confirmed:false once the timeout elapses without reaching a majority", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		await seedThreeMembers();
		setAcked("durability-peer-1", false);
		setAcked("durability-peer-2", false);

		const result = await mesh.waitForMajorityDurability(75);

		expect(result.confirmed).toBe(false);
	});

	test("resolves confirmed:true once a lagging replica's ack catches up mid-wait", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		await seedThreeMembers();
		setAcked("durability-peer-1", false);
		setAcked("durability-peer-2", false);
		setTimeout(() => setAcked("durability-peer-1", true), 40);

		const result = await mesh.waitForMajorityDurability(1_000);

		expect(result.confirmed).toBe(true);
	});

	test("is a no-op (always confirmed) below the auto-failover member floor", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		const selfNodeId = await repository.haNodeId();
		const now = Date.now();
		await repository.upsertHaClusterMember({
			node_id: selfNodeId,
			name: "self",
			version: APP_VERSION,
			admin_url: "https://self.test",
			first_seen_at: now,
			last_seen_at: now,
			credential_hash: await sha256Hex("self-credential"),
			activated_at: now,
		});
		await mesh.loadRegisteredMembers();

		const result = await mesh.waitForMajorityDurability(50);

		expect(result.confirmed).toBe(true);
	});

	test("is a no-op when HA is disabled", async () => {
		config.ha.enabled = false;
		const result = await mesh.waitForMajorityDurability(50);
		expect(result.confirmed).toBe(true);
	});

	test("is a no-op on a replica - the covered write always executes on the primary", async () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		const result = await mesh.waitForMajorityDurability(50);
		expect(result.confirmed).toBe(true);
	});

	test("withDurability merges durabilityConfirmed into the caller's response body without altering existing fields", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		await seedThreeMembers();
		setAcked("durability-peer-1", true);

		const merged = await withDurability({ ok: true, id: "site-1" });

		expect(merged).toEqual({ ok: true, id: "site-1", durabilityConfirmed: true });
	});
});

describe("HA mesh service: rejects a duplicate node identity", () => {
	afterEach(() => {
		mesh.nodes.clear();
	});

	test("a cursor acknowledgement refreshes the primary's application-level liveness timestamp", async () => {
		const ws = { send: () => {}, close: () => {} };
		const previousSeenAt = Date.now() - 60_000;
		mesh.nodes.set(ws, {
			nodeId: "live-node",
			name: "live-node",
			version: APP_VERSION,
			connectedAt: previousSeenAt,
			connected: true,
			lastSeenAt: previousSeenAt,
			adminUrl: "https://live-node.test",
			lastAckedSeq: 3,
		});

		await mesh.handlePrimaryMessage(ws, JSON.stringify({ type: "cursor", seq: 4 }));

		expect(mesh.nodes.get(ws)?.lastAckedSeq).toBe(4);
		expect(mesh.nodes.get(ws)?.lastSeenAt).toBeGreaterThan(previousSeenAt);
	});

	test("a second connection announcing an already-connected nodeId is closed, the first is kept", async () => {
		const firstCloses: unknown[] = [];
		const secondCloses: unknown[] = [];
		const firstWs = {
			send: () => {},
			close: (...args: unknown[]) => firstCloses.push(args),
			data: { authenticatedNodeId: "cloned-node-uuid", authenticatedActive: true },
		};
		const secondWs = {
			send: () => {},
			close: (...args: unknown[]) => secondCloses.push(args),
			data: { authenticatedNodeId: "cloned-node-uuid", authenticatedActive: true },
		};
		const announce = JSON.stringify({ type: "announce", nodeId: "cloned-node-uuid", name: "node-a", version: APP_VERSION, adminUrl: "https://node-a.test" });

		await mesh.handlePrimaryMessage(firstWs, announce);
		expect(firstCloses).toHaveLength(0);
		expect(mesh.nodes.size).toBe(1);

		await mesh.handlePrimaryMessage(secondWs, announce.replace("node-a", "node-b"));
		expect(secondCloses).toHaveLength(1);
		expect(mesh.nodes.size).toBe(1);
		expect([...mesh.nodes.values()][0]!.name).toBe("node-a");
	});

	test("the same socket re-announcing the same nodeId (a reconnect) is not treated as a duplicate", async () => {
		const ws = { send: () => {}, close: () => {}, data: { authenticatedNodeId: "stable-node-uuid", authenticatedActive: true } };
		const announce = JSON.stringify({ type: "announce", nodeId: "stable-node-uuid", name: "node-a", version: APP_VERSION, adminUrl: "https://node-a.test" });
		await mesh.handlePrimaryMessage(ws, announce);
		await mesh.handlePrimaryMessage(ws, announce);
		expect(mesh.nodes.size).toBe(1);
	});

	test("a valid adminUrl is captured into the node's live registry entry", async () => {
		const ws = { send: () => {}, close: () => {}, data: { authenticatedNodeId: "addr-node-uuid", authenticatedActive: true } };
		await mesh.handlePrimaryMessage(
			ws,
			JSON.stringify({ type: "announce", nodeId: "addr-node-uuid", name: "node-addr", version: APP_VERSION, adminUrl: "https://node-addr.test" }),
		);
		expect([...mesh.nodes.values()][0]?.adminUrl).toBe("https://node-addr.test");
	});

	test("an announce with a non-string adminUrl is rejected, same as any other malformed field", async () => {
		const closes: unknown[] = [];
		const ws = { send: () => {}, close: (...args: unknown[]) => closes.push(args), data: { authenticatedNodeId: "bad-addr-node", authenticatedActive: true } };
		await mesh.handlePrimaryMessage(ws, JSON.stringify({ type: "announce", nodeId: "bad-addr-node", name: "n", version: APP_VERSION, adminUrl: 12345 }));
		expect(closes).toHaveLength(1);
		expect(mesh.nodes.size).toBe(0);
	});

	test("an announce cannot register a plaintext or credential-bearing admin URL", async () => {
		for (const adminUrl of ["http://node.test", "https://user:secret@node.test"]) {
			const closes: unknown[] = [];
			const ws = {
				send: () => {},
				close: (...args: unknown[]) => closes.push(args),
				data: { authenticatedNodeId: `insecure-${closes.length}-${adminUrl.length}`, authenticatedActive: true },
			};
			await mesh.handlePrimaryMessage(
				ws,
				JSON.stringify({ type: "announce", nodeId: `insecure-${closes.length}-${adminUrl.length}`, name: "n", version: APP_VERSION, adminUrl }),
			);
			expect(closes).toHaveLength(1);
			expect(mesh.nodes.has(ws)).toBe(false);
		}
	});

	test("an announce with an empty adminUrl is still accepted (older/misconfigured node, just not promotable)", async () => {
		const ws = { send: () => {}, close: () => {}, data: { authenticatedNodeId: "empty-addr-node", authenticatedActive: true } };
		await mesh.handlePrimaryMessage(ws, JSON.stringify({ type: "announce", nodeId: "empty-addr-node", name: "n", version: APP_VERSION, adminUrl: "" }));
		expect([...mesh.nodes.values()][0]?.adminUrl).toBe("");
	});
});

describe("HA mesh service: durable cluster version fence", () => {
	test("a mismatched announcement is persisted and fences writes until the same node reports the primary version", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		const now = Date.now();

		await repository.upsertHaClusterMember({
			node_id: "upgrade-node",
			name: "upgrade-node",
			version: "0.0.0",
			admin_url: null,
			first_seen_at: now,
			last_seen_at: now,
			credential_hash: await sha256Hex("upgrade-node-credential"),
		});
		const ws = { send: () => {}, close: () => {}, data: { authenticatedNodeId: "upgrade-node", authenticatedActive: true } };
		await mesh.handlePrimaryMessage(
			ws,
			JSON.stringify({ type: "announce", nodeId: "upgrade-node", name: "upgrade-node", version: "0.0.1", adminUrl: "https://upgrade.test" }),
		);
		expect(mesh.versionMismatches()).toEqual([{ nodeId: "upgrade-node", name: "upgrade-node", version: "0.0.1" }]);
		expect((await repository.haClusterMembers()).find((member) => member.node_id === "upgrade-node")?.version).toBe("0.0.1");

		await mesh.handlePrimaryMessage(
			ws,
			JSON.stringify({ type: "announce", nodeId: "upgrade-node", name: "upgrade-node", version: APP_VERSION, adminUrl: "https://upgrade.test" }),
		);
		expect(mesh.versionMismatches()).toEqual([]);
	});

	test("an offline mismatch is restored from durable membership and can be explicitly forgotten", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		const now = Date.now();
		await repository.upsertHaClusterMember({
			node_id: "offline-old-node",
			name: "offline-old-node",
			version: "0.0.1",
			admin_url: "https://offline-old.test",
			first_seen_at: now,
			last_seen_at: now,
			credential_hash: await sha256Hex("offline-old-node-credential"),
		});
		await mesh.loadRegisteredMembers();
		expect(mesh.versionMismatches()).toHaveLength(1);

		markLongOffline("offline-old-node");
		await mesh.forgetNode("offline-old-node");
		expect(mesh.versionMismatches()).toEqual([]);
		expect((await repository.haClusterMembers()).some((member) => member.node_id === "offline-old-node")).toBe(false);
	});

	test("a forgotten node cannot silently register with its old shared token, but fresh one-time enrollment re-authorizes that identity", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		config.ha.sharedToken = "revocation-test-cluster-token";
		const nodeId = "durably-revoked-node";
		const now = Date.now();
		await repository.upsertHaClusterMember({
			node_id: nodeId,
			name: "retired replica",
			version: APP_VERSION,
			admin_url: "https://retired.test",
			first_seen_at: now,
			last_seen_at: now,
			credential_hash: await sha256Hex("durably-revoked-node-original-credential"),
		});
		await mesh.loadRegisteredMembers();
		markLongOffline(nodeId);
		await mesh.forgetNode(nodeId);
		expect(await repository.haRevokedClusterNodeIds()).toContain(nodeId);
		const snapshotMember = (await repository.fullSnapshot()).rows.find((row) => row.entity_type === "ha_cluster_member" && row.entity_id === nodeId);
		expect((JSON.parse(snapshotMember!.payload_json) as { revoked_at: number | null }).revoked_at).toEqual(expect.any(Number));

		mesh.registeredMembers.clear();
		mesh.revokedNodeIds.clear();
		await mesh.loadRegisteredMembers();

		const rejectedCloses: unknown[] = [];
		const rejectedSocket = {
			send: () => {},
			close: (...args: unknown[]) => rejectedCloses.push(args),
			data: { authenticatedNodeId: nodeId, authenticatedActive: true },
		};
		await mesh.handlePrimaryMessage(
			rejectedSocket,
			JSON.stringify({ type: "announce", nodeId, name: "retired replica", version: APP_VERSION, adminUrl: "https://retired.test" }),
		);
		expect(rejectedCloses).toHaveLength(1);
		expect(mesh.nodes.has(rejectedSocket)).toBe(false);

		const enrollmentCode = "fresh-re-enrollment-code";
		await repository.createHaEnrollmentCode(await sha256Hex(enrollmentCode), Date.now() + 60_000);
		const enrolled = await mesh.handleEnrollRequest(
			new Request("https://primary.test/_ha/enroll", {
				method: "POST",
				headers: { authorization: `Bearer ${enrollmentCode}`, "content-type": "application/json" },
				body: JSON.stringify({ nodeId, name: "returning replica", version: APP_VERSION, adminUrl: "https://returned.test" }),
			}),
		);
		expect(enrolled.status).toBe(200);
		expect(await repository.haRevokedClusterNodeIds()).not.toContain(nodeId);

		const acceptedCloses: unknown[] = [];
		const acceptedSocket = {
			send: () => {},
			close: (...args: unknown[]) => acceptedCloses.push(args),
			data: { authenticatedNodeId: nodeId, authenticatedActive: true },
		};
		await mesh.handlePrimaryMessage(
			acceptedSocket,
			JSON.stringify({ type: "announce", nodeId, name: "returned replica", version: APP_VERSION, adminUrl: "https://returned.test" }),
		);
		expect(acceptedCloses).toHaveLength(0);
		expect(mesh.nodes.get(acceptedSocket)?.name).toBe("returned replica");
	});
});

describe("HA mesh service: dead-letters a relay the primary cannot apply", () => {
	afterEach(() => {
		mesh.nodes.clear();
	});

	test("a relay apply failure sends a relay_reject, records a dead letter, and never acks", async () => {
		const originalApply = repository.applyReplicatedSessionRelay;
		const originalDeadLetter = repository.deadLetterRelay;
		repository.applyReplicatedSessionRelay = async () => {
			throw new Error("simulated permanent conflict");
		};
		let deadLetterReason = "not yet called";
		repository.deadLetterRelay = async (nodeId, relayId, entityType, entityId, op, payload, reason) => {
			deadLetterReason = reason;
		};
		const sent: string[] = [];
		const ws = { send: (data: string) => sent.push(data), close: () => {}, data: { authenticatedNodeId: "dead-letter-node", authenticatedActive: true } };
		try {
			await mesh.handlePrimaryMessage(
				ws,
				JSON.stringify({ type: "announce", nodeId: "dead-letter-node", name: "n", version: APP_VERSION, adminUrl: "https://n.test" }),
			);
			await mesh.handlePrimaryMessage(
				ws,
				JSON.stringify({ type: "relay", relayId: 1, entityType: "admin_session", entityId: "sess_1", op: "insert", payloadJson: null }),
			);
			expect(sent).toHaveLength(1);
			const message = JSON.parse(sent[0]!) as { type: string; relayId: number; reason: string };
			expect(message.type).toBe("relay_reject");
			expect(message.relayId).toBe(1);
			expect(deadLetterReason).toContain("simulated permanent conflict");
		} finally {
			repository.applyReplicatedSessionRelay = originalApply;
			repository.deadLetterRelay = originalDeadLetter;
		}
	});

	test("a transient database error is neither acked nor dead-lettered, leaving it for the replica's own retry", async () => {
		const originalApply = repository.applyReplicatedSessionRelay;
		const originalDeadLetter = repository.deadLetterRelay;
		repository.applyReplicatedSessionRelay = async () => {
			throw new Bun.SQL.SQLiteError("database is locked", { code: "SQLITE_BUSY", errno: 5 });
		};
		let deadLetterCalled = false;
		repository.deadLetterRelay = async () => {
			deadLetterCalled = true;
		};
		const sent: string[] = [];
		const ws = { send: (data: string) => sent.push(data), close: () => {}, data: { authenticatedNodeId: "transient-error-node", authenticatedActive: true } };
		try {
			await mesh.handlePrimaryMessage(
				ws,
				JSON.stringify({ type: "announce", nodeId: "transient-error-node", name: "n", version: APP_VERSION, adminUrl: "https://n.test" }),
			);
			await mesh.handlePrimaryMessage(
				ws,
				JSON.stringify({ type: "relay", relayId: 1, entityType: "admin_session", entityId: "sess_1", op: "insert", payloadJson: null }),
			);
			expect(sent).toHaveLength(0);
			expect(deadLetterCalled).toBe(false);
		} finally {
			repository.applyReplicatedSessionRelay = originalApply;
			repository.deadLetterRelay = originalDeadLetter;
		}
	});

	test("a relay arriving during promotion is neither rejected nor dead-lettered and remains retryable", async () => {
		const originalApply = repository.applyReplicatedSessionRelay;
		const originalDeadLetter = repository.deadLetterRelay;
		repository.applyReplicatedSessionRelay = async () => {
			throw new HaPromotionWriteFenceError();
		};
		let deadLetterCalled = false;
		repository.deadLetterRelay = async () => {
			deadLetterCalled = true;
		};
		const sent: string[] = [];
		const ws = { send: (data: string) => sent.push(data), close: () => {}, data: { authenticatedNodeId: "promotion-fence-node", authenticatedActive: true } };
		try {
			await mesh.handlePrimaryMessage(
				ws,
				JSON.stringify({ type: "announce", nodeId: "promotion-fence-node", name: "n", version: APP_VERSION, adminUrl: "https://n.test" }),
			);
			await mesh.handlePrimaryMessage(
				ws,
				JSON.stringify({ type: "relay", relayId: 1, entityType: "admin_session", entityId: "sess_1", op: "insert", payloadJson: null }),
			);
			expect(sent).toHaveLength(0);
			expect(deadLetterCalled).toBe(false);
		} finally {
			repository.applyReplicatedSessionRelay = originalApply;
			repository.deadLetterRelay = originalDeadLetter;
		}
	});

	test("a relay arriving while the primary is quorum-fenced is neither rejected nor dead-lettered and remains retryable", async () => {
		const originalApply = repository.applyReplicatedSessionRelay;
		const originalDeadLetter = repository.deadLetterRelay;
		repository.applyReplicatedSessionRelay = async () => {
			throw new HaQuorumLossFenceError();
		};
		let deadLetterCalled = false;
		repository.deadLetterRelay = async () => {
			deadLetterCalled = true;
		};
		const sent: string[] = [];
		const ws = { send: (data: string) => sent.push(data), close: () => {}, data: { authenticatedNodeId: "quorum-fence-node", authenticatedActive: true } };
		try {
			await mesh.handlePrimaryMessage(
				ws,
				JSON.stringify({ type: "announce", nodeId: "quorum-fence-node", name: "n", version: APP_VERSION, adminUrl: "https://n.test" }),
			);
			await mesh.handlePrimaryMessage(
				ws,
				JSON.stringify({ type: "relay", relayId: 1, entityType: "admin_session", entityId: "sess_1", op: "insert", payloadJson: null }),
			);
			expect(sent).toHaveLength(0);
			expect(deadLetterCalled).toBe(false);
		} finally {
			repository.applyReplicatedSessionRelay = originalApply;
			repository.deadLetterRelay = originalDeadLetter;
		}
	});
});

describe("HA mesh service: accepts RBAC permission relays", () => {
	afterEach(() => {
		mesh.nodes.clear();
	});

	test("a relay for admin_site_permission is applied and acked, not silently dropped", async () => {
		const originalApply = repository.applyReplicatedSessionRelay;
		let applied = { entityType: "not-yet-called", entityId: "not-yet-called" };
		repository.applyReplicatedSessionRelay = async (nodeId, relayId, entityType, entityId) => {
			applied = { entityType, entityId };
		};
		const sent: string[] = [];
		const ws = { send: (data: string) => sent.push(data), close: () => {}, data: { authenticatedNodeId: "rbac-relay-node", authenticatedActive: true } };
		try {
			await mesh.handlePrimaryMessage(
				ws,
				JSON.stringify({ type: "announce", nodeId: "rbac-relay-node", name: "n", version: APP_VERSION, adminUrl: "https://n.test" }),
			);
			await mesh.handlePrimaryMessage(
				ws,
				JSON.stringify({ type: "relay", relayId: 1, entityType: "admin_site_permission", entityId: "user_1:site_1", op: "insert", payloadJson: "{}" }),
			);
			expect(applied).toEqual({ entityType: "admin_site_permission", entityId: "user_1:site_1" });
			expect(sent).toHaveLength(1);
			expect((JSON.parse(sent[0]!) as { type: string }).type).toBe("relay_ack");
		} finally {
			repository.applyReplicatedSessionRelay = originalApply;
		}
	});

	test("a relay for admin_stream_permission is applied and acked, not silently dropped", async () => {
		const originalApply = repository.applyReplicatedSessionRelay;
		let applied = { entityType: "not-yet-called", entityId: "not-yet-called" };
		repository.applyReplicatedSessionRelay = async (nodeId, relayId, entityType, entityId) => {
			applied = { entityType, entityId };
		};
		const sent: string[] = [];
		const ws = { send: (data: string) => sent.push(data), close: () => {}, data: { authenticatedNodeId: "rbac-relay-node-2", authenticatedActive: true } };
		try {
			await mesh.handlePrimaryMessage(
				ws,
				JSON.stringify({ type: "announce", nodeId: "rbac-relay-node-2", name: "n", version: APP_VERSION, adminUrl: "https://n.test" }),
			);
			await mesh.handlePrimaryMessage(
				ws,
				JSON.stringify({ type: "relay", relayId: 1, entityType: "admin_stream_permission", entityId: "user_1:stream_1", op: "insert", payloadJson: "{}" }),
			);
			expect(applied).toEqual({ entityType: "admin_stream_permission", entityId: "user_1:stream_1" });
			expect(sent).toHaveLength(1);
			expect((JSON.parse(sent[0]!) as { type: string }).type).toBe("relay_ack");
		} finally {
			repository.applyReplicatedSessionRelay = originalApply;
		}
	});
});

describe("HA mesh service: replica reconciles from a rejected relay instead of leaving diverged state serving", () => {
	afterEach(() => {
		mesh.relayInFlightId = null;
		mesh.relayInFlightSentAt = 0;
		mesh.hasBootstrapped = false;
		mesh.replicaSocket = null;
	});

	test("a relay_reject deletes the outbox row and clears the in-flight slot", async () => {
		const originalDelete = repository.deleteSessionRelayRows;
		let deletedIds: number[] = [];
		repository.deleteSessionRelayRows = async (ids: number[]) => {
			deletedIds = ids;
		};
		mesh.relayInFlightId = 42;
		mesh.relayInFlightSentAt = Date.now();
		try {
			mesh.handleIncomingMessage({ data: JSON.stringify({ type: "relay_reject", relayId: 42, reason: "simulated" }) } as MessageEvent);
			await mesh.messageQueue;
			expect(deletedIds).toEqual([42]);
			expect(mesh.relayInFlightId).toBeNull();
		} finally {
			repository.deleteSessionRelayRows = originalDelete;
		}
	});

	test("forces a fresh full snapshot and reconnects, instead of quietly moving on to the next relay", async () => {
		const originalDelete = repository.deleteSessionRelayRows;
		const originalForceRebootstrap = repository.forceRebootstrap;
		repository.deleteSessionRelayRows = async () => {};
		let forceRebootstrapCalled = false;
		repository.forceRebootstrap = async () => {
			forceRebootstrapCalled = true;
		};
		const closes: unknown[] = [];
		mesh.replicaSocket = { readyState: WebSocket.OPEN, send: () => {}, close: (...args: unknown[]) => closes.push(args) };
		mesh.hasBootstrapped = true;
		const generationBefore = mesh.connectionGeneration;
		try {
			mesh.handleIncomingMessage({ data: JSON.stringify({ type: "relay_reject", relayId: 7, reason: "simulated permanent conflict" }) } as MessageEvent);
			await mesh.messageQueue;

			expect(forceRebootstrapCalled).toBe(true);
			expect(mesh.hasBootstrapped).toBe(false);
			expect(mesh.connectionGeneration).toBe(generationBefore + 1);
			expect(closes).toEqual([[4000, "local state diverged from a rejected relay - reconnecting for a fresh snapshot"]]);
		} finally {
			repository.deleteSessionRelayRows = originalDelete;
			repository.forceRebootstrap = originalForceRebootstrap;
		}
	});
});

describe("HA mesh service: early runtime preparation", () => {
	const originalEnabled = config.ha.enabled;
	const originalRole = config.ha.role;

	beforeEach(() => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		config.ha.fencedForPromotion = false;
		config.ha.authorityFence = null;
		mesh.runtimePrepared = false;
	});

	afterEach(async () => {
		await db`DELETE FROM ha_promotion_intent`;
		config.ha.enabled = originalEnabled;
		config.ha.role = originalRole;
		config.ha.fencedForPromotion = false;
		config.ha.authorityFence = null;
		mesh.runtimePrepared = false;
	});

	test("raises a promoted primary's changelog sequence before later runtime writes are possible", async () => {
		const cursorRows = (await db`SELECT last_applied_seq,bootstrapped FROM replication_cursor WHERE id=1`) as Array<{
			last_applied_seq: number;
			bootstrapped: number;
		}>;
		const originalCursor = Number(cursorRows[0]?.last_applied_seq ?? 0);
		const originalBootstrapped = Number(cursorRows[0]?.bootstrapped ?? 0);
		const promotionCursor = Math.max(originalCursor, await repository.latestChangelogSeq()) + 100;
		await repository.markBootstrapped(promotionCursor);

		try {
			await mesh.prepareForRuntimeAtBoot();
			const preparedThrough = mesh.lastBroadcastSeq;
			expect(preparedThrough).toBeGreaterThanOrEqual(promotionCursor);

			const now = Date.now();
			await repository.upsertHaClusterMember({
				node_id: "post-prepare-member",
				name: "post-prepare-member",
				version: APP_VERSION,
				admin_url: null,
				first_seen_at: now,
				last_seen_at: now,
				credential_hash: await sha256Hex("post-prepare-member-credential"),
			});
			expect(await repository.latestChangelogSeq()).toBeGreaterThan(preparedThrough);
		} finally {
			await db`UPDATE replication_cursor SET last_applied_seq=${originalCursor},bootstrapped=${originalBootstrapped} WHERE id=1`;
		}
	});

	test("restores an interrupted promotion fence before even a membership write can run", async () => {
		await repository.saveHaPromotionIntent({
			promotion_id: "early-fence-promotion",
			target_node_id: "early-fence-target",
			target_url: "https://early-fence-target.test:7443",
			target_admin_url: "https://early-fence-target.test",
			new_epoch: 1,
			created_at: Date.now(),
		});

		await mesh.prepareForRuntimeAtBoot();
		expect(config.ha.fencedForPromotion).toBe(true);
		await expect(
			repository.upsertHaClusterMember({
				node_id: "must-not-write",
				name: "must-not-write",
				version: APP_VERSION,
				admin_url: null,
				first_seen_at: Date.now(),
				last_seen_at: Date.now(),
			}),
		).rejects.toBeInstanceOf(HaPromotionWriteFenceError);
	});

	test("a restored authority fence skips promoted-primary write preparation and remains write-closed", async () => {
		config.ha.authorityFence = { observedEpoch: 6, sourceNodeId: "newer-authority", observedAt: Date.now() };
		await mesh.prepareForRuntimeAtBoot();
		expect(mesh.runtimePrepared).toBe(true);
		await expect(
			repository.upsertHaClusterMember({
				node_id: "must-not-write-under-authority-fence",
				name: "must-not-write-under-authority-fence",
				version: APP_VERSION,
				admin_url: null,
				first_seen_at: Date.now(),
				last_seen_at: Date.now(),
			}),
		).rejects.toBeInstanceOf(HaPrimaryAuthorityFenceError);
	});
});

describe("HA mesh service: manual promote", () => {
	const originalRole = config.ha.role;
	const originalPrimaryUrl = config.ha.primaryUrl;
	const originalPrimaryAdminUrl = config.ha.primaryAdminUrl;
	const originalEpoch = config.ha.epoch;

	beforeEach(async () => {
		restartCalls = [];
		mesh.nodes.clear();
		mesh.replicas.clear();
		mesh.registeredMembers.clear();
		await db`DELETE FROM ha_cluster_members`;

		config.ha.epoch = originalEpoch;
		const existing = await repository.haClusterConfigRow();
		if (existing) {
			await repository.updateHaClusterConfig({ enabled: true, role: config.ha.role, primaryUrl: null, primaryAdminUrl: null, clusterEpoch: originalEpoch });
		} else {
			await repository.insertHaClusterConfig({
				enabled: true,
				role: config.ha.role,
				nodeName: "promote-test-node",
				primaryUrl: null,
				primaryAdminUrl: null,
				sharedTokenEncrypted: null,
				selfAdminUrl: null,
				clusterEpoch: originalEpoch,
			});
		}
	});

	afterEach(async () => {
		config.ha.role = originalRole;
		config.ha.primaryUrl = originalPrimaryUrl;
		config.ha.primaryAdminUrl = originalPrimaryAdminUrl;
		config.ha.epoch = originalEpoch;
		mesh.nodes.clear();
		mesh.replicas.clear();
		mesh.nodeId = null;
		mesh.pendingPreparePromoteAck = null;
		mesh.pendingPromotionFenceAck = null;
		mesh.pendingPromoteAppliedAck = null;
		config.ha.fencedForPromotion = false;
		mesh.server = null;

		mesh.state = "unknown";

		await db`DELETE FROM ha_cluster_config`;
		await db`DELETE FROM ha_promotion_intent`;
		await db`DELETE FROM ha_cluster_members`;
	});

	test("promoteNode refuses on a node that is not the primary", async () => {
		config.ha.role = "replica";
		await expect(mesh.promoteNode("some-node")).rejects.toThrow(/Only the primary/);
	});

	test("a higher-epoch announcement durably fences a stale primary before it can accept more writes", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		config.ha.epoch = 3;
		config.ha.authorityFence = null;
		mesh.server = {};
		const sent: string[] = [];
		const ws = { send: (data: string) => sent.push(data), close: () => {}, data: { authenticatedNodeId: "newer-epoch-node", authenticatedActive: true } };
		mesh.replicas.add(ws);

		await mesh.handlePrimaryMessage(
			ws,
			JSON.stringify({
				type: "announce",
				nodeId: "newer-epoch-node",
				name: "new primary witness",
				version: APP_VERSION,
				adminUrl: "https://newer-epoch.test",
				epoch: 4,
			}),
		);

		expect(config.ha.authorityFence).toMatchObject({ observedEpoch: 4, sourceNodeId: "newer-epoch-node" });
		expect(mesh.ready()).toBe(false);
		const row = await repository.haClusterConfigRow();
		expect(row?.authority_fenced).toBe(1);
		expect(row?.authority_fence_epoch).toBe(4);
		expect(row?.authority_fence_node_id).toBe("newer-epoch-node");
		expect(sent.map((data) => JSON.parse(data) as { type: string; primaryFenced?: boolean })).toContainEqual(
			expect.objectContaining({ type: "heartbeat", primaryFenced: true }),
		);
		await expect(haPrimaryWriteBarrier.runPrimaryWrite(async () => "unsafe")).rejects.toBeInstanceOf(HaPrimaryAuthorityFenceError);
	});

	test("promotion completion cannot erase a concurrently-observed newer authority", async () => {
		config.ha.role = "primary";
		await repository.saveHaPromotionIntent({
			promotion_id: "authority-race-promotion",
			target_node_id: "promotion-target",
			target_url: "https://promotion-target.test:7443",
			target_admin_url: "https://promotion-target.test",
			new_epoch: 1,
			created_at: Date.now(),
		});
		await repository.fenceHaPrimaryAuthority(2, "already-newer-node", Date.now());

		expect(
			await repository.completeHaPromotionIntent("authority-race-promotion", {
				primaryUrl: "https://promotion-target.test:7443",
				primaryAdminUrl: "https://promotion-target.test",
				clusterEpoch: 1,
			}),
		).toBe(false);
		const row = await repository.haClusterConfigRow();
		expect(row?.role).toBe("primary");
		expect(row?.authority_fenced).toBe(1);
		expect(row?.cluster_epoch).toBe(2);
		expect(await repository.haPromotionIntent()).not.toBeNull();
	});

	test("promoteNode refuses a target that is not currently connected", async () => {
		config.ha.role = "primary";
		await expect(mesh.promoteNode("not-connected-node")).rejects.toThrow(/not currently connected/);
	});

	test("promoteNode expires and refuses a half-open target that stopped acknowledging heartbeats", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		mesh.nodeId = "promotion-primary";
		const closes: unknown[] = [];
		const targetWs = {
			send: () => 1,
			close: (...args: unknown[]) => closes.push(args),
			data: { authenticatedNodeId: "stalled-target", authenticatedActive: true },
		};
		await mesh.handlePrimaryMessage(
			targetWs,
			JSON.stringify({
				type: "announce",
				nodeId: "stalled-target",
				name: "stalled-target",
				version: APP_VERSION,
				adminUrl: "https://stalled-target.test",
				epoch: config.ha.epoch,
			}),
		);
		const target = mesh.nodes.get(targetWs)!;
		target.lastSeenAt = Date.now() - 60_000;

		await expect(mesh.promoteNode("stalled-target")).rejects.toThrow(/not currently connected/);

		expect(closes).toEqual([[4000, "replica heartbeat acknowledgement timeout"]]);
		expect(mesh.nodes.has(targetWs)).toBe(false);
		expect(config.ha.fencedForPromotion).toBe(false);
	});

	test("promoteNode refuses while another registered replica is offline", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		mesh.nodeId = "promotion-primary";
		const targetWs = { send: () => 1, close: () => {}, data: { authenticatedNodeId: "online-target", authenticatedActive: true } };
		await mesh.handlePrimaryMessage(
			targetWs,
			JSON.stringify({ type: "announce", nodeId: "online-target", name: "online-target", version: APP_VERSION, adminUrl: "https://online-target.test" }),
		);
		const now = Date.now();
		await repository.upsertHaClusterMember({
			node_id: "offline-bystander",
			name: "offline-bystander",
			version: APP_VERSION,
			admin_url: "https://offline-bystander.test",
			first_seen_at: now,
			last_seen_at: now,
			credential_hash: await sha256Hex("offline-bystander-credential"),
		});
		await mesh.loadRegisteredMembers();

		await expect(mesh.promoteNode("online-target")).rejects.toThrow(/registered replicas are offline/);
		expect(config.ha.fencedForPromotion).toBe(false);
	});

	test("a primary restart with an unfinished durable intent comes back write-fenced", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		await repository.saveHaPromotionIntent({
			promotion_id: "restart-recovery-promotion",
			target_node_id: "restart-recovery-target",
			target_url: "https://restart-recovery.test:7443",
			target_admin_url: "https://restart-recovery.test",
			new_epoch: 1,
			created_at: Date.now(),
		});
		const originalStartPrimary = mesh.startPrimary;
		mesh.startPrimary = async () => {};
		try {
			config.ha.fencedForPromotion = false;
			await mesh.start();
			expect(config.ha.fencedForPromotion).toBe(true);
			expect((await repository.haClusterConfigRow())?.role).toBe("primary");
		} finally {
			mesh.startPrimary = originalStartPrimary;
		}
	});

	test("promoteNode refuses a target with no announced admin URL", async () => {
		config.ha.role = "primary";
		const ws = { send: () => {}, close: () => {}, data: { authenticatedNodeId: "no-addr-target", authenticatedActive: true } };
		await mesh.handlePrimaryMessage(ws, JSON.stringify({ type: "announce", nodeId: "no-addr-target", name: "n", version: APP_VERSION, adminUrl: "" }));
		await expect(mesh.promoteNode("no-addr-target")).rejects.toThrow(/has not announced a reachable admin URL/);
	});

	test("promoteNode refuses a connected target running a different version", async () => {
		config.ha.role = "primary";
		const ws = { send: () => {}, close: () => {}, data: { authenticatedNodeId: "old-version-target", authenticatedActive: true } };
		await mesh.handlePrimaryMessage(
			ws,
			JSON.stringify({ type: "announce", nodeId: "old-version-target", name: "old target", version: "0.0.1", adminUrl: "https://old-target.test" }),
		);
		await expect(mesh.promoteNode("old-version-target")).rejects.toThrow(/runs BurrowGate 0\.0\.1/);
		expect((await repository.haClusterConfigRow())?.role).toBe("primary");
	});

	test("promoteNode broadcasts to every connected replica and demotes this node", async () => {
		config.ha.role = "primary";
		config.ha.port = 7443;

		const targetWs = {
			send: (data: string) => {
				const message = JSON.parse(data) as { type: string; promotionId?: string };
				if (message.type === "prepare_promote") {
					void mesh.handlePrimaryMessage(
						targetWs,
						JSON.stringify({ type: "prepare_promote_ack", cursor: Number.MAX_SAFE_INTEGER, promotionId: message.promotionId }),
					);
				} else if (message.type === "promote") {
					void mesh.handlePrimaryMessage(targetWs, JSON.stringify({ type: "promote_applied_ack", promotionId: message.promotionId, success: true }));
				}
			},
			close: () => {},
			data: { authenticatedNodeId: "promote-target", authenticatedActive: true },
		};
		await mesh.handlePrimaryMessage(
			targetWs,
			JSON.stringify({ type: "announce", nodeId: "promote-target", name: "target", version: APP_VERSION, adminUrl: "https://target.test:9000" }),
		);
		const sent: Array<{ ws: string; data: string }> = [];
		const bystanderWs = { send: (data: string) => sent.push({ ws: "bystander", data }) };
		mesh.replicas.add(bystanderWs);
		mesh.replicas.add({ send: (data: string) => sent.push({ ws: "target", data }) });

		mesh.lastBroadcastSeq = await repository.latestChangelogSeq();

		await mesh.promoteNode("promote-target");

		expect(sent).toHaveLength(4);
		const parsed = sent.map(({ ws, data }) => ({ ws, message: JSON.parse(data) as Record<string, unknown> }));
		const fenceHeartbeats = parsed.filter(({ message }) => message.type === "heartbeat");
		expect(fenceHeartbeats).toHaveLength(2);
		expect(fenceHeartbeats.every(({ message }) => message.primaryFenced === true && typeof message.promotionId === "string")).toBe(true);
		const promoteMessages = parsed.filter(({ message }) => message.type === "promote");
		expect(promoteMessages).toHaveLength(2);
		const message = promoteMessages[0]!.message as unknown as {
			type: string;
			newPrimaryNodeId: string;
			newPrimaryUrl: string;
			newPrimaryAdminUrl: string;
		};
		expect(message.type).toBe("promote");
		expect(message.newPrimaryNodeId).toBe("promote-target");

		expect(message.newPrimaryUrl).toBe("https://target.test:7443");
		expect(message.newPrimaryAdminUrl).toBe("https://target.test:9000");

		const row = await repository.haClusterConfigRow();
		expect(row?.role).toBe("replica");
		expect(row?.primary_url).toBe("https://target.test:7443");
		expect(await repository.haPromotionIntent()).toBeNull();

		await new Promise((resolve) => setTimeout(resolve, 350));
		expect(restartCalls).toContain("ha-promote");
	});

	test("promoteNode waits until every bystander has applied the readiness fence before preparing the target", async () => {
		config.ha.role = "primary";
		config.ha.port = 7443;
		let prepareMessages = 0;
		let fencePromotionId: string | undefined;
		const targetWs = {
			send: (data: string) => {
				const message = JSON.parse(data) as { type: string; promotionId?: string };
				if (message.type === "prepare_promote") {
					prepareMessages += 1;
					void mesh.handlePrimaryMessage(
						targetWs,
						JSON.stringify({ type: "prepare_promote_ack", cursor: Number.MAX_SAFE_INTEGER, promotionId: message.promotionId }),
					);
				} else if (message.type === "promote") {
					void mesh.handlePrimaryMessage(targetWs, JSON.stringify({ type: "promote_applied_ack", promotionId: message.promotionId, success: true }));
				}
				return 1;
			},
			close: () => {},
			data: { authenticatedNodeId: "fence-target", authenticatedActive: true },
		};
		const bystanderWs = {
			send: (data: string) => {
				const message = JSON.parse(data) as { type: string; promotionId?: string; primaryFenced?: boolean };
				if (message.type === "heartbeat" && message.primaryFenced === true) fencePromotionId = message.promotionId;
				return 1;
			},
			close: () => {},
			data: { authenticatedNodeId: "fence-bystander", authenticatedActive: true },
		};
		await mesh.handlePrimaryMessage(
			targetWs,
			JSON.stringify({ type: "announce", nodeId: "fence-target", name: "target", version: APP_VERSION, adminUrl: "https://fence-target.test" }),
		);
		await mesh.handlePrimaryMessage(
			bystanderWs,
			JSON.stringify({ type: "announce", nodeId: "fence-bystander", name: "bystander", version: APP_VERSION, adminUrl: "https://fence-bystander.test" }),
		);
		mesh.replicas.add(targetWs);
		mesh.replicas.add(bystanderWs);
		mesh.lastBroadcastSeq = await repository.latestChangelogSeq();

		const promotion = mesh.promoteNode("fence-target");
		await new Promise((resolve) => setTimeout(resolve, 10));
		expect(fencePromotionId).toBeDefined();
		expect(prepareMessages).toBe(0);
		expect(config.ha.fencedForPromotion).toBe(true);

		await mesh.handlePrimaryMessage(bystanderWs, JSON.stringify({ type: "promotion_fence_ack", promotionId: fencePromotionId }));
		await promotion;
		expect(prepareMessages).toBe(1);
		expect((await repository.haClusterConfigRow())?.role).toBe("replica");
	});

	test("promoteNode flushes unbroadcast changelog rows to every replica before the promote message, in order", async () => {
		config.ha.role = "primary";
		config.ha.port = 7443;

		config.ha.enabled = true;
		const targetWs = {
			send: (data: string) => {
				const message = JSON.parse(data) as { type: string; promotionId?: string };
				if (message.type === "prepare_promote") {
					void mesh.handlePrimaryMessage(
						targetWs,
						JSON.stringify({ type: "prepare_promote_ack", cursor: Number.MAX_SAFE_INTEGER, promotionId: message.promotionId }),
					);
				} else if (message.type === "promote") {
					void mesh.handlePrimaryMessage(targetWs, JSON.stringify({ type: "promote_applied_ack", promotionId: message.promotionId, success: true }));
				}
			},
			close: () => {},
			data: { authenticatedNodeId: "flush-target", authenticatedActive: true },
		};
		await mesh.handlePrimaryMessage(
			targetWs,
			JSON.stringify({ type: "announce", nodeId: "flush-target", name: "target", version: APP_VERSION, adminUrl: "https://flush-target.test:9000" }),
		);
		const sent: string[] = [];
		mesh.replicas.add({ send: (data: string) => sent.push(data) });
		mesh.lastBroadcastSeq = await repository.latestChangelogSeq();

		await repository.insertFirewallSyncWhitelistCidr({ id: "flush-test-cidr", network_cidr: "10.0.0.0/8", note: null, created_at: Date.now() });

		await mesh.promoteNode("flush-target");

		expect(sent.length).toBeGreaterThanOrEqual(2);
		const messages = sent.map((data) => JSON.parse(data) as { type: string; row?: { entity_type: string; entity_id: string } });
		const changeMessage = messages.find((message) => message.type === "change" && message.row?.entity_id === "flush-test-cidr");
		expect(changeMessage).toBeDefined();
		expect(changeMessage!.row!.entity_type).toBe("firewall_sync_whitelist_cidr");

		expect(messages.at(-1)!.type).toBe("promote");

		await new Promise((resolve) => setTimeout(resolve, 350));
	});

	test("promoteNode aborts without promoting if the target disconnects before confirming readiness", async () => {
		config.ha.role = "primary";
		config.ha.port = 7443;
		const targetWs = { send: () => {}, close: () => {}, data: { authenticatedNodeId: "disconnect-target", authenticatedActive: true } };
		await mesh.handlePrimaryMessage(
			targetWs,
			JSON.stringify({ type: "announce", nodeId: "disconnect-target", name: "target", version: APP_VERSION, adminUrl: "https://disconnect-target.test:9000" }),
		);
		mesh.replicas.add(targetWs);

		const promotion = mesh.promoteNode("disconnect-target");

		await new Promise((resolve) => setTimeout(resolve, 10));
		mesh.handlePrimaryClose(targetWs);

		await expect(promotion).rejects.toThrow(/disconnected while confirming/);

		expect(config.ha.role).toBe("primary");
		const row = await repository.haClusterConfigRow();
		expect(row?.role).toBe("primary");

		expect(config.ha.fencedForPromotion).toBe(false);
	});

	test("promoteNode rejects immediately (not after the full timeout) if sending prepare_promote itself fails", async () => {
		config.ha.role = "primary";
		config.ha.port = 7443;
		const targetWs = {
			send: () => {
				throw new Error("simulated dead socket");
			},
			close: () => {},
			data: { authenticatedNodeId: "send-fail-target", authenticatedActive: true },
		};
		await mesh.handlePrimaryMessage(
			targetWs,
			JSON.stringify({ type: "announce", nodeId: "send-fail-target", name: "target", version: APP_VERSION, adminUrl: "https://send-fail-target.test:9000" }),
		);
		mesh.replicas.add(targetWs);

		mesh.lastBroadcastSeq = await repository.latestChangelogSeq();

		const started = Date.now();
		await expect(mesh.promoteNode("send-fail-target")).rejects.toThrow(/simulated dead socket/);

		expect(Date.now() - started).toBeLessThan(1_000);
		expect(config.ha.fencedForPromotion).toBe(false);
	});

	test("promoteNode aborts if the target acks below the barrier sequence, instead of trusting it", async () => {
		config.ha.role = "primary";
		config.ha.port = 7443;
		const targetWs = {
			send: (data: string) => {
				const message = JSON.parse(data) as { type: string; barrierSeq?: number; promotionId?: string };
				if (message.type === "prepare_promote") {
					void mesh.handlePrimaryMessage(
						targetWs,
						JSON.stringify({ type: "prepare_promote_ack", cursor: (message.barrierSeq ?? 0) - 1, promotionId: message.promotionId }),
					);
				}
			},
			close: () => {},
			data: { authenticatedNodeId: "short-ack-target", authenticatedActive: true },
		};
		await mesh.handlePrimaryMessage(
			targetWs,
			JSON.stringify({ type: "announce", nodeId: "short-ack-target", name: "target", version: APP_VERSION, adminUrl: "https://short-ack-target.test:9000" }),
		);
		mesh.replicas.add(targetWs);

		await expect(mesh.promoteNode("short-ack-target")).rejects.toThrow(/short of the required barrier/);
		expect(config.ha.role).toBe("primary");
		expect(config.ha.fencedForPromotion).toBe(false);
	});

	test("does not demote the old primary when the target disconnects before acknowledging durable activation", async () => {
		config.ha.role = "primary";
		config.ha.port = 7443;
		const targetWs = {
			send: (data: string) => {
				const message = JSON.parse(data) as { type: string; promotionId?: string };
				if (message.type === "prepare_promote") {
					void mesh.handlePrimaryMessage(
						targetWs,
						JSON.stringify({ type: "prepare_promote_ack", cursor: Number.MAX_SAFE_INTEGER, promotionId: message.promotionId }),
					);
				} else if (message.type === "promote") {
					mesh.handlePrimaryClose(targetWs);
				}
			},
			close: () => {},
			data: { authenticatedNodeId: "activation-disconnect-target", authenticatedActive: true },
		};
		await mesh.handlePrimaryMessage(
			targetWs,
			JSON.stringify({
				type: "announce",
				nodeId: "activation-disconnect-target",
				name: "target",
				version: APP_VERSION,
				adminUrl: "https://activation-disconnect.test",
			}),
		);

		await expect(mesh.promoteNode("activation-disconnect-target")).rejects.toThrow(/before its promotion acknowledgement/);

		const configRow = await repository.haClusterConfigRow();
		expect(configRow?.role).toBe("primary");
		expect(config.ha.role).toBe("primary");

		expect(await repository.haPromotionIntent()).toMatchObject({ target_node_id: "activation-disconnect-target" });
		expect(config.ha.fencedForPromotion).toBe(true);
	});

	test("resumes and completes an interrupted promotion once the target reconnects under the same node id", async () => {
		config.ha.role = "primary";
		config.ha.port = 7443;
		await repository.saveHaPromotionIntent({
			promotion_id: "resume-test-promotion",
			target_node_id: "resume-test-target",
			target_url: "https://resume-test-target.test:7443",
			target_admin_url: "https://resume-test-target.test",
			new_epoch: 7,
			created_at: Date.now(),
		});
		config.ha.fencedForPromotion = true;

		const targetWs = {
			send: (data: string) => {
				const message = JSON.parse(data) as { type: string; promotionId?: string };
				if (message.type === "prepare_promote") {
					void mesh.handlePrimaryMessage(
						targetWs,
						JSON.stringify({ type: "prepare_promote_ack", cursor: Number.MAX_SAFE_INTEGER, promotionId: message.promotionId }),
					);
				} else if (message.type === "promote") {
					expect(message.promotionId).toBe("resume-test-promotion");
					void mesh.handlePrimaryMessage(targetWs, JSON.stringify({ type: "promote_applied_ack", promotionId: message.promotionId, success: true }));
				}
			},
			close: () => {},
			data: { authenticatedNodeId: "resume-test-target", authenticatedActive: true },
		};

		await mesh.handlePrimaryMessage(
			targetWs,
			JSON.stringify({ type: "announce", nodeId: "resume-test-target", name: "target", version: APP_VERSION, adminUrl: "https://resume-test-target.test" }),
		);

		const deadline = Date.now() + 2_000;
		while ((await repository.haPromotionIntent()) !== null && Date.now() < deadline) {
			await new Promise((resolve) => setTimeout(resolve, 10));
		}

		expect(await repository.haPromotionIntent()).toBeNull();
		const roleAfter: string = config.ha.role;
		expect(roleAfter).toBe("replica");
		expect(config.ha.fencedForPromotion).toBe(false);
		const row = await repository.haClusterConfigRow();
		expect(row?.role).toBe("replica");
		expect(row?.cluster_epoch).toBe(7);

		await new Promise((resolve) => setTimeout(resolve, 350));
		expect(restartCalls).toContain("ha-promote");
	});

	test("cancels the durable fence when the target explicitly rejects activation", async () => {
		config.ha.role = "primary";
		config.ha.port = 7443;
		const targetWs = {
			send: (data: string) => {
				const message = JSON.parse(data) as { type: string; promotionId?: string };
				if (message.type === "prepare_promote") {
					void mesh.handlePrimaryMessage(
						targetWs,
						JSON.stringify({ type: "prepare_promote_ack", cursor: Number.MAX_SAFE_INTEGER, promotionId: message.promotionId }),
					);
				} else if (message.type === "promote") {
					void mesh.handlePrimaryMessage(
						targetWs,
						JSON.stringify({ type: "promote_applied_ack", promotionId: message.promotionId, success: false, reason: "simulated target DB failure" }),
					);
				}
			},
			close: () => {},
			data: { authenticatedNodeId: "activation-reject-target", authenticatedActive: true },
		};
		await mesh.handlePrimaryMessage(
			targetWs,
			JSON.stringify({
				type: "announce",
				nodeId: "activation-reject-target",
				name: "target",
				version: APP_VERSION,
				adminUrl: "https://activation-reject.test",
			}),
		);

		await expect(mesh.promoteNode("activation-reject-target")).rejects.toThrow(/simulated target DB failure/);
		expect((await repository.haClusterConfigRow())?.role).toBe("primary");
		expect(await repository.haPromotionIntent()).toBeNull();
		expect(config.ha.fencedForPromotion).toBe(false);
	});

	test("cancels the durable fence when Bun reports that the activation message was dropped", async () => {
		config.ha.role = "primary";
		config.ha.port = 7443;
		const targetWs = {
			send: (data: string) => {
				const message = JSON.parse(data) as { type: string; promotionId?: string };
				if (message.type === "prepare_promote") {
					void mesh.handlePrimaryMessage(
						targetWs,
						JSON.stringify({ type: "prepare_promote_ack", cursor: Number.MAX_SAFE_INTEGER, promotionId: message.promotionId }),
					);
					return 1;
				}
				if (message.type === "promote") return 0;
				return 1;
			},
			close: () => {},
			data: { authenticatedNodeId: "activation-drop-target", authenticatedActive: true },
		};
		await mesh.handlePrimaryMessage(
			targetWs,
			JSON.stringify({ type: "announce", nodeId: "activation-drop-target", name: "target", version: APP_VERSION, adminUrl: "https://activation-drop.test" }),
		);

		await expect(mesh.promoteNode("activation-drop-target")).rejects.toThrow(/dropped the activation message/);
		expect((await repository.haClusterConfigRow())?.role).toBe("primary");
		expect(await repository.haPromotionIntent()).toBeNull();
		expect(config.ha.fencedForPromotion).toBe(false);
	});

	test("a stale ack carrying an old promotionId does not satisfy a later promotion attempt on the same target", async () => {
		config.ha.role = "primary";
		config.ha.port = 7443;
		let capturedPromotionId: string | undefined;
		const targetWs = {
			send: (data: string) => {
				const message = JSON.parse(data) as { type: string; promotionId?: string };
				if (message.type === "prepare_promote") {
					capturedPromotionId = message.promotionId;
				} else if (message.type === "promote") {
					void mesh.handlePrimaryMessage(targetWs, JSON.stringify({ type: "promote_applied_ack", promotionId: message.promotionId, success: true }));
				}
			},
			close: () => {},
			data: { authenticatedNodeId: "stale-nonce-target", authenticatedActive: true },
		};
		await mesh.handlePrimaryMessage(
			targetWs,
			JSON.stringify({
				type: "announce",
				nodeId: "stale-nonce-target",
				name: "target",
				version: APP_VERSION,
				adminUrl: "https://stale-nonce-target.test:9000",
			}),
		);
		mesh.replicas.add(targetWs);

		const promotion = mesh.promoteNode("stale-nonce-target");

		await new Promise((resolve) => setTimeout(resolve, 10));
		expect(capturedPromotionId).toBeDefined();

		await mesh.handlePrimaryMessage(
			targetWs,
			JSON.stringify({ type: "prepare_promote_ack", cursor: Number.MAX_SAFE_INTEGER, promotionId: "a-completely-different-promotion-id" }),
		);
		await new Promise((resolve) => setTimeout(resolve, 50));
		expect(config.ha.role).toBe("primary");
		expect(config.ha.fencedForPromotion).toBe(true);

		await mesh.handlePrimaryMessage(
			targetWs,
			JSON.stringify({ type: "prepare_promote_ack", cursor: Number.MAX_SAFE_INTEGER, promotionId: capturedPromotionId }),
		);
		await promotion;
		const roleAfter: string = config.ha.role;
		expect(roleAfter).toBe("replica");

		await new Promise((resolve) => setTimeout(resolve, 350));
	});

	test("a promote message queued behind a failed apply does not run", async () => {
		const originalApply = repository.applyReplicatedChange;
		repository.applyReplicatedChange = async () => {
			throw new Error("simulated apply failure");
		};
		mesh.state = "connected";
		mesh.cursor = 0;
		mesh.nodeId = "generation-guard-node";
		mesh.replicaSocket = fakeSocket();
		mesh.messageQueue = Promise.resolve();

		config.ha.role = "replica";
		await repository.updateHaClusterConfig({ role: "replica" });
		try {
			const failingChange = {
				data: JSON.stringify({
					type: "change",
					row: { seq: 1, entity_type: "site", entity_id: "s1", op: "insert", payload_json: "{}", created_at: Date.now() },
				}),
			} as MessageEvent;
			const stalePromote = {
				data: JSON.stringify({
					type: "promote",
					promotionId: "generation-guard-promotion",
					newPrimaryNodeId: "generation-guard-node",
					newPrimaryUrl: "https://stale:7443",
					newPrimaryAdminUrl: "https://stale",
				}),
			} as MessageEvent;

			mesh.handleIncomingMessage(failingChange);
			mesh.handleIncomingMessage(stalePromote);
			await mesh.messageQueue;

			expect(config.ha.role).toBe("replica");
			const row = await repository.haClusterConfigRow();
			expect(row?.role).toBe("replica");
		} finally {
			repository.applyReplicatedChange = originalApply;
		}
	});

	test("handlePromote on the node being promoted sets role to primary with no primary URL", async () => {
		mesh.nodeId = "this-node-uuid";
		config.ha.role = "replica";
		await mesh.handlePromote({
			type: "promote",
			promotionId: "target-promotion",
			newPrimaryNodeId: "this-node-uuid",
			newPrimaryUrl: "https://irrelevant:7443",
			newPrimaryAdminUrl: "https://irrelevant",
			newEpoch: 7,
		});
		const row = await repository.haClusterConfigRow();
		expect(row?.role).toBe("primary");
		expect(row?.primary_url).toBeNull();
		expect(row?.primary_admin_url).toBeNull();
		expect(row?.cluster_epoch).toBe(7);
		expect(config.ha.epoch).toBe(7);

		expect(config.ha.role).toBe("replica");
		await new Promise((resolve) => setTimeout(resolve, 350));
		expect(restartCalls).toContain("ha-promote");
	});

	test("handlePromote on a bystander replica re-points at the new primary", async () => {
		mesh.nodeId = "bystander-uuid";
		await mesh.handlePromote({
			type: "promote",
			promotionId: "bystander-promotion",
			newPrimaryNodeId: "other-node-uuid",
			newPrimaryUrl: "https://new-primary.test:7443",
			newPrimaryAdminUrl: "https://new-primary.test",
			newEpoch: 8,
		});
		const row = await repository.haClusterConfigRow();
		expect(row?.role).toBe("replica");
		expect(row?.primary_url).toBe("https://new-primary.test:7443");
		expect(row?.primary_admin_url).toBe("https://new-primary.test");
		expect(row?.cluster_epoch).toBe(8);
		expect(config.ha.epoch).toBe(8);
		await new Promise((resolve) => setTimeout(resolve, 350));
		expect(restartCalls).toContain("ha-promote");
	});

	test("a bystander that missed promotion durably follows the former primary's redirect", async () => {
		config.ha.role = "replica";
		config.ha.primaryUrl = "https://old-primary.test:7443";
		config.ha.primaryAdminUrl = "https://old-primary.test";
		config.ha.epoch = 4;
		mesh.caCertificate = "old-primary-certificate";
		await repository.updateHaClusterConfig({
			role: "replica",
			primaryUrl: config.ha.primaryUrl,
			primaryAdminUrl: config.ha.primaryAdminUrl,
			clusterEpoch: config.ha.epoch,
		});

		await mesh.handlePrimaryRedirect({
			type: "primary_redirect",
			primaryUrl: "https://new-primary.test:7443",
			primaryAdminUrl: "https://new-primary.test",
			epoch: 5,
		});

		const row = await repository.haClusterConfigRow();
		expect(row?.primary_url).toBe("https://new-primary.test:7443");
		expect(row?.primary_admin_url).toBe("https://new-primary.test");
		expect(row?.cluster_epoch).toBe(5);
		expect(mesh.caCertificate).toBeNull();
		await new Promise((resolve) => setTimeout(resolve, 350));
		expect(restartCalls).toContain("ha-primary-redirect");
	});

	test("handlePromote retries target persistence, then rejects activation without restarting on failure", async () => {
		mesh.nodeId = "retry-fail-node";
		const sent: string[] = [];
		mesh.replicaSocket = fakeSocket((data) => sent.push(data));
		const originalUpdate = repository.updateHaClusterConfig;
		let attempts = 0;
		repository.updateHaClusterConfig = async () => {
			attempts += 1;
			throw new Error("simulated persistent DB failure");
		};
		try {
			await mesh.handlePromote({
				type: "promote",
				promotionId: "retry-fail-promotion",
				newPrimaryNodeId: "retry-fail-node",
				newPrimaryUrl: "https://irrelevant:7443",
				newPrimaryAdminUrl: "https://irrelevant",
				newEpoch: 9,
			});
			expect(attempts).toBe(3);
			const ack = JSON.parse(sent.at(-1)!) as { type: string; promotionId: string; success: boolean; reason?: string };
			expect(ack).toEqual({
				type: "promote_applied_ack",
				promotionId: "retry-fail-promotion",
				success: false,
				reason: "The target could not persist its primary role after repeated attempts",
			});
			await new Promise((resolve) => setTimeout(resolve, 350));
			expect(restartCalls).not.toContain("ha-promote");
		} finally {
			repository.updateHaClusterConfig = originalUpdate;
		}
	});
});

describe("HA mesh service: resolveCaCertificate's fallback fetch", () => {
	const originalFetch = globalThis.fetch;
	const originalDataDirectory = config.dataDirectory;
	const originalPrimaryAdminUrl = config.ha.primaryAdminUrl;
	const originalSharedToken = config.ha.sharedToken;
	let tempDir = "";

	afterEach(async () => {
		globalThis.fetch = originalFetch;
		config.dataDirectory = originalDataDirectory;
		config.ha.primaryAdminUrl = originalPrimaryAdminUrl;
		config.ha.sharedToken = originalSharedToken;
		if (tempDir) {
			await rm(tempDir, { recursive: true, force: true });
			tempDir = "";
		}
	});

	test("accepts a self-signed admin-URL certificate, authenticating via the bearer token instead of the system CA store", async () => {
		tempDir = await mkdtemp(join(tmpdir(), "bg-ha-resolve-ca-test-"));
		config.dataDirectory = tempDir;
		config.ha.primaryAdminUrl = "https://primary.internal";
		config.ha.sharedToken = "test-shared-token";
		let capturedTls: unknown;
		let capturedAuth: string | null = null as string | null;
		globalThis.fetch = (async (_url: unknown, init?: RequestInit) => {
			capturedTls = (init as (RequestInit & { tls?: unknown }) | undefined)?.tls;
			capturedAuth = new Headers(init?.headers).get("authorization");
			return Response.json({ cert: "fetched-and-pinned-certificate" });
		}) as unknown as typeof fetch;

		const result = await mesh.resolveCaCertificate();

		expect(result).toBe("fetched-and-pinned-certificate");
		expect(capturedTls).toMatchObject({ rejectUnauthorized: false });
		expect(capturedAuth).toBe("Bearer test-shared-token");
		expect(await Bun.file(join(tempDir, "tls", "ha-primary-ca.pem")).text()).toBe("fetched-and-pinned-certificate");
	});
});

describe("readWithIdleTimeout", () => {
	test("resolves normally when the read finishes before the timeout", async () => {
		const reader = { read: async () => "chunk" };
		await expect(readWithIdleTimeout(reader, 1_000)).resolves.toBe("chunk");
	});

	test("rejects if no chunk arrives within the timeout, without waiting for the stalled read", async () => {
		const reader = { read: () => new Promise<string>(() => {}) };
		await expect(readWithIdleTimeout(reader, 20)).rejects.toThrow(/stalled/);
	});
});
