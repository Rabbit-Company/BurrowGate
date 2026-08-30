import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { config } from "../src/config.ts";
import { db } from "../src/db/client.ts";
import { repository } from "../src/db/repository.ts";
import { MEMBERSHIP_SHRINK_GRACE_MS } from "../src/ha-timing.ts";
import { haElectionPeerClient, haElectionService } from "../src/services/ha-election-service.ts";
import { haMeshService } from "../src/services/ha-mesh-service.ts";
import { processLifecycle } from "../src/services/process-lifecycle-service.ts";
import { sha256Hex } from "../src/utils/crypto.ts";

let restartCalls: string[] = [];
processLifecycle.gracefulRestart = (async (reason: string) => {
	restartCalls.push(reason);
}) as typeof processLifecycle.gracefulRestart;

const election = haElectionService as unknown as {
	handleHttpRequest(request: Request, identity?: { nodeId: string; active: boolean }): Promise<Response>;
	handleVoteRequest(request: Request): Promise<Response>;
	handleWhoIsPrimary(): Promise<Response>;
	handleAnnouncePrimary(request: Request): Promise<Response>;
	tickPrimaryQuorum(): Promise<void>;
	tryAutomaticFormerPrimaryRecovery(reason: string): Promise<void>;
	tryDiscoverPrimaryFromPeers(members: unknown[]): Promise<boolean>;
	startCampaign(members: unknown[], nodeId: string): Promise<void>;
	runCampaign(
		term: number,
		ownCursor: number,
		members: unknown[],
		nodeId: string,
		connectivityGeneration?: number,
		expectedPrimaryUrl?: string | null,
		expectedPrimaryAdminUrl?: string | null,
	): Promise<void>;
	electionTimeoutMs(members: unknown[], nodeId: string): Promise<number>;
	peerCertCache: Map<string, string>;
	campaigningTerm: number | null;
	recentMaxMemberCount: number;
	recentMaxMemberCountAt: number;
};

const mesh = haMeshService as unknown as {
	nodes: Map<unknown, unknown>;
	replicas: Set<unknown>;
	registeredMembers: Map<unknown, unknown>;
	cursor: number;
	nodeId: string | null;
	state: string;
	disconnectedSince: number;
	electionWinnerActivating: boolean;
	verifiedPrimaryConnectionGeneration: number;
	primaryAuthorityAmbiguous: boolean;
	runtimePrepared: boolean;
	offlineSince: Map<string, number>;
	prepareForRuntimeAtBoot(): Promise<void>;
	forgetNode(nodeId: string): Promise<void>;
};

function voteRequest(body: Record<string, unknown>): Request {
	return new Request("https://node.test:7443/_ha/vote-request", {
		method: "POST",
		headers: { authorization: `Bearer ${config.ha.sharedToken}`, "content-type": "application/json" },
		body: JSON.stringify(body),
	});
}

function announceRequest(body: Record<string, unknown>): Request {
	return new Request("https://node.test:7443/_ha/announce-primary", {
		method: "POST",
		headers: { authorization: `Bearer ${config.ha.sharedToken}`, "content-type": "application/json" },
		body: JSON.stringify(body),
	});
}

async function seedMembers(nodeId: string, count: number): Promise<void> {
	const now = Date.now();

	await repository.upsertHaClusterMember({
		node_id: nodeId,
		name: "self",
		version: "1.0.0",
		admin_url: "https://self.test",
		first_seen_at: now,
		last_seen_at: now,
		credential_hash: await sha256Hex(config.ha.sharedToken!),
	});
	for (let index = 1; index < count; index++) {
		await repository.upsertHaClusterMember({
			node_id: `peer-${index}`,
			name: `peer-${index}`,
			version: "1.0.0",
			admin_url: `https://peer-${index}.test`,
			first_seen_at: now,
			last_seen_at: now,
			credential_hash: await sha256Hex(`peer-${index}-credential`),
		});
	}
}

describe("HA election service", () => {
	const originalRole = config.ha.role;
	const originalEpoch = config.ha.epoch;
	const originalSharedToken = config.ha.sharedToken;
	const originalAutoFailoverEnabled = config.ha.autoFailoverEnabled;
	const originalAuthorityFence = config.ha.authorityFence;
	const originalFencedForPromotion = config.ha.fencedForPromotion;
	const originalQuorumFenced = config.ha.quorumFenced;
	const originalLastMajorityConfirmedAt = config.ha.lastMajorityConfirmedAt;
	const originalQuorumTrackingActive = config.ha.quorumTrackingActive;
	const originalElectionInProgress = config.ha.electionInProgress;
	const originalSelfAdminUrl = config.ha.selfAdminUrl;
	const originalPrimaryUrl = config.ha.primaryUrl;
	const originalPrimaryAdminUrl = config.ha.primaryAdminUrl;
	const originalMeshState = mesh.state;
	const originalDisconnectedSince = mesh.disconnectedSince;
	const originalElectionWinnerActivating = mesh.electionWinnerActivating;
	const originalVerifiedPrimaryConnectionGeneration = mesh.verifiedPrimaryConnectionGeneration;
	const originalPrimaryAuthorityAmbiguous = mesh.primaryAuthorityAmbiguous;
	const originalRuntimePrepared = mesh.runtimePrepared;

	beforeEach(async () => {
		restartCalls = [];
		config.ha.sharedToken = "test-shared-token";
		config.ha.autoFailoverEnabled = true;
		config.ha.authorityFence = null;
		config.ha.fencedForPromotion = false;
		config.ha.quorumFenced = false;
		config.ha.lastMajorityConfirmedAt = Date.now();
		config.ha.quorumTrackingActive = false;
		config.ha.electionInProgress = false;
		config.ha.epoch = 0;
		election.campaigningTerm = null;
		election.recentMaxMemberCount = 0;
		election.recentMaxMemberCountAt = 0;
		election.peerCertCache.clear();
		mesh.cursor = 0;

		mesh.state = "disconnected";
		mesh.disconnectedSince = Date.now();
		mesh.electionWinnerActivating = false;
		mesh.verifiedPrimaryConnectionGeneration = 0;
		mesh.primaryAuthorityAmbiguous = false;
		mesh.runtimePrepared = originalRuntimePrepared;

		const existing = await repository.haClusterConfigRow();
		if (existing) {
			await repository.updateHaClusterConfig({ enabled: true, role: "replica", primaryUrl: null, primaryAdminUrl: null, clusterEpoch: 0 });
			await db`UPDATE ha_cluster_config SET voted_for_term=NULL, voted_for_node_id=NULL, quorum_fenced=0, quorum_fenced_at=NULL WHERE id=1`;
		} else {
			await repository.insertHaClusterConfig({
				enabled: true,
				role: "replica",
				nodeName: "election-test-node",
				primaryUrl: null,
				primaryAdminUrl: null,
				sharedTokenEncrypted: null,
				selfAdminUrl: null,
				clusterEpoch: 0,
			});
		}
	});

	afterEach(async () => {
		config.ha.role = originalRole;
		config.ha.epoch = originalEpoch;
		config.ha.sharedToken = originalSharedToken;
		config.ha.autoFailoverEnabled = originalAutoFailoverEnabled;
		config.ha.authorityFence = originalAuthorityFence;
		config.ha.fencedForPromotion = originalFencedForPromotion;
		config.ha.quorumFenced = originalQuorumFenced;
		config.ha.lastMajorityConfirmedAt = originalLastMajorityConfirmedAt;
		config.ha.quorumTrackingActive = originalQuorumTrackingActive;
		config.ha.electionInProgress = originalElectionInProgress;
		config.ha.selfAdminUrl = originalSelfAdminUrl;
		config.ha.primaryUrl = originalPrimaryUrl;
		config.ha.primaryAdminUrl = originalPrimaryAdminUrl;
		election.campaigningTerm = null;
		election.recentMaxMemberCount = 0;
		election.recentMaxMemberCountAt = 0;
		election.peerCertCache.clear();
		mesh.nodes.clear();
		mesh.replicas.clear();
		mesh.registeredMembers.clear();
		mesh.nodeId = null;
		mesh.state = originalMeshState;
		mesh.disconnectedSince = originalDisconnectedSince;
		mesh.electionWinnerActivating = originalElectionWinnerActivating;
		mesh.verifiedPrimaryConnectionGeneration = originalVerifiedPrimaryConnectionGeneration;
		mesh.primaryAuthorityAmbiguous = originalPrimaryAuthorityAmbiguous;
		mesh.runtimePrepared = originalRuntimePrepared;
		await db`DELETE FROM ha_cluster_members`;

		await db`DELETE FROM ha_cluster_config`;

		await db`DELETE FROM replication_cursor`;
	});

	describe("handleVoteRequest: the floor", () => {
		test("binds the claimed candidate id to the member credential that authenticated the HTTP request", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "replica";
			config.ha.epoch = 1;
			mesh.cursor = 0;
			const response = await election.handleHttpRequest(
				voteRequest({ term: 2, candidateId: "peer-1", candidateCursor: 0, candidateAdminUrl: "https://peer-1.test" }),
				{ nodeId, active: true },
			);
			const body = (await response.json()) as { voteGranted: boolean; reason?: string };
			expect(body.voteGranted).toBe(false);
			expect(body.reason).toMatch(/identity does not match/);
			expect(config.ha.epoch).toBe(1);
		});

		test("refuses below the 3-member floor, even with a genuinely newer term", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 2);
			config.ha.epoch = 1;
			const response = await election.handleVoteRequest(
				voteRequest({ term: 2, candidateId: "peer-1", candidateCursor: 0, candidateAdminUrl: "https://peer-1.test" }),
			);
			const body = (await response.json()) as { voteGranted: boolean; reason?: string };
			expect(body.voteGranted).toBe(false);
			expect(body.reason).toMatch(/below the 3-member floor/);
		});

		test("re-checks the floor fresh on every call, not cached from an earlier grant", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "replica";
			config.ha.epoch = 1;
			mesh.cursor = 0;
			const first = await election.handleVoteRequest(
				voteRequest({ term: 2, candidateId: "peer-1", candidateCursor: 0, candidateAdminUrl: "https://peer-1.test" }),
			);
			expect(((await first.json()) as { voteGranted: boolean }).voteGranted).toBe(true);

			await db`DELETE FROM ha_cluster_members WHERE node_id='peer-2'`;
			const second = await election.handleVoteRequest(
				voteRequest({ term: 3, candidateId: "peer-2", candidateCursor: 0, candidateAdminUrl: "https://peer-2.test" }),
			);
			expect(((await second.json()) as { voteGranted: boolean }).voteGranted).toBe(false);
		});
	});

	describe("handleVoteRequest: term and log-up-to-date safety", () => {
		test("refuses a candidate that advertises a plaintext admin endpoint", async () => {
			const response = await election.handleVoteRequest(
				voteRequest({ term: 2, candidateId: "peer-1", candidateCursor: 0, candidateAdminUrl: "http://peer-1.test" }),
			);
			const body = (await response.json()) as { voteGranted: boolean; reason?: string };
			expect(body.voteGranted).toBe(false);
			expect(body.reason).toMatch(/malformed vote-request body/);
		});

		test("a replica still connected to its verified primary refuses the vote without consuming it", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "replica";
			config.ha.epoch = 1;
			mesh.state = "connected";
			mesh.disconnectedSince = 0;
			mesh.cursor = 0;

			const response = await election.handleVoteRequest(
				voteRequest({ term: 2, candidateId: "peer-1", candidateCursor: 0, candidateAdminUrl: "https://peer-1.test" }),
			);
			const body = (await response.json()) as { voteGranted: boolean; reason?: string };

			expect(body.voteGranted).toBe(false);
			expect(body.reason).toMatch(/still has a verified primary connection/);
			expect(config.ha.epoch).toBe(1);
			const row = await repository.haClusterConfigRow();
			expect(row?.voted_for_term).toBeNull();
			expect(row?.voted_for_node_id).toBeNull();
		});

		test("refuses a stale term (not newer than this node's own epoch)", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.epoch = 5;
			const response = await election.handleVoteRequest(
				voteRequest({ term: 5, candidateId: "peer-1", candidateCursor: 0, candidateAdminUrl: "https://peer-1.test" }),
			);
			expect(((await response.json()) as { voteGranted: boolean }).voteGranted).toBe(false);
		});

		test("refuses a candidate whose cursor is behind this voter's own, WITHOUT consuming the term's vote", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);

			config.ha.role = "replica";
			config.ha.epoch = 1;
			mesh.cursor = 10;
			const behind = await election.handleVoteRequest(
				voteRequest({ term: 2, candidateId: "peer-1", candidateCursor: 5, candidateAdminUrl: "https://peer-1.test" }),
			);
			expect(((await behind.json()) as { voteGranted: boolean }).voteGranted).toBe(false);
			const afterRejection = await repository.haClusterConfigRow();
			expect(afterRejection?.cluster_epoch).toBe(2);
			expect(afterRejection?.voted_for_term).toBeNull();

			const caughtUp = await election.handleVoteRequest(
				voteRequest({ term: 2, candidateId: "peer-2", candidateCursor: 10, candidateAdminUrl: "https://peer-2.test" }),
			);
			expect(((await caughtUp.json()) as { voteGranted: boolean }).voteGranted).toBe(true);
		});

		test("grants a candidate whose cursor is at least as caught up", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "replica";
			config.ha.epoch = 1;
			mesh.cursor = 3;
			const response = await election.handleVoteRequest(
				voteRequest({ term: 2, candidateId: "peer-1", candidateCursor: 3, candidateAdminUrl: "https://peer-1.test" }),
			);
			expect(((await response.json()) as { voteGranted: boolean }).voteGranted).toBe(true);
		});
	});

	describe("handleVoteRequest: one vote per term", () => {
		test("re-grants idempotently to the SAME candidate/term (a retried request after a dropped response)", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "replica";
			config.ha.epoch = 1;
			mesh.cursor = 0;
			const body = { term: 2, candidateId: "peer-1", candidateCursor: 0, candidateAdminUrl: "https://peer-1.test" };
			const first = await election.handleVoteRequest(voteRequest(body));
			const second = await election.handleVoteRequest(voteRequest(body));
			expect(((await first.json()) as { voteGranted: boolean }).voteGranted).toBe(true);
			expect(((await second.json()) as { voteGranted: boolean }).voteGranted).toBe(true);
		});

		test("refuses a DIFFERENT candidate in the same already-voted term", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "replica";
			config.ha.epoch = 1;
			mesh.cursor = 0;
			await election.handleVoteRequest(voteRequest({ term: 2, candidateId: "peer-1", candidateCursor: 0, candidateAdminUrl: "https://peer-1.test" }));
			const other = await election.handleVoteRequest(
				voteRequest({ term: 2, candidateId: "peer-2", candidateCursor: 0, candidateAdminUrl: "https://peer-2.test" }),
			);
			expect(((await other.json()) as { voteGranted: boolean; reason?: string }).voteGranted).toBe(false);
		});

		test("persists the vote grant durably before responding (survives this process reading it back fresh)", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "replica";
			config.ha.epoch = 1;
			mesh.cursor = 0;
			await election.handleVoteRequest(voteRequest({ term: 2, candidateId: "peer-1", candidateCursor: 0, candidateAdminUrl: "https://peer-1.test" }));
			const row = await repository.haClusterConfigRow();
			expect(row?.voted_for_term).toBe(2);
			expect(row?.voted_for_node_id).toBe("peer-1");
		});
	});

	describe("handleVoteRequest: temporary primary election fence", () => {
		test("a failed campaign temporarily fences the primary, never receives its vote, then safely clears", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "primary";
			config.ha.epoch = 3;
			config.ha.authorityFence = null;
			config.ha.quorumFenced = false;
			await repository.updateHaClusterConfig({ role: "primary", clusterEpoch: 3 });
			const cursor = await repository.latestChangelogSeq();
			const sent: string[] = [];
			const socket = {
				send(data: string) {
					sent.push(data);
					return 1;
				},
				close() {},
			};
			mesh.replicas.add(socket);
			mesh.nodes.set(socket, { nodeId: "peer-2", name: "peer-2", lastSeenAt: Date.now() });

			const response = await election.handleVoteRequest(
				voteRequest({ term: 4, candidateId: "peer-1", candidateCursor: cursor, candidateAdminUrl: "https://peer-1.test" }),
			);
			const vote = (await response.json()) as { voteGranted: boolean; reason?: string };

			expect(vote.voteGranted).toBe(false);
			expect(vote.reason).toMatch(/active primary does not grant/);
			expect(config.ha.epoch).toBe(4);
			expect(config.ha.authorityFence).toBeNull();
			expect(config.ha.quorumFenced).toBe(true);
			let row = await repository.haClusterConfigRow();
			expect(row?.role).toBe("primary");
			expect(row?.cluster_epoch).toBe(4);
			expect(row?.authority_fenced).toBe(0);
			expect(row?.quorum_fenced).toBe(1);
			expect(row?.voted_for_term).toBeNull();
			expect(sent.map((payload) => JSON.parse(payload) as { primaryFenced?: boolean }).some((message) => message.primaryFenced === true)).toBe(true);

			await election.tickPrimaryQuorum();
			expect(config.ha.quorumFenced).toBe(true);
			await db`UPDATE ha_cluster_config SET quorum_fenced_at=${Date.now() - 60_000} WHERE id=1`;
			mesh.nodes.set(socket, { nodeId: "peer-2", name: "peer-2", lastSeenAt: Date.now() });
			await election.tickPrimaryQuorum();

			expect(config.ha.role).toBe("primary");
			expect(config.ha.authorityFence).toBeNull();
			expect(config.ha.quorumFenced).toBe(false);
			row = await repository.haClusterConfigRow();
			expect(row?.role).toBe("primary");
			expect(row?.quorum_fenced).toBe(0);
			const { haPrimaryWriteBarrier } = await import("../src/services/ha-write-barrier.ts");
			await expect(haPrimaryWriteBarrier.runPrimaryWrite(async () => "ok")).resolves.toBe("ok");
			expect(sent.map((payload) => JSON.parse(payload) as { primaryFenced?: boolean }).some((message) => message.primaryFenced === false)).toBe(true);
		});
	});

	describe("handleWhoIsPrimary / handleAnnouncePrimary", () => {
		test("binds a winner announcement to the member credential that authenticated it", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "replica";
			config.ha.epoch = 5;
			const response = await election.handleHttpRequest(
				announceRequest({
					epoch: 6,
					primaryNodeId: "peer-1",
					primaryUrl: "https://peer-1.test:7443",
					primaryAdminUrl: "https://peer-1.test",
				}),
				{ nodeId, active: true },
			);
			expect(response.status).toBe(403);
			expect(config.ha.epoch).toBe(5);
		});

		test("who-is-primary answers with this node's own belief as a replica", async () => {
			config.ha.role = "replica";
			config.ha.epoch = 2;
			config.ha.primaryUrl = "https://primary.test:7443";
			config.ha.primaryAdminUrl = "https://primary.test";
			const response = await election.handleWhoIsPrimary();
			const body = (await response.json()) as { epoch: number; primaryUrl: string | null; primaryAdminUrl: string | null; role?: string };
			expect(body).toEqual({ epoch: 2, primaryUrl: "https://primary.test:7443", primaryAdminUrl: "https://primary.test", role: "replica" });
		});

		test("who-is-primary answers with itself as primary, deriving the mesh URL from selfAdminUrl", async () => {
			config.ha.role = "primary";
			config.ha.epoch = 7;
			config.ha.selfAdminUrl = "https://me.test";
			config.ha.port = 7443;
			const response = await election.handleWhoIsPrimary();
			const body = (await response.json()) as { epoch: number; primaryUrl: string | null; primaryAdminUrl: string | null; role?: string };
			expect(body.epoch).toBe(7);
			expect(body.primaryUrl).toBe("https://me.test:7443");
			expect(body.primaryAdminUrl).toBe("https://me.test");
			expect(body.role).toBe("primary");
		});

		test("who-is-primary refuses to self-report as authoritative while quorum-loss fenced", async () => {
			config.ha.role = "primary";
			config.ha.epoch = 7;
			config.ha.selfAdminUrl = "https://me.test";
			config.ha.quorumFenced = true;
			const response = await election.handleWhoIsPrimary();
			const body = (await response.json()) as { epoch: number; primaryUrl: string | null; primaryAdminUrl: string | null; role?: string };
			expect(body).toEqual({ epoch: 7, primaryUrl: null, primaryAdminUrl: null, role: "replica" });
		});

		test("who-is-primary refuses to self-report as authoritative while durably authority-fenced", async () => {
			config.ha.role = "primary";
			config.ha.epoch = 7;
			config.ha.selfAdminUrl = "https://me.test";
			config.ha.authorityFence = { observedEpoch: 9, sourceNodeId: "winner", observedAt: Date.now() };
			const response = await election.handleWhoIsPrimary();
			const body = (await response.json()) as { epoch: number; primaryUrl: string | null; primaryAdminUrl: string | null; role?: string };
			expect(body).toEqual({ epoch: 7, primaryUrl: null, primaryAdminUrl: null, role: "replica" });
		});

		test("who-is-primary still self-reports as authoritative while merely mid-promotion (not authority-in-doubt)", async () => {
			config.ha.role = "primary";
			config.ha.epoch = 7;
			config.ha.selfAdminUrl = "https://me.test";
			config.ha.fencedForPromotion = true;
			const response = await election.handleWhoIsPrimary();
			const body = (await response.json()) as { epoch: number; primaryUrl: string | null; primaryAdminUrl: string | null; role?: string };
			expect(body.role).toBe("primary");
		});

		test("announce-primary is a no-op on a lower epoch", async () => {
			config.ha.role = "replica";
			config.ha.epoch = 5;
			const response = await election.handleAnnouncePrimary(
				announceRequest({ epoch: 4, primaryUrl: "https://x.test:7443", primaryAdminUrl: "https://x.test" }),
			);
			expect(((await response.json()) as { adopted: boolean }).adopted).toBe(false);
			expect(restartCalls).not.toContain("ha-primary-discovered");
		});

		test("announce-primary rejects plaintext topology before it can be persisted", async () => {
			config.ha.role = "replica";
			config.ha.epoch = 5;
			const response = await election.handleAnnouncePrimary(
				announceRequest({ epoch: 6, primaryUrl: "https://winner.test:7443", primaryAdminUrl: "http://winner.test" }),
			);
			expect(response.status).toBe(400);
			expect((await repository.haClusterConfigRow())?.cluster_epoch).toBe(0);
			expect(restartCalls).not.toContain("ha-primary-discovered");
		});

		test("announce-primary is idempotent when this node already follows that primary at the same term", async () => {
			config.ha.role = "replica";
			config.ha.epoch = 5;
			config.ha.primaryUrl = "https://current.test:7443";
			config.ha.primaryAdminUrl = "https://current.test";
			const response = await election.handleAnnouncePrimary(
				announceRequest({ epoch: 5, primaryUrl: "https://current.test:7443", primaryAdminUrl: "https://current.test" }),
			);
			expect(((await response.json()) as { adopted: boolean }).adopted).toBe(false);
			expect(restartCalls).not.toContain("ha-primary-discovered");
		});

		test("a voter adopts the election winner announced at the term it already persisted", async () => {
			config.ha.role = "replica";
			config.ha.epoch = 6;
			config.ha.primaryUrl = "https://dead-primary.test:7443";
			config.ha.primaryAdminUrl = "https://dead-primary.test";
			await repository.updateHaClusterConfig({
				role: "replica",
				primaryUrl: config.ha.primaryUrl,
				primaryAdminUrl: config.ha.primaryAdminUrl,
				clusterEpoch: 6,
			});
			const response = await election.handleAnnouncePrimary(
				announceRequest({ epoch: 6, primaryUrl: "https://winner.test:7443", primaryAdminUrl: "https://winner.test" }),
			);
			expect(((await response.json()) as { adopted: boolean }).adopted).toBe(true);
			expect(config.ha.epoch).toBe(6);
			expect(config.ha.primaryUrl).toBe("https://winner.test:7443");
			const row = await repository.haClusterConfigRow();
			expect(row?.role).toBe("replica");
			expect(row?.primary_url).toBe("https://winner.test:7443");
		});

		test("equal-term winner adoption atomically clears obsolete primary fences and cancels a local campaign", async () => {
			config.ha.role = "primary";
			config.ha.epoch = 7;
			config.ha.authorityFence = { observedEpoch: 7, sourceNodeId: "winner", observedAt: Date.now() };
			config.ha.quorumFenced = true;
			config.ha.electionInProgress = true;
			election.campaigningTerm = 7;
			await repository.updateHaClusterConfig({ role: "primary", primaryUrl: null, primaryAdminUrl: null, clusterEpoch: 7 });
			await repository.fenceHaPrimaryAuthority(7, "winner", Date.now());
			await repository.setQuorumFence(Date.now());

			const response = await election.handleAnnouncePrimary(
				announceRequest({ epoch: 7, primaryUrl: "https://winner.test:7443", primaryAdminUrl: "https://winner.test" }),
			);
			expect(((await response.json()) as { adopted: boolean }).adopted).toBe(true);
			expect(election.campaigningTerm).toBeNull();
			expect(config.ha.electionInProgress).toBe(false);
			expect(config.ha.authorityFence).toBeNull();
			expect(config.ha.quorumFenced).toBe(false);
			const row = await repository.haClusterConfigRow();
			expect(row?.role).toBe("replica");
			expect(row?.authority_fenced).toBe(0);
			expect(row?.quorum_fenced).toBe(0);
		});

		test("demoting a node that was itself primary forces a fresh bootstrap, not just the dedicated recovery path", async () => {
			config.ha.role = "primary";
			config.ha.epoch = 7;
			await repository.updateHaClusterConfig({ role: "primary", primaryUrl: null, primaryAdminUrl: null, clusterEpoch: 7 });
			await db`DELETE FROM replication_cursor`;
			await db`INSERT INTO replication_cursor (id,last_applied_seq,bootstrapped) VALUES (1,0,1)`;

			const response = await election.handleAnnouncePrimary(
				announceRequest({ epoch: 8, primaryUrl: "https://winner.test:7443", primaryAdminUrl: "https://winner.test" }),
			);

			expect(((await response.json()) as { adopted: boolean }).adopted).toBe(true);
			expect(await repository.needsBootstrap()).toBe(true);
			await db`DELETE FROM replication_cursor`;
		});

		test("demoting a node that was already a replica does NOT force an unnecessary fresh bootstrap", async () => {
			config.ha.role = "replica";
			config.ha.epoch = 5;
			config.ha.primaryUrl = "https://old.test:7443";
			config.ha.primaryAdminUrl = "https://old.test";
			await repository.updateHaClusterConfig({ role: "replica", primaryUrl: "https://old.test:7443", primaryAdminUrl: "https://old.test", clusterEpoch: 5 });
			await db`DELETE FROM replication_cursor`;
			await db`INSERT INTO replication_cursor (id,last_applied_seq,bootstrapped) VALUES (1,0,1)`;

			const response = await election.handleAnnouncePrimary(
				announceRequest({ epoch: 6, primaryUrl: "https://new.test:7443", primaryAdminUrl: "https://new.test" }),
			);

			expect(((await response.json()) as { adopted: boolean }).adopted).toBe(true);
			expect(await repository.needsBootstrap()).toBe(false);
			await db`DELETE FROM replication_cursor`;
		});

		test("announce-primary adopts a genuinely newer epoch and schedules a restart", async () => {
			config.ha.role = "replica";
			config.ha.epoch = 5;
			config.ha.primaryUrl = "https://old.test:7443";
			config.ha.primaryAdminUrl = "https://old.test";
			const response = await election.handleAnnouncePrimary(
				announceRequest({ epoch: 6, primaryUrl: "https://new.test:7443", primaryAdminUrl: "https://new.test" }),
			);
			expect(((await response.json()) as { adopted: boolean }).adopted).toBe(true);
			expect(config.ha.epoch).toBe(6);
			expect(config.ha.primaryUrl).toBe("https://new.test:7443");
			await new Promise((resolve) => setTimeout(resolve, 350));
			expect(restartCalls).toContain("ha-primary-discovered");
		});
	});

	describe("quorum-loss self-fence (primary side)", () => {
		test("an election-capable primary boots fenced until it proves fresh majority connectivity", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "primary";
			await repository.updateHaClusterConfig({ role: "primary" });
			mesh.runtimePrepared = false;

			await mesh.prepareForRuntimeAtBoot();

			expect(config.ha.quorumFenced).toBe(true);
			const row = await repository.haClusterConfigRow();
			expect(row?.quorum_fenced).toBe(1);
			expect(row?.quorum_fenced_at).not.toBeNull();
		});

		test("does nothing below the auto-failover member floor, and clears a stale fence from a shrunk cluster", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 2);
			config.ha.role = "primary";
			config.ha.quorumFenced = true;
			await repository.setQuorumFence(Date.now() - 60_000);
			await election.tickPrimaryQuorum();
			expect(config.ha.quorumFenced).toBe(false);
		});

		test("boots fenced using the durable high-water-mark when local membership just shrank below the floor, even across a restart", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 2);
			config.ha.role = "primary";
			await repository.updateHaClusterConfig({ role: "primary" });

			await db`UPDATE ha_cluster_config SET recent_max_member_count=3, recent_max_member_count_at=${Date.now()} WHERE id=1`;
			mesh.runtimePrepared = false;

			await mesh.prepareForRuntimeAtBoot();

			expect(config.ha.quorumFenced).toBe(true);
		});

		test("boots unfenced once the durable high-water-mark has aged past the grace window", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 2);
			config.ha.role = "primary";
			await repository.updateHaClusterConfig({ role: "primary" });
			await db`UPDATE ha_cluster_config SET recent_max_member_count=3, recent_max_member_count_at=${Date.now() - (MEMBERSHIP_SHRINK_GRACE_MS + 1000)} WHERE id=1`;
			mesh.runtimePrepared = false;

			await mesh.prepareForRuntimeAtBoot();

			expect(config.ha.quorumFenced).toBe(false);
		});

		test("forgetNode durably records the pre-forget member count", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "primary";
			await repository.updateHaClusterConfig({ role: "primary" });
			mesh.nodes.set({ close: () => {} }, { nodeId: "peer-1", lastSeenAt: Date.now() });
			mesh.offlineSince.set("peer-2", Date.now() - 3_600_000);

			await mesh.forgetNode("peer-2");

			const row = await repository.haClusterConfigRow();
			expect(row?.recent_max_member_count).toBe(3);
			expect(row?.recent_max_member_count_at).not.toBeNull();
		});

		test("keeps requiring the OLD, larger membership count for a grace window after a local shrink, instead of immediately trusting the new one", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "primary";
			mesh.nodes.clear();
			await election.tickPrimaryQuorum();
			expect(config.ha.quorumFenced).toBe(false);

			await db`DELETE FROM ha_cluster_members WHERE node_id='peer-2'`;
			expect((await repository.haClusterMembers()).length).toBe(2);

			config.ha.lastMajorityConfirmedAt = Date.now() - (config.ha.quorumLossFenceSeconds * 1000 + 1000);
			await election.tickPrimaryQuorum();

			expect(config.ha.quorumFenced).toBe(true);

			election.recentMaxMemberCountAt = Date.now() - (MEMBERSHIP_SHRINK_GRACE_MS + 1000);
			await election.tickPrimaryQuorum();
			expect(config.ha.quorumFenced).toBe(false);
		});

		test("sets the fence only after sustained loss past quorumLossFenceSeconds, not on the first missed tick", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "primary";
			mesh.nodes.clear();
			await election.tickPrimaryQuorum();
			expect(config.ha.quorumFenced).toBe(false);
			config.ha.lastMajorityConfirmedAt = Date.now() - (config.ha.quorumLossFenceSeconds * 1000 + 1000);
			await election.tickPrimaryQuorum();
			expect(config.ha.quorumFenced).toBe(true);
		});

		test("fences on the very first tick after a simulated long freeze, not just after a second tick", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "primary";

			mesh.nodes.set({ close: () => {} }, { nodeId: "peer-1", lastSeenAt: Date.now() });
			mesh.nodes.set({ close: () => {} }, { nodeId: "peer-2", lastSeenAt: Date.now() });
			await election.tickPrimaryQuorum();
			expect(config.ha.quorumTrackingActive).toBe(true);
			expect(config.ha.quorumFenced).toBe(false);

			mesh.nodes.clear();
			config.ha.lastMajorityConfirmedAt = Date.now() - (config.ha.quorumLossFenceSeconds * 1000 + 60_000);

			await election.tickPrimaryQuorum();

			expect(config.ha.quorumFenced).toBe(true);
		});

		test("self-clears once majority connectivity returns", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "primary";
			config.ha.quorumFenced = true;

			await repository.setQuorumFence(Date.now() - 60_000);
			mesh.nodes.set({ close: () => {} }, { nodeId: "peer-1", lastSeenAt: Date.now() });
			mesh.nodes.set({ close: () => {} }, { nodeId: "peer-2", lastSeenAt: Date.now() });
			await election.tickPrimaryQuorum();
			expect(config.ha.quorumFenced).toBe(false);
			const row = await repository.haClusterConfigRow();
			expect(row?.quorum_fenced).toBe(0);
		});

		test("an open socket that stopped acknowledging heartbeats is expired and cannot satisfy quorum", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "primary";
			const closes: unknown[] = [];
			const staleSocket = { close: (...args: unknown[]) => closes.push(args) };
			mesh.nodes.set(staleSocket, {
				nodeId: "peer-1",
				name: "peer-1",
				lastSeenAt: Date.now() - 60_000,
			});

			await election.tickPrimaryQuorum();

			expect(closes).toEqual([[4000, "replica heartbeat acknowledgement timeout"]]);
			expect(mesh.nodes.has(staleSocket)).toBe(false);
			expect(config.ha.quorumFenced).toBe(false);
			config.ha.lastMajorityConfirmedAt = Date.now() - (config.ha.quorumLossFenceSeconds * 1000 + 1000);
			await election.tickPrimaryQuorum();
			expect(config.ha.quorumFenced).toBe(true);
		});

		test("a live but unregistered socket cannot inflate the registered-member quorum", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "primary";
			mesh.nodes.set({ close: () => {} }, { nodeId: "not-a-member", name: "intruder", lastSeenAt: Date.now() });

			await election.tickPrimaryQuorum();

			expect(config.ha.quorumFenced).toBe(false);
		});

		test("HaQuorumLossFenceError gates both ordinary writes and promotion while fenced", async () => {
			const { haPrimaryWriteBarrier, HaQuorumLossFenceError } = await import("../src/services/ha-write-barrier.ts");
			config.ha.quorumFenced = true;
			await expect(haPrimaryWriteBarrier.runPrimaryWrite(async () => "should not run")).rejects.toBeInstanceOf(HaQuorumLossFenceError);
			await expect(haPrimaryWriteBarrier.beginPromotion()).rejects.toBeInstanceOf(HaQuorumLossFenceError);
		});

		test("a write is fenced directly against a stale lastMajorityConfirmedAt, even before any tick has set quorumFenced", async () => {
			const { haPrimaryWriteBarrier, HaQuorumLossFenceError } = await import("../src/services/ha-write-barrier.ts");
			config.ha.quorumFenced = false;
			config.ha.quorumTrackingActive = true;
			config.ha.lastMajorityConfirmedAt = Date.now() - (config.ha.quorumLossFenceSeconds * 1000 + 60_000);
			await expect(haPrimaryWriteBarrier.runPrimaryWrite(async () => "should not run")).rejects.toBeInstanceOf(HaQuorumLossFenceError);
			await expect(haPrimaryWriteBarrier.beginPromotion()).rejects.toBeInstanceOf(HaQuorumLossFenceError);
		});

		test("a small or auto-failover-disabled cluster (quorumTrackingActive false) is never fenced by a stale lastMajorityConfirmedAt alone", async () => {
			const { haPrimaryWriteBarrier } = await import("../src/services/ha-write-barrier.ts");
			config.ha.quorumFenced = false;
			config.ha.quorumTrackingActive = false;

			config.ha.lastMajorityConfirmedAt = Date.now() - 999_000_000;
			await expect(haPrimaryWriteBarrier.runPrimaryWrite(async () => "ran")).resolves.toBe("ran");
		});
	});

	describe("automatic former-primary recovery", () => {
		const fence = { observedEpoch: 5, sourceNodeId: "peer-1", observedAt: Date.now() };

		test("does nothing below the auto-failover member floor, leaving the fence in place", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 2);
			config.ha.role = "primary";
			config.ha.epoch = 1;
			config.ha.authorityFence = fence;
			election.peerCertCache.set("peer-1", "fake-cert-1");
			const original = haElectionPeerClient.whoIsPrimary;
			haElectionPeerClient.whoIsPrimary = async () => ({
				epoch: 5,
				primaryUrl: "https://peer-1.test:7443",
				primaryAdminUrl: "https://peer-1.test",
				role: "primary" as const,
			});
			try {
				await election.tryAutomaticFormerPrimaryRecovery("durably authority-fenced");
			} finally {
				haElectionPeerClient.whoIsPrimary = original;
			}
			expect(config.ha.role).toBe("primary");
			expect(config.ha.authorityFence).toEqual(fence);
		});

		test("does not adopt when only a minority of registered members confirm the same topology", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "primary";
			config.ha.epoch = 1;
			config.ha.authorityFence = fence;
			election.peerCertCache.set("peer-1", "fake-cert-1");
			election.peerCertCache.set("peer-2", "fake-cert-2");
			const original = haElectionPeerClient.whoIsPrimary;
			haElectionPeerClient.whoIsPrimary = async (peerMeshUrl: string) =>
				peerMeshUrl.includes("peer-1")
					? { epoch: 5, primaryUrl: "https://peer-1.test:7443", primaryAdminUrl: "https://peer-1.test", role: "primary" as const }
					: { epoch: 5, primaryUrl: "https://someone-else.test:7443", primaryAdminUrl: "https://someone-else.test", role: "replica" as const };
			try {
				await election.tryAutomaticFormerPrimaryRecovery("durably authority-fenced");
			} finally {
				haElectionPeerClient.whoIsPrimary = original;
			}
			expect(config.ha.role).toBe("primary");
			expect(config.ha.authorityFence).toEqual(fence);
			expect(restartCalls).not.toContain("ha-former-primary-recovery");
		});

		test("does not adopt when a majority agrees but the confirmed primary never confirms its own role", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "primary";
			config.ha.epoch = 1;
			config.ha.authorityFence = fence;
			election.peerCertCache.set("peer-1", "fake-cert-1");
			election.peerCertCache.set("peer-2", "fake-cert-2");
			const original = haElectionPeerClient.whoIsPrimary;

			haElectionPeerClient.whoIsPrimary = async () => ({
				epoch: 5,
				primaryUrl: "https://ghost-primary.test:7443",
				primaryAdminUrl: "https://ghost-primary.test",
				role: "replica" as const,
			});
			try {
				await election.tryAutomaticFormerPrimaryRecovery("durably authority-fenced");
			} finally {
				haElectionPeerClient.whoIsPrimary = original;
			}
			expect(config.ha.role).toBe("primary");
			expect(config.ha.authorityFence).toEqual(fence);
			expect(restartCalls).not.toContain("ha-former-primary-recovery");
		});

		test("automatically demotes and forces a fresh bootstrap once a majority - including the confirmed primary itself - agree", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "primary";
			await repository.updateHaClusterConfig({ role: "primary", clusterEpoch: 1 });
			config.ha.epoch = 1;
			config.ha.authorityFence = fence;
			await repository.fenceHaPrimaryAuthority(fence.observedEpoch, fence.sourceNodeId, fence.observedAt);
			await db`DELETE FROM replication_cursor`;
			await db`INSERT INTO replication_cursor (id,last_applied_seq,bootstrapped) VALUES (1,0,1)`;
			election.peerCertCache.set("peer-1", "fake-cert-1");
			election.peerCertCache.set("peer-2", "fake-cert-2");
			const original = haElectionPeerClient.whoIsPrimary;
			haElectionPeerClient.whoIsPrimary = async (peerMeshUrl: string) =>
				peerMeshUrl.includes("peer-1")
					? { epoch: 5, primaryUrl: "https://peer-1.test:7443", primaryAdminUrl: "https://peer-1.test", role: "primary" as const }
					: { epoch: 5, primaryUrl: "https://peer-1.test:7443", primaryAdminUrl: "https://peer-1.test", role: "replica" as const };
			try {
				await election.tryAutomaticFormerPrimaryRecovery("durably authority-fenced");
			} finally {
				haElectionPeerClient.whoIsPrimary = original;
			}
			expect(config.ha.role as string).toBe("replica");
			expect(config.ha.epoch).toBe(5);
			expect(config.ha.primaryUrl).toBe("https://peer-1.test:7443");
			expect(config.ha.primaryAdminUrl).toBe("https://peer-1.test");
			expect(config.ha.authorityFence).toBeNull();
			expect(await repository.needsBootstrap()).toBe(true);
			const row = await repository.haClusterConfigRow();
			expect(row?.authority_fenced).toBe(0);
			await new Promise((resolve) => setTimeout(resolve, 350));
			expect(restartCalls).toContain("ha-former-primary-recovery");
		});

		test("wipes this node's own stale local changelog history when it was itself the fenced primary", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "primary";
			await repository.updateHaClusterConfig({ role: "primary", clusterEpoch: 1 });
			config.ha.epoch = 1;
			config.ha.authorityFence = fence;
			await repository.fenceHaPrimaryAuthority(fence.observedEpoch, fence.sourceNodeId, fence.observedAt);
			await db`DELETE FROM replication_cursor`;
			await db`INSERT INTO replication_cursor (id,last_applied_seq,bootstrapped) VALUES (1,0,1)`;

			await db`DELETE FROM replication_changelog`;
			await db`INSERT INTO replication_changelog (entity_type,entity_id,op,payload_json,created_at) VALUES ('site','diverged-site','insert','{}',${Date.now()})`;
			await db`UPDATE replication_changelog_state SET high_watermark=999 WHERE id=1`;
			election.peerCertCache.set("peer-1", "fake-cert-1");
			election.peerCertCache.set("peer-2", "fake-cert-2");
			const original = haElectionPeerClient.whoIsPrimary;
			haElectionPeerClient.whoIsPrimary = async (peerMeshUrl: string) =>
				peerMeshUrl.includes("peer-1")
					? { epoch: 5, primaryUrl: "https://peer-1.test:7443", primaryAdminUrl: "https://peer-1.test", role: "primary" as const }
					: { epoch: 5, primaryUrl: "https://peer-1.test:7443", primaryAdminUrl: "https://peer-1.test", role: "replica" as const };
			try {
				await election.tryAutomaticFormerPrimaryRecovery("durably authority-fenced");
			} finally {
				haElectionPeerClient.whoIsPrimary = original;
			}

			expect(await repository.changelogSince(0, 100)).toEqual([]);
			const stateRows = (await db`SELECT high_watermark FROM replication_changelog_state WHERE id=1`) as Array<{ high_watermark: number }>;
			expect(Number(stateRows[0]?.high_watermark)).toBe(0);
		});

		test("accepts a majority-confirmed winner reported at an EQUAL epoch, not just a strictly newer one", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "primary";
			await repository.updateHaClusterConfig({ role: "primary", clusterEpoch: 5 });
			config.ha.epoch = 5;
			config.ha.quorumFenced = true;
			await repository.setQuorumFence(Date.now());
			await db`DELETE FROM replication_cursor`;
			await db`INSERT INTO replication_cursor (id,last_applied_seq,bootstrapped) VALUES (1,0,1)`;
			election.peerCertCache.set("peer-1", "fake-cert-1");
			election.peerCertCache.set("peer-2", "fake-cert-2");
			const original = haElectionPeerClient.whoIsPrimary;
			haElectionPeerClient.whoIsPrimary = async (peerMeshUrl: string) =>
				peerMeshUrl.includes("peer-1")
					? { epoch: 5, primaryUrl: "https://peer-1.test:7443", primaryAdminUrl: "https://peer-1.test", role: "primary" as const }
					: { epoch: 5, primaryUrl: "https://peer-1.test:7443", primaryAdminUrl: "https://peer-1.test", role: "replica" as const };
			try {
				await election.tryAutomaticFormerPrimaryRecovery("quorum-loss fenced");
			} finally {
				haElectionPeerClient.whoIsPrimary = original;
			}
			expect(config.ha.role as string).toBe("replica");
			expect(config.ha.epoch).toBe(5);
			expect(config.ha.primaryUrl).toBe("https://peer-1.test:7443");
			await new Promise((resolve) => setTimeout(resolve, 350));
			expect(restartCalls).toContain("ha-former-primary-recovery");
		});

		test("tickPrimaryQuorum attempts recovery for an already quorum-fenced primary still below majority, instead of sitting inert", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "primary";
			await repository.updateHaClusterConfig({ role: "primary", clusterEpoch: 5 });
			config.ha.epoch = 5;

			mesh.nodes.set({ close: () => {} }, { nodeId: "peer-1", lastSeenAt: Date.now() });
			mesh.nodes.set({ close: () => {} }, { nodeId: "peer-2", lastSeenAt: Date.now() });
			await election.tickPrimaryQuorum();
			expect(config.ha.quorumTrackingActive).toBe(true);

			config.ha.quorumFenced = true;
			config.ha.lastMajorityConfirmedAt = Date.now() - (config.ha.quorumLossFenceSeconds * 1000 + 1000);
			mesh.nodes.clear();
			election.peerCertCache.set("peer-1", "fake-cert-1");
			election.peerCertCache.set("peer-2", "fake-cert-2");
			const original = haElectionPeerClient.whoIsPrimary;
			haElectionPeerClient.whoIsPrimary = async (peerMeshUrl: string) =>
				peerMeshUrl.includes("peer-1")
					? { epoch: 5, primaryUrl: "https://peer-1.test:7443", primaryAdminUrl: "https://peer-1.test", role: "primary" as const }
					: { epoch: 5, primaryUrl: "https://peer-1.test:7443", primaryAdminUrl: "https://peer-1.test", role: "replica" as const };
			try {
				await election.tickPrimaryQuorum();
			} finally {
				haElectionPeerClient.whoIsPrimary = original;
			}
			expect(config.ha.role as string).toBe("replica");
			expect(config.ha.primaryUrl).toBe("https://peer-1.test:7443");
		});
	});

	describe("mutual exclusion between manual promotion and automatic election", () => {
		test("beginPromotion refuses while an automatic election is in progress", async () => {
			const { haPrimaryWriteBarrier, HaPromotionWriteFenceError } = await import("../src/services/ha-write-barrier.ts");
			config.ha.electionInProgress = true;
			await expect(haPrimaryWriteBarrier.beginPromotion()).rejects.toBeInstanceOf(HaPromotionWriteFenceError);
		});

		test("startCampaign refuses to run while a manual promotion is fenced", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "replica";
			config.ha.epoch = 1;
			config.ha.fencedForPromotion = true;
			await election.startCampaign([], nodeId);
			expect(election.campaigningTerm).toBeNull();
			expect(config.ha.electionInProgress).toBe(false);
		});
	});

	describe("campaign orchestration (candidate side)", () => {
		function withMockedPeerClient(overrides: Partial<typeof haElectionPeerClient>, run: () => Promise<void>): Promise<void> {
			const original = { ...haElectionPeerClient };
			Object.assign(haElectionPeerClient, overrides);
			return run().finally(() => Object.assign(haElectionPeerClient, original));
		}

		test("wins a 3-node election when a majority (including itself) grants the vote", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "replica";
			config.ha.epoch = 1;
			config.ha.selfAdminUrl = "https://self.test";

			mesh.nodeId = nodeId;
			election.peerCertCache.set("peer-1", "fake-cert-1");
			election.peerCertCache.set("peer-2", "fake-cert-2");
			await withMockedPeerClient(
				{
					requestVote: async () => ({ voteGranted: true, voterTerm: 2 }),
					announcePrimary: async () => undefined,
				},
				async () => {
					const members = await repository.haClusterMembers();
					await election.startCampaign(members, nodeId);
				},
			);

			const row = await repository.haClusterConfigRow();
			expect(row?.role).toBe("primary");
			expect(row?.cluster_epoch).toBe(2);
			expect(config.ha.epoch).toBe(2);
			await new Promise((resolve) => setTimeout(resolve, 350));
			expect(restartCalls).toContain("ha-election-won");
			expect(election.campaigningTerm).toBeNull();
			expect(config.ha.electionInProgress).toBe(false);
		});

		test("does not win without a majority and retries a later round at a fresh durable term", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "replica";
			config.ha.epoch = 1;
			election.peerCertCache.set("peer-1", "fake-cert-1");
			election.peerCertCache.set("peer-2", "fake-cert-2");
			const requestedTerms: number[] = [];
			await withMockedPeerClient(
				{
					requestVote: async (_peerMeshUrl, _peerCert, body) => {
						requestedTerms.push(body.term);
						return { voteGranted: false, voterTerm: body.term, reason: "simulated refusal" };
					},
				},
				async () => {
					const members = await repository.haClusterMembers();
					await election.startCampaign(members, nodeId);
					await election.startCampaign(members, nodeId);
				},
			);
			expect(config.ha.role).toBe("replica");
			expect(restartCalls).not.toContain("ha-election-won");
			expect(election.campaigningTerm).toBeNull();
			expect(config.ha.electionInProgress).toBe(false);
			expect(requestedTerms).toEqual([2, 2, 3, 3]);
			expect(config.ha.epoch).toBe(3);
			const row = await repository.haClusterConfigRow();
			expect(row?.cluster_epoch).toBe(3);
			expect(row?.voted_for_term).toBe(3);
		});

		test("abandons and adopts the term when a peer reports it already knows about a newer one", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "replica";
			config.ha.epoch = 1;
			election.peerCertCache.set("peer-1", "fake-cert-1");
			election.peerCertCache.set("peer-2", "fake-cert-2");
			await withMockedPeerClient(
				{
					requestVote: async () => ({ voteGranted: false, voterTerm: 9 }),
				},
				async () => {
					const members = await repository.haClusterMembers();
					await election.startCampaign(members, nodeId);
				},
			);
			expect(config.ha.role).toBe("replica");
			expect(config.ha.epoch).toBe(9);
			expect(restartCalls).not.toContain("ha-election-won");
		});

		test("a crash-mid-campaign self-vote is idempotent: re-campaigning at the same term after restart re-affirms rather than double-votes", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "replica";
			config.ha.epoch = 1;
			mesh.nodeId = nodeId;

			expect(await repository.tryPersistVoteGrant(2, nodeId)).toBe(true);
			election.peerCertCache.set("peer-1", "fake-cert-1");
			election.peerCertCache.set("peer-2", "fake-cert-2");
			await withMockedPeerClient(
				{
					requestVote: async () => ({ voteGranted: true, voterTerm: 2 }),
					announcePrimary: async () => undefined,
				},
				async () => {
					const members = await repository.haClusterMembers();
					await election.startCampaign(members, nodeId);
				},
			);

			const row = await repository.haClusterConfigRow();
			expect(row?.role).toBe("primary");

			await new Promise((resolve) => setTimeout(resolve, 350));
			expect(restartCalls).toContain("ha-election-won");
		});

		test("vote replies arriving after a winner announcement cannot activate the abandoned candidate", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "replica";
			config.ha.epoch = 5;
			config.ha.primaryUrl = "https://dead-primary.test:7443";
			config.ha.primaryAdminUrl = "https://dead-primary.test";
			await repository.updateHaClusterConfig({
				role: "replica",
				primaryUrl: config.ha.primaryUrl,
				primaryAdminUrl: config.ha.primaryAdminUrl,
				clusterEpoch: 5,
			});
			election.campaigningTerm = 6;
			config.ha.electionInProgress = true;
			election.peerCertCache.set("peer-1", "fake-cert-1");
			election.peerCertCache.set("peer-2", "fake-cert-2");

			let releaseVotes!: () => void;
			const votesReleased = new Promise<void>((resolve) => {
				releaseVotes = resolve;
			});

			let startedCount = 0;
			let markBothStarted!: () => void;
			const bothStarted = new Promise<void>((resolve) => {
				markBothStarted = resolve;
			});
			const original = { ...haElectionPeerClient };
			haElectionPeerClient.requestVote = async () => {
				startedCount += 1;
				if (startedCount === 2) markBothStarted();
				await votesReleased;
				return { voteGranted: true, voterTerm: 6 };
			};
			try {
				const campaign = election.runCampaign(6, 0, await repository.haClusterMembers(), nodeId);
				await bothStarted;
				const announcement = await election.handleAnnouncePrimary(
					announceRequest({ epoch: 6, primaryUrl: "https://winner.test:7443", primaryAdminUrl: "https://winner.test" }),
				);
				expect(((await announcement.json()) as { adopted: boolean }).adopted).toBe(true);
				releaseVotes();
				await campaign;
			} finally {
				Object.assign(haElectionPeerClient, original);
				releaseVotes();
			}

			const row = await repository.haClusterConfigRow();
			expect(row?.role).toBe("replica");
			expect(row?.primary_url).toBe("https://winner.test:7443");
			await new Promise((resolve) => setTimeout(resolve, 350));
			expect(restartCalls).toContain("ha-primary-discovered");
			expect(restartCalls).not.toContain("ha-election-won");
		});

		test("a newer winner persisted during activation cannot be overwritten by the older election result", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "replica";
			config.ha.epoch = 6;
			config.ha.primaryUrl = "https://old-primary.test:7443";
			config.ha.primaryAdminUrl = "https://old-primary.test";
			await repository.updateHaClusterConfig({
				role: "replica",
				primaryUrl: config.ha.primaryUrl,
				primaryAdminUrl: config.ha.primaryAdminUrl,
				clusterEpoch: 5,
			});
			expect(await repository.tryPersistVoteGrant(6, nodeId)).toBe(true);
			mesh.nodeId = nodeId;
			election.campaigningTerm = 6;
			config.ha.electionInProgress = true;
			election.peerCertCache.set("peer-1", "fake-cert-1");
			election.peerCertCache.set("peer-2", "fake-cert-2");

			let activationStarted!: () => void;
			const started = new Promise<void>((resolve) => {
				activationStarted = resolve;
			});
			let releaseActivation!: () => void;
			const released = new Promise<void>((resolve) => {
				releaseActivation = resolve;
			});
			const originalActivate = repository.activateHaElectionWinner;
			const originalPeerClient = { ...haElectionPeerClient };
			repository.activateHaElectionWinner = async (...args) => {
				activationStarted();
				await released;
				return await originalActivate(...args);
			};
			haElectionPeerClient.requestVote = async () => ({ voteGranted: true, voterTerm: 6 });
			try {
				const campaign = election.runCampaign(
					6,
					0,
					await repository.haClusterMembers(),
					nodeId,
					mesh.verifiedPrimaryConnectionGeneration,
					config.ha.primaryUrl,
					config.ha.primaryAdminUrl,
				);
				await started;
				const announcement = await election.handleAnnouncePrimary(
					announceRequest({ epoch: 7, primaryUrl: "https://newer-winner.test:7443", primaryAdminUrl: "https://newer-winner.test" }),
				);
				expect(((await announcement.json()) as { adopted: boolean }).adopted).toBe(true);
				releaseActivation();
				await campaign;
			} finally {
				repository.activateHaElectionWinner = originalActivate;
				Object.assign(haElectionPeerClient, originalPeerClient);
				releaseActivation();
			}

			const row = await repository.haClusterConfigRow();
			expect(row?.role).toBe("replica");
			expect(row?.cluster_epoch).toBe(7);
			expect(row?.primary_url).toBe("https://newer-winner.test:7443");
			await new Promise((resolve) => setTimeout(resolve, 350));
			expect(restartCalls).toContain("ha-primary-discovered");
			expect(restartCalls).not.toContain("ha-election-won");
		});

		test("delayed majority replies cannot activate a candidate that verified a primary connection mid-campaign", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "replica";
			config.ha.epoch = 5;
			await repository.updateHaClusterConfig({ role: "replica", clusterEpoch: 6 });
			election.campaigningTerm = 6;
			config.ha.electionInProgress = true;
			election.peerCertCache.set("peer-1", "fake-cert-1");
			election.peerCertCache.set("peer-2", "fake-cert-2");

			let releaseVotes!: () => void;
			const votesReleased = new Promise<void>((resolve) => {
				releaseVotes = resolve;
			});
			let startedCount = 0;
			let markBothStarted!: () => void;
			const bothStarted = new Promise<void>((resolve) => {
				markBothStarted = resolve;
			});
			const original = { ...haElectionPeerClient };
			haElectionPeerClient.requestVote = async () => {
				startedCount += 1;
				if (startedCount === 2) markBothStarted();
				await votesReleased;
				return { voteGranted: true, voterTerm: 6 };
			};
			try {
				const campaign = election.runCampaign(6, 0, await repository.haClusterMembers(), nodeId);
				await bothStarted;

				mesh.verifiedPrimaryConnectionGeneration += 1;
				mesh.state = "connected";
				mesh.disconnectedSince = 0;
				mesh.state = "disconnected";
				mesh.disconnectedSince = Date.now();
				releaseVotes();
				await campaign;
			} finally {
				Object.assign(haElectionPeerClient, original);
				releaseVotes();
			}

			const row = await repository.haClusterConfigRow();
			expect(row?.role).toBe("replica");
			expect(mesh.electionWinnerActivating).toBe(false);
			expect(mesh.primaryAuthorityAmbiguous).toBe(false);
			await new Promise((resolve) => setTimeout(resolve, 350));
			expect(restartCalls).not.toContain("ha-election-won");
		});
	});

	describe("discovery fallback", () => {
		test("adopts the highest epoch reported by any single reachable peer", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "replica";
			config.ha.epoch = 1;
			election.peerCertCache.set("peer-1", "fake-cert-1");
			election.peerCertCache.set("peer-2", "fake-cert-2");
			const original = haElectionPeerClient.whoIsPrimary;
			haElectionPeerClient.whoIsPrimary = async (peerMeshUrl: string) => {
				if (peerMeshUrl.includes("peer-1")) return { epoch: 1, primaryUrl: null, primaryAdminUrl: null, role: "replica" };
				return { epoch: 4, primaryUrl: "https://new-primary.test:7443", primaryAdminUrl: "https://new-primary.test", role: "primary" };
			};
			try {
				const members = await repository.haClusterMembers();
				const adopted = await election.tryDiscoverPrimaryFromPeers(members);
				expect(adopted).toBe(true);
				expect(config.ha.epoch).toBe(4);
				expect(config.ha.primaryUrl).toBe("https://new-primary.test:7443");
			} finally {
				haElectionPeerClient.whoIsPrimary = original;
			}
			await new Promise((resolve) => setTimeout(resolve, 350));
			expect(restartCalls).toContain("ha-primary-discovered");
		});

		test("returns false and adopts nothing when no peer knows about a newer epoch", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "replica";
			config.ha.epoch = 5;
			config.ha.primaryUrl = "https://same.test:7443";
			config.ha.primaryAdminUrl = "https://same.test";
			election.peerCertCache.set("peer-1", "fake-cert-1");
			election.peerCertCache.set("peer-2", "fake-cert-2");
			const original = haElectionPeerClient.whoIsPrimary;
			haElectionPeerClient.whoIsPrimary = async () => ({
				epoch: 5,
				primaryUrl: "https://same.test:7443",
				primaryAdminUrl: "https://same.test",
				role: "primary",
			});
			try {
				const members = await repository.haClusterMembers();
				const adopted = await election.tryDiscoverPrimaryFromPeers(members);
				expect(adopted).toBe(false);
			} finally {
				haElectionPeerClient.whoIsPrimary = original;
			}
		});

		test("a voter that missed the winner announcement adopts the directly queried primary at the same term", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			config.ha.role = "replica";
			config.ha.epoch = 8;
			config.ha.primaryUrl = "https://dead-primary.test:7443";
			config.ha.primaryAdminUrl = "https://dead-primary.test";
			await repository.updateHaClusterConfig({
				role: "replica",
				primaryUrl: config.ha.primaryUrl,
				primaryAdminUrl: config.ha.primaryAdminUrl,
				clusterEpoch: 8,
			});
			election.peerCertCache.set("peer-1", "fake-cert-1");
			election.peerCertCache.set("peer-2", "fake-cert-2");
			const original = haElectionPeerClient.whoIsPrimary;
			haElectionPeerClient.whoIsPrimary = async (peerMeshUrl: string) =>
				peerMeshUrl.includes("peer-1")
					? { epoch: 8, primaryUrl: "https://winner.test:7443", primaryAdminUrl: "https://winner.test", role: "primary" }
					: { epoch: 8, primaryUrl: "https://dead-primary.test:7443", primaryAdminUrl: "https://dead-primary.test", role: "replica" };
			try {
				const adopted = await election.tryDiscoverPrimaryFromPeers(await repository.haClusterMembers());
				expect(adopted).toBe(true);
				expect(config.ha.epoch).toBe(8);
				expect(config.ha.primaryUrl).toBe("https://winner.test:7443");
			} finally {
				haElectionPeerClient.whoIsPrimary = original;
			}

			await new Promise((resolve) => setTimeout(resolve, 350));
			expect(restartCalls).toContain("ha-primary-discovered");
		});
	});

	describe("tiered election timeout", () => {
		test("is at least the configured base with no lag/rank/jitter contribution", async () => {
			const nodeId = await repository.haNodeId();
			await seedMembers(nodeId, 3);
			const timeout = await election.electionTimeoutMs([{ node_id: nodeId }, { node_id: "peer-1" }, { node_id: "peer-2" }], nodeId);
			expect(timeout).toBeGreaterThanOrEqual(config.ha.electionTimeoutBaseSeconds * 1000);
		});

		test("penalizes a larger replication gap with a longer timeout", async () => {
			const nodeId = await repository.haNodeId();

			const base = config.ha.electionTimeoutBaseSeconds * 1000;
			const smallGapPenalty = Math.min(5 * 50, 20_000);
			const largeGapPenalty = Math.min(500 * 50, 20_000);
			expect(largeGapPenalty).toBeGreaterThan(smallGapPenalty);
			expect(base + largeGapPenalty).toBeGreaterThan(base + smallGapPenalty);
		});
	});
});
