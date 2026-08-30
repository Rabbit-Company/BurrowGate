import { config } from "../config.ts";
import { repository, type HaClusterMemberRecord } from "../db/repository.ts";
import { Logger } from "../logger.ts";
import { deriveMeshUrl } from "./ha-config-service.ts";
import { HA_REPLICA_LIVENESS_TIMEOUT_MS, haMeshService, notifyHaEvent, type HaRequestIdentity } from "./ha-mesh-service.ts";
import { processLifecycle } from "./process-lifecycle-service.ts";
import { HA_ELECTION_TICK_INTERVAL_MS, MEMBERSHIP_SHRINK_GRACE_MS } from "../ha-timing.ts";
import { isSecureHaUrl } from "../ha-url.ts";

const VOTE_REQUEST_FETCH_TIMEOUT_MS = 3_000;
const WHO_IS_PRIMARY_FETCH_TIMEOUT_MS = 3_000;
const PEER_CERT_FETCH_TIMEOUT_MS = 5_000;

interface VoteRequestBody {
	term: number;
	candidateId: string;
	candidateCursor: number;
	candidateAdminUrl: string;
}
interface VoteResponseBody {
	voteGranted: boolean;
	voterTerm: number;
	reason?: string;
}
interface WhoIsPrimaryResponseBody {
	epoch: number;
	primaryUrl: string | null;
	primaryAdminUrl: string | null;
	role?: "primary" | "replica";
}

interface AnnouncePrimaryBody {
	epoch: number;
	primaryNodeId: string;
	primaryUrl: string;
	primaryAdminUrl: string;
}

export const haElectionPeerClient = {
	async requestVote(peerMeshUrl: string, peerCert: string, body: VoteRequestBody): Promise<VoteResponseBody> {
		const response = await fetch(`${peerMeshUrl}/_ha/vote-request`, {
			method: "POST",
			headers: { authorization: `Bearer ${config.ha.sharedToken}`, "content-type": "application/json" },
			body: JSON.stringify(body),
			tls: { ca: peerCert, checkServerIdentity: () => undefined },
			signal: AbortSignal.timeout(VOTE_REQUEST_FETCH_TIMEOUT_MS),
		});
		if (!response.ok) throw new Error(`vote-request to ${peerMeshUrl} failed with status ${response.status}`);
		return (await response.json()) as VoteResponseBody;
	},
	async whoIsPrimary(peerMeshUrl: string, peerCert: string): Promise<WhoIsPrimaryResponseBody> {
		const response = await fetch(`${peerMeshUrl}/_ha/who-is-primary`, {
			headers: { authorization: `Bearer ${config.ha.sharedToken}` },
			tls: { ca: peerCert, checkServerIdentity: () => undefined },
			signal: AbortSignal.timeout(WHO_IS_PRIMARY_FETCH_TIMEOUT_MS),
		});
		if (!response.ok) throw new Error(`who-is-primary to ${peerMeshUrl} failed with status ${response.status}`);
		return (await response.json()) as WhoIsPrimaryResponseBody;
	},
	async announcePrimary(peerMeshUrl: string, peerCert: string, body: AnnouncePrimaryBody): Promise<void> {
		const response = await fetch(`${peerMeshUrl}/_ha/announce-primary`, {
			method: "POST",
			headers: { authorization: `Bearer ${config.ha.sharedToken}`, "content-type": "application/json" },
			body: JSON.stringify(body),
			tls: { ca: peerCert, checkServerIdentity: () => undefined },
			signal: AbortSignal.timeout(WHO_IS_PRIMARY_FETCH_TIMEOUT_MS),
		});
		if (!response.ok) throw new Error(`announce-primary to ${peerMeshUrl} failed with status ${response.status}`);
	},
};

class HaElectionService {
	private tickTimer: ReturnType<typeof setInterval> | null = null;
	private tickRunning = false;
	private stopped = false;

	private readonly peerCertCache = new Map<string, string>();

	private campaigningTerm: number | null = null;

	private recentMaxMemberCount = 0;
	private recentMaxMemberCountAt = 0;

	start(): void {
		if (!config.ha.enabled || this.tickTimer) return;
		this.stopped = false;
		this.tickTimer = setInterval(() => void this.tick(), HA_ELECTION_TICK_INTERVAL_MS);
		(this.tickTimer as unknown as { unref?: () => void }).unref?.();
	}

	stop(): void {
		this.stopped = true;
		if (this.tickTimer) clearInterval(this.tickTimer);
		this.tickTimer = null;
	}

	async handleHttpRequest(request: Request, identity?: HaRequestIdentity): Promise<Response> {
		const url = new URL(request.url);
		if (url.pathname === "/_ha/who-is-primary" && request.method === "GET") return await this.handleWhoIsPrimary();
		if (url.pathname === "/_ha/vote-request" && request.method === "POST") return await this.handleVoteRequest(request, identity?.nodeId);
		if (url.pathname === "/_ha/announce-primary" && request.method === "POST") return await this.handleAnnouncePrimary(request, identity?.nodeId);
		return new Response("Not found", { status: 404 });
	}

	private async handleAnnouncePrimary(request: Request, authenticatedNodeId?: string): Promise<Response> {
		let body: Partial<AnnouncePrimaryBody>;
		try {
			body = (await request.json()) as Partial<AnnouncePrimaryBody>;
		} catch {
			return new Response("Malformed announce-primary body", { status: 400 });
		}

		if (
			authenticatedNodeId &&
			(typeof body.primaryNodeId !== "string" || !body.primaryNodeId || body.primaryNodeId.length > 64 || body.primaryNodeId !== authenticatedNodeId)
		) {
			return new Response("The announced primary identity does not match the authenticated HA member", { status: 403 });
		}
		if (
			!Number.isSafeInteger(body.epoch) ||
			typeof body.primaryUrl !== "string" ||
			!body.primaryUrl ||
			typeof body.primaryAdminUrl !== "string" ||
			!body.primaryAdminUrl
		) {
			return new Response("Malformed announce-primary body", { status: 400 });
		}
		let primaryUrl: URL;
		let primaryAdminUrl: URL;
		try {
			primaryUrl = new URL(body.primaryUrl!);
			primaryAdminUrl = new URL(body.primaryAdminUrl!);
		} catch {
			return new Response("Malformed announce-primary body", { status: 400 });
		}
		if (!isSecureHaUrl(primaryUrl.href) || !isSecureHaUrl(primaryAdminUrl.href)) {
			return new Response("Malformed announce-primary body", { status: 400 });
		}
		if (body.epoch! < config.ha.epoch) return Response.json({ ok: true, adopted: false });
		const alreadyAdopted =
			config.ha.role === "replica" &&
			body.epoch === config.ha.epoch &&
			body.primaryUrl === config.ha.primaryUrl &&
			body.primaryAdminUrl === config.ha.primaryAdminUrl;
		if (alreadyAdopted) return Response.json({ ok: true, adopted: false });

		this.abandonCampaign();
		const adopted = await haMeshService.adoptDiscoveredPrimary(
			body.primaryUrl,
			body.primaryAdminUrl,
			body.epoch!,
			"was directly notified of a new primary after an automatic failover election",
		);
		return Response.json({ ok: true, adopted });
	}

	private async handleWhoIsPrimary(): Promise<Response> {
		if (config.ha.role === "primary" && !config.ha.quorumFenced && !config.ha.authorityFence) {
			const primaryUrl = config.ha.selfAdminUrl ? deriveMeshUrl(config.ha.selfAdminUrl, config.ha.port) : null;
			return Response.json({ epoch: config.ha.epoch, primaryUrl, primaryAdminUrl: config.ha.selfAdminUrl, role: "primary" } satisfies WhoIsPrimaryResponseBody);
		}
		return Response.json({
			epoch: config.ha.epoch,
			primaryUrl: config.ha.primaryUrl,
			primaryAdminUrl: config.ha.primaryAdminUrl,
			role: "replica",
		} satisfies WhoIsPrimaryResponseBody);
	}

	private rejectVote(reason: string): Response {
		return Response.json({ voteGranted: false, voterTerm: config.ha.epoch, reason } satisfies VoteResponseBody);
	}

	private async handleVoteRequest(request: Request, authenticatedNodeId?: string): Promise<Response> {
		let body: Partial<VoteRequestBody>;
		try {
			body = (await request.json()) as Partial<VoteRequestBody>;
		} catch {
			return this.rejectVote("malformed vote-request body");
		}
		if (
			!Number.isSafeInteger(body.term) ||
			body.term! < 0 ||
			typeof body.candidateId !== "string" ||
			!body.candidateId ||
			body.candidateId.length > 64 ||
			!Number.isSafeInteger(body.candidateCursor) ||
			body.candidateCursor! < 0 ||
			typeof body.candidateAdminUrl !== "string" ||
			!isSecureHaUrl(body.candidateAdminUrl)
		) {
			return this.rejectVote("malformed vote-request body");
		}
		const term = body.term!;
		const candidateId = body.candidateId!;
		const candidateCursor = body.candidateCursor!;
		if (authenticatedNodeId && candidateId !== authenticatedNodeId) {
			return this.rejectVote("candidate identity does not match the authenticated HA member");
		}

		if (!config.ha.autoFailoverEnabled) return this.rejectVote("automatic failover is disabled on this node");

		const members = await repository.haClusterMembers();
		if (members.length < config.ha.autoFailoverMinMembers) {
			return this.rejectVote(
				`this cluster has only ${members.length} registered member(s), below the ${config.ha.autoFailoverMinMembers}-member floor for automatic failover`,
			);
		}

		if (term < config.ha.epoch) return this.rejectVote(`term ${term} is older than this node's current epoch ${config.ha.epoch}`);

		if (config.ha.role !== "primary" && haMeshService.disconnectedDurationMs() === null) {
			return this.rejectVote("this replica still has a verified primary connection and cannot vote in an election");
		}

		if (config.ha.role === "primary") {
			config.ha.quorumFenced = true;
			let persistedTerm: number | null;
			try {
				persistedTerm = await repository.fenceHaPrimaryForElectionTerm(term, Date.now());
			} catch (error) {
				Logger.error("[BurrowGate] HA: could not durably fence this primary for an election request; keeping the live process fenced", {
					error,
					term,
					candidateId,
				});
				return this.rejectVote("could not durably fence this primary for the proposed election term");
			}
			if (persistedTerm === null) return this.rejectVote("this node is no longer the active primary");
			config.ha.epoch = Math.max(config.ha.epoch, persistedTerm);
			await haMeshService
				.broadcastPrimaryFenceState()
				.catch((error) =>
					Logger.warn("[BurrowGate] HA: failed to broadcast the temporary election fence; replicas will receive it on the next heartbeat", { error }),
				);
			return this.rejectVote("an active primary does not grant election votes");
		} else {
			let persistedTerm: number | null;
			try {
				persistedTerm = await repository.adoptHaReplicaElectionTerm(term);
			} catch (error) {
				Logger.error("[BurrowGate] HA: could not durably adopt the proposed election term; refusing the vote", { error, term, candidateId });
				return this.rejectVote("could not durably adopt the proposed election term");
			}
			if (persistedTerm === null) return this.rejectVote("this node is no longer a replica eligible to vote");
			config.ha.epoch = Math.max(config.ha.epoch, persistedTerm);
			if (term < config.ha.epoch) return this.rejectVote(`term ${term} is older than this node's current epoch ${config.ha.epoch}`);
		}

		const ownCursor = await haMeshService.currentReplicationCursor();
		if (candidateCursor < ownCursor) {
			return this.rejectVote(`candidate's cursor ${candidateCursor} is behind this node's own cursor ${ownCursor}`);
		}

		const granted = await repository.tryPersistVoteGrant(term, candidateId);
		if (!granted) return this.rejectVote("already voted for a different candidate in this term");
		return Response.json({ voteGranted: true, voterTerm: term } satisfies VoteResponseBody);
	}

	private async resolvePeerCertificate(member: HaClusterMemberRecord): Promise<string> {
		const cached = this.peerCertCache.get(member.node_id);
		if (cached) return cached;
		if (!member.admin_url) throw new Error(`peer ${member.node_id} has not announced a reachable admin URL`);
		if (!isSecureHaUrl(member.admin_url)) throw new Error(`peer ${member.node_id} has an insecure or malformed admin URL`);
		const url = new URL("/_burrowgate/api/admin/ha/certificate", member.admin_url);
		const response = await fetch(url, {
			headers: { authorization: `Bearer ${config.ha.sharedToken}` },
			signal: AbortSignal.timeout(PEER_CERT_FETCH_TIMEOUT_MS),
		});
		if (!response.ok) throw new Error(`failed to fetch the HA certificate for peer ${member.node_id} (status ${response.status})`);
		const body = (await response.json()) as { cert?: string };
		if (!body.cert) throw new Error(`peer ${member.node_id} returned an empty HA certificate`);
		this.peerCertCache.set(member.node_id, body.cert);
		return body.cert;
	}

	private async tick(): Promise<void> {
		if (this.stopped || !config.ha.enabled || this.tickRunning) return;
		this.tickRunning = true;
		try {
			if (config.ha.role === "primary") await this.tickPrimaryQuorum();
			else await this.tickReplicaElection();
		} catch (error) {
			Logger.error("[BurrowGate] HA: election service tick failed", { error });
		} finally {
			this.tickRunning = false;
		}
	}

	private async tickPrimaryQuorum(): Promise<void> {
		if (!config.ha.autoFailoverEnabled) {
			config.ha.quorumTrackingActive = false;
			return await this.clearQuorumLossIfFenced();
		}

		if (config.ha.authorityFence) {
			config.ha.quorumTrackingActive = false;
			return await this.tryAutomaticFormerPrimaryRecovery("durably authority-fenced");
		}
		if (config.ha.fencedForPromotion || config.ha.electionInProgress) {
			config.ha.quorumTrackingActive = false;
			return;
		}
		const members = await repository.haClusterMembers();

		const effectiveMemberCount = this.trackedMemberCount(members.length);
		if (effectiveMemberCount < config.ha.autoFailoverMinMembers) {
			config.ha.quorumTrackingActive = false;
			return await this.clearQuorumLossIfFenced();
		}

		if (!config.ha.quorumTrackingActive) config.ha.lastMajorityConfirmedAt = Date.now();
		config.ha.quorumTrackingActive = true;

		const majority = Math.floor(effectiveMemberCount / 2) + 1;
		const registeredNodeIds = new Set(members.map((member) => member.node_id));
		const ownCount = 1 + haMeshService.connectedReplicaCount(registeredNodeIds);
		if (ownCount >= majority) {
			config.ha.lastMajorityConfirmedAt = Date.now();

			if (config.ha.quorumFenced) {
				const persisted = await repository.haClusterConfigRow();
				const fencedAt = persisted?.quorum_fenced_at;
				if (fencedAt !== null && fencedAt !== undefined && Date.now() - Number(fencedAt) < HA_REPLICA_LIVENESS_TIMEOUT_MS) return;
			}
			return await this.clearQuorumLossIfFenced();
		}

		if (Date.now() - config.ha.lastMajorityConfirmedAt < config.ha.quorumLossFenceSeconds * 1000) return;
		if (config.ha.quorumFenced) {
			return await this.tryAutomaticFormerPrimaryRecovery("quorum-loss fenced");
		}
		config.ha.quorumFenced = true;
		await repository.setQuorumFence(Date.now());
		Logger.error("[BurrowGate] HA: lost contact with a majority of registered cluster members - self-fencing until quorum returns", {
			total: members.length,
			effectiveTotal: effectiveMemberCount,
			ownCount,
			majority,
			lastMajorityConfirmedAt: config.ha.lastMajorityConfirmedAt,
		});
		notifyHaEvent("ha_node_down", "critical", "This primary lost contact with a majority of the cluster and is self-fencing until quorum returns", "primary");
	}

	private async clearQuorumLossIfFenced(): Promise<void> {
		if (!config.ha.quorumFenced) return;
		config.ha.quorumFenced = false;
		await repository.clearQuorumFence();
		await haMeshService
			.broadcastPrimaryFenceState()
			.catch((error) =>
				Logger.warn("[BurrowGate] HA: failed to broadcast the cleared quorum/election fence; replicas will recover on the next heartbeat", { error }),
			);
		Logger.warn("[BurrowGate] HA: cleared this primary's quorum-loss fence");
		notifyHaEvent("ha_node_up", "info", "This primary regained majority cluster connectivity and cleared its quorum-loss fence", "primary");
	}

	private trackedMemberCount(currentCount: number): number {
		const now = Date.now();
		if (currentCount >= this.recentMaxMemberCount || now - this.recentMaxMemberCountAt >= MEMBERSHIP_SHRINK_GRACE_MS) {
			this.recentMaxMemberCount = currentCount;
			this.recentMaxMemberCountAt = now;
			return currentCount;
		}
		return this.recentMaxMemberCount;
	}

	private async tryAutomaticFormerPrimaryRecovery(reason: string): Promise<void> {
		const members = await repository.haClusterMembers();
		if (members.length < config.ha.autoFailoverMinMembers) return;
		const nodeId = await repository.haNodeId();
		const peers = members.filter((member) => member.node_id !== nodeId && member.admin_url);
		const majority = Math.floor(members.length / 2) + 1;

		const results = await Promise.allSettled(
			peers.map(async (peer) => {
				const cert = await this.resolvePeerCertificate(peer);
				const meshUrl = deriveMeshUrl(peer.admin_url!, config.ha.port);
				const response = await haElectionPeerClient.whoIsPrimary(meshUrl, cert);
				return { peer, response };
			}),
		);

		interface Candidate {
			epoch: number;
			primaryUrl: string;
			primaryAdminUrl: string;
			confirmers: Set<string>;
			primarySelfConfirmed: boolean;
		}
		const candidates = new Map<string, Candidate>();
		for (const result of results) {
			if (result.status !== "fulfilled") continue;
			const { peer, response } = result.value;
			if (!Number.isSafeInteger(response.epoch) || response.epoch < config.ha.epoch) continue;
			if (!response.primaryUrl || !response.primaryAdminUrl) continue;
			if (!isSecureHaUrl(response.primaryUrl) || !isSecureHaUrl(response.primaryAdminUrl)) continue;
			const key = JSON.stringify([response.epoch, response.primaryUrl, response.primaryAdminUrl]);
			let candidate = candidates.get(key);
			if (!candidate) {
				candidate = {
					epoch: response.epoch,
					primaryUrl: response.primaryUrl,
					primaryAdminUrl: response.primaryAdminUrl,
					confirmers: new Set(),
					primarySelfConfirmed: false,
				};
				candidates.set(key, candidate);
			}
			candidate.confirmers.add(peer.node_id);

			if (response.role === "primary" && response.primaryAdminUrl === peer.admin_url) candidate.primarySelfConfirmed = true;
		}

		let winner: Candidate | null = null;
		for (const candidate of candidates.values()) {
			if (candidate.confirmers.size < majority) continue;
			if (!candidate.primarySelfConfirmed) continue;
			if (!winner || candidate.epoch > winner.epoch) winner = candidate;
		}
		if (!winner) return;

		Logger.warn(
			`[BurrowGate] HA: a majority of registered members, including the primary itself, confirmed a newer primary while this node was ${reason} - automatically demoting to a replica of the confirmed primary`,
			{ ownEpoch: config.ha.epoch, confirmedEpoch: winner.epoch, confirmedPrimaryUrl: winner.primaryUrl, confirmers: winner.confirmers.size, majority },
		);
		notifyHaEvent(
			"ha_node_up",
			"critical",
			`This node was a stale primary and automatically recovered: demoted to a replica of the majority-confirmed primary (epoch ${winner.epoch})`,
			"primary",
		);
		await haMeshService.adoptDiscoveredPrimary(
			winner.primaryUrl,
			winner.primaryAdminUrl,
			winner.epoch,
			`automatically recovered from being ${reason} after majority confirmation`,
			"ha-former-primary-recovery",
		);
	}

	private async tickReplicaElection(): Promise<void> {
		if (this.campaigningTerm !== null) return;
		const disconnectedMs = haMeshService.disconnectedDurationMs();
		if (disconnectedMs === null) return;

		const members = await repository.haClusterMembers();
		if (members.length < config.ha.autoFailoverMinMembers) return;

		if (await this.tryDiscoverPrimaryFromPeers(members)) return;

		if (!config.ha.autoFailoverEnabled) return;
		const nodeId = await repository.haNodeId();
		const timeoutMs = await this.electionTimeoutMs(members, nodeId);
		if (disconnectedMs < timeoutMs) return;
		await this.startCampaign(members, nodeId);
	}

	private async electionTimeoutMs(members: HaClusterMemberRecord[], nodeId: string): Promise<number> {
		const { cursor, lastHeartbeatLatestSeq } = haMeshService.replicaConnectivitySnapshot();
		const gap = Math.max(0, lastHeartbeatLatestSeq - cursor);
		const lagPenaltyMs = Math.min(gap * 50, 20_000);
		const sortedIds = members.map((member) => member.node_id).sort();
		const rank = Math.max(0, sortedIds.indexOf(nodeId));
		const rankOffsetMs = rank * 500;
		const jitterMs = Math.random() * config.ha.electionTimeoutJitterMs;
		return config.ha.electionTimeoutBaseSeconds * 1000 + lagPenaltyMs + rankOffsetMs + jitterMs;
	}

	private async tryDiscoverPrimaryFromPeers(members: HaClusterMemberRecord[]): Promise<boolean> {
		const nodeId = await repository.haNodeId();
		for (const peer of members) {
			if (peer.node_id === nodeId || !peer.admin_url) continue;
			try {
				const cert = await this.resolvePeerCertificate(peer);
				const meshUrl = deriveMeshUrl(peer.admin_url, config.ha.port);
				const response = await haElectionPeerClient.whoIsPrimary(meshUrl, cert);
				const newerTerm = response.epoch > config.ha.epoch;
				const equalTermPrimaryWithDifferentTopology =
					response.epoch === config.ha.epoch &&
					response.role === "primary" &&
					(response.primaryUrl !== config.ha.primaryUrl || response.primaryAdminUrl !== config.ha.primaryAdminUrl);
				if ((newerTerm || equalTermPrimaryWithDifferentTopology) && response.primaryUrl && response.primaryAdminUrl) {
					this.abandonCampaign();
					const adopted = await haMeshService.adoptDiscoveredPrimary(
						response.primaryUrl,
						response.primaryAdminUrl,
						response.epoch,
						`learned of a primary from peer ${peer.node_id} via discovery polling`,
					);
					if (adopted) return true;
				}
			} catch (error) {
				Logger.warn("[BurrowGate] HA: discovery-fallback query to a peer failed, will retry on the next tick", { error, peerNodeId: peer.node_id });
			}
		}
		return false;
	}

	private abandonCampaign(): void {
		this.campaigningTerm = null;
		config.ha.electionInProgress = false;
	}

	private async startCampaign(members: HaClusterMemberRecord[], nodeId: string): Promise<void> {
		if (config.ha.fencedForPromotion) return;
		if (haMeshService.disconnectedDurationMs() === null) return;
		const term = config.ha.epoch + 1;
		const connectivityGeneration = haMeshService.electionConnectivityGeneration();
		const expectedPrimaryUrl = config.ha.primaryUrl;
		const expectedPrimaryAdminUrl = config.ha.primaryAdminUrl;

		config.ha.electionInProgress = true;
		this.campaigningTerm = term;

		try {
			const ownCursor = await haMeshService.currentReplicationCursor();
			if (this.campaigningTerm !== term || !config.ha.electionInProgress || haMeshService.disconnectedDurationMs() === null) return;
			if (!(await repository.tryPersistVoteGrant(term, nodeId))) return;
			if (this.campaigningTerm !== term || !config.ha.electionInProgress || haMeshService.disconnectedDurationMs() === null) return;

			config.ha.epoch = Math.max(config.ha.epoch, term);
			Logger.warn("[BurrowGate] HA: lost contact with the primary past this node's election timeout - campaigning for automatic failover", {
				term,
				ownCursor,
				memberCount: members.length,
			});
			await this.runCampaign(term, ownCursor, members, nodeId, connectivityGeneration, expectedPrimaryUrl, expectedPrimaryAdminUrl);
		} finally {
			this.abandonCampaign();
		}
	}

	private async runCampaign(
		term: number,
		ownCursor: number,
		members: HaClusterMemberRecord[],
		nodeId: string,
		connectivityGeneration = haMeshService.electionConnectivityGeneration(),
		expectedPrimaryUrl = config.ha.primaryUrl,
		expectedPrimaryAdminUrl = config.ha.primaryAdminUrl,
	): Promise<void> {
		const majority = Math.floor(members.length / 2) + 1;
		const grantedBy = new Set<string>([nodeId]);
		const peers = members.filter((member) => member.node_id !== nodeId);
		const results = await Promise.allSettled(
			peers.map(async (peer) => {
				const cert = await this.resolvePeerCertificate(peer);
				const meshUrl = deriveMeshUrl(peer.admin_url!, config.ha.port);
				const response = await haElectionPeerClient.requestVote(meshUrl, cert, {
					term,
					candidateId: nodeId,
					candidateCursor: ownCursor,
					candidateAdminUrl: config.ha.selfAdminUrl ?? "",
				});
				return { peer, response };
			}),
		);
		for (const result of results) {
			if (result.status !== "fulfilled") continue;
			const { peer, response } = result.value;
			if (response.voterTerm > term) {
				config.ha.epoch = Math.max(config.ha.epoch, response.voterTerm);
				await repository
					.adoptHaReplicaElectionTerm(response.voterTerm)
					.catch((error) =>
						Logger.error("[BurrowGate] HA: failed to durably adopt a newer election term reported by a peer", { error, term: response.voterTerm }),
					);
				return;
			}
			if (response.voteGranted) grantedBy.add(peer.node_id);
		}
		if (grantedBy.size < majority) {
			Logger.warn("[BurrowGate] HA: automatic failover election did not reach a majority, will retry with a fresh term if still disconnected", {
				term,
				grantedBy: grantedBy.size,
				majority,
			});
			notifyHaEvent("ha_node_down", "warning", "An automatic failover election did not reach a majority and was abandoned", "replica");
			return;
		}

		if (this.campaigningTerm !== term || !config.ha.electionInProgress) return;
		if (!haMeshService.beginElectionWinnerActivation(connectivityGeneration)) {
			Logger.warn(
				"[BurrowGate] HA: election reached a majority but this node reconnected to a verified primary before activation; abandoning the stale result",
				{ term },
			);
			return;
		}
		let activated = false;
		try {
			activated = await this.winElection(term, members, nodeId, expectedPrimaryUrl, expectedPrimaryAdminUrl);
		} finally {
			haMeshService.finishElectionWinnerActivation(activated);
		}
	}

	private async winElection(
		term: number,
		members: HaClusterMemberRecord[],
		nodeId: string,
		expectedPrimaryUrl: string | null,
		expectedPrimaryAdminUrl: string | null,
	): Promise<boolean> {
		Logger.warn("[BurrowGate] HA: won an automatic failover election, activating as primary", { term, memberCount: members.length });
		const persisted = await haMeshService.activateElectionWinner(nodeId, term, expectedPrimaryUrl, expectedPrimaryAdminUrl);
		if (!persisted) {
			Logger.error("[BurrowGate] HA: won an automatic failover election but durable activation was rejected or could not be persisted - remaining a replica");
			return false;
		}
		notifyHaEvent("ha_node_up", "critical", `This node won an automatic failover election and is becoming the new primary (term ${term})`, "replica");

		await this.notifyPeersOfNewPrimary(members, nodeId, term);
		setTimeout(() => void processLifecycle.gracefulRestart("ha-election-won"), 300);
		return true;
	}

	private async notifyPeersOfNewPrimary(members: HaClusterMemberRecord[], newPrimaryNodeId: string, newEpoch: number): Promise<void> {
		const newPrimaryAdminUrl = config.ha.selfAdminUrl ?? "";
		if (!newPrimaryAdminUrl) return;
		const newPrimaryUrl = deriveMeshUrl(newPrimaryAdminUrl, config.ha.port);
		await Promise.allSettled(
			members
				.filter((member) => member.node_id !== newPrimaryNodeId && member.admin_url)
				.map(async (peer) => {
					try {
						const cert = await this.resolvePeerCertificate(peer);
						const meshUrl = deriveMeshUrl(peer.admin_url!, config.ha.port);
						await haElectionPeerClient.announcePrimary(meshUrl, cert, {
							epoch: newEpoch,
							primaryNodeId: newPrimaryNodeId,
							primaryUrl: newPrimaryUrl,
							primaryAdminUrl: newPrimaryAdminUrl,
						});
					} catch (error) {
						Logger.warn("[BurrowGate] HA: failed to directly notify a peer about the new primary after an election, it will discover it on its own", {
							error,
							peerNodeId: peer.node_id,
						});
					}
				}),
		);
	}
}

export const haElectionService = new HaElectionService();
