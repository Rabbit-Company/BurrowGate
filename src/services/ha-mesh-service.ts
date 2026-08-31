import type { Server, ServerWebSocket } from "bun";
import { X509Certificate } from "node:crypto";
import { config } from "../config.ts";
import {
	isTransientDatabaseError,
	repository,
	type HaClusterConfigInsert,
	type HaClusterMemberRecord,
	type HaPromotionIntentRecord,
	type MultiWriterEntityType,
	type ReplicatedEntityType,
	type ReplicationChangelogRow,
	type ReplicationSnapshotRow,
} from "../db/repository.ts";
import { Logger } from "../logger.ts";
import { deriveMeshUrl } from "./ha-config-service.ts";
import { deletePinnedHaCertificate, haTlsCertificate, pinPrimaryHaCertificate, readPinnedHaCertificate } from "./ha-tls-service.ts";
import { invalidateAllNetworkPolicy } from "./ip-rule-service.ts";
import { loadBalancer } from "./load-balancer-service.ts";
import { notificationService } from "./notification-service.ts";
import { originHealthManager } from "./origin-health-service.ts";
import { processLifecycle } from "./process-lifecycle-service.ts";
import { invalidateAllRouteNetworkPolicy } from "./route-ip-rule-service.ts";
import { invalidateAllRoutePolicyCache } from "./route-policy-service.ts";
import {
	decryptSecret,
	encryptSecret,
	hasOperatorConfiguredMasterKey,
	installMasterKeyFromPrimary,
	masterSecretForReplication,
} from "./secret-encryption-service.ts";
import { staticAssetCache } from "./static-cache-service.ts";
import { invalidateAllStreamNetworkPolicy } from "./stream-ip-rule-service.ts";
import { streamHealthManager } from "./stream-health-service.ts";
import { streamProxyManager } from "./stream-proxy-service.ts";
import { requestTlsReload } from "./tls-listener-service.ts";
import { HaPrimaryAuthorityFenceError, HaPromotionWriteFenceError, HaQuorumLossFenceError, haPrimaryWriteBarrier } from "./ha-write-barrier.ts";
import { APP_VERSION } from "../ui/layout.ts";
import { randomToken, sha256Hex } from "../utils/crypto.ts";
import {
	HA_FORGET_MIN_OFFLINE_FLOOR_MS,
	HA_FORGET_MIN_OFFLINE_RECONNECT_MULTIPLIER,
	HA_HEARTBEAT_INTERVAL_MS,
	HA_MAJORITY_DURABILITY_POLL_MS,
	HA_MAJORITY_DURABILITY_TIMEOUT_MS,
	HA_REPLICA_LIVENESS_TIMEOUT_MS,
	MEMBERSHIP_SHRINK_GRACE_MS,
} from "../ha-timing.ts";
import { isSecureHaUrl } from "../ha-url.ts";

export { HA_REPLICA_LIVENESS_TIMEOUT_MS } from "../ha-timing.ts";

const MASTER_KEY_CHECK_PLAINTEXT = "burrowgate-ha-key-check";
const BROADCAST_INTERVAL_MS = 500;

const RELAY_DRAIN_INTERVAL_MS = 500;
const RELAY_ACK_TIMEOUT_MS = 5_000;
const RELAY_PUBLICATION_TIMEOUT_MS = 10_000;

const PREPARE_PROMOTE_ACK_TIMEOUT_MS = 12_000;
const PROMOTION_FENCE_ACK_TIMEOUT_MS = 12_000;
const PROMOTE_APPLIED_ACK_TIMEOUT_MS = 12_000;

const MEMBERSHIP_ACTIVATION_DURABILITY_TIMEOUT_MS = 12_000;

const PREPARE_PROMOTE_DRAIN_TIMEOUT_MS = 8_000;

const HA_FETCH_TIMEOUT_MS = 30_000;

export const APPLY_FAILURE_REBOOTSTRAP_THRESHOLD = 3;

export const RUNTIME_CONVERGENCE_RESTART_THRESHOLD = 3;

const PROMOTE_PERSIST_MAX_ATTEMPTS = 3;
const PROMOTE_PERSIST_RETRY_DELAY_MS = 500;
const MULTI_WRITER_ENTITY_TYPES = new Set<MultiWriterEntityType>([
	"admin_session",
	"access_session",
	"ip_rule",
	"country_rule",
	"asn_rule",
	"stream_ip_rule",
	"admin_user",
	"access_user",
	"admin_recovery_code",
	"admin_webauthn_credential",
	"access_webauthn_credential",
	"site_access_user",
	"admin_site_permission",
	"admin_stream_permission",
]);

interface HelloMessage {
	type: "hello";
	keyCheck: string;
	epoch: number;
	version: string;

	primaryFenced?: boolean;
}

interface RequestMasterKeyMessage {
	type: "request_master_key";
}

interface MasterKeyMessage {
	type: "master_key";
	key: string;
}
interface ChangeMessage {
	type: "change";
	row: ReplicationChangelogRow;
}
interface HeartbeatMessage {
	type: "heartbeat";
	latestSeq: number;
	primaryFenced?: boolean;

	promotionId?: string;
}
interface PromotionFenceAckMessage {
	type: "promotion_fence_ack";
	promotionId: string;
}

interface RelayMessage {
	type: "relay";
	relayId: number;
	entityType: MultiWriterEntityType;
	entityId: string;
	op: "insert" | "update" | "delete";
	payloadJson: string | null;
}

interface RelayAckMessage {
	type: "relay_ack";
	relayId: number;
}

interface RelayRejectMessage {
	type: "relay_reject";
	relayId: number;
	reason: string;
}

interface AnnounceMessage {
	type: "announce";
	nodeId: string;
	name: string;
	version: string;
	adminUrl: string;
	epoch: number;
}

interface PromoteMessage {
	type: "promote";
	promotionId: string;
	newPrimaryNodeId: string;
	newPrimaryUrl: string;
	newPrimaryAdminUrl: string;
	newEpoch: number;
}

interface PrimaryRedirectMessage {
	type: "primary_redirect";
	primaryUrl: string;
	primaryAdminUrl: string;
	epoch: number;
}

interface PromoteAppliedAckMessage {
	type: "promote_applied_ack";
	promotionId: string;
	success: boolean;
	reason?: string;
}

interface CursorMessage {
	type: "cursor";
	seq: number;
}

interface PreparePromoteMessage {
	type: "prepare_promote";
	barrierSeq: number;

	promotionId: string;
}

interface PreparePromoteAckMessage {
	type: "prepare_promote_ack";
	cursor: number;
	promotionId: string;
}
type StreamMessage =
	| HelloMessage
	| RequestMasterKeyMessage
	| MasterKeyMessage
	| ChangeMessage
	| HeartbeatMessage
	| PromotionFenceAckMessage
	| RelayMessage
	| RelayAckMessage
	| RelayRejectMessage
	| AnnounceMessage
	| PromoteMessage
	| PrimaryRedirectMessage
	| PromoteAppliedAckMessage
	| CursorMessage
	| PreparePromoteMessage
	| PreparePromoteAckMessage;

export interface HaClusterNode {
	nodeId: string;
	name: string;
	version: string;
	connectedAt: number | null;
	connected: boolean;
	lastSeenAt: number;
	adminUrl: string;
	lastAckedSeq: number | null;
}

export type HaClusterStatus =
	| {
			role: "primary";
			self: { name: string; version: string; selfAdminUrl: string | null };
			nodes: HaClusterNode[];
			latestSeq: number;
			versionCompatible: boolean;
			versionMismatches: Array<{ nodeId: string; name: string; version: string }>;
			fencedForPromotion: boolean;
			authorityFence: { observedEpoch: number; sourceNodeId: string; observedAt: number } | null;
			stuckPromotionIntent: { promotionId: string; targetNodeId: string } | null;
			quorumFenced: boolean;
			autoFailoverEligible: boolean;
	  }
	| {
			role: "replica";
			self: { name: string; version: string; selfAdminUrl: string | null };
			connectionState: HaConnectionState;
			primaryReachable: true;
			primary?: { name: string; version: string };
			nodes?: HaClusterNode[];
	  }
	| {
			role: "replica";
			self: { name: string; version: string; selfAdminUrl: string | null };
			connectionState: HaConnectionState;
			primaryReachable: false;
			primary?: { name: string; version: string };
			nodes?: HaClusterNode[];
	  };

export type HaConnectionState = "unknown" | "connected" | "disconnected" | "key_mismatch" | "epoch_mismatch" | "version_mismatch" | "connection_rejected";

async function deletePinnedHaCa(): Promise<void> {
	await deletePinnedHaCertificate();
}

function unref(timer: ReturnType<typeof setTimeout> | ReturnType<typeof setInterval>): void {
	(timer as unknown as { unref?: () => void }).unref?.();
}

function certificateFingerprint(pem: string): string {
	try {
		return new X509Certificate(pem).fingerprint256;
	} catch (error) {
		return `unreadable (${error instanceof Error ? error.message : String(error)})`;
	}
}

export async function readWithIdleTimeout<T>(reader: { read(): Promise<T> }, timeoutMs: number): Promise<T> {
	let timer: ReturnType<typeof setTimeout> | undefined;
	try {
		return await Promise.race([
			reader.read(),
			new Promise<never>((_, reject) => {
				timer = setTimeout(() => reject(new Error(`HA snapshot stream stalled - no data received for ${timeoutMs}ms`)), timeoutMs);
			}),
		]);
	} finally {
		clearTimeout(timer);
	}
}

export function notifyHaEvent(
	type: "ha_node_down" | "ha_node_up",
	severity: "warning" | "critical" | "info",
	summary: string,
	role: "primary" | "replica",
): void {
	notificationService.recordGlobalEvent(type, severity, summary, { role }, Date.now()).catch((error) => {
		Logger.error("HA: failed to record a cluster notification event", { error, type });
	});
}

async function persistRoleChangeWithRetry(patch: Partial<HaClusterConfigInsert>, logContext: Record<string, unknown>): Promise<boolean> {
	for (let attempt = 1; attempt <= PROMOTE_PERSIST_MAX_ATTEMPTS; attempt++) {
		try {
			await repository.updateHaClusterConfig(patch);
			return true;
		} catch (error) {
			Logger.error(`HA: failed to persist a role change (attempt ${attempt}/${PROMOTE_PERSIST_MAX_ATTEMPTS})`, { error, ...logContext });
			if (attempt < PROMOTE_PERSIST_MAX_ATTEMPTS) await new Promise((resolve) => setTimeout(resolve, PROMOTE_PERSIST_RETRY_DELAY_MS));
		}
	}
	return false;
}

async function persistElectionWinnerWithRetry(
	term: number,
	candidateNodeId: string,
	expectedPrimaryUrl: string | null,
	expectedPrimaryAdminUrl: string | null,
): Promise<boolean> {
	for (let attempt = 1; attempt <= PROMOTE_PERSIST_MAX_ATTEMPTS; attempt++) {
		try {
			const activated = await repository.activateHaElectionWinner(term, candidateNodeId, expectedPrimaryUrl, expectedPrimaryAdminUrl);
			if (!activated) {
				Logger.warn("HA: abandoned election-winner activation because the durable term, vote, role, or primary topology changed concurrently", {
					term,
					candidateNodeId,
				});
				return false;
			}
			return true;
		} catch (error) {
			Logger.error(`HA: failed to persist an automatic election winner (attempt ${attempt}/${PROMOTE_PERSIST_MAX_ATTEMPTS})`, {
				error,
				term,
				candidateNodeId,
			});
			if (attempt < PROMOTE_PERSIST_MAX_ATTEMPTS) await new Promise((resolve) => setTimeout(resolve, PROMOTE_PERSIST_RETRY_DELAY_MS));
		}
	}
	return false;
}

async function completePromotionWithRetry(intent: HaPromotionIntentRecord): Promise<boolean> {
	for (let attempt = 1; attempt <= PROMOTE_PERSIST_MAX_ATTEMPTS; attempt++) {
		try {
			if (
				await repository.completeHaPromotionIntent(intent.promotion_id, {
					primaryUrl: intent.target_url,
					primaryAdminUrl: intent.target_admin_url,
					clusterEpoch: intent.new_epoch,
				})
			)
				return true;
		} catch (error) {
			Logger.error(`HA: failed to finalize the old primary's demotion (attempt ${attempt}/${PROMOTE_PERSIST_MAX_ATTEMPTS})`, {
				error,
				promotionId: intent.promotion_id,
				targetNodeId: intent.target_node_id,
			});
		}
		if (attempt < PROMOTE_PERSIST_MAX_ATTEMPTS) await new Promise((resolve) => setTimeout(resolve, PROMOTE_PERSIST_RETRY_DELAY_MS));
	}
	return false;
}

class PromotionMessageNotSentError extends Error {}
class PromotionTargetRejectedError extends Error {}

export interface HaRequestIdentity {
	nodeId: string;
	active: boolean;
}

export async function authenticateHaRequest(request: Request, allowPending = false): Promise<HaRequestIdentity | null> {
	const authorization = request.headers.get("authorization") ?? "";
	const supplied = authorization.startsWith("Bearer ") ? authorization.slice(7).trim() : "";
	if (!supplied) return null;
	const member = await repository.haMemberByCredentialHash(await sha256Hex(supplied));
	if (!member || (!allowPending && !member.active)) return null;
	return { nodeId: member.node_id, active: member.active };
}

export async function isAuthorized(request: Request): Promise<boolean> {
	return (await authenticateHaRequest(request)) !== null;
}

interface HaSocketData {
	authenticatedNodeId: string;
	authenticatedActive: boolean;
}

type HaServer = Server<HaSocketData>;
type HaServerWebSocket = ServerWebSocket<HaSocketData>;

class HaMeshService {
	private server: HaServer | null = null;
	private readonly replicas = new Set<HaServerWebSocket>();

	private readonly nodes = new Map<HaServerWebSocket, HaClusterNode>();
	private readonly registeredMembers = new Map<string, HaClusterMemberRecord>();
	private readonly revokedNodeIds = new Set<string>();

	private readonly offlineSince = new Map<string, number>();
	private broadcastTimer: ReturnType<typeof setInterval> | null = null;
	private lastBroadcastSeq = 0;
	private lastHeartbeatBroadcastAt = 0;

	private pendingPreparePromoteAck: {
		ws: HaServerWebSocket;
		promotionId: string;
		resolve: (cursor: number) => void;
		reject: (error: Error) => void;
	} | null = null;
	private pendingPromotionFenceAck: {
		promotionId: string;
		awaiting: Set<HaServerWebSocket>;
		resolve: () => void;
		reject: (error: Error) => void;
	} | null = null;
	private pendingPromoteAppliedAck: {
		ws: HaServerWebSocket;
		promotionId: string;
		resolve: () => void;
		reject: (error: Error) => void;
	} | null = null;
	private promotionRecoveryRunning = false;
	private primaryMessageQueue: Promise<void> = Promise.resolve();
	private replicaSocket: WebSocket | null = null;
	private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
	private relayDrainTimer: ReturnType<typeof setInterval> | null = null;
	private heartbeatWatchdogTimer: ReturnType<typeof setInterval> | null = null;
	private reconnectDelayMs = config.ha.reconnectMinDelayMs;
	private caCertificate: string | null = null;
	private cursor = 0;
	private lastHeartbeatLatestSeq = 0;
	private state: HaConnectionState = "unknown";
	private disconnectedSince = Date.now();
	private verifiedConnectionThisProcess = false;
	private lastVerifiedSyncAt = 0;
	private primaryAuthorityAmbiguous = false;
	private electionWinnerActivating = false;
	private verifiedPrimaryConnectionGeneration = 0;
	private primaryAuthorityAmbiguousBeforeElectionActivation = false;
	private stopped = false;
	private nodeId: string | null = null;
	private relayInFlightId: number | null = null;
	private relayInFlightSentAt = 0;
	private hasBootstrapped = false;
	private bootstrapInFlight: Promise<void> | null = null;
	private messageQueue: Promise<void> = Promise.resolve();
	private connectionGeneration = 0;
	private consecutiveApplyFailureSeq: number | null = null;
	private consecutiveApplyFailureCount = 0;
	private runtimePrepared = false;

	async prepareForRuntimeAtBoot(): Promise<void> {
		if (!config.ha.enabled || this.runtimePrepared) return;
		this.nodeId = await repository.haNodeId();
		if (config.ha.role !== "primary") {
			this.runtimePrepared = true;
			return;
		}

		const intent = await repository.haPromotionIntent();
		if (intent) {
			config.ha.fencedForPromotion = true;
			Logger.warn("HA: recovering an interrupted promotion; this primary remains write-fenced until the target acknowledges activation", {
				promotionId: intent.promotion_id,
				targetNodeId: intent.target_node_id,
			});
		}
		if (config.ha.authorityFence) {
			Logger.error("HA: this primary is durably authority-fenced after observing a newer cluster epoch; it will stay out of service until reconfigured", {
				...config.ha.authorityFence,
				localEpoch: config.ha.epoch,
			});
		}

		await this.loadRegisteredMembers();
		if (intent || config.ha.authorityFence) {
			this.lastBroadcastSeq = await repository.latestChangelogSeq();
			this.runtimePrepared = true;
			return;
		}

		const knownHighWatermark = Math.max(await repository.latestChangelogSeq(), await repository.replicationCursor());
		await repository.bumpChangelogSequenceTo(knownHighWatermark);
		const broadcastFromSeq = await repository.latestChangelogSeq();
		const adoptedRelays = await repository.adoptPendingSessionRelaysAsPrimary(this.nodeId);
		if (adoptedRelays > 0) {
			Logger.warn("HA: adopted replica relay events left across promotion before starting runtime services", {
				count: adoptedRelays,
			});
		}

		this.lastBroadcastSeq = broadcastFromSeq;

		const persisted = await repository.haClusterConfigRow();
		const recentMax = persisted?.recent_max_member_count ?? null;
		const recentMaxAt = persisted?.recent_max_member_count_at ?? null;
		const withinGrace = recentMax !== null && recentMaxAt !== null && Date.now() - Number(recentMaxAt) < MEMBERSHIP_SHRINK_GRACE_MS;
		const effectiveMemberCount = withinGrace ? Math.max(this.registeredMembers.size, Number(recentMax)) : this.registeredMembers.size;
		if (config.ha.autoFailoverEnabled && effectiveMemberCount >= config.ha.autoFailoverMinMembers) {
			config.ha.quorumFenced = true;
			await repository.setQuorumFence(Date.now());
			Logger.warn("HA: primary booted with election-capable membership and will remain write-fenced until fresh majority connectivity is verified", {
				memberCount: this.registeredMembers.size,
				effectiveMemberCount,
			});
		}
		this.runtimePrepared = true;
	}

	async start(): Promise<void> {
		if (!config.ha.enabled) return;
		await this.prepareForRuntimeAtBoot();
		if (config.ha.role === "primary") {
			if (!config.ha.fencedForPromotion && !config.ha.authorityFence && !config.ha.quorumFenced) {
				const now = Date.now();
				await this.recordClusterMember({
					node_id: this.nodeId!,
					name: config.ha.nodeName,
					version: APP_VERSION,
					admin_url: config.ha.selfAdminUrl,
					first_seen_at: now,
					last_seen_at: now,
					credential_hash: config.ha.sharedToken ? await sha256Hex(config.ha.sharedToken) : null,
				});
			}
			await this.startPrimary();
		} else await this.startReplica();
	}

	async stop(): Promise<void> {
		this.stopped = true;
		if (this.broadcastTimer) clearInterval(this.broadcastTimer);
		if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
		if (this.relayDrainTimer) clearInterval(this.relayDrainTimer);
		if (this.heartbeatWatchdogTimer) clearInterval(this.heartbeatWatchdogTimer);
		for (const socket of this.replicas) socket.close(1001, "shutting down");
		this.server?.stop(true);
		this.replicaSocket?.close(1001, "shutting down");
	}

	connectionState(): HaConnectionState {
		return this.state;
	}

	ready(): boolean {
		if (!config.ha.enabled) return true;
		if (config.ha.authorityFence) return false;
		if (config.ha.quorumFenced) return false;
		if (this.runtimeConvergenceFenced) return false;
		if (config.ha.role === "primary") return this.server !== null && !config.ha.fencedForPromotion;
		if (!this.hasBootstrapped || ["version_mismatch", "key_mismatch", "epoch_mismatch", "connection_rejected"].includes(this.state)) return false;
		if (!this.verifiedConnectionThisProcess) return false;
		if (this.primaryAuthorityAmbiguous) return false;
		if (this.state === "connected") return Date.now() - this.lastVerifiedSyncAt <= config.ha.maxSyncStalenessSeconds * 1000;
		return Date.now() - this.disconnectedSince <= config.ha.disconnectedReadyGraceSeconds * 1000;
	}

	async currentReplicationCursor(): Promise<number> {
		return config.ha.role === "primary" ? await repository.latestChangelogSeq() : this.cursor;
	}

	connectedReplicaCount(registeredNodeIds: ReadonlySet<string>): number {
		this.expireStaleReplicaConnections();
		return [...this.nodes.values()].filter((node) => registeredNodeIds.has(node.nodeId)).length;
	}

	private majorityConnectivityShortfall(members: HaClusterMemberRecord[]): string | null {
		if (members.length < config.ha.autoFailoverMinMembers) return null;
		const registeredNodeIds = new Set(members.map((member) => member.node_id));
		const majority = Math.floor(members.length / 2) + 1;
		const ownCount = 1 + this.connectedReplicaCount(registeredNodeIds);
		if (ownCount >= majority) return null;
		return `${ownCount}/${members.length} members reachable; ${majority} required`;
	}

	replicaConnectivitySnapshot(): { cursor: number; lastHeartbeatLatestSeq: number } {
		return { cursor: this.cursor, lastHeartbeatLatestSeq: this.lastHeartbeatLatestSeq };
	}

	disconnectedDurationMs(): number | null {
		if (config.ha.role !== "replica" || this.state !== "disconnected" || this.disconnectedSince === 0) return null;
		return Date.now() - this.disconnectedSince;
	}

	electionConnectivityGeneration(): number {
		return this.verifiedPrimaryConnectionGeneration;
	}

	beginElectionWinnerActivation(expectedConnectionGeneration: number): boolean {
		if (
			config.ha.role !== "replica" ||
			this.state !== "disconnected" ||
			this.disconnectedSince === 0 ||
			this.electionWinnerActivating ||
			this.verifiedPrimaryConnectionGeneration !== expectedConnectionGeneration
		) {
			return false;
		}
		this.electionWinnerActivating = true;
		this.primaryAuthorityAmbiguousBeforeElectionActivation = this.primaryAuthorityAmbiguous;
		this.primaryAuthorityAmbiguous = true;
		this.connectionGeneration += 1;
		this.replicaSocket?.close(1000, "activating automatic-election winner");
		return true;
	}

	finishElectionWinnerActivation(succeeded: boolean): void {
		if (succeeded) return;
		this.electionWinnerActivating = false;
		this.primaryAuthorityAmbiguous = this.primaryAuthorityAmbiguousBeforeElectionActivation;
		this.primaryAuthorityAmbiguousBeforeElectionActivation = false;
	}

	private async startPrimary(): Promise<void> {
		this.nodeId ??= await repository.haNodeId();
		const { cert, key } = await haTlsCertificate();
		this.server = Bun.serve<HaSocketData>({
			hostname: config.host,
			port: config.ha.port,
			tls: { cert, key },
			fetch: (request, server) => this.handleRequest(request, server),
			websocket: {
				open: (ws) => this.handlePrimaryOpen(ws),
				close: (ws) => this.handlePrimaryClose(ws),
				message: (ws, data) => this.enqueuePrimaryMessage(ws, data),
			},
		});
		this.broadcastTimer = setInterval(() => void this.broadcastNewChanges(), BROADCAST_INTERVAL_MS);
		unref(this.broadcastTimer);
		Logger.info(`HA mesh listening on port ${config.ha.port} (primary, TLS)`, { certificateFingerprintSha256: certificateFingerprint(cert) });
	}

	private async handleRequest(request: Request, server: HaServer): Promise<Response | undefined> {
		const url = new URL(request.url);

		if (url.pathname === "/_ha/enroll" && request.method === "POST") return await this.handleEnrollRequest(request);

		const isElectionPath = url.pathname === "/_ha/vote-request" || url.pathname === "/_ha/who-is-primary" || url.pathname === "/_ha/announce-primary";
		const identity = await authenticateHaRequest(request, !isElectionPath);
		if (!identity) return new Response("Unauthorized", { status: 401 });
		if (url.pathname === "/_ha/stream") {
			if (server.upgrade(request, { data: { authenticatedNodeId: identity.nodeId, authenticatedActive: identity.active } })) return undefined;
			return new Response("Upgrade failed", { status: 426 });
		}
		if (url.pathname === "/_ha/changelog" && request.method === "GET") {
			const since = Number(url.searchParams.get("since") ?? "0");
			const rows = await repository.changelogSince(Number.isFinite(since) ? since : 0, config.ha.changelogPageSize);
			const latestSeq = await repository.latestChangelogSeq();
			return Response.json({ rows, latestSeq });
		}
		if (url.pathname === "/_ha/snapshot" && request.method === "GET") {
			if (!request.headers.get("accept")?.includes("application/x-ndjson")) {
				return Response.json(await repository.fullSnapshot());
			}
			const encoder = new TextEncoder();
			const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>();
			const writer = writable.getWriter();
			void repository
				.streamFullSnapshot(
					async (seq) => await writer.write(encoder.encode(`${JSON.stringify({ type: "meta", seq })}\n`)),
					async (row) => await writer.write(encoder.encode(`${JSON.stringify({ type: "row", row })}\n`)),
				)
				.then(async () => await writer.close())
				.catch(async (error) => {
					Logger.error("HA: snapshot stream failed", { error });
					await writer.abort(error).catch(() => undefined);
				});
			return new Response(readable, { headers: { "content-type": "application/x-ndjson" } });
		}
		if (isElectionPath) return await this.delegateToElectionService(request, identity);
		return new Response("Not found", { status: 404 });
	}

	private async delegateToElectionService(request: Request, identity: HaRequestIdentity): Promise<Response> {
		const { haElectionService } = await import("./ha-election-service.ts");
		return await haElectionService.handleHttpRequest(request, identity);
	}

	private async handleEnrollRequest(request: Request): Promise<Response> {
		const authorization = request.headers.get("authorization") ?? "";
		const supplied = authorization.startsWith("Bearer ") ? authorization.slice(7).trim() : "";
		if (!supplied) return new Response("Unauthorized", { status: 401 });
		let body: { nodeId?: unknown; name?: unknown; version?: unknown; adminUrl?: unknown };
		try {
			body = (await request.json()) as typeof body;
		} catch {
			return new Response("Malformed enrollment body", { status: 400 });
		}
		const { nodeId, name, version, adminUrl } = body;
		if (
			typeof nodeId !== "string" ||
			!nodeId ||
			nodeId.length > 64 ||
			typeof name !== "string" ||
			!name ||
			name.length > 255 ||
			typeof version !== "string" ||
			!version ||
			version.length > 64 ||
			typeof adminUrl !== "string" ||
			!adminUrl ||
			adminUrl.length > 2048 ||
			!isSecureHaUrl(adminUrl)
		) {
			return new Response("Malformed enrollment body", { status: 400 });
		}

		const shortfall = this.majorityConnectivityShortfall(await repository.haClusterMembers());
		if (shortfall) {
			return new Response(
				`This primary does not currently have majority connectivity to the existing cluster (${shortfall}) and cannot safely accept new members right now`,
				{ status: 503 },
			);
		}
		const credential = randomToken(32);
		const now = Date.now();
		const redeemed = await repository.redeemHaEnrollmentCode(
			await sha256Hex(supplied),
			now,
			{ node_id: nodeId, name, version, admin_url: adminUrl, first_seen_at: now, last_seen_at: now },
			await sha256Hex(credential),
		);
		if (!redeemed) return new Response("Unauthorized", { status: 401 });

		await this.loadRegisteredMembers();
		return Response.json({ sharedToken: credential });
	}

	private refreshVersionFence(): void {
		const mismatches = new Map<string, { nodeId: string; name: string; version: string }>();
		for (const member of this.registeredMembers.values()) {
			if (member.node_id !== this.nodeId && member.version !== APP_VERSION) {
				mismatches.set(member.node_id, { nodeId: member.node_id, name: member.name, version: member.version });
			}
		}
		for (const node of this.nodes.values()) {
			if (node.nodeId !== this.nodeId && node.version !== APP_VERSION) {
				mismatches.set(node.nodeId, { nodeId: node.nodeId, name: node.name, version: node.version });
			}
		}
		config.ha.versionMismatchNodes = [...mismatches.values()];
	}

	private async loadRegisteredMembers(): Promise<void> {
		this.nodeId ??= await repository.haNodeId();
		this.registeredMembers.clear();
		for (const member of await repository.haClusterMembers()) this.registeredMembers.set(member.node_id, member);
		this.revokedNodeIds.clear();
		for (const nodeId of await repository.haRevokedClusterNodeIds()) this.revokedNodeIds.add(nodeId);
		this.refreshVersionFence();
	}

	private async recordClusterMember(member: HaClusterMemberRecord): Promise<void> {
		if (this.revokedNodeIds.has(member.node_id)) throw new Error("This HA node has been revoked and must use a fresh join code before reconnecting");
		const existing = this.registeredMembers.get(member.node_id);
		const normalized = { ...member, first_seen_at: existing?.first_seen_at ?? member.first_seen_at };

		this.refreshVersionFence();
		try {
			await repository.upsertHaClusterMember(normalized);
		} catch (error) {
			this.refreshVersionFence();
			throw error;
		}
		this.registeredMembers.set(member.node_id, normalized);
		this.refreshVersionFence();
	}

	private expireStaleReplicaConnections(now = Date.now()): void {
		for (const [ws, node] of this.nodes) {
			if (now - node.lastSeenAt <= HA_REPLICA_LIVENESS_TIMEOUT_MS) continue;
			Logger.warn("HA: replica stopped acknowledging heartbeats; removing its stale connection from quorum", {
				nodeId: node.nodeId,
				name: node.name,
				lastSeenAt: node.lastSeenAt,
			});

			this.handlePrimaryClose(ws);
			try {
				ws.close(4000, "replica heartbeat acknowledgement timeout");
			} catch (error) {
				Logger.warn("HA: failed to close a stale replica socket after expiring it", { error, nodeId: node.nodeId });
			}
		}
	}

	private offlineRegisteredMembers(): HaClusterMemberRecord[] {
		this.expireStaleReplicaConnections();
		const connectedNodeIds = new Set([...this.nodes.values()].map((node) => node.nodeId));
		return [...this.registeredMembers.values()].filter((member) => member.node_id !== this.nodeId && !connectedNodeIds.has(member.node_id));
	}

	versionMismatches(): Array<{ nodeId: string; name: string; version: string }> {
		return config.ha.versionMismatchNodes.map((node) => ({ ...node }));
	}

	async forgetNode(nodeId: string): Promise<void> {
		if (config.ha.role !== "primary") throw new Error("Only the primary can forget a cluster node");
		if (nodeId === this.nodeId) throw new Error("The primary cannot forget itself");
		if ([...this.nodes.values()].some((node) => node.nodeId === nodeId)) {
			throw new Error("That node is currently connected - stop it or make it leave the cluster before forgetting it");
		}

		const minOfflineMs = Math.max(HA_FORGET_MIN_OFFLINE_FLOOR_MS, config.ha.reconnectMaxDelayMs * HA_FORGET_MIN_OFFLINE_RECONNECT_MULTIPLIER);
		const offlineSince = this.offlineSince.get(nodeId) ?? this.registeredMembers.get(nodeId)?.last_seen_at;

		const offlineMs = offlineSince === undefined ? Infinity : Date.now() - offlineSince;
		if (offlineMs < minOfflineMs) {
			throw new Error(
				`That node was only recently seen disconnecting - wait at least ${Math.ceil((minOfflineMs - offlineMs) / 1000)} more second(s) before forgetting it, in case it is only a transient network blip`,
			);
		}

		const members = await repository.haClusterMembers();
		const shortfall = this.majorityConnectivityShortfall(members);
		if (shortfall) {
			throw new Error(`Cannot forget a cluster node without current majority connectivity (${shortfall})`);
		}

		if (!(await repository.deleteHaClusterMember(nodeId, members.length))) throw new Error("That cluster node is not registered");
		this.registeredMembers.delete(nodeId);
		this.revokedNodeIds.add(nodeId);
		this.offlineSince.delete(nodeId);
		this.refreshVersionFence();
	}

	private handlePrimaryOpen(ws: HaServerWebSocket): void {
		this.replicas.add(ws);
		encryptSecret(MASTER_KEY_CHECK_PLAINTEXT)
			.then((keyCheck) => {
				const hello: HelloMessage = {
					type: "hello",
					keyCheck,
					epoch: config.ha.epoch,
					version: APP_VERSION,
					primaryFenced: config.ha.fencedForPromotion || !!config.ha.authorityFence || config.ha.quorumFenced,
				};
				ws.send(JSON.stringify(hello));
			})
			.catch((error) => {
				Logger.error("HA: failed to build the hello handshake for a connecting replica", { error });
				ws.close();
			});
	}

	private handlePrimaryClose(ws: HaServerWebSocket): void {
		this.replicas.delete(ws);
		const node = this.nodes.get(ws);
		this.nodes.delete(ws);
		this.refreshVersionFence();
		if (node) {
			this.offlineSince.set(node.nodeId, Date.now());
			notifyHaEvent("ha_node_down", "warning", `HA replica disconnected: ${node.name}`, "replica");
		}
		if (this.pendingPreparePromoteAck?.ws === ws) {
			this.pendingPreparePromoteAck.reject(new Error("The target node disconnected while confirming it was ready for promotion"));
			this.pendingPreparePromoteAck = null;
		}
		if (this.pendingPromotionFenceAck?.awaiting.has(ws)) {
			this.pendingPromotionFenceAck.reject(new Error("A bystander replica disconnected before acknowledging the promotion fence"));
			this.pendingPromotionFenceAck = null;
		}
		if (this.pendingPromoteAppliedAck?.ws === ws) {
			this.pendingPromoteAppliedAck.reject(new Error("The target node disconnected before its promotion acknowledgement was received"));
			this.pendingPromoteAppliedAck = null;
		}
	}

	private async fenceForNewerEpoch(message: AnnounceMessage): Promise<boolean> {
		return await this.fenceAuthorityForNewerEpoch(message.epoch, message.nodeId, message.name);
	}

	async fenceAuthorityForNewerEpoch(reportedEpoch: number, sourceNodeId: string, sourceName: string): Promise<boolean> {
		const announcedEpoch = Number.isSafeInteger(reportedEpoch) ? reportedEpoch : 0;
		if (announcedEpoch <= config.ha.epoch) return false;
		const now = Date.now();
		if (!config.ha.authorityFence || announcedEpoch > config.ha.authorityFence.observedEpoch) {
			config.ha.authorityFence = { observedEpoch: announcedEpoch, sourceNodeId, observedAt: now };
		}
		Logger.error(
			"HA: a connected node reports a newer cluster epoch - this primary is now durably authority-fenced and removed from service until explicitly reconfigured",
			{ nodeId: sourceNodeId, name: sourceName, replicaEpoch: announcedEpoch, primaryEpoch: config.ha.epoch },
		);
		await repository
			.fenceHaPrimaryAuthority(announcedEpoch, sourceNodeId, now)
			.catch((error) => Logger.error("HA: failed to persist the stale-primary authority fence; keeping the live process fenced", { error }));
		await this.broadcastHeartbeat().catch((error) => Logger.warn("HA: failed to broadcast the stale-primary authority fence to connected replicas", { error }));
		return true;
	}

	async broadcastPrimaryFenceState(): Promise<void> {
		if (config.ha.role !== "primary") return;
		await this.broadcastHeartbeat();
	}

	private async recoverFromPrimaryMessageFailure(promise: Promise<void>, ws: HaServerWebSocket): Promise<void> {
		try {
			await promise;
		} catch (error) {
			Logger.error("HA: a primary message handler failed unexpectedly; closing the connection", { error });
			this.handlePrimaryClose(ws);
			try {
				ws.close(1011, "an unexpected error occurred processing a previous message; reconnect to retry");
			} catch (closeError) {
				Logger.warn("HA: failed to close a connection after its own message handler threw", { error: closeError });
			}
		}
	}

	private enqueuePrimaryMessage(ws: HaServerWebSocket, data: string | Buffer): void {
		let parsed: { type?: unknown } | undefined;
		try {
			parsed = JSON.parse(String(data)) as { type?: unknown };
		} catch {
			parsed = undefined;
		}
		if (parsed?.type !== "announce" && parsed?.type !== "relay") {
			void this.recoverFromPrimaryMessageFailure(this.handlePrimaryMessage(ws, data), ws);
			return;
		}
		this.primaryMessageQueue = this.recoverFromPrimaryMessageFailure(
			this.primaryMessageQueue.then(() => this.handlePrimaryMessage(ws, data)),
			ws,
		);
	}

	private async handlePrimaryMessage(ws: HaServerWebSocket, data: string | Buffer): Promise<void> {
		let message:
			| RelayMessage
			| AnnounceMessage
			| RequestMasterKeyMessage
			| CursorMessage
			| PreparePromoteAckMessage
			| PromotionFenceAckMessage
			| PromoteAppliedAckMessage;
		try {
			message = JSON.parse(String(data)) as
				| RelayMessage
				| AnnounceMessage
				| RequestMasterKeyMessage
				| CursorMessage
				| PreparePromoteAckMessage
				| PromotionFenceAckMessage
				| PromoteAppliedAckMessage;
		} catch {
			return;
		}
		if (message.type === "cursor") {
			if (!Number.isSafeInteger(message.seq) || message.seq < 0) return;
			const node = this.nodes.get(ws);
			if (node) {
				node.lastAckedSeq = message.seq;
				node.lastSeenAt = Date.now();
			}
			return;
		}
		if (message.type === "prepare_promote_ack") {
			if (
				this.pendingPreparePromoteAck?.ws === ws &&
				this.pendingPreparePromoteAck.promotionId === message.promotionId &&
				Number.isSafeInteger(message.cursor)
			) {
				this.pendingPreparePromoteAck.resolve(message.cursor);
			}
			return;
		}
		if (message.type === "promotion_fence_ack") {
			const pending = this.pendingPromotionFenceAck;
			if (
				pending &&
				pending.promotionId === message.promotionId &&
				typeof message.promotionId === "string" &&
				message.promotionId.length > 0 &&
				message.promotionId.length <= 64 &&
				pending.awaiting.delete(ws) &&
				pending.awaiting.size === 0
			) {
				pending.resolve();
			}
			return;
		}
		if (message.type === "promote_applied_ack") {
			if (
				typeof message.promotionId === "string" &&
				message.promotionId.length > 0 &&
				message.promotionId.length <= 64 &&
				typeof message.success === "boolean" &&
				this.pendingPromoteAppliedAck?.ws === ws &&
				this.pendingPromoteAppliedAck.promotionId === message.promotionId
			) {
				if (message.success) this.pendingPromoteAppliedAck.resolve();
				else
					this.pendingPromoteAppliedAck.reject(
						new PromotionTargetRejectedError(
							typeof message.reason === "string" && message.reason.length <= 2048
								? message.reason || "The target could not persist its primary role"
								: "The target could not persist its primary role",
						),
					);
			}
			return;
		}
		if (message.type === "request_master_key") {
			try {
				const response: MasterKeyMessage = { type: "master_key", key: await masterSecretForReplication() };
				ws.send(JSON.stringify(response));
			} catch (error) {
				Logger.error("HA: failed to provide this primary's master key to a joining replica", { error });
			}
			return;
		}
		if (message.type === "announce") {
			if (
				typeof message.nodeId !== "string" ||
				message.nodeId.length === 0 ||
				message.nodeId.length > 64 ||
				typeof message.name !== "string" ||
				message.name.length > 255 ||
				typeof message.version !== "string" ||
				message.version.length > 64 ||
				typeof message.adminUrl !== "string" ||
				message.adminUrl.length > 2048
			) {
				ws.close(1008, "invalid node identity");
				return;
			}
			if (message.adminUrl && !isSecureHaUrl(message.adminUrl)) {
				ws.close(1008, "node admin URL must use HTTPS");
				return;
			}

			if (message.nodeId !== ws.data.authenticatedNodeId) {
				Logger.error("HA: rejected an announce claiming a node identity different from the one that authenticated this connection", {
					claimedNodeId: message.nodeId,
					authenticatedNodeId: ws.data.authenticatedNodeId,
				});
				ws.close(1008, "announced node identity does not match the authenticated connection");
				return;
			}
			if (this.revokedNodeIds.has(message.nodeId)) {
				Logger.warn("HA: rejected a forgotten node that attempted to reconnect without fresh enrollment", {
					nodeId: message.nodeId,
					name: message.name,
				});
				ws.close(1008, "node membership has been revoked; use a fresh join code");
				return;
			}
			const announced = this.nodes.get(ws);
			if (announced && announced.nodeId !== message.nodeId) {
				ws.close(1008, "node identity changed");
				return;
			}

			const reportedNewerEpoch = await this.fenceForNewerEpoch(message);

			if (!announced) {
				for (const [otherWs, other] of this.nodes) {
					if (otherWs !== ws && other.nodeId === message.nodeId) {
						Logger.error(
							"HA: rejected a replica connection announcing a node identity that's already connected - this usually means a database was cloned onto a second instance instead of provisioned fresh",
							{ nodeId: message.nodeId, name: message.name },
						);
						ws.close(1008, "a node with this identity is already connected");
						return;
					}
				}
			}
			const now = Date.now();
			const isFirstAnnounce = !announced;
			const liveNode: HaClusterNode = {
				nodeId: message.nodeId,
				name: message.name,
				version: message.version,
				connectedAt: announced?.connectedAt ?? now,
				connected: true,
				lastSeenAt: now,
				adminUrl: message.adminUrl,

				lastAckedSeq: announced?.lastAckedSeq ?? null,
			};
			this.nodes.set(ws, liveNode);
			this.offlineSince.delete(message.nodeId);
			if (reportedNewerEpoch) {
				if (isFirstAnnounce) notifyHaEvent("ha_node_up", "info", `HA replica connected: ${message.name}`, "replica");
				return;
			}

			let oldMembersForDurabilityCheck: HaClusterMemberRecord[] | null = null;
			if (!ws.data.authenticatedActive) {
				const members = await repository.haClusterMembers();
				const shortfall = this.majorityConnectivityShortfall(members);
				if (shortfall) {
					Logger.warn("HA: refused to activate a pending cluster member while this primary lacks majority connectivity to the existing cluster", {
						nodeId: message.nodeId,
						name: message.name,
						shortfall,
					});
					this.handlePrimaryClose(ws);
					ws.close(
						1011,
						`this primary does not currently have majority connectivity to the existing cluster (${shortfall}) and cannot safely activate new members right now; reconnect to retry`,
					);
					return;
				}
				oldMembersForDurabilityCheck = members;
			}
			if (oldMembersForDurabilityCheck) {
				const oldMembers = oldMembersForDurabilityCheck;

				const outcome = await haPrimaryWriteBarrier.runPrimaryWrite(async (): Promise<"activated" | "write-not-durable" | "not-confirmed"> => {
					try {
						await this.recordClusterMember({
							node_id: message.nodeId,
							name: message.name,
							version: message.version,
							admin_url: message.adminUrl || null,
							first_seen_at: now,
							last_seen_at: now,
						});

						ws.data.authenticatedActive = true;
					} catch (error) {
						Logger.error("HA: failed to persist a replica's cluster membership; keeping its live version fence active", {
							error,
							nodeId: message.nodeId,
							version: message.version,
						});

						return "write-not-durable";
					}

					const confirmed = await this.waitForMembershipActivationDurability(oldMembers);
					if (!confirmed) {
						Logger.warn("HA: could not confirm a majority of the existing membership durably received this activation in time - reverting it back to pending", {
							nodeId: message.nodeId,
							name: message.name,
						});
						await repository.revertHaClusterMemberActivation(message.nodeId).catch((error) => {
							Logger.error("HA: failed to revert an unconfirmed activation back to pending; it may remain durably (but unconfirmed) active", {
								error,
								nodeId: message.nodeId,
							});
						});
						this.registeredMembers.delete(message.nodeId);
						this.refreshVersionFence();
						return "not-confirmed";
					}
					return "activated";
				});
				if (outcome === "write-not-durable") {
					this.handlePrimaryClose(ws);
					ws.close(1011, "could not durably activate cluster membership; reconnect to retry");
					return;
				}
				if (outcome === "not-confirmed") {
					this.handlePrimaryClose(ws);
					ws.close(1011, "could not confirm this activation durably reached a majority of the existing cluster in time; reconnect to retry");
					return;
				}
			} else {
				try {
					await this.recordClusterMember({
						node_id: message.nodeId,
						name: message.name,
						version: message.version,
						admin_url: message.adminUrl || null,
						first_seen_at: now,
						last_seen_at: now,
					});
					ws.data.authenticatedActive = true;
				} catch (error) {
					Logger.error("HA: failed to persist a replica's cluster membership; keeping its live version fence active", {
						error,
						nodeId: message.nodeId,
						version: message.version,
					});
				}
			}
			if (isFirstAnnounce) notifyHaEvent("ha_node_up", "info", `HA replica connected: ${message.name}`, "replica");
			void this.resumePromotionIfNeeded(ws, message.nodeId);
			return;
		}
		if (message.type !== "relay") return;
		try {
			const node = this.nodes.get(ws);
			if (!node) throw new Error("Replica sent a relay before announcing its node identity");
			if (
				!Number.isSafeInteger(message.relayId) ||
				message.relayId <= 0 ||
				!MULTI_WRITER_ENTITY_TYPES.has(message.entityType) ||
				typeof message.entityId !== "string" ||
				message.entityId.length === 0 ||
				message.entityId.length > 255 ||
				!["insert", "update", "delete"].includes(message.op)
			) {
				throw new Error("Replica sent an invalid relay message");
			}
			const payload = message.payloadJson ? (JSON.parse(message.payloadJson) as object) : null;
			try {
				await repository.applyReplicatedSessionRelay(node.nodeId, message.relayId, message.entityType, message.entityId, message.op, payload);

				const ack: RelayAckMessage = { type: "relay_ack", relayId: message.relayId };
				ws.send(JSON.stringify(ack));
			} catch (error) {
				if (
					error instanceof HaPromotionWriteFenceError ||
					error instanceof HaPrimaryAuthorityFenceError ||
					error instanceof HaQuorumLossFenceError ||
					isTransientDatabaseError(error)
				) {
					Logger.warn("HA: temporarily unable to apply a relayed session event, leaving it for the replica to retry", {
						error,
						nodeId: node.nodeId,
						relayId: message.relayId,
						entityType: message.entityType,
						entityId: message.entityId,
					});
					return;
				}
				const reason = error instanceof Error ? error.message : String(error);
				Logger.error("HA: rejecting a relayed session event that could not be applied - dead-lettering it", {
					error,
					nodeId: node.nodeId,
					relayId: message.relayId,
					entityType: message.entityType,
					entityId: message.entityId,
				});
				await repository
					.deadLetterRelay(node.nodeId, message.relayId, message.entityType, message.entityId, message.op, payload, reason)
					.catch((dlqError) => Logger.error("HA: failed to record a dead-lettered relay", { error: dlqError }));
				const reject: RelayRejectMessage = { type: "relay_reject", relayId: message.relayId, reason };
				ws.send(JSON.stringify(reject));
			}
		} catch (error) {
			Logger.error("HA: failed to apply a relayed session event", { error, entityType: message.entityType, entityId: message.entityId });
		}
	}

	async clusterStatus(): Promise<HaClusterStatus> {
		const self = { name: config.ha.nodeName, version: APP_VERSION, selfAdminUrl: config.ha.selfAdminUrl };
		if (config.ha.role === "primary") {
			this.expireStaleReplicaConnections();
			const liveByNodeId = new Map([...this.nodes.values()].map((node) => [node.nodeId, node]));
			const nodeIds = new Set([...this.registeredMembers.keys(), ...liveByNodeId.keys()]);
			if (this.nodeId) nodeIds.delete(this.nodeId);
			const nodes = [...nodeIds].map((nodeId): HaClusterNode => {
				const live = liveByNodeId.get(nodeId);
				const registered = this.registeredMembers.get(nodeId);
				return {
					nodeId,
					name: live?.name ?? registered?.name ?? nodeId,
					version: live?.version ?? registered?.version ?? "unknown",
					connectedAt: live?.connectedAt ?? null,
					connected: !!live,
					lastSeenAt: live?.lastSeenAt ?? registered?.last_seen_at ?? 0,
					adminUrl: live?.adminUrl ?? registered?.admin_url ?? "",
					lastAckedSeq: live?.lastAckedSeq ?? null,
				};
			});

			const activelyResolvingPromotion =
				this.promotionRecoveryRunning ||
				this.pendingPromotionFenceAck !== null ||
				this.pendingPreparePromoteAck !== null ||
				this.pendingPromoteAppliedAck !== null;
			const intent = config.ha.fencedForPromotion && !activelyResolvingPromotion ? await repository.haPromotionIntent() : null;
			return {
				role: "primary",
				self,
				nodes,
				latestSeq: await repository.latestChangelogSeq(),
				versionCompatible: config.ha.versionMismatchNodes.length === 0,
				versionMismatches: this.versionMismatches(),
				fencedForPromotion: config.ha.fencedForPromotion,
				authorityFence: config.ha.authorityFence ? { ...config.ha.authorityFence } : null,
				stuckPromotionIntent: intent ? { promotionId: intent.promotion_id, targetNodeId: intent.target_node_id } : null,
				quorumFenced: config.ha.quorumFenced,

				autoFailoverEligible: config.ha.autoFailoverEnabled && this.registeredMembers.size >= config.ha.autoFailoverMinMembers,
			};
		}
		return { role: "replica", self, connectionState: this.state, primaryReachable: this.state === "connected" };
	}

	private async waitForPreparePromoteAck(targetWs: HaServerWebSocket, barrierSeq: number, promotionId: string = crypto.randomUUID()): Promise<string> {
		if (this.pendingPreparePromoteAck) throw new Error("Another promotion is already in progress on this node");
		await new Promise<void>((resolve, reject) => {
			const timeout = setTimeout(() => {
				this.pendingPreparePromoteAck = null;
				reject(new Error("Timed out waiting for the target node to confirm it has durably applied every change - try again once it catches up"));
			}, PREPARE_PROMOTE_ACK_TIMEOUT_MS);
			unref(timeout);
			this.pendingPreparePromoteAck = {
				ws: targetWs,
				promotionId,
				resolve: (cursor) => {
					clearTimeout(timeout);
					this.pendingPreparePromoteAck = null;
					if (cursor < barrierSeq) {
						reject(new Error(`Target acknowledged cursor ${cursor}, short of the required barrier ${barrierSeq} - aborting promotion`));
						return;
					}
					resolve();
				},
				reject: (error) => {
					clearTimeout(timeout);
					this.pendingPreparePromoteAck = null;
					reject(error);
				},
			};
			try {
				const message: PreparePromoteMessage = { type: "prepare_promote", barrierSeq, promotionId };
				if (targetWs.send(JSON.stringify(message)) === 0) throw new Error("The target connection dropped the promotion-readiness request");
			} catch (error) {
				clearTimeout(timeout);
				this.pendingPreparePromoteAck = null;
				reject(error instanceof Error ? error : new Error(String(error)));
			}
		});
		return promotionId;
	}

	private async waitForBystanderPromotionFence(targetWs: HaServerWebSocket, promotionId: string): Promise<void> {
		if (this.pendingPromotionFenceAck) throw new Error("Another promotion-fence broadcast is already in progress on this node");
		const awaiting = new Set([...this.nodes.keys()].filter((ws) => ws !== targetWs));
		await new Promise<void>((resolve, reject) => {
			let deliveryComplete = false;
			let settled = false;
			const timeout = setTimeout(() => {
				if (settled) return;
				settled = true;
				this.pendingPromotionFenceAck = null;
				reject(new Error("Timed out waiting for every bystander replica to acknowledge the promotion fence"));
			}, PROMOTION_FENCE_ACK_TIMEOUT_MS);
			unref(timeout);
			const finish = () => {
				if (settled || !deliveryComplete || awaiting.size > 0) return;
				settled = true;
				clearTimeout(timeout);
				this.pendingPromotionFenceAck = null;
				resolve();
			};
			const fail = (error: Error) => {
				if (settled) return;
				settled = true;
				clearTimeout(timeout);
				this.pendingPromotionFenceAck = null;
				reject(error);
			};
			this.pendingPromotionFenceAck = { promotionId, awaiting, resolve: finish, reject: fail };
			void this.broadcastHeartbeat(true, promotionId)
				.then(() => {
					deliveryComplete = true;
					finish();
				})
				.catch((error) => fail(error instanceof Error ? error : new Error(String(error))));
		});
	}

	private async waitForPromoteAppliedAck(targetWs: HaServerWebSocket, message: PromoteMessage): Promise<void> {
		if (this.pendingPromoteAppliedAck) throw new Error("Another target activation is already in progress on this node");
		await new Promise<void>((resolve, reject) => {
			const timeout = setTimeout(() => {
				this.pendingPromoteAppliedAck = null;
				reject(
					new Error(
						"Timed out waiting for the target to durably activate as primary; this node remains fenced and will resume the handoff if the target reconnects",
					),
				);
			}, PROMOTE_APPLIED_ACK_TIMEOUT_MS);
			unref(timeout);
			this.pendingPromoteAppliedAck = {
				ws: targetWs,
				promotionId: message.promotionId,
				resolve: () => {
					clearTimeout(timeout);
					this.pendingPromoteAppliedAck = null;
					resolve();
				},
				reject: (error) => {
					clearTimeout(timeout);
					this.pendingPromoteAppliedAck = null;
					reject(error);
				},
			};
			try {
				if (targetWs.send(JSON.stringify(message)) === 0) {
					throw new PromotionMessageNotSentError("The target connection dropped the activation message before delivery");
				}
			} catch (error) {
				clearTimeout(timeout);
				this.pendingPromoteAppliedAck = null;
				reject(
					error instanceof PromotionMessageNotSentError ? error : new PromotionMessageNotSentError(error instanceof Error ? error.message : String(error)),
				);
			}
		});
	}

	private async finalizePromotion(targetWs: HaServerWebSocket, intent: HaPromotionIntentRecord): Promise<void> {
		const message: PromoteMessage = {
			type: "promote",
			promotionId: intent.promotion_id,
			newPrimaryNodeId: intent.target_node_id,
			newPrimaryUrl: intent.target_url,
			newPrimaryAdminUrl: intent.target_admin_url,
			newEpoch: intent.new_epoch,
		};
		await this.waitForPromoteAppliedAck(targetWs, message);

		const payload = JSON.stringify(message);
		for (const socket of this.replicas) {
			if (socket === targetWs) continue;
			try {
				socket.send(payload);
			} catch (error) {
				Logger.warn("HA: failed to notify a bystander replica about the new primary", { error, promotionId: intent.promotion_id });
			}
		}

		if (!(await completePromotionWithRetry(intent))) {
			throw new Error(
				"The target is primary, but this node could not persist its own demotion; it remains durably write-fenced and requires operator attention",
			);
		}
		config.ha.role = "replica";
		config.ha.primaryUrl = intent.target_url;
		config.ha.primaryAdminUrl = intent.target_admin_url;
		config.ha.epoch = intent.new_epoch;
		haPrimaryWriteBarrier.endPromotion();
		Logger.warn("HA: target acknowledged activation; demoting this node and restarting", {
			targetNodeId: intent.target_node_id,
			newPrimaryUrl: intent.target_url,
			newEpoch: intent.new_epoch,
		});
		await deletePinnedHaCa();
		setTimeout(() => void processLifecycle.gracefulRestart("ha-promote"), 300);
	}

	private async resumePromotionIfNeeded(targetWs: HaServerWebSocket, targetNodeId: string): Promise<void> {
		if (this.promotionRecoveryRunning || config.ha.role !== "primary") return;
		const intent = await repository.haPromotionIntent();
		if (!intent || intent.target_node_id !== targetNodeId) return;
		this.promotionRecoveryRunning = true;
		try {
			await this.broadcastAllPendingChanges();
			const barrierSeq = this.lastBroadcastSeq;
			await this.waitForPreparePromoteAck(targetWs, barrierSeq, intent.promotion_id);
			await this.finalizePromotion(targetWs, intent);
		} catch (error) {
			Logger.error("HA: interrupted promotion recovery did not complete; keeping this node durably write-fenced", {
				error,
				promotionId: intent.promotion_id,
				targetNodeId,
			});
		} finally {
			this.promotionRecoveryRunning = false;
		}
	}

	async promoteNode(targetNodeId: string): Promise<void> {
		if (config.ha.role !== "primary") throw new Error("Only the primary can promote a node");
		if (config.ha.authorityFence) throw new Error("This node has evidence that it is no longer the authoritative primary and cannot promote another node");
		this.expireStaleReplicaConnections();
		const targetEntry = [...this.nodes.entries()].find(([, node]) => node.nodeId === targetNodeId);
		if (!targetEntry) throw new Error("That node is not currently connected");
		const [targetWs, target] = targetEntry;
		if (target.version !== APP_VERSION) {
			throw new Error(`Cannot promote ${target.name}: it runs BurrowGate ${target.version}, but this primary runs ${APP_VERSION}`);
		}
		if (!target.adminUrl) throw new Error("That node has not announced a reachable admin URL and cannot be promoted");
		if (config.ha.fencedForPromotion) throw new Error("A promotion is already in progress on this node");
		const offlineAtStart = this.offlineRegisteredMembers();
		if (offlineAtStart.length > 0) {
			throw new Error(
				`Cannot promote while registered replicas are offline (${offlineAtStart.map((member) => member.name).join(", ")}). Reconnect them or explicitly forget decommissioned nodes first, otherwise they can remain pointed at the old primary.`,
			);
		}

		await haPrimaryWriteBarrier.beginPromotion();
		let durableIntent: HaPromotionIntentRecord | null = null;
		try {
			try {
				await this.broadcastAllPendingChanges();
			} catch (error) {
				throw new Error("Failed to flush pending changes to every replica before promoting - aborting so nothing is lost. Check the logs and try again.", {
					cause: error,
				});
			}

			const promotionId = crypto.randomUUID();
			await this.waitForBystanderPromotionFence(targetWs, promotionId);
			const barrierSeq = this.lastBroadcastSeq;

			await this.waitForPreparePromoteAck(targetWs, barrierSeq, promotionId);
			const offlineBeforeActivation = this.offlineRegisteredMembers();
			if (offlineBeforeActivation.length > 0) {
				throw new Error(
					`A registered replica disconnected while preparing promotion (${offlineBeforeActivation.map((member) => member.name).join(", ")}); aborting before the target is activated.`,
				);
			}

			const newPrimaryUrl = deriveMeshUrl(target.adminUrl, config.ha.port);
			const newEpoch = config.ha.epoch + 1;

			durableIntent = {
				id: 1,
				promotion_id: promotionId,
				target_node_id: targetNodeId,
				target_url: newPrimaryUrl,
				target_admin_url: target.adminUrl,
				new_epoch: newEpoch,
				created_at: Date.now(),
			};
			await repository.saveHaPromotionIntent({
				promotion_id: durableIntent.promotion_id,
				target_node_id: durableIntent.target_node_id,
				target_url: durableIntent.target_url,
				target_admin_url: durableIntent.target_admin_url,
				new_epoch: durableIntent.new_epoch,
				created_at: durableIntent.created_at,
			});
			await this.finalizePromotion(targetWs, durableIntent);
			durableIntent = null;
		} catch (error) {
			if (durableIntent && (error instanceof PromotionMessageNotSentError || error instanceof PromotionTargetRejectedError)) {
				await repository.clearHaPromotionIntent(durableIntent.promotion_id);
				durableIntent = null;
			}
			throw error;
		} finally {
			if (!durableIntent) {
				haPrimaryWriteBarrier.endPromotion();

				if (config.ha.role === "primary") {
					await this.broadcastHeartbeat().catch((error) => {
						Logger.warn("HA: failed to broadcast the cleared promotion fence; replicas will recover on the next heartbeat", { error });
					});
				}
			}
		}
	}

	async applyRoleChange(
		newPrimaryNodeId: string,
		newPrimaryUrl: string,
		newPrimaryAdminUrl: string,
		newEpoch: number,
		logContext: Record<string, unknown>,
	): Promise<boolean> {
		const becomingPrimary = newPrimaryNodeId === this.nodeId;
		const patch: Partial<HaClusterConfigInsert> = becomingPrimary
			? { role: "primary", primaryUrl: null, primaryAdminUrl: null, clusterEpoch: newEpoch }
			: { role: "replica", primaryUrl: newPrimaryUrl, primaryAdminUrl: newPrimaryAdminUrl, clusterEpoch: newEpoch };
		const persisted = await persistRoleChangeWithRetry(patch, { becomingPrimary, newPrimaryNodeId, ...logContext });
		if (!persisted) return false;
		if (becomingPrimary) {
		} else {
			config.ha.role = "replica";
			config.ha.primaryUrl = newPrimaryUrl;
			config.ha.primaryAdminUrl = newPrimaryAdminUrl;
			await deletePinnedHaCa();
		}
		config.ha.epoch = newEpoch;
		return true;
	}

	async activateElectionWinner(
		candidateNodeId: string,
		term: number,
		expectedPrimaryUrl: string | null,
		expectedPrimaryAdminUrl: string | null,
	): Promise<boolean> {
		if (candidateNodeId !== this.nodeId) {
			Logger.error("HA: refused to activate an election winner whose node id is not this process", {
				candidateNodeId,
				localNodeId: this.nodeId,
				term,
			});
			return false;
		}
		const persisted = await persistElectionWinnerWithRetry(term, candidateNodeId, expectedPrimaryUrl, expectedPrimaryAdminUrl);
		if (!persisted) return false;

		config.ha.epoch = term;
		return true;
	}

	private async handlePromote(message: PromoteMessage): Promise<void> {
		if (
			typeof message.promotionId !== "string" ||
			message.promotionId.length === 0 ||
			message.promotionId.length > 64 ||
			typeof message.newPrimaryNodeId !== "string" ||
			message.newPrimaryNodeId.length === 0 ||
			message.newPrimaryNodeId.length > 64 ||
			typeof message.newPrimaryUrl !== "string" ||
			message.newPrimaryUrl.length === 0 ||
			message.newPrimaryUrl.length > 2048 ||
			typeof message.newPrimaryAdminUrl !== "string" ||
			message.newPrimaryAdminUrl.length === 0 ||
			message.newPrimaryAdminUrl.length > 2048 ||
			!Number.isSafeInteger(message.newEpoch) ||
			message.newEpoch < config.ha.epoch
		) {
			Logger.error("HA: ignored a malformed or stale promotion message");
			return;
		}
		const becomingPrimary = message.newPrimaryNodeId === this.nodeId;
		Logger.warn(
			becomingPrimary
				? "HA: this node has been promoted to primary, restarting to apply"
				: "HA: the primary has changed, restarting to reconnect to the new one",
			{ newPrimaryNodeId: message.newPrimaryNodeId },
		);
		const persisted = await this.applyRoleChange(message.newPrimaryNodeId, message.newPrimaryUrl, message.newPrimaryAdminUrl, message.newEpoch, {
			promotionId: message.promotionId,
		});
		if (persisted) {
			if (becomingPrimary) {
				const ack: PromoteAppliedAckMessage = { type: "promote_applied_ack", promotionId: message.promotionId, success: true };
				try {
					this.replicaSocket?.send(JSON.stringify(ack));
				} catch (error) {
					Logger.warn("HA: primary role is durable but its acknowledgement could not be sent; the old primary will retain its recovery fence", {
						error,
						promotionId: message.promotionId,
					});
				}
			}
		} else {
			if (becomingPrimary) {
				const ack: PromoteAppliedAckMessage = {
					type: "promote_applied_ack",
					promotionId: message.promotionId,
					success: false,
					reason: "The target could not persist its primary role after repeated attempts",
				};
				try {
					this.replicaSocket?.send(JSON.stringify(ack));
				} catch (error) {
					Logger.warn("HA: failed to report that target activation was rejected", { error, promotionId: message.promotionId });
				}
				Logger.error("HA: refused promotion because this node could not persist its primary role; remaining a replica");
				return;
			}

			Logger.error("HA: failed to persist the new primary after several attempts - restarting this bystander on its previous configuration");
			notifyHaEvent(
				"ha_node_down",
				"critical",
				"This replica could not persist the new primary after repeated attempts - restarting with its old configuration instead",
				"replica",
			);
		}
		setTimeout(() => {
			void processLifecycle.gracefulRestart("ha-promote");
		}, 300);
	}

	private async broadcastAllPendingChanges(): Promise<void> {
		if (this.replicas.size === 0) return;
		for (;;) {
			const rows = await repository.changelogSince(this.lastBroadcastSeq, config.ha.changelogPageSize);
			if (rows.length === 0) return;
			for (const row of rows) {
				const message: ChangeMessage = { type: "change", row };
				const payload = JSON.stringify(message);
				for (const socket of this.replicas) socket.send(payload);
			}
			this.lastBroadcastSeq = rows[rows.length - 1]!.seq;
			if (rows.length < config.ha.changelogPageSize) return;
		}
	}

	private async broadcastNewChanges(): Promise<void> {
		try {
			if (config.ha.role !== "primary") return;

			this.expireStaleReplicaConnections();
			await this.broadcastAllPendingChanges();
			const now = Date.now();
			if (now - this.lastHeartbeatBroadcastAt >= HA_HEARTBEAT_INTERVAL_MS) {
				await this.broadcastHeartbeat();
			}
		} catch (error) {
			Logger.error("HA: failed to broadcast changelog rows to replicas", { error });
		}
	}

	async waitForMajorityDurability(timeoutMs = HA_MAJORITY_DURABILITY_TIMEOUT_MS): Promise<{ confirmed: boolean; seq: number }> {
		if (!config.ha.enabled || config.ha.role !== "primary") return { confirmed: true, seq: 0 };
		const members = await repository.haClusterMembers();
		if (members.length < config.ha.autoFailoverMinMembers) return { confirmed: true, seq: 0 };
		const seq = await repository.latestChangelogSeq();
		const majority = Math.floor(members.length / 2) + 1;
		const registeredNodeIds = new Set(members.map((member) => member.node_id));
		const deadline = Date.now() + timeoutMs;

		void this.broadcastNewChanges();
		for (;;) {
			if (1 + this.countMembersAckedAtLeast(seq, registeredNodeIds) >= majority) return { confirmed: true, seq };
			if (Date.now() >= deadline) return { confirmed: false, seq };
			await new Promise((resolve) => setTimeout(resolve, HA_MAJORITY_DURABILITY_POLL_MS));
		}
	}

	private countMembersAckedAtLeast(seq: number, registeredNodeIds: Set<string>): number {
		let count = 0;
		for (const node of this.nodes.values()) {
			if (registeredNodeIds.has(node.nodeId) && node.lastAckedSeq !== null && node.lastAckedSeq >= seq) count++;
		}
		return count;
	}

	private async waitForMembershipActivationDurability(
		oldMembers: HaClusterMemberRecord[],
		timeoutMs: number = MEMBERSHIP_ACTIVATION_DURABILITY_TIMEOUT_MS,
	): Promise<boolean> {
		const majority = Math.floor(oldMembers.length / 2) + 1;
		const registeredNodeIds = new Set(oldMembers.map((member) => member.node_id));
		const seq = await repository.latestChangelogSeq();
		const deadline = Date.now() + timeoutMs;
		void this.broadcastNewChanges();
		for (;;) {
			if (1 + this.countMembersAckedAtLeast(seq, registeredNodeIds) >= majority) return true;
			if (Date.now() >= deadline) return false;
			await new Promise((resolve) => setTimeout(resolve, HA_MAJORITY_DURABILITY_POLL_MS));
		}
	}

	private async broadcastHeartbeat(requireDelivery = false, promotionId?: string): Promise<void> {
		const heartbeat: HeartbeatMessage = {
			type: "heartbeat",
			latestSeq: await repository.latestChangelogSeq(),
			primaryFenced: config.ha.fencedForPromotion || !!config.ha.authorityFence || config.ha.quorumFenced,
			...(promotionId ? { promotionId } : {}),
		};
		const payload = JSON.stringify(heartbeat);
		for (const socket of this.replicas) {
			const sent = socket.send(payload);
			if (requireDelivery && sent === 0) {
				throw new Error("A connected replica could not accept the promotion-fence heartbeat");
			}
		}
		this.lastHeartbeatBroadcastAt = Date.now();
	}

	private async startReplica(): Promise<void> {
		this.electionWinnerActivating = false;
		this.disconnectedSince = Date.now();
		this.verifiedConnectionThisProcess = false;
		this.lastVerifiedSyncAt = 0;
		this.primaryAuthorityAmbiguous = false;
		this.cursor = await repository.replicationCursor();
		this.nodeId = await repository.haNodeId();

		this.hasBootstrapped = !(await repository.needsBootstrap());
		await this.startReplicaRedirectListener();
		Logger.info(`HA replica starting, connecting to primary at ${config.ha.primaryUrl}`);
		void this.connectToPrimary();
		this.relayDrainTimer = setInterval(() => void this.drainSessionRelayOutbox(), RELAY_DRAIN_INTERVAL_MS);
		unref(this.relayDrainTimer);
		this.heartbeatWatchdogTimer = setInterval(() => {
			this.checkHeartbeatWatchdog();
			void this.retryRuntimeConvergenceIfFenced();
		}, HA_HEARTBEAT_INTERVAL_MS);
		unref(this.heartbeatWatchdogTimer);
	}

	private checkHeartbeatWatchdog(): void {
		if (this.state !== "connected") return;
		if (Date.now() - this.lastVerifiedSyncAt <= HA_REPLICA_LIVENESS_TIMEOUT_MS) return;
		Logger.error(
			"HA: no heartbeat acknowledged from the primary within the liveness timeout - actively closing this connection instead of leaving it half-open",
			{
				lastVerifiedSyncAt: this.lastVerifiedSyncAt,
				timeoutMs: HA_REPLICA_LIVENESS_TIMEOUT_MS,
			},
		);
		const socket = this.replicaSocket;
		const reason = "no heartbeat received from the primary within the liveness timeout";

		this.handleReplicaClose({ code: 4000, reason });
		socket?.close(4000, reason);
	}

	private async startReplicaRedirectListener(): Promise<void> {
		const { cert, key } = await haTlsCertificate();
		this.server = Bun.serve<HaSocketData>({
			hostname: config.host,
			port: config.ha.port,
			tls: { cert, key },
			fetch: async (request, server) => {
				const identity = await authenticateHaRequest(request);
				if (!identity) return new Response("Unauthorized", { status: 401 });
				const pathname = new URL(request.url).pathname;
				if (pathname === "/_ha/vote-request" || pathname === "/_ha/who-is-primary" || pathname === "/_ha/announce-primary") {
					return await this.delegateToElectionService(request, identity);
				}
				if (pathname !== "/_ha/stream") return new Response("Not found", { status: 404 });
				if (server.upgrade(request, { data: { authenticatedNodeId: identity.nodeId, authenticatedActive: identity.active } })) return undefined;
				return new Response("Unable to upgrade", { status: 400 });
			},
			websocket: {
				open: (ws) => {
					if (!config.ha.primaryUrl || !config.ha.primaryAdminUrl) {
						ws.close(1011, "replica has no primary topology");
						return;
					}
					const redirect: PrimaryRedirectMessage = {
						type: "primary_redirect",
						primaryUrl: config.ha.primaryUrl,
						primaryAdminUrl: config.ha.primaryAdminUrl,
						epoch: config.ha.epoch,
					};
					ws.send(JSON.stringify(redirect));
					ws.close(1000, "primary moved");
				},
				message: () => {},
			},
		});
	}

	private async resolveCaCertificate(): Promise<string> {
		const pinned = await readPinnedHaCertificate();
		if (pinned) {
			Logger.info("HA: using the already-pinned primary certificate", { certificateFingerprintSha256: certificateFingerprint(pinned) });
			return pinned;
		}
		const url = new URL("/_burrowgate/api/admin/ha/certificate", config.ha.primaryAdminUrl!);
		const response = await fetch(url, {
			headers: { authorization: `Bearer ${config.ha.sharedToken}` },
			signal: AbortSignal.timeout(HA_FETCH_TIMEOUT_MS),
			tls: { rejectUnauthorized: false },
		});
		if (!response.ok) throw new Error(`Failed to fetch the primary's HA certificate (status ${response.status})`);
		const body = (await response.json()) as { cert?: string };
		if (!body.cert) throw new Error("Primary's HA certificate response was empty");
		await pinPrimaryHaCertificate(body.cert);
		Logger.info("HA: fetched and pinned the primary's certificate", { certificateFingerprintSha256: certificateFingerprint(body.cert) });
		return body.cert;
	}

	private tlsOptions(): { ca: string } | undefined {
		if (!this.caCertificate) return undefined;

		return { ca: this.caCertificate };
	}

	private async drainSessionRelayOutbox(): Promise<void> {
		if (this.state !== "connected" || !this.replicaSocket || this.replicaSocket.readyState !== WebSocket.OPEN) return;
		if (this.relayInFlightId !== null && Date.now() - this.relayInFlightSentAt < RELAY_ACK_TIMEOUT_MS) return;

		try {
			const rows = await repository.pendingSessionRelayRows(1);
			const row = rows[0];
			if (row && this.replicaSocket.readyState === WebSocket.OPEN) {
				const message: RelayMessage = {
					type: "relay",
					relayId: row.id,
					entityType: row.entity_type,
					entityId: row.entity_id,
					op: row.op,
					payloadJson: row.payload_json,
				};
				try {
					this.relayInFlightId = row.id;
					this.relayInFlightSentAt = Date.now();
					this.replicaSocket.send(JSON.stringify(message));
				} catch (error) {
					this.relayInFlightId = null;
					this.relayInFlightSentAt = 0;
					Logger.warn("HA: failed to relay a session event to the primary", { error });
				}
			}
		} catch (error) {
			Logger.error("HA: failed to drain the session relay outbox", { error });
		}
	}

	async waitForRelayPublication(entityType: MultiWriterEntityType, entityId: string, timeoutMs = RELAY_PUBLICATION_TIMEOUT_MS): Promise<void> {
		if (!config.ha.enabled || config.ha.role !== "replica") return;
		const deadline = Date.now() + timeoutMs;
		for (;;) {
			if (!(await repository.hasPendingSessionRelay(entityType, entityId))) return;
			if (Date.now() >= deadline) throw new Error("The HA primary did not acknowledge the new session before the publication deadline");
			void this.drainSessionRelayOutbox();
			await new Promise((resolve) => setTimeout(resolve, 25));
		}
	}

	private async handlePreparePromote(message: PreparePromoteMessage): Promise<void> {
		if (
			typeof message.promotionId !== "string" ||
			message.promotionId.length === 0 ||
			message.promotionId.length > 64 ||
			!Number.isSafeInteger(message.barrierSeq) ||
			message.barrierSeq < 0
		)
			return;
		const generation = this.connectionGeneration;
		const deadline = Date.now() + PREPARE_PROMOTE_DRAIN_TIMEOUT_MS;
		for (;;) {
			if (generation !== this.connectionGeneration) return;
			const pending = await repository.pendingSessionRelayRows(1);
			const caughtUpToBarrier = this.cursor >= message.barrierSeq;
			if (pending.length === 0 && this.relayInFlightId === null && caughtUpToBarrier) {
				const ack: PreparePromoteAckMessage = { type: "prepare_promote_ack", cursor: this.cursor, promotionId: message.promotionId };
				this.replicaSocket?.send(JSON.stringify(ack));
				return;
			}
			if (Date.now() >= deadline) {
				Logger.error(
					"HA: could not confirm this node was fully caught up and drained before a promotion request in time - not acking, the primary will abort the promotion",
					{ cursor: this.cursor, barrierSeq: message.barrierSeq, outboxDrained: pending.length === 0 && this.relayInFlightId === null },
				);
				return;
			}
			void this.drainSessionRelayOutbox();
			await new Promise((resolve) => setTimeout(resolve, 100));
		}
	}

	private async connectToPrimary(): Promise<void> {
		if (this.stopped) return;
		if (!this.caCertificate) {
			try {
				this.caCertificate = await this.resolveCaCertificate();
			} catch (error) {
				Logger.warn("HA: failed to obtain the primary's HA certificate, will retry", { error });
				this.scheduleReconnect();
				return;
			}
		}
		if (this.stopped) return;

		try {
			const streamUrl = new URL("/_ha/stream", config.ha.primaryUrl!);
			streamUrl.protocol = streamUrl.protocol === "https:" ? "wss:" : "ws:";
			Logger.info("HA: attempting to connect to primary", {
				url: streamUrl.href,
				pinnedCertificateFingerprintSha256: this.caCertificate ? certificateFingerprint(this.caCertificate) : "none (unpinned - plain TLS)",
			});
			const socket = new WebSocket(streamUrl, { headers: { authorization: `Bearer ${config.ha.sharedToken}` }, tls: this.tlsOptions() });
			this.replicaSocket = socket;

			this.messageQueue = Promise.resolve();

			this.connectionGeneration += 1;
			socket.addEventListener("open", () => {
				Logger.info("HA: connected to primary");
			});

			socket.addEventListener("message", (event) => this.handleIncomingMessage(event));
			socket.addEventListener("close", (event) => this.handleReplicaClose(event));
			socket.addEventListener("error", (event) => {
				Logger.warn("HA: connection to primary errored", { error: event });
			});
		} catch (error) {
			Logger.warn("HA: failed to open a connection to the primary, will retry", { error });
			this.scheduleReconnect();
		}
	}

	private handleReplicaClose(event: Pick<CloseEvent, "code" | "reason">): void {
		this.relayInFlightId = null;
		this.relayInFlightSentAt = 0;

		this.connectionGeneration += 1;
		const wasConnected = this.state === "connected";
		if (event.code === 1008) {
			this.state = "connection_rejected";
			Logger.error("HA: the primary refused this connection - this will keep failing until fixed, not just resolve on retry", {
				code: event.code,
				reason: event.reason,
			});
		} else {
			const standingFailure = ["key_mismatch", "version_mismatch", "epoch_mismatch", "connection_rejected"].includes(this.state);
			if (!standingFailure) {
				Logger.warn("HA: connection to primary closed", { code: event.code, reason: event.reason });
				this.reconnectDelayMs = config.ha.reconnectMinDelayMs;
				if (this.state !== "disconnected") {
					this.state = "disconnected";
					this.disconnectedSince = Date.now();
					if (wasConnected) notifyHaEvent("ha_node_down", "critical", "Lost connection to the HA primary", "primary");
				}
			}
		}

		if (event.code === 1015 && this.caCertificate) {
			Logger.warn("HA: TLS handshake with the primary failed while a certificate was pinned - clearing the pin so the next attempt fetches a fresh one");
			this.caCertificate = null;
			void deletePinnedHaCa();
		}
		this.scheduleReconnect();
	}

	private scheduleReconnect(): void {
		if (this.stopped || this.reconnectTimer) return;
		this.reconnectTimer = setTimeout(() => {
			this.reconnectTimer = null;
			void this.connectToPrimary();
		}, this.reconnectDelayMs);
		unref(this.reconnectTimer);
		this.reconnectDelayMs = Math.min(this.reconnectDelayMs * 2, config.ha.reconnectMaxDelayMs);
	}

	private handleIncomingMessage(event: MessageEvent): void {
		let parsed: { type?: unknown } | undefined;
		try {
			parsed = JSON.parse(String(event.data)) as { type?: unknown };
		} catch {
			parsed = undefined;
		}
		if (parsed?.type === "prepare_promote") {
			void this.handlePreparePromote(parsed as PreparePromoteMessage);
			return;
		}

		const generation = this.connectionGeneration;
		this.messageQueue = this.messageQueue.then(() => this.handleMessage(event, generation));
	}

	private async handleMessage(event: MessageEvent, generation: number): Promise<void> {
		if (generation !== this.connectionGeneration) return;
		let message: StreamMessage;
		try {
			message = JSON.parse(String(event.data)) as StreamMessage;
		} catch {
			return;
		}
		if (message.type === "hello") {
			await this.handleHello(message);
			return;
		}
		if (message.type === "master_key") {
			await this.handleMasterKeyProvisioned(message);
			return;
		}

		if (
			message.type === "relay" ||
			message.type === "announce" ||
			message.type === "request_master_key" ||
			message.type === "cursor" ||
			message.type === "prepare_promote_ack" ||
			message.type === "promote_applied_ack" ||
			message.type === "prepare_promote"
		)
			return;
		if (message.type === "relay_ack") {
			try {
				await repository.deleteSessionRelayRows([message.relayId]);
				if (this.relayInFlightId === message.relayId) {
					this.relayInFlightId = null;
					this.relayInFlightSentAt = 0;
					void this.drainSessionRelayOutbox();
				}
			} catch (error) {
				this.relayInFlightSentAt = 0;
				Logger.warn("HA: failed to clear an acked relay outbox row, will resend harmlessly", { error, relayId: message.relayId });
			}
			return;
		}
		if (message.type === "relay_reject") {
			Logger.error(
				"HA: a relayed session event was permanently rejected by the primary - this replica's local state has diverged, forcing a full re-bootstrap to reconcile it",
				{ relayId: message.relayId, reason: message.reason },
			);
			try {
				await repository.deleteSessionRelayRows([message.relayId]);
			} catch (error) {
				Logger.warn("HA: failed to clear a rejected relay outbox row, will resend harmlessly", { error, relayId: message.relayId });
			} finally {
				if (this.relayInFlightId === message.relayId) {
					this.relayInFlightId = null;
					this.relayInFlightSentAt = 0;
				}
			}
			await this.forceRebootstrapNow();

			this.connectionGeneration += 1;
			this.replicaSocket?.close(4000, "local state diverged from a rejected relay - reconnecting for a fresh snapshot");
			return;
		}
		if (message.type === "promote") {
			this.primaryAuthorityAmbiguous = true;
			await this.handlePromote(message);
			return;
		}
		if (message.type === "primary_redirect") {
			await this.handlePrimaryRedirect(message);
			return;
		}
		if (message.type === "heartbeat") {
			if (!Number.isSafeInteger(message.latestSeq) || message.latestSeq < 0 || this.state !== "connected") return;

			this.lastHeartbeatLatestSeq = message.latestSeq;
			this.primaryAuthorityAmbiguous = message.primaryFenced === true;
			if (message.primaryFenced === true && typeof message.promotionId === "string" && message.promotionId.length > 0 && message.promotionId.length <= 64) {
				const ack: PromotionFenceAckMessage = { type: "promotion_fence_ack", promotionId: message.promotionId };
				this.replicaSocket?.send(JSON.stringify(ack));
			}
			try {
				if (message.latestSeq > this.cursor) await this.runCatchUp();
				if (this.cursor < message.latestSeq) throw new Error(`HA heartbeat is ahead of the local replication cursor (${message.latestSeq} > ${this.cursor})`);
				this.lastVerifiedSyncAt = Date.now();

				this.sendCursorUpdate();
			} catch (error) {
				Logger.error("HA: failed to catch up to the primary heartbeat, reconnecting", {
					error,
					latestSeq: message.latestSeq,
					cursor: this.cursor,
				});
				this.connectionGeneration += 1;
				this.replicaSocket?.close();
			}
			return;
		}

		if (message.type === "promotion_fence_ack") return;
		if (this.state !== "connected") return;
		if (message.row.seq <= this.cursor) return;

		try {
			if (message.row.seq > this.cursor + 1) {
				await this.runCatchUp();
				return;
			}
			await this.applyRow(message.row);
		} catch (error) {
			Logger.error("HA: failed to apply a replicated change, reconnecting", { error, seq: message.row.seq });

			this.connectionGeneration += 1;
			this.replicaSocket?.close();
		}
	}

	private async handlePrimaryRedirect(message: PrimaryRedirectMessage): Promise<void> {
		if (
			typeof message.primaryUrl !== "string" ||
			message.primaryUrl.length === 0 ||
			message.primaryUrl.length > 2048 ||
			typeof message.primaryAdminUrl !== "string" ||
			message.primaryAdminUrl.length === 0 ||
			message.primaryAdminUrl.length > 2048 ||
			!Number.isSafeInteger(message.epoch) ||
			message.epoch < config.ha.epoch
		)
			return;
		let meshUrl: URL;
		let adminUrl: URL;
		try {
			meshUrl = new URL(message.primaryUrl);
			adminUrl = new URL(message.primaryAdminUrl);
		} catch {
			return;
		}
		if (!isSecureHaUrl(meshUrl.href) || !isSecureHaUrl(adminUrl.href)) return;
		if (message.primaryUrl === config.ha.primaryUrl && message.primaryAdminUrl === config.ha.primaryAdminUrl) {
			Logger.error("HA: a replica redirected this node back to the same non-primary address; refusing a topology loop");
			this.state = "epoch_mismatch";
			return;
		}
		await this.adoptDiscoveredPrimary(
			message.primaryUrl,
			message.primaryAdminUrl,
			message.epoch,
			"learned that the primary moved from the former primary",
			"ha-primary-redirect",
		);
	}

	async adoptDiscoveredPrimary(
		primaryUrl: string,
		primaryAdminUrl: string,
		epoch: number,
		reason: string,
		restartReason = "ha-primary-discovered",
	): Promise<boolean> {
		if (!isSecureHaUrl(primaryUrl) || !isSecureHaUrl(primaryAdminUrl)) {
			Logger.error("HA: refused to adopt a primary topology containing a non-HTTPS or credential-bearing URL", {
				primaryUrl,
				primaryAdminUrl,
				epoch,
			});
			return false;
		}
		this.primaryAuthorityAmbiguous = true;

		const { adopted, forcedFreshBootstrap } = await repository.adoptHaDiscoveredPrimary({ primaryUrl, primaryAdminUrl, clusterEpoch: epoch });
		if (!adopted) {
			Logger.warn("HA: ignored a discovered primary because a newer cluster epoch was persisted concurrently", {
				primaryUrl,
				primaryAdminUrl,
				reportedEpoch: epoch,
			});
			return false;
		}
		config.ha.role = "replica";
		config.ha.primaryUrl = primaryUrl;
		config.ha.primaryAdminUrl = primaryAdminUrl;
		config.ha.epoch = epoch;
		config.ha.authorityFence = null;
		config.ha.quorumFenced = false;
		config.ha.electionInProgress = false;
		haPrimaryWriteBarrier.endPromotion();
		this.caCertificate = null;
		await deletePinnedHaCa();
		if (forcedFreshBootstrap) {
			this.hasBootstrapped = false;
			Logger.warn(
				"HA: this node was itself primary before adopting a newer one - forcing a full fresh snapshot to reconcile any local writes the new primary never received",
				{
					primaryUrl,
					primaryAdminUrl,
					epoch,
				},
			);
		}
		Logger.warn(`HA: ${reason}, restarting to reconnect`, { primaryUrl, primaryAdminUrl, epoch });
		setTimeout(() => void processLifecycle.gracefulRestart(restartReason), 300);
		return true;
	}

	private async handleHello(message: HelloMessage): Promise<void> {
		this.primaryAuthorityAmbiguous = message.primaryFenced === true;
		if (message.version !== APP_VERSION) {
			this.state = "version_mismatch";
			this.nodeId ??= await repository.haNodeId();
			const announce: AnnounceMessage = {
				type: "announce",
				nodeId: this.nodeId,
				name: config.ha.nodeName,
				version: APP_VERSION,
				adminUrl: config.ha.selfAdminUrl ?? "",
				epoch: config.ha.epoch,
			};

			this.replicaSocket?.send(JSON.stringify(announce));
			Logger.error("HA: primary and replica versions differ; refusing replication until every cluster node runs the same version", {
				primaryVersion: typeof message.version === "string" ? message.version : "unknown",
				replicaVersion: APP_VERSION,
			});
			return;
		}

		if (message.epoch < config.ha.epoch) {
			this.state = "epoch_mismatch";
			this.nodeId ??= await repository.haNodeId();
			const announce: AnnounceMessage = {
				type: "announce",
				nodeId: this.nodeId,
				name: config.ha.nodeName,
				version: APP_VERSION,
				adminUrl: config.ha.selfAdminUrl ?? "",
				epoch: config.ha.epoch,
			};

			this.replicaSocket?.send(JSON.stringify(announce));
			Logger.error("HA: this primary's cluster epoch is older than one already seen - it may not know it was demoted, refusing to trust it", {
				primaryEpoch: message.epoch,
				knownEpoch: config.ha.epoch,
			});
			return;
		}

		if (message.epoch > config.ha.epoch) {
			config.ha.epoch = message.epoch;
			await repository
				.updateHaClusterConfig({ clusterEpoch: message.epoch })
				.catch((error) => Logger.warn("HA: failed to persist the primary's newer cluster epoch, will retry on the next connection", { error }));
		}

		if (!hasOperatorConfiguredMasterKey() && (await repository.needsBootstrap())) {
			const request: RequestMasterKeyMessage = { type: "request_master_key" };
			this.replicaSocket?.send(JSON.stringify(request));
			return;
		}
		try {
			const plaintext = await decryptSecret(message.keyCheck);
			if (plaintext !== MASTER_KEY_CHECK_PLAINTEXT) throw new Error("mismatch");
		} catch {
			this.state = "key_mismatch";
			Logger.error("HA: BG_MASTER_KEY on this node does not match the primary's - refusing to apply replicated changes until it's fixed");
			this.replicaSocket?.close(4000, "master key mismatch");
			return;
		}
		await this.proceedAfterKeyVerified();
	}

	private async handleMasterKeyProvisioned(message: MasterKeyMessage): Promise<void> {
		try {
			await installMasterKeyFromPrimary(message.key, async (encryptWithNewKey) => {
				if (config.ha.sharedToken) {
					await repository.updateHaClusterConfig({ sharedTokenEncrypted: await encryptWithNewKey(config.ha.sharedToken) });
				}
			});
			Logger.info("HA: received and installed the master key from the primary");
		} catch (error) {
			Logger.error("HA: failed to install the master key received from the primary", { error });
			this.state = "key_mismatch";
			this.replicaSocket?.close(4000, "failed to install provisioned master key");
			return;
		}
		await this.proceedAfterKeyVerified();
	}

	private async proceedAfterKeyVerified(): Promise<void> {
		try {
			if (await repository.needsBootstrap()) await this.bootstrapSnapshot();
			await this.runCatchUp();

			if (this.electionWinnerActivating) {
				this.replicaSocket?.close(1000, "automatic-election winner is activating");
				return;
			}
			const wasDisconnected = this.state === "disconnected";
			this.verifiedPrimaryConnectionGeneration += 1;
			this.state = "connected";
			this.disconnectedSince = 0;
			this.verifiedConnectionThisProcess = true;
			this.lastVerifiedSyncAt = Date.now();
			this.nodeId ??= await repository.haNodeId();
			const announce: AnnounceMessage = {
				type: "announce",
				nodeId: this.nodeId,
				name: config.ha.nodeName,
				version: APP_VERSION,
				adminUrl: config.ha.selfAdminUrl ?? "",
				epoch: config.ha.epoch,
			};
			this.replicaSocket?.send(JSON.stringify(announce));
			this.sendCursorUpdate();
			void this.drainSessionRelayOutbox();
			if (wasDisconnected) notifyHaEvent("ha_node_up", "info", "Reconnected to the HA primary", "primary");
		} catch (error) {
			Logger.error("HA: catch-up from primary failed", { error });
			this.connectionGeneration += 1;
			this.replicaSocket?.close();
		}
	}

	private async fetchChangelogPage(since: number): Promise<{ rows: ReplicationChangelogRow[]; latestSeq: number }> {
		const url = new URL("/_ha/changelog", config.ha.primaryUrl!);
		url.searchParams.set("since", String(since));
		const response = await fetch(url, {
			headers: { authorization: `Bearer ${config.ha.sharedToken}` },
			tls: this.tlsOptions(),
			signal: AbortSignal.timeout(HA_FETCH_TIMEOUT_MS),
		});
		if (!response.ok) throw new Error(`HA changelog pull failed with status ${response.status}`);
		return (await response.json()) as { rows: ReplicationChangelogRow[]; latestSeq: number };
	}

	private async runCatchUp(): Promise<void> {
		for (;;) {
			const page = await this.fetchChangelogPage(this.cursor);

			const visibleGap = page.rows.length > 0 && page.rows[0]!.seq > this.cursor + 1;
			const invisibleGap = page.rows.length === 0 && page.latestSeq > this.cursor;
			if (visibleGap || invisibleGap) {
				Logger.warn("HA: catch-up hit a gap the changelog can no longer fill (likely pruned), re-bootstrapping from a snapshot", {
					cursor: this.cursor,
					oldestSurvivingSeq: page.rows[0]?.seq ?? null,
					latestSeq: page.latestSeq,
				});
				await this.bootstrapSnapshot();
				return;
			}
			for (const row of page.rows) await this.applyRow(row);
			if (page.rows.length < config.ha.changelogPageSize) break;
		}
	}

	private async bootstrapSnapshot(): Promise<void> {
		if (this.bootstrapInFlight) return this.bootstrapInFlight;
		this.bootstrapInFlight = this.performBootstrapSnapshot().finally(() => {
			this.bootstrapInFlight = null;
		});
		return this.bootstrapInFlight;
	}

	private async performBootstrapSnapshot(): Promise<void> {
		const url = new URL("/_ha/snapshot", config.ha.primaryUrl!);

		const headersController = new AbortController();
		const headersTimeout = setTimeout(() => headersController.abort(), HA_FETCH_TIMEOUT_MS);
		let response: Response;
		try {
			response = await fetch(url, {
				headers: { authorization: `Bearer ${config.ha.sharedToken}`, accept: "application/x-ndjson" },
				tls: this.tlsOptions(),
				signal: headersController.signal,
			});
		} finally {
			clearTimeout(headersTimeout);
		}
		if (!response.ok) throw new Error(`HA snapshot pull failed with status ${response.status}`);
		let seq: number;
		let rowCount: number;
		if (response.headers.get("content-type")?.includes("application/x-ndjson")) {
			({ seq, rowCount } = await this.consumeSnapshotStream(response));
		} else {
			const body = (await response.json()) as { seq: number; rows: ReplicationSnapshotRow[] };
			await repository.reconcileToSnapshot(body.rows);
			seq = body.seq;
			rowCount = body.rows.length;
		}
		await repository.updateReplicationCursor(seq);
		await repository.markBootstrapped(seq);
		this.cursor = seq;
		this.hasBootstrapped = true;
		this.sendCursorUpdate();

		await this.recordRuntimeConvergenceOutcome(await this.refreshAllRuntimeState());
		Logger.info(`HA: applied a full snapshot (${rowCount} rows), resuming from seq ${seq}`);
	}

	private async consumeSnapshotStream(response: Response): Promise<{ seq: number; rowCount: number }> {
		if (!response.body) throw new Error("HA snapshot response body was empty");
		const snapshotId = crypto.randomUUID();
		const reader = response.body.getReader();
		const decoder = new TextDecoder();
		let buffer = "";
		let seq: number | null = null;
		let rowCount = 0;
		let stagedCount = 0;
		let batch: ReplicationSnapshotRow[] = [];
		const flush = async () => {
			if (batch.length === 0) return;
			await repository.stageSnapshotRows(snapshotId, stagedCount, batch);
			stagedCount += batch.length;
			batch = [];
		};
		const consumeLine = async (line: string) => {
			if (!line.trim()) return;
			const message = JSON.parse(line) as { type?: unknown; seq?: unknown; row?: ReplicationSnapshotRow };
			if (message.type === "meta") {
				if (!Number.isSafeInteger(message.seq) || Number(message.seq) < 0) throw new Error("HA snapshot metadata contained an invalid sequence");
				seq = Number(message.seq);
				return;
			}
			if (message.type !== "row" || !message.row || seq === null) throw new Error("HA snapshot stream contained an invalid or out-of-order record");
			batch.push(message.row);
			rowCount += 1;
			if (batch.length >= config.ha.changelogPageSize) await flush();
		};
		await repository.clearSnapshotStaging();
		try {
			for (;;) {
				const { done, value } = await readWithIdleTimeout(reader, HA_FETCH_TIMEOUT_MS);
				if (done) break;
				buffer += decoder.decode(value, { stream: true });
				for (;;) {
					const newline = buffer.indexOf("\n");
					if (newline < 0) break;
					const line = buffer.slice(0, newline);
					buffer = buffer.slice(newline + 1);
					await consumeLine(line);
				}
			}
			buffer += decoder.decode();
			if (buffer.trim()) await consumeLine(buffer);
			await flush();
			if (seq === null) throw new Error("HA snapshot stream did not contain metadata");
			await repository.reconcileStagedSnapshot(snapshotId);
			return { seq, rowCount };
		} catch (error) {
			await reader.cancel(error).catch(() => undefined);
			await repository.clearSnapshotStaging(snapshotId).catch(() => undefined);
			throw error;
		} finally {
			reader.releaseLock();
		}
	}

	private async applyRow(row: ReplicationChangelogRow): Promise<void> {
		if (row.seq <= this.cursor) return;
		try {
			await repository.applyReplicatedChange(row, this.nodeId ?? undefined);
		} catch (error) {
			await this.recordApplyFailureAndMaybeForceRebootstrap(row.seq);
			throw error;
		}
		this.consecutiveApplyFailureSeq = null;
		this.consecutiveApplyFailureCount = 0;
		await repository.updateReplicationCursor(row.seq);
		this.cursor = Math.max(this.cursor, row.seq);
		this.sendCursorUpdate();
		await this.recordRuntimeConvergenceOutcome(await this.invalidateForReplicatedRow(row.entity_type, row.entity_id));
	}

	private async recordApplyFailureAndMaybeForceRebootstrap(seq: number): Promise<void> {
		if (this.consecutiveApplyFailureSeq === seq) {
			this.consecutiveApplyFailureCount += 1;
		} else {
			this.consecutiveApplyFailureSeq = seq;
			this.consecutiveApplyFailureCount = 1;
		}
		if (this.consecutiveApplyFailureCount < APPLY_FAILURE_REBOOTSTRAP_THRESHOLD) return;
		Logger.error(
			`HA: seq ${seq} has failed to apply ${this.consecutiveApplyFailureCount} times in a row - forcing a full re-bootstrap on the next connection instead of retrying it again`,
			{ seq, attempts: this.consecutiveApplyFailureCount },
		);
		this.consecutiveApplyFailureSeq = null;
		this.consecutiveApplyFailureCount = 0;
		await this.forceRebootstrapNow();
	}

	private async forceRebootstrapNow(): Promise<void> {
		await repository
			.forceRebootstrap()
			.then(() => {
				this.hasBootstrapped = false;
			})
			.catch((error) => Logger.error("HA: failed to force a re-bootstrap", { error }));
	}

	private sendCursorUpdate(): void {
		if (this.replicaSocket?.readyState !== WebSocket.OPEN) return;
		const message: CursorMessage = { type: "cursor", seq: this.cursor };
		this.replicaSocket.send(JSON.stringify(message));
	}

	private async invalidateForReplicatedRow(entityType: ReplicatedEntityType, entityId: string): Promise<boolean> {
		let succeeded = true;
		const fail = (error: unknown, message: string, extra?: Record<string, unknown>): void => {
			succeeded = false;
			Logger.error(`HA: ${message}`, { error, ...extra });
		};
		if (entityType === "certificate" || entityType === "site_tls_settings" || entityType === "site") {
			await requestTlsReload().catch((error) => fail(error, "failed to reload the TLS listener after a replicated change"));
		}
		if (entityType === "ip_rule" || entityType === "country_rule" || entityType === "asn_rule") {
			invalidateAllNetworkPolicy();
		}
		if (entityType === "route_ip_rule" || entityType === "route_country_rule" || entityType === "route_asn_rule") {
			invalidateAllRouteNetworkPolicy();
		}
		if (entityType === "route_policy") {
			invalidateAllRoutePolicyCache();
		}
		if (entityType === "site_origin" || entityType === "site") {
			await loadBalancer.initialize().catch((error) => fail(error, "failed to refresh the load balancer's origin map after a replicated change"));

			await originHealthManager.initialize().catch((error) => fail(error, "failed to refresh origin health checks after a replicated change"));
			staticAssetCache.purge({});
		}
		if (entityType === "stream") {
			const stream = await repository.streamById(entityId);
			if (stream) {
				await streamProxyManager.apply(stream).catch((error) => fail(error, "failed to apply a replicated stream", { entityId }));
			} else {
				await streamProxyManager.remove(entityId).catch((error) => fail(error, "failed to remove a replicated stream", { entityId }));
			}
			await streamHealthManager.refresh(entityId).catch((error) => fail(error, "failed to refresh stream health checks after a replicated change"));
		}
		if (entityType === "stream_ip_rule" || entityType === "stream_country_rule" || entityType === "stream_asn_rule") {
			invalidateAllStreamNetworkPolicy();
		}
		return succeeded;
	}

	private async refreshAllRuntimeState(): Promise<boolean> {
		let succeeded = true;
		const fail = (error: unknown, message: string): void => {
			succeeded = false;
			Logger.error(`HA: ${message}`, { error });
		};
		await requestTlsReload().catch((error) => fail(error, "failed to reload the TLS listener after a snapshot"));
		invalidateAllNetworkPolicy();
		invalidateAllRouteNetworkPolicy();
		invalidateAllRoutePolicyCache();
		await loadBalancer.initialize().catch((error) => fail(error, "failed to refresh the load balancer's origin map after a snapshot"));
		await originHealthManager.initialize().catch((error) => fail(error, "failed to refresh origin health checks after a snapshot"));
		staticAssetCache.purge({});
		invalidateAllStreamNetworkPolicy();
		try {
			const currentIds = new Set((await repository.allStreams()).map((stream) => stream.id));
			for (const status of streamProxyManager.statusesView()) {
				if (!currentIds.has(status.id)) await streamProxyManager.remove(status.id);
			}
			await streamProxyManager.start();
			await streamHealthManager.initialize();
		} catch (error) {
			fail(error, "failed to refresh stream runtime state after a snapshot");
		}
		return succeeded;
	}

	private runtimeConvergenceFenced = false;
	private consecutiveRuntimeConvergenceFailures = 0;

	private async recordRuntimeConvergenceOutcome(succeeded: boolean): Promise<void> {
		if (succeeded) {
			if (this.runtimeConvergenceFenced) {
				Logger.warn("HA: live runtime state reconciled with the database again - clearing the convergence fence");
				notifyHaEvent("ha_node_up", "info", "This node's runtime state (TLS/routing/streams/health checks) reconciled with its database again", "replica");
			}
			this.runtimeConvergenceFenced = false;
			this.consecutiveRuntimeConvergenceFailures = 0;
			return;
		}
		this.consecutiveRuntimeConvergenceFailures += 1;
		if (!this.runtimeConvergenceFenced) {
			this.runtimeConvergenceFenced = true;
			Logger.error(
				"HA: replicated database state applied but refreshing live runtime state (TLS/routing/streams/health checks) failed - marking this node unhealthy until it reconciles",
				{ consecutiveFailures: this.consecutiveRuntimeConvergenceFailures },
			);
			notifyHaEvent(
				"ha_node_down",
				"critical",
				"This node's database is up to date but its live runtime state (TLS/routing/streams/health checks) failed to refresh - marked unhealthy",
				"replica",
			);
		}
		if (this.consecutiveRuntimeConvergenceFailures < RUNTIME_CONVERGENCE_RESTART_THRESHOLD) return;
		Logger.error("HA: runtime convergence kept failing after repeated automatic retries - restarting to force every subsystem to re-initialize fresh", {
			consecutiveFailures: this.consecutiveRuntimeConvergenceFailures,
		});
		this.consecutiveRuntimeConvergenceFailures = 0;
		setTimeout(() => void processLifecycle.gracefulRestart("ha-runtime-convergence-failure"), 300);
	}

	private async retryRuntimeConvergenceIfFenced(): Promise<void> {
		if (!this.runtimeConvergenceFenced) return;
		await this.recordRuntimeConvergenceOutcome(await this.refreshAllRuntimeState());
	}
}

export const haMeshService = new HaMeshService();

export async function withDurability<T extends object>(data: T): Promise<T & { durabilityConfirmed: boolean }> {
	const { confirmed } = await haMeshService.waitForMajorityDurability();
	return { ...data, durabilityConfirmed: confirmed };
}
