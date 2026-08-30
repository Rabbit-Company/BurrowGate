import { config, type HaRole } from "../config.ts";
import { MEMBERSHIP_SHRINK_GRACE_MS } from "../ha-timing.ts";
import { haPrimaryWriteBarrier } from "../services/ha-write-barrier.ts";
import { db } from "./client.ts";
import type { TransactionSQL } from "bun";
import type {
	IpRuleAction,
	AccessUserRecord,
	AccessSessionRecord,
	AcmeAccountRecord,
	AcmeHttpChallengeRecord,
	AdminAccessLevel,
	AdminAuditLogRecord,
	AdminRecoveryCodeRecord,
	AdminSessionRecord,
	AdminSsoSettingsRecord,
	AdminUserRecord,
	AdminUserSitePermissionRecord,
	AdminUserStreamPermissionRecord,
	AdminWebauthnCredentialRecord,
	AccessWebauthnCredentialRecord,
	CertificateEventRecord,
	CertificateRecord,
	ChallengeFlowRecord,
	CountryRuleRecord,
	AsnRuleRecord,
	ChallengeStepRecord,
	DnsProviderRecord,
	FirewallSyncProviderRecord,
	FirewallSyncStatus,
	FirewallSyncWhitelistCidrRecord,
	IpRuleRecord,
	RequestEventRecord,
	RoutePolicyRecord,
	RouteIpRuleRecord,
	RouteCountryRuleRecord,
	RouteAsnRuleRecord,
	SiteRecord,
	SiteAccessSettingsRecord,
	SiteSsoSettingsRecord,
	SiteTlsSettingsRecord,
	BandwidthMinuteRecord,
	StreamRecord,
	StreamEventRecord,
	StreamBandwidthMinuteRecord,
	StreamProtocol,
	StreamEventType,
	StreamRuleAction,
	StreamIpRuleRecord,
	StreamCountryRuleRecord,
	StreamAsnRuleRecord,
	OriginHealthStatusRecord,
	OriginHealthEventRecord,
	NotificationEventRecord,
	NotificationEventType,
	NotificationOutboxRecord,
	NotificationOutboxStatus,
	NotificationEventWithDeliveryRecord,
	PendingNotificationDeliveryRecord,
	PendingChangeEntityType,
	PendingChangeRecord,
	PendingChangeStatus,
	SiteOriginRecord,
	OriginBackendHealthStatusRecord,
	OriginBackendHealthEventRecord,
	LatencyCheckResult,
	SystemMetricSample,
} from "../types.ts";

export type SortDirection = "asc" | "desc";

export interface PageResult<T> {
	items: T[];
	page: number;
	pageSize: number;
	total: number;
	totalPages: number;
}

export interface EventQuery {
	siteId?: string | string[];
	originId?: string;
	page: number;
	pageSize: number;
	search?: string;
	decision?: string;
	cacheStatus?: "hit" | "miss" | "bypass";
	protectionStatus?: "clean" | "monitored" | "blocked";
	method?: string;
	statusGroup?: "1xx" | "2xx" | "3xx" | "4xx" | "5xx";
	countryCode?: string;
	asn?: number;
	since?: number;
	until?: number;
	sortBy: "created_at" | "ip" | "country_code" | "asn" | "method" | "path" | "status" | "decision" | "cache_status" | "protection_status" | "latency_ms";
	sortDirection: SortDirection;
}

export interface SessionQuery {
	siteId?: string | string[];
	page: number;
	pageSize: number;
	search?: string;
	state?: "active" | "expired" | "revoked";
	countryCode?: string;
	asn?: number;
	since?: number;
	until?: number;
	sortBy: "last_seen_at" | "created_at" | "expires_at" | "request_count" | "last_ip" | "country_code" | "asn";
	sortDirection: SortDirection;
}

export interface RuleQuery {
	siteId: string;
	page: number;
	pageSize: number;
	search?: string;
	action?: IpRuleAction;
	state?: "active" | "expired";
	sortBy: "created_at" | "expires_at" | "network_cidr" | "action";
	sortDirection: SortDirection;
}

export interface AuditLogQuery {
	page: number;
	pageSize: number;
	search?: string;
	actorUserId?: string;
	action?: string;
	resourceType?: string;
	resourceId?: string;
	since?: number;
	until?: number;
	sortBy: "created_at" | "action" | "actor_username" | "resource_type";
	sortDirection: SortDirection;
}

export interface StreamRuleQuery {
	streamId: string;
	page: number;
	pageSize: number;
	search?: string;
	action?: StreamRuleAction;
	state?: "active" | "expired";
	sortBy: "created_at" | "expires_at" | "network_cidr" | "action";
	sortDirection: SortDirection;
}

export interface NotificationQuery {
	siteId: string;
	page: number;
	pageSize: number;
	search?: string;
	type?: NotificationEventType;
	status?: NotificationOutboxStatus;
	sortBy: "created_at" | "occurred_at" | "type" | "status";
	sortDirection: SortDirection;
}

export interface StreamNotificationQuery {
	streamId: string;
	page: number;
	pageSize: number;
	search?: string;
	type?: NotificationEventType;
	status?: NotificationOutboxStatus;
	sortBy: "created_at" | "occurred_at" | "type" | "status";
	sortDirection: SortDirection;
}

export interface BandwidthIpQuery {
	siteId: string | string[] | undefined;
	page: number;
	pageSize: number;
	search?: string;
	countryCode?: string;
	protocol?: "http" | "websocket";
	since: number;
	until: number;
	sortBy:
		| "ip"
		| "country_code"
		| "client_received_bytes"
		| "client_sent_bytes"
		| "upstream_sent_bytes"
		| "upstream_received_bytes"
		| "client_total_bytes"
		| "upstream_total_bytes";
	sortDirection: SortDirection;
}

export interface BandwidthIpRow {
	ip: string;
	country_code: string;
	client_received_bytes: number | string;
	client_sent_bytes: number | string;
	upstream_sent_bytes: number | string;
	upstream_received_bytes: number | string;
	client_total_bytes: number | string;
	upstream_total_bytes: number | string;
}

export interface StreamEventQuery {
	streamId?: string | string[];
	page: number;
	pageSize: number;
	search?: string;
	protocol?: StreamProtocol;
	eventType?: StreamEventType;
	countryCode?: string;
	asn?: number;
	since: number;
	until: number;
	sortBy:
		| "created_at"
		| "event_type"
		| "protocol"
		| "incoming_port"
		| "client_ip"
		| "country_code"
		| "asn"
		| "reason"
		| "protection_rule_id"
		| "connection_id"
		| "client_to_upstream_bytes"
		| "upstream_to_client_bytes";
	sortDirection: SortDirection;
}

export interface StreamBandwidthQuery {
	streamId?: string | string[];
	page: number;
	pageSize: number;
	search?: string;
	protocol?: StreamProtocol;
	countryCode?: string;
	since: number;
	until: number;
	sortBy: "protocol" | "incoming_port" | "ip" | "country_code" | "client_to_upstream_bytes" | "upstream_to_client_bytes" | "total_bytes";
	sortDirection: SortDirection;
}

export interface StreamBandwidthRow {
	stream_id: string;
	incoming_port: number | string;
	ip: string;
	country_code: string;
	protocol: StreamProtocol;
	client_to_upstream_bytes: number | string;
	upstream_to_client_bytes: number | string;
	total_bytes: number | string;
}

export interface TrafficMetricPoint {
	bucket: number;
	requests: number;
	blocked: number;
	errors: number;
	averageLatency: number;
}

export interface CacheMetricPoint {
	bucket: number;
	hits: number;
	misses: number;
	bypasses: number;
	hitRatio: number;
}

export function fillCacheMetricSeries(rows: CacheMetricPoint[], startBucket: number, endTime: number, bucketMs: number): CacheMetricPoint[] {
	const firstBucket = Math.floor(startBucket / bucketMs) * bucketMs;
	const endBucket = Math.floor(endTime / bucketMs) * bucketMs;
	const byBucket = new Map(rows.map((row) => [row.bucket, row]));
	const completed: CacheMetricPoint[] = [];
	for (let bucket = firstBucket; bucket <= endBucket; bucket += bucketMs) {
		completed.push(byBucket.get(bucket) ?? { bucket, hits: 0, misses: 0, bypasses: 0, hitRatio: 0 });
	}
	return completed;
}

export function fillTrafficMetricSeries(rows: TrafficMetricPoint[], startBucket: number, endTime: number, bucketMs: number): TrafficMetricPoint[] {
	const firstBucket = Math.floor(startBucket / bucketMs) * bucketMs;
	const endBucket = Math.floor(endTime / bucketMs) * bucketMs;
	const byBucket = new Map(rows.map((row) => [row.bucket, row]));
	const completed: TrafficMetricPoint[] = [];
	for (let bucket = firstBucket; bucket <= endBucket; bucket += bucketMs) {
		completed.push(
			byBucket.get(bucket) ?? {
				bucket,
				requests: 0,
				blocked: 0,
				errors: 0,
				averageLatency: 0,
			},
		);
	}
	return completed;
}

function metricBucketExpression(column: "created_at" | "expires_at" | "revoked_at" | "bucket_start", bucketMs: number) {
	const safeColumn = db.unsafe(column);
	return config.databaseUrl.startsWith("mysql://") || config.databaseUrl.startsWith("mariadb://")
		? db`FLOOR(${safeColumn} / ${bucketMs})`
		: db`CAST(${safeColumn} / ${bucketMs} AS BIGINT)`;
}

function emptyMetricPoints<T extends { bucket: number }>(startBucket: number, endTime: number, bucketMs: number, factory: (bucket: number) => T): T[] {
	const firstBucket = Math.floor(startBucket / bucketMs) * bucketMs;
	const endBucket = Math.floor(endTime / bucketMs) * bucketMs;
	const points: T[] = [];
	for (let bucket = firstBucket; bucket <= endBucket; bucket += bucketMs) points.push(factory(bucket));
	return points;
}

function toNumber(value: unknown): number {
	const converted = Number(value ?? 0);
	return Number.isFinite(converted) ? converted : 0;
}

interface LatencyMinuteRow {
	bucket: number | string;
	min_latency_ms: number | string | null;
	max_latency_ms: number | string | null;
	sum_latency_ms: number | string;
	total_count: number | string;
	timeout_count: number | string;
}

interface LatencySeriesPoint {
	bucket: number;
	minLatencyMs: number | null;
	maxLatencyMs: number | null;
	avgLatencyMs: number | null;
	totalCount: number;
	timeoutCount: number;
	timeoutPct: number;
}

/** Merges pre-aggregated min/max/sum/count rows (already grouped by display bucket) onto a zero-filled bucket skeleton. */
function latencySeriesFromRows(since: number, until: number, bucketMs: number, rows: LatencyMinuteRow[]): LatencySeriesPoint[] {
	const points = emptyMetricPoints<LatencySeriesPoint>(since, until, bucketMs, (value) => ({
		bucket: value,
		minLatencyMs: null,
		maxLatencyMs: null,
		avgLatencyMs: null,
		totalCount: 0,
		timeoutCount: 0,
		timeoutPct: 0,
	}));
	const byBucket = new Map(points.map((point) => [point.bucket, point]));
	for (const row of rows) {
		const point = byBucket.get(toNumber(row.bucket));
		if (!point) continue;
		const totalCount = toNumber(row.total_count);
		const timeoutCount = toNumber(row.timeout_count);
		const successCount = totalCount - timeoutCount;
		point.minLatencyMs = row.min_latency_ms === null ? null : toNumber(row.min_latency_ms);
		point.maxLatencyMs = row.max_latency_ms === null ? null : toNumber(row.max_latency_ms);
		point.avgLatencyMs = successCount > 0 ? toNumber(row.sum_latency_ms) / successCount : null;
		point.totalCount = totalCount;
		point.timeoutCount = timeoutCount;
		point.timeoutPct = totalCount > 0 ? (timeoutCount / totalCount) * 100 : 0;
	}
	return points;
}

function isMySqlDatabase(): boolean {
	return config.databaseUrl.startsWith("mysql://") || config.databaseUrl.startsWith("mariadb://");
}

function isSqliteDatabase(): boolean {
	return config.databaseUrl.startsWith("sqlite") || config.databaseUrl.startsWith("file") || config.databaseUrl === ":memory:";
}

const TRANSIENT_POSTGRES_SQLSTATES = new Set(["40001", "40P01", "53300", "53400", "57P03", "08000", "08001", "08003", "08004", "08006"]);
const TRANSIENT_MYSQL_CODES = new Set([
	"ER_LOCK_DEADLOCK",
	"ER_LOCK_WAIT_TIMEOUT",
	"ER_LOCK_TIMEOUT",
	"ER_CON_COUNT_ERROR",
	"PROTOCOL_CONNECTION_LOST",
	"PROTOCOL_SEQUENCE_TIMEOUT",
	"ECONNREFUSED",
	"ECONNRESET",
	"ETIMEDOUT",
]);
const TRANSIENT_SQLITE_CODES = new Set(["SQLITE_BUSY", "SQLITE_LOCKED", "SQLITE_INTERRUPT", "SQLITE_PROTOCOL"]);

export function isTransientDatabaseError(error: unknown): boolean {
	if (error instanceof Bun.SQL.PostgresError) return TRANSIENT_POSTGRES_SQLSTATES.has(error.code);
	if (error instanceof Bun.SQL.MySQLError) return TRANSIENT_MYSQL_CODES.has(error.code);
	if (error instanceof Bun.SQL.SQLiteError) return TRANSIENT_SQLITE_CODES.has(error.code);
	return false;
}

function deletedRowCount(result: unknown): number {
	const metadata = result as { count?: number | null; affectedRows?: number | null };
	return toNumber(metadata.count ?? metadata.affectedRows);
}

function pageResult<T>(items: T[], totalValue: unknown, page: number, pageSize: number): PageResult<T> {
	const total = toNumber(totalValue);
	return {
		items,
		page,
		pageSize,
		total,
		totalPages: Math.max(1, Math.ceil(total / pageSize)),
	};
}

function searchPattern(search: string | undefined): string | null {
	const value = search?.trim().toLowerCase();
	return value ? `%${value}%` : null;
}

export type TabMetricsScope = "requests" | "blocked" | "protection" | "cache" | "access" | "routes" | "sites" | "bandwidth" | "sessions";

function siteScopeFilter(siteScope: string | string[] | undefined) {
	if (siteScope === undefined) return db``;
	if (Array.isArray(siteScope)) return db`AND site_id IN ${db(siteScope)}`;
	return db`AND site_id=${siteScope}`;
}

function streamScopeFilter(streamScope: string | string[] | undefined) {
	if (streamScope === undefined) return db``;
	if (Array.isArray(streamScope)) return db`AND stream_id IN ${db(streamScope)}`;
	return db`AND stream_id=${streamScope}`;
}

function tabScopeFilter(scope: Exclude<TabMetricsScope, "bandwidth" | "sessions">) {
	switch (scope) {
		case "blocked":
			return db`AND decision IN ('blocked','route-blocked')`;
		case "protection":
			return db`AND protection_status IN ('monitored','blocked')`;
		case "cache":
			return db`AND cache_status='hit'`;
		case "access":
			return db`AND decision IN ('access-login-required','access-login-failed','access-login-rate-limited','access-authenticated')`;
		case "routes":
			return db`AND decision IN ('challenge-required','rate-limited','route-blocked')`;
		case "requests":
		case "sites":
			return db``;
	}
}

export type ReplicatedEntityType =
	| "site"
	| "site_origin"
	| "route_policy"
	| "route_ip_rule"
	| "route_country_rule"
	| "route_asn_rule"
	| "dns_provider"
	| "admin_session"
	| "access_session"
	| "certificate"
	| "site_tls_settings"
	| "acme_http_challenge"
	| "ip_rule"
	| "country_rule"
	| "asn_rule"
	| "site_access_settings"
	| "admin_sso_settings"
	| "site_sso_settings"
	| "admin_user"
	| "access_user"
	| "admin_recovery_code"
	| "admin_webauthn_credential"
	| "access_webauthn_credential"
	| "site_access_user"
	| "admin_site_permission"
	| "admin_stream_permission"
	| "stream"
	| "stream_ip_rule"
	| "stream_country_rule"
	| "stream_asn_rule"
	| "relay_watermark"
	| "firewall_sync_provider"
	| "firewall_sync_whitelist_cidr"
	| "pending_change"
	| "acme_account"
	| "ha_cluster_member";

export type MultiWriterEntityType =
	| "admin_session"
	| "access_session"
	| "ip_rule"
	| "country_rule"
	| "asn_rule"
	| "stream_ip_rule"
	| "admin_user"
	| "access_user"
	| "admin_recovery_code"
	| "admin_webauthn_credential"
	| "access_webauthn_credential"
	| "site_access_user"
	| "admin_site_permission"
	| "admin_stream_permission";

function assertPrimaryWritable(action: string): void {
	if (config.ha.enabled && config.ha.role === "replica") {
		throw new Error(`Replica nodes cannot write ${action} directly - writes must go through the primary`);
	}
	if (config.ha.enabled && config.ha.role === "primary" && config.ha.versionMismatchNodes.length > 0) {
		const versions = config.ha.versionMismatchNodes.map((node) => `${node.name} (${node.version})`).join(", ");
		throw new Error(`Cannot write ${action} while HA cluster versions differ from this primary: ${versions}`);
	}

	if (config.ha.fencedForPromotion && !haPrimaryWriteBarrier.hasActiveLease()) {
		throw new Error(`Cannot write ${action} right now - this node is promoting a replica and will restart shortly, try again in a moment`);
	}
}

async function acquireChangelogOrderingLock(tx: TransactionSQL): Promise<void> {
	if (isSqliteDatabase()) return;
	await tx`SELECT id FROM replication_changelog_lock WHERE id=1 FOR UPDATE`;
}

async function appendChangelogEntry(
	tx: TransactionSQL,
	entityType: ReplicatedEntityType,
	entityId: string,
	op: "insert" | "update" | "delete",
	payload: object | null,
): Promise<void> {
	if (!config.ha.enabled) return;
	await acquireChangelogOrderingLock(tx);
	await tx`INSERT INTO replication_changelog (entity_type,entity_id,op,payload_json,created_at) VALUES (${entityType},${entityId},${op},${payload === null ? null : JSON.stringify(payload)},${Date.now()})`;
	const seqRows = (await tx`SELECT MAX(seq) AS max_seq FROM replication_changelog`) as Array<{ max_seq: number | null }>;
	const stateRows = (await tx`SELECT high_watermark FROM replication_changelog_state WHERE id=1`) as Array<{ high_watermark: number }>;
	const highWatermark = Math.max(Number(seqRows[0]?.max_seq ?? 0), Number(stateRows[0]?.high_watermark ?? 0));
	await tx`UPDATE replication_changelog_state SET high_watermark=${highWatermark} WHERE id=1`;
}

async function applyRecentMaxMemberCount(tx: TransactionSQL, count: number): Promise<void> {
	const now = Date.now();
	await tx`UPDATE ha_cluster_config SET
		recent_max_member_count = CASE WHEN recent_max_member_count IS NULL OR ${count} >= recent_max_member_count OR ${now} - COALESCE(recent_max_member_count_at, 0) >= ${MEMBERSHIP_SHRINK_GRACE_MS} THEN ${count} ELSE recent_max_member_count END,
		recent_max_member_count_at = CASE WHEN recent_max_member_count IS NULL OR ${count} >= recent_max_member_count OR ${now} - COALESCE(recent_max_member_count_at, 0) >= ${MEMBERSHIP_SHRINK_GRACE_MS} THEN ${now} ELSE recent_max_member_count_at END,
		updated_at = ${now}
		WHERE id=1`;
}

async function replicateSessionChange(
	tx: TransactionSQL,
	entityType: MultiWriterEntityType,
	entityId: string,
	op: "insert" | "update" | "delete",
	relayPayload: object | null,
	primaryPayload: object | null = relayPayload,
): Promise<void> {
	if (!config.ha.enabled) return;
	if (config.ha.role === "primary") {
		await appendChangelogEntry(tx, entityType, entityId, op, primaryPayload);
		return;
	}
	await tx`INSERT INTO session_relay_outbox (entity_type,entity_id,op,payload_json,created_at) VALUES (${entityType},${entityId},${op},${relayPayload === null ? null : JSON.stringify(relayPayload)},${Date.now()})`;
}

const ADMIN_USER_MUTABLE_FIELDS = [
	"username",
	"password_hash",
	"role",
	"totp_secret_encrypted",
	"totp_enrolled_at",
	"must_enroll_totp",
	"enabled",
	"sso_subject",
	"auth_source",
] as const;
const ACCESS_USER_MUTABLE_FIELDS = [
	"username",
	"password_hash",
	"enabled",
	"totp_required",
	"totp_secret_encrypted",
	"totp_enrolled_at",
	"api_token_hash",
	"api_token_created_at",
	"sso_subject",
	"auth_source",
] as const;
const RELAY_PATCH_MARKER = "burrowgate-ha-field-patch-v1";
const RELAY_EVENT_MARKER = "burrowgate-ha-relay-event-v1";

function relayFieldPatch<T extends Record<string, unknown>>(before: T | undefined, after: T, fields: readonly string[]): object {
	const changes: Record<string, unknown> = {};
	for (const field of fields) if (!before || !Object.is(before[field], after[field])) changes[field] = after[field];
	return { __haRelayPatch: RELAY_PATCH_MARKER, changes };
}

function parseRelayFieldPatch(payload: object | null, allowedFields: readonly string[]): Record<string, unknown> | null {
	const envelope = payload as { __haRelayPatch?: unknown; changes?: unknown } | null;
	if (
		!envelope ||
		envelope.__haRelayPatch !== RELAY_PATCH_MARKER ||
		!envelope.changes ||
		typeof envelope.changes !== "object" ||
		Array.isArray(envelope.changes)
	)
		return null;
	const changes = envelope.changes as Record<string, unknown>;
	if (Object.keys(changes).some((field) => !allowedFields.includes(field))) throw new Error("Invalid field in HA identity patch");
	return changes;
}

async function applyChangelogRow(
	transaction: TransactionSQL,
	entityType: ReplicatedEntityType,
	entityId: string,
	row: Record<string, unknown> | null,
	localNodeId?: string,
): Promise<void> {
	const relayEvent = row as {
		__haRelayEvent?: unknown;
		nodeId?: unknown;
		relayId?: unknown;
		op?: unknown;
		payload?: unknown;
		watermark?: unknown;
	} | null;
	if (relayEvent?.__haRelayEvent === RELAY_EVENT_MARKER) {
		const watermark = relayEvent.watermark as { node_id?: unknown; last_relay_id?: unknown; updated_at?: unknown } | null;
		if (
			typeof relayEvent.nodeId !== "string" ||
			!Number.isSafeInteger(relayEvent.relayId) ||
			!["insert", "update", "delete"].includes(String(relayEvent.op)) ||
			watermark?.node_id !== relayEvent.nodeId ||
			Number(watermark?.last_relay_id) !== Number(relayEvent.relayId) ||
			!Number.isFinite(Number(watermark?.updated_at))
		) {
			throw new Error("Invalid HA relay event in changelog");
		}
		const op = relayEvent.op as "insert" | "update" | "delete";
		const payload = op === "delete" ? null : (relayEvent.payload as Record<string, unknown> | null);

		if (relayEvent.nodeId !== localNodeId) await applyChangelogRow(transaction, entityType, entityId, payload);
		await transaction`DELETE FROM replication_relay_watermarks WHERE node_id=${relayEvent.nodeId}`;
		await transaction`INSERT INTO replication_relay_watermarks ${transaction(watermark as Record<string, unknown>)}`;
		return;
	}
	switch (entityType) {
		case "site":
			await transaction`DELETE FROM sites WHERE id=${entityId}`;
			if (row) await transaction`INSERT INTO sites ${transaction(row)}`;
			return;
		case "site_origin":
			await transaction`DELETE FROM site_origins WHERE id=${entityId}`;
			if (row) await transaction`INSERT INTO site_origins ${transaction(row)}`;
			return;
		case "route_policy":
			await transaction`DELETE FROM route_policies WHERE id=${entityId}`;
			if (row) await transaction`INSERT INTO route_policies ${transaction(row)}`;
			return;
		case "route_ip_rule":
			await transaction`DELETE FROM route_ip_rules WHERE id=${entityId}`;
			if (row) await transaction`INSERT INTO route_ip_rules ${transaction(row)}`;
			return;
		case "route_country_rule":
			await transaction`DELETE FROM route_country_rules WHERE id=${entityId}`;
			if (row) await transaction`INSERT INTO route_country_rules ${transaction(row)}`;
			return;
		case "route_asn_rule":
			await transaction`DELETE FROM route_asn_rules WHERE id=${entityId}`;
			if (row) await transaction`INSERT INTO route_asn_rules ${transaction(row)}`;
			return;
		case "dns_provider":
			await transaction`DELETE FROM dns_providers WHERE id=${entityId}`;
			if (row) await transaction`INSERT INTO dns_providers ${transaction(row)}`;
			return;
		case "admin_session":
			await transaction`DELETE FROM admin_sessions WHERE id=${entityId}`;
			if (row) await transaction`INSERT INTO admin_sessions ${transaction(row)}`;
			return;
		case "access_session":
			await transaction`DELETE FROM access_sessions WHERE id=${entityId}`;
			if (row) await transaction`INSERT INTO access_sessions ${transaction(row)}`;
			return;
		case "certificate":
			await transaction`DELETE FROM certificates WHERE id=${entityId}`;
			if (row) await transaction`INSERT INTO certificates ${transaction(row)}`;
			return;

		case "site_tls_settings":
			await transaction`DELETE FROM site_tls_settings WHERE site_id=${entityId}`;
			if (row) await transaction`INSERT INTO site_tls_settings ${transaction(row)}`;
			return;

		case "acme_http_challenge":
			await transaction`DELETE FROM acme_http_challenges WHERE token=${entityId}`;
			if (row) await transaction`INSERT INTO acme_http_challenges ${transaction(row)}`;
			return;
		case "ip_rule":
			await transaction`DELETE FROM ip_rules WHERE id=${entityId}`;
			if (row) await transaction`INSERT INTO ip_rules ${transaction(row)}`;
			return;
		case "country_rule":
			await transaction`DELETE FROM country_rules WHERE id=${entityId}`;
			if (row) await transaction`INSERT INTO country_rules ${transaction(row)}`;
			return;
		case "asn_rule":
			await transaction`DELETE FROM asn_rules WHERE id=${entityId}`;
			if (row) await transaction`INSERT INTO asn_rules ${transaction(row)}`;
			return;
		case "site_access_settings":
			await transaction`DELETE FROM site_access_settings WHERE site_id=${entityId}`;
			if (row) await transaction`INSERT INTO site_access_settings ${transaction(row)}`;
			return;
		case "admin_sso_settings":
			await transaction`DELETE FROM admin_sso_settings WHERE id=${entityId}`;
			if (row) await transaction`INSERT INTO admin_sso_settings ${transaction(row)}`;
			return;
		case "site_sso_settings":
			await transaction`DELETE FROM site_sso_settings WHERE site_id=${entityId}`;
			if (row) await transaction`INSERT INTO site_sso_settings ${transaction(row)}`;
			return;
		case "admin_user":
			await transaction`DELETE FROM admin_users WHERE id=${entityId}`;
			if (row) await transaction`INSERT INTO admin_users ${transaction(row)}`;
			return;
		case "access_user":
			await transaction`DELETE FROM access_users WHERE id=${entityId}`;
			if (row) await transaction`INSERT INTO access_users ${transaction(row)}`;
			return;
		case "admin_recovery_code":
			await transaction`DELETE FROM admin_recovery_codes WHERE id=${entityId}`;
			if (row) await transaction`INSERT INTO admin_recovery_codes ${transaction(row)}`;
			return;
		case "admin_webauthn_credential":
			await transaction`DELETE FROM admin_webauthn_credentials WHERE id=${entityId}`;
			if (row) await transaction`INSERT INTO admin_webauthn_credentials ${transaction(row)}`;
			return;
		case "access_webauthn_credential":
			await transaction`DELETE FROM access_webauthn_credentials WHERE id=${entityId}`;
			if (row) await transaction`INSERT INTO access_webauthn_credentials ${transaction(row)}`;
			return;

		case "site_access_user": {
			const [siteId, userId] = entityId.split(":");
			await transaction`DELETE FROM site_access_users WHERE site_id=${siteId} AND user_id=${userId}`;
			if (row) await transaction`INSERT INTO site_access_users ${transaction(row)}`;
			return;
		}
		case "relay_watermark":
			await transaction`DELETE FROM replication_relay_watermarks WHERE node_id=${entityId}`;
			if (row) await transaction`INSERT INTO replication_relay_watermarks ${transaction(row)}`;
			return;

		case "admin_site_permission": {
			const [userId, siteId] = entityId.split(":");
			await transaction`DELETE FROM admin_user_site_permissions WHERE user_id=${userId} AND site_id=${siteId}`;
			if (row) await transaction`INSERT INTO admin_user_site_permissions ${transaction(row)}`;
			return;
		}

		case "admin_stream_permission": {
			const [userId, streamId] = entityId.split(":");
			await transaction`DELETE FROM admin_user_stream_permissions WHERE user_id=${userId} AND stream_id=${streamId}`;
			if (row) await transaction`INSERT INTO admin_user_stream_permissions ${transaction(row)}`;
			return;
		}

		case "stream":
			await transaction`DELETE FROM stream_bindings WHERE stream_id=${entityId}`;
			await transaction`DELETE FROM streams WHERE id=${entityId}`;
			if (row) {
				await transaction`INSERT INTO streams ${transaction(row)}`;
				if (row.tcp_enabled === 1)
					await transaction`INSERT INTO stream_bindings (stream_id,protocol,incoming_port) VALUES (${entityId},'tcp',${row.incoming_port as number})`;
				if (row.udp_enabled === 1)
					await transaction`INSERT INTO stream_bindings (stream_id,protocol,incoming_port) VALUES (${entityId},'udp',${row.incoming_port as number})`;
			}
			return;
		case "stream_ip_rule":
			await transaction`DELETE FROM stream_ip_rules WHERE id=${entityId}`;
			if (row) await transaction`INSERT INTO stream_ip_rules ${transaction(row)}`;
			return;
		case "stream_country_rule":
			await transaction`DELETE FROM stream_country_rules WHERE id=${entityId}`;
			if (row) await transaction`INSERT INTO stream_country_rules ${transaction(row)}`;
			return;
		case "stream_asn_rule":
			await transaction`DELETE FROM stream_asn_rules WHERE id=${entityId}`;
			if (row) await transaction`INSERT INTO stream_asn_rules ${transaction(row)}`;
			return;
		case "firewall_sync_provider":
			await transaction`DELETE FROM firewall_sync_providers WHERE id=${entityId}`;
			if (row) await transaction`INSERT INTO firewall_sync_providers ${transaction(row)}`;
			return;
		case "firewall_sync_whitelist_cidr":
			await transaction`DELETE FROM firewall_sync_whitelist_cidrs WHERE id=${entityId}`;
			if (row) await transaction`INSERT INTO firewall_sync_whitelist_cidrs ${transaction(row)}`;
			return;
		case "pending_change":
			await transaction`DELETE FROM pending_changes WHERE id=${entityId}`;
			if (row) await transaction`INSERT INTO pending_changes ${transaction(row)}`;
			return;
		case "acme_account":
			await transaction`DELETE FROM acme_accounts WHERE id=${entityId}`;
			if (row) await transaction`INSERT INTO acme_accounts ${transaction(row)}`;
			return;
		case "ha_cluster_member":
			await transaction`DELETE FROM ha_cluster_members WHERE node_id=${entityId}`;
			if (row) await transaction`INSERT INTO ha_cluster_members ${transaction(row)}`;
			return;
		default:
			throw new Error(`Unknown replicated entity type: ${String(entityType)}`);
	}
}

async function applyMultiWriterMutation(
	transaction: TransactionSQL,
	entityType: MultiWriterEntityType,
	entityId: string,
	op: "insert" | "update" | "delete",
	payload: object | null,
): Promise<Record<string, unknown> | null> {
	let appliedPayload = payload as Record<string, unknown> | null;
	if (op === "update" && entityType === "admin_user") {
		const changes = parseRelayFieldPatch(payload, ADMIN_USER_MUTABLE_FIELDS);
		if (changes) {
			const current = (await transaction`SELECT * FROM admin_users WHERE id=${entityId} LIMIT 1`) as Array<Record<string, unknown>>;
			if (!current[0]) throw new Error(`Cannot apply an HA patch to missing admin user ${entityId}`);
			appliedPayload = { ...current[0], ...changes, updated_at: Math.max(Date.now(), Number(current[0].updated_at ?? 0) + 1) };
		}
	} else if (op === "update" && entityType === "access_user") {
		const changes = parseRelayFieldPatch(payload, ACCESS_USER_MUTABLE_FIELDS);
		if (changes) {
			const current = (await transaction`SELECT * FROM access_users WHERE id=${entityId} LIMIT 1`) as Array<Record<string, unknown>>;
			if (!current[0]) throw new Error(`Cannot apply an HA patch to missing access user ${entityId}`);
			appliedPayload = { ...current[0], ...changes, updated_at: Math.max(Date.now(), Number(current[0].updated_at ?? 0) + 1) };
		}
	}
	await applyChangelogRow(transaction, entityType, entityId, op === "delete" ? null : appliedPayload);
	return op === "delete" ? null : appliedPayload;
}

async function reapplyPendingSessionRelays(transaction: TransactionSQL): Promise<void> {
	const identityRows = (await transaction`SELECT node_uuid FROM ha_node_identity WHERE id=1 LIMIT 1`) as Array<{ node_uuid: string }>;
	const localNodeId = identityRows[0]?.node_uuid;
	const watermarkRows = localNodeId
		? ((await transaction`SELECT last_relay_id FROM replication_relay_watermarks WHERE node_id=${localNodeId} LIMIT 1`) as Array<{
				last_relay_id: number;
			}>)
		: [];

	const acceptedThrough = Number(watermarkRows[0]?.last_relay_id ?? 0);
	const pending =
		(await transaction`SELECT id,entity_type,entity_id,op,payload_json FROM session_relay_outbox WHERE id > ${acceptedThrough} ORDER BY id ASC`) as Array<{
			id: number;
			entity_type: MultiWriterEntityType;
			entity_id: string;
			op: "insert" | "update" | "delete";
			payload_json: string | null;
		}>;
	for (const row of pending) {
		const payload = row.payload_json ? (JSON.parse(row.payload_json) as object) : null;
		await applyMultiWriterMutation(transaction, row.entity_type, row.entity_id, row.op, payload);
	}
}

const SNAPSHOT_TABLES: Array<{ entityType: ReplicatedEntityType; table: string; entityId: (row: Record<string, unknown>) => string }> = [
	{ entityType: "site", table: "sites", entityId: (row) => row.id as string },
	{ entityType: "site_origin", table: "site_origins", entityId: (row) => row.id as string },
	{ entityType: "route_policy", table: "route_policies", entityId: (row) => row.id as string },
	{ entityType: "route_ip_rule", table: "route_ip_rules", entityId: (row) => row.id as string },
	{ entityType: "route_country_rule", table: "route_country_rules", entityId: (row) => row.id as string },
	{ entityType: "route_asn_rule", table: "route_asn_rules", entityId: (row) => row.id as string },
	{ entityType: "dns_provider", table: "dns_providers", entityId: (row) => row.id as string },
	{ entityType: "admin_session", table: "admin_sessions", entityId: (row) => row.id as string },
	{ entityType: "access_session", table: "access_sessions", entityId: (row) => row.id as string },
	{ entityType: "certificate", table: "certificates", entityId: (row) => row.id as string },
	{ entityType: "site_tls_settings", table: "site_tls_settings", entityId: (row) => row.site_id as string },
	{ entityType: "acme_http_challenge", table: "acme_http_challenges", entityId: (row) => row.token as string },
	{ entityType: "ip_rule", table: "ip_rules", entityId: (row) => row.id as string },
	{ entityType: "country_rule", table: "country_rules", entityId: (row) => row.id as string },
	{ entityType: "asn_rule", table: "asn_rules", entityId: (row) => row.id as string },
	{ entityType: "site_access_settings", table: "site_access_settings", entityId: (row) => row.site_id as string },
	{ entityType: "admin_sso_settings", table: "admin_sso_settings", entityId: (row) => row.id as string },
	{ entityType: "site_sso_settings", table: "site_sso_settings", entityId: (row) => row.site_id as string },
	{ entityType: "admin_user", table: "admin_users", entityId: (row) => row.id as string },
	{ entityType: "access_user", table: "access_users", entityId: (row) => row.id as string },
	{ entityType: "admin_recovery_code", table: "admin_recovery_codes", entityId: (row) => row.id as string },
	{ entityType: "admin_webauthn_credential", table: "admin_webauthn_credentials", entityId: (row) => row.id as string },
	{ entityType: "access_webauthn_credential", table: "access_webauthn_credentials", entityId: (row) => row.id as string },
	{ entityType: "site_access_user", table: "site_access_users", entityId: (row) => `${row.site_id as string}:${row.user_id as string}` },
	{ entityType: "relay_watermark", table: "replication_relay_watermarks", entityId: (row) => row.node_id as string },
	{ entityType: "admin_site_permission", table: "admin_user_site_permissions", entityId: (row) => `${row.user_id as string}:${row.site_id as string}` },
	{ entityType: "admin_stream_permission", table: "admin_user_stream_permissions", entityId: (row) => `${row.user_id as string}:${row.stream_id as string}` },
	{ entityType: "stream", table: "streams", entityId: (row) => row.id as string },
	{ entityType: "stream_ip_rule", table: "stream_ip_rules", entityId: (row) => row.id as string },
	{ entityType: "stream_country_rule", table: "stream_country_rules", entityId: (row) => row.id as string },
	{ entityType: "stream_asn_rule", table: "stream_asn_rules", entityId: (row) => row.id as string },
	{ entityType: "firewall_sync_provider", table: "firewall_sync_providers", entityId: (row) => row.id as string },
	{ entityType: "firewall_sync_whitelist_cidr", table: "firewall_sync_whitelist_cidrs", entityId: (row) => row.id as string },
	{ entityType: "pending_change", table: "pending_changes", entityId: (row) => row.id as string },
	{ entityType: "acme_account", table: "acme_accounts", entityId: (row) => row.id as string },
	{ entityType: "ha_cluster_member", table: "ha_cluster_members", entityId: (row) => row.node_id as string },
];

async function withConsistentSnapshot<T>(fn: (transaction: TransactionSQL) => Promise<T>): Promise<T> {
	if (isSqliteDatabase()) return await db.begin(fn);
	if (isMySqlDatabase()) {
		const connection = await db.reserve();
		try {
			await connection.unsafe("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ");
			return await connection.begin(fn);
		} finally {
			connection.release();
		}
	}
	return await db.begin("isolation level repeatable read read only", fn);
}

async function scanSnapshotRows(transaction: TransactionSQL, pageSize: number, onRow: (row: ReplicationSnapshotRow) => Promise<void>): Promise<void> {
	const limit = Math.max(1, Math.trunc(pageSize));
	for (const table of SNAPSHOT_TABLES) {
		const orderBy =
			table.entityType === "site_tls_settings" || table.entityType === "site_access_settings" || table.entityType === "site_sso_settings"
				? "site_id"
				: table.entityType === "acme_http_challenge"
					? "token"
					: table.entityType === "site_access_user"
						? "site_id,user_id"
						: table.entityType === "relay_watermark" || table.entityType === "ha_cluster_member"
							? "node_id"
							: table.entityType === "admin_site_permission"
								? "user_id,site_id"
								: table.entityType === "admin_stream_permission"
									? "user_id,stream_id"
									: "id";
		let offset = 0;
		for (;;) {
			const tableRows = (await transaction.unsafe(`SELECT * FROM ${table.table} ORDER BY ${orderBy} LIMIT ${limit} OFFSET ${offset}`)) as Array<
				Record<string, unknown>
			>;
			for (const row of tableRows) {
				await onRow({ entity_type: table.entityType, entity_id: table.entityId(row), payload_json: JSON.stringify(row) });
			}
			if (tableRows.length < limit) break;
			offset += tableRows.length;
		}
	}
}

export interface ReplicationChangelogRow {
	seq: number;
	entity_type: ReplicatedEntityType;
	entity_id: string;
	op: "insert" | "update" | "delete";
	payload_json: string | null;
	created_at: number;
}

export interface ReplicationSnapshotRow {
	entity_type: ReplicatedEntityType;
	entity_id: string;
	payload_json: string;
}

export interface HaClusterConfigRow {
	id: number;
	enabled: number;

	role: HaRole;
	node_name: string;
	primary_url: string | null;
	primary_admin_url: string | null;
	shared_token_encrypted: string | null;
	self_admin_url: string | null;

	cluster_epoch: number;

	authority_fenced: number;
	authority_fence_epoch: number | null;
	authority_fence_node_id: string | null;
	authority_fenced_at: number | null;

	voted_for_term: number | null;
	voted_for_node_id: string | null;

	quorum_fenced: number;
	quorum_fenced_at: number | null;

	recent_max_member_count: number | null;
	recent_max_member_count_at: number | null;
	updated_at: number;
}

export interface HaClusterConfigInsert {
	enabled: boolean;
	role: HaRole;
	nodeName: string;
	primaryUrl: string | null;
	primaryAdminUrl: string | null;
	sharedTokenEncrypted: string | null;
	selfAdminUrl: string | null;
	clusterEpoch: number;
}

export interface HaPromotionIntentRecord {
	id: number;
	promotion_id: string;
	target_node_id: string;
	target_url: string;
	target_admin_url: string;
	new_epoch: number;
	created_at: number;
}

export interface HaClusterMemberRecord {
	node_id: string;
	name: string;
	version: string;
	admin_url: string | null;
	first_seen_at: number;
	last_seen_at: number;
	credential_hash?: string | null;
	activated_at?: number | null;
	revoked_at?: number | null;
}

export interface HaAuthenticatedMember {
	node_id: string;
	active: boolean;
}

export interface SessionRelayRow {
	id: number;
	entity_type: MultiWriterEntityType;
	entity_id: string;
	op: "insert" | "update" | "delete";
	payload_json: string | null;
	created_at: number;
}

export interface DeadLetteredRelayRecord {
	id: string;
	node_id: string;
	relay_id: number;
	entity_type: string;
	entity_id: string;
	op: string;
	payload_json: string | null;
	reason: string;
	occurred_at: number;
}

export const repository = {
	async siteByHost(host: string): Promise<SiteRecord | null> {
		const rows = (await db`SELECT * FROM sites WHERE public_host = ${host} AND enabled = 1 LIMIT 1`) as SiteRecord[];
		return rows[0] ?? null;
	},
	async siteById(id: string): Promise<SiteRecord | null> {
		const rows = (await db`SELECT * FROM sites WHERE id = ${id} LIMIT 1`) as SiteRecord[];
		return rows[0] ?? null;
	},
	async siteByPublicHost(host: string): Promise<SiteRecord | null> {
		const rows = (await db`SELECT * FROM sites WHERE public_host = ${host} LIMIT 1`) as SiteRecord[];
		return rows[0] ?? null;
	},
	async allSites(): Promise<SiteRecord[]> {
		return (await db`SELECT * FROM sites ORDER BY name ASC`) as SiteRecord[];
	},
	async insertSite(site: SiteRecord): Promise<void> {
		assertPrimaryWritable("a site");
		await db.begin(async (transaction) => {
			await transaction`INSERT INTO sites (id,name,public_host,origin_type,origin_url,origin_signing_secret,ip_extraction_preset,enabled,session_ttl_seconds,challenge_policy_json,default_access_mode,event_retention_days,default_ip_action,default_country_action,error_response_mode,error_html_template,error_json_fields_json,challenge_html_template,health_check_enabled,health_check_path,health_check_interval_seconds,health_check_timeout_ms,health_check_failure_threshold,health_check_recovery_threshold,health_check_failure_mode,health_alert_enabled,health_alert_provider,health_alert_webhook_url,health_alert_webhook_secret,load_balancing_algorithm,load_balancing_affinity,outbound_fetch_protocol,websocket_policy_json,http_policy_json,created_at,updated_at)
			VALUES (${site.id},${site.name},${site.public_host},${site.origin_type ?? "proxy"},${site.origin_url},${site.origin_signing_secret},${site.ip_extraction_preset},${site.enabled},${site.session_ttl_seconds},${site.challenge_policy_json},${site.default_access_mode},${site.event_retention_days},${site.default_ip_action},${site.default_country_action},${site.error_response_mode},${site.error_html_template},${site.error_json_fields_json},${site.challenge_html_template},${site.health_check_enabled},${site.health_check_path},${site.health_check_interval_seconds},${site.health_check_timeout_ms},${site.health_check_failure_threshold},${site.health_check_recovery_threshold},${site.health_check_failure_mode},${site.health_alert_enabled},${site.health_alert_provider},${site.health_alert_webhook_url},${site.health_alert_webhook_secret},${site.load_balancing_algorithm},${site.load_balancing_affinity},${site.outbound_fetch_protocol ?? "http1"},${site.websocket_policy_json ?? null},${site.http_policy_json ?? null},${site.created_at},${site.updated_at})`;
			await appendChangelogEntry(transaction, "site", site.id, "insert", site);
		});
	},
	async updateSite(site: SiteRecord): Promise<void> {
		assertPrimaryWritable("a site");
		await db.begin(async (transaction) => {
			await transaction`UPDATE sites SET name=${site.name}, public_host=${site.public_host}, origin_type=${site.origin_type ?? "proxy"}, origin_url=${site.origin_url}, origin_signing_secret=${site.origin_signing_secret}, ip_extraction_preset=${site.ip_extraction_preset}, enabled=${site.enabled}, session_ttl_seconds=${site.session_ttl_seconds}, challenge_policy_json=${site.challenge_policy_json}, default_access_mode=${site.default_access_mode}, event_retention_days=${site.event_retention_days}, default_ip_action=${site.default_ip_action}, default_country_action=${site.default_country_action}, error_response_mode=${site.error_response_mode}, error_html_template=${site.error_html_template}, error_json_fields_json=${site.error_json_fields_json}, challenge_html_template=${site.challenge_html_template}, health_check_enabled=${site.health_check_enabled}, health_check_path=${site.health_check_path}, health_check_interval_seconds=${site.health_check_interval_seconds}, health_check_timeout_ms=${site.health_check_timeout_ms}, health_check_failure_threshold=${site.health_check_failure_threshold}, health_check_recovery_threshold=${site.health_check_recovery_threshold}, health_check_failure_mode=${site.health_check_failure_mode}, health_alert_enabled=${site.health_alert_enabled}, health_alert_provider=${site.health_alert_provider}, health_alert_webhook_url=${site.health_alert_webhook_url}, health_alert_webhook_secret=${site.health_alert_webhook_secret}, load_balancing_algorithm=${site.load_balancing_algorithm}, load_balancing_affinity=${site.load_balancing_affinity}, outbound_fetch_protocol=${site.outbound_fetch_protocol ?? "http1"}, websocket_policy_json=${site.websocket_policy_json ?? null}, http_policy_json=${site.http_policy_json ?? null}, updated_at=${site.updated_at} WHERE id=${site.id}`;
			await appendChangelogEntry(transaction, "site", site.id, "update", site);
		});
	},
	async deleteSiteCascade(siteId: string): Promise<void> {
		assertPrimaryWritable("a site");
		const flowRows = (await db`SELECT id FROM challenge_flows WHERE site_id=${siteId}`) as Array<{ id: string }>;
		const flowIds = flowRows.map((row) => row.id);
		const stepRows = flowIds.length ? ((await db`SELECT id FROM challenge_steps WHERE flow_id IN ${db(flowIds)}`) as Array<{ id: string }>) : [];
		const stepIds = stepRows.map((row) => row.id);
		const routePolicyRows = (await db`SELECT id FROM route_policies WHERE site_id=${siteId}`) as Array<{ id: string }>;
		const routePolicyIds = routePolicyRows.map((row) => row.id);
		const routeRuleIds = routePolicyIds.length
			? {
					ip: ((await db`SELECT id FROM route_ip_rules WHERE route_policy_id IN ${db(routePolicyIds)}`) as Array<{ id: string }>).map((r) => r.id),
					country: ((await db`SELECT id FROM route_country_rules WHERE route_policy_id IN ${db(routePolicyIds)}`) as Array<{ id: string }>).map((r) => r.id),
					asn: ((await db`SELECT id FROM route_asn_rules WHERE route_policy_id IN ${db(routePolicyIds)}`) as Array<{ id: string }>).map((r) => r.id),
				}
			: { ip: [] as string[], country: [] as string[], asn: [] as string[] };
		const certificateRow = (await db`SELECT id FROM certificates WHERE site_id=${siteId} LIMIT 1`) as Array<{ id: string }>;
		const hasTlsSettings = ((await db`SELECT site_id FROM site_tls_settings WHERE site_id=${siteId} LIMIT 1`) as Array<{ site_id: string }>).length > 0;
		const hasAccessSettings = ((await db`SELECT site_id FROM site_access_settings WHERE site_id=${siteId} LIMIT 1`) as Array<{ site_id: string }>).length > 0;
		const hasSsoSettings = ((await db`SELECT site_id FROM site_sso_settings WHERE site_id=${siteId} LIMIT 1`) as Array<{ site_id: string }>).length > 0;
		const accessUserIds = ((await db`SELECT user_id FROM site_access_users WHERE site_id=${siteId}`) as Array<{ user_id: string }>).map((r) => r.user_id);
		const acmeChallengeTokens = ((await db`SELECT token FROM acme_http_challenges WHERE site_id=${siteId}`) as Array<{ token: string }>).map((r) => r.token);
		const originIds = ((await db`SELECT id FROM site_origins WHERE site_id=${siteId}`) as Array<{ id: string }>).map((r) => r.id);
		const sitePermissionUserIds = ((await db`SELECT user_id FROM admin_user_site_permissions WHERE site_id=${siteId}`) as Array<{ user_id: string }>).map(
			(r) => r.user_id,
		);
		const pendingChangeIds = ((await db`SELECT id FROM pending_changes WHERE entity_type='site' AND entity_id=${siteId}`) as Array<{ id: string }>).map(
			(r) => r.id,
		);
		await db.begin(async (transaction) => {
			if (stepIds.length > 0) await transaction`DELETE FROM challenge_consumptions WHERE step_id IN ${transaction(stepIds)}`;
			if (flowIds.length > 0) await transaction`DELETE FROM challenge_steps WHERE flow_id IN ${transaction(flowIds)}`;
			await transaction`DELETE FROM challenge_flows WHERE site_id=${siteId}`;
			if (routePolicyIds.length > 0) {
				await transaction`DELETE FROM route_ip_rules WHERE route_policy_id IN ${transaction(routePolicyIds)}`;
				await transaction`DELETE FROM route_country_rules WHERE route_policy_id IN ${transaction(routePolicyIds)}`;
				await transaction`DELETE FROM route_asn_rules WHERE route_policy_id IN ${transaction(routePolicyIds)}`;
			}
			await transaction`DELETE FROM route_policies WHERE site_id=${siteId}`;
			await transaction`DELETE FROM access_sessions WHERE site_id=${siteId}`;
			await transaction`DELETE FROM site_access_users WHERE site_id=${siteId}`;
			await transaction`DELETE FROM site_access_settings WHERE site_id=${siteId}`;
			await transaction`DELETE FROM admin_user_site_permissions WHERE site_id=${siteId}`;
			await transaction`DELETE FROM ip_rules WHERE site_id=${siteId}`;
			await transaction`DELETE FROM country_rules WHERE site_id=${siteId}`;
			await transaction`DELETE FROM asn_rules WHERE site_id=${siteId}`;
			await transaction`DELETE FROM request_events WHERE site_id=${siteId}`;
			await transaction`DELETE FROM bandwidth_minutes WHERE site_id=${siteId}`;
			await transaction`DELETE FROM acme_http_challenges WHERE site_id=${siteId}`;
			await transaction`DELETE FROM certificate_events WHERE site_id=${siteId}`;
			await transaction`DELETE FROM health_alert_outbox WHERE site_id=${siteId}`;
			await transaction`DELETE FROM notification_outbox WHERE site_id=${siteId}`;
			await transaction`DELETE FROM notification_events WHERE site_id=${siteId}`;
			await transaction`DELETE FROM origin_backend_health_events WHERE site_id=${siteId}`;
			await transaction`DELETE FROM origin_backend_health_status WHERE site_id=${siteId}`;
			await transaction`DELETE FROM origin_health_events WHERE site_id=${siteId}`;
			await transaction`DELETE FROM origin_health_status WHERE site_id=${siteId}`;
			await transaction`DELETE FROM site_origins WHERE site_id=${siteId}`;
			await transaction`DELETE FROM certificates WHERE site_id=${siteId}`;
			await transaction`DELETE FROM site_tls_settings WHERE site_id=${siteId}`;
			await transaction`DELETE FROM site_sso_settings WHERE site_id=${siteId}`;
			await transaction`DELETE FROM pending_changes WHERE entity_type='site' AND entity_id=${siteId}`;
			await transaction`DELETE FROM sites WHERE id=${siteId}`;
			for (const ruleId of routeRuleIds.ip) await appendChangelogEntry(transaction, "route_ip_rule", ruleId, "delete", null);
			for (const ruleId of routeRuleIds.country) await appendChangelogEntry(transaction, "route_country_rule", ruleId, "delete", null);
			for (const ruleId of routeRuleIds.asn) await appendChangelogEntry(transaction, "route_asn_rule", ruleId, "delete", null);
			for (const routePolicyId of routePolicyIds) await appendChangelogEntry(transaction, "route_policy", routePolicyId, "delete", null);
			for (const token of acmeChallengeTokens) await appendChangelogEntry(transaction, "acme_http_challenge", token, "delete", null);
			if (certificateRow[0]) await appendChangelogEntry(transaction, "certificate", certificateRow[0].id, "delete", null);
			if (hasTlsSettings) await appendChangelogEntry(transaction, "site_tls_settings", siteId, "delete", null);
			if (hasAccessSettings) await appendChangelogEntry(transaction, "site_access_settings", siteId, "delete", null);
			if (hasSsoSettings) await appendChangelogEntry(transaction, "site_sso_settings", siteId, "delete", null);
			for (const userId of accessUserIds) await appendChangelogEntry(transaction, "site_access_user", `${siteId}:${userId}`, "delete", null);
			for (const originId of originIds) await appendChangelogEntry(transaction, "site_origin", originId, "delete", null);
			for (const userId of sitePermissionUserIds) await appendChangelogEntry(transaction, "admin_site_permission", `${userId}:${siteId}`, "delete", null);
			for (const changeId of pendingChangeIds) await appendChangelogEntry(transaction, "pending_change", changeId, "delete", null);
			await appendChangelogEntry(transaction, "site", siteId, "delete", null);
		});
	},
	async originsForSite(siteId: string): Promise<SiteOriginRecord[]> {
		return (await db`SELECT * FROM site_origins WHERE site_id=${siteId} ORDER BY priority ASC, is_primary DESC, created_at ASC`) as SiteOriginRecord[];
	},
	async allOrigins(): Promise<SiteOriginRecord[]> {
		return (await db`SELECT * FROM site_origins ORDER BY site_id ASC, priority ASC, is_primary DESC, created_at ASC`) as SiteOriginRecord[];
	},
	async originById(id: string, siteId?: string): Promise<SiteOriginRecord | null> {
		const rows = siteId
			? ((await db`SELECT * FROM site_origins WHERE id=${id} AND site_id=${siteId} LIMIT 1`) as SiteOriginRecord[])
			: ((await db`SELECT * FROM site_origins WHERE id=${id} LIMIT 1`) as SiteOriginRecord[]);
		return rows[0] ?? null;
	},
	async primaryOrigin(siteId: string): Promise<SiteOriginRecord | null> {
		const rows = (await db`SELECT * FROM site_origins WHERE site_id=${siteId} AND is_primary=1 LIMIT 1`) as SiteOriginRecord[];
		return rows[0] ?? null;
	},
	async insertOrigin(origin: SiteOriginRecord): Promise<void> {
		assertPrimaryWritable("an origin");
		await db.begin(async (transaction) => {
			await transaction`INSERT INTO site_origins (id,site_id,name,origin_type,origin_url,static_index_file,static_spa_fallback,enabled,draining,priority,weight,health_check_path,is_primary,mtls_enabled,mtls_certificate_pem,mtls_encrypted_private_key,mtls_ca_pem,created_at,updated_at) VALUES (${origin.id},${origin.site_id},${origin.name},${origin.origin_type},${origin.origin_url},${origin.static_index_file},${origin.static_spa_fallback},${origin.enabled},${origin.draining},${origin.priority},${origin.weight},${origin.health_check_path},${origin.is_primary},${origin.mtls_enabled},${origin.mtls_certificate_pem},${origin.mtls_encrypted_private_key},${origin.mtls_ca_pem},${origin.created_at},${origin.updated_at})`;
			await appendChangelogEntry(transaction, "site_origin", origin.id, "insert", origin);
		});
	},
	async updateOrigin(origin: SiteOriginRecord): Promise<void> {
		assertPrimaryWritable("an origin");
		await db.begin(async (transaction) => {
			await transaction`UPDATE site_origins SET name=${origin.name}, origin_type=${origin.origin_type}, origin_url=${origin.origin_url}, static_index_file=${origin.static_index_file}, static_spa_fallback=${origin.static_spa_fallback}, enabled=${origin.enabled}, draining=${origin.draining}, priority=${origin.priority}, weight=${origin.weight}, health_check_path=${origin.health_check_path}, mtls_enabled=${origin.mtls_enabled}, mtls_certificate_pem=${origin.mtls_certificate_pem}, mtls_encrypted_private_key=${origin.mtls_encrypted_private_key}, mtls_ca_pem=${origin.mtls_ca_pem}, updated_at=${origin.updated_at} WHERE id=${origin.id} AND site_id=${origin.site_id}`;
			await appendChangelogEntry(transaction, "site_origin", origin.id, "update", origin);
		});
	},
	async deleteOrigin(id: string, siteId: string): Promise<void> {
		assertPrimaryWritable("an origin");
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM site_origins WHERE id=${id} AND site_id=${siteId} AND is_primary=0`;
			await appendChangelogEntry(transaction, "site_origin", id, "delete", null);
		});
	},
	async originHealthStatus(siteId: string): Promise<OriginHealthStatusRecord | null> {
		const rows = (await db`SELECT * FROM origin_health_status WHERE site_id=${siteId} LIMIT 1`) as OriginHealthStatusRecord[];
		return rows[0] ?? null;
	},
	async allOriginHealthStatuses(): Promise<OriginHealthStatusRecord[]> {
		return (await db`SELECT * FROM origin_health_status`) as OriginHealthStatusRecord[];
	},
	async saveOriginHealthStatus(status: OriginHealthStatusRecord): Promise<void> {
		const existing = await this.originHealthStatus(status.site_id);
		if (existing) {
			await db`UPDATE origin_health_status SET state=${status.state}, consecutive_failures=${status.consecutive_failures}, consecutive_successes=${status.consecutive_successes}, last_checked_at=${status.last_checked_at}, last_healthy_at=${status.last_healthy_at}, last_unhealthy_at=${status.last_unhealthy_at}, last_status=${status.last_status}, last_latency_ms=${status.last_latency_ms}, last_error=${status.last_error}, updated_at=${status.updated_at} WHERE site_id=${status.site_id}`;
			return;
		}
		await db`INSERT INTO origin_health_status (site_id,state,consecutive_failures,consecutive_successes,last_checked_at,last_healthy_at,last_unhealthy_at,last_status,last_latency_ms,last_error,updated_at) VALUES (${status.site_id},${status.state},${status.consecutive_failures},${status.consecutive_successes},${status.last_checked_at},${status.last_healthy_at},${status.last_unhealthy_at},${status.last_status},${status.last_latency_ms},${status.last_error},${status.updated_at})`;
	},
	async insertOriginHealthEvent(event: OriginHealthEventRecord): Promise<void> {
		await db`INSERT INTO origin_health_events (id,site_id,from_state,to_state,status,latency_ms,error,created_at) VALUES (${event.id},${event.site_id},${event.from_state},${event.to_state},${event.status},${event.latency_ms},${event.error},${event.created_at})`;
	},
	async originHealthEvents(siteId: string, limit = 50): Promise<OriginHealthEventRecord[]> {
		return (await db`SELECT * FROM origin_health_events WHERE site_id=${siteId} ORDER BY created_at DESC LIMIT ${limit}`) as OriginHealthEventRecord[];
	},
	async insertNotificationEvent(event: NotificationEventRecord): Promise<void> {
		await db`INSERT INTO notification_events (id,site_id,stream_id,type,severity,summary,payload_json,occurred_at,created_at) VALUES (${event.id},${event.site_id},${event.stream_id},${event.type},${event.severity},${event.summary},${event.payload_json},${event.occurred_at},${event.created_at})`;
	},
	async insertNotificationOutbox(outbox: NotificationOutboxRecord): Promise<void> {
		await db`INSERT INTO notification_outbox (id,event_id,site_id,stream_id,status,attempts,next_attempt_at,last_error,created_at,delivered_at) VALUES (${outbox.id},${outbox.event_id},${outbox.site_id},${outbox.stream_id},${outbox.status},${outbox.attempts},${outbox.next_attempt_at},${outbox.last_error},${outbox.created_at},${outbox.delivered_at})`;
	},
	async pendingNotificationOutbox(now: number, limit: number): Promise<PendingNotificationDeliveryRecord[]> {
		return (await db`
			SELECT no.id, no.event_id, no.site_id, no.stream_id, no.status, no.attempts, no.next_attempt_at, no.last_error, no.created_at, no.delivered_at,
				ne.type, ne.severity, ne.summary, ne.payload_json, ne.occurred_at
			FROM notification_outbox no
			JOIN notification_events ne ON ne.id = no.event_id
			WHERE no.status='pending' AND no.next_attempt_at <= ${now}
				AND no.id = (
					SELECT oldest.id FROM notification_outbox oldest
					WHERE oldest.status='pending'
						AND (
							(no.site_id IS NOT NULL AND oldest.site_id = no.site_id)
							OR (no.stream_id IS NOT NULL AND oldest.stream_id = no.stream_id)
						)
					ORDER BY oldest.created_at ASC, oldest.id ASC
					LIMIT 1
				)
			ORDER BY no.created_at ASC
			LIMIT ${limit}`) as PendingNotificationDeliveryRecord[];
	},
	async updateNotificationOutboxDelivery(
		id: string,
		status: "pending" | "delivered" | "failed",
		attempts: number,
		nextAttemptAt: number,
		error: string | null,
		deliveredAt: number | null,
	): Promise<void> {
		await db`UPDATE notification_outbox SET status=${status}, attempts=${attempts}, next_attempt_at=${nextAttemptAt}, last_error=${error}, delivered_at=${deliveredAt} WHERE id=${id}`;
	},
	async insertPendingChange(change: PendingChangeRecord): Promise<void> {
		assertPrimaryWritable("a scheduled change");
		await db.begin(async (transaction) => {
			await transaction`INSERT INTO pending_changes (id,entity_type,entity_id,changes_json,summary,apply_at,status,attempts,last_error,created_by,created_at,applied_at) VALUES (${change.id},${change.entity_type},${change.entity_id},${change.changes_json},${change.summary},${change.apply_at},${change.status},${change.attempts},${change.last_error},${change.created_by},${change.created_at},${change.applied_at})`;
			await appendChangelogEntry(transaction, "pending_change", change.id, "insert", change);
		});
	},
	async pendingChangeById(id: string): Promise<PendingChangeRecord | null> {
		const rows = (await db`SELECT * FROM pending_changes WHERE id=${id} LIMIT 1`) as PendingChangeRecord[];
		return rows[0] ?? null;
	},
	/** Strictly the active schedule slot for an entity - used to reject staging a second change while one is already pending. */
	async pendingChangeFor(entityType: PendingChangeEntityType, entityId: string): Promise<PendingChangeRecord | null> {
		const rows =
			(await db`SELECT * FROM pending_changes WHERE entity_type=${entityType} AND entity_id=${entityId} AND status='pending' LIMIT 1`) as PendingChangeRecord[];
		return rows[0] ?? null;
	},
	/** The entity's current change - pending or failed - for display and for apply-now/cancel to act on. Failed rows are cleaned up when a new change is staged, so at most one row per entity is expected; ORDER BY guards against that invariant ever being violated. */
	async pendingOrFailedChangeFor(entityType: PendingChangeEntityType, entityId: string): Promise<PendingChangeRecord | null> {
		const rows = (await db`
			SELECT * FROM pending_changes WHERE entity_type=${entityType} AND entity_id=${entityId} AND status IN ('pending', 'failed')
			ORDER BY created_at DESC LIMIT 1`) as PendingChangeRecord[];
		return rows[0] ?? null;
	},
	async pendingChangesFor(entityType: PendingChangeEntityType, entityIds: string[]): Promise<PendingChangeRecord[]> {
		if (entityIds.length === 0) return [];
		return (await db`
			SELECT * FROM pending_changes WHERE entity_type=${entityType} AND entity_id IN ${db(entityIds)} AND status IN ('pending', 'failed')`) as PendingChangeRecord[];
	},
	async deleteFailedPendingChangesFor(entityType: PendingChangeEntityType, entityId: string): Promise<void> {
		assertPrimaryWritable("a scheduled change");
		const ids = (
			(await db`SELECT id FROM pending_changes WHERE entity_type=${entityType} AND entity_id=${entityId} AND status='failed'`) as Array<{ id: string }>
		).map((row) => row.id);
		if (ids.length === 0) return;
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM pending_changes WHERE entity_type=${entityType} AND entity_id=${entityId} AND status='failed'`;
			for (const id of ids) await appendChangelogEntry(transaction, "pending_change", id, "delete", null);
		});
	},
	async duePendingChanges(now: number, limit: number): Promise<PendingChangeRecord[]> {
		return (await db`SELECT * FROM pending_changes WHERE status='pending' AND apply_at <= ${now} ORDER BY apply_at ASC LIMIT ${limit}`) as PendingChangeRecord[];
	},
	async updatePendingChangeStatus(
		id: string,
		status: PendingChangeStatus,
		attempts: number,
		applyAt: number,
		lastError: string | null,
		appliedAt: number | null,
	): Promise<void> {
		assertPrimaryWritable("a scheduled change");
		await db.begin(async (transaction) => {
			await transaction`UPDATE pending_changes SET status=${status}, attempts=${attempts}, apply_at=${applyAt}, last_error=${lastError}, applied_at=${appliedAt} WHERE id=${id}`;
			const rows = (await transaction`SELECT * FROM pending_changes WHERE id=${id}`) as PendingChangeRecord[];
			if (rows[0]) await appendChangelogEntry(transaction, "pending_change", id, "update", rows[0]);
		});
	},
	async deletePendingChange(id: string): Promise<void> {
		assertPrimaryWritable("a scheduled change");
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM pending_changes WHERE id=${id}`;
			await appendChangelogEntry(transaction, "pending_change", id, "delete", null);
		});
	},
	async pagedNotificationsForSite(query: NotificationQuery): Promise<PageResult<NotificationEventWithDeliveryRecord>> {
		const pattern = searchPattern(query.search);
		const searchFilter = pattern ? db`AND (LOWER(ne.summary) LIKE ${pattern} OR LOWER(ne.type) LIKE ${pattern})` : db``;
		const typeFilter = query.type ? db`AND ne.type=${query.type}` : db``;
		const statusFilter = query.status ? db`AND no.status=${query.status}` : db``;
		const sortColumn =
			query.sortBy === "type" ? "ne.type" : query.sortBy === "status" ? "no.status" : query.sortBy === "occurred_at" ? "ne.occurred_at" : "no.created_at";
		const order = db.unsafe(`${sortColumn} ${query.sortDirection.toUpperCase()}`);
		const offset = (query.page - 1) * query.pageSize;
		const [countRow] = (await db`
			SELECT COUNT(*) AS count FROM notification_outbox no
			JOIN notification_events ne ON ne.id = no.event_id
			WHERE no.site_id=${query.siteId} ${searchFilter} ${typeFilter} ${statusFilter}
		`) as Array<{ count: number | string }>;
		const items = (await db`
			SELECT ne.id, ne.site_id, ne.stream_id, ne.type, ne.severity, ne.summary, ne.payload_json, ne.occurred_at, ne.created_at,
				no.status AS delivery_status, no.attempts AS delivery_attempts, no.last_error AS delivery_last_error, no.delivered_at
			FROM notification_outbox no
			JOIN notification_events ne ON ne.id = no.event_id
			WHERE no.site_id=${query.siteId} ${searchFilter} ${typeFilter} ${statusFilter}
			ORDER BY ${order}
			LIMIT ${query.pageSize} OFFSET ${offset}
		`) as NotificationEventWithDeliveryRecord[];
		return pageResult(items, countRow?.count, query.page, query.pageSize);
	},
	async pagedNotificationsForStream(query: StreamNotificationQuery): Promise<PageResult<NotificationEventWithDeliveryRecord>> {
		const pattern = searchPattern(query.search);
		const searchFilter = pattern ? db`AND (LOWER(ne.summary) LIKE ${pattern} OR LOWER(ne.type) LIKE ${pattern})` : db``;
		const typeFilter = query.type ? db`AND ne.type=${query.type}` : db``;
		const statusFilter = query.status ? db`AND no.status=${query.status}` : db``;
		const sortColumn =
			query.sortBy === "type" ? "ne.type" : query.sortBy === "status" ? "no.status" : query.sortBy === "occurred_at" ? "ne.occurred_at" : "no.created_at";
		const order = db.unsafe(`${sortColumn} ${query.sortDirection.toUpperCase()}`);
		const offset = (query.page - 1) * query.pageSize;
		const [countRow] = (await db`
			SELECT COUNT(*) AS count FROM notification_outbox no
			JOIN notification_events ne ON ne.id = no.event_id
			WHERE no.stream_id=${query.streamId} ${searchFilter} ${typeFilter} ${statusFilter}
		`) as Array<{ count: number | string }>;
		const items = (await db`
			SELECT ne.id, ne.site_id, ne.stream_id, ne.type, ne.severity, ne.summary, ne.payload_json, ne.occurred_at, ne.created_at,
				no.status AS delivery_status, no.attempts AS delivery_attempts, no.last_error AS delivery_last_error, no.delivered_at
			FROM notification_outbox no
			JOIN notification_events ne ON ne.id = no.event_id
			WHERE no.stream_id=${query.streamId} ${searchFilter} ${typeFilter} ${statusFilter}
			ORDER BY ${order}
			LIMIT ${query.pageSize} OFFSET ${offset}
		`) as NotificationEventWithDeliveryRecord[];
		return pageResult(items, countRow?.count, query.page, query.pageSize);
	},
	async backendHealthStatus(originId: string): Promise<OriginBackendHealthStatusRecord | null> {
		const rows = (await db`SELECT * FROM origin_backend_health_status WHERE origin_id=${originId} LIMIT 1`) as OriginBackendHealthStatusRecord[];
		return rows[0] ?? null;
	},
	async allBackendHealthStatuses(): Promise<OriginBackendHealthStatusRecord[]> {
		return (await db`SELECT * FROM origin_backend_health_status`) as OriginBackendHealthStatusRecord[];
	},
	async saveBackendHealthStatus(status: OriginBackendHealthStatusRecord): Promise<void> {
		const existing = await this.backendHealthStatus(status.origin_id);
		if (existing) {
			await db`UPDATE origin_backend_health_status SET site_id=${status.site_id}, state=${status.state}, consecutive_failures=${status.consecutive_failures}, consecutive_successes=${status.consecutive_successes}, last_checked_at=${status.last_checked_at}, last_healthy_at=${status.last_healthy_at}, last_unhealthy_at=${status.last_unhealthy_at}, last_status=${status.last_status}, last_latency_ms=${status.last_latency_ms}, last_error=${status.last_error}, updated_at=${status.updated_at} WHERE origin_id=${status.origin_id}`;
			return;
		}
		await db`INSERT INTO origin_backend_health_status (origin_id,site_id,state,consecutive_failures,consecutive_successes,last_checked_at,last_healthy_at,last_unhealthy_at,last_status,last_latency_ms,last_error,updated_at) VALUES (${status.origin_id},${status.site_id},${status.state},${status.consecutive_failures},${status.consecutive_successes},${status.last_checked_at},${status.last_healthy_at},${status.last_unhealthy_at},${status.last_status},${status.last_latency_ms},${status.last_error},${status.updated_at})`;
	},
	async insertBackendHealthEvent(event: OriginBackendHealthEventRecord): Promise<void> {
		await db`INSERT INTO origin_backend_health_events (id,site_id,origin_id,from_state,to_state,status,latency_ms,error,created_at) VALUES (${event.id},${event.site_id},${event.origin_id},${event.from_state},${event.to_state},${event.status},${event.latency_ms},${event.error},${event.created_at})`;
	},
	async backendHealthEvents(siteId: string, limit = 100): Promise<OriginBackendHealthEventRecord[]> {
		return (await db`SELECT * FROM origin_backend_health_events WHERE site_id=${siteId} ORDER BY created_at DESC LIMIT ${limit}`) as OriginBackendHealthEventRecord[];
	},
	async addOriginLatencyResult(originId: string, siteId: string, bucketStart: number, result: LatencyCheckResult): Promise<void> {
		const latency = result.timedOut ? null : Math.max(0, Math.round(result.latencyMs ?? 0));
		const sum = result.timedOut ? 0 : (latency ?? 0);
		const timeout = result.timedOut ? 1 : 0;
		if (isMySqlDatabase()) {
			await db`INSERT INTO origin_latency_minutes (origin_id,site_id,bucket_start,min_latency_ms,max_latency_ms,sum_latency_ms,total_count,timeout_count)
				VALUES (${originId},${siteId},${bucketStart},${latency},${latency},${sum},1,${timeout})
				ON DUPLICATE KEY UPDATE
				min_latency_ms = CASE WHEN min_latency_ms IS NULL THEN ${latency} WHEN ${latency} IS NULL THEN min_latency_ms WHEN min_latency_ms <= ${latency} THEN min_latency_ms ELSE ${latency} END,
				max_latency_ms = CASE WHEN max_latency_ms IS NULL THEN ${latency} WHEN ${latency} IS NULL THEN max_latency_ms WHEN max_latency_ms >= ${latency} THEN max_latency_ms ELSE ${latency} END,
				sum_latency_ms = sum_latency_ms + ${sum},
				total_count = total_count + 1,
				timeout_count = timeout_count + ${timeout}`;
			return;
		}
		await db`INSERT INTO origin_latency_minutes (origin_id,site_id,bucket_start,min_latency_ms,max_latency_ms,sum_latency_ms,total_count,timeout_count)
			VALUES (${originId},${siteId},${bucketStart},${latency},${latency},${sum},1,${timeout})
			ON CONFLICT (origin_id,bucket_start) DO UPDATE SET
			min_latency_ms = CASE WHEN origin_latency_minutes.min_latency_ms IS NULL THEN excluded.min_latency_ms WHEN excluded.min_latency_ms IS NULL THEN origin_latency_minutes.min_latency_ms WHEN origin_latency_minutes.min_latency_ms <= excluded.min_latency_ms THEN origin_latency_minutes.min_latency_ms ELSE excluded.min_latency_ms END,
			max_latency_ms = CASE WHEN origin_latency_minutes.max_latency_ms IS NULL THEN excluded.max_latency_ms WHEN excluded.max_latency_ms IS NULL THEN origin_latency_minutes.max_latency_ms WHEN origin_latency_minutes.max_latency_ms >= excluded.max_latency_ms THEN origin_latency_minutes.max_latency_ms ELSE excluded.max_latency_ms END,
			sum_latency_ms = origin_latency_minutes.sum_latency_ms + excluded.sum_latency_ms,
			total_count = origin_latency_minutes.total_count + excluded.total_count,
			timeout_count = origin_latency_minutes.timeout_count + excluded.timeout_count`;
	},
	async originLatencyMetrics(
		siteId: string | string[] | undefined,
		since: number,
		until: number,
		bucketMs: number,
	): Promise<{
		series: Array<{
			bucket: number;
			minLatencyMs: number | null;
			maxLatencyMs: number | null;
			avgLatencyMs: number | null;
			totalCount: number;
			timeoutCount: number;
			timeoutPct: number;
		}>;
	}> {
		const siteFilter = siteScopeFilter(siteId);
		const minuteSince = Math.floor(since / 60_000) * 60_000;
		const bucket = metricBucketExpression("bucket_start", bucketMs);
		const rows = (await db`
      SELECT ${bucket} * ${bucketMs} AS bucket,
        MIN(min_latency_ms) AS min_latency_ms,
        MAX(max_latency_ms) AS max_latency_ms,
        COALESCE(SUM(sum_latency_ms),0) AS sum_latency_ms,
        COALESCE(SUM(total_count),0) AS total_count,
        COALESCE(SUM(timeout_count),0) AS timeout_count
      FROM origin_latency_minutes
      WHERE bucket_start >= ${minuteSince} AND bucket_start <= ${until} ${siteFilter}
      GROUP BY ${bucket}
      ORDER BY bucket ASC
    `) as LatencyMinuteRow[];
		return { series: latencySeriesFromRows(since, until, bucketMs, rows) };
	},
	async deleteOriginLatencyBeforeForSiteBatch(siteId: string, cutoff: number, limit: number): Promise<number> {
		if (isMySqlDatabase()) {
			return deletedRowCount(
				await db`DELETE FROM origin_latency_minutes WHERE site_id=${siteId} AND bucket_start < ${cutoff} ORDER BY bucket_start ASC LIMIT ${limit}`,
			);
		}
		if (isSqliteDatabase()) {
			return deletedRowCount(
				await db`DELETE FROM origin_latency_minutes WHERE rowid IN (SELECT rowid FROM origin_latency_minutes WHERE site_id=${siteId} AND bucket_start < ${cutoff} ORDER BY bucket_start ASC LIMIT ${limit})`,
			);
		}
		return deletedRowCount(
			await db`DELETE FROM origin_latency_minutes WHERE ctid IN (SELECT ctid FROM origin_latency_minutes WHERE site_id=${siteId} AND bucket_start < ${cutoff} ORDER BY bucket_start ASC LIMIT ${limit})`,
		);
	},
	async assignSessionOrigin(sessionId: string, siteId: string, originId: string | null): Promise<void> {
		await db`UPDATE access_sessions SET origin_id=${originId} WHERE id=${sessionId} AND site_id=${siteId}`;
	},
	async assignSessionsFromOrigin(originId: string, replacementId: string | null): Promise<void> {
		await db`UPDATE access_sessions SET origin_id=${replacementId} WHERE origin_id=${originId}`;
	},
	async deleteBackendHealthStatus(originId: string): Promise<void> {
		await db`DELETE FROM origin_backend_health_status WHERE origin_id=${originId}`;
	},
	async routePolicies(siteId: string): Promise<RoutePolicyRecord[]> {
		return (await db`SELECT * FROM route_policies WHERE site_id=${siteId} ORDER BY priority DESC, created_at ASC`) as RoutePolicyRecord[];
	},
	async routePolicyById(id: string, siteId: string): Promise<RoutePolicyRecord | null> {
		const rows = (await db`SELECT * FROM route_policies WHERE id=${id} AND site_id=${siteId} LIMIT 1`) as RoutePolicyRecord[];
		return rows[0] ?? null;
	},
	async insertRoutePolicy(policy: RoutePolicyRecord): Promise<void> {
		assertPrimaryWritable("a route policy");
		await db.begin(async (transaction) => {
			await transaction`INSERT INTO route_policies (id,site_id,name,path_pattern,methods_json,access_mode,challenge_policy_json,rate_limit_enabled,rate_limit_algorithm,rate_limit_window_ms,rate_limit_max,rate_limit_refill_rate,rate_limit_refill_interval_ms,rate_limit_precision_ms,rate_limit_key_mode,rate_limit_key_header,rate_limit_scope,websocket_policy_json,http_policy_json,default_ip_action,default_country_action,priority,enabled,created_at,updated_at)
				VALUES (${policy.id},${policy.site_id},${policy.name},${policy.path_pattern},${policy.methods_json},${policy.access_mode},${policy.challenge_policy_json},${policy.rate_limit_enabled},${policy.rate_limit_algorithm},${policy.rate_limit_window_ms},${policy.rate_limit_max},${policy.rate_limit_refill_rate},${policy.rate_limit_refill_interval_ms},${policy.rate_limit_precision_ms},${policy.rate_limit_key_mode},${policy.rate_limit_key_header},${policy.rate_limit_scope},${policy.websocket_policy_json ?? null},${policy.http_policy_json ?? null},${policy.default_ip_action ?? "inherit"},${policy.default_country_action ?? "inherit"},${policy.priority},${policy.enabled},${policy.created_at},${policy.updated_at})`;
			await appendChangelogEntry(transaction, "route_policy", policy.id, "insert", policy);
		});
	},
	async updateRoutePolicy(policy: RoutePolicyRecord): Promise<void> {
		assertPrimaryWritable("a route policy");
		await db.begin(async (transaction) => {
			await transaction`UPDATE route_policies SET name=${policy.name}, path_pattern=${policy.path_pattern}, methods_json=${policy.methods_json}, access_mode=${policy.access_mode}, challenge_policy_json=${policy.challenge_policy_json}, rate_limit_enabled=${policy.rate_limit_enabled}, rate_limit_algorithm=${policy.rate_limit_algorithm}, rate_limit_window_ms=${policy.rate_limit_window_ms}, rate_limit_max=${policy.rate_limit_max}, rate_limit_refill_rate=${policy.rate_limit_refill_rate}, rate_limit_refill_interval_ms=${policy.rate_limit_refill_interval_ms}, rate_limit_precision_ms=${policy.rate_limit_precision_ms}, rate_limit_key_mode=${policy.rate_limit_key_mode}, rate_limit_key_header=${policy.rate_limit_key_header}, rate_limit_scope=${policy.rate_limit_scope}, websocket_policy_json=${policy.websocket_policy_json ?? null}, http_policy_json=${policy.http_policy_json ?? null}, default_ip_action=${policy.default_ip_action ?? "inherit"}, default_country_action=${policy.default_country_action ?? "inherit"}, priority=${policy.priority}, enabled=${policy.enabled}, updated_at=${policy.updated_at} WHERE id=${policy.id} AND site_id=${policy.site_id}`;
			await appendChangelogEntry(transaction, "route_policy", policy.id, "update", policy);
		});
	},
	async deleteRoutePolicy(id: string, siteId: string): Promise<void> {
		assertPrimaryWritable("a route policy");
		const ruleIds = {
			ip: ((await db`SELECT id FROM route_ip_rules WHERE route_policy_id=${id}`) as Array<{ id: string }>).map((r) => r.id),
			country: ((await db`SELECT id FROM route_country_rules WHERE route_policy_id=${id}`) as Array<{ id: string }>).map((r) => r.id),
			asn: ((await db`SELECT id FROM route_asn_rules WHERE route_policy_id=${id}`) as Array<{ id: string }>).map((r) => r.id),
		};
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM route_ip_rules WHERE route_policy_id=${id}`;
			await transaction`DELETE FROM route_country_rules WHERE route_policy_id=${id}`;
			await transaction`DELETE FROM route_asn_rules WHERE route_policy_id=${id}`;
			await transaction`DELETE FROM route_policies WHERE id=${id} AND site_id=${siteId}`;
			for (const ruleId of ruleIds.ip) await appendChangelogEntry(transaction, "route_ip_rule", ruleId, "delete", null);
			for (const ruleId of ruleIds.country) await appendChangelogEntry(transaction, "route_country_rule", ruleId, "delete", null);
			for (const ruleId of ruleIds.asn) await appendChangelogEntry(transaction, "route_asn_rule", ruleId, "delete", null);
			await appendChangelogEntry(transaction, "route_policy", id, "delete", null);
		});
	},
	async sessionByHash(siteId: string, hash: string): Promise<AccessSessionRecord | null> {
		const rows = (await db`SELECT * FROM access_sessions WHERE site_id=${siteId} AND token_hash=${hash} LIMIT 1`) as AccessSessionRecord[];
		return rows[0] ?? null;
	},
	async sessionById(siteId: string, id: string): Promise<AccessSessionRecord | null> {
		const rows = (await db`SELECT * FROM access_sessions WHERE site_id=${siteId} AND id=${id} LIMIT 1`) as AccessSessionRecord[];
		return rows[0] ?? null;
	},
	async insertSession(session: AccessSessionRecord): Promise<void> {
		await db.begin(async (transaction) => {
			await transaction`INSERT INTO access_sessions (id,site_id,token_hash,initial_ip,last_ip,user_agent_hash,created_at,last_seen_at,expires_at,revoked_at,verification_summary_json,request_count,country_code,asn,asn_org,access_user_id,authenticated_at,origin_id,sso_sid)
			VALUES (${session.id},${session.site_id},${session.token_hash},${session.initial_ip},${session.last_ip},${session.user_agent_hash},${session.created_at},${session.last_seen_at},${session.expires_at},${session.revoked_at},${session.verification_summary_json},${session.request_count},${session.country_code},${session.asn},${session.asn_org},${session.access_user_id},${session.authenticated_at},${session.origin_id ?? null},${session.sso_sid ?? null})`;
			await replicateSessionChange(transaction, "access_session", session.id, "insert", session);
		});
	},
	async authenticateSession(id: string, siteId: string, userId: string, now: number, ssoSid: string | null = null): Promise<void> {
		await db.begin(async (transaction) => {
			const existing =
				(await transaction`SELECT * FROM access_sessions WHERE id=${id} AND site_id=${siteId} AND revoked_at IS NULL AND expires_at > ${now} LIMIT 1`) as AccessSessionRecord[];
			await transaction`UPDATE access_sessions SET access_user_id=${userId}, authenticated_at=${now}, sso_sid=${ssoSid} WHERE id=${id} AND site_id=${siteId} AND revoked_at IS NULL AND expires_at > ${now}`;
			if (existing[0]) {
				await replicateSessionChange(transaction, "access_session", id, "update", {
					...existing[0],
					access_user_id: userId,
					authenticated_at: now,
					sso_sid: ssoSid,
				});
			}
		});
	},
	async revokeAccessSessionsBySsoSid(siteId: string, sid: string, now: number): Promise<number> {
		return await db.begin(async (transaction) => {
			const matches =
				(await transaction`SELECT * FROM access_sessions WHERE site_id=${siteId} AND sso_sid=${sid} AND revoked_at IS NULL`) as AccessSessionRecord[];
			const affected = deletedRowCount(
				await transaction`UPDATE access_sessions SET revoked_at=${now} WHERE site_id=${siteId} AND sso_sid=${sid} AND revoked_at IS NULL`,
			);
			for (const session of matches) await replicateSessionChange(transaction, "access_session", session.id, "update", { ...session, revoked_at: now });
			return affected;
		});
	},
	async activeAccessSessionForUser(siteId: string, userId: string, now: number): Promise<AccessSessionRecord | null> {
		const rows =
			(await db`SELECT * FROM access_sessions WHERE site_id=${siteId} AND access_user_id=${userId} AND revoked_at IS NULL AND expires_at > ${now} ORDER BY last_seen_at DESC LIMIT 1`) as AccessSessionRecord[];
		return rows[0] ?? null;
	},
	async revokeSessionsForAccessUser(userId: string, now: number, siteId?: string): Promise<void> {
		await db.begin(async (transaction) => {
			const matches = siteId
				? ((await transaction`SELECT * FROM access_sessions WHERE access_user_id=${userId} AND site_id=${siteId} AND revoked_at IS NULL`) as AccessSessionRecord[])
				: ((await transaction`SELECT * FROM access_sessions WHERE access_user_id=${userId} AND revoked_at IS NULL`) as AccessSessionRecord[]);
			if (siteId) {
				await transaction`UPDATE access_sessions SET revoked_at=${now} WHERE access_user_id=${userId} AND site_id=${siteId} AND revoked_at IS NULL`;
			} else {
				await transaction`UPDATE access_sessions SET revoked_at=${now} WHERE access_user_id=${userId} AND revoked_at IS NULL`;
			}
			for (const session of matches) await replicateSessionChange(transaction, "access_session", session.id, "update", { ...session, revoked_at: now });
		});
	},
	async accessSettings(siteId: string): Promise<SiteAccessSettingsRecord | null> {
		const rows = (await db`SELECT * FROM site_access_settings WHERE site_id=${siteId} LIMIT 1`) as SiteAccessSettingsRecord[];
		return rows[0] ?? null;
	},
	async ensureAccessSettings(siteId: string, now = Date.now()): Promise<SiteAccessSettingsRecord> {
		const existing = await this.accessSettings(siteId);
		if (existing) return existing;
		const settings: SiteAccessSettingsRecord = {
			site_id: siteId,
			enabled: 0,
			send_username_to_upstream: 0,
			session_verification_token_hash: null,
			session_verification_token_created_at: null,
			created_at: now,
			updated_at: now,
		};
		try {
			await db`INSERT INTO site_access_settings (site_id,enabled,send_username_to_upstream,session_verification_token_hash,session_verification_token_created_at,created_at,updated_at) VALUES (${siteId},0,0,${null},${null},${now},${now})`;
		} catch {
			return (await this.accessSettings(siteId)) ?? settings;
		}
		return settings;
	},
	async updateAccessSettings(settings: SiteAccessSettingsRecord): Promise<void> {
		assertPrimaryWritable("site access settings");
		await db.begin(async (transaction) => {
			await transaction`UPDATE site_access_settings SET enabled=${settings.enabled},send_username_to_upstream=${settings.send_username_to_upstream},session_verification_token_hash=${settings.session_verification_token_hash},session_verification_token_created_at=${settings.session_verification_token_created_at},updated_at=${settings.updated_at} WHERE site_id=${settings.site_id}`;
			await appendChangelogEntry(transaction, "site_access_settings", settings.site_id, "update", settings);
		});
	},
	async accessUsersForSite(siteId: string): Promise<Array<AccessUserRecord & { site_count: number | string }>> {
		return (await db`SELECT u.*, (SELECT COUNT(*) FROM site_access_users memberships WHERE memberships.user_id=u.id) AS site_count
			FROM access_users u JOIN site_access_users membership ON membership.user_id=u.id
			WHERE membership.site_id=${siteId} ORDER BY u.username ASC`) as Array<AccessUserRecord & { site_count: number | string }>;
	},
	async availableAccessUsers(siteId: string): Promise<Array<AccessUserRecord & { site_count: number | string }>> {
		return (await db`SELECT u.*, (SELECT COUNT(*) FROM site_access_users memberships WHERE memberships.user_id=u.id) AS site_count
			FROM access_users u
			WHERE u.id NOT IN (SELECT user_id FROM site_access_users WHERE site_id=${siteId})
			ORDER BY u.username ASC`) as Array<AccessUserRecord & { site_count: number | string }>;
	},
	async accessUserById(id: string): Promise<AccessUserRecord | null> {
		const rows = (await db`SELECT * FROM access_users WHERE id=${id} LIMIT 1`) as AccessUserRecord[];
		return rows[0] ?? null;
	},
	async accessUserByUsername(username: string): Promise<AccessUserRecord | null> {
		const rows = (await db`SELECT * FROM access_users WHERE username=${username} LIMIT 1`) as AccessUserRecord[];
		return rows[0] ?? null;
	},
	async accessUserForSite(siteId: string, userId: string): Promise<AccessUserRecord | null> {
		const rows =
			(await db`SELECT u.* FROM access_users u JOIN site_access_users membership ON membership.user_id=u.id WHERE membership.site_id=${siteId} AND u.id=${userId} LIMIT 1`) as AccessUserRecord[];
		return rows[0] ?? null;
	},
	async accessUserForSiteByUsername(siteId: string, username: string): Promise<AccessUserRecord | null> {
		const rows =
			(await db`SELECT u.* FROM access_users u JOIN site_access_users membership ON membership.user_id=u.id WHERE membership.site_id=${siteId} AND u.username=${username} LIMIT 1`) as AccessUserRecord[];
		return rows[0] ?? null;
	},
	async insertAccessUser(user: AccessUserRecord): Promise<void> {
		await db.begin(async (transaction) => {
			await transaction`INSERT INTO access_users (id,username,password_hash,enabled,created_at,updated_at,totp_required,totp_secret_encrypted,totp_enrolled_at,api_token_hash,api_token_created_at,sso_subject,auth_source)
			VALUES (${user.id},${user.username},${user.password_hash},${user.enabled},${user.created_at},${user.updated_at},${user.totp_required},${user.totp_secret_encrypted},${user.totp_enrolled_at},${user.api_token_hash},${user.api_token_created_at},${user.sso_subject},${user.auth_source})`;
			await replicateSessionChange(transaction, "access_user", user.id, "insert", user);
		});
	},
	async updateAccessUser(user: AccessUserRecord): Promise<void> {
		await db.begin(async (transaction) => {
			const existing = (await transaction`SELECT * FROM access_users WHERE id=${user.id} LIMIT 1`) as AccessUserRecord[];
			await transaction`UPDATE access_users SET username=${user.username},password_hash=${user.password_hash},enabled=${user.enabled},updated_at=${user.updated_at},totp_required=${user.totp_required},totp_secret_encrypted=${user.totp_secret_encrypted},totp_enrolled_at=${user.totp_enrolled_at},api_token_hash=${user.api_token_hash},api_token_created_at=${user.api_token_created_at},sso_subject=${user.sso_subject},auth_source=${user.auth_source} WHERE id=${user.id}`;
			const patch = relayFieldPatch(
				existing[0] as unknown as Record<string, unknown> | undefined,
				user as unknown as Record<string, unknown>,
				ACCESS_USER_MUTABLE_FIELDS,
			);
			await replicateSessionChange(transaction, "access_user", user.id, "update", patch, user);
		});
	},
	async accessUserByApiTokenHash(hash: string): Promise<AccessUserRecord | null> {
		const rows = (await db`SELECT * FROM access_users WHERE api_token_hash=${hash} LIMIT 1`) as AccessUserRecord[];
		return rows[0] ?? null;
	},
	async accessUserBySsoSubject(subject: string): Promise<AccessUserRecord | null> {
		const rows = (await db`SELECT * FROM access_users WHERE sso_subject=${subject} LIMIT 1`) as AccessUserRecord[];
		return rows[0] ?? null;
	},
	async deleteAccessUser(userId: string): Promise<void> {
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM access_users WHERE id=${userId}`;
			await replicateSessionChange(transaction, "access_user", userId, "delete", null);
		});
	},
	async assignAccessUser(siteId: string, userId: string, now = Date.now()): Promise<void> {
		await db.begin(async (transaction) => {
			await transaction`INSERT INTO site_access_users (site_id,user_id,created_at) VALUES (${siteId},${userId},${now})`;
			await replicateSessionChange(transaction, "site_access_user", `${siteId}:${userId}`, "insert", { site_id: siteId, user_id: userId, created_at: now });
		});
	},
	async unassignAccessUser(siteId: string, userId: string): Promise<void> {
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM site_access_users WHERE site_id=${siteId} AND user_id=${userId}`;
			await replicateSessionChange(transaction, "site_access_user", `${siteId}:${userId}`, "delete", null);
		});
	},
	async accessSiteIdsForUser(userId: string): Promise<string[]> {
		const rows = (await db`SELECT site_id FROM site_access_users WHERE user_id=${userId}`) as Array<{ site_id: string }>;
		return rows.map((row) => row.site_id);
	},
	async accessWebauthnCredentialsForUserAndSite(userId: string, siteId: string): Promise<AccessWebauthnCredentialRecord[]> {
		return (await db`SELECT * FROM access_webauthn_credentials WHERE user_id=${userId} AND site_id=${siteId} ORDER BY created_at ASC`) as AccessWebauthnCredentialRecord[];
	},
	async accessWebauthnCredentialByHashForSite(hash: string, siteId: string): Promise<AccessWebauthnCredentialRecord | null> {
		const rows =
			(await db`SELECT * FROM access_webauthn_credentials WHERE credential_id_hash=${hash} AND site_id=${siteId} LIMIT 1`) as AccessWebauthnCredentialRecord[];
		return rows[0] ?? null;
	},
	async accessWebauthnCredentialById(id: string, userId: string, siteId: string): Promise<AccessWebauthnCredentialRecord | null> {
		const rows =
			(await db`SELECT * FROM access_webauthn_credentials WHERE id=${id} AND user_id=${userId} AND site_id=${siteId} LIMIT 1`) as AccessWebauthnCredentialRecord[];
		return rows[0] ?? null;
	},
	async insertAccessWebauthnCredential(record: AccessWebauthnCredentialRecord): Promise<void> {
		await db.begin(async (transaction) => {
			await transaction`INSERT INTO access_webauthn_credentials (id,user_id,site_id,rp_id,credential_id,credential_id_hash,public_key,sign_count,transports_json,aaguid,device_type,backed_up,nickname,created_at,last_used_at,updated_at)
			VALUES (${record.id},${record.user_id},${record.site_id},${record.rp_id},${record.credential_id},${record.credential_id_hash},${record.public_key},${record.sign_count},${record.transports_json},${record.aaguid},${record.device_type},${record.backed_up},${record.nickname},${record.created_at},${record.last_used_at},${record.updated_at})`;
			await replicateSessionChange(transaction, "access_webauthn_credential", record.id, "insert", record);
		});
	},

	async touchAccessWebauthnCredential(id: string, signCount: number, now: number): Promise<void> {
		await db`UPDATE access_webauthn_credentials SET sign_count=${signCount}, last_used_at=${now}, updated_at=${now} WHERE id=${id}`;
	},
	async renameAccessWebauthnCredential(id: string, userId: string, siteId: string, nickname: string | null, now: number): Promise<void> {
		await db.begin(async (transaction) => {
			const existing =
				(await transaction`SELECT * FROM access_webauthn_credentials WHERE id=${id} AND user_id=${userId} AND site_id=${siteId} LIMIT 1`) as AccessWebauthnCredentialRecord[];
			await transaction`UPDATE access_webauthn_credentials SET nickname=${nickname}, updated_at=${now} WHERE id=${id} AND user_id=${userId} AND site_id=${siteId}`;
			if (existing[0]) await replicateSessionChange(transaction, "access_webauthn_credential", id, "update", { ...existing[0], nickname, updated_at: now });
		});
	},
	async deleteAccessWebauthnCredential(id: string, userId: string, siteId: string): Promise<void> {
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM access_webauthn_credentials WHERE id=${id} AND user_id=${userId} AND site_id=${siteId}`;
			await replicateSessionChange(transaction, "access_webauthn_credential", id, "delete", null);
		});
	},
	async deleteAccessWebauthnCredentialsForUserAndSite(userId: string, siteId: string): Promise<void> {
		await db.begin(async (transaction) => {
			const existing = (await transaction`SELECT id FROM access_webauthn_credentials WHERE user_id=${userId} AND site_id=${siteId}`) as Array<{ id: string }>;
			await transaction`DELETE FROM access_webauthn_credentials WHERE user_id=${userId} AND site_id=${siteId}`;
			for (const row of existing) await replicateSessionChange(transaction, "access_webauthn_credential", row.id, "delete", null);
		});
	},
	async deleteAllAccessWebauthnCredentialsForUser(userId: string): Promise<void> {
		await db.begin(async (transaction) => {
			const existing = (await transaction`SELECT id FROM access_webauthn_credentials WHERE user_id=${userId}`) as Array<{ id: string }>;
			await transaction`DELETE FROM access_webauthn_credentials WHERE user_id=${userId}`;
			for (const row of existing) await replicateSessionChange(transaction, "access_webauthn_credential", row.id, "delete", null);
		});
	},
	async touchSession(id: string, ip: string, now: number): Promise<void> {
		await db`UPDATE access_sessions SET last_ip=${ip}, last_seen_at=${now}, request_count=request_count+1 WHERE id=${id}`;
	},
	async revokeSession(id: string, now: number): Promise<void> {
		await db.begin(async (transaction) => {
			const existing = (await transaction`SELECT * FROM access_sessions WHERE id=${id} AND revoked_at IS NULL LIMIT 1`) as AccessSessionRecord[];
			await transaction`UPDATE access_sessions SET revoked_at=${now} WHERE id=${id} AND revoked_at IS NULL`;
			if (existing[0]) await replicateSessionChange(transaction, "access_session", id, "update", { ...existing[0], revoked_at: now });
		});
	},
	async revokeSessionForSite(id: string, siteId: string, now: number): Promise<void> {
		await db.begin(async (transaction) => {
			const existing =
				(await transaction`SELECT * FROM access_sessions WHERE id=${id} AND site_id=${siteId} AND revoked_at IS NULL LIMIT 1`) as AccessSessionRecord[];
			await transaction`UPDATE access_sessions SET revoked_at=${now} WHERE id=${id} AND site_id=${siteId} AND revoked_at IS NULL`;
			if (existing[0]) await replicateSessionChange(transaction, "access_session", id, "update", { ...existing[0], revoked_at: now });
		});
	},
	async pagedSessions(query: SessionQuery): Promise<PageResult<AccessSessionRecord & { access_username: string | null }>> {
		const pattern = searchPattern(query.search);
		const exactSearch = query.search?.trim().toLowerCase() || null;
		const now = Date.now();
		const siteFilter =
			query.siteId === undefined ? db`` : Array.isArray(query.siteId) ? db`AND s.site_id IN ${db(query.siteId)}` : db`AND s.site_id=${query.siteId}`;
		const searchFilter = pattern
			? db`AND (s.id=${exactSearch} OR s.user_agent_hash=${exactSearch} OR LOWER(s.initial_ip) LIKE ${pattern} OR LOWER(s.last_ip) LIKE ${pattern} OR LOWER(COALESCE(au.username,'')) LIKE ${pattern})`
			: db``;
		const countryFilter = query.countryCode ? db`AND COALESCE(s.country_code, 'ZZ')=${query.countryCode}` : db``;
		const asnFilter = query.asn ? db`AND s.asn=${query.asn}` : db``;
		const stateFilter =
			query.state === "active"
				? db`AND s.revoked_at IS NULL AND s.expires_at > ${now}`
				: query.state === "expired"
					? db`AND s.revoked_at IS NULL AND s.expires_at <= ${now}`
					: query.state === "revoked"
						? db`AND s.revoked_at IS NOT NULL`
						: db``;
		const rangeFilter =
			query.since !== undefined && query.until !== undefined
				? db`AND s.created_at <= ${query.until} AND (s.expires_at >= ${query.since} OR s.last_seen_at >= ${query.since} OR (s.revoked_at IS NOT NULL AND s.revoked_at >= ${query.since}))`
				: db``;
		const order = db.unsafe(`s.${query.sortBy} ${query.sortDirection.toUpperCase()}`);
		const offset = (query.page - 1) * query.pageSize;
		const [countRow] = (await db`
      SELECT COUNT(*) AS count FROM access_sessions s LEFT JOIN access_users au ON au.id = s.access_user_id
      WHERE 1=1 ${siteFilter} ${searchFilter} ${countryFilter} ${asnFilter} ${stateFilter} ${rangeFilter}
    `) as Array<{ count: number | string }>;
		const items = (await db`
      SELECT s.*, au.username AS access_username FROM access_sessions s LEFT JOIN access_users au ON au.id = s.access_user_id
      WHERE 1=1 ${siteFilter} ${searchFilter} ${countryFilter} ${asnFilter} ${stateFilter} ${rangeFilter}
      ORDER BY ${order}
      LIMIT ${query.pageSize} OFFSET ${offset}
    `) as Array<AccessSessionRecord & { access_username: string | null }>;
		return pageResult(items, countRow?.count, query.page, query.pageSize);
	},
	async insertFlow(flow: ChallengeFlowRecord): Promise<void> {
		await db`INSERT INTO challenge_flows (id,site_id,return_path,client_ip,user_agent_hash,current_step,policy_json,status,created_at,expires_at,completed_at) VALUES (${flow.id},${flow.site_id},${flow.return_path},${flow.client_ip},${flow.user_agent_hash},${flow.current_step},${flow.policy_json},${flow.status},${flow.created_at},${flow.expires_at},${flow.completed_at})`;
	},
	async flow(id: string): Promise<ChallengeFlowRecord | null> {
		const rows = (await db`SELECT * FROM challenge_flows WHERE id=${id} LIMIT 1`) as ChallengeFlowRecord[];
		return rows[0] ?? null;
	},
	async updateFlowStep(id: string, step: number): Promise<void> {
		await db`UPDATE challenge_flows SET current_step=${step} WHERE id=${id}`;
	},
	async completeFlow(id: string, now: number): Promise<void> {
		await db`UPDATE challenge_flows SET status='completed', completed_at=${now} WHERE id=${id} AND status='pending'`;
	},
	async step(flowId: string, index: number): Promise<ChallengeStepRecord | null> {
		const rows = (await db`SELECT * FROM challenge_steps WHERE flow_id=${flowId} AND step_index=${index} LIMIT 1`) as ChallengeStepRecord[];
		return rows[0] ?? null;
	},
	async insertStep(step: ChallengeStepRecord): Promise<void> {
		await db`INSERT INTO challenge_steps (id,flow_id,step_index,provider,config_json,private_data_json,public_data_json,status,attempts,created_at,expires_at,completed_at) VALUES (${step.id},${step.flow_id},${step.step_index},${step.provider},${step.config_json},${step.private_data_json},${step.public_data_json},${step.status},${step.attempts},${step.created_at},${step.expires_at},${step.completed_at})`;
	},
	async failStepAttempt(id: string): Promise<void> {
		await db`UPDATE challenge_steps SET attempts=attempts+1 WHERE id=${id}`;
	},
	async completeStep(id: string, now: number): Promise<void> {
		await db`UPDATE challenge_steps SET status='completed', completed_at=${now} WHERE id=${id} AND status='pending'`;
	},
	async consumeStep(id: string, now: number): Promise<boolean> {
		try {
			await db`INSERT INTO challenge_consumptions (step_id,consumed_at) VALUES (${id},${now})`;
			return true;
		} catch {
			return false;
		}
	},
	async pagedRules(query: RuleQuery): Promise<PageResult<IpRuleRecord>> {
		const pattern = searchPattern(query.search);
		const now = Date.now();
		const searchFilter = pattern ? db`AND (LOWER(network_cidr) LIKE ${pattern} OR LOWER(reason) LIKE ${pattern} OR LOWER(rule_id) LIKE ${pattern})` : db``;
		const actionFilter = query.action ? db`AND action=${query.action}` : db``;
		const stateFilter =
			query.state === "active"
				? db`AND (expires_at IS NULL OR expires_at > ${now})`
				: query.state === "expired"
					? db`AND expires_at IS NOT NULL AND expires_at <= ${now}`
					: db``;
		const order = db.unsafe(`${query.sortBy} ${query.sortDirection.toUpperCase()}`);
		const offset = (query.page - 1) * query.pageSize;
		const [countRow] = (await db`
      SELECT COUNT(*) AS count FROM ip_rules
      WHERE site_id=${query.siteId} ${searchFilter} ${actionFilter} ${stateFilter}
    `) as Array<{ count: number | string }>;
		const items = (await db`
      SELECT * FROM ip_rules
      WHERE site_id=${query.siteId} ${searchFilter} ${actionFilter} ${stateFilter}
      ORDER BY ${order}
      LIMIT ${query.pageSize} OFFSET ${offset}
    `) as IpRuleRecord[];
		return pageResult(items, countRow?.count, query.page, query.pageSize);
	},
	async rules(siteId: string): Promise<IpRuleRecord[]> {
		return (await db`SELECT * FROM ip_rules WHERE site_id=${siteId} ORDER BY created_at DESC`) as IpRuleRecord[];
	},
	async insertRule(rule: IpRuleRecord): Promise<void> {
		await db.begin(async (transaction) => {
			await transaction`INSERT INTO ip_rules (id,site_id,network_cidr,action,reason,created_at,expires_at,rule_id) VALUES (${rule.id},${rule.site_id},${rule.network_cidr},${rule.action},${rule.reason},${rule.created_at},${rule.expires_at},${rule.rule_id})`;
			await replicateSessionChange(transaction, "ip_rule", rule.id, "insert", rule);
		});
	},
	async deleteRule(id: string): Promise<void> {
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM ip_rules WHERE id=${id}`;
			await replicateSessionChange(transaction, "ip_rule", id, "delete", null);
		});
	},
	async deleteRuleForSite(id: string, siteId: string): Promise<void> {
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM ip_rules WHERE id=${id} AND site_id=${siteId}`;
			await replicateSessionChange(transaction, "ip_rule", id, "delete", null);
		});
	},
	async deleteRulesForSite(ids: string[], siteId: string): Promise<number> {
		let deleted = 0;
		await db.begin(async (transaction) => {
			for (const id of ids) {
				await transaction`DELETE FROM ip_rules WHERE id=${id} AND site_id=${siteId}`;
				await replicateSessionChange(transaction, "ip_rule", id, "delete", null);
				deleted += 1;
			}
		});
		return deleted;
	},
	async countryRules(siteId: string): Promise<CountryRuleRecord[]> {
		return (await db`SELECT * FROM country_rules WHERE site_id=${siteId} ORDER BY country_code ASC`) as CountryRuleRecord[];
	},
	async countryRuleByCode(siteId: string, countryCode: string): Promise<CountryRuleRecord | null> {
		const rows = (await db`SELECT * FROM country_rules WHERE site_id=${siteId} AND country_code=${countryCode} LIMIT 1`) as CountryRuleRecord[];
		return rows[0] ?? null;
	},
	async insertCountryRule(rule: CountryRuleRecord): Promise<void> {
		await db.begin(async (transaction) => {
			await transaction`INSERT INTO country_rules (id,site_id,country_code,action,reason,created_at,expires_at) VALUES (${rule.id},${rule.site_id},${rule.country_code},${rule.action},${rule.reason},${rule.created_at},${rule.expires_at})`;
			await replicateSessionChange(transaction, "country_rule", rule.id, "insert", rule);
		});
	},
	async deleteCountryRuleForSite(id: string, siteId: string): Promise<void> {
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM country_rules WHERE id=${id} AND site_id=${siteId}`;
			await replicateSessionChange(transaction, "country_rule", id, "delete", null);
		});
	},
	async asnRules(siteId: string): Promise<AsnRuleRecord[]> {
		return (await db`SELECT * FROM asn_rules WHERE site_id=${siteId} ORDER BY asn ASC`) as AsnRuleRecord[];
	},
	async asnRuleByAsn(siteId: string, asn: number): Promise<AsnRuleRecord | null> {
		const rows = (await db`SELECT * FROM asn_rules WHERE site_id=${siteId} AND asn=${asn} LIMIT 1`) as AsnRuleRecord[];
		return rows[0] ?? null;
	},
	async insertAsnRule(rule: AsnRuleRecord): Promise<void> {
		await db.begin(async (transaction) => {
			await transaction`INSERT INTO asn_rules (id,site_id,asn,action,reason,created_at,expires_at) VALUES (${rule.id},${rule.site_id},${rule.asn},${rule.action},${rule.reason},${rule.created_at},${rule.expires_at})`;
			await replicateSessionChange(transaction, "asn_rule", rule.id, "insert", rule);
		});
	},
	async deleteAsnRuleForSite(id: string, siteId: string): Promise<void> {
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM asn_rules WHERE id=${id} AND site_id=${siteId}`;
			await replicateSessionChange(transaction, "asn_rule", id, "delete", null);
		});
	},
	async routeIpRules(routePolicyId: string): Promise<RouteIpRuleRecord[]> {
		return (await db`SELECT * FROM route_ip_rules WHERE route_policy_id=${routePolicyId} ORDER BY created_at DESC`) as RouteIpRuleRecord[];
	},
	async insertRouteIpRule(rule: RouteIpRuleRecord): Promise<void> {
		assertPrimaryWritable("a route IP rule");
		await db.begin(async (transaction) => {
			await transaction`INSERT INTO route_ip_rules (id,route_policy_id,network_cidr,action,reason,created_at,expires_at) VALUES (${rule.id},${rule.route_policy_id},${rule.network_cidr},${rule.action},${rule.reason},${rule.created_at},${rule.expires_at})`;
			await appendChangelogEntry(transaction, "route_ip_rule", rule.id, "insert", rule);
		});
	},
	async deleteRouteIpRuleForRoute(id: string, routePolicyId: string): Promise<void> {
		assertPrimaryWritable("a route IP rule");
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM route_ip_rules WHERE id=${id} AND route_policy_id=${routePolicyId}`;
			await appendChangelogEntry(transaction, "route_ip_rule", id, "delete", null);
		});
	},
	async routeCountryRules(routePolicyId: string): Promise<RouteCountryRuleRecord[]> {
		return (await db`SELECT * FROM route_country_rules WHERE route_policy_id=${routePolicyId} ORDER BY country_code ASC`) as RouteCountryRuleRecord[];
	},
	async routeCountryRuleByCode(routePolicyId: string, countryCode: string): Promise<RouteCountryRuleRecord | null> {
		const rows =
			(await db`SELECT * FROM route_country_rules WHERE route_policy_id=${routePolicyId} AND country_code=${countryCode} LIMIT 1`) as RouteCountryRuleRecord[];
		return rows[0] ?? null;
	},
	async insertRouteCountryRule(rule: RouteCountryRuleRecord): Promise<void> {
		assertPrimaryWritable("a route country rule");
		await db.begin(async (transaction) => {
			await transaction`INSERT INTO route_country_rules (id,route_policy_id,country_code,action,reason,created_at,expires_at) VALUES (${rule.id},${rule.route_policy_id},${rule.country_code},${rule.action},${rule.reason},${rule.created_at},${rule.expires_at})`;
			await appendChangelogEntry(transaction, "route_country_rule", rule.id, "insert", rule);
		});
	},
	async deleteRouteCountryRuleForRoute(id: string, routePolicyId: string): Promise<void> {
		assertPrimaryWritable("a route country rule");
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM route_country_rules WHERE id=${id} AND route_policy_id=${routePolicyId}`;
			await appendChangelogEntry(transaction, "route_country_rule", id, "delete", null);
		});
	},
	async routeAsnRules(routePolicyId: string): Promise<RouteAsnRuleRecord[]> {
		return (await db`SELECT * FROM route_asn_rules WHERE route_policy_id=${routePolicyId} ORDER BY asn ASC`) as RouteAsnRuleRecord[];
	},
	async routeAsnRuleByAsn(routePolicyId: string, asn: number): Promise<RouteAsnRuleRecord | null> {
		const rows = (await db`SELECT * FROM route_asn_rules WHERE route_policy_id=${routePolicyId} AND asn=${asn} LIMIT 1`) as RouteAsnRuleRecord[];
		return rows[0] ?? null;
	},
	async insertRouteAsnRule(rule: RouteAsnRuleRecord): Promise<void> {
		assertPrimaryWritable("a route ASN rule");
		await db.begin(async (transaction) => {
			await transaction`INSERT INTO route_asn_rules (id,route_policy_id,asn,action,reason,created_at,expires_at) VALUES (${rule.id},${rule.route_policy_id},${rule.asn},${rule.action},${rule.reason},${rule.created_at},${rule.expires_at})`;
			await appendChangelogEntry(transaction, "route_asn_rule", rule.id, "insert", rule);
		});
	},
	async deleteRouteAsnRuleForRoute(id: string, routePolicyId: string): Promise<void> {
		assertPrimaryWritable("a route ASN rule");
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM route_asn_rules WHERE id=${id} AND route_policy_id=${routePolicyId}`;
			await appendChangelogEntry(transaction, "route_asn_rule", id, "delete", null);
		});
	},
	async updateSiteNetworkDefaults(siteId: string, defaultIpAction: string, defaultCountryAction: string, updatedAt: number): Promise<void> {
		assertPrimaryWritable("a site");
		await db.begin(async (transaction) => {
			await transaction`UPDATE sites SET default_ip_action=${defaultIpAction}, default_country_action=${defaultCountryAction}, updated_at=${updatedAt} WHERE id=${siteId}`;
			const rows = (await transaction`SELECT * FROM sites WHERE id=${siteId} LIMIT 1`) as SiteRecord[];
			if (rows[0]) await appendChangelogEntry(transaction, "site", siteId, "update", rows[0]);
		});
	},
	async pagedStreamRules(query: StreamRuleQuery): Promise<PageResult<StreamIpRuleRecord>> {
		const pattern = searchPattern(query.search);
		const now = Date.now();
		const searchFilter = pattern ? db`AND (LOWER(network_cidr) LIKE ${pattern} OR LOWER(reason) LIKE ${pattern})` : db``;
		const actionFilter = query.action ? db`AND action=${query.action}` : db``;
		const stateFilter =
			query.state === "active"
				? db`AND (expires_at IS NULL OR expires_at > ${now})`
				: query.state === "expired"
					? db`AND expires_at IS NOT NULL AND expires_at <= ${now}`
					: db``;
		const order = db.unsafe(`${query.sortBy} ${query.sortDirection.toUpperCase()}`);
		const offset = (query.page - 1) * query.pageSize;
		const [countRow] = (await db`
      SELECT COUNT(*) AS count FROM stream_ip_rules
      WHERE stream_id=${query.streamId} ${searchFilter} ${actionFilter} ${stateFilter}
    `) as Array<{ count: number | string }>;
		const items = (await db`
      SELECT * FROM stream_ip_rules
      WHERE stream_id=${query.streamId} ${searchFilter} ${actionFilter} ${stateFilter}
      ORDER BY ${order}
      LIMIT ${query.pageSize} OFFSET ${offset}
    `) as StreamIpRuleRecord[];
		return pageResult(items, countRow?.count, query.page, query.pageSize);
	},
	async streamRules(streamId: string): Promise<StreamIpRuleRecord[]> {
		return (await db`SELECT * FROM stream_ip_rules WHERE stream_id=${streamId} ORDER BY created_at DESC`) as StreamIpRuleRecord[];
	},
	async insertStreamRule(rule: StreamIpRuleRecord): Promise<void> {
		await db.begin(async (transaction) => {
			await transaction`INSERT INTO stream_ip_rules (id,stream_id,network_cidr,action,reason,created_at,expires_at) VALUES (${rule.id},${rule.stream_id},${rule.network_cidr},${rule.action},${rule.reason},${rule.created_at},${rule.expires_at})`;
			await replicateSessionChange(transaction, "stream_ip_rule", rule.id, "insert", rule);
		});
	},
	async deleteStreamRuleForStream(id: string, streamId: string): Promise<void> {
		assertPrimaryWritable("a stream network rule");
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM stream_ip_rules WHERE id=${id} AND stream_id=${streamId}`;
			await appendChangelogEntry(transaction, "stream_ip_rule", id, "delete", null);
		});
	},
	async deleteStreamRulesForStream(ids: string[], streamId: string): Promise<number> {
		assertPrimaryWritable("a stream network rule");
		let deleted = 0;
		await db.begin(async (transaction) => {
			for (const id of ids) {
				await transaction`DELETE FROM stream_ip_rules WHERE id=${id} AND stream_id=${streamId}`;
				await appendChangelogEntry(transaction, "stream_ip_rule", id, "delete", null);
				deleted += 1;
			}
		});
		return deleted;
	},
	async streamCountryRules(streamId: string): Promise<StreamCountryRuleRecord[]> {
		return (await db`SELECT * FROM stream_country_rules WHERE stream_id=${streamId} ORDER BY country_code ASC`) as StreamCountryRuleRecord[];
	},
	async streamCountryRuleByCode(streamId: string, countryCode: string): Promise<StreamCountryRuleRecord | null> {
		const rows =
			(await db`SELECT * FROM stream_country_rules WHERE stream_id=${streamId} AND country_code=${countryCode} LIMIT 1`) as StreamCountryRuleRecord[];
		return rows[0] ?? null;
	},
	async insertStreamCountryRule(rule: StreamCountryRuleRecord): Promise<void> {
		assertPrimaryWritable("a stream network rule");
		await db.begin(async (transaction) => {
			await transaction`INSERT INTO stream_country_rules (id,stream_id,country_code,action,reason,created_at,expires_at) VALUES (${rule.id},${rule.stream_id},${rule.country_code},${rule.action},${rule.reason},${rule.created_at},${rule.expires_at})`;
			await appendChangelogEntry(transaction, "stream_country_rule", rule.id, "insert", rule);
		});
	},
	async deleteStreamCountryRuleForStream(id: string, streamId: string): Promise<void> {
		assertPrimaryWritable("a stream network rule");
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM stream_country_rules WHERE id=${id} AND stream_id=${streamId}`;
			await appendChangelogEntry(transaction, "stream_country_rule", id, "delete", null);
		});
	},
	async streamAsnRules(streamId: string): Promise<StreamAsnRuleRecord[]> {
		return (await db`SELECT * FROM stream_asn_rules WHERE stream_id=${streamId} ORDER BY asn ASC`) as StreamAsnRuleRecord[];
	},
	async streamAsnRuleByAsn(streamId: string, asn: number): Promise<StreamAsnRuleRecord | null> {
		const rows = (await db`SELECT * FROM stream_asn_rules WHERE stream_id=${streamId} AND asn=${asn} LIMIT 1`) as StreamAsnRuleRecord[];
		return rows[0] ?? null;
	},
	async insertStreamAsnRule(rule: StreamAsnRuleRecord): Promise<void> {
		assertPrimaryWritable("a stream network rule");
		await db.begin(async (transaction) => {
			await transaction`INSERT INTO stream_asn_rules (id,stream_id,asn,action,reason,created_at,expires_at) VALUES (${rule.id},${rule.stream_id},${rule.asn},${rule.action},${rule.reason},${rule.created_at},${rule.expires_at})`;
			await appendChangelogEntry(transaction, "stream_asn_rule", rule.id, "insert", rule);
		});
	},
	async deleteStreamAsnRuleForStream(id: string, streamId: string): Promise<void> {
		assertPrimaryWritable("a stream network rule");
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM stream_asn_rules WHERE id=${id} AND stream_id=${streamId}`;
			await appendChangelogEntry(transaction, "stream_asn_rule", id, "delete", null);
		});
	},
	async updateStreamNetworkDefaults(streamId: string, defaultIpAction: string, defaultCountryAction: string, updatedAt: number): Promise<void> {
		assertPrimaryWritable("a stream");
		await db.begin(async (transaction) => {
			await transaction`UPDATE streams SET default_ip_action=${defaultIpAction}, default_country_action=${defaultCountryAction}, updated_at=${updatedAt} WHERE id=${streamId}`;
			const rows = (await transaction`SELECT * FROM streams WHERE id=${streamId} LIMIT 1`) as StreamRecord[];
			if (rows[0]) await appendChangelogEntry(transaction, "stream", streamId, "update", rows[0]);
		});
	},
	async updateStreamProtectionPolicy(streamId: string, protectionPolicyJson: string, updatedAt: number): Promise<void> {
		assertPrimaryWritable("a stream");
		await db.begin(async (transaction) => {
			await transaction`UPDATE streams SET protection_policy_json=${protectionPolicyJson}, updated_at=${updatedAt} WHERE id=${streamId}`;
			const rows = (await transaction`SELECT * FROM streams WHERE id=${streamId} LIMIT 1`) as StreamRecord[];
			if (rows[0]) await appendChangelogEntry(transaction, "stream", streamId, "update", rows[0]);
		});
	},
	async updateStreamBandwidthPolicy(streamId: string, bandwidthPolicyJson: string, updatedAt: number): Promise<void> {
		assertPrimaryWritable("a stream");
		await db.begin(async (transaction) => {
			await transaction`UPDATE streams SET bandwidth_policy_json=${bandwidthPolicyJson}, updated_at=${updatedAt} WHERE id=${streamId}`;
			const rows = (await transaction`SELECT * FROM streams WHERE id=${streamId} LIMIT 1`) as StreamRecord[];
			if (rows[0]) await appendChangelogEntry(transaction, "stream", streamId, "update", rows[0]);
		});
	},
	async updateStreamNotificationPolicy(streamId: string, notificationPolicyJson: string, updatedAt: number): Promise<void> {
		assertPrimaryWritable("a stream");
		await db.begin(async (transaction) => {
			await transaction`UPDATE streams SET notification_policy_json=${notificationPolicyJson}, updated_at=${updatedAt} WHERE id=${streamId}`;
			const rows = (await transaction`SELECT * FROM streams WHERE id=${streamId} LIMIT 1`) as StreamRecord[];
			if (rows[0]) await appendChangelogEntry(transaction, "stream", streamId, "update", rows[0]);
		});
	},
	async deleteExpiredStreamRulesBeforeForStreamBatch(streamId: string, cutoff: number, limit: number): Promise<number> {
		const rows =
			(await db`SELECT id FROM stream_ip_rules WHERE stream_id=${streamId} AND expires_at IS NOT NULL AND expires_at < ${cutoff} ORDER BY expires_at ASC LIMIT ${limit}`) as Array<{
				id: string;
			}>;
		if (rows.length === 0) return 0;
		await db`DELETE FROM stream_ip_rules WHERE id IN ${db(rows.map((row) => row.id))}`;
		return rows.length;
	},
	async insertEvent(event: RequestEventRecord): Promise<void> {
		await db`INSERT INTO request_events (id,site_id,session_id,ip,method,path,status,decision,latency_ms,country_code,asn,asn_org,origin_id,cache_status,protection_status,protection_rule_id,protection_category,protection_severity,protection_ruleset_id,protection_ruleset_version,protection_matches_json,access_username,referer,referer_host,request_body,request_body_truncated,request_content_type,request_headers,request_headers_truncated,response_headers,response_headers_truncated,created_at) VALUES (${event.id},${event.site_id},${event.session_id},${event.ip},${event.method},${event.path},${event.status},${event.decision},${event.latency_ms},${event.country_code},${event.asn},${event.asn_org},${event.origin_id ?? null},${event.cache_status},${event.protection_status},${event.protection_rule_id},${event.protection_category},${event.protection_severity},${event.protection_ruleset_id},${event.protection_ruleset_version},${event.protection_matches_json},${event.access_username ?? null},${event.referer ?? null},${event.referer_host ?? null},${event.request_body ?? null},${event.request_body_truncated ?? null},${event.request_content_type ?? null},${event.request_headers ?? null},${event.request_headers_truncated ?? null},${event.response_headers ?? null},${event.response_headers_truncated ?? null},${event.created_at})`;
	},
	async updateEventResponseBody(id: string, responseBody: string, truncated: boolean, contentType: string | null): Promise<void> {
		await db`UPDATE request_events SET response_body=${responseBody}, response_body_truncated=${truncated ? 1 : 0}, response_content_type=${contentType} WHERE id=${id}`;
	},
	async addBandwidthDeltas(records: BandwidthMinuteRecord[]): Promise<void> {
		if (records.length === 0) return;
		const mysql = config.databaseUrl.startsWith("mysql://") || config.databaseUrl.startsWith("mariadb://");
		await db.begin(async (transaction) => {
			for (const record of records) {
				if (mysql) {
					await transaction`INSERT INTO bandwidth_minutes (site_id,bucket_start,ip,country_code,protocol,client_received_bytes,client_sent_bytes,upstream_sent_bytes,upstream_received_bytes)
						VALUES (${record.site_id},${record.bucket_start},${record.ip},${record.country_code},${record.protocol},${record.client_received_bytes},${record.client_sent_bytes},${record.upstream_sent_bytes},${record.upstream_received_bytes})
						ON DUPLICATE KEY UPDATE
						client_received_bytes=client_received_bytes+${record.client_received_bytes},
						client_sent_bytes=client_sent_bytes+${record.client_sent_bytes},
						upstream_sent_bytes=upstream_sent_bytes+${record.upstream_sent_bytes},
						upstream_received_bytes=upstream_received_bytes+${record.upstream_received_bytes}`;
				} else {
					await transaction`INSERT INTO bandwidth_minutes (site_id,bucket_start,ip,country_code,protocol,client_received_bytes,client_sent_bytes,upstream_sent_bytes,upstream_received_bytes)
						VALUES (${record.site_id},${record.bucket_start},${record.ip},${record.country_code},${record.protocol},${record.client_received_bytes},${record.client_sent_bytes},${record.upstream_sent_bytes},${record.upstream_received_bytes})
						ON CONFLICT (site_id,bucket_start,ip,country_code,protocol) DO UPDATE SET
						client_received_bytes=bandwidth_minutes.client_received_bytes+EXCLUDED.client_received_bytes,
						client_sent_bytes=bandwidth_minutes.client_sent_bytes+EXCLUDED.client_sent_bytes,
						upstream_sent_bytes=bandwidth_minutes.upstream_sent_bytes+EXCLUDED.upstream_sent_bytes,
						upstream_received_bytes=bandwidth_minutes.upstream_received_bytes+EXCLUDED.upstream_received_bytes`;
				}
			}
		});
	},
	async addConnectivityPingResult(target: string, bucketStart: number, result: LatencyCheckResult): Promise<void> {
		const latency = result.timedOut ? null : Math.max(0, Math.round(result.latencyMs ?? 0));
		const sum = result.timedOut ? 0 : (latency ?? 0);
		const timeout = result.timedOut ? 1 : 0;
		if (isMySqlDatabase()) {
			await db`INSERT INTO connectivity_ping_minutes (target,bucket_start,min_latency_ms,max_latency_ms,sum_latency_ms,total_count,timeout_count)
				VALUES (${target},${bucketStart},${latency},${latency},${sum},1,${timeout})
				ON DUPLICATE KEY UPDATE
				min_latency_ms = CASE WHEN min_latency_ms IS NULL THEN ${latency} WHEN ${latency} IS NULL THEN min_latency_ms WHEN min_latency_ms <= ${latency} THEN min_latency_ms ELSE ${latency} END,
				max_latency_ms = CASE WHEN max_latency_ms IS NULL THEN ${latency} WHEN ${latency} IS NULL THEN max_latency_ms WHEN max_latency_ms >= ${latency} THEN max_latency_ms ELSE ${latency} END,
				sum_latency_ms = sum_latency_ms + ${sum},
				total_count = total_count + 1,
				timeout_count = timeout_count + ${timeout}`;
			return;
		}
		await db`INSERT INTO connectivity_ping_minutes (target,bucket_start,min_latency_ms,max_latency_ms,sum_latency_ms,total_count,timeout_count)
			VALUES (${target},${bucketStart},${latency},${latency},${sum},1,${timeout})
			ON CONFLICT (target,bucket_start) DO UPDATE SET
			min_latency_ms = CASE WHEN connectivity_ping_minutes.min_latency_ms IS NULL THEN excluded.min_latency_ms WHEN excluded.min_latency_ms IS NULL THEN connectivity_ping_minutes.min_latency_ms WHEN connectivity_ping_minutes.min_latency_ms <= excluded.min_latency_ms THEN connectivity_ping_minutes.min_latency_ms ELSE excluded.min_latency_ms END,
			max_latency_ms = CASE WHEN connectivity_ping_minutes.max_latency_ms IS NULL THEN excluded.max_latency_ms WHEN excluded.max_latency_ms IS NULL THEN connectivity_ping_minutes.max_latency_ms WHEN connectivity_ping_minutes.max_latency_ms >= excluded.max_latency_ms THEN connectivity_ping_minutes.max_latency_ms ELSE excluded.max_latency_ms END,
			sum_latency_ms = connectivity_ping_minutes.sum_latency_ms + excluded.sum_latency_ms,
			total_count = connectivity_ping_minutes.total_count + excluded.total_count,
			timeout_count = connectivity_ping_minutes.timeout_count + excluded.timeout_count`;
	},
	async connectivityPingMetrics(
		targets: string[],
		since: number,
		until: number,
		bucketMs: number,
	): Promise<{
		targets: string[];
		series: Array<{ bucket: number; avg: Record<string, number | null>; timeoutPct: Record<string, number> }>;
		summary: Array<{
			target: string;
			minLatencyMs: number | null;
			maxLatencyMs: number | null;
			avgLatencyMs: number | null;
			totalCount: number;
			timeoutCount: number;
			timeoutPct: number;
		}>;
	}> {
		if (targets.length === 0) return { targets: [], series: [], summary: [] };
		const minuteSince = Math.floor(since / 60_000) * 60_000;
		const bucket = metricBucketExpression("bucket_start", bucketMs);
		const rows = (await db`
      SELECT target, ${bucket} * ${bucketMs} AS bucket,
        MIN(min_latency_ms) AS min_latency_ms,
        MAX(max_latency_ms) AS max_latency_ms,
        COALESCE(SUM(sum_latency_ms),0) AS sum_latency_ms,
        COALESCE(SUM(total_count),0) AS total_count,
        COALESCE(SUM(timeout_count),0) AS timeout_count
      FROM connectivity_ping_minutes
      WHERE target IN ${db(targets)} AND bucket_start >= ${minuteSince} AND bucket_start <= ${until}
      GROUP BY target, ${bucket}
      ORDER BY bucket ASC
    `) as Array<LatencyMinuteRow & { target: string }>;
		const points = emptyMetricPoints(since, until, bucketMs, (value) => ({
			bucket: value,
			avg: Object.fromEntries(targets.map((target) => [target, null as number | null])),
			timeoutPct: Object.fromEntries(targets.map((target) => [target, 0])),
		}));
		const byBucket = new Map(points.map((point) => [point.bucket, point]));
		const totals = new Map(targets.map((target) => [target, { min: null as number | null, max: null as number | null, sum: 0, total: 0, timeout: 0 }]));
		for (const row of rows) {
			const totalCount = toNumber(row.total_count);
			const timeoutCount = toNumber(row.timeout_count);
			const successCount = totalCount - timeoutCount;
			const point = byBucket.get(toNumber(row.bucket));
			if (point) {
				point.avg[row.target] = successCount > 0 ? toNumber(row.sum_latency_ms) / successCount : null;
				point.timeoutPct[row.target] = totalCount > 0 ? (timeoutCount / totalCount) * 100 : 0;
			}
			const total = totals.get(row.target);
			if (!total) continue;
			const rowMin = row.min_latency_ms === null ? null : toNumber(row.min_latency_ms);
			const rowMax = row.max_latency_ms === null ? null : toNumber(row.max_latency_ms);
			total.min = rowMin === null ? total.min : total.min === null ? rowMin : Math.min(total.min, rowMin);
			total.max = rowMax === null ? total.max : total.max === null ? rowMax : Math.max(total.max, rowMax);
			total.sum += toNumber(row.sum_latency_ms);
			total.total += totalCount;
			total.timeout += timeoutCount;
		}
		const summary = targets.map((target) => {
			const total = totals.get(target)!;
			const successCount = total.total - total.timeout;
			return {
				target,
				minLatencyMs: total.min,
				maxLatencyMs: total.max,
				avgLatencyMs: successCount > 0 ? total.sum / successCount : null,
				totalCount: total.total,
				timeoutCount: total.timeout,
				timeoutPct: total.total > 0 ? (total.timeout / total.total) * 100 : 0,
			};
		});
		return { targets, series: points, summary };
	},
	async deleteConnectivityPingBeforeBatch(cutoff: number, limit: number): Promise<number> {
		if (isMySqlDatabase()) {
			return deletedRowCount(await db`DELETE FROM connectivity_ping_minutes WHERE bucket_start < ${cutoff} ORDER BY bucket_start ASC LIMIT ${limit}`);
		}
		if (isSqliteDatabase()) {
			return deletedRowCount(
				await db`DELETE FROM connectivity_ping_minutes WHERE rowid IN (SELECT rowid FROM connectivity_ping_minutes WHERE bucket_start < ${cutoff} ORDER BY bucket_start ASC LIMIT ${limit})`,
			);
		}
		return deletedRowCount(
			await db`DELETE FROM connectivity_ping_minutes WHERE ctid IN (SELECT ctid FROM connectivity_ping_minutes WHERE bucket_start < ${cutoff} ORDER BY bucket_start ASC LIMIT ${limit})`,
		);
	},
	async addSystemMetricSample(bucketStart: number, sample: SystemMetricSample): Promise<void> {
		const cpu = Math.max(0, Math.min(100, sample.cpuPct));
		const memoryUsed = Math.max(0, Math.round(sample.memoryUsedBytes));
		const memoryTotal = Math.max(0, Math.round(sample.memoryTotalBytes));
		const diskUsed = Math.max(0, Math.round(sample.diskUsedBytes));
		const diskTotal = Math.max(0, Math.round(sample.diskTotalBytes));
		const rxBps = Math.max(0, sample.networkRxBps);
		const txBps = Math.max(0, sample.networkTxBps);
		if (isMySqlDatabase()) {
			await db`INSERT INTO system_metrics_minutes
				(bucket_start,cpu_min_pct,cpu_max_pct,cpu_sum_pct,memory_min_bytes,memory_max_bytes,memory_sum_bytes,memory_total_bytes,disk_min_bytes,disk_max_bytes,disk_sum_bytes,disk_total_bytes,network_rx_min_bps,network_rx_max_bps,network_rx_sum_bps,network_tx_min_bps,network_tx_max_bps,network_tx_sum_bps,sample_count)
				VALUES (${bucketStart},${cpu},${cpu},${cpu},${memoryUsed},${memoryUsed},${memoryUsed},${memoryTotal},${diskUsed},${diskUsed},${diskUsed},${diskTotal},${rxBps},${rxBps},${rxBps},${txBps},${txBps},${txBps},1)
				ON DUPLICATE KEY UPDATE
				cpu_min_pct = CASE WHEN cpu_min_pct <= ${cpu} THEN cpu_min_pct ELSE ${cpu} END,
				cpu_max_pct = CASE WHEN cpu_max_pct >= ${cpu} THEN cpu_max_pct ELSE ${cpu} END,
				cpu_sum_pct = cpu_sum_pct + ${cpu},
				memory_min_bytes = CASE WHEN memory_min_bytes <= ${memoryUsed} THEN memory_min_bytes ELSE ${memoryUsed} END,
				memory_max_bytes = CASE WHEN memory_max_bytes >= ${memoryUsed} THEN memory_max_bytes ELSE ${memoryUsed} END,
				memory_sum_bytes = memory_sum_bytes + ${memoryUsed},
				memory_total_bytes = ${memoryTotal},
				disk_min_bytes = CASE WHEN disk_min_bytes <= ${diskUsed} THEN disk_min_bytes ELSE ${diskUsed} END,
				disk_max_bytes = CASE WHEN disk_max_bytes >= ${diskUsed} THEN disk_max_bytes ELSE ${diskUsed} END,
				disk_sum_bytes = disk_sum_bytes + ${diskUsed},
				disk_total_bytes = ${diskTotal},
				network_rx_min_bps = CASE WHEN network_rx_min_bps <= ${rxBps} THEN network_rx_min_bps ELSE ${rxBps} END,
				network_rx_max_bps = CASE WHEN network_rx_max_bps >= ${rxBps} THEN network_rx_max_bps ELSE ${rxBps} END,
				network_rx_sum_bps = network_rx_sum_bps + ${rxBps},
				network_tx_min_bps = CASE WHEN network_tx_min_bps <= ${txBps} THEN network_tx_min_bps ELSE ${txBps} END,
				network_tx_max_bps = CASE WHEN network_tx_max_bps >= ${txBps} THEN network_tx_max_bps ELSE ${txBps} END,
				network_tx_sum_bps = network_tx_sum_bps + ${txBps},
				sample_count = sample_count + 1`;
			return;
		}
		await db`INSERT INTO system_metrics_minutes
			(bucket_start,cpu_min_pct,cpu_max_pct,cpu_sum_pct,memory_min_bytes,memory_max_bytes,memory_sum_bytes,memory_total_bytes,disk_min_bytes,disk_max_bytes,disk_sum_bytes,disk_total_bytes,network_rx_min_bps,network_rx_max_bps,network_rx_sum_bps,network_tx_min_bps,network_tx_max_bps,network_tx_sum_bps,sample_count)
			VALUES (${bucketStart},${cpu},${cpu},${cpu},${memoryUsed},${memoryUsed},${memoryUsed},${memoryTotal},${diskUsed},${diskUsed},${diskUsed},${diskTotal},${rxBps},${rxBps},${rxBps},${txBps},${txBps},${txBps},1)
			ON CONFLICT (bucket_start) DO UPDATE SET
			cpu_min_pct = CASE WHEN system_metrics_minutes.cpu_min_pct <= excluded.cpu_min_pct THEN system_metrics_minutes.cpu_min_pct ELSE excluded.cpu_min_pct END,
			cpu_max_pct = CASE WHEN system_metrics_minutes.cpu_max_pct >= excluded.cpu_max_pct THEN system_metrics_minutes.cpu_max_pct ELSE excluded.cpu_max_pct END,
			cpu_sum_pct = system_metrics_minutes.cpu_sum_pct + excluded.cpu_sum_pct,
			memory_min_bytes = CASE WHEN system_metrics_minutes.memory_min_bytes <= excluded.memory_min_bytes THEN system_metrics_minutes.memory_min_bytes ELSE excluded.memory_min_bytes END,
			memory_max_bytes = CASE WHEN system_metrics_minutes.memory_max_bytes >= excluded.memory_max_bytes THEN system_metrics_minutes.memory_max_bytes ELSE excluded.memory_max_bytes END,
			memory_sum_bytes = system_metrics_minutes.memory_sum_bytes + excluded.memory_sum_bytes,
			memory_total_bytes = excluded.memory_total_bytes,
			disk_min_bytes = CASE WHEN system_metrics_minutes.disk_min_bytes <= excluded.disk_min_bytes THEN system_metrics_minutes.disk_min_bytes ELSE excluded.disk_min_bytes END,
			disk_max_bytes = CASE WHEN system_metrics_minutes.disk_max_bytes >= excluded.disk_max_bytes THEN system_metrics_minutes.disk_max_bytes ELSE excluded.disk_max_bytes END,
			disk_sum_bytes = system_metrics_minutes.disk_sum_bytes + excluded.disk_sum_bytes,
			disk_total_bytes = excluded.disk_total_bytes,
			network_rx_min_bps = CASE WHEN system_metrics_minutes.network_rx_min_bps <= excluded.network_rx_min_bps THEN system_metrics_minutes.network_rx_min_bps ELSE excluded.network_rx_min_bps END,
			network_rx_max_bps = CASE WHEN system_metrics_minutes.network_rx_max_bps >= excluded.network_rx_max_bps THEN system_metrics_minutes.network_rx_max_bps ELSE excluded.network_rx_max_bps END,
			network_rx_sum_bps = system_metrics_minutes.network_rx_sum_bps + excluded.network_rx_sum_bps,
			network_tx_min_bps = CASE WHEN system_metrics_minutes.network_tx_min_bps <= excluded.network_tx_min_bps THEN system_metrics_minutes.network_tx_min_bps ELSE excluded.network_tx_min_bps END,
			network_tx_max_bps = CASE WHEN system_metrics_minutes.network_tx_max_bps >= excluded.network_tx_max_bps THEN system_metrics_minutes.network_tx_max_bps ELSE excluded.network_tx_max_bps END,
			network_tx_sum_bps = system_metrics_minutes.network_tx_sum_bps + excluded.network_tx_sum_bps,
			sample_count = system_metrics_minutes.sample_count + excluded.sample_count`;
	},
	async systemMetrics(
		since: number,
		until: number,
		bucketMs: number,
	): Promise<{
		series: Array<{
			bucket: number;
			cpuMinPct: number | null;
			cpuAvgPct: number | null;
			cpuMaxPct: number | null;
			memoryMinBytes: number | null;
			memoryAvgBytes: number | null;
			memoryMaxBytes: number | null;
			memoryTotalBytes: number | null;
			diskMinBytes: number | null;
			diskAvgBytes: number | null;
			diskMaxBytes: number | null;
			diskTotalBytes: number | null;
			networkRxMinBps: number | null;
			networkRxAvgBps: number | null;
			networkRxMaxBps: number | null;
			networkTxMinBps: number | null;
			networkTxAvgBps: number | null;
			networkTxMaxBps: number | null;
		}>;
		summary: {
			cpuMinPct: number | null;
			cpuAvgPct: number | null;
			cpuMaxPct: number | null;
			memoryMinBytes: number | null;
			memoryAvgBytes: number | null;
			memoryMaxBytes: number | null;
			memoryTotalBytes: number | null;
			diskMinBytes: number | null;
			diskAvgBytes: number | null;
			diskMaxBytes: number | null;
			diskTotalBytes: number | null;
			networkRxMinBps: number | null;
			networkRxAvgBps: number | null;
			networkRxMaxBps: number | null;
			networkTxMinBps: number | null;
			networkTxAvgBps: number | null;
			networkTxMaxBps: number | null;
		};
	}> {
		const minuteSince = Math.floor(since / 60_000) * 60_000;
		const bucket = metricBucketExpression("bucket_start", bucketMs);
		const rows = (await db`
      SELECT ${bucket} * ${bucketMs} AS bucket,
        MIN(cpu_min_pct) AS cpu_min_pct, MAX(cpu_max_pct) AS cpu_max_pct, COALESCE(SUM(cpu_sum_pct),0) AS cpu_sum_pct,
        MIN(memory_min_bytes) AS memory_min_bytes, MAX(memory_max_bytes) AS memory_max_bytes, COALESCE(SUM(memory_sum_bytes),0) AS memory_sum_bytes, MAX(memory_total_bytes) AS memory_total_bytes,
        MIN(disk_min_bytes) AS disk_min_bytes, MAX(disk_max_bytes) AS disk_max_bytes, COALESCE(SUM(disk_sum_bytes),0) AS disk_sum_bytes, MAX(disk_total_bytes) AS disk_total_bytes,
        MIN(network_rx_min_bps) AS network_rx_min_bps, MAX(network_rx_max_bps) AS network_rx_max_bps, COALESCE(SUM(network_rx_sum_bps),0) AS network_rx_sum_bps,
        MIN(network_tx_min_bps) AS network_tx_min_bps, MAX(network_tx_max_bps) AS network_tx_max_bps, COALESCE(SUM(network_tx_sum_bps),0) AS network_tx_sum_bps,
        COALESCE(SUM(sample_count),0) AS sample_count
      FROM system_metrics_minutes
      WHERE bucket_start >= ${minuteSince} AND bucket_start <= ${until}
      GROUP BY ${bucket}
      ORDER BY bucket ASC
    `) as Array<{
			bucket: number | string;
			cpu_min_pct: number | string | null;
			cpu_max_pct: number | string | null;
			cpu_sum_pct: number | string;
			memory_min_bytes: number | string | null;
			memory_max_bytes: number | string | null;
			memory_sum_bytes: number | string;
			memory_total_bytes: number | string | null;
			disk_min_bytes: number | string | null;
			disk_max_bytes: number | string | null;
			disk_sum_bytes: number | string;
			disk_total_bytes: number | string | null;
			network_rx_min_bps: number | string | null;
			network_rx_max_bps: number | string | null;
			network_rx_sum_bps: number | string;
			network_tx_min_bps: number | string | null;
			network_tx_max_bps: number | string | null;
			network_tx_sum_bps: number | string;
			sample_count: number | string;
		}>;
		const points = emptyMetricPoints(since, until, bucketMs, (value) => ({
			bucket: value,
			cpuMinPct: null as number | null,
			cpuAvgPct: null as number | null,
			cpuMaxPct: null as number | null,
			memoryMinBytes: null as number | null,
			memoryAvgBytes: null as number | null,
			memoryMaxBytes: null as number | null,
			memoryTotalBytes: null as number | null,
			diskMinBytes: null as number | null,
			diskAvgBytes: null as number | null,
			diskMaxBytes: null as number | null,
			diskTotalBytes: null as number | null,
			networkRxMinBps: null as number | null,
			networkRxAvgBps: null as number | null,
			networkRxMaxBps: null as number | null,
			networkTxMinBps: null as number | null,
			networkTxAvgBps: null as number | null,
			networkTxMaxBps: null as number | null,
		}));
		const byBucket = new Map(points.map((point) => [point.bucket, point]));
		const totals = {
			cpuMin: null as number | null,
			cpuMax: null as number | null,
			cpuSum: 0,
			memoryMin: null as number | null,
			memoryMax: null as number | null,
			memorySum: 0,
			memoryTotal: null as number | null,
			diskMin: null as number | null,
			diskMax: null as number | null,
			diskSum: 0,
			diskTotal: null as number | null,
			networkRxSum: 0,
			networkRxMin: null as number | null,
			networkRxMax: null as number | null,
			networkTxSum: 0,
			networkTxMin: null as number | null,
			networkTxMax: null as number | null,
			sampleCount: 0,
		};
		for (const row of rows) {
			const sampleCount = toNumber(row.sample_count);
			const point = byBucket.get(toNumber(row.bucket));
			if (point) {
				point.cpuMinPct = row.cpu_min_pct === null ? null : toNumber(row.cpu_min_pct);
				point.cpuMaxPct = row.cpu_max_pct === null ? null : toNumber(row.cpu_max_pct);
				point.cpuAvgPct = sampleCount > 0 ? toNumber(row.cpu_sum_pct) / sampleCount : null;
				point.memoryMinBytes = row.memory_min_bytes === null ? null : toNumber(row.memory_min_bytes);
				point.memoryMaxBytes = row.memory_max_bytes === null ? null : toNumber(row.memory_max_bytes);
				point.memoryAvgBytes = sampleCount > 0 ? toNumber(row.memory_sum_bytes) / sampleCount : null;
				point.memoryTotalBytes = row.memory_total_bytes === null ? null : toNumber(row.memory_total_bytes);
				point.diskMinBytes = row.disk_min_bytes === null ? null : toNumber(row.disk_min_bytes);
				point.diskMaxBytes = row.disk_max_bytes === null ? null : toNumber(row.disk_max_bytes);
				point.diskAvgBytes = sampleCount > 0 ? toNumber(row.disk_sum_bytes) / sampleCount : null;
				point.diskTotalBytes = row.disk_total_bytes === null ? null : toNumber(row.disk_total_bytes);
				point.networkRxMinBps = row.network_rx_min_bps === null ? null : toNumber(row.network_rx_min_bps);
				point.networkRxMaxBps = row.network_rx_max_bps === null ? null : toNumber(row.network_rx_max_bps);
				point.networkRxAvgBps = sampleCount > 0 ? toNumber(row.network_rx_sum_bps) / sampleCount : null;
				point.networkTxMinBps = row.network_tx_min_bps === null ? null : toNumber(row.network_tx_min_bps);
				point.networkTxMaxBps = row.network_tx_max_bps === null ? null : toNumber(row.network_tx_max_bps);
				point.networkTxAvgBps = sampleCount > 0 ? toNumber(row.network_tx_sum_bps) / sampleCount : null;
			}
			totals.cpuMin =
				row.cpu_min_pct === null ? totals.cpuMin : totals.cpuMin === null ? toNumber(row.cpu_min_pct) : Math.min(totals.cpuMin, toNumber(row.cpu_min_pct));
			totals.cpuMax =
				row.cpu_max_pct === null ? totals.cpuMax : totals.cpuMax === null ? toNumber(row.cpu_max_pct) : Math.max(totals.cpuMax, toNumber(row.cpu_max_pct));
			totals.cpuSum += toNumber(row.cpu_sum_pct);
			totals.memoryMin =
				row.memory_min_bytes === null
					? totals.memoryMin
					: totals.memoryMin === null
						? toNumber(row.memory_min_bytes)
						: Math.min(totals.memoryMin, toNumber(row.memory_min_bytes));
			totals.memoryMax =
				row.memory_max_bytes === null
					? totals.memoryMax
					: totals.memoryMax === null
						? toNumber(row.memory_max_bytes)
						: Math.max(totals.memoryMax, toNumber(row.memory_max_bytes));
			totals.memorySum += toNumber(row.memory_sum_bytes);
			totals.memoryTotal = row.memory_total_bytes === null ? totals.memoryTotal : toNumber(row.memory_total_bytes);
			totals.diskMin =
				row.disk_min_bytes === null
					? totals.diskMin
					: totals.diskMin === null
						? toNumber(row.disk_min_bytes)
						: Math.min(totals.diskMin, toNumber(row.disk_min_bytes));
			totals.diskMax =
				row.disk_max_bytes === null
					? totals.diskMax
					: totals.diskMax === null
						? toNumber(row.disk_max_bytes)
						: Math.max(totals.diskMax, toNumber(row.disk_max_bytes));
			totals.diskSum += toNumber(row.disk_sum_bytes);
			totals.diskTotal = row.disk_total_bytes === null ? totals.diskTotal : toNumber(row.disk_total_bytes);
			totals.networkRxSum += toNumber(row.network_rx_sum_bps);
			totals.networkRxMin =
				row.network_rx_min_bps === null
					? totals.networkRxMin
					: totals.networkRxMin === null
						? toNumber(row.network_rx_min_bps)
						: Math.min(totals.networkRxMin, toNumber(row.network_rx_min_bps));
			totals.networkRxMax =
				row.network_rx_max_bps === null
					? totals.networkRxMax
					: totals.networkRxMax === null
						? toNumber(row.network_rx_max_bps)
						: Math.max(totals.networkRxMax, toNumber(row.network_rx_max_bps));
			totals.networkTxSum += toNumber(row.network_tx_sum_bps);
			totals.networkTxMin =
				row.network_tx_min_bps === null
					? totals.networkTxMin
					: totals.networkTxMin === null
						? toNumber(row.network_tx_min_bps)
						: Math.min(totals.networkTxMin, toNumber(row.network_tx_min_bps));
			totals.networkTxMax =
				row.network_tx_max_bps === null
					? totals.networkTxMax
					: totals.networkTxMax === null
						? toNumber(row.network_tx_max_bps)
						: Math.max(totals.networkTxMax, toNumber(row.network_tx_max_bps));
			totals.sampleCount += sampleCount;
		}
		const summary = {
			cpuMinPct: totals.cpuMin,
			cpuAvgPct: totals.sampleCount > 0 ? totals.cpuSum / totals.sampleCount : null,
			cpuMaxPct: totals.cpuMax,
			memoryMinBytes: totals.memoryMin,
			memoryAvgBytes: totals.sampleCount > 0 ? totals.memorySum / totals.sampleCount : null,
			memoryMaxBytes: totals.memoryMax,
			memoryTotalBytes: totals.memoryTotal,
			diskMinBytes: totals.diskMin,
			diskAvgBytes: totals.sampleCount > 0 ? totals.diskSum / totals.sampleCount : null,
			diskMaxBytes: totals.diskMax,
			diskTotalBytes: totals.diskTotal,
			networkRxMinBps: totals.networkRxMin,
			networkRxAvgBps: totals.sampleCount > 0 ? totals.networkRxSum / totals.sampleCount : null,
			networkRxMaxBps: totals.networkRxMax,
			networkTxMinBps: totals.networkTxMin,
			networkTxAvgBps: totals.sampleCount > 0 ? totals.networkTxSum / totals.sampleCount : null,
			networkTxMaxBps: totals.networkTxMax,
		};
		return { series: points, summary };
	},
	async deleteSystemMetricsBeforeBatch(cutoff: number, limit: number): Promise<number> {
		if (isMySqlDatabase()) {
			return deletedRowCount(await db`DELETE FROM system_metrics_minutes WHERE bucket_start < ${cutoff} ORDER BY bucket_start ASC LIMIT ${limit}`);
		}
		if (isSqliteDatabase()) {
			return deletedRowCount(
				await db`DELETE FROM system_metrics_minutes WHERE rowid IN (SELECT rowid FROM system_metrics_minutes WHERE bucket_start < ${cutoff} ORDER BY bucket_start ASC LIMIT ${limit})`,
			);
		}
		return deletedRowCount(
			await db`DELETE FROM system_metrics_minutes WHERE ctid IN (SELECT ctid FROM system_metrics_minutes WHERE bucket_start < ${cutoff} ORDER BY bucket_start ASC LIMIT ${limit})`,
		);
	},
	async pagedEvents(query: EventQuery): Promise<PageResult<RequestEventRecord>> {
		const pattern = searchPattern(query.search);
		const exactSearch = query.search?.trim().toLowerCase() || null;
		const siteFilter = siteScopeFilter(query.siteId);
		const searchFilter = pattern
			? db`AND (id=${exactSearch} OR LOWER(ip) LIKE ${pattern} OR LOWER(path) LIKE ${pattern} OR LOWER(COALESCE(protection_rule_id,'')) LIKE ${pattern} OR LOWER(COALESCE(access_username,'')) LIKE ${pattern} OR LOWER(COALESCE(referer_host,'')) LIKE ${pattern} OR session_id=${exactSearch})`
			: db``;
		const decisionFilter = query.decision ? db`AND decision=${query.decision}` : db``;
		const cacheStatusFilter = query.cacheStatus ? db`AND cache_status=${query.cacheStatus}` : db``;
		const protectionStatusFilter = query.protectionStatus ? db`AND protection_status=${query.protectionStatus}` : db``;
		const originFilter = query.originId ? db`AND origin_id=${query.originId}` : db``;
		const countryFilter = query.countryCode ? db`AND COALESCE(country_code, 'ZZ')=${query.countryCode}` : db``;
		const asnFilter = query.asn ? db`AND asn=${query.asn}` : db``;
		const methodFilter = query.method ? db`AND method=${query.method}` : db``;
		const statusFilter =
			query.statusGroup === "1xx"
				? db`AND status >= 100 AND status < 200`
				: query.statusGroup === "2xx"
					? db`AND status >= 200 AND status < 300`
					: query.statusGroup === "3xx"
						? db`AND status >= 300 AND status < 400`
						: query.statusGroup === "4xx"
							? db`AND status >= 400 AND status < 500`
							: query.statusGroup === "5xx"
								? db`AND status >= 500 AND status < 600`
								: db``;
		const sinceFilter = query.since ? db`AND created_at >= ${query.since}` : db``;
		const untilFilter = query.until ? db`AND created_at <= ${query.until}` : db``;
		const order = db.unsafe(`${query.sortBy} ${query.sortDirection.toUpperCase()}`);
		const offset = (query.page - 1) * query.pageSize;
		const [countRow] = (await db`
      SELECT COUNT(*) AS count FROM request_events
      WHERE 1=1 ${siteFilter} ${searchFilter} ${countryFilter} ${asnFilter} ${decisionFilter} ${cacheStatusFilter} ${protectionStatusFilter} ${originFilter} ${methodFilter} ${statusFilter} ${sinceFilter} ${untilFilter}
    `) as Array<{ count: number | string }>;
		const items = (await db`
      SELECT id,site_id,session_id,ip,method,path,status,decision,latency_ms,country_code,asn,asn_org,origin_id,cache_status,
        protection_status,protection_rule_id,protection_category,protection_severity,protection_ruleset_id,protection_ruleset_version,
        protection_matches_json,access_username,referer,referer_host,created_at,
        (CASE WHEN request_body IS NOT NULL THEN 1 ELSE 0 END) AS has_request_body,
        (CASE WHEN response_body IS NOT NULL THEN 1 ELSE 0 END) AS has_response_body
      FROM request_events
      WHERE 1=1 ${siteFilter} ${searchFilter} ${countryFilter} ${asnFilter} ${decisionFilter} ${cacheStatusFilter} ${protectionStatusFilter} ${originFilter} ${methodFilter} ${statusFilter} ${sinceFilter} ${untilFilter}
      ORDER BY ${order}
      LIMIT ${query.pageSize} OFFSET ${offset}
    `) as Array<RequestEventRecord & { has_request_body: number; has_response_body: number }>;
		return pageResult(items, countRow?.count, query.page, query.pageSize);
	},
	async eventById(id: string, siteId?: string): Promise<RequestEventRecord | null> {
		const rows = siteId
			? ((await db`SELECT * FROM request_events WHERE id=${id} AND site_id=${siteId} LIMIT 1`) as RequestEventRecord[])
			: ((await db`SELECT * FROM request_events WHERE id=${id} LIMIT 1`) as RequestEventRecord[]);
		return rows[0] ?? null;
	},
	async trafficMetrics(
		siteId: string | string[] | undefined,
		since: number,
		until: number,
		bucketMs: number,
	): Promise<{
		series: TrafficMetricPoint[];
		decisions: Array<{ decision: string; count: number }>;
		methods: Array<{ method: string; count: number }>;
	}> {
		const siteFilter = siteScopeFilter(siteId);
		const bucketExpression =
			config.databaseUrl.startsWith("mysql://") || config.databaseUrl.startsWith("mariadb://")
				? db`FLOOR(created_at / ${bucketMs})`
				: db`CAST(created_at / ${bucketMs} AS BIGINT)`;
		const rows = (await db`
      SELECT
        ${bucketExpression} * ${bucketMs} AS bucket,
        COUNT(*) AS requests,
		SUM(CASE WHEN decision IN ('blocked','route-blocked','managed-protection-blocked','websocket-policy-denied','rate-limited','request-limited') THEN 1 ELSE 0 END) AS blocked,
        SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END) AS errors,
        COALESCE(AVG(latency_ms), 0) AS average_latency
      FROM request_events
      WHERE created_at >= ${since} AND created_at <= ${until} ${siteFilter}
      GROUP BY ${bucketExpression}
      ORDER BY bucket ASC
    `) as Array<{ bucket: number | string; requests: number | string; blocked: number | string; errors: number | string; average_latency: number | string }>;
		const decisions = (await db`
      SELECT decision, COUNT(*) AS count
      FROM request_events
      WHERE created_at >= ${since} AND created_at <= ${until} ${siteFilter}
      GROUP BY decision
      ORDER BY count DESC
    `) as Array<{ decision: string; count: number | string }>;
		const methods = (await db`
      SELECT method, COUNT(*) AS count
      FROM request_events
      WHERE created_at >= ${since} AND created_at <= ${until} ${siteFilter}
      GROUP BY method
      ORDER BY count DESC
      LIMIT 15
    `) as Array<{ method: string; count: number | string }>;
		return {
			series: fillTrafficMetricSeries(
				rows.map((row) => ({
					bucket: toNumber(row.bucket),
					requests: toNumber(row.requests),
					blocked: toNumber(row.blocked),
					errors: toNumber(row.errors),
					averageLatency: Math.round(toNumber(row.average_latency)),
				})),
				since,
				until,
				bucketMs,
			),
			decisions: decisions.map((row) => ({ decision: row.decision, count: toNumber(row.count) })),
			methods: methods.map((row) => ({ method: row.method, count: toNumber(row.count) })),
		};
	},
	async cacheMetrics(
		siteId: string | string[] | undefined,
		since: number,
		until: number,
		bucketMs: number,
	): Promise<{
		series: CacheMetricPoint[];
		totals: { hits: number; misses: number; bypasses: number; hitRatio: number; originRequestsAvoided: number };
		topPaths: Array<{ path: string; hits: number; misses: number; bypasses: number; hitRatio: number }>;
	}> {
		const siteFilter = siteScopeFilter(siteId);
		const bucketExpression = metricBucketExpression("created_at", bucketMs);
		const rows = (await db`
      SELECT
        ${bucketExpression} * ${bucketMs} AS bucket,
        SUM(CASE WHEN cache_status='hit' THEN 1 ELSE 0 END) AS hits,
        SUM(CASE WHEN cache_status='miss' THEN 1 ELSE 0 END) AS misses,
        SUM(CASE WHEN cache_status='bypass' THEN 1 ELSE 0 END) AS bypasses
      FROM request_events
      WHERE created_at >= ${since} AND created_at <= ${until} AND cache_status IS NOT NULL ${siteFilter}
      GROUP BY ${bucketExpression}
      ORDER BY bucket ASC
    `) as Array<{ bucket: number | string; hits: number | string; misses: number | string; bypasses: number | string }>;
		const series = fillCacheMetricSeries(
			rows.map((row) => {
				const hits = toNumber(row.hits);
				const misses = toNumber(row.misses);
				return {
					bucket: toNumber(row.bucket),
					hits,
					misses,
					bypasses: toNumber(row.bypasses),
					hitRatio: hits + misses > 0 ? (hits / (hits + misses)) * 100 : 0,
				};
			}),
			since,
			until,
			bucketMs,
		);
		const totals = series.reduce(
			(result, point) => {
				result.hits += point.hits;
				result.misses += point.misses;
				result.bypasses += point.bypasses;
				return result;
			},
			{ hits: 0, misses: 0, bypasses: 0 },
		);
		const paths = (await db`
      SELECT
        path,
        SUM(CASE WHEN cache_status='hit' THEN 1 ELSE 0 END) AS hits,
        SUM(CASE WHEN cache_status='miss' THEN 1 ELSE 0 END) AS misses,
        SUM(CASE WHEN cache_status='bypass' THEN 1 ELSE 0 END) AS bypasses
      FROM request_events
      WHERE created_at >= ${since} AND created_at <= ${until} AND cache_status IS NOT NULL ${siteFilter}
      GROUP BY path
      ORDER BY hits DESC, misses DESC
      LIMIT 10
    `) as Array<{ path: string; hits: number | string; misses: number | string; bypasses: number | string }>;
		return {
			series,
			totals: {
				...totals,
				hitRatio: totals.hits + totals.misses > 0 ? totals.hits / (totals.hits + totals.misses) : 0,
				originRequestsAvoided: totals.hits,
			},
			topPaths: paths.map((row) => {
				const hits = toNumber(row.hits);
				const misses = toNumber(row.misses);
				return {
					path: row.path,
					hits,
					misses,
					bypasses: toNumber(row.bypasses),
					hitRatio: hits + misses > 0 ? hits / (hits + misses) : 0,
				};
			}),
		};
	},
	async protectionMetrics(
		siteId: string | string[] | undefined,
		since: number,
		until: number,
		bucketMs: number,
	): Promise<{
		series: Array<{ bucket: number; clean: number; monitored: number; blocked: number }>;
		totals: { inspected: number; clean: number; monitored: number; blocked: number };
		topRules: Array<{ ruleId: string; category: string; severity: string; monitored: number; blocked: number; count: number }>;
	}> {
		const siteFilter = siteScopeFilter(siteId);
		const bucket = metricBucketExpression("created_at", bucketMs);
		const rows = (await db`
      SELECT ${bucket} * ${bucketMs} AS bucket,
        SUM(CASE WHEN protection_status='clean' THEN 1 ELSE 0 END) AS clean,
        SUM(CASE WHEN protection_status='monitored' THEN 1 ELSE 0 END) AS monitored,
        SUM(CASE WHEN protection_status='blocked' THEN 1 ELSE 0 END) AS blocked
      FROM request_events
      WHERE created_at >= ${since} AND created_at <= ${until} AND protection_status IS NOT NULL ${siteFilter}
      GROUP BY ${bucket}
      ORDER BY bucket ASC
    `) as Array<{ bucket: number | string; clean: number | string; monitored: number | string; blocked: number | string }>;
		const points = emptyMetricPoints(since, until, bucketMs, (bucketStart) => ({ bucket: bucketStart, clean: 0, monitored: 0, blocked: 0 }));
		const byBucket = new Map(points.map((point) => [point.bucket, point]));
		for (const row of rows) {
			const point = byBucket.get(toNumber(row.bucket));
			if (!point) continue;
			point.clean = toNumber(row.clean);
			point.monitored = toNumber(row.monitored);
			point.blocked = toNumber(row.blocked);
		}
		const totals = points.reduce(
			(result, point) => {
				result.clean += point.clean;
				result.monitored += point.monitored;
				result.blocked += point.blocked;
				return result;
			},
			{ clean: 0, monitored: 0, blocked: 0 },
		);
		const rules = (await db`
      SELECT protection_rule_id AS rule_id, protection_category AS category, protection_severity AS severity,
        SUM(CASE WHEN protection_status='monitored' THEN 1 ELSE 0 END) AS monitored,
        SUM(CASE WHEN protection_status='blocked' THEN 1 ELSE 0 END) AS blocked,
        COUNT(*) AS count
      FROM request_events
      WHERE created_at >= ${since} AND created_at <= ${until} AND protection_rule_id IS NOT NULL ${siteFilter}
      GROUP BY protection_rule_id, protection_category, protection_severity
      ORDER BY count DESC
      LIMIT 20
    `) as Array<{
			rule_id: string;
			category: string | null;
			severity: string | null;
			monitored: number | string;
			blocked: number | string;
			count: number | string;
		}>;
		return {
			series: points,
			totals: { ...totals, inspected: totals.clean + totals.monitored + totals.blocked },
			topRules: rules.map((row) => ({
				ruleId: row.rule_id,
				category: row.category ?? "unknown",
				severity: row.severity ?? "unknown",
				monitored: toNumber(row.monitored),
				blocked: toNumber(row.blocked),
				count: toNumber(row.count),
			})),
		};
	},
	async bandwidthMetrics(
		siteId: string | string[] | undefined,
		since: number,
		until: number,
		bucketMs: number,
	): Promise<{
		series: Array<{ bucket: number; clientUpload: number; clientDownload: number; upstreamUpload: number; upstreamDownload: number }>;
		protocols: Array<{ protocol: string; clientBytes: number; upstreamBytes: number }>;
	}> {
		const siteFilter = siteScopeFilter(siteId);
		const minuteSince = Math.floor(since / 60_000) * 60_000;
		const bucket = metricBucketExpression("bucket_start", bucketMs);
		const rows = (await db`
      SELECT ${bucket} * ${bucketMs} AS bucket,
        COALESCE(SUM(client_received_bytes),0) AS client_upload,
        COALESCE(SUM(client_sent_bytes),0) AS client_download,
        COALESCE(SUM(upstream_sent_bytes),0) AS upstream_upload,
        COALESCE(SUM(upstream_received_bytes),0) AS upstream_download
      FROM bandwidth_minutes
      WHERE bucket_start >= ${minuteSince} AND bucket_start <= ${until} ${siteFilter}
      GROUP BY ${bucket}
      ORDER BY bucket ASC
    `) as Array<{
			bucket: number | string;
			client_upload: number | string;
			client_download: number | string;
			upstream_upload: number | string;
			upstream_download: number | string;
		}>;
		const protocolRows = (await db`
      SELECT protocol,
        COALESCE(SUM(client_received_bytes + client_sent_bytes),0) AS client_bytes,
        COALESCE(SUM(upstream_sent_bytes + upstream_received_bytes),0) AS upstream_bytes
      FROM bandwidth_minutes
      WHERE bucket_start >= ${minuteSince} AND bucket_start <= ${until} ${siteFilter}
      GROUP BY protocol
      ORDER BY client_bytes DESC
    `) as Array<{ protocol: string; client_bytes: number | string; upstream_bytes: number | string }>;
		const points = emptyMetricPoints(since, until, bucketMs, (value) => ({
			bucket: value,
			clientUpload: 0,
			clientDownload: 0,
			upstreamUpload: 0,
			upstreamDownload: 0,
		}));
		const byBucket = new Map(points.map((point) => [point.bucket, point]));
		for (const row of rows) {
			const point = byBucket.get(toNumber(row.bucket));
			if (!point) continue;
			point.clientUpload = toNumber(row.client_upload);
			point.clientDownload = toNumber(row.client_download);
			point.upstreamUpload = toNumber(row.upstream_upload);
			point.upstreamDownload = toNumber(row.upstream_download);
		}
		return {
			series: points,
			protocols: protocolRows.map((row) => ({
				protocol: row.protocol,
				clientBytes: toNumber(row.client_bytes),
				upstreamBytes: toNumber(row.upstream_bytes),
			})),
		};
	},
	async pagedBandwidthIps(query: BandwidthIpQuery): Promise<PageResult<BandwidthIpRow>> {
		const minuteSince = Math.floor(query.since / 60_000) * 60_000;
		const pattern = searchPattern(query.search);
		const siteFilter = siteScopeFilter(query.siteId);
		const searchFilter = pattern ? db`AND LOWER(ip) LIKE ${pattern}` : db``;
		const countryFilter = query.countryCode ? db`AND country_code=${query.countryCode}` : db``;
		const protocolFilter = query.protocol ? db`AND protocol=${query.protocol}` : db``;
		const order = db.unsafe(`${query.sortBy} ${query.sortDirection.toUpperCase()}`);
		const offset = (query.page - 1) * query.pageSize;
		const [countRow] = (await db`
      SELECT COUNT(*) AS count FROM (
        SELECT ip, country_code
        FROM bandwidth_minutes
        WHERE bucket_start >= ${minuteSince} AND bucket_start <= ${query.until}
          AND ip <> '__other__' ${siteFilter} ${searchFilter} ${countryFilter} ${protocolFilter}
        GROUP BY ip, country_code
      ) AS bandwidth_ips
    `) as Array<{ count: number | string }>;
		const items = (await db`
      SELECT ip, country_code,
        COALESCE(SUM(client_received_bytes),0) AS client_received_bytes,
        COALESCE(SUM(client_sent_bytes),0) AS client_sent_bytes,
        COALESCE(SUM(upstream_sent_bytes),0) AS upstream_sent_bytes,
        COALESCE(SUM(upstream_received_bytes),0) AS upstream_received_bytes,
        COALESCE(SUM(client_received_bytes + client_sent_bytes),0) AS client_total_bytes,
        COALESCE(SUM(upstream_sent_bytes + upstream_received_bytes),0) AS upstream_total_bytes
      FROM bandwidth_minutes
      WHERE bucket_start >= ${minuteSince} AND bucket_start <= ${query.until}
        AND ip <> '__other__' ${siteFilter} ${searchFilter} ${countryFilter} ${protocolFilter}
      GROUP BY ip, country_code
      ORDER BY ${order}
      LIMIT ${query.pageSize} OFFSET ${offset}
    `) as BandwidthIpRow[];
		return pageResult(items, countRow?.count, query.page, query.pageSize);
	},
	async sessionMetrics(
		siteId: string | string[] | undefined,
		since: number,
		until: number,
		bucketMs: number,
	): Promise<{
		series: Array<{ bucket: number; created: number; expired: number; revoked: number; active: number }>;
		states: Array<{ label: string; count: number }>;
	}> {
		const siteFilter = siteScopeFilter(siteId);
		const createdBucket = metricBucketExpression("created_at", bucketMs);
		const expiredBucket = metricBucketExpression("expires_at", bucketMs);
		const revokedBucket = metricBucketExpression("revoked_at", bucketMs);
		const createdRows = (await db`
      SELECT ${createdBucket} * ${bucketMs} AS bucket, COUNT(*) AS count
      FROM access_sessions
      WHERE created_at >= ${since} AND created_at <= ${until} ${siteFilter}
      GROUP BY ${createdBucket}
      ORDER BY bucket ASC
    `) as Array<{ bucket: number | string; count: number | string }>;
		const expiredRows = (await db`
      SELECT ${expiredBucket} * ${bucketMs} AS bucket, COUNT(*) AS count
      FROM access_sessions
      WHERE expires_at >= ${since} AND expires_at <= ${until}
        AND (revoked_at IS NULL OR expires_at <= revoked_at) ${siteFilter}
      GROUP BY ${expiredBucket}
      ORDER BY bucket ASC
    `) as Array<{ bucket: number | string; count: number | string }>;
		const revokedRows = (await db`
      SELECT ${revokedBucket} * ${bucketMs} AS bucket, COUNT(*) AS count
      FROM access_sessions
      WHERE revoked_at IS NOT NULL AND revoked_at >= ${since} AND revoked_at <= ${until}
        AND revoked_at < expires_at ${siteFilter}
      GROUP BY ${revokedBucket}
      ORDER BY bucket ASC
    `) as Array<{ bucket: number | string; count: number | string }>;
		const [initialRow] = (await db`
      SELECT COUNT(*) AS count
      FROM access_sessions
      WHERE created_at < ${since} AND expires_at >= ${since}
        AND (revoked_at IS NULL OR revoked_at >= ${since}) ${siteFilter}
    `) as Array<{ count: number | string }>;
		const now = Date.now();
		const [stateRow] = (await db`
      SELECT
        SUM(CASE WHEN revoked_at IS NULL AND expires_at > ${now} THEN 1 ELSE 0 END) AS active,
        SUM(CASE WHEN revoked_at IS NULL AND expires_at <= ${now} THEN 1 ELSE 0 END) AS expired,
        SUM(CASE WHEN revoked_at IS NOT NULL THEN 1 ELSE 0 END) AS revoked
      FROM access_sessions
      WHERE 1=1 ${siteFilter}
    `) as Array<{ active: number | string; expired: number | string; revoked: number | string }>;

		const points = emptyMetricPoints(since, until, bucketMs, (bucket) => ({
			bucket,
			created: 0,
			expired: 0,
			revoked: 0,
			active: 0,
		}));
		const byBucket = new Map(points.map((point) => [point.bucket, point]));
		for (const row of createdRows) {
			const point = byBucket.get(toNumber(row.bucket));
			if (point) point.created = toNumber(row.count);
		}
		for (const row of expiredRows) {
			const point = byBucket.get(toNumber(row.bucket));
			if (point) point.expired = toNumber(row.count);
		}
		for (const row of revokedRows) {
			const point = byBucket.get(toNumber(row.bucket));
			if (point) point.revoked = toNumber(row.count);
		}
		let active = toNumber(initialRow?.count);
		for (const point of points) {
			active = Math.max(0, active + point.created - point.expired - point.revoked);
			point.active = active;
		}
		return {
			series: points,
			states: [
				{ label: "Active", count: toNumber(stateRow?.active) },
				{ label: "Expired", count: toNumber(stateRow?.expired) },
				{ label: "Revoked", count: toNumber(stateRow?.revoked) },
			],
		};
	},
	async ruleMetrics(
		siteId: string,
		since: number,
		until: number,
		bucketMs: number,
	): Promise<{
		series: Array<{ bucket: number; pass: number; allow: number; block: number; challenge: number }>;
		states: Array<{ label: string; active: number; expired: number }>;
	}> {
		const bucket = metricBucketExpression("created_at", bucketMs);
		const rows = (await db`
      SELECT ${bucket} * ${bucketMs} AS bucket, action, COUNT(*) AS count
      FROM (
        SELECT created_at, action FROM ip_rules WHERE site_id=${siteId}
        UNION ALL
        SELECT created_at, action FROM country_rules WHERE site_id=${siteId}
        UNION ALL
        SELECT created_at, action FROM asn_rules WHERE site_id=${siteId}
      ) AS network_rules
      WHERE created_at >= ${since} AND created_at <= ${until}
      GROUP BY ${bucket}, action
      ORDER BY bucket ASC
    `) as Array<{ bucket: number | string; action: string; count: number | string }>;
		const now = Date.now();
		const stateRows = (await db`
      SELECT action,
        SUM(CASE WHEN expires_at IS NULL OR expires_at > ${now} THEN 1 ELSE 0 END) AS active,
        SUM(CASE WHEN expires_at IS NOT NULL AND expires_at <= ${now} THEN 1 ELSE 0 END) AS expired
      FROM (
        SELECT action, expires_at FROM ip_rules WHERE site_id=${siteId}
        UNION ALL
        SELECT action, expires_at FROM country_rules WHERE site_id=${siteId}
        UNION ALL
        SELECT action, expires_at FROM asn_rules WHERE site_id=${siteId}
      ) AS network_rules
      GROUP BY action
    `) as Array<{ action: string; active: number | string; expired: number | string }>;
		const points = emptyMetricPoints(since, until, bucketMs, (value) => ({
			bucket: value,
			pass: 0,
			allow: 0,
			block: 0,
			challenge: 0,
		}));
		const byBucket = new Map(points.map((point) => [point.bucket, point]));
		for (const row of rows) {
			const point = byBucket.get(toNumber(row.bucket));
			if (!point || !["pass", "allow", "block", "challenge"].includes(row.action)) continue;
			point[row.action as "pass" | "allow" | "block" | "challenge"] = toNumber(row.count);
		}
		const states = new Map(stateRows.map((row) => [row.action, row]));
		return {
			series: points,
			states: [
				{ action: "pass", label: "Follow route" },
				{ action: "allow", label: "Bypass" },
				{ action: "block", label: "Block" },
				{ action: "challenge", label: "Challenge" },
			].map(({ action, label }) => ({
				label,
				active: toNumber(states.get(action)?.active),
				expired: toNumber(states.get(action)?.expired),
			})),
		};
	},
	async routeMetrics(
		siteId: string,
		since: number,
		until: number,
		bucketMs: number,
	): Promise<{
		series: Array<{ bucket: number; verified: number; bypassed: number; challenged: number; rateLimited: number; blocked: number }>;
		policies: Array<{ label: string; count: number }>;
		enabledPolicies: number;
		disabledPolicies: number;
	}> {
		const bucket = metricBucketExpression("created_at", bucketMs);
		const rows = (await db`
      SELECT ${bucket} * ${bucketMs} AS bucket,
        SUM(CASE WHEN decision IN ('proxied','websocket-proxied','proxied-authenticated','websocket-authenticated') THEN 1 ELSE 0 END) AS verified,
        SUM(CASE WHEN decision IN ('proxied-unprotected','websocket-unprotected','allowlisted','websocket-allowlisted') THEN 1 ELSE 0 END) AS bypassed,
        SUM(CASE WHEN decision='challenge-required' THEN 1 ELSE 0 END) AS challenged,
        SUM(CASE WHEN decision='rate-limited' THEN 1 ELSE 0 END) AS rate_limited,
		SUM(CASE WHEN decision IN ('route-blocked','managed-protection-blocked','websocket-policy-denied','request-limited') THEN 1 ELSE 0 END) AS blocked
      FROM request_events
      WHERE site_id=${siteId} AND created_at >= ${since} AND created_at <= ${until}
      GROUP BY ${bucket}
      ORDER BY bucket ASC
    `) as Array<{
			bucket: number | string;
			verified: number | string;
			bypassed: number | string;
			challenged: number | string;
			rate_limited: number | string;
			blocked: number | string;
		}>;
		const policyRows = (await db`
      SELECT access_mode, COUNT(*) AS count,
        SUM(CASE WHEN enabled=1 THEN 1 ELSE 0 END) AS enabled,
        SUM(CASE WHEN enabled=0 THEN 1 ELSE 0 END) AS disabled,
        SUM(CASE WHEN rate_limit_enabled=1 THEN 1 ELSE 0 END) AS rate_limited
      FROM route_policies
      WHERE site_id=${siteId}
      GROUP BY access_mode
    `) as Array<{ access_mode: string; count: number | string; enabled: number | string; disabled: number | string; rate_limited: number | string }>;
		const points = emptyMetricPoints(since, until, bucketMs, (value) => ({
			bucket: value,
			verified: 0,
			bypassed: 0,
			challenged: 0,
			rateLimited: 0,
			blocked: 0,
		}));
		const byBucket = new Map(points.map((point) => [point.bucket, point]));
		for (const row of rows) {
			const point = byBucket.get(toNumber(row.bucket));
			if (!point) continue;
			point.verified = toNumber(row.verified);
			point.bypassed = toNumber(row.bypassed);
			point.challenged = toNumber(row.challenged);
			point.rateLimited = toNumber(row.rate_limited);
			point.blocked = toNumber(row.blocked);
		}
		const counts = new Map(policyRows.map((row) => [row.access_mode, toNumber(row.count)]));
		const rateLimited = policyRows.reduce((sum, row) => sum + toNumber(row.rate_limited), 0);
		return {
			series: points,
			policies: [
				{ label: "Inherit", count: counts.get("inherit") ?? 0 },
				{ label: "Challenge", count: counts.get("challenge") ?? 0 },
				{ label: "Bypass", count: counts.get("bypass") ?? 0 },
				{ label: "Block", count: counts.get("block") ?? 0 },
				{ label: "Rate limited", count: rateLimited },
			],
			enabledPolicies: policyRows.reduce((sum, row) => sum + toNumber(row.enabled), 0),
			disabledPolicies: policyRows.reduce((sum, row) => sum + toNumber(row.disabled), 0),
		};
	},
	async accessListMetrics(
		siteId: string,
		since: number,
		until: number,
		bucketMs: number,
	): Promise<{
		series: Array<{ bucket: number; authenticated: number; loginRequired: number; failed: number; rateLimited: number }>;
		activeUsers: number;
		disabledUsers: number;
	}> {
		const bucket = metricBucketExpression("created_at", bucketMs);
		const rows = (await db`
      SELECT ${bucket} * ${bucketMs} AS bucket,
        SUM(CASE WHEN decision IN ('access-authenticated','proxied-authenticated','websocket-authenticated') THEN 1 ELSE 0 END) AS authenticated,
        SUM(CASE WHEN decision='access-login-required' THEN 1 ELSE 0 END) AS login_required,
        SUM(CASE WHEN decision='access-login-failed' THEN 1 ELSE 0 END) AS failed,
        SUM(CASE WHEN decision='access-login-rate-limited' THEN 1 ELSE 0 END) AS rate_limited
      FROM request_events
      WHERE site_id=${siteId} AND created_at >= ${since} AND created_at <= ${until}
      GROUP BY ${bucket}
      ORDER BY bucket ASC
    `) as Array<{
			bucket: number | string;
			authenticated: number | string;
			login_required: number | string;
			failed: number | string;
			rate_limited: number | string;
		}>;
		const [users] = (await db`
      SELECT
        SUM(CASE WHEN u.enabled=1 THEN 1 ELSE 0 END) AS active,
        SUM(CASE WHEN u.enabled=0 THEN 1 ELSE 0 END) AS disabled
      FROM access_users u JOIN site_access_users membership ON membership.user_id=u.id
      WHERE membership.site_id=${siteId}
    `) as Array<{ active: number | string; disabled: number | string }>;
		const points = emptyMetricPoints(since, until, bucketMs, (value) => ({
			bucket: value,
			authenticated: 0,
			loginRequired: 0,
			failed: 0,
			rateLimited: 0,
		}));
		const byBucket = new Map(points.map((point) => [point.bucket, point]));
		for (const row of rows) {
			const point = byBucket.get(toNumber(row.bucket));
			if (!point) continue;
			point.authenticated = toNumber(row.authenticated);
			point.loginRequired = toNumber(row.login_required);
			point.failed = toNumber(row.failed);
			point.rateLimited = toNumber(row.rate_limited);
		}
		return {
			series: points,
			activeUsers: toNumber(users?.active),
			disabledUsers: toNumber(users?.disabled),
		};
	},
	async siteMetrics(
		since: number,
		until: number,
		bucketMs: number,
	): Promise<{
		series: Array<{ bucket: number; values: Record<string, number> }>;
		sites: Array<{ key: string; label: string; requests: number; averageLatency: number }>;
		enabledSites: number;
		disabledSites: number;
	}> {
		const bucket = metricBucketExpression("created_at", bucketMs);
		const siteRows = (await db`SELECT id,name,enabled FROM sites ORDER BY enabled DESC,name ASC`) as Array<{ id: string; name: string; enabled: number }>;
		const rows = (await db`
      SELECT site_id, ${bucket} * ${bucketMs} AS bucket, COUNT(*) AS requests, COALESCE(SUM(latency_ms),0) AS total_latency
      FROM request_events
      WHERE created_at >= ${since} AND created_at <= ${until}
      GROUP BY site_id, ${bucket}
      ORDER BY bucket ASC
    `) as Array<{ site_id: string; bucket: number | string; requests: number | string; total_latency: number | string }>;
		const totals = new Map<string, { requests: number; totalLatency: number }>();
		for (const row of rows) {
			const current = totals.get(row.site_id) ?? { requests: 0, totalLatency: 0 };
			current.requests += toNumber(row.requests);
			current.totalLatency += toNumber(row.total_latency);
			totals.set(row.site_id, current);
		}
		const ordered = [...siteRows].sort((a, b) => {
			const requestDifference = (totals.get(b.id)?.requests ?? 0) - (totals.get(a.id)?.requests ?? 0);
			return requestDifference || b.enabled - a.enabled || a.name.localeCompare(b.name);
		});
		const selected = ordered.length <= 6 ? ordered : ordered.slice(0, 5);
		const selectedIds = new Set(selected.map((site) => site.id));
		const includeOther = ordered.length > selected.length;
		const descriptors = selected.map((site) => {
			const total = totals.get(site.id) ?? { requests: 0, totalLatency: 0 };
			return {
				key: site.id,
				label: site.name,
				requests: total.requests,
				averageLatency: total.requests > 0 ? Math.round(total.totalLatency / total.requests) : 0,
			};
		});
		if (includeOther) {
			let requests = 0;
			let totalLatency = 0;
			for (const site of ordered) {
				if (selectedIds.has(site.id)) continue;
				const total = totals.get(site.id);
				requests += total?.requests ?? 0;
				totalLatency += total?.totalLatency ?? 0;
			}
			descriptors.push({
				key: "__other__",
				label: `Other (${ordered.length - selected.length})`,
				requests,
				averageLatency: requests > 0 ? Math.round(totalLatency / requests) : 0,
			});
		}
		const points = emptyMetricPoints(since, until, bucketMs, (value) => ({ bucket: value, values: {} as Record<string, number> }));
		const byBucket = new Map(points.map((point) => [point.bucket, point]));
		for (const point of points) {
			for (const descriptor of descriptors) point.values[descriptor.key] = 0;
		}
		for (const row of rows) {
			const point = byBucket.get(toNumber(row.bucket));
			if (!point) continue;
			const key = selectedIds.has(row.site_id) ? row.site_id : includeOther ? "__other__" : null;
			if (key) point.values[key] = (point.values[key] ?? 0) + toNumber(row.requests);
		}
		return {
			series: points,
			sites: descriptors,
			enabledSites: siteRows.filter((site) => site.enabled === 1).length,
			disabledSites: siteRows.filter((site) => site.enabled !== 1).length,
		};
	},
	async overview(siteId: string | string[] | undefined, since: number, until: number): Promise<Record<string, number>> {
		const now = Date.now();
		const sessionSiteFilter = siteScopeFilter(siteId);
		const eventSiteFilter = siteScopeFilter(siteId);
		const ruleSiteFilter = siteScopeFilter(siteId);
		const flowSiteFilter = siteScopeFilter(siteId);
		const [sessions] =
			(await db`SELECT COUNT(*) AS count FROM access_sessions WHERE revoked_at IS NULL AND expires_at > ${now} ${sessionSiteFilter}`) as Array<{
				count: number | string;
			}>;
		const [eventStats] = (await db`
      SELECT
        COUNT(*) AS requests,
		SUM(CASE WHEN decision IN ('blocked','route-blocked','managed-protection-blocked','websocket-policy-denied','rate-limited','request-limited') THEN 1 ELSE 0 END) AS blocked,
        SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END) AS errors,
		SUM(CASE WHEN cache_status='hit' THEN 1 ELSE 0 END) AS cache_hits,
		SUM(CASE WHEN cache_status='miss' THEN 1 ELSE 0 END) AS cache_misses,
        COUNT(DISTINCT ip) AS unique_ips,
        COALESCE(AVG(latency_ms),0) AS average_latency
      FROM request_events
      WHERE created_at >= ${since} AND created_at <= ${until} ${eventSiteFilter}
    `) as Array<{
			requests: number | string;
			blocked: number | string;
			errors: number | string;
			cache_hits: number | string;
			cache_misses: number | string;
			unique_ips: number | string;
			average_latency: number | string;
		}>;
		const [challenges] =
			(await db`SELECT COUNT(*) AS count FROM challenge_flows WHERE created_at >= ${since} AND created_at <= ${until} ${flowSiteFilter}`) as Array<{
				count: number | string;
			}>;
		const [ipRules] = (await db`SELECT COUNT(*) AS count FROM ip_rules WHERE (expires_at IS NULL OR expires_at > ${now}) ${ruleSiteFilter}`) as Array<{
			count: number | string;
		}>;
		const [countryRules] =
			(await db`SELECT COUNT(*) AS count FROM country_rules WHERE (expires_at IS NULL OR expires_at > ${now}) ${ruleSiteFilter}`) as Array<{
				count: number | string;
			}>;
		const [asnRules] = (await db`SELECT COUNT(*) AS count FROM asn_rules WHERE (expires_at IS NULL OR expires_at > ${now}) ${ruleSiteFilter}`) as Array<{
			count: number | string;
		}>;
		const requests = toNumber(eventStats?.requests);
		const errors = toNumber(eventStats?.errors);
		const cacheHits = toNumber(eventStats?.cache_hits);
		const cacheMisses = toNumber(eventStats?.cache_misses);
		return {
			activeSessions: toNumber(sessions?.count),
			activeRules: toNumber(ipRules?.count) + toNumber(countryRules?.count) + toNumber(asnRules?.count),
			cacheHitRatio: cacheHits + cacheMisses > 0 ? cacheHits / (cacheHits + cacheMisses) : 0,
			blocked24h: toNumber(eventStats?.blocked),
			requests24h: requests,
			challenges24h: toNumber(challenges?.count),
			errors24h: errors,
			uniqueIps24h: toNumber(eventStats?.unique_ips),
			averageLatency24h: Math.round(toNumber(eventStats?.average_latency)),
			errorRate24h: requests > 0 ? Math.round((errors / requests) * 10_000) / 100 : 0,
			rangeFrom: since,
			rangeTo: until,
			rangeDurationMs: Math.max(0, until - since),
		};
	},
	async tabGeoMetrics(
		siteScope: string | string[] | undefined,
		since: number,
		until: number,
		scope: TabMetricsScope,
	): Promise<Array<{ countryCode: string; count: number }>> {
		if (Array.isArray(siteScope) && siteScope.length === 0) return [];
		const siteFilter = siteScopeFilter(siteScope);
		if (scope === "sessions") {
			const rows = (await db`
        SELECT COALESCE(country_code, 'ZZ') AS country_code, COUNT(*) AS count
        FROM access_sessions
        WHERE created_at >= ${since} AND created_at <= ${until} ${siteFilter}
        GROUP BY COALESCE(country_code, 'ZZ')
        ORDER BY count DESC
      `) as Array<{ country_code: string; count: number | string }>;
			return rows.map((row) => ({ countryCode: row.country_code, count: toNumber(row.count) }));
		}
		if (scope === "bandwidth") {
			const minuteSince = Math.floor(since / 60_000) * 60_000;
			const rows = (await db`
        SELECT COALESCE(country_code, 'ZZ') AS country_code,
          COALESCE(SUM(client_received_bytes + client_sent_bytes),0) AS count
        FROM bandwidth_minutes
        WHERE bucket_start >= ${minuteSince} AND bucket_start <= ${until} ${siteFilter}
        GROUP BY COALESCE(country_code, 'ZZ')
        ORDER BY count DESC
      `) as Array<{ country_code: string; count: number | string }>;
			return rows.map((row) => ({ countryCode: row.country_code, count: toNumber(row.count) }));
		}
		const scopeFilter = tabScopeFilter(scope);
		const rows = (await db`
      SELECT COALESCE(country_code, 'ZZ') AS country_code, COUNT(*) AS count
      FROM request_events
      WHERE created_at >= ${since} AND created_at <= ${until} ${siteFilter} ${scopeFilter}
      GROUP BY COALESCE(country_code, 'ZZ')
      ORDER BY count DESC
    `) as Array<{ country_code: string; count: number | string }>;
		return rows.map((row) => ({ countryCode: row.country_code, count: toNumber(row.count) }));
	},
	async tabAsnMetrics(
		siteScope: string | string[] | undefined,
		since: number,
		until: number,
		scope: Exclude<TabMetricsScope, "bandwidth">,
	): Promise<Array<{ asn: number; org: string; count: number }>> {
		if (Array.isArray(siteScope) && siteScope.length === 0) return [];
		const siteFilter = siteScopeFilter(siteScope);
		if (scope === "sessions") {
			const rows = (await db`
        SELECT COALESCE(asn, 0) AS asn, COALESCE(asn_org, 'Unknown') AS asn_org, COUNT(*) AS count
        FROM access_sessions
        WHERE created_at >= ${since} AND created_at <= ${until} ${siteFilter}
        GROUP BY COALESCE(asn, 0), COALESCE(asn_org, 'Unknown')
        ORDER BY count DESC
        LIMIT 25
      `) as Array<{ asn: number | string; asn_org: string; count: number | string }>;
			return rows.map((row) => ({ asn: toNumber(row.asn), org: row.asn_org, count: toNumber(row.count) }));
		}
		const scopeFilter = tabScopeFilter(scope);
		const rows = (await db`
      SELECT COALESCE(asn, 0) AS asn, COALESCE(asn_org, 'Unknown') AS asn_org, COUNT(*) AS count
      FROM request_events
      WHERE created_at >= ${since} AND created_at <= ${until} ${siteFilter} ${scopeFilter}
      GROUP BY COALESCE(asn, 0), COALESCE(asn_org, 'Unknown')
      ORDER BY count DESC
      LIMIT 25
    `) as Array<{ asn: number | string; asn_org: string; count: number | string }>;
		return rows.map((row) => ({ asn: toNumber(row.asn), org: row.asn_org, count: toNumber(row.count) }));
	},
	async tabRefererMetrics(
		siteScope: string | string[] | undefined,
		since: number,
		until: number,
		scope: Exclude<TabMetricsScope, "access" | "bandwidth" | "sessions">,
	): Promise<Array<{ refererHost: string; count: number }>> {
		if (Array.isArray(siteScope) && siteScope.length === 0) return [];
		const siteFilter = siteScopeFilter(siteScope);
		const scopeFilter = tabScopeFilter(scope);
		const rows = (await db`
      SELECT referer_host, COUNT(*) AS count
      FROM request_events
      WHERE created_at >= ${since} AND created_at <= ${until} ${siteFilter} ${scopeFilter}
        AND referer_host IS NOT NULL AND referer_host != '(same site)'
      GROUP BY referer_host
      ORDER BY count DESC
      LIMIT 25
    `) as Array<{ referer_host: string; count: number | string }>;
		return rows.map((row) => ({ refererHost: row.referer_host, count: toNumber(row.count) }));
	},
	async tabIpMetrics(
		siteScope: string | string[] | undefined,
		since: number,
		until: number,
		scope: "blocked" | "routes",
	): Promise<Array<{ ip: string; count: number }>> {
		if (Array.isArray(siteScope) && siteScope.length === 0) return [];
		const siteFilter = siteScopeFilter(siteScope);
		const scopeFilter = tabScopeFilter(scope);
		const rows = (await db`
      SELECT ip, COUNT(*) AS count
      FROM request_events
      WHERE created_at >= ${since} AND created_at <= ${until} ${siteFilter} ${scopeFilter}
      GROUP BY ip
      ORDER BY count DESC
      LIMIT 25
    `) as Array<{ ip: string; count: number | string }>;
		return rows.map((row) => ({ ip: row.ip, count: toNumber(row.count) }));
	},
	async tabBandwidthIpMetrics(siteScope: string | string[] | undefined, since: number, until: number): Promise<Array<{ ip: string; count: number }>> {
		if (Array.isArray(siteScope) && siteScope.length === 0) return [];
		const siteFilter = siteScopeFilter(siteScope);
		const minuteSince = Math.floor(since / 60_000) * 60_000;
		const rows = (await db`
      SELECT ip, COALESCE(SUM(client_received_bytes + client_sent_bytes),0) AS count
      FROM bandwidth_minutes
      WHERE bucket_start >= ${minuteSince} AND bucket_start <= ${until} AND ip <> '__other__' ${siteFilter}
      GROUP BY ip
      ORDER BY count DESC
      LIMIT 25
    `) as Array<{ ip: string; count: number | string }>;
		return rows.map((row) => ({ ip: row.ip, count: toNumber(row.count) }));
	},
	async tabPathMetrics(
		siteScope: string | string[] | undefined,
		since: number,
		until: number,
		scope: "protection" | "requests",
	): Promise<Array<{ path: string; count: number }>> {
		if (Array.isArray(siteScope) && siteScope.length === 0) return [];
		const siteFilter = siteScopeFilter(siteScope);
		const scopeFilter = tabScopeFilter(scope);
		const rows = (await db`
      SELECT path, COUNT(*) AS count
      FROM request_events
      WHERE created_at >= ${since} AND created_at <= ${until} ${siteFilter} ${scopeFilter}
      GROUP BY path
      ORDER BY count DESC
      LIMIT 25
    `) as Array<{ path: string; count: number | string }>;
		return rows.map((row) => ({ path: row.path, count: toNumber(row.count) }));
	},
	async accessUsernameMetrics(siteScope: string | string[] | undefined, since: number, until: number): Promise<Array<{ username: string; count: number }>> {
		if (Array.isArray(siteScope) && siteScope.length === 0) return [];
		const siteFilter = siteScopeFilter(siteScope);
		const rows = (await db`
      SELECT COALESCE(access_username, '(anonymous)') AS username, COUNT(*) AS count
      FROM request_events
      WHERE created_at >= ${since} AND created_at <= ${until} ${siteFilter}
        AND decision IN ('access-login-required','access-login-failed','access-login-rate-limited','access-authenticated')
      GROUP BY COALESCE(access_username, '(anonymous)')
      ORDER BY count DESC
      LIMIT 25
    `) as Array<{ username: string; count: number | string }>;
		return rows.map((row) => ({ username: row.username, count: toNumber(row.count) }));
	},
	async sessionUsernameMetrics(siteScope: string | string[] | undefined, since: number, until: number): Promise<Array<{ username: string; count: number }>> {
		if (Array.isArray(siteScope) && siteScope.length === 0) return [];
		const siteFilter = siteScope === undefined ? db`` : Array.isArray(siteScope) ? db`AND s.site_id IN ${db(siteScope)}` : db`AND s.site_id=${siteScope}`;
		const rows = (await db`
      SELECT COALESCE(u.username, '(anonymous)') AS username, COUNT(*) AS count
      FROM access_sessions s
      LEFT JOIN access_users u ON u.id = s.access_user_id
      WHERE s.created_at >= ${since} AND s.created_at <= ${until} ${siteFilter}
      GROUP BY COALESCE(u.username, '(anonymous)')
      ORDER BY count DESC
      LIMIT 25
    `) as Array<{ username: string; count: number | string }>;
		return rows.map((row) => ({ username: row.username, count: toNumber(row.count) }));
	},
	async eventsMissingCountry(limit: number): Promise<Array<{ id: string; ip: string }>> {
		if (limit <= 0) return [];
		return (await db`SELECT id, ip FROM request_events WHERE country_code IS NULL ORDER BY created_at DESC LIMIT ${limit}`) as Array<{
			id: string;
			ip: string;
		}>;
	},
	async sessionsMissingCountry(limit: number): Promise<Array<{ id: string; initial_ip: string }>> {
		if (limit <= 0) return [];
		return (await db`SELECT id, initial_ip FROM access_sessions WHERE country_code IS NULL ORDER BY created_at DESC LIMIT ${limit}`) as Array<{
			id: string;
			initial_ip: string;
		}>;
	},
	async updateEventCountry(id: string, countryCode: string): Promise<void> {
		await db`UPDATE request_events SET country_code=${countryCode} WHERE id=${id} AND country_code IS NULL`;
	},
	async updateSessionCountry(id: string, countryCode: string): Promise<void> {
		await db`UPDATE access_sessions SET country_code=${countryCode} WHERE id=${id} AND country_code IS NULL`;
	},
	async eventsMissingAsn(limit: number): Promise<Array<{ id: string; ip: string }>> {
		if (limit <= 0) return [];
		return (await db`SELECT id, ip FROM request_events WHERE asn IS NULL ORDER BY created_at DESC LIMIT ${limit}`) as Array<{
			id: string;
			ip: string;
		}>;
	},
	async sessionsMissingAsn(limit: number): Promise<Array<{ id: string; initial_ip: string }>> {
		if (limit <= 0) return [];
		return (await db`SELECT id, initial_ip FROM access_sessions WHERE asn IS NULL ORDER BY created_at DESC LIMIT ${limit}`) as Array<{
			id: string;
			initial_ip: string;
		}>;
	},
	async updateEventAsn(id: string, asn: number, org: string): Promise<void> {
		await db`UPDATE request_events SET asn=${asn}, asn_org=${org} WHERE id=${id} AND asn IS NULL`;
	},
	async updateSessionAsn(id: string, asn: number, org: string): Promise<void> {
		await db`UPDATE access_sessions SET asn=${asn}, asn_org=${org} WHERE id=${id} AND asn IS NULL`;
	},
	async tlsSettings(siteId: string): Promise<SiteTlsSettingsRecord | null> {
		const rows = (await db`SELECT * FROM site_tls_settings WHERE site_id=${siteId} LIMIT 1`) as SiteTlsSettingsRecord[];
		return rows[0] ?? null;
	},
	async ensureTlsSettings(siteId: string, now = Date.now()): Promise<SiteTlsSettingsRecord> {
		const existing = await this.tlsSettings(siteId);
		if (existing) return existing;
		const settings: SiteTlsSettingsRecord = {
			site_id: siteId,
			mode: "disabled",
			force_https: 0,
			acme_email: null,
			acme_directory_url: null,
			acme_challenge_type: "http-01",
			acme_dns_provider_id: null,
			created_at: now,
			updated_at: now,
		};
		try {
			await db`INSERT INTO site_tls_settings (site_id,mode,force_https,acme_email,acme_directory_url,acme_challenge_type,acme_dns_provider_id,created_at,updated_at) VALUES (${settings.site_id},${settings.mode},${settings.force_https},${settings.acme_email},${settings.acme_directory_url},${settings.acme_challenge_type},${settings.acme_dns_provider_id},${settings.created_at},${settings.updated_at})`;
		} catch {
			return (await this.tlsSettings(siteId)) ?? settings;
		}
		return settings;
	},
	async saveTlsSettings(settings: SiteTlsSettingsRecord): Promise<void> {
		assertPrimaryWritable("site TLS settings");
		const existing = await this.tlsSettings(settings.site_id);
		await db.begin(async (transaction) => {
			if (existing) {
				await transaction`UPDATE site_tls_settings SET mode=${settings.mode},force_https=${settings.force_https},acme_email=${settings.acme_email},acme_directory_url=${settings.acme_directory_url},acme_challenge_type=${settings.acme_challenge_type},acme_dns_provider_id=${settings.acme_dns_provider_id},updated_at=${settings.updated_at} WHERE site_id=${settings.site_id}`;
			} else {
				await transaction`INSERT INTO site_tls_settings (site_id,mode,force_https,acme_email,acme_directory_url,acme_challenge_type,acme_dns_provider_id,created_at,updated_at) VALUES (${settings.site_id},${settings.mode},${settings.force_https},${settings.acme_email},${settings.acme_directory_url},${settings.acme_challenge_type},${settings.acme_dns_provider_id},${settings.created_at},${settings.updated_at})`;
			}
			await appendChangelogEntry(transaction, "site_tls_settings", settings.site_id, existing ? "update" : "insert", settings);
		});
	},
	async certificateBySite(siteId: string): Promise<CertificateRecord | null> {
		const rows = (await db`SELECT * FROM certificates WHERE site_id=${siteId} LIMIT 1`) as CertificateRecord[];
		return rows[0] ?? null;
	},
	async activeCertificates(): Promise<Array<CertificateRecord & { public_host: string }>> {
		return (await db`SELECT c.*, s.public_host FROM certificates c JOIN sites s ON s.id=c.site_id JOIN site_tls_settings t ON t.site_id=s.id WHERE c.status='active' AND c.expires_at > ${Date.now()} AND c.certificate_pem IS NOT NULL AND c.encrypted_private_key IS NOT NULL AND s.enabled=1 AND t.mode <> 'disabled' ORDER BY s.public_host ASC`) as Array<
			CertificateRecord & { public_host: string }
		>;
	},
	async saveCertificate(certificate: CertificateRecord): Promise<void> {
		assertPrimaryWritable("a certificate");
		const existing = await this.certificateBySite(certificate.site_id);
		await db.begin(async (transaction) => {
			if (existing) {
				await transaction`UPDATE certificates SET id=${certificate.id},source=${certificate.source},status=${certificate.status},primary_domain=${certificate.primary_domain},alternative_names_json=${certificate.alternative_names_json},certificate_pem=${certificate.certificate_pem},encrypted_private_key=${certificate.encrypted_private_key},issuer=${certificate.issuer},serial_number=${certificate.serial_number},valid_from=${certificate.valid_from},expires_at=${certificate.expires_at},next_renewal_at=${certificate.next_renewal_at},last_attempt_at=${certificate.last_attempt_at},last_error=${certificate.last_error},updated_at=${certificate.updated_at} WHERE site_id=${certificate.site_id}`;
			} else {
				await transaction`INSERT INTO certificates (id,site_id,source,status,primary_domain,alternative_names_json,certificate_pem,encrypted_private_key,issuer,serial_number,valid_from,expires_at,next_renewal_at,last_attempt_at,last_error,created_at,updated_at) VALUES (${certificate.id},${certificate.site_id},${certificate.source},${certificate.status},${certificate.primary_domain},${certificate.alternative_names_json},${certificate.certificate_pem},${certificate.encrypted_private_key},${certificate.issuer},${certificate.serial_number},${certificate.valid_from},${certificate.expires_at},${certificate.next_renewal_at},${certificate.last_attempt_at},${certificate.last_error},${certificate.created_at},${certificate.updated_at})`;
			}
			await appendChangelogEntry(transaction, "certificate", certificate.id, existing ? "update" : "insert", certificate);
		});
	},
	async updateCertificateAttempt(siteId: string, attemptedAt: number, error: string | null): Promise<void> {
		assertPrimaryWritable("a certificate");
		await db.begin(async (transaction) => {
			const existing = (await transaction`SELECT * FROM certificates WHERE site_id=${siteId} LIMIT 1`) as CertificateRecord[];
			await transaction`UPDATE certificates SET last_attempt_at=${attemptedAt},last_error=${error},updated_at=${attemptedAt} WHERE site_id=${siteId}`;
			if (existing[0]) {
				await appendChangelogEntry(transaction, "certificate", existing[0].id, "update", {
					...existing[0],
					last_attempt_at: attemptedAt,
					last_error: error,
					updated_at: attemptedAt,
				});
			}
		});
	},
	async deleteCertificate(siteId: string): Promise<void> {
		assertPrimaryWritable("a certificate");
		await db.begin(async (transaction) => {
			const existing = (await transaction`SELECT id FROM certificates WHERE site_id=${siteId} LIMIT 1`) as Array<{ id: string }>;
			await transaction`DELETE FROM certificates WHERE site_id=${siteId}`;
			if (existing[0]) await appendChangelogEntry(transaction, "certificate", existing[0].id, "delete", null);
		});
	},
	async dueAcmeCertificates(cutoff: number): Promise<CertificateRecord[]> {
		return (await db`SELECT c.* FROM certificates c JOIN site_tls_settings t ON t.site_id=c.site_id JOIN sites s ON s.id=c.site_id WHERE c.source='letsencrypt' AND c.status='active' AND ((t.mode='letsencrypt' AND s.enabled=1) OR EXISTS (SELECT 1 FROM streams st WHERE st.certificate_id=c.id AND st.tcp_enabled=1)) AND c.next_renewal_at IS NOT NULL AND c.next_renewal_at <= ${cutoff} ORDER BY c.next_renewal_at ASC`) as CertificateRecord[];
	},
	async acmeAccount(directoryUrl: string): Promise<AcmeAccountRecord | null> {
		const rows = (await db`SELECT * FROM acme_accounts WHERE directory_url=${directoryUrl} LIMIT 1`) as AcmeAccountRecord[];
		return rows[0] ?? null;
	},
	async saveAcmeAccount(account: AcmeAccountRecord): Promise<void> {
		const existing = await this.acmeAccount(account.directory_url);
		await db.begin(async (transaction) => {
			if (existing) {
				await transaction`UPDATE acme_accounts SET email=${account.email},account_url=${account.account_url},encrypted_account_key=${account.encrypted_account_key},terms_accepted_at=${account.terms_accepted_at},updated_at=${account.updated_at} WHERE directory_url=${account.directory_url}`;
			} else {
				await transaction`INSERT INTO acme_accounts (id,directory_url,email,account_url,encrypted_account_key,terms_accepted_at,created_at,updated_at) VALUES (${account.id},${account.directory_url},${account.email},${account.account_url},${account.encrypted_account_key},${account.terms_accepted_at},${account.created_at},${account.updated_at})`;
			}

			await appendChangelogEntry(transaction, "acme_account", account.id, existing ? "update" : "insert", account);
		});
	},
	async acmeChallenge(token: string, hostname: string): Promise<AcmeHttpChallengeRecord | null> {
		const rows =
			(await db`SELECT * FROM acme_http_challenges WHERE token=${token} AND hostname=${hostname} AND expires_at > ${Date.now()} LIMIT 1`) as AcmeHttpChallengeRecord[];
		return rows[0] ?? null;
	},
	async saveAcmeChallenge(challenge: AcmeHttpChallengeRecord): Promise<void> {
		assertPrimaryWritable("an ACME challenge");
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM acme_http_challenges WHERE token=${challenge.token}`;
			await transaction`INSERT INTO acme_http_challenges (token,site_id,hostname,key_authorization,created_at,expires_at) VALUES (${challenge.token},${challenge.site_id},${challenge.hostname},${challenge.key_authorization},${challenge.created_at},${challenge.expires_at})`;
			await appendChangelogEntry(transaction, "acme_http_challenge", challenge.token, "insert", challenge);
		});
	},
	async deleteAcmeChallenge(token: string): Promise<void> {
		assertPrimaryWritable("an ACME challenge");
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM acme_http_challenges WHERE token=${token}`;
			await appendChangelogEntry(transaction, "acme_http_challenge", token, "delete", null);
		});
	},
	async deleteAcmeChallengesForSite(siteId: string): Promise<void> {
		assertPrimaryWritable("an ACME challenge");
		await db.begin(async (transaction) => {
			const matches = (await transaction`SELECT token FROM acme_http_challenges WHERE site_id=${siteId}`) as Array<{ token: string }>;
			await transaction`DELETE FROM acme_http_challenges WHERE site_id=${siteId}`;
			for (const row of matches) await appendChangelogEntry(transaction, "acme_http_challenge", row.token, "delete", null);
		});
	},
	async deleteExpiredAcmeChallengesBatch(now: number, limit: number): Promise<number> {
		const rows = (await db`SELECT token FROM acme_http_challenges WHERE expires_at <= ${now} ORDER BY expires_at ASC LIMIT ${limit}`) as Array<{
			token: string;
		}>;
		if (rows.length === 0) return 0;
		await db`DELETE FROM acme_http_challenges WHERE token IN ${db(rows.map((row) => row.token))}`;
		return rows.length;
	},
	async insertCertificateEvent(event: CertificateEventRecord): Promise<void> {
		await db`INSERT INTO certificate_events (id,site_id,certificate_id,level,message,details_json,created_at) VALUES (${event.id},${event.site_id},${event.certificate_id},${event.level},${event.message},${event.details_json},${event.created_at})`;
	},
	async certificateEvents(siteId: string, limit = 30): Promise<CertificateEventRecord[]> {
		return (await db`SELECT * FROM certificate_events WHERE site_id=${siteId} ORDER BY created_at DESC LIMIT ${limit}`) as CertificateEventRecord[];
	},
	async deleteRequestEventsBeforeForSiteBatch(siteId: string, cutoff: number, limit: number): Promise<number> {
		const rows = (await db`SELECT id FROM request_events WHERE site_id=${siteId} AND created_at < ${cutoff} ORDER BY created_at ASC LIMIT ${limit}`) as Array<{
			id: string;
		}>;
		if (rows.length === 0) return 0;
		await db`DELETE FROM request_events WHERE id IN ${db(rows.map((row) => row.id))}`;
		return rows.length;
	},
	async deleteBandwidthBeforeForSiteBatch(siteId: string, cutoff: number, limit: number): Promise<number> {
		if (isMySqlDatabase()) {
			return deletedRowCount(
				await db`DELETE FROM bandwidth_minutes WHERE site_id=${siteId} AND bucket_start < ${cutoff} ORDER BY bucket_start ASC LIMIT ${limit}`,
			);
		}
		if (isSqliteDatabase()) {
			return deletedRowCount(
				await db`DELETE FROM bandwidth_minutes WHERE rowid IN (SELECT rowid FROM bandwidth_minutes WHERE site_id=${siteId} AND bucket_start < ${cutoff} ORDER BY bucket_start ASC LIMIT ${limit})`,
			);
		}
		return deletedRowCount(
			await db`DELETE FROM bandwidth_minutes WHERE ctid IN (SELECT ctid FROM bandwidth_minutes WHERE site_id=${siteId} AND bucket_start < ${cutoff} ORDER BY bucket_start ASC LIMIT ${limit})`,
		);
	},
	async deleteSessionsBeforeForSiteBatch(siteId: string, cutoff: number, limit: number): Promise<number> {
		const rows =
			(await db`SELECT id FROM access_sessions WHERE site_id=${siteId} AND (expires_at < ${cutoff} OR (revoked_at IS NOT NULL AND revoked_at < ${cutoff})) ORDER BY expires_at ASC LIMIT ${limit}`) as Array<{
				id: string;
			}>;
		if (rows.length === 0) return 0;
		await db`DELETE FROM access_sessions WHERE id IN ${db(rows.map((row) => row.id))}`;
		return rows.length;
	},
	async deleteExpiredChallengeArtifactsBatch(now: number, limit: number): Promise<number> {
		const rows = (await db`SELECT id FROM challenge_steps WHERE expires_at < ${now} ORDER BY expires_at ASC LIMIT ${limit}`) as Array<{ id: string }>;
		if (rows.length === 0) return 0;
		const ids = rows.map((row) => row.id);
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM challenge_consumptions WHERE step_id IN ${transaction(ids)}`;
			await transaction`DELETE FROM challenge_steps WHERE id IN ${transaction(ids)}`;
		});
		return rows.length;
	},
	async deleteChallengeFlowsBeforeForSiteBatch(siteId: string, cutoff: number, limit: number): Promise<number> {
		const rows = (await db`SELECT id FROM challenge_flows WHERE site_id=${siteId} AND created_at < ${cutoff} ORDER BY created_at ASC LIMIT ${limit}`) as Array<{
			id: string;
		}>;
		if (rows.length === 0) return 0;
		const flowIds = rows.map((row) => row.id);
		const stepRows = (await db`SELECT id FROM challenge_steps WHERE flow_id IN ${db(flowIds)}`) as Array<{ id: string }>;
		await db.begin(async (transaction) => {
			if (stepRows.length > 0) {
				const stepIds = stepRows.map((row) => row.id);
				await transaction`DELETE FROM challenge_consumptions WHERE step_id IN ${transaction(stepIds)}`;
				await transaction`DELETE FROM challenge_steps WHERE id IN ${transaction(stepIds)}`;
			}
			await transaction`DELETE FROM challenge_flows WHERE id IN ${transaction(flowIds)}`;
		});
		return rows.length;
	},
	async deleteExpiredRulesBeforeForSiteBatch(siteId: string, cutoff: number, limit: number): Promise<number> {
		const rows =
			(await db`SELECT id FROM ip_rules WHERE site_id=${siteId} AND expires_at IS NOT NULL AND expires_at < ${cutoff} ORDER BY expires_at ASC LIMIT ${limit}`) as Array<{
				id: string;
			}>;
		if (rows.length === 0) return 0;
		await db`DELETE FROM ip_rules WHERE id IN ${db(rows.map((row) => row.id))}`;
		return rows.length;
	},
	async deleteCertificateEventsBeforeForSiteBatch(siteId: string, cutoff: number, limit: number): Promise<number> {
		const rows =
			(await db`SELECT id FROM certificate_events WHERE site_id=${siteId} AND created_at < ${cutoff} ORDER BY created_at ASC LIMIT ${limit}`) as Array<{
				id: string;
			}>;
		if (rows.length === 0) return 0;
		await db`DELETE FROM certificate_events WHERE id IN ${db(rows.map((row) => row.id))}`;
		return rows.length;
	},
	async deleteOriginHealthEventsBeforeForSiteBatch(siteId: string, cutoff: number, limit: number): Promise<number> {
		const rows =
			(await db`SELECT id FROM origin_health_events WHERE site_id=${siteId} AND created_at < ${cutoff} ORDER BY created_at ASC LIMIT ${limit}`) as Array<{
				id: string;
			}>;
		if (rows.length === 0) return 0;
		await db`DELETE FROM origin_health_events WHERE id IN ${db(rows.map((row) => row.id))}`;
		return rows.length;
	},
	async deleteBackendHealthEventsBeforeForSiteBatch(siteId: string, cutoff: number, limit: number): Promise<number> {
		const rows =
			(await db`SELECT id FROM origin_backend_health_events WHERE site_id=${siteId} AND created_at < ${cutoff} ORDER BY created_at ASC LIMIT ${limit}`) as Array<{
				id: string;
			}>;
		if (rows.length === 0) return 0;
		await db`DELETE FROM origin_backend_health_events WHERE id IN ${db(rows.map((row) => row.id))}`;
		return rows.length;
	},
	async deleteNotificationOutboxBeforeForSiteBatch(siteId: string, cutoff: number, limit: number): Promise<number> {
		const rows =
			(await db`SELECT id FROM notification_outbox WHERE site_id=${siteId} AND created_at < ${cutoff} AND status <> 'pending' ORDER BY created_at ASC LIMIT ${limit}`) as Array<{
				id: string;
			}>;
		if (rows.length === 0) return 0;
		await db`DELETE FROM notification_outbox WHERE id IN ${db(rows.map((row) => row.id))}`;
		return rows.length;
	},
	async deleteNotificationEventsBeforeForSiteBatch(siteId: string, cutoff: number, limit: number): Promise<number> {
		const rows =
			(await db`SELECT id FROM notification_events WHERE site_id=${siteId} AND created_at < ${cutoff} ORDER BY created_at ASC LIMIT ${limit}`) as Array<{
				id: string;
			}>;
		if (rows.length === 0) return 0;
		await db`DELETE FROM notification_events WHERE id IN ${db(rows.map((row) => row.id))}`;
		return rows.length;
	},
	async deleteGlobalNotificationEventsBeforeBatch(cutoff: number, limit: number): Promise<number> {
		const rows =
			(await db`SELECT id FROM notification_events WHERE site_id IS NULL AND stream_id IS NULL AND created_at < ${cutoff} ORDER BY created_at ASC LIMIT ${limit}`) as Array<{
				id: string;
			}>;
		if (rows.length === 0) return 0;
		await db`DELETE FROM notification_events WHERE id IN ${db(rows.map((row) => row.id))}`;
		return rows.length;
	},
	async deleteNotificationOutboxBeforeForStreamBatch(streamId: string, cutoff: number, limit: number): Promise<number> {
		const rows =
			(await db`SELECT id FROM notification_outbox WHERE stream_id=${streamId} AND created_at < ${cutoff} AND status <> 'pending' ORDER BY created_at ASC LIMIT ${limit}`) as Array<{
				id: string;
			}>;
		if (rows.length === 0) return 0;
		await db`DELETE FROM notification_outbox WHERE id IN ${db(rows.map((row) => row.id))}`;
		return rows.length;
	},
	async deleteNotificationEventsBeforeForStreamBatch(streamId: string, cutoff: number, limit: number): Promise<number> {
		const rows =
			(await db`SELECT id FROM notification_events WHERE stream_id=${streamId} AND created_at < ${cutoff} ORDER BY created_at ASC LIMIT ${limit}`) as Array<{
				id: string;
			}>;
		if (rows.length === 0) return 0;
		await db`DELETE FROM notification_events WHERE id IN ${db(rows.map((row) => row.id))}`;
		return rows.length;
	},
	async deleteExpiredAdminSessionsBatch(now: number, limit: number): Promise<number> {
		const rows = (await db`SELECT id FROM admin_sessions WHERE expires_at <= ${now} ORDER BY expires_at ASC LIMIT ${limit}`) as Array<{ id: string }>;
		if (rows.length === 0) return 0;
		await db`DELETE FROM admin_sessions WHERE id IN ${db(rows.map((row) => row.id))}`;
		return rows.length;
	},
	async allStreams(): Promise<StreamRecord[]> {
		return (await db`SELECT * FROM streams ORDER BY name ASC`) as StreamRecord[];
	},
	async streamById(id: string): Promise<StreamRecord | null> {
		const rows = (await db`SELECT * FROM streams WHERE id=${id} LIMIT 1`) as StreamRecord[];
		return rows[0] ?? null;
	},
	async saveStream(stream: StreamRecord): Promise<void> {
		assertPrimaryWritable("a stream");
		const existing = await this.streamById(stream.id);
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM stream_bindings WHERE stream_id=${stream.id}`;
			if (existing) {
				await transaction`UPDATE streams SET name=${stream.name},incoming_port=${stream.incoming_port},forward_host=${stream.forward_host},forward_port=${stream.forward_port},tcp_enabled=${stream.tcp_enabled},udp_enabled=${stream.udp_enabled},proxy_protocol=${stream.proxy_protocol},certificate_id=${stream.certificate_id},event_retention_days=${stream.event_retention_days},default_ip_action=${stream.default_ip_action},default_country_action=${stream.default_country_action},max_connections_per_ip=${stream.max_connections_per_ip},connection_rate_limit_enabled=${stream.connection_rate_limit_enabled},connection_rate_limit_algorithm=${stream.connection_rate_limit_algorithm},connection_rate_limit_window_ms=${stream.connection_rate_limit_window_ms},connection_rate_limit_max=${stream.connection_rate_limit_max},connection_rate_limit_refill_rate=${stream.connection_rate_limit_refill_rate},connection_rate_limit_refill_interval_ms=${stream.connection_rate_limit_refill_interval_ms},connection_rate_limit_precision_ms=${stream.connection_rate_limit_precision_ms},udp_amplification_max_ratio=${stream.udp_amplification_max_ratio},protection_policy_json=${stream.protection_policy_json},bandwidth_policy_json=${stream.bandwidth_policy_json},origin_health_check_enabled=${stream.origin_health_check_enabled},origin_health_check_interval_seconds=${stream.origin_health_check_interval_seconds},origin_health_check_timeout_ms=${stream.origin_health_check_timeout_ms},origin_health_check_failure_threshold=${stream.origin_health_check_failure_threshold},origin_health_check_recovery_threshold=${stream.origin_health_check_recovery_threshold},notification_policy_json=${stream.notification_policy_json},updated_at=${stream.updated_at} WHERE id=${stream.id}`;
			} else {
				await transaction`INSERT INTO streams (id,name,incoming_port,forward_host,forward_port,tcp_enabled,udp_enabled,proxy_protocol,certificate_id,event_retention_days,default_ip_action,default_country_action,max_connections_per_ip,connection_rate_limit_enabled,connection_rate_limit_algorithm,connection_rate_limit_window_ms,connection_rate_limit_max,connection_rate_limit_refill_rate,connection_rate_limit_refill_interval_ms,connection_rate_limit_precision_ms,udp_amplification_max_ratio,protection_policy_json,bandwidth_policy_json,origin_health_check_enabled,origin_health_check_interval_seconds,origin_health_check_timeout_ms,origin_health_check_failure_threshold,origin_health_check_recovery_threshold,notification_policy_json,created_at,updated_at) VALUES (${stream.id},${stream.name},${stream.incoming_port},${stream.forward_host},${stream.forward_port},${stream.tcp_enabled},${stream.udp_enabled},${stream.proxy_protocol},${stream.certificate_id},${stream.event_retention_days},${stream.default_ip_action},${stream.default_country_action},${stream.max_connections_per_ip},${stream.connection_rate_limit_enabled},${stream.connection_rate_limit_algorithm},${stream.connection_rate_limit_window_ms},${stream.connection_rate_limit_max},${stream.connection_rate_limit_refill_rate},${stream.connection_rate_limit_refill_interval_ms},${stream.connection_rate_limit_precision_ms},${stream.udp_amplification_max_ratio},${stream.protection_policy_json},${stream.bandwidth_policy_json},${stream.origin_health_check_enabled},${stream.origin_health_check_interval_seconds},${stream.origin_health_check_timeout_ms},${stream.origin_health_check_failure_threshold},${stream.origin_health_check_recovery_threshold},${stream.notification_policy_json},${stream.created_at},${stream.updated_at})`;
			}
			if (stream.tcp_enabled === 1) {
				await transaction`INSERT INTO stream_bindings (stream_id,protocol,incoming_port) VALUES (${stream.id},'tcp',${stream.incoming_port})`;
			}
			if (stream.udp_enabled === 1) {
				await transaction`INSERT INTO stream_bindings (stream_id,protocol,incoming_port) VALUES (${stream.id},'udp',${stream.incoming_port})`;
			}
			await appendChangelogEntry(transaction, "stream", stream.id, existing ? "update" : "insert", stream);
		});
	},
	async deleteStream(id: string): Promise<void> {
		assertPrimaryWritable("a stream");
		const ipRuleIds = ((await db`SELECT id FROM stream_ip_rules WHERE stream_id=${id}`) as Array<{ id: string }>).map((r) => r.id);
		const countryRuleIds = ((await db`SELECT id FROM stream_country_rules WHERE stream_id=${id}`) as Array<{ id: string }>).map((r) => r.id);
		const asnRuleIds = ((await db`SELECT id FROM stream_asn_rules WHERE stream_id=${id}`) as Array<{ id: string }>).map((r) => r.id);
		const permissionUserIds = ((await db`SELECT user_id FROM admin_user_stream_permissions WHERE stream_id=${id}`) as Array<{ user_id: string }>).map(
			(r) => r.user_id,
		);
		const pendingChangeIds = ((await db`SELECT id FROM pending_changes WHERE entity_type='stream' AND entity_id=${id}`) as Array<{ id: string }>).map(
			(r) => r.id,
		);
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM stream_bindings WHERE stream_id=${id}`;
			await transaction`DELETE FROM stream_events WHERE stream_id=${id}`;
			await transaction`DELETE FROM stream_bandwidth_minutes WHERE stream_id=${id}`;
			await transaction`DELETE FROM stream_origin_latency_minutes WHERE stream_id=${id}`;
			await transaction`DELETE FROM stream_ip_rules WHERE stream_id=${id}`;
			await transaction`DELETE FROM stream_country_rules WHERE stream_id=${id}`;
			await transaction`DELETE FROM stream_asn_rules WHERE stream_id=${id}`;
			await transaction`DELETE FROM admin_user_stream_permissions WHERE stream_id=${id}`;
			await transaction`DELETE FROM notification_outbox WHERE stream_id=${id}`;
			await transaction`DELETE FROM notification_events WHERE stream_id=${id}`;
			await transaction`DELETE FROM pending_changes WHERE entity_type='stream' AND entity_id=${id}`;
			await transaction`DELETE FROM streams WHERE id=${id}`;
			for (const ruleId of ipRuleIds) await appendChangelogEntry(transaction, "stream_ip_rule", ruleId, "delete", null);
			for (const ruleId of countryRuleIds) await appendChangelogEntry(transaction, "stream_country_rule", ruleId, "delete", null);
			for (const ruleId of asnRuleIds) await appendChangelogEntry(transaction, "stream_asn_rule", ruleId, "delete", null);
			for (const userId of permissionUserIds) await appendChangelogEntry(transaction, "admin_stream_permission", `${userId}:${id}`, "delete", null);
			for (const changeId of pendingChangeIds) await appendChangelogEntry(transaction, "pending_change", changeId, "delete", null);
			await appendChangelogEntry(transaction, "stream", id, "delete", null);
		});
	},
	async certificateById(id: string): Promise<CertificateRecord | null> {
		const rows = (await db`SELECT * FROM certificates WHERE id=${id} LIMIT 1`) as CertificateRecord[];
		return rows[0] ?? null;
	},
	async streamCertificateOptions(): Promise<Array<CertificateRecord & { site_name: string; public_host: string }>> {
		return (await db`SELECT c.*,s.name AS site_name,s.public_host FROM certificates c JOIN sites s ON s.id=c.site_id WHERE c.status='active' AND c.expires_at > ${Date.now()} AND c.certificate_pem IS NOT NULL AND c.encrypted_private_key IS NOT NULL ORDER BY c.primary_domain ASC`) as Array<
			CertificateRecord & { site_name: string; public_host: string }
		>;
	},
	async streamsUsingCertificate(certificateId: string): Promise<StreamRecord[]> {
		return (await db`SELECT * FROM streams WHERE certificate_id=${certificateId} ORDER BY incoming_port ASC`) as StreamRecord[];
	},
	async insertStreamEvents(events: StreamEventRecord[]): Promise<void> {
		if (events.length === 0) return;
		await db.begin(async (transaction) => {
			for (const event of events) {
				await transaction`INSERT INTO stream_events (id,stream_id,incoming_port,connection_id,protocol,event_type,client_ip,client_port,country_code,asn,asn_org,reason,error,protection_rule_id,client_to_upstream_bytes,upstream_to_client_bytes,duration_ms,username,created_at) VALUES (${event.id},${event.stream_id},${event.incoming_port},${event.connection_id},${event.protocol},${event.event_type},${event.client_ip},${event.client_port},${event.country_code},${event.asn},${event.asn_org},${event.reason},${event.error},${event.protection_rule_id},${event.client_to_upstream_bytes},${event.upstream_to_client_bytes},${event.duration_ms},${event.username},${event.created_at})`;
			}
		});
	},
	async addStreamBandwidthDeltas(records: StreamBandwidthMinuteRecord[]): Promise<void> {
		if (records.length === 0) return;
		const mysql = config.databaseUrl.startsWith("mysql://") || config.databaseUrl.startsWith("mariadb://");
		await db.begin(async (transaction) => {
			for (const record of records) {
				if (mysql) {
					await transaction`INSERT INTO stream_bandwidth_minutes (stream_id,incoming_port,bucket_start,ip,country_code,protocol,client_to_upstream_bytes,upstream_to_client_bytes) VALUES (${record.stream_id},${record.incoming_port},${record.bucket_start},${record.ip},${record.country_code},${record.protocol},${record.client_to_upstream_bytes},${record.upstream_to_client_bytes}) ON DUPLICATE KEY UPDATE client_to_upstream_bytes=client_to_upstream_bytes+${record.client_to_upstream_bytes},upstream_to_client_bytes=upstream_to_client_bytes+${record.upstream_to_client_bytes}`;
				} else {
					await transaction`INSERT INTO stream_bandwidth_minutes (stream_id,incoming_port,bucket_start,ip,country_code,protocol,client_to_upstream_bytes,upstream_to_client_bytes) VALUES (${record.stream_id},${record.incoming_port},${record.bucket_start},${record.ip},${record.country_code},${record.protocol},${record.client_to_upstream_bytes},${record.upstream_to_client_bytes}) ON CONFLICT (stream_id,incoming_port,bucket_start,ip,country_code,protocol) DO UPDATE SET client_to_upstream_bytes=stream_bandwidth_minutes.client_to_upstream_bytes+EXCLUDED.client_to_upstream_bytes,upstream_to_client_bytes=stream_bandwidth_minutes.upstream_to_client_bytes+EXCLUDED.upstream_to_client_bytes`;
				}
			}
		});
	},
	async addStreamOriginLatencyResult(streamId: string, bucketStart: number, result: LatencyCheckResult): Promise<void> {
		const latency = result.timedOut ? null : Math.max(0, Math.round(result.latencyMs ?? 0));
		const sum = result.timedOut ? 0 : (latency ?? 0);
		const timeout = result.timedOut ? 1 : 0;
		if (isMySqlDatabase()) {
			await db`INSERT INTO stream_origin_latency_minutes (stream_id,bucket_start,min_latency_ms,max_latency_ms,sum_latency_ms,total_count,timeout_count)
				VALUES (${streamId},${bucketStart},${latency},${latency},${sum},1,${timeout})
				ON DUPLICATE KEY UPDATE
				min_latency_ms = CASE WHEN min_latency_ms IS NULL THEN ${latency} WHEN ${latency} IS NULL THEN min_latency_ms WHEN min_latency_ms <= ${latency} THEN min_latency_ms ELSE ${latency} END,
				max_latency_ms = CASE WHEN max_latency_ms IS NULL THEN ${latency} WHEN ${latency} IS NULL THEN max_latency_ms WHEN max_latency_ms >= ${latency} THEN max_latency_ms ELSE ${latency} END,
				sum_latency_ms = sum_latency_ms + ${sum},
				total_count = total_count + 1,
				timeout_count = timeout_count + ${timeout}`;
			return;
		}
		await db`INSERT INTO stream_origin_latency_minutes (stream_id,bucket_start,min_latency_ms,max_latency_ms,sum_latency_ms,total_count,timeout_count)
			VALUES (${streamId},${bucketStart},${latency},${latency},${sum},1,${timeout})
			ON CONFLICT (stream_id,bucket_start) DO UPDATE SET
			min_latency_ms = CASE WHEN stream_origin_latency_minutes.min_latency_ms IS NULL THEN excluded.min_latency_ms WHEN excluded.min_latency_ms IS NULL THEN stream_origin_latency_minutes.min_latency_ms WHEN stream_origin_latency_minutes.min_latency_ms <= excluded.min_latency_ms THEN stream_origin_latency_minutes.min_latency_ms ELSE excluded.min_latency_ms END,
			max_latency_ms = CASE WHEN stream_origin_latency_minutes.max_latency_ms IS NULL THEN excluded.max_latency_ms WHEN excluded.max_latency_ms IS NULL THEN stream_origin_latency_minutes.max_latency_ms WHEN stream_origin_latency_minutes.max_latency_ms >= excluded.max_latency_ms THEN stream_origin_latency_minutes.max_latency_ms ELSE excluded.max_latency_ms END,
			sum_latency_ms = stream_origin_latency_minutes.sum_latency_ms + excluded.sum_latency_ms,
			total_count = stream_origin_latency_minutes.total_count + excluded.total_count,
			timeout_count = stream_origin_latency_minutes.timeout_count + excluded.timeout_count`;
	},
	async streamOriginLatencyMetrics(
		streamId: string | string[] | undefined,
		since: number,
		until: number,
		bucketMs: number,
	): Promise<{
		series: Array<{
			bucket: number;
			minLatencyMs: number | null;
			maxLatencyMs: number | null;
			avgLatencyMs: number | null;
			totalCount: number;
			timeoutCount: number;
			timeoutPct: number;
		}>;
	}> {
		const streamFilter = streamScopeFilter(streamId);
		const minuteSince = Math.floor(since / 60_000) * 60_000;
		const bucket = metricBucketExpression("bucket_start", bucketMs);
		const rows = (await db`
      SELECT ${bucket} * ${bucketMs} AS bucket,
        MIN(min_latency_ms) AS min_latency_ms,
        MAX(max_latency_ms) AS max_latency_ms,
        COALESCE(SUM(sum_latency_ms),0) AS sum_latency_ms,
        COALESCE(SUM(total_count),0) AS total_count,
        COALESCE(SUM(timeout_count),0) AS timeout_count
      FROM stream_origin_latency_minutes
      WHERE bucket_start >= ${minuteSince} AND bucket_start <= ${until} ${streamFilter}
      GROUP BY ${bucket}
      ORDER BY bucket ASC
    `) as LatencyMinuteRow[];
		return { series: latencySeriesFromRows(since, until, bucketMs, rows) };
	},
	async deleteStreamOriginLatencyBeforeBatch(streamId: string, cutoff: number, limit: number): Promise<number> {
		if (isMySqlDatabase()) {
			return deletedRowCount(
				await db`DELETE FROM stream_origin_latency_minutes WHERE stream_id=${streamId} AND bucket_start < ${cutoff} ORDER BY bucket_start ASC LIMIT ${limit}`,
			);
		}
		if (isSqliteDatabase()) {
			return deletedRowCount(
				await db`DELETE FROM stream_origin_latency_minutes WHERE rowid IN (SELECT rowid FROM stream_origin_latency_minutes WHERE stream_id=${streamId} AND bucket_start < ${cutoff} ORDER BY bucket_start ASC LIMIT ${limit})`,
			);
		}
		return deletedRowCount(
			await db`DELETE FROM stream_origin_latency_minutes WHERE ctid IN (SELECT ctid FROM stream_origin_latency_minutes WHERE stream_id=${streamId} AND bucket_start < ${cutoff} ORDER BY bucket_start ASC LIMIT ${limit})`,
		);
	},
	async pagedStreamEvents(query: StreamEventQuery): Promise<PageResult<StreamEventRecord>> {
		const pattern = searchPattern(query.search);
		const exactSearch = query.search?.trim().toLowerCase() || null;
		const exactSearchUpper = query.search?.trim().toUpperCase() || null;
		const streamFilter = streamScopeFilter(query.streamId);
		const protocolFilter = query.protocol ? db`AND protocol=${query.protocol}` : db``;
		const typeFilter = query.eventType ? db`AND event_type=${query.eventType}` : db``;
		const countryFilter = query.countryCode ? db`AND COALESCE(country_code,'ZZ')=${query.countryCode}` : db``;
		const asnFilter = query.asn ? db`AND asn=${query.asn}` : db``;
		const searchFilter = pattern
			? db`AND (LOWER(COALESCE(client_ip,'')) LIKE ${pattern} OR LOWER(COALESCE(reason,'')) LIKE ${pattern} OR LOWER(COALESCE(error,'')) LIKE ${pattern} OR LOWER(COALESCE(username,'')) LIKE ${pattern} OR connection_id=${exactSearch} OR protection_rule_id=${exactSearchUpper})`
			: db``;
		const offset = (query.page - 1) * query.pageSize;
		const order = db.unsafe(`${query.sortBy} ${query.sortDirection.toUpperCase()}`);
		const [countRow] =
			(await db`SELECT COUNT(*) AS count FROM stream_events WHERE created_at >= ${query.since} AND created_at <= ${query.until} ${streamFilter} ${protocolFilter} ${typeFilter} ${countryFilter} ${asnFilter} ${searchFilter}`) as Array<{
				count: number | string;
			}>;
		const items =
			(await db`SELECT * FROM stream_events WHERE created_at >= ${query.since} AND created_at <= ${query.until} ${streamFilter} ${protocolFilter} ${typeFilter} ${countryFilter} ${asnFilter} ${searchFilter} ORDER BY ${order} LIMIT ${query.pageSize} OFFSET ${offset}`) as StreamEventRecord[];
		return pageResult(items, countRow?.count, query.page, query.pageSize);
	},
	async pagedStreamBandwidth(query: StreamBandwidthQuery): Promise<PageResult<StreamBandwidthRow>> {
		const minuteSince = Math.floor(query.since / 60_000) * 60_000;
		const pattern = searchPattern(query.search);
		const streamFilter = streamScopeFilter(query.streamId);
		const protocolFilter = query.protocol ? db`AND protocol=${query.protocol}` : db``;
		const countryFilter = query.countryCode ? db`AND country_code=${query.countryCode}` : db``;
		const searchFilter = pattern ? db`AND LOWER(ip) LIKE ${pattern}` : db``;
		const offset = (query.page - 1) * query.pageSize;
		const order = db.unsafe(`${query.sortBy} ${query.sortDirection.toUpperCase()}`);
		const [countRow] =
			(await db`SELECT COUNT(*) AS count FROM (SELECT stream_id,incoming_port,ip,country_code,protocol FROM stream_bandwidth_minutes WHERE bucket_start >= ${minuteSince} AND bucket_start <= ${query.until} AND ip <> '__other__' ${streamFilter} ${protocolFilter} ${countryFilter} ${searchFilter} GROUP BY stream_id,incoming_port,ip,country_code,protocol) AS stream_bandwidth_ips`) as Array<{
				count: number | string;
			}>;
		const items =
			(await db`SELECT stream_id,incoming_port,ip,country_code,protocol,COALESCE(SUM(client_to_upstream_bytes),0) AS client_to_upstream_bytes,COALESCE(SUM(upstream_to_client_bytes),0) AS upstream_to_client_bytes,COALESCE(SUM(client_to_upstream_bytes+upstream_to_client_bytes),0) AS total_bytes FROM stream_bandwidth_minutes WHERE bucket_start >= ${minuteSince} AND bucket_start <= ${query.until} AND ip <> '__other__' ${streamFilter} ${protocolFilter} ${countryFilter} ${searchFilter} GROUP BY stream_id,incoming_port,ip,country_code,protocol ORDER BY ${order} LIMIT ${query.pageSize} OFFSET ${offset}`) as StreamBandwidthRow[];
		return pageResult(items, countRow?.count, query.page, query.pageSize);
	},
	async streamOverview(
		streamId: string | string[] | undefined,
		since: number,
		until: number,
	): Promise<{
		connections: number;
		disconnections: number;
		errors: number;
		blocked: number;
		uniqueIps: number;
		clientToUpstreamBytes: number;
		upstreamToClientBytes: number;
		countries: Array<{ countryCode: string; connections: number; bytes: number; blocked: number }>;
		asns: Array<{ asn: number; org: string; connections: number; blocked: number }>;
	}> {
		const eventStreamFilter = streamScopeFilter(streamId);
		const bandwidthStreamFilter = streamScopeFilter(streamId);
		const minuteSince = Math.floor(since / 60_000) * 60_000;
		const [events] =
			(await db`SELECT SUM(CASE WHEN event_type='connected' THEN 1 ELSE 0 END) AS connections,SUM(CASE WHEN event_type='disconnected' THEN 1 ELSE 0 END) AS disconnections,SUM(CASE WHEN event_type IN ('upstream-error','listener-error') THEN 1 ELSE 0 END) AS errors,SUM(CASE WHEN event_type='blocked' THEN 1 ELSE 0 END) AS blocked,COUNT(DISTINCT CASE WHEN event_type='connected' THEN client_ip ELSE NULL END) AS unique_ips FROM stream_events WHERE created_at >= ${since} AND created_at <= ${until} ${eventStreamFilter}`) as Array<
				Record<string, number | string>
			>;
		const [bandwidth] =
			(await db`SELECT COALESCE(SUM(client_to_upstream_bytes),0) AS client_to_upstream_bytes,COALESCE(SUM(upstream_to_client_bytes),0) AS upstream_to_client_bytes FROM stream_bandwidth_minutes WHERE bucket_start >= ${minuteSince} AND bucket_start <= ${until} ${bandwidthStreamFilter}`) as Array<
				Record<string, number | string>
			>;
		const countryRows =
			(await db`SELECT country_code,COALESCE(SUM(client_to_upstream_bytes+upstream_to_client_bytes),0) AS bytes FROM stream_bandwidth_minutes WHERE bucket_start >= ${minuteSince} AND bucket_start <= ${until} ${bandwidthStreamFilter} GROUP BY country_code ORDER BY bytes DESC`) as Array<{
				country_code: string;
				bytes: number | string;
			}>;
		const connectionCountries =
			(await db`SELECT COALESCE(country_code,'ZZ') AS country_code,COUNT(*) AS connections FROM stream_events WHERE event_type='connected' AND created_at >= ${since} AND created_at <= ${until} ${eventStreamFilter} GROUP BY COALESCE(country_code,'ZZ')`) as Array<{
				country_code: string;
				connections: number | string;
			}>;
		const blockedCountries =
			(await db`SELECT COALESCE(country_code,'ZZ') AS country_code,COUNT(*) AS blocked FROM stream_events WHERE event_type='blocked' AND created_at >= ${since} AND created_at <= ${until} ${eventStreamFilter} GROUP BY COALESCE(country_code,'ZZ')`) as Array<{
				country_code: string;
				blocked: number | string;
			}>;
		const connectionsByCountry = new Map(connectionCountries.map((row) => [row.country_code, toNumber(row.connections)]));
		const blockedByCountry = new Map(blockedCountries.map((row) => [row.country_code, toNumber(row.blocked)]));
		const countries = new Map<string, { countryCode: string; connections: number; bytes: number; blocked: number }>();
		for (const row of countryRows)
			countries.set(row.country_code, {
				countryCode: row.country_code,
				connections: connectionsByCountry.get(row.country_code) ?? 0,
				bytes: toNumber(row.bytes),
				blocked: blockedByCountry.get(row.country_code) ?? 0,
			});
		for (const row of connectionCountries)
			if (!countries.has(row.country_code))
				countries.set(row.country_code, {
					countryCode: row.country_code,
					connections: toNumber(row.connections),
					bytes: 0,
					blocked: blockedByCountry.get(row.country_code) ?? 0,
				});
		for (const row of blockedCountries)
			if (!countries.has(row.country_code))
				countries.set(row.country_code, { countryCode: row.country_code, connections: 0, bytes: 0, blocked: toNumber(row.blocked) });
		const connectionAsns =
			(await db`SELECT COALESCE(asn,0) AS asn,COALESCE(asn_org,'Unknown') AS asn_org,COUNT(*) AS connections FROM stream_events WHERE event_type='connected' AND created_at >= ${since} AND created_at <= ${until} ${eventStreamFilter} GROUP BY COALESCE(asn,0),COALESCE(asn_org,'Unknown')`) as Array<{
				asn: number | string;
				asn_org: string;
				connections: number | string;
			}>;
		const blockedAsns =
			(await db`SELECT COALESCE(asn,0) AS asn,COALESCE(asn_org,'Unknown') AS asn_org,COUNT(*) AS blocked FROM stream_events WHERE event_type='blocked' AND created_at >= ${since} AND created_at <= ${until} ${eventStreamFilter} GROUP BY COALESCE(asn,0),COALESCE(asn_org,'Unknown')`) as Array<{
				asn: number | string;
				asn_org: string;
				blocked: number | string;
			}>;
		const blockedByAsn = new Map(blockedAsns.map((row) => [toNumber(row.asn), toNumber(row.blocked)]));
		const asns = new Map<number, { asn: number; org: string; connections: number; blocked: number }>();
		for (const row of connectionAsns) {
			const asn = toNumber(row.asn);
			asns.set(asn, { asn, org: row.asn_org, connections: toNumber(row.connections), blocked: blockedByAsn.get(asn) ?? 0 });
		}
		for (const row of blockedAsns) {
			const asn = toNumber(row.asn);
			if (!asns.has(asn)) asns.set(asn, { asn, org: row.asn_org, connections: 0, blocked: toNumber(row.blocked) });
		}
		return {
			connections: toNumber(events?.connections),
			disconnections: toNumber(events?.disconnections),
			errors: toNumber(events?.errors),
			blocked: toNumber(events?.blocked),
			uniqueIps: toNumber(events?.unique_ips),
			clientToUpstreamBytes: toNumber(bandwidth?.client_to_upstream_bytes),
			upstreamToClientBytes: toNumber(bandwidth?.upstream_to_client_bytes),
			countries: [...countries.values()].sort((a, b) => b.bytes - a.bytes || b.connections - a.connections),
			asns: [...asns.values()].sort((a, b) => b.connections - a.connections || b.blocked - a.blocked).slice(0, 25),
		};
	},
	async streamMetrics(
		streamId: string | string[] | undefined,
		since: number,
		until: number,
		bucketMs: number,
	): Promise<{
		series: Array<{
			bucket: number;
			connected: number;
			disconnected: number;
			errors: number;
			blocked: number;
			clientToUpstreamBytes: number;
			upstreamToClientBytes: number;
		}>;
	}> {
		const eventStreamFilter = streamScopeFilter(streamId);
		const bandwidthStreamFilter = streamScopeFilter(streamId);
		const eventBucket = metricBucketExpression("created_at", bucketMs);
		const bandwidthBucket = metricBucketExpression("bucket_start", bucketMs);
		const minuteSince = Math.floor(since / 60_000) * 60_000;
		const eventRows = (await db`
      SELECT ${eventBucket} * ${bucketMs} AS bucket,
        SUM(CASE WHEN event_type='connected' THEN 1 ELSE 0 END) AS connected,
        SUM(CASE WHEN event_type='disconnected' THEN 1 ELSE 0 END) AS disconnected,
        SUM(CASE WHEN event_type IN ('upstream-error','listener-error') THEN 1 ELSE 0 END) AS errors,
        SUM(CASE WHEN event_type='blocked' THEN 1 ELSE 0 END) AS blocked
      FROM stream_events
      WHERE created_at >= ${since} AND created_at <= ${until} ${eventStreamFilter}
      GROUP BY ${eventBucket}
      ORDER BY bucket ASC
    `) as Array<{
			bucket: number | string;
			connected: number | string;
			disconnected: number | string;
			errors: number | string;
			blocked: number | string;
		}>;
		const bandwidthRows = (await db`
      SELECT ${bandwidthBucket} * ${bucketMs} AS bucket,
        COALESCE(SUM(client_to_upstream_bytes),0) AS client_to_upstream_bytes,
        COALESCE(SUM(upstream_to_client_bytes),0) AS upstream_to_client_bytes
      FROM stream_bandwidth_minutes
      WHERE bucket_start >= ${minuteSince} AND bucket_start <= ${until} ${bandwidthStreamFilter}
      GROUP BY ${bandwidthBucket}
      ORDER BY bucket ASC
    `) as Array<{
			bucket: number | string;
			client_to_upstream_bytes: number | string;
			upstream_to_client_bytes: number | string;
		}>;
		const series = emptyMetricPoints(since, until, bucketMs, (bucket) => ({
			bucket,
			connected: 0,
			disconnected: 0,
			errors: 0,
			blocked: 0,
			clientToUpstreamBytes: 0,
			upstreamToClientBytes: 0,
		}));
		const byBucket = new Map(series.map((point) => [point.bucket, point]));
		for (const row of eventRows) {
			const point = byBucket.get(toNumber(row.bucket));
			if (!point) continue;
			point.connected = toNumber(row.connected);
			point.disconnected = toNumber(row.disconnected);
			point.errors = toNumber(row.errors);
			point.blocked = toNumber(row.blocked);
		}
		for (const row of bandwidthRows) {
			const point = byBucket.get(toNumber(row.bucket));
			if (!point) continue;
			point.clientToUpstreamBytes = toNumber(row.client_to_upstream_bytes);
			point.upstreamToClientBytes = toNumber(row.upstream_to_client_bytes);
		}
		return { series };
	},
	async streamLongLivedMetrics(
		streamId: string | string[] | undefined,
		since: number,
		until: number,
		bucketMs: number,
		minDurationMs: number,
	): Promise<{ series: Array<{ bucket: number; connected: number; disconnected: number }> }> {
		const eventStreamFilter = streamScopeFilter(streamId);

		const disconnectedBucket = metricBucketExpression("created_at", bucketMs);
		const connectedBucket = isMySqlDatabase()
			? db`FLOOR((created_at - duration_ms) / ${bucketMs})`
			: db`CAST((created_at - duration_ms) / ${bucketMs} AS BIGINT)`;
		const disconnectedRows = (await db`
      SELECT ${disconnectedBucket} * ${bucketMs} AS bucket, COUNT(*) AS count
      FROM stream_events
      WHERE event_type='disconnected' AND duration_ms >= ${minDurationMs}
        AND created_at >= ${since} AND created_at <= ${until} ${eventStreamFilter}
      GROUP BY ${disconnectedBucket}
    `) as Array<{ bucket: number | string; count: number | string }>;
		const connectedRows = (await db`
      SELECT ${connectedBucket} * ${bucketMs} AS bucket, COUNT(*) AS count
      FROM stream_events
      WHERE event_type='disconnected' AND duration_ms >= ${minDurationMs}
        AND created_at >= ${since} AND created_at <= ${until} ${eventStreamFilter}
      GROUP BY ${connectedBucket}
    `) as Array<{ bucket: number | string; count: number | string }>;
		const series = emptyMetricPoints(since, until, bucketMs, (bucket) => ({ bucket, connected: 0, disconnected: 0 }));
		const byBucket = new Map(series.map((point) => [point.bucket, point]));
		for (const row of disconnectedRows) {
			const point = byBucket.get(toNumber(row.bucket));
			if (point) point.disconnected = toNumber(row.count);
		}
		for (const row of connectedRows) {
			const point = byBucket.get(toNumber(row.bucket));
			if (point) point.connected = toNumber(row.count);
		}
		return { series };
	},
	async streamsComparisonMetrics(streamIds: string[], since: number, until: number): Promise<Array<{ streamId: string; connections: number; bytes: number }>> {
		if (streamIds.length === 0) return [];
		const streamFilter = db`AND stream_id IN ${db(streamIds)}`;
		const minuteSince = Math.floor(since / 60_000) * 60_000;
		const eventRows = (await db`
      SELECT stream_id, COUNT(*) AS connections
      FROM stream_events
      WHERE event_type='connected' AND created_at >= ${since} AND created_at <= ${until} ${streamFilter}
      GROUP BY stream_id
    `) as Array<{ stream_id: string; connections: number | string }>;
		const bandwidthRows = (await db`
      SELECT stream_id, COALESCE(SUM(client_to_upstream_bytes + upstream_to_client_bytes),0) AS bytes
      FROM stream_bandwidth_minutes
      WHERE bucket_start >= ${minuteSince} AND bucket_start <= ${until} ${streamFilter}
      GROUP BY stream_id
    `) as Array<{ stream_id: string; bytes: number | string }>;
		const totals = new Map<string, { connections: number; bytes: number }>();
		for (const row of eventRows) totals.set(row.stream_id, { connections: toNumber(row.connections), bytes: 0 });
		for (const row of bandwidthRows) {
			const current = totals.get(row.stream_id) ?? { connections: 0, bytes: 0 };
			current.bytes = toNumber(row.bytes);
			totals.set(row.stream_id, current);
		}
		return [...totals.entries()].map(([streamId, value]) => ({ streamId, ...value }));
	},
	async streamTabIpMetrics(
		streamId: string | string[] | undefined,
		since: number,
		until: number,
		scope: "blocked",
	): Promise<Array<{ ip: string; count: number }>> {
		const streamFilter = streamScopeFilter(streamId);
		const scopeFilter = scope === "blocked" ? db`AND event_type='blocked'` : db``;
		const rows = (await db`
      SELECT COALESCE(client_ip, 'unknown') AS ip, COUNT(*) AS count
      FROM stream_events
      WHERE created_at >= ${since} AND created_at <= ${until} ${streamFilter} ${scopeFilter}
      GROUP BY COALESCE(client_ip, 'unknown')
      ORDER BY count DESC
      LIMIT 25
    `) as Array<{ ip: string; count: number | string }>;
		return rows.map((row) => ({ ip: row.ip, count: toNumber(row.count) }));
	},
	async streamTabBandwidthIpMetrics(streamId: string | string[] | undefined, since: number, until: number): Promise<Array<{ ip: string; count: number }>> {
		const streamFilter = streamScopeFilter(streamId);
		const minuteSince = Math.floor(since / 60_000) * 60_000;
		const rows = (await db`
      SELECT ip, COALESCE(SUM(client_to_upstream_bytes + upstream_to_client_bytes),0) AS count
      FROM stream_bandwidth_minutes
      WHERE bucket_start >= ${minuteSince} AND bucket_start <= ${until} AND ip <> '__other__' ${streamFilter}
      GROUP BY ip
      ORDER BY count DESC
      LIMIT 25
    `) as Array<{ ip: string; count: number | string }>;
		return rows.map((row) => ({ ip: row.ip, count: toNumber(row.count) }));
	},
	async streamBlockReasonMetrics(streamId: string | string[] | undefined, since: number, until: number): Promise<Array<{ reason: string; count: number }>> {
		const streamFilter = streamScopeFilter(streamId);
		const rows = (await db`
      SELECT COALESCE(reason, 'Unknown') AS reason, COUNT(*) AS count
      FROM stream_events
      WHERE event_type='blocked' AND created_at >= ${since} AND created_at <= ${until} ${streamFilter}
      GROUP BY COALESCE(reason, 'Unknown')
      ORDER BY count DESC
      LIMIT 15
    `) as Array<{ reason: string; count: number | string }>;
		return rows.map((row) => ({ reason: row.reason, count: toNumber(row.count) }));
	},
	async streamErrorReasonMetrics(streamId: string | string[] | undefined, since: number, until: number): Promise<Array<{ error: string; count: number }>> {
		const streamFilter = streamScopeFilter(streamId);
		const rows = (await db`
      SELECT error, COUNT(*) AS count
      FROM stream_events
      WHERE event_type IN ('upstream-error','listener-error') AND error IS NOT NULL AND created_at >= ${since} AND created_at <= ${until} ${streamFilter}
      GROUP BY error
      ORDER BY count DESC
      LIMIT 15
    `) as Array<{ error: string; count: number | string }>;
		return rows.map((row) => ({ error: row.error, count: toNumber(row.count) }));
	},
	async streamProtocolMetrics(
		streamId: string | string[] | undefined,
		since: number,
		until: number,
	): Promise<Array<{ protocol: string; connections: number; bytes: number }>> {
		const eventStreamFilter = streamScopeFilter(streamId);
		const bandwidthStreamFilter = streamScopeFilter(streamId);
		const minuteSince = Math.floor(since / 60_000) * 60_000;
		const eventRows = (await db`
      SELECT protocol, COUNT(*) AS connections
      FROM stream_events
      WHERE event_type='connected' AND created_at >= ${since} AND created_at <= ${until} ${eventStreamFilter}
      GROUP BY protocol
    `) as Array<{ protocol: string; connections: number | string }>;
		const bandwidthRows = (await db`
      SELECT protocol, COALESCE(SUM(client_to_upstream_bytes + upstream_to_client_bytes),0) AS bytes
      FROM stream_bandwidth_minutes
      WHERE bucket_start >= ${minuteSince} AND bucket_start <= ${until} ${bandwidthStreamFilter}
      GROUP BY protocol
    `) as Array<{ protocol: string; bytes: number | string }>;
		const totals = new Map<string, { connections: number; bytes: number }>();
		for (const row of eventRows) totals.set(row.protocol, { connections: toNumber(row.connections), bytes: 0 });
		for (const row of bandwidthRows) {
			const current = totals.get(row.protocol) ?? { connections: 0, bytes: 0 };
			current.bytes = toNumber(row.bytes);
			totals.set(row.protocol, current);
		}
		return [...totals.entries()].map(([protocol, value]) => ({ protocol, ...value }));
	},
	async deleteStreamEventsBeforeBatch(streamId: string, cutoff: number, limit: number): Promise<number> {
		const rows =
			(await db`SELECT id FROM stream_events WHERE stream_id=${streamId} AND created_at < ${cutoff} ORDER BY created_at ASC LIMIT ${limit}`) as Array<{
				id: string;
			}>;
		if (rows.length === 0) return 0;
		await db`DELETE FROM stream_events WHERE id IN ${db(rows.map((row) => row.id))}`;
		return rows.length;
	},
	async deleteStreamBandwidthBeforeBatch(streamId: string, cutoff: number, limit: number): Promise<number> {
		if (isMySqlDatabase()) {
			return deletedRowCount(
				await db`DELETE FROM stream_bandwidth_minutes WHERE stream_id=${streamId} AND bucket_start < ${cutoff} ORDER BY bucket_start ASC LIMIT ${limit}`,
			);
		}
		if (isSqliteDatabase()) {
			return deletedRowCount(
				await db`DELETE FROM stream_bandwidth_minutes WHERE rowid IN (SELECT rowid FROM stream_bandwidth_minutes WHERE stream_id=${streamId} AND bucket_start < ${cutoff} ORDER BY bucket_start ASC LIMIT ${limit})`,
			);
		}
		return deletedRowCount(
			await db`DELETE FROM stream_bandwidth_minutes WHERE ctid IN (SELECT ctid FROM stream_bandwidth_minutes WHERE stream_id=${streamId} AND bucket_start < ${cutoff} ORDER BY bucket_start ASC LIMIT ${limit})`,
		);
	},
	async adminByHash(hash: string): Promise<AdminSessionRecord | null> {
		const rows = (await db`SELECT * FROM admin_sessions WHERE token_hash=${hash} LIMIT 1`) as AdminSessionRecord[];
		return rows[0] ?? null;
	},
	async insertAdmin(session: AdminSessionRecord): Promise<void> {
		await db.begin(async (transaction) => {
			await transaction`INSERT INTO admin_sessions (id,token_hash,username,user_id,created_at,expires_at,last_seen_at,sso_sid) VALUES (${session.id},${session.token_hash},${session.username},${session.user_id},${session.created_at},${session.expires_at},${session.last_seen_at},${session.sso_sid ?? null})`;
			await replicateSessionChange(transaction, "admin_session", session.id, "insert", session);
		});
	},
	async revokeAdminSessionsBySsoSid(sid: string): Promise<number> {
		return await db.begin(async (transaction) => {
			const matches = (await transaction`SELECT id FROM admin_sessions WHERE sso_sid=${sid}`) as Array<{ id: string }>;
			const affected = deletedRowCount(await transaction`DELETE FROM admin_sessions WHERE sso_sid=${sid}`);
			for (const row of matches) await replicateSessionChange(transaction, "admin_session", row.id, "delete", null);
			return affected;
		});
	},
	async touchAdmin(id: string, now: number): Promise<void> {
		await db`UPDATE admin_sessions SET last_seen_at=${now} WHERE id=${id}`;
	},
	async deleteAdmin(hash: string): Promise<void> {
		await db.begin(async (transaction) => {
			const existing = (await transaction`SELECT id FROM admin_sessions WHERE token_hash=${hash} LIMIT 1`) as Array<{ id: string }>;
			await transaction`DELETE FROM admin_sessions WHERE token_hash=${hash}`;
			if (existing[0]) await replicateSessionChange(transaction, "admin_session", existing[0].id, "delete", null);
		});
	},
	async revokeAdminSessionsForUser(userId: string): Promise<void> {
		await db.begin(async (transaction) => {
			const matches = (await transaction`SELECT id FROM admin_sessions WHERE user_id=${userId}`) as Array<{ id: string }>;
			await transaction`DELETE FROM admin_sessions WHERE user_id=${userId}`;
			for (const row of matches) await replicateSessionChange(transaction, "admin_session", row.id, "delete", null);
		});
	},
	async anyAdminUserExists(): Promise<boolean> {
		const rows = (await db`SELECT id FROM admin_users LIMIT 1`) as Array<{ id: string }>;
		return rows.length > 0;
	},
	async allAdminUsers(): Promise<AdminUserRecord[]> {
		return (await db`SELECT * FROM admin_users ORDER BY username ASC`) as AdminUserRecord[];
	},
	async adminUserById(id: string): Promise<AdminUserRecord | null> {
		const rows = (await db`SELECT * FROM admin_users WHERE id=${id} LIMIT 1`) as AdminUserRecord[];
		return rows[0] ?? null;
	},
	async adminUserByUsername(username: string): Promise<AdminUserRecord | null> {
		const rows = (await db`SELECT * FROM admin_users WHERE username=${username} LIMIT 1`) as AdminUserRecord[];
		return rows[0] ?? null;
	},
	async countEnabledAdministrators(excludedUserId?: string): Promise<number> {
		const rows = (await db`SELECT id FROM admin_users WHERE role='administrator' AND enabled=1`) as Array<{ id: string }>;
		return rows.filter((row) => row.id !== excludedUserId).length;
	},
	async insertAdminUser(user: AdminUserRecord): Promise<void> {
		await db.begin(async (transaction) => {
			await transaction`INSERT INTO admin_users (id,username,password_hash,role,totp_secret_encrypted,totp_enrolled_at,must_enroll_totp,enabled,created_at,updated_at,created_by_user_id,sso_subject,auth_source)
			VALUES (${user.id},${user.username},${user.password_hash},${user.role},${user.totp_secret_encrypted},${user.totp_enrolled_at},${user.must_enroll_totp},${user.enabled},${user.created_at},${user.updated_at},${user.created_by_user_id},${user.sso_subject},${user.auth_source})`;
			await replicateSessionChange(transaction, "admin_user", user.id, "insert", user);
		});
	},
	async updateAdminUser(user: AdminUserRecord): Promise<void> {
		await db.begin(async (transaction) => {
			const existing = (await transaction`SELECT * FROM admin_users WHERE id=${user.id} LIMIT 1`) as AdminUserRecord[];
			await transaction`UPDATE admin_users SET username=${user.username},password_hash=${user.password_hash},role=${user.role},totp_secret_encrypted=${user.totp_secret_encrypted},totp_enrolled_at=${user.totp_enrolled_at},must_enroll_totp=${user.must_enroll_totp},enabled=${user.enabled},updated_at=${user.updated_at},sso_subject=${user.sso_subject},auth_source=${user.auth_source} WHERE id=${user.id}`;
			const patch = relayFieldPatch(
				existing[0] as unknown as Record<string, unknown> | undefined,
				user as unknown as Record<string, unknown>,
				ADMIN_USER_MUTABLE_FIELDS,
			);
			await replicateSessionChange(transaction, "admin_user", user.id, "update", patch, user);
		});
	},
	async adminUserBySsoSubject(subject: string): Promise<AdminUserRecord | null> {
		const rows = (await db`SELECT * FROM admin_users WHERE sso_subject=${subject} LIMIT 1`) as AdminUserRecord[];
		return rows[0] ?? null;
	},
	async deleteAdminUserCascade(userId: string): Promise<void> {
		await db.begin(async (transaction) => {
			const sitePermissions = (await transaction`SELECT site_id FROM admin_user_site_permissions WHERE user_id=${userId}`) as Array<{ site_id: string }>;
			await transaction`DELETE FROM admin_user_site_permissions WHERE user_id=${userId}`;
			const streamPermissions = (await transaction`SELECT stream_id FROM admin_user_stream_permissions WHERE user_id=${userId}`) as Array<{
				stream_id: string;
			}>;
			await transaction`DELETE FROM admin_user_stream_permissions WHERE user_id=${userId}`;
			const recoveryCodes = (await transaction`SELECT id FROM admin_recovery_codes WHERE user_id=${userId}`) as Array<{ id: string }>;
			await transaction`DELETE FROM admin_recovery_codes WHERE user_id=${userId}`;
			const webauthnCredentials = (await transaction`SELECT id FROM admin_webauthn_credentials WHERE user_id=${userId}`) as Array<{ id: string }>;
			await transaction`DELETE FROM admin_webauthn_credentials WHERE user_id=${userId}`;
			const sessions = (await transaction`SELECT id FROM admin_sessions WHERE user_id=${userId}`) as Array<{ id: string }>;
			await transaction`DELETE FROM admin_sessions WHERE user_id=${userId}`;
			await transaction`DELETE FROM admin_users WHERE id=${userId}`;
			for (const row of sessions) await replicateSessionChange(transaction, "admin_session", row.id, "delete", null);
			for (const row of recoveryCodes) await replicateSessionChange(transaction, "admin_recovery_code", row.id, "delete", null);
			for (const row of webauthnCredentials) await replicateSessionChange(transaction, "admin_webauthn_credential", row.id, "delete", null);
			for (const row of sitePermissions) await replicateSessionChange(transaction, "admin_site_permission", `${userId}:${row.site_id}`, "delete", null);
			for (const row of streamPermissions) await replicateSessionChange(transaction, "admin_stream_permission", `${userId}:${row.stream_id}`, "delete", null);
			await replicateSessionChange(transaction, "admin_user", userId, "delete", null);
		});
	},
	async replaceAdminRecoveryCodes(userId: string, codes: AdminRecoveryCodeRecord[]): Promise<void> {
		await db.begin(async (transaction) => {
			const existing = (await transaction`SELECT id FROM admin_recovery_codes WHERE user_id=${userId}`) as Array<{ id: string }>;
			await transaction`DELETE FROM admin_recovery_codes WHERE user_id=${userId}`;
			for (const row of existing) await replicateSessionChange(transaction, "admin_recovery_code", row.id, "delete", null);
			for (const code of codes) {
				await transaction`INSERT INTO admin_recovery_codes (id,user_id,code_hash,created_at,used_at) VALUES (${code.id},${code.user_id},${code.code_hash},${code.created_at},${code.used_at})`;
				await replicateSessionChange(transaction, "admin_recovery_code", code.id, "insert", code);
			}
		});
	},
	async unusedAdminRecoveryCodeCount(userId: string): Promise<number> {
		const rows = (await db`SELECT id FROM admin_recovery_codes WHERE user_id=${userId} AND used_at IS NULL`) as Array<{ id: string }>;
		return rows.length;
	},
	async consumeAdminRecoveryCodeByHash(userId: string, codeHash: string, now: number): Promise<boolean> {
		return await db.begin(async (transaction) => {
			const existing =
				(await transaction`SELECT * FROM admin_recovery_codes WHERE user_id=${userId} AND code_hash=${codeHash} AND used_at IS NULL LIMIT 1`) as AdminRecoveryCodeRecord[];
			const result = await transaction`UPDATE admin_recovery_codes SET used_at=${now} WHERE user_id=${userId} AND code_hash=${codeHash} AND used_at IS NULL`;
			const consumed = deletedRowCount(result) > 0;
			if (consumed && existing[0]) await replicateSessionChange(transaction, "admin_recovery_code", existing[0].id, "update", { ...existing[0], used_at: now });
			return consumed;
		});
	},
	async adminWebauthnCredentialsForUser(userId: string): Promise<AdminWebauthnCredentialRecord[]> {
		return (await db`SELECT * FROM admin_webauthn_credentials WHERE user_id=${userId} ORDER BY created_at ASC`) as AdminWebauthnCredentialRecord[];
	},
	async adminWebauthnCredentialByHash(hash: string): Promise<AdminWebauthnCredentialRecord | null> {
		const rows = (await db`SELECT * FROM admin_webauthn_credentials WHERE credential_id_hash=${hash} LIMIT 1`) as AdminWebauthnCredentialRecord[];
		return rows[0] ?? null;
	},
	async adminWebauthnCredentialById(id: string, userId: string): Promise<AdminWebauthnCredentialRecord | null> {
		const rows = (await db`SELECT * FROM admin_webauthn_credentials WHERE id=${id} AND user_id=${userId} LIMIT 1`) as AdminWebauthnCredentialRecord[];
		return rows[0] ?? null;
	},
	async insertAdminWebauthnCredential(record: AdminWebauthnCredentialRecord): Promise<void> {
		await db.begin(async (transaction) => {
			await transaction`INSERT INTO admin_webauthn_credentials (id,user_id,rp_id,credential_id,credential_id_hash,public_key,sign_count,transports_json,aaguid,device_type,backed_up,nickname,created_at,last_used_at,updated_at)
			VALUES (${record.id},${record.user_id},${record.rp_id},${record.credential_id},${record.credential_id_hash},${record.public_key},${record.sign_count},${record.transports_json},${record.aaguid},${record.device_type},${record.backed_up},${record.nickname},${record.created_at},${record.last_used_at},${record.updated_at})`;
			await replicateSessionChange(transaction, "admin_webauthn_credential", record.id, "insert", record);
		});
	},

	async touchAdminWebauthnCredential(id: string, signCount: number, now: number): Promise<void> {
		await db`UPDATE admin_webauthn_credentials SET sign_count=${signCount}, last_used_at=${now}, updated_at=${now} WHERE id=${id}`;
	},
	async renameAdminWebauthnCredential(id: string, userId: string, nickname: string | null, now: number): Promise<void> {
		await db.begin(async (transaction) => {
			const existing =
				(await transaction`SELECT * FROM admin_webauthn_credentials WHERE id=${id} AND user_id=${userId} LIMIT 1`) as AdminWebauthnCredentialRecord[];
			await transaction`UPDATE admin_webauthn_credentials SET nickname=${nickname}, updated_at=${now} WHERE id=${id} AND user_id=${userId}`;
			if (existing[0]) await replicateSessionChange(transaction, "admin_webauthn_credential", id, "update", { ...existing[0], nickname, updated_at: now });
		});
	},
	async deleteAdminWebauthnCredential(id: string, userId: string): Promise<void> {
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM admin_webauthn_credentials WHERE id=${id} AND user_id=${userId}`;
			await replicateSessionChange(transaction, "admin_webauthn_credential", id, "delete", null);
		});
	},
	async deleteAllAdminWebauthnCredentialsForUser(userId: string): Promise<void> {
		await db.begin(async (transaction) => {
			const existing = (await transaction`SELECT id FROM admin_webauthn_credentials WHERE user_id=${userId}`) as Array<{ id: string }>;
			await transaction`DELETE FROM admin_webauthn_credentials WHERE user_id=${userId}`;
			for (const row of existing) await replicateSessionChange(transaction, "admin_webauthn_credential", row.id, "delete", null);
		});
	},
	async adminSitePermission(userId: string, siteId: string): Promise<AdminUserSitePermissionRecord | null> {
		const rows = (await db`SELECT * FROM admin_user_site_permissions WHERE user_id=${userId} AND site_id=${siteId} LIMIT 1`) as AdminUserSitePermissionRecord[];
		return rows[0] ?? null;
	},
	async adminStreamPermission(userId: string, streamId: string): Promise<AdminUserStreamPermissionRecord | null> {
		const rows =
			(await db`SELECT * FROM admin_user_stream_permissions WHERE user_id=${userId} AND stream_id=${streamId} LIMIT 1`) as AdminUserStreamPermissionRecord[];
		return rows[0] ?? null;
	},
	async adminSitePermissionsForUser(userId: string): Promise<AdminUserSitePermissionRecord[]> {
		return (await db`SELECT * FROM admin_user_site_permissions WHERE user_id=${userId}`) as AdminUserSitePermissionRecord[];
	},
	async adminStreamPermissionsForUser(userId: string): Promise<AdminUserStreamPermissionRecord[]> {
		return (await db`SELECT * FROM admin_user_stream_permissions WHERE user_id=${userId}`) as AdminUserStreamPermissionRecord[];
	},
	async replaceAdminSitePermissions(
		userId: string,
		permissions: Array<{ siteId: string; level: Exclude<AdminAccessLevel, "none"> }>,
		now = Date.now(),
	): Promise<void> {
		await db.begin(async (transaction) => {
			const existing = (await transaction`SELECT site_id FROM admin_user_site_permissions WHERE user_id=${userId}`) as Array<{ site_id: string }>;
			await transaction`DELETE FROM admin_user_site_permissions WHERE user_id=${userId}`;
			for (const row of existing) await replicateSessionChange(transaction, "admin_site_permission", `${userId}:${row.site_id}`, "delete", null);
			for (const permission of permissions) {
				await transaction`INSERT INTO admin_user_site_permissions (user_id,site_id,level,created_at,updated_at) VALUES (${userId},${permission.siteId},${permission.level},${now},${now})`;
				await replicateSessionChange(transaction, "admin_site_permission", `${userId}:${permission.siteId}`, "insert", {
					user_id: userId,
					site_id: permission.siteId,
					level: permission.level,
					created_at: now,
					updated_at: now,
				});
			}
		});
	},
	async replaceAdminStreamPermissions(
		userId: string,
		permissions: Array<{ streamId: string; level: Exclude<AdminAccessLevel, "none"> }>,
		now = Date.now(),
	): Promise<void> {
		await db.begin(async (transaction) => {
			const existing = (await transaction`SELECT stream_id FROM admin_user_stream_permissions WHERE user_id=${userId}`) as Array<{ stream_id: string }>;
			await transaction`DELETE FROM admin_user_stream_permissions WHERE user_id=${userId}`;
			for (const row of existing) await replicateSessionChange(transaction, "admin_stream_permission", `${userId}:${row.stream_id}`, "delete", null);
			for (const permission of permissions) {
				await transaction`INSERT INTO admin_user_stream_permissions (user_id,stream_id,level,created_at,updated_at) VALUES (${userId},${permission.streamId},${permission.level},${now},${now})`;
				await replicateSessionChange(transaction, "admin_stream_permission", `${userId}:${permission.streamId}`, "insert", {
					user_id: userId,
					stream_id: permission.streamId,
					level: permission.level,
					created_at: now,
					updated_at: now,
				});
			}
		});
	},
	async adminSitesForUser(userId: string): Promise<SiteRecord[]> {
		return (await db`SELECT s.* FROM sites s JOIN admin_user_site_permissions permission ON permission.site_id=s.id WHERE permission.user_id=${userId} ORDER BY s.name ASC`) as SiteRecord[];
	},
	async adminStreamsForUser(userId: string): Promise<StreamRecord[]> {
		return (await db`SELECT s.* FROM streams s JOIN admin_user_stream_permissions permission ON permission.stream_id=s.id WHERE permission.user_id=${userId} ORDER BY s.name ASC`) as StreamRecord[];
	},
	async insertAdminAuditEntry(entry: AdminAuditLogRecord): Promise<void> {
		await db`INSERT INTO admin_audit_log (id,actor_user_id,actor_username,action,resource_type,resource_id,summary,detail_json,ip,created_at)
		VALUES (${entry.id},${entry.actor_user_id},${entry.actor_username},${entry.action},${entry.resource_type},${entry.resource_id},${entry.summary},${entry.detail_json},${entry.ip},${entry.created_at})`;
	},
	async pagedAdminAuditLog(query: AuditLogQuery): Promise<PageResult<AdminAuditLogRecord>> {
		const pattern = searchPattern(query.search);
		const searchFilter = pattern ? db`AND (LOWER(actor_username) LIKE ${pattern} OR LOWER(summary) LIKE ${pattern} OR LOWER(action) LIKE ${pattern})` : db``;
		const actorFilter = query.actorUserId ? db`AND actor_user_id=${query.actorUserId}` : db``;
		const actionFilter = query.action ? db`AND action=${query.action}` : db``;
		const resourceTypeFilter = query.resourceType ? db`AND resource_type=${query.resourceType}` : db``;
		const resourceIdFilter = query.resourceId ? db`AND resource_id=${query.resourceId}` : db``;
		const sinceFilter = query.since !== undefined ? db`AND created_at >= ${query.since}` : db``;
		const untilFilter = query.until !== undefined ? db`AND created_at <= ${query.until}` : db``;
		const order = db.unsafe(`${query.sortBy} ${query.sortDirection.toUpperCase()}`);
		const offset = (query.page - 1) * query.pageSize;
		const [countRow] = (await db`
      SELECT COUNT(*) AS count FROM admin_audit_log
      WHERE 1=1 ${searchFilter} ${actorFilter} ${actionFilter} ${resourceTypeFilter} ${resourceIdFilter} ${sinceFilter} ${untilFilter}
    `) as Array<{ count: number | string }>;
		const items = (await db`
      SELECT * FROM admin_audit_log
      WHERE 1=1 ${searchFilter} ${actorFilter} ${actionFilter} ${resourceTypeFilter} ${resourceIdFilter} ${sinceFilter} ${untilFilter}
      ORDER BY ${order}
      LIMIT ${query.pageSize} OFFSET ${offset}
    `) as AdminAuditLogRecord[];
		return pageResult(items, countRow?.count, query.page, query.pageSize);
	},
	async purgeAdminAuditLogOlderThan(cutoff: number): Promise<number> {
		return deletedRowCount(await db`DELETE FROM admin_audit_log WHERE created_at < ${cutoff}`);
	},
	async purgeAllAdminAuditLog(): Promise<number> {
		return deletedRowCount(await db`DELETE FROM admin_audit_log`);
	},
	async adminSsoSettings(): Promise<AdminSsoSettingsRecord | null> {
		const rows = (await db`SELECT * FROM admin_sso_settings WHERE id='instance' LIMIT 1`) as AdminSsoSettingsRecord[];
		return rows[0] ?? null;
	},
	async ensureAdminSsoSettings(now = Date.now()): Promise<AdminSsoSettingsRecord> {
		const existing = await this.adminSsoSettings();
		if (existing) return existing;
		const settings: AdminSsoSettingsRecord = {
			id: "instance",
			enabled: 0,
			enforce_sso: 0,
			issuer_url: null,
			client_id: null,
			client_secret_encrypted: null,
			scopes: "openid email profile",
			button_label: "Single sign-on",
			created_at: now,
			updated_at: now,
		};
		try {
			await db`INSERT INTO admin_sso_settings (id,enabled,enforce_sso,issuer_url,client_id,client_secret_encrypted,scopes,button_label,created_at,updated_at) VALUES (${settings.id},${settings.enabled},${settings.enforce_sso},${settings.issuer_url},${settings.client_id},${settings.client_secret_encrypted},${settings.scopes},${settings.button_label},${settings.created_at},${settings.updated_at})`;
		} catch {
			return (await this.adminSsoSettings()) ?? settings;
		}
		return settings;
	},
	async saveAdminSsoSettings(settings: AdminSsoSettingsRecord): Promise<void> {
		assertPrimaryWritable("admin SSO settings");
		const existing = await this.adminSsoSettings();
		await db.begin(async (transaction) => {
			if (existing) {
				await transaction`UPDATE admin_sso_settings SET enabled=${settings.enabled},enforce_sso=${settings.enforce_sso},issuer_url=${settings.issuer_url},client_id=${settings.client_id},client_secret_encrypted=${settings.client_secret_encrypted},scopes=${settings.scopes},button_label=${settings.button_label},updated_at=${settings.updated_at} WHERE id=${settings.id}`;
			} else {
				await transaction`INSERT INTO admin_sso_settings (id,enabled,enforce_sso,issuer_url,client_id,client_secret_encrypted,scopes,button_label,created_at,updated_at) VALUES (${settings.id},${settings.enabled},${settings.enforce_sso},${settings.issuer_url},${settings.client_id},${settings.client_secret_encrypted},${settings.scopes},${settings.button_label},${settings.created_at},${settings.updated_at})`;
			}
			await appendChangelogEntry(transaction, "admin_sso_settings", settings.id, existing ? "update" : "insert", settings);
		});
	},
	async siteSsoSettings(siteId: string): Promise<SiteSsoSettingsRecord | null> {
		const rows = (await db`SELECT * FROM site_sso_settings WHERE site_id=${siteId} LIMIT 1`) as SiteSsoSettingsRecord[];
		return rows[0] ?? null;
	},
	async ensureSiteSsoSettings(siteId: string, now = Date.now()): Promise<SiteSsoSettingsRecord> {
		const existing = await this.siteSsoSettings(siteId);
		if (existing) return existing;
		const settings: SiteSsoSettingsRecord = {
			site_id: siteId,
			enabled: 0,
			enforce_sso: 0,
			issuer_url: null,
			client_id: null,
			client_secret_encrypted: null,
			scopes: "openid email profile",
			button_label: "Single sign-on",
			created_at: now,
			updated_at: now,
		};
		try {
			await db`INSERT INTO site_sso_settings (site_id,enabled,enforce_sso,issuer_url,client_id,client_secret_encrypted,scopes,button_label,created_at,updated_at) VALUES (${settings.site_id},${settings.enabled},${settings.enforce_sso},${settings.issuer_url},${settings.client_id},${settings.client_secret_encrypted},${settings.scopes},${settings.button_label},${settings.created_at},${settings.updated_at})`;
		} catch {
			return (await this.siteSsoSettings(siteId)) ?? settings;
		}
		return settings;
	},
	async saveSiteSsoSettings(settings: SiteSsoSettingsRecord): Promise<void> {
		assertPrimaryWritable("site SSO settings");
		const existing = await this.siteSsoSettings(settings.site_id);
		await db.begin(async (transaction) => {
			if (existing) {
				await transaction`UPDATE site_sso_settings SET enabled=${settings.enabled},enforce_sso=${settings.enforce_sso},issuer_url=${settings.issuer_url},client_id=${settings.client_id},client_secret_encrypted=${settings.client_secret_encrypted},scopes=${settings.scopes},button_label=${settings.button_label},updated_at=${settings.updated_at} WHERE site_id=${settings.site_id}`;
			} else {
				await transaction`INSERT INTO site_sso_settings (site_id,enabled,enforce_sso,issuer_url,client_id,client_secret_encrypted,scopes,button_label,created_at,updated_at) VALUES (${settings.site_id},${settings.enabled},${settings.enforce_sso},${settings.issuer_url},${settings.client_id},${settings.client_secret_encrypted},${settings.scopes},${settings.button_label},${settings.created_at},${settings.updated_at})`;
			}
			await appendChangelogEntry(transaction, "site_sso_settings", settings.site_id, existing ? "update" : "insert", settings);
		});
	},
	async allDnsProviders(): Promise<DnsProviderRecord[]> {
		return (await db`SELECT * FROM dns_providers ORDER BY created_at ASC`) as DnsProviderRecord[];
	},
	async dnsProviderById(id: string): Promise<DnsProviderRecord | null> {
		const rows = (await db`SELECT * FROM dns_providers WHERE id=${id}`) as DnsProviderRecord[];
		return rows[0] ?? null;
	},
	async insertDnsProvider(record: DnsProviderRecord): Promise<void> {
		assertPrimaryWritable("a DNS provider");
		await db.begin(async (transaction) => {
			await transaction`INSERT INTO dns_providers (id,name,type,config_json,created_at,updated_at) VALUES (${record.id},${record.name},${record.type},${record.config_json},${record.created_at},${record.updated_at})`;
			await appendChangelogEntry(transaction, "dns_provider", record.id, "insert", record);
		});
	},
	async updateDnsProviderConfig(id: string, name: string, configJson: string, updatedAt: number): Promise<void> {
		assertPrimaryWritable("a DNS provider");
		await db.begin(async (transaction) => {
			await transaction`UPDATE dns_providers SET name=${name}, config_json=${configJson}, updated_at=${updatedAt} WHERE id=${id}`;
			const rows = (await transaction`SELECT * FROM dns_providers WHERE id=${id}`) as Array<Record<string, unknown>>;
			if (rows[0]) await appendChangelogEntry(transaction, "dns_provider", id, "update", rows[0]);
		});
	},
	async deleteDnsProvider(id: string): Promise<void> {
		assertPrimaryWritable("a DNS provider");
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM dns_providers WHERE id=${id}`;
			await appendChangelogEntry(transaction, "dns_provider", id, "delete", null);
		});
	},
	async sitesUsingDnsProvider(dnsProviderId: string): Promise<SiteRecord[]> {
		return (await db`
			SELECT sites.* FROM sites
			JOIN site_tls_settings ON site_tls_settings.site_id = sites.id
			WHERE site_tls_settings.acme_dns_provider_id = ${dnsProviderId} AND site_tls_settings.acme_challenge_type = 'dns-01'
			ORDER BY sites.name ASC
		`) as SiteRecord[];
	},
	async allFirewallSyncProviders(): Promise<FirewallSyncProviderRecord[]> {
		return (await db`SELECT * FROM firewall_sync_providers ORDER BY created_at ASC`) as FirewallSyncProviderRecord[];
	},
	async firewallSyncProviderById(id: string): Promise<FirewallSyncProviderRecord | null> {
		const rows = (await db`SELECT * FROM firewall_sync_providers WHERE id=${id}`) as FirewallSyncProviderRecord[];
		return rows[0] ?? null;
	},
	async insertFirewallSyncProvider(record: FirewallSyncProviderRecord): Promise<void> {
		assertPrimaryWritable("a firewall sync provider");
		await db.begin(async (transaction) => {
			await transaction`INSERT INTO firewall_sync_providers (id,name,type,enabled,max_entries,config_json,acknowledged_no_whitelist,last_checked_at,last_synced_at,last_sync_status,last_sync_error,last_applied_count,last_applied_hash,created_at,updated_at) VALUES (${record.id},${record.name},${record.type},${record.enabled},${record.max_entries},${record.config_json},${record.acknowledged_no_whitelist},${record.last_checked_at},${record.last_synced_at},${record.last_sync_status},${record.last_sync_error},${record.last_applied_count},${record.last_applied_hash},${record.created_at},${record.updated_at})`;
			await appendChangelogEntry(transaction, "firewall_sync_provider", record.id, "insert", record);
		});
	},
	async updateFirewallSyncProviderConfig(
		id: string,
		name: string,
		enabled: number,
		maxEntries: number,
		configJson: string,
		acknowledgedNoWhitelist: number,
		updatedAt: number,
	): Promise<void> {
		assertPrimaryWritable("a firewall sync provider");
		await db.begin(async (transaction) => {
			await transaction`UPDATE firewall_sync_providers SET name=${name}, enabled=${enabled}, max_entries=${maxEntries}, config_json=${configJson}, acknowledged_no_whitelist=${acknowledgedNoWhitelist}, updated_at=${updatedAt} WHERE id=${id}`;
			const rows = (await transaction`SELECT * FROM firewall_sync_providers WHERE id=${id}`) as Array<Record<string, unknown>>;
			if (rows[0]) await appendChangelogEntry(transaction, "firewall_sync_provider", id, "update", rows[0]);
		});
	},
	async updateFirewallSyncProviderResult(
		id: string,
		checkedAt: number,
		syncedAt: number | null,
		status: FirewallSyncStatus | null,
		error: string | null,
		appliedCount: number,
		appliedHash: string | null,
	): Promise<void> {
		await db`UPDATE firewall_sync_providers SET last_checked_at=${checkedAt}, last_synced_at=${syncedAt}, last_sync_status=${status}, last_sync_error=${error}, last_applied_count=${appliedCount}, last_applied_hash=${appliedHash} WHERE id=${id}`;
	},
	async deleteFirewallSyncProvider(id: string): Promise<void> {
		assertPrimaryWritable("a firewall sync provider");
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM firewall_sync_providers WHERE id=${id}`;
			await appendChangelogEntry(transaction, "firewall_sync_provider", id, "delete", null);
		});
	},
	async activeBannedCidrRows(now: number): Promise<Array<{ network_cidr: string; created_at: number }>> {
		return (await db`
			SELECT network_cidr, created_at FROM ip_rules WHERE action='block' AND (expires_at IS NULL OR expires_at > ${now})
			UNION ALL
			SELECT network_cidr, created_at FROM stream_ip_rules WHERE action='block' AND (expires_at IS NULL OR expires_at > ${now})
		`) as Array<{ network_cidr: string; created_at: number }>;
	},
	async allFirewallSyncWhitelistCidrs(): Promise<FirewallSyncWhitelistCidrRecord[]> {
		return (await db`SELECT * FROM firewall_sync_whitelist_cidrs ORDER BY created_at ASC`) as FirewallSyncWhitelistCidrRecord[];
	},
	async insertFirewallSyncWhitelistCidr(record: FirewallSyncWhitelistCidrRecord): Promise<void> {
		assertPrimaryWritable("a firewall sync whitelist entry");
		await db.begin(async (transaction) => {
			await transaction`INSERT INTO firewall_sync_whitelist_cidrs (id,network_cidr,note,created_at) VALUES (${record.id},${record.network_cidr},${record.note},${record.created_at})`;
			await appendChangelogEntry(transaction, "firewall_sync_whitelist_cidr", record.id, "insert", record);
		});
	},
	async deleteFirewallSyncWhitelistCidr(id: string): Promise<void> {
		assertPrimaryWritable("a firewall sync whitelist entry");
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM firewall_sync_whitelist_cidrs WHERE id=${id}`;
			await appendChangelogEntry(transaction, "firewall_sync_whitelist_cidr", id, "delete", null);
		});
	},

	async applyReplicatedChange(row: ReplicationChangelogRow, localNodeId?: string): Promise<void> {
		const payload = row.payload_json ? (JSON.parse(row.payload_json) as Record<string, unknown>) : null;
		await db.begin(async (transaction) => {
			await applyChangelogRow(transaction, row.entity_type, row.entity_id, payload, localNodeId);
		});
	},
	async changelogSince(seq: number, limit: number): Promise<ReplicationChangelogRow[]> {
		return (await db`SELECT * FROM replication_changelog WHERE seq > ${seq} ORDER BY seq ASC LIMIT ${limit}`) as ReplicationChangelogRow[];
	},
	async latestChangelogSeq(): Promise<number> {
		const rows = (await db`SELECT high_watermark FROM replication_changelog_state WHERE id=1`) as Array<{ high_watermark: number }>;
		return Number(rows[0]?.high_watermark ?? 0);
	},

	async bumpChangelogSequenceTo(minNextSeq: number): Promise<void> {
		if (minNextSeq <= 0) return;
		if (isSqliteDatabase()) {
			const rows = (await db`SELECT seq FROM sqlite_sequence WHERE name='replication_changelog'`) as Array<{ seq: number }>;
			if (rows.length > 0) {
				if (rows[0]!.seq < minNextSeq) await db`UPDATE sqlite_sequence SET seq=${minNextSeq} WHERE name='replication_changelog'`;
			} else {
				await db`INSERT INTO sqlite_sequence (name, seq) VALUES ('replication_changelog', ${minNextSeq})`;
			}
		} else if (isMySqlDatabase()) {
			await db.unsafe(`ALTER TABLE replication_changelog AUTO_INCREMENT = ${Math.trunc(minNextSeq) + 1}`);
		} else {
			await db`SELECT setval(pg_get_serial_sequence('replication_changelog','seq'), (SELECT GREATEST(${minNextSeq}, COALESCE(MAX(seq),0)) FROM replication_changelog), true)`;
		}
		const current = await this.latestChangelogSeq();
		if (current < minNextSeq) await db`UPDATE replication_changelog_state SET high_watermark=${minNextSeq} WHERE id=1`;
	},
	async deleteReplicationChangelogBeforeBatch(cutoff: number, limit: number): Promise<number> {
		if (isMySqlDatabase()) {
			return deletedRowCount(await db`DELETE FROM replication_changelog WHERE created_at < ${cutoff} ORDER BY seq ASC LIMIT ${limit}`);
		}
		if (isSqliteDatabase()) {
			return deletedRowCount(
				await db`DELETE FROM replication_changelog WHERE rowid IN (SELECT rowid FROM replication_changelog WHERE created_at < ${cutoff} ORDER BY seq ASC LIMIT ${limit})`,
			);
		}
		return deletedRowCount(
			await db`DELETE FROM replication_changelog WHERE ctid IN (SELECT ctid FROM replication_changelog WHERE created_at < ${cutoff} ORDER BY seq ASC LIMIT ${limit})`,
		);
	},

	async deleteDeadLetteredRelaysBeforeBatch(cutoff: number, limit: number): Promise<number> {
		if (isMySqlDatabase()) {
			return deletedRowCount(await db`DELETE FROM dead_lettered_relays WHERE occurred_at < ${cutoff} LIMIT ${limit}`);
		}
		if (isSqliteDatabase()) {
			return deletedRowCount(
				await db`DELETE FROM dead_lettered_relays WHERE rowid IN (SELECT rowid FROM dead_lettered_relays WHERE occurred_at < ${cutoff} ORDER BY occurred_at ASC LIMIT ${limit})`,
			);
		}
		return deletedRowCount(
			await db`DELETE FROM dead_lettered_relays WHERE ctid IN (SELECT ctid FROM dead_lettered_relays WHERE occurred_at < ${cutoff} ORDER BY occurred_at ASC LIMIT ${limit})`,
		);
	},
	async replicationCursor(): Promise<number> {
		const rows = (await db`SELECT last_applied_seq FROM replication_cursor WHERE id=1`) as Array<{ last_applied_seq: number }>;
		return rows[0]?.last_applied_seq ?? 0;
	},
	async updateReplicationCursor(seq: number): Promise<void> {
		const rows = (await db`SELECT id FROM replication_cursor WHERE id=1`) as Array<{ id: number }>;
		if (rows.length > 0) {
			await db`UPDATE replication_cursor SET last_applied_seq=${seq} WHERE id=1`;
		} else {
			await db`INSERT INTO replication_cursor (id,last_applied_seq) VALUES (1,${seq})`;
		}
	},

	async haClusterConfigRow(): Promise<HaClusterConfigRow | null> {
		const rows = (await db`SELECT * FROM ha_cluster_config WHERE id=1`) as HaClusterConfigRow[];
		return rows[0] ?? null;
	},
	async insertHaClusterConfig(row: HaClusterConfigInsert): Promise<void> {
		await db`INSERT INTO ha_cluster_config (id,enabled,role,node_name,primary_url,primary_admin_url,shared_token_encrypted,self_admin_url,cluster_epoch,updated_at) VALUES (1,${row.enabled ? 1 : 0},${row.role},${row.nodeName},${row.primaryUrl},${row.primaryAdminUrl},${row.sharedTokenEncrypted},${row.selfAdminUrl},${row.clusterEpoch},${Date.now()})`;
	},
	async updateHaClusterConfig(patch: Partial<HaClusterConfigInsert>): Promise<void> {
		await db.begin(async (transaction) => {
			const rows = (await transaction`SELECT id FROM ha_cluster_config WHERE id=1`) as Array<{ id: number }>;
			if (rows.length === 0) throw new Error("ha_cluster_config has not been seeded yet");

			if (patch.enabled !== undefined) await transaction`UPDATE ha_cluster_config SET enabled=${patch.enabled ? 1 : 0} WHERE id=1`;
			if (patch.role !== undefined) await transaction`UPDATE ha_cluster_config SET role=${patch.role} WHERE id=1`;
			if (patch.nodeName !== undefined) await transaction`UPDATE ha_cluster_config SET node_name=${patch.nodeName} WHERE id=1`;
			if (patch.primaryUrl !== undefined) await transaction`UPDATE ha_cluster_config SET primary_url=${patch.primaryUrl} WHERE id=1`;
			if (patch.primaryAdminUrl !== undefined) await transaction`UPDATE ha_cluster_config SET primary_admin_url=${patch.primaryAdminUrl} WHERE id=1`;
			if (patch.sharedTokenEncrypted !== undefined)
				await transaction`UPDATE ha_cluster_config SET shared_token_encrypted=${patch.sharedTokenEncrypted} WHERE id=1`;
			if (patch.selfAdminUrl !== undefined) await transaction`UPDATE ha_cluster_config SET self_admin_url=${patch.selfAdminUrl} WHERE id=1`;
			if (patch.clusterEpoch !== undefined) await transaction`UPDATE ha_cluster_config SET cluster_epoch=${patch.clusterEpoch} WHERE id=1`;
			await transaction`UPDATE ha_cluster_config SET updated_at=${Date.now()} WHERE id=1`;
		});
	},

	async adoptHaDiscoveredPrimary(patch: {
		primaryUrl: string;
		primaryAdminUrl: string;
		clusterEpoch: number;
	}): Promise<{ adopted: boolean; forcedFreshBootstrap: boolean }> {
		if (!Number.isSafeInteger(patch.clusterEpoch) || patch.clusterEpoch < 0) throw new Error("Invalid discovered HA epoch");
		return await db.begin(async (transaction) => {
			const current = (await transaction`SELECT role FROM ha_cluster_config WHERE id=1`) as Array<{ role: string | null }>;
			const wasPrimary = current[0]?.role === "primary";
			const result =
				await transaction`UPDATE ha_cluster_config SET role='replica',primary_url=${patch.primaryUrl},primary_admin_url=${patch.primaryAdminUrl},cluster_epoch=${patch.clusterEpoch},authority_fenced=0,authority_fence_epoch=NULL,authority_fence_node_id=NULL,authority_fenced_at=NULL,quorum_fenced=0,quorum_fenced_at=NULL,updated_at=${Date.now()} WHERE id=1 AND cluster_epoch <= ${patch.clusterEpoch}`;
			if (deletedRowCount(result) === 0) return { adopted: false, forcedFreshBootstrap: false };
			await transaction`DELETE FROM ha_promotion_intent WHERE id=1`;
			if (wasPrimary) {
				await transaction`UPDATE replication_cursor SET bootstrapped=0 WHERE id=1`;

				await transaction`DELETE FROM session_relay_outbox`;
				await transaction`DELETE FROM replication_changelog`;
				await transaction`UPDATE replication_changelog_state SET high_watermark=0 WHERE id=1`;
			}
			return { adopted: true, forcedFreshBootstrap: wasPrimary };
		});
	},
	async fenceHaPrimaryAuthority(observedEpoch: number, sourceNodeId: string, observedAt: number): Promise<void> {
		if (!Number.isSafeInteger(observedEpoch) || observedEpoch < 0) throw new Error("Invalid observed HA epoch");
		if (!sourceNodeId || sourceNodeId.length > 64) throw new Error("Invalid HA authority-fence source node id");
		await db`UPDATE ha_cluster_config SET authority_fenced=1,authority_fence_epoch=${observedEpoch},authority_fence_node_id=${sourceNodeId},authority_fenced_at=${observedAt},cluster_epoch=CASE WHEN cluster_epoch < ${observedEpoch} THEN ${observedEpoch} ELSE cluster_epoch END,updated_at=${Date.now()} WHERE id=1 AND (authority_fence_epoch IS NULL OR authority_fence_epoch < ${observedEpoch})`;
	},

	async fenceHaPrimaryForElectionTerm(term: number, fencedAt: number): Promise<number | null> {
		if (!Number.isSafeInteger(term) || term < 0) throw new Error("Invalid HA election term");
		return await db.begin(async (transaction) => {
			await transaction`UPDATE ha_cluster_config SET quorum_fenced_at=CASE WHEN quorum_fenced=1 AND cluster_epoch >= ${term} THEN quorum_fenced_at ELSE ${fencedAt} END,cluster_epoch=CASE WHEN cluster_epoch < ${term} THEN ${term} ELSE cluster_epoch END,quorum_fenced=1,updated_at=${Date.now()} WHERE id=1 AND role='primary'`;
			const rows = (await transaction`SELECT cluster_epoch FROM ha_cluster_config WHERE id=1 AND role='primary'`) as Array<{ cluster_epoch: number }>;
			return rows[0] ? toNumber(rows[0].cluster_epoch) : null;
		});
	},

	async adoptHaReplicaElectionTerm(term: number): Promise<number | null> {
		if (!Number.isSafeInteger(term) || term < 0) throw new Error("Invalid HA election term");
		return await db.begin(async (transaction) => {
			await transaction`UPDATE ha_cluster_config SET cluster_epoch=CASE WHEN cluster_epoch < ${term} THEN ${term} ELSE cluster_epoch END,updated_at=${Date.now()} WHERE id=1 AND role='replica'`;
			const rows = (await transaction`SELECT cluster_epoch FROM ha_cluster_config WHERE id=1 AND role='replica'`) as Array<{ cluster_epoch: number }>;
			return rows[0] ? toNumber(rows[0].cluster_epoch) : null;
		});
	},

	async tryPersistVoteGrant(term: number, candidateNodeId: string): Promise<boolean> {
		if (!Number.isSafeInteger(term) || term < 0) throw new Error("Invalid election term");
		if (!candidateNodeId || candidateNodeId.length > 64) throw new Error("Invalid election candidate node id");
		const result =
			await db`UPDATE ha_cluster_config SET cluster_epoch=CASE WHEN cluster_epoch < ${term} THEN ${term} ELSE cluster_epoch END,voted_for_term=${term},voted_for_node_id=${candidateNodeId},updated_at=${Date.now()} WHERE id=1 AND role='replica' AND cluster_epoch <= ${term} AND (voted_for_term IS NULL OR voted_for_term < ${term} OR (voted_for_term=${term} AND voted_for_node_id=${candidateNodeId}))`;
		return deletedRowCount(result) > 0;
	},

	async activateHaElectionWinner(
		term: number,
		candidateNodeId: string,
		expectedPrimaryUrl: string | null,
		expectedPrimaryAdminUrl: string | null,
	): Promise<boolean> {
		if (!Number.isSafeInteger(term) || term < 0) throw new Error("Invalid HA election winner term");
		if (!candidateNodeId || candidateNodeId.length > 64) throw new Error("Invalid HA election winner node id");
		return await db.begin(async (transaction) => {
			const result =
				await transaction`UPDATE ha_cluster_config SET role='primary',primary_url=NULL,primary_admin_url=NULL,cluster_epoch=${term},authority_fenced=0,authority_fence_epoch=NULL,authority_fence_node_id=NULL,authority_fenced_at=NULL,quorum_fenced=0,quorum_fenced_at=NULL,updated_at=${Date.now()} WHERE id=1 AND role='replica' AND cluster_epoch=${term} AND voted_for_term=${term} AND voted_for_node_id=${candidateNodeId} AND COALESCE(primary_url,'')=${expectedPrimaryUrl ?? ""} AND COALESCE(primary_admin_url,'')=${expectedPrimaryAdminUrl ?? ""}`;
			if (deletedRowCount(result) === 0) return false;
			await transaction`DELETE FROM ha_promotion_intent WHERE id=1`;
			return true;
		});
	},

	async setQuorumFence(at: number): Promise<void> {
		await db`UPDATE ha_cluster_config SET quorum_fenced=1,quorum_fenced_at=${at},updated_at=${Date.now()} WHERE id=1`;
	},
	async clearQuorumFence(): Promise<void> {
		await db`UPDATE ha_cluster_config SET quorum_fenced=0,quorum_fenced_at=NULL,updated_at=${Date.now()} WHERE id=1`;
	},
	async haClusterMembers(): Promise<HaClusterMemberRecord[]> {
		return (await db`SELECT * FROM ha_cluster_members WHERE revoked_at IS NULL AND activated_at IS NOT NULL ORDER BY first_seen_at ASC,node_id ASC`) as HaClusterMemberRecord[];
	},
	async haMemberByCredentialHash(credentialHash: string): Promise<HaAuthenticatedMember | null> {
		if (!credentialHash || credentialHash.length !== 64) return null;
		const rows =
			(await db`SELECT node_id,activated_at FROM ha_cluster_members WHERE credential_hash=${credentialHash} AND revoked_at IS NULL LIMIT 1`) as Array<{
				node_id: string;
				activated_at: number | null;
			}>;
		return rows[0] ? { node_id: rows[0].node_id, active: rows[0].activated_at != null } : null;
	},
	async haRevokedClusterNodeIds(): Promise<string[]> {
		const rows = (await db`SELECT node_id FROM ha_cluster_members WHERE revoked_at IS NOT NULL ORDER BY node_id ASC`) as Array<{ node_id: string }>;
		return rows.map((row) => row.node_id);
	},
	async upsertHaClusterMember(member: HaClusterMemberRecord): Promise<void> {
		await db.begin(async (transaction) => {
			const current =
				(await transaction`SELECT first_seen_at,credential_hash,activated_at,revoked_at FROM ha_cluster_members WHERE node_id=${member.node_id} LIMIT 1`) as Array<{
					first_seen_at: number;
					credential_hash: string | null;
					activated_at: number | null;
					revoked_at: number | null;
				}>;
			if (current[0]?.revoked_at != null) throw new Error("This HA node has been revoked and must use a fresh join code before reconnecting");
			const row: HaClusterMemberRecord = {
				...member,
				first_seen_at: current[0]?.first_seen_at ?? member.first_seen_at,
				credential_hash: member.credential_hash ?? current[0]?.credential_hash ?? null,
				activated_at: member.activated_at ?? current[0]?.activated_at ?? Date.now(),
				revoked_at: null,
			};
			if (!row.credential_hash) throw new Error("This HA member has no enrolled node credential");
			if (current.length > 0) {
				await transaction`UPDATE ha_cluster_members SET name=${row.name},version=${row.version},admin_url=${row.admin_url},last_seen_at=${row.last_seen_at},credential_hash=${row.credential_hash},activated_at=${row.activated_at} WHERE node_id=${row.node_id} AND revoked_at IS NULL`;
			} else {
				await transaction`INSERT INTO ha_cluster_members (node_id,name,version,admin_url,first_seen_at,last_seen_at,credential_hash,activated_at,revoked_at) VALUES (${row.node_id},${row.name},${row.version},${row.admin_url},${row.first_seen_at},${row.last_seen_at},${row.credential_hash},${row.activated_at},NULL)`;
			}
			await appendChangelogEntry(transaction, "ha_cluster_member", row.node_id, current.length > 0 ? "update" : "insert", row);
		});
	},

	async deleteHaClusterMember(nodeId: string, preForgetMemberCount: number): Promise<boolean> {
		if (!Number.isSafeInteger(preForgetMemberCount) || preForgetMemberCount < 0) throw new Error("Invalid member count");
		return await db.begin(async (transaction) => {
			const current = (await transaction`SELECT * FROM ha_cluster_members WHERE node_id=${nodeId} AND revoked_at IS NULL LIMIT 1`) as HaClusterMemberRecord[];
			if (current.length === 0) return false;
			const row = { ...current[0]!, credential_hash: null, revoked_at: Date.now() };
			const result =
				await transaction`UPDATE ha_cluster_members SET credential_hash=NULL,revoked_at=${row.revoked_at} WHERE node_id=${nodeId} AND revoked_at IS NULL`;
			if (deletedRowCount(result) === 0) return false;
			await appendChangelogEntry(transaction, "ha_cluster_member", nodeId, "update", row);
			await applyRecentMaxMemberCount(transaction, preForgetMemberCount);
			return true;
		});
	},

	async revertHaClusterMemberActivation(nodeId: string): Promise<void> {
		await db.begin(async (transaction) => {
			const current =
				(await transaction`SELECT * FROM ha_cluster_members WHERE node_id=${nodeId} AND revoked_at IS NULL AND activated_at IS NOT NULL LIMIT 1`) as HaClusterMemberRecord[];
			if (current.length === 0) return;
			const row = { ...current[0]!, activated_at: null };
			await transaction`UPDATE ha_cluster_members SET activated_at=NULL WHERE node_id=${nodeId} AND revoked_at IS NULL`;
			await appendChangelogEntry(transaction, "ha_cluster_member", nodeId, "update", row);
		});
	},

	async updateHaClusterConfigAndResetMembership(patch: HaClusterConfigInsert): Promise<void> {
		await db.begin(async (transaction) => {
			const currentRows = (await transaction`SELECT id FROM ha_cluster_config WHERE id=1`) as Array<{ id: number }>;
			if (currentRows.length === 0) throw new Error("ha_cluster_config has not been seeded yet");
			await transaction`UPDATE ha_cluster_config SET enabled=${patch.enabled ? 1 : 0},role=${patch.role},node_name=${patch.nodeName},primary_url=${patch.primaryUrl},primary_admin_url=${patch.primaryAdminUrl},shared_token_encrypted=${patch.sharedTokenEncrypted},self_admin_url=${patch.selfAdminUrl},cluster_epoch=${patch.clusterEpoch},authority_fenced=0,authority_fence_epoch=NULL,authority_fence_node_id=NULL,authority_fenced_at=NULL,updated_at=${Date.now()} WHERE id=1`;
			await transaction`DELETE FROM ha_cluster_members`;
		});
	},
	async haPromotionIntent(): Promise<HaPromotionIntentRecord | null> {
		const rows = (await db`SELECT * FROM ha_promotion_intent WHERE id=1`) as HaPromotionIntentRecord[];
		return rows[0] ?? null;
	},
	async saveHaPromotionIntent(intent: Omit<HaPromotionIntentRecord, "id">): Promise<void> {
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM ha_promotion_intent WHERE id=1`;
			await transaction`INSERT INTO ha_promotion_intent (id,promotion_id,target_node_id,target_url,target_admin_url,new_epoch,created_at) VALUES (1,${intent.promotion_id},${intent.target_node_id},${intent.target_url},${intent.target_admin_url},${intent.new_epoch},${intent.created_at})`;
		});
	},
	async clearHaPromotionIntent(promotionId: string): Promise<boolean> {
		const result = await db`DELETE FROM ha_promotion_intent WHERE id=1 AND promotion_id=${promotionId}`;
		return deletedRowCount(result) > 0;
	},

	async completeHaPromotionIntent(promotionId: string, patch: { primaryUrl: string; primaryAdminUrl: string; clusterEpoch: number }): Promise<boolean> {
		return await db.begin(async (transaction) => {
			const intents = (await transaction`SELECT promotion_id FROM ha_promotion_intent WHERE id=1`) as Array<{ promotion_id: string }>;
			if (intents[0]?.promotion_id !== promotionId) return false;
			const currentRows = (await transaction`SELECT id FROM ha_cluster_config WHERE id=1`) as Array<{ id: number }>;
			if (currentRows.length === 0) throw new Error("ha_cluster_config has not been seeded yet");
			const result =
				await transaction`UPDATE ha_cluster_config SET role='replica',primary_url=${patch.primaryUrl},primary_admin_url=${patch.primaryAdminUrl},cluster_epoch=${patch.clusterEpoch},updated_at=${Date.now()} WHERE id=1 AND authority_fenced=0`;
			if (deletedRowCount(result) === 0) return false;
			await transaction`DELETE FROM ha_promotion_intent WHERE id=1 AND promotion_id=${promotionId}`;
			return true;
		});
	},

	async createHaEnrollmentCode(codeHash: string, expiresAt: number): Promise<void> {
		const now = Date.now();
		await db`DELETE FROM ha_enrollment_codes WHERE expires_at < ${now}`;
		await db`INSERT INTO ha_enrollment_codes (code_hash,created_at,expires_at,used_at) VALUES (${codeHash},${now},${expiresAt},NULL)`;
	},

	async redeemHaEnrollmentCode(codeHash: string, now: number, member: HaClusterMemberRecord, credentialHash: string): Promise<boolean> {
		if (!member.node_id || member.node_id.length > 64 || !credentialHash || credentialHash.length !== 64) return false;
		return await db.begin(async (transaction) => {
			const result = await transaction`UPDATE ha_enrollment_codes SET used_at=${now} WHERE code_hash=${codeHash} AND used_at IS NULL AND expires_at > ${now}`;
			if (deletedRowCount(result) === 0) return false;
			const existing = (await transaction`SELECT * FROM ha_cluster_members WHERE node_id=${member.node_id} LIMIT 1`) as HaClusterMemberRecord[];
			const row: HaClusterMemberRecord = {
				...member,
				first_seen_at: existing[0]?.first_seen_at ?? member.first_seen_at,
				credential_hash: credentialHash,
				activated_at: null,
				revoked_at: null,
			};
			if (existing[0]) {
				await transaction`UPDATE ha_cluster_members SET name=${row.name},version=${row.version},admin_url=${row.admin_url},last_seen_at=${row.last_seen_at},credential_hash=${credentialHash},activated_at=NULL,revoked_at=NULL WHERE node_id=${row.node_id}`;
			} else {
				await transaction`INSERT INTO ha_cluster_members (node_id,name,version,admin_url,first_seen_at,last_seen_at,credential_hash,activated_at,revoked_at) VALUES (${row.node_id},${row.name},${row.version},${row.admin_url},${row.first_seen_at},${row.last_seen_at},${credentialHash},NULL,NULL)`;
			}
			await appendChangelogEntry(transaction, "ha_cluster_member", row.node_id, existing[0] ? "update" : "insert", row);
			return true;
		});
	},

	async needsBootstrap(): Promise<boolean> {
		const rows = (await db`SELECT bootstrapped FROM replication_cursor WHERE id=1`) as Array<{ bootstrapped: number }>;
		return (rows[0]?.bootstrapped ?? 0) === 0;
	},

	async forceRebootstrap(): Promise<void> {
		await db`UPDATE replication_cursor SET bootstrapped=0 WHERE id=1`;
	},

	async updateHaClusterConfigAndResetReplicationState(patch: HaClusterConfigInsert): Promise<void> {
		await db.begin(async (transaction) => {
			const currentRows = (await transaction`SELECT id FROM ha_cluster_config WHERE id=1`) as Array<{ id: number }>;
			if (currentRows.length === 0) throw new Error("ha_cluster_config has not been seeded yet");
			await transaction`UPDATE ha_cluster_config SET enabled=${patch.enabled ? 1 : 0}, role=${patch.role}, node_name=${patch.nodeName}, primary_url=${patch.primaryUrl}, primary_admin_url=${patch.primaryAdminUrl}, shared_token_encrypted=${patch.sharedTokenEncrypted}, self_admin_url=${patch.selfAdminUrl}, cluster_epoch=${patch.clusterEpoch}, authority_fenced=0, authority_fence_epoch=NULL, authority_fence_node_id=NULL, authority_fenced_at=NULL, updated_at=${Date.now()} WHERE id=1`;
			await transaction`UPDATE replication_cursor SET last_applied_seq=0, bootstrapped=0 WHERE id=1`;
			await transaction`DELETE FROM session_relay_outbox`;
			await transaction`DELETE FROM replication_changelog`;
			await transaction`UPDATE replication_changelog_state SET high_watermark=0 WHERE id=1`;
			await transaction`DELETE FROM ha_cluster_members`;
		});
	},
	async markBootstrapped(seq: number): Promise<void> {
		const rows = (await db`SELECT id FROM replication_cursor WHERE id=1`) as Array<{ id: number }>;
		if (rows.length > 0) {
			await db`UPDATE replication_cursor SET last_applied_seq=${seq}, bootstrapped=1 WHERE id=1`;
		} else {
			await db`INSERT INTO replication_cursor (id,last_applied_seq,bootstrapped) VALUES (1,${seq},1)`;
		}
	},

	async fullSnapshot(): Promise<{ seq: number; rows: ReplicationSnapshotRow[] }> {
		return await withConsistentSnapshot(async (transaction) => {
			const seqRows = (await transaction`SELECT high_watermark FROM replication_changelog_state WHERE id=1`) as Array<{ high_watermark: number }>;
			const seq = Number(seqRows[0]?.high_watermark ?? 0);
			const rows: ReplicationSnapshotRow[] = [];
			await scanSnapshotRows(transaction, config.ha.changelogPageSize, async (row) => void rows.push(row));
			return { seq, rows };
		});
	},

	async streamFullSnapshot(onStart: (seq: number) => Promise<void>, onRow: (row: ReplicationSnapshotRow) => Promise<void>): Promise<void> {
		await withConsistentSnapshot(async (transaction) => {
			const seqRows = (await transaction`SELECT high_watermark FROM replication_changelog_state WHERE id=1`) as Array<{ high_watermark: number }>;
			await onStart(Number(seqRows[0]?.high_watermark ?? 0));
			await scanSnapshotRows(transaction, config.ha.changelogPageSize, onRow);
		});
	},

	async reconcileToSnapshot(rows: ReplicationSnapshotRow[]): Promise<void> {
		await db.begin(async (transaction) => {
			for (const table of SNAPSHOT_TABLES) await transaction.unsafe(`DELETE FROM ${table.table}`);
			for (const row of rows) {
				const payload = JSON.parse(row.payload_json) as Record<string, unknown>;
				await applyChangelogRow(transaction, row.entity_type, row.entity_id, payload);
			}
			await reapplyPendingSessionRelays(transaction);
		});
	},
	async clearSnapshotStaging(snapshotId?: string): Promise<void> {
		if (snapshotId) await db`DELETE FROM replication_snapshot_staging WHERE snapshot_id=${snapshotId}`;
		else await db`DELETE FROM replication_snapshot_staging`;
	},
	async stageSnapshotRows(snapshotId: string, startRow: number, rows: ReplicationSnapshotRow[]): Promise<void> {
		if (rows.length === 0) return;
		await db.begin(async (transaction) => {
			for (let index = 0; index < rows.length; index += 1) {
				const row = rows[index]!;
				await transaction`INSERT INTO replication_snapshot_staging (snapshot_id,row_num,entity_type,entity_id,payload_json) VALUES (${snapshotId},${startRow + index},${row.entity_type},${row.entity_id},${row.payload_json})`;
			}
		});
	},
	async reconcileStagedSnapshot(snapshotId: string): Promise<void> {
		await db.begin(async (transaction) => {
			for (const table of SNAPSHOT_TABLES) await transaction.unsafe(`DELETE FROM ${table.table}`);
			let offset = 0;
			const pageSize = Math.max(1, Math.trunc(config.ha.changelogPageSize));
			for (;;) {
				const rows =
					(await transaction`SELECT entity_type,entity_id,payload_json FROM replication_snapshot_staging WHERE snapshot_id=${snapshotId} ORDER BY row_num ASC LIMIT ${pageSize} OFFSET ${offset}`) as ReplicationSnapshotRow[];
				for (const row of rows) await applyChangelogRow(transaction, row.entity_type, row.entity_id, JSON.parse(row.payload_json) as Record<string, unknown>);
				if (rows.length < pageSize) break;
				offset += rows.length;
			}
			await reapplyPendingSessionRelays(transaction);
			await transaction`DELETE FROM replication_snapshot_staging WHERE snapshot_id=${snapshotId}`;
		});
	},
	async haNodeId(): Promise<string> {
		const rows = (await db`SELECT node_uuid FROM ha_node_identity WHERE id=1`) as Array<{ node_uuid: string }>;
		if (!rows[0]?.node_uuid) throw new Error("HA node identity is missing; run database migrations before starting the mesh");
		return rows[0].node_uuid;
	},

	async applyReplicatedSessionRelay(
		nodeId: string,
		relayId: number,
		entityType: MultiWriterEntityType,
		entityId: string,
		op: "insert" | "update" | "delete",
		payload: object | null,
	): Promise<void> {
		if (!nodeId || nodeId.length > 64) throw new Error("Invalid HA relay node id");
		if (!Number.isSafeInteger(relayId) || relayId <= 0) throw new Error("Invalid HA relay id");
		await db.begin(async (transaction) => {
			let watermarks = (
				isSqliteDatabase()
					? await transaction`SELECT last_relay_id FROM replication_relay_watermarks WHERE node_id=${nodeId}`
					: await transaction`SELECT last_relay_id FROM replication_relay_watermarks WHERE node_id=${nodeId} FOR UPDATE`
			) as Array<{ last_relay_id: number }>;
			if (watermarks.length === 0) {
				await transaction`INSERT INTO replication_relay_watermarks (node_id,last_relay_id,updated_at) VALUES (${nodeId},0,${Date.now()})`;
				watermarks = [{ last_relay_id: 0 }];
			}
			const lastRelayId = Number(watermarks[0]!.last_relay_id);
			if (relayId <= lastRelayId) return;
			const appliedPayload = await applyMultiWriterMutation(transaction, entityType, entityId, op, payload);
			const watermark = { node_id: nodeId, last_relay_id: relayId, updated_at: Date.now() };
			await transaction`UPDATE replication_relay_watermarks SET last_relay_id=${relayId},updated_at=${watermark.updated_at} WHERE node_id=${nodeId}`;
			await appendChangelogEntry(transaction, entityType, entityId, op, {
				__haRelayEvent: RELAY_EVENT_MARKER,
				nodeId,
				relayId,
				op,
				payload: op === "delete" ? null : appliedPayload,
				watermark,
			});
		});
	},
	async pendingSessionRelayRows(limit: number): Promise<SessionRelayRow[]> {
		return (await db`SELECT * FROM session_relay_outbox ORDER BY id ASC LIMIT ${limit}`) as SessionRelayRow[];
	},
	async hasPendingSessionRelay(entityType: MultiWriterEntityType, entityId: string): Promise<boolean> {
		const rows = (await db`SELECT id FROM session_relay_outbox WHERE entity_type=${entityType} AND entity_id=${entityId} LIMIT 1`) as Array<{ id: number }>;
		return rows.length > 0;
	},
	async deleteSessionRelayRows(ids: number[]): Promise<void> {
		if (ids.length === 0) return;
		await db`DELETE FROM session_relay_outbox WHERE id IN ${db(ids)}`;
	},

	async adoptPendingSessionRelaysAsPrimary(nodeId: string): Promise<number> {
		let adopted = 0;
		for (;;) {
			const rows = await this.pendingSessionRelayRows(1);
			const row = rows[0];
			if (!row) return adopted;
			const payload = row.payload_json ? (JSON.parse(row.payload_json) as object) : null;
			await this.applyReplicatedSessionRelay(nodeId, row.id, row.entity_type, row.entity_id, row.op, payload);
			await this.deleteSessionRelayRows([row.id]);
			adopted += 1;
		}
	},

	async deadLetterRelay(
		nodeId: string,
		relayId: number,
		entityType: string,
		entityId: string,
		op: string,
		payload: object | null,
		reason: string,
	): Promise<void> {
		await db`INSERT INTO dead_lettered_relays (id,node_id,relay_id,entity_type,entity_id,op,payload_json,reason,occurred_at) VALUES (${crypto.randomUUID()},${nodeId},${relayId},${entityType},${entityId},${op},${payload === null ? null : JSON.stringify(payload)},${reason},${Date.now()})`;
	},
	async recentDeadLetteredRelays(limit: number): Promise<DeadLetteredRelayRecord[]> {
		return (await db`SELECT * FROM dead_lettered_relays ORDER BY occurred_at DESC LIMIT ${limit}`) as DeadLetteredRelayRecord[];
	},
};

const PRIMARY_WRITE_METHOD_NAMES = [
	"insertSession",
	"authenticateSession",
	"revokeAccessSessionsBySsoSid",
	"revokeSessionsForAccessUser",
	"insertAccessUser",
	"updateAccessUser",
	"deleteAccessUser",
	"assignAccessUser",
	"unassignAccessUser",
	"insertAccessWebauthnCredential",
	"renameAccessWebauthnCredential",
	"deleteAccessWebauthnCredential",
	"deleteAccessWebauthnCredentialsForUserAndSite",
	"deleteAllAccessWebauthnCredentialsForUser",
	"revokeSession",
	"revokeSessionForSite",
	"insertRule",
	"deleteRule",
	"deleteRuleForSite",
	"deleteRulesForSite",
	"insertCountryRule",
	"deleteCountryRuleForSite",
	"insertAsnRule",
	"deleteAsnRuleForSite",
	"insertAdmin",
	"revokeAdminSessionsBySsoSid",
	"deleteAdmin",
	"revokeAdminSessionsForUser",
	"insertAdminUser",
	"updateAdminUser",
	"deleteAdminUserCascade",
	"replaceAdminRecoveryCodes",
	"consumeAdminRecoveryCodeByHash",
	"insertAdminWebauthnCredential",
	"renameAdminWebauthnCredential",
	"deleteAdminWebauthnCredential",
	"deleteAllAdminWebauthnCredentialsForUser",
	"replaceAdminSitePermissions",
	"replaceAdminStreamPermissions",
	"applyReplicatedSessionRelay",
	"upsertHaClusterMember",
	"deleteHaClusterMember",
	"revertHaClusterMemberActivation",
	"redeemHaEnrollmentCode",
	"insertSite",
	"updateSite",
	"deleteSiteCascade",
	"insertOrigin",
	"updateOrigin",
	"deleteOrigin",
	"insertPendingChange",
	"deleteFailedPendingChangesFor",
	"updatePendingChangeStatus",
	"deletePendingChange",
	"insertRoutePolicy",
	"updateRoutePolicy",
	"deleteRoutePolicy",
	"updateAccessSettings",
	"insertRouteIpRule",
	"deleteRouteIpRuleForRoute",
	"insertRouteCountryRule",
	"deleteRouteCountryRuleForRoute",
	"insertRouteAsnRule",
	"deleteRouteAsnRuleForRoute",
	"updateSiteNetworkDefaults",
	"insertStreamRule",
	"deleteStreamRuleForStream",
	"deleteStreamRulesForStream",
	"insertStreamCountryRule",
	"deleteStreamCountryRuleForStream",
	"insertStreamAsnRule",
	"deleteStreamAsnRuleForStream",
	"updateStreamNetworkDefaults",
	"updateStreamProtectionPolicy",
	"updateStreamBandwidthPolicy",
	"updateStreamNotificationPolicy",
	"saveTlsSettings",
	"saveCertificate",
	"updateCertificateAttempt",
	"deleteCertificate",
	"saveAcmeAccount",
	"saveAcmeChallenge",
	"deleteAcmeChallenge",
	"deleteAcmeChallengesForSite",
	"saveStream",
	"deleteStream",
	"saveAdminSsoSettings",
	"saveSiteSsoSettings",
	"insertDnsProvider",
	"updateDnsProviderConfig",
	"deleteDnsProvider",
	"insertFirewallSyncProvider",
	"updateFirewallSyncProviderConfig",
	"deleteFirewallSyncProvider",
	"insertFirewallSyncWhitelistCidr",
	"deleteFirewallSyncWhitelistCidr",
] as const satisfies ReadonlyArray<keyof typeof repository>;

type AsyncRepositoryMethod = (...args: unknown[]) => Promise<unknown>;
const writableRepository = repository as unknown as Record<string, AsyncRepositoryMethod>;
for (const methodName of PRIMARY_WRITE_METHOD_NAMES) {
	const implementation = writableRepository[methodName]!;
	writableRepository[methodName] = async (...args: unknown[]) =>
		await haPrimaryWriteBarrier.runPrimaryWrite(async () => await implementation.apply(repository, args));
}
