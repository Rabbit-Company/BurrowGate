import { config } from "../config.ts";
import { db } from "./client.ts";
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
	ChallengeStepRecord,
	FirewallSyncProviderRecord,
	FirewallSyncStatus,
	FirewallSyncWhitelistCidrRecord,
	IpRuleRecord,
	RequestEventRecord,
	RoutePolicyRecord,
	RouteIpRuleRecord,
	RouteCountryRuleRecord,
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
	since?: number;
	until?: number;
	sortBy: "created_at" | "ip" | "country_code" | "method" | "path" | "status" | "decision" | "cache_status" | "protection_status" | "latency_ms";
	sortDirection: SortDirection;
}

export interface SessionQuery {
	siteId?: string | string[];
	page: number;
	pageSize: number;
	search?: string;
	state?: "active" | "expired" | "revoked";
	countryCode?: string;
	since?: number;
	until?: number;
	sortBy: "last_seen_at" | "created_at" | "expires_at" | "request_count" | "last_ip" | "country_code";
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
	since: number;
	until: number;
	sortBy:
		| "created_at"
		| "event_type"
		| "protocol"
		| "incoming_port"
		| "client_ip"
		| "country_code"
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
		await db`INSERT INTO sites (id,name,public_host,origin_url,origin_signing_secret,ip_extraction_preset,enabled,session_ttl_seconds,challenge_policy_json,default_access_mode,event_retention_days,default_ip_action,default_country_action,error_response_mode,error_html_template,error_json_fields_json,challenge_html_template,health_check_enabled,health_check_path,health_check_interval_seconds,health_check_timeout_ms,health_check_failure_threshold,health_check_recovery_threshold,health_check_failure_mode,health_alert_enabled,health_alert_provider,health_alert_webhook_url,health_alert_webhook_secret,load_balancing_algorithm,load_balancing_affinity,websocket_policy_json,http_policy_json,created_at,updated_at)
		VALUES (${site.id},${site.name},${site.public_host},${site.origin_url},${site.origin_signing_secret},${site.ip_extraction_preset},${site.enabled},${site.session_ttl_seconds},${site.challenge_policy_json},${site.default_access_mode},${site.event_retention_days},${site.default_ip_action},${site.default_country_action},${site.error_response_mode},${site.error_html_template},${site.error_json_fields_json},${site.challenge_html_template},${site.health_check_enabled},${site.health_check_path},${site.health_check_interval_seconds},${site.health_check_timeout_ms},${site.health_check_failure_threshold},${site.health_check_recovery_threshold},${site.health_check_failure_mode},${site.health_alert_enabled},${site.health_alert_provider},${site.health_alert_webhook_url},${site.health_alert_webhook_secret},${site.load_balancing_algorithm},${site.load_balancing_affinity},${site.websocket_policy_json ?? null},${site.http_policy_json ?? null},${site.created_at},${site.updated_at})`;
	},
	async updateSite(site: SiteRecord): Promise<void> {
		await db`UPDATE sites SET name=${site.name}, public_host=${site.public_host}, origin_url=${site.origin_url}, origin_signing_secret=${site.origin_signing_secret}, ip_extraction_preset=${site.ip_extraction_preset}, enabled=${site.enabled}, session_ttl_seconds=${site.session_ttl_seconds}, challenge_policy_json=${site.challenge_policy_json}, default_access_mode=${site.default_access_mode}, event_retention_days=${site.event_retention_days}, default_ip_action=${site.default_ip_action}, default_country_action=${site.default_country_action}, error_response_mode=${site.error_response_mode}, error_html_template=${site.error_html_template}, error_json_fields_json=${site.error_json_fields_json}, challenge_html_template=${site.challenge_html_template}, health_check_enabled=${site.health_check_enabled}, health_check_path=${site.health_check_path}, health_check_interval_seconds=${site.health_check_interval_seconds}, health_check_timeout_ms=${site.health_check_timeout_ms}, health_check_failure_threshold=${site.health_check_failure_threshold}, health_check_recovery_threshold=${site.health_check_recovery_threshold}, health_check_failure_mode=${site.health_check_failure_mode}, health_alert_enabled=${site.health_alert_enabled}, health_alert_provider=${site.health_alert_provider}, health_alert_webhook_url=${site.health_alert_webhook_url}, health_alert_webhook_secret=${site.health_alert_webhook_secret}, load_balancing_algorithm=${site.load_balancing_algorithm}, load_balancing_affinity=${site.load_balancing_affinity}, websocket_policy_json=${site.websocket_policy_json ?? null}, http_policy_json=${site.http_policy_json ?? null}, updated_at=${site.updated_at} WHERE id=${site.id}`;
	},
	async deleteSiteCascade(siteId: string): Promise<void> {
		const flowRows = (await db`SELECT id FROM challenge_flows WHERE site_id=${siteId}`) as Array<{ id: string }>;
		const flowIds = flowRows.map((row) => row.id);
		const stepRows = flowIds.length ? ((await db`SELECT id FROM challenge_steps WHERE flow_id IN ${db(flowIds)}`) as Array<{ id: string }>) : [];
		const stepIds = stepRows.map((row) => row.id);
		const routePolicyRows = (await db`SELECT id FROM route_policies WHERE site_id=${siteId}`) as Array<{ id: string }>;
		const routePolicyIds = routePolicyRows.map((row) => row.id);
		await db.begin(async (transaction) => {
			if (stepIds.length > 0) await transaction`DELETE FROM challenge_consumptions WHERE step_id IN ${transaction(stepIds)}`;
			if (flowIds.length > 0) await transaction`DELETE FROM challenge_steps WHERE flow_id IN ${transaction(flowIds)}`;
			await transaction`DELETE FROM challenge_flows WHERE site_id=${siteId}`;
			if (routePolicyIds.length > 0) {
				await transaction`DELETE FROM route_ip_rules WHERE route_policy_id IN ${transaction(routePolicyIds)}`;
				await transaction`DELETE FROM route_country_rules WHERE route_policy_id IN ${transaction(routePolicyIds)}`;
			}
			await transaction`DELETE FROM route_policies WHERE site_id=${siteId}`;
			await transaction`DELETE FROM access_sessions WHERE site_id=${siteId}`;
			await transaction`DELETE FROM site_access_users WHERE site_id=${siteId}`;
			await transaction`DELETE FROM site_access_settings WHERE site_id=${siteId}`;
			await transaction`DELETE FROM admin_user_site_permissions WHERE site_id=${siteId}`;
			await transaction`DELETE FROM ip_rules WHERE site_id=${siteId}`;
			await transaction`DELETE FROM country_rules WHERE site_id=${siteId}`;
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
		await db`INSERT INTO site_origins (id,site_id,name,origin_url,enabled,draining,priority,weight,health_check_path,is_primary,created_at,updated_at) VALUES (${origin.id},${origin.site_id},${origin.name},${origin.origin_url},${origin.enabled},${origin.draining},${origin.priority},${origin.weight},${origin.health_check_path},${origin.is_primary},${origin.created_at},${origin.updated_at})`;
	},
	async updateOrigin(origin: SiteOriginRecord): Promise<void> {
		await db`UPDATE site_origins SET name=${origin.name}, origin_url=${origin.origin_url}, enabled=${origin.enabled}, draining=${origin.draining}, priority=${origin.priority}, weight=${origin.weight}, health_check_path=${origin.health_check_path}, updated_at=${origin.updated_at} WHERE id=${origin.id} AND site_id=${origin.site_id}`;
	},
	async deleteOrigin(id: string, siteId: string): Promise<void> {
		await db`DELETE FROM site_origins WHERE id=${id} AND site_id=${siteId} AND is_primary=0`;
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
		await db`INSERT INTO pending_changes (id,entity_type,entity_id,changes_json,summary,apply_at,status,attempts,last_error,created_by,created_at,applied_at) VALUES (${change.id},${change.entity_type},${change.entity_id},${change.changes_json},${change.summary},${change.apply_at},${change.status},${change.attempts},${change.last_error},${change.created_by},${change.created_at},${change.applied_at})`;
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
		await db`DELETE FROM pending_changes WHERE entity_type=${entityType} AND entity_id=${entityId} AND status='failed'`;
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
		await db`UPDATE pending_changes SET status=${status}, attempts=${attempts}, apply_at=${applyAt}, last_error=${lastError}, applied_at=${appliedAt} WHERE id=${id}`;
	},
	async deletePendingChange(id: string): Promise<void> {
		await db`DELETE FROM pending_changes WHERE id=${id}`;
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
		await db`INSERT INTO route_policies (id,site_id,name,path_pattern,methods_json,access_mode,challenge_policy_json,rate_limit_enabled,rate_limit_algorithm,rate_limit_window_ms,rate_limit_max,rate_limit_refill_rate,rate_limit_refill_interval_ms,rate_limit_precision_ms,rate_limit_key_mode,rate_limit_key_header,rate_limit_scope,websocket_policy_json,http_policy_json,default_ip_action,default_country_action,priority,enabled,created_at,updated_at)
			VALUES (${policy.id},${policy.site_id},${policy.name},${policy.path_pattern},${policy.methods_json},${policy.access_mode},${policy.challenge_policy_json},${policy.rate_limit_enabled},${policy.rate_limit_algorithm},${policy.rate_limit_window_ms},${policy.rate_limit_max},${policy.rate_limit_refill_rate},${policy.rate_limit_refill_interval_ms},${policy.rate_limit_precision_ms},${policy.rate_limit_key_mode},${policy.rate_limit_key_header},${policy.rate_limit_scope},${policy.websocket_policy_json ?? null},${policy.http_policy_json ?? null},${policy.default_ip_action ?? "inherit"},${policy.default_country_action ?? "inherit"},${policy.priority},${policy.enabled},${policy.created_at},${policy.updated_at})`;
	},
	async updateRoutePolicy(policy: RoutePolicyRecord): Promise<void> {
		await db`UPDATE route_policies SET name=${policy.name}, path_pattern=${policy.path_pattern}, methods_json=${policy.methods_json}, access_mode=${policy.access_mode}, challenge_policy_json=${policy.challenge_policy_json}, rate_limit_enabled=${policy.rate_limit_enabled}, rate_limit_algorithm=${policy.rate_limit_algorithm}, rate_limit_window_ms=${policy.rate_limit_window_ms}, rate_limit_max=${policy.rate_limit_max}, rate_limit_refill_rate=${policy.rate_limit_refill_rate}, rate_limit_refill_interval_ms=${policy.rate_limit_refill_interval_ms}, rate_limit_precision_ms=${policy.rate_limit_precision_ms}, rate_limit_key_mode=${policy.rate_limit_key_mode}, rate_limit_key_header=${policy.rate_limit_key_header}, rate_limit_scope=${policy.rate_limit_scope}, websocket_policy_json=${policy.websocket_policy_json ?? null}, http_policy_json=${policy.http_policy_json ?? null}, default_ip_action=${policy.default_ip_action ?? "inherit"}, default_country_action=${policy.default_country_action ?? "inherit"}, priority=${policy.priority}, enabled=${policy.enabled}, updated_at=${policy.updated_at} WHERE id=${policy.id} AND site_id=${policy.site_id}`;
	},
	async deleteRoutePolicy(id: string, siteId: string): Promise<void> {
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM route_ip_rules WHERE route_policy_id=${id}`;
			await transaction`DELETE FROM route_country_rules WHERE route_policy_id=${id}`;
			await transaction`DELETE FROM route_policies WHERE id=${id} AND site_id=${siteId}`;
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
		await db`INSERT INTO access_sessions (id,site_id,token_hash,initial_ip,last_ip,user_agent_hash,created_at,last_seen_at,expires_at,revoked_at,verification_summary_json,request_count,country_code,access_user_id,authenticated_at,origin_id,sso_sid)
		VALUES (${session.id},${session.site_id},${session.token_hash},${session.initial_ip},${session.last_ip},${session.user_agent_hash},${session.created_at},${session.last_seen_at},${session.expires_at},${session.revoked_at},${session.verification_summary_json},${session.request_count},${session.country_code},${session.access_user_id},${session.authenticated_at},${session.origin_id ?? null},${session.sso_sid ?? null})`;
	},
	async authenticateSession(id: string, siteId: string, userId: string, now: number, ssoSid: string | null = null): Promise<void> {
		await db`UPDATE access_sessions SET access_user_id=${userId}, authenticated_at=${now}, sso_sid=${ssoSid} WHERE id=${id} AND site_id=${siteId} AND revoked_at IS NULL AND expires_at > ${now}`;
	},
	async revokeAccessSessionsBySsoSid(siteId: string, sid: string, now: number): Promise<number> {
		return deletedRowCount(await db`UPDATE access_sessions SET revoked_at=${now} WHERE site_id=${siteId} AND sso_sid=${sid} AND revoked_at IS NULL`);
	},
	async activeAccessSessionForUser(siteId: string, userId: string, now: number): Promise<AccessSessionRecord | null> {
		const rows =
			(await db`SELECT * FROM access_sessions WHERE site_id=${siteId} AND access_user_id=${userId} AND revoked_at IS NULL AND expires_at > ${now} ORDER BY last_seen_at DESC LIMIT 1`) as AccessSessionRecord[];
		return rows[0] ?? null;
	},
	async revokeSessionsForAccessUser(userId: string, now: number, siteId?: string): Promise<void> {
		if (siteId) {
			await db`UPDATE access_sessions SET revoked_at=${now} WHERE access_user_id=${userId} AND site_id=${siteId} AND revoked_at IS NULL`;
			return;
		}
		await db`UPDATE access_sessions SET revoked_at=${now} WHERE access_user_id=${userId} AND revoked_at IS NULL`;
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
		await db`UPDATE site_access_settings SET enabled=${settings.enabled},send_username_to_upstream=${settings.send_username_to_upstream},session_verification_token_hash=${settings.session_verification_token_hash},session_verification_token_created_at=${settings.session_verification_token_created_at},updated_at=${settings.updated_at} WHERE site_id=${settings.site_id}`;
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
		await db`INSERT INTO access_users (id,username,password_hash,enabled,created_at,updated_at,totp_required,totp_secret_encrypted,totp_enrolled_at,api_token_hash,api_token_created_at,sso_subject,auth_source)
		VALUES (${user.id},${user.username},${user.password_hash},${user.enabled},${user.created_at},${user.updated_at},${user.totp_required},${user.totp_secret_encrypted},${user.totp_enrolled_at},${user.api_token_hash},${user.api_token_created_at},${user.sso_subject},${user.auth_source})`;
	},
	async updateAccessUser(user: AccessUserRecord): Promise<void> {
		await db`UPDATE access_users SET username=${user.username},password_hash=${user.password_hash},enabled=${user.enabled},updated_at=${user.updated_at},totp_required=${user.totp_required},totp_secret_encrypted=${user.totp_secret_encrypted},totp_enrolled_at=${user.totp_enrolled_at},api_token_hash=${user.api_token_hash},api_token_created_at=${user.api_token_created_at},sso_subject=${user.sso_subject},auth_source=${user.auth_source} WHERE id=${user.id}`;
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
		await db`DELETE FROM access_users WHERE id=${userId}`;
	},
	async assignAccessUser(siteId: string, userId: string, now = Date.now()): Promise<void> {
		await db`INSERT INTO site_access_users (site_id,user_id,created_at) VALUES (${siteId},${userId},${now})`;
	},
	async unassignAccessUser(siteId: string, userId: string): Promise<void> {
		await db`DELETE FROM site_access_users WHERE site_id=${siteId} AND user_id=${userId}`;
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
		await db`INSERT INTO access_webauthn_credentials (id,user_id,site_id,rp_id,credential_id,credential_id_hash,public_key,sign_count,transports_json,aaguid,device_type,backed_up,nickname,created_at,last_used_at,updated_at)
		VALUES (${record.id},${record.user_id},${record.site_id},${record.rp_id},${record.credential_id},${record.credential_id_hash},${record.public_key},${record.sign_count},${record.transports_json},${record.aaguid},${record.device_type},${record.backed_up},${record.nickname},${record.created_at},${record.last_used_at},${record.updated_at})`;
	},
	async touchAccessWebauthnCredential(id: string, signCount: number, now: number): Promise<void> {
		await db`UPDATE access_webauthn_credentials SET sign_count=${signCount}, last_used_at=${now}, updated_at=${now} WHERE id=${id}`;
	},
	async renameAccessWebauthnCredential(id: string, userId: string, siteId: string, nickname: string | null, now: number): Promise<void> {
		await db`UPDATE access_webauthn_credentials SET nickname=${nickname}, updated_at=${now} WHERE id=${id} AND user_id=${userId} AND site_id=${siteId}`;
	},
	async deleteAccessWebauthnCredential(id: string, userId: string, siteId: string): Promise<void> {
		await db`DELETE FROM access_webauthn_credentials WHERE id=${id} AND user_id=${userId} AND site_id=${siteId}`;
	},
	async deleteAccessWebauthnCredentialsForUserAndSite(userId: string, siteId: string): Promise<void> {
		await db`DELETE FROM access_webauthn_credentials WHERE user_id=${userId} AND site_id=${siteId}`;
	},
	async deleteAllAccessWebauthnCredentialsForUser(userId: string): Promise<void> {
		await db`DELETE FROM access_webauthn_credentials WHERE user_id=${userId}`;
	},
	async touchSession(id: string, ip: string, now: number): Promise<void> {
		await db`UPDATE access_sessions SET last_ip=${ip}, last_seen_at=${now}, request_count=request_count+1 WHERE id=${id}`;
	},
	async revokeSession(id: string, now: number): Promise<void> {
		await db`UPDATE access_sessions SET revoked_at=${now} WHERE id=${id} AND revoked_at IS NULL`;
	},
	async revokeSessionForSite(id: string, siteId: string, now: number): Promise<void> {
		await db`UPDATE access_sessions SET revoked_at=${now} WHERE id=${id} AND site_id=${siteId} AND revoked_at IS NULL`;
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
      WHERE 1=1 ${siteFilter} ${searchFilter} ${countryFilter} ${stateFilter} ${rangeFilter}
    `) as Array<{ count: number | string }>;
		const items = (await db`
      SELECT s.*, au.username AS access_username FROM access_sessions s LEFT JOIN access_users au ON au.id = s.access_user_id
      WHERE 1=1 ${siteFilter} ${searchFilter} ${countryFilter} ${stateFilter} ${rangeFilter}
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
		await db`INSERT INTO ip_rules (id,site_id,network_cidr,action,reason,created_at,expires_at,rule_id) VALUES (${rule.id},${rule.site_id},${rule.network_cidr},${rule.action},${rule.reason},${rule.created_at},${rule.expires_at},${rule.rule_id})`;
	},
	async deleteRule(id: string): Promise<void> {
		await db`DELETE FROM ip_rules WHERE id=${id}`;
	},
	async deleteRuleForSite(id: string, siteId: string): Promise<void> {
		await db`DELETE FROM ip_rules WHERE id=${id} AND site_id=${siteId}`;
	},
	async deleteRulesForSite(ids: string[], siteId: string): Promise<number> {
		let deleted = 0;
		for (const id of ids) {
			await db`DELETE FROM ip_rules WHERE id=${id} AND site_id=${siteId}`;
			deleted += 1;
		}
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
		await db`INSERT INTO country_rules (id,site_id,country_code,action,reason,created_at,expires_at) VALUES (${rule.id},${rule.site_id},${rule.country_code},${rule.action},${rule.reason},${rule.created_at},${rule.expires_at})`;
	},
	async deleteCountryRuleForSite(id: string, siteId: string): Promise<void> {
		await db`DELETE FROM country_rules WHERE id=${id} AND site_id=${siteId}`;
	},
	async routeIpRules(routePolicyId: string): Promise<RouteIpRuleRecord[]> {
		return (await db`SELECT * FROM route_ip_rules WHERE route_policy_id=${routePolicyId} ORDER BY created_at DESC`) as RouteIpRuleRecord[];
	},
	async insertRouteIpRule(rule: RouteIpRuleRecord): Promise<void> {
		await db`INSERT INTO route_ip_rules (id,route_policy_id,network_cidr,action,reason,created_at,expires_at) VALUES (${rule.id},${rule.route_policy_id},${rule.network_cidr},${rule.action},${rule.reason},${rule.created_at},${rule.expires_at})`;
	},
	async deleteRouteIpRuleForRoute(id: string, routePolicyId: string): Promise<void> {
		await db`DELETE FROM route_ip_rules WHERE id=${id} AND route_policy_id=${routePolicyId}`;
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
		await db`INSERT INTO route_country_rules (id,route_policy_id,country_code,action,reason,created_at,expires_at) VALUES (${rule.id},${rule.route_policy_id},${rule.country_code},${rule.action},${rule.reason},${rule.created_at},${rule.expires_at})`;
	},
	async deleteRouteCountryRuleForRoute(id: string, routePolicyId: string): Promise<void> {
		await db`DELETE FROM route_country_rules WHERE id=${id} AND route_policy_id=${routePolicyId}`;
	},
	async updateSiteNetworkDefaults(siteId: string, defaultIpAction: string, defaultCountryAction: string, updatedAt: number): Promise<void> {
		await db`UPDATE sites SET default_ip_action=${defaultIpAction}, default_country_action=${defaultCountryAction}, updated_at=${updatedAt} WHERE id=${siteId}`;
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
		await db`INSERT INTO stream_ip_rules (id,stream_id,network_cidr,action,reason,created_at,expires_at) VALUES (${rule.id},${rule.stream_id},${rule.network_cidr},${rule.action},${rule.reason},${rule.created_at},${rule.expires_at})`;
	},
	async deleteStreamRuleForStream(id: string, streamId: string): Promise<void> {
		await db`DELETE FROM stream_ip_rules WHERE id=${id} AND stream_id=${streamId}`;
	},
	async deleteStreamRulesForStream(ids: string[], streamId: string): Promise<number> {
		let deleted = 0;
		for (const id of ids) {
			await db`DELETE FROM stream_ip_rules WHERE id=${id} AND stream_id=${streamId}`;
			deleted += 1;
		}
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
		await db`INSERT INTO stream_country_rules (id,stream_id,country_code,action,reason,created_at,expires_at) VALUES (${rule.id},${rule.stream_id},${rule.country_code},${rule.action},${rule.reason},${rule.created_at},${rule.expires_at})`;
	},
	async deleteStreamCountryRuleForStream(id: string, streamId: string): Promise<void> {
		await db`DELETE FROM stream_country_rules WHERE id=${id} AND stream_id=${streamId}`;
	},
	async updateStreamNetworkDefaults(streamId: string, defaultIpAction: string, defaultCountryAction: string, updatedAt: number): Promise<void> {
		await db`UPDATE streams SET default_ip_action=${defaultIpAction}, default_country_action=${defaultCountryAction}, updated_at=${updatedAt} WHERE id=${streamId}`;
	},
	async updateStreamProtectionPolicy(streamId: string, protectionPolicyJson: string, updatedAt: number): Promise<void> {
		await db`UPDATE streams SET protection_policy_json=${protectionPolicyJson}, updated_at=${updatedAt} WHERE id=${streamId}`;
	},
	async updateStreamBandwidthPolicy(streamId: string, bandwidthPolicyJson: string, updatedAt: number): Promise<void> {
		await db`UPDATE streams SET bandwidth_policy_json=${bandwidthPolicyJson}, updated_at=${updatedAt} WHERE id=${streamId}`;
	},
	async updateStreamNotificationPolicy(streamId: string, notificationPolicyJson: string, updatedAt: number): Promise<void> {
		await db`UPDATE streams SET notification_policy_json=${notificationPolicyJson}, updated_at=${updatedAt} WHERE id=${streamId}`;
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
		await db`INSERT INTO request_events (id,site_id,session_id,ip,method,path,status,decision,latency_ms,country_code,origin_id,cache_status,protection_status,protection_rule_id,protection_category,protection_severity,protection_ruleset_id,protection_ruleset_version,protection_matches_json,access_username,referer,referer_host,request_body,request_body_truncated,request_content_type,created_at) VALUES (${event.id},${event.site_id},${event.session_id},${event.ip},${event.method},${event.path},${event.status},${event.decision},${event.latency_ms},${event.country_code},${event.origin_id ?? null},${event.cache_status},${event.protection_status},${event.protection_rule_id},${event.protection_category},${event.protection_severity},${event.protection_ruleset_id},${event.protection_ruleset_version},${event.protection_matches_json},${event.access_username ?? null},${event.referer ?? null},${event.referer_host ?? null},${event.request_body ?? null},${event.request_body_truncated ?? null},${event.request_content_type ?? null},${event.created_at})`;
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
      WHERE 1=1 ${siteFilter} ${searchFilter} ${countryFilter} ${decisionFilter} ${cacheStatusFilter} ${protectionStatusFilter} ${originFilter} ${methodFilter} ${statusFilter} ${sinceFilter} ${untilFilter}
    `) as Array<{ count: number | string }>;
		const items = (await db`
      SELECT id,site_id,session_id,ip,method,path,status,decision,latency_ms,country_code,origin_id,cache_status,
        protection_status,protection_rule_id,protection_category,protection_severity,protection_ruleset_id,protection_ruleset_version,
        protection_matches_json,access_username,referer,referer_host,created_at,
        (CASE WHEN request_body IS NOT NULL THEN 1 ELSE 0 END) AS has_request_body,
        (CASE WHEN response_body IS NOT NULL THEN 1 ELSE 0 END) AS has_response_body
      FROM request_events
      WHERE 1=1 ${siteFilter} ${searchFilter} ${countryFilter} ${decisionFilter} ${cacheStatusFilter} ${protectionStatusFilter} ${originFilter} ${methodFilter} ${statusFilter} ${sinceFilter} ${untilFilter}
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
		const requests = toNumber(eventStats?.requests);
		const errors = toNumber(eventStats?.errors);
		const cacheHits = toNumber(eventStats?.cache_hits);
		const cacheMisses = toNumber(eventStats?.cache_misses);
		return {
			activeSessions: toNumber(sessions?.count),
			activeRules: toNumber(ipRules?.count) + toNumber(countryRules?.count),
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
			created_at: now,
			updated_at: now,
		};
		try {
			await db`INSERT INTO site_tls_settings (site_id,mode,force_https,acme_email,acme_directory_url,created_at,updated_at) VALUES (${settings.site_id},${settings.mode},${settings.force_https},${settings.acme_email},${settings.acme_directory_url},${settings.created_at},${settings.updated_at})`;
		} catch {
			return (await this.tlsSettings(siteId)) ?? settings;
		}
		return settings;
	},
	async saveTlsSettings(settings: SiteTlsSettingsRecord): Promise<void> {
		const existing = await this.tlsSettings(settings.site_id);
		if (existing) {
			await db`UPDATE site_tls_settings SET mode=${settings.mode},force_https=${settings.force_https},acme_email=${settings.acme_email},acme_directory_url=${settings.acme_directory_url},updated_at=${settings.updated_at} WHERE site_id=${settings.site_id}`;
		} else {
			await db`INSERT INTO site_tls_settings (site_id,mode,force_https,acme_email,acme_directory_url,created_at,updated_at) VALUES (${settings.site_id},${settings.mode},${settings.force_https},${settings.acme_email},${settings.acme_directory_url},${settings.created_at},${settings.updated_at})`;
		}
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
		const existing = await this.certificateBySite(certificate.site_id);
		if (existing) {
			await db`UPDATE certificates SET id=${certificate.id},source=${certificate.source},status=${certificate.status},primary_domain=${certificate.primary_domain},alternative_names_json=${certificate.alternative_names_json},certificate_pem=${certificate.certificate_pem},encrypted_private_key=${certificate.encrypted_private_key},issuer=${certificate.issuer},serial_number=${certificate.serial_number},valid_from=${certificate.valid_from},expires_at=${certificate.expires_at},next_renewal_at=${certificate.next_renewal_at},last_attempt_at=${certificate.last_attempt_at},last_error=${certificate.last_error},updated_at=${certificate.updated_at} WHERE site_id=${certificate.site_id}`;
		} else {
			await db`INSERT INTO certificates (id,site_id,source,status,primary_domain,alternative_names_json,certificate_pem,encrypted_private_key,issuer,serial_number,valid_from,expires_at,next_renewal_at,last_attempt_at,last_error,created_at,updated_at) VALUES (${certificate.id},${certificate.site_id},${certificate.source},${certificate.status},${certificate.primary_domain},${certificate.alternative_names_json},${certificate.certificate_pem},${certificate.encrypted_private_key},${certificate.issuer},${certificate.serial_number},${certificate.valid_from},${certificate.expires_at},${certificate.next_renewal_at},${certificate.last_attempt_at},${certificate.last_error},${certificate.created_at},${certificate.updated_at})`;
		}
	},
	async updateCertificateAttempt(siteId: string, attemptedAt: number, error: string | null): Promise<void> {
		await db`UPDATE certificates SET last_attempt_at=${attemptedAt},last_error=${error},updated_at=${attemptedAt} WHERE site_id=${siteId}`;
	},
	async deleteCertificate(siteId: string): Promise<void> {
		await db`DELETE FROM certificates WHERE site_id=${siteId}`;
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
		if (existing) {
			await db`UPDATE acme_accounts SET email=${account.email},account_url=${account.account_url},encrypted_account_key=${account.encrypted_account_key},terms_accepted_at=${account.terms_accepted_at},updated_at=${account.updated_at} WHERE directory_url=${account.directory_url}`;
		} else {
			await db`INSERT INTO acme_accounts (id,directory_url,email,account_url,encrypted_account_key,terms_accepted_at,created_at,updated_at) VALUES (${account.id},${account.directory_url},${account.email},${account.account_url},${account.encrypted_account_key},${account.terms_accepted_at},${account.created_at},${account.updated_at})`;
		}
	},
	async acmeChallenge(token: string, hostname: string): Promise<AcmeHttpChallengeRecord | null> {
		const rows =
			(await db`SELECT * FROM acme_http_challenges WHERE token=${token} AND hostname=${hostname} AND expires_at > ${Date.now()} LIMIT 1`) as AcmeHttpChallengeRecord[];
		return rows[0] ?? null;
	},
	async saveAcmeChallenge(challenge: AcmeHttpChallengeRecord): Promise<void> {
		await db`DELETE FROM acme_http_challenges WHERE token=${challenge.token}`;
		await db`INSERT INTO acme_http_challenges (token,site_id,hostname,key_authorization,created_at,expires_at) VALUES (${challenge.token},${challenge.site_id},${challenge.hostname},${challenge.key_authorization},${challenge.created_at},${challenge.expires_at})`;
	},
	async deleteAcmeChallenge(token: string): Promise<void> {
		await db`DELETE FROM acme_http_challenges WHERE token=${token}`;
	},
	async deleteAcmeChallengesForSite(siteId: string): Promise<void> {
		await db`DELETE FROM acme_http_challenges WHERE site_id=${siteId}`;
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
		});
	},
	async deleteStream(id: string): Promise<void> {
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM stream_bindings WHERE stream_id=${id}`;
			await transaction`DELETE FROM stream_events WHERE stream_id=${id}`;
			await transaction`DELETE FROM stream_bandwidth_minutes WHERE stream_id=${id}`;
			await transaction`DELETE FROM stream_origin_latency_minutes WHERE stream_id=${id}`;
			await transaction`DELETE FROM stream_ip_rules WHERE stream_id=${id}`;
			await transaction`DELETE FROM stream_country_rules WHERE stream_id=${id}`;
			await transaction`DELETE FROM admin_user_stream_permissions WHERE stream_id=${id}`;
			await transaction`DELETE FROM notification_outbox WHERE stream_id=${id}`;
			await transaction`DELETE FROM notification_events WHERE stream_id=${id}`;
			await transaction`DELETE FROM pending_changes WHERE entity_type='stream' AND entity_id=${id}`;
			await transaction`DELETE FROM streams WHERE id=${id}`;
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
				await transaction`INSERT INTO stream_events (id,stream_id,incoming_port,connection_id,protocol,event_type,client_ip,client_port,country_code,reason,error,protection_rule_id,client_to_upstream_bytes,upstream_to_client_bytes,duration_ms,username,created_at) VALUES (${event.id},${event.stream_id},${event.incoming_port},${event.connection_id},${event.protocol},${event.event_type},${event.client_ip},${event.client_port},${event.country_code},${event.reason},${event.error},${event.protection_rule_id},${event.client_to_upstream_bytes},${event.upstream_to_client_bytes},${event.duration_ms},${event.username},${event.created_at})`;
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
		const searchFilter = pattern
			? db`AND (LOWER(COALESCE(client_ip,'')) LIKE ${pattern} OR LOWER(COALESCE(reason,'')) LIKE ${pattern} OR LOWER(COALESCE(error,'')) LIKE ${pattern} OR LOWER(COALESCE(username,'')) LIKE ${pattern} OR connection_id=${exactSearch} OR protection_rule_id=${exactSearchUpper})`
			: db``;
		const offset = (query.page - 1) * query.pageSize;
		const order = db.unsafe(`${query.sortBy} ${query.sortDirection.toUpperCase()}`);
		const [countRow] =
			(await db`SELECT COUNT(*) AS count FROM stream_events WHERE created_at >= ${query.since} AND created_at <= ${query.until} ${streamFilter} ${protocolFilter} ${typeFilter} ${countryFilter} ${searchFilter}`) as Array<{
				count: number | string;
			}>;
		const items =
			(await db`SELECT * FROM stream_events WHERE created_at >= ${query.since} AND created_at <= ${query.until} ${streamFilter} ${protocolFilter} ${typeFilter} ${countryFilter} ${searchFilter} ORDER BY ${order} LIMIT ${query.pageSize} OFFSET ${offset}`) as StreamEventRecord[];
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
		return {
			connections: toNumber(events?.connections),
			disconnections: toNumber(events?.disconnections),
			errors: toNumber(events?.errors),
			blocked: toNumber(events?.blocked),
			uniqueIps: toNumber(events?.unique_ips),
			clientToUpstreamBytes: toNumber(bandwidth?.client_to_upstream_bytes),
			upstreamToClientBytes: toNumber(bandwidth?.upstream_to_client_bytes),
			countries: [...countries.values()].sort((a, b) => b.bytes - a.bytes || b.connections - a.connections),
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
		// Duration is only known once a connection closes, so both series are derived from
		// 'disconnected' rows: the disconnect bucket uses created_at directly, and the connect
		// bucket is reconstructed as created_at - duration_ms (the connection's open time).
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
		await db`INSERT INTO admin_sessions (id,token_hash,username,user_id,created_at,expires_at,last_seen_at,sso_sid) VALUES (${session.id},${session.token_hash},${session.username},${session.user_id},${session.created_at},${session.expires_at},${session.last_seen_at},${session.sso_sid ?? null})`;
	},
	async revokeAdminSessionsBySsoSid(sid: string): Promise<number> {
		return deletedRowCount(await db`DELETE FROM admin_sessions WHERE sso_sid=${sid}`);
	},
	async touchAdmin(id: string, now: number): Promise<void> {
		await db`UPDATE admin_sessions SET last_seen_at=${now} WHERE id=${id}`;
	},
	async deleteAdmin(hash: string): Promise<void> {
		await db`DELETE FROM admin_sessions WHERE token_hash=${hash}`;
	},
	async revokeAdminSessionsForUser(userId: string): Promise<void> {
		await db`DELETE FROM admin_sessions WHERE user_id=${userId}`;
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
		await db`INSERT INTO admin_users (id,username,password_hash,role,totp_secret_encrypted,totp_enrolled_at,must_enroll_totp,enabled,created_at,updated_at,created_by_user_id,sso_subject,auth_source)
		VALUES (${user.id},${user.username},${user.password_hash},${user.role},${user.totp_secret_encrypted},${user.totp_enrolled_at},${user.must_enroll_totp},${user.enabled},${user.created_at},${user.updated_at},${user.created_by_user_id},${user.sso_subject},${user.auth_source})`;
	},
	async updateAdminUser(user: AdminUserRecord): Promise<void> {
		await db`UPDATE admin_users SET username=${user.username},password_hash=${user.password_hash},role=${user.role},totp_secret_encrypted=${user.totp_secret_encrypted},totp_enrolled_at=${user.totp_enrolled_at},must_enroll_totp=${user.must_enroll_totp},enabled=${user.enabled},updated_at=${user.updated_at},sso_subject=${user.sso_subject},auth_source=${user.auth_source} WHERE id=${user.id}`;
	},
	async adminUserBySsoSubject(subject: string): Promise<AdminUserRecord | null> {
		const rows = (await db`SELECT * FROM admin_users WHERE sso_subject=${subject} LIMIT 1`) as AdminUserRecord[];
		return rows[0] ?? null;
	},
	async deleteAdminUserCascade(userId: string): Promise<void> {
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM admin_user_site_permissions WHERE user_id=${userId}`;
			await transaction`DELETE FROM admin_user_stream_permissions WHERE user_id=${userId}`;
			await transaction`DELETE FROM admin_recovery_codes WHERE user_id=${userId}`;
			await transaction`DELETE FROM admin_webauthn_credentials WHERE user_id=${userId}`;
			await transaction`DELETE FROM admin_sessions WHERE user_id=${userId}`;
			await transaction`DELETE FROM admin_users WHERE id=${userId}`;
		});
	},
	async replaceAdminRecoveryCodes(userId: string, codes: AdminRecoveryCodeRecord[]): Promise<void> {
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM admin_recovery_codes WHERE user_id=${userId}`;
			for (const code of codes) {
				await transaction`INSERT INTO admin_recovery_codes (id,user_id,code_hash,created_at,used_at) VALUES (${code.id},${code.user_id},${code.code_hash},${code.created_at},${code.used_at})`;
			}
		});
	},
	async unusedAdminRecoveryCodeCount(userId: string): Promise<number> {
		const rows = (await db`SELECT id FROM admin_recovery_codes WHERE user_id=${userId} AND used_at IS NULL`) as Array<{ id: string }>;
		return rows.length;
	},
	async consumeAdminRecoveryCodeByHash(userId: string, codeHash: string, now: number): Promise<boolean> {
		const result = await db`UPDATE admin_recovery_codes SET used_at=${now} WHERE user_id=${userId} AND code_hash=${codeHash} AND used_at IS NULL`;
		return deletedRowCount(result) > 0;
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
		await db`INSERT INTO admin_webauthn_credentials (id,user_id,rp_id,credential_id,credential_id_hash,public_key,sign_count,transports_json,aaguid,device_type,backed_up,nickname,created_at,last_used_at,updated_at)
		VALUES (${record.id},${record.user_id},${record.rp_id},${record.credential_id},${record.credential_id_hash},${record.public_key},${record.sign_count},${record.transports_json},${record.aaguid},${record.device_type},${record.backed_up},${record.nickname},${record.created_at},${record.last_used_at},${record.updated_at})`;
	},
	async touchAdminWebauthnCredential(id: string, signCount: number, now: number): Promise<void> {
		await db`UPDATE admin_webauthn_credentials SET sign_count=${signCount}, last_used_at=${now}, updated_at=${now} WHERE id=${id}`;
	},
	async renameAdminWebauthnCredential(id: string, userId: string, nickname: string | null, now: number): Promise<void> {
		await db`UPDATE admin_webauthn_credentials SET nickname=${nickname}, updated_at=${now} WHERE id=${id} AND user_id=${userId}`;
	},
	async deleteAdminWebauthnCredential(id: string, userId: string): Promise<void> {
		await db`DELETE FROM admin_webauthn_credentials WHERE id=${id} AND user_id=${userId}`;
	},
	async deleteAllAdminWebauthnCredentialsForUser(userId: string): Promise<void> {
		await db`DELETE FROM admin_webauthn_credentials WHERE user_id=${userId}`;
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
			await transaction`DELETE FROM admin_user_site_permissions WHERE user_id=${userId}`;
			for (const permission of permissions) {
				await transaction`INSERT INTO admin_user_site_permissions (user_id,site_id,level,created_at,updated_at) VALUES (${userId},${permission.siteId},${permission.level},${now},${now})`;
			}
		});
	},
	async replaceAdminStreamPermissions(
		userId: string,
		permissions: Array<{ streamId: string; level: Exclude<AdminAccessLevel, "none"> }>,
		now = Date.now(),
	): Promise<void> {
		await db.begin(async (transaction) => {
			await transaction`DELETE FROM admin_user_stream_permissions WHERE user_id=${userId}`;
			for (const permission of permissions) {
				await transaction`INSERT INTO admin_user_stream_permissions (user_id,stream_id,level,created_at,updated_at) VALUES (${userId},${permission.streamId},${permission.level},${now},${now})`;
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
		const existing = await this.adminSsoSettings();
		if (existing) {
			await db`UPDATE admin_sso_settings SET enabled=${settings.enabled},enforce_sso=${settings.enforce_sso},issuer_url=${settings.issuer_url},client_id=${settings.client_id},client_secret_encrypted=${settings.client_secret_encrypted},scopes=${settings.scopes},button_label=${settings.button_label},updated_at=${settings.updated_at} WHERE id=${settings.id}`;
		} else {
			await db`INSERT INTO admin_sso_settings (id,enabled,enforce_sso,issuer_url,client_id,client_secret_encrypted,scopes,button_label,created_at,updated_at) VALUES (${settings.id},${settings.enabled},${settings.enforce_sso},${settings.issuer_url},${settings.client_id},${settings.client_secret_encrypted},${settings.scopes},${settings.button_label},${settings.created_at},${settings.updated_at})`;
		}
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
		const existing = await this.siteSsoSettings(settings.site_id);
		if (existing) {
			await db`UPDATE site_sso_settings SET enabled=${settings.enabled},enforce_sso=${settings.enforce_sso},issuer_url=${settings.issuer_url},client_id=${settings.client_id},client_secret_encrypted=${settings.client_secret_encrypted},scopes=${settings.scopes},button_label=${settings.button_label},updated_at=${settings.updated_at} WHERE site_id=${settings.site_id}`;
		} else {
			await db`INSERT INTO site_sso_settings (site_id,enabled,enforce_sso,issuer_url,client_id,client_secret_encrypted,scopes,button_label,created_at,updated_at) VALUES (${settings.site_id},${settings.enabled},${settings.enforce_sso},${settings.issuer_url},${settings.client_id},${settings.client_secret_encrypted},${settings.scopes},${settings.button_label},${settings.created_at},${settings.updated_at})`;
		}
	},
	async allFirewallSyncProviders(): Promise<FirewallSyncProviderRecord[]> {
		return (await db`SELECT * FROM firewall_sync_providers ORDER BY created_at ASC`) as FirewallSyncProviderRecord[];
	},
	async firewallSyncProviderById(id: string): Promise<FirewallSyncProviderRecord | null> {
		const rows = (await db`SELECT * FROM firewall_sync_providers WHERE id=${id}`) as FirewallSyncProviderRecord[];
		return rows[0] ?? null;
	},
	async insertFirewallSyncProvider(record: FirewallSyncProviderRecord): Promise<void> {
		await db`INSERT INTO firewall_sync_providers (id,name,type,enabled,max_entries,config_json,acknowledged_no_whitelist,last_checked_at,last_synced_at,last_sync_status,last_sync_error,last_applied_count,last_applied_hash,created_at,updated_at) VALUES (${record.id},${record.name},${record.type},${record.enabled},${record.max_entries},${record.config_json},${record.acknowledged_no_whitelist},${record.last_checked_at},${record.last_synced_at},${record.last_sync_status},${record.last_sync_error},${record.last_applied_count},${record.last_applied_hash},${record.created_at},${record.updated_at})`;
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
		await db`UPDATE firewall_sync_providers SET name=${name}, enabled=${enabled}, max_entries=${maxEntries}, config_json=${configJson}, acknowledged_no_whitelist=${acknowledgedNoWhitelist}, updated_at=${updatedAt} WHERE id=${id}`;
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
		await db`DELETE FROM firewall_sync_providers WHERE id=${id}`;
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
		await db`INSERT INTO firewall_sync_whitelist_cidrs (id,network_cidr,note,created_at) VALUES (${record.id},${record.network_cidr},${record.note},${record.created_at})`;
	},
	async deleteFirewallSyncWhitelistCidr(id: string): Promise<void> {
		await db`DELETE FROM firewall_sync_whitelist_cidrs WHERE id=${id}`;
	},
};
