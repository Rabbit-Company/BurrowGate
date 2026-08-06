import { config } from "../config.ts";
import { db } from "./client.ts";
import type {
	IpRuleAction,
	AccessUserRecord,
	AccessSessionRecord,
	AcmeAccountRecord,
	AcmeHttpChallengeRecord,
	AdminSessionRecord,
	CertificateEventRecord,
	CertificateRecord,
	ChallengeFlowRecord,
	CountryRuleRecord,
	ChallengeStepRecord,
	IpRuleRecord,
	RequestEventRecord,
	RoutePolicyRecord,
	SiteRecord,
	SiteAccessSettingsRecord,
	SiteTlsSettingsRecord,
	BandwidthMinuteRecord,
	StreamRecord,
	StreamEventRecord,
	StreamBandwidthMinuteRecord,
	StreamProtocol,
	StreamEventType,
	OriginHealthStatusRecord,
	OriginHealthEventRecord,
	HealthAlertOutboxRecord,
	SiteOriginRecord,
	OriginBackendHealthStatusRecord,
	OriginBackendHealthEventRecord,
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
	siteId?: string;
	originId?: string;
	page: number;
	pageSize: number;
	search?: string;
	decision?: string;
	cacheStatus?: "hit" | "miss" | "bypass";
	method?: string;
	statusGroup?: "1xx" | "2xx" | "3xx" | "4xx" | "5xx";
	countryCode?: string;
	since?: number;
	until?: number;
	sortBy: "created_at" | "ip" | "country_code" | "method" | "path" | "status" | "decision" | "cache_status" | "latency_ms";
	sortDirection: SortDirection;
}

export interface SessionQuery {
	siteId?: string;
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

export interface BandwidthIpQuery {
	siteId: string;
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
	streamId?: string;
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
		| "client_to_upstream_bytes"
		| "upstream_to_client_bytes";
	sortDirection: SortDirection;
}

export interface StreamBandwidthQuery {
	streamId?: string;
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
		return (await db`SELECT * FROM sites ORDER BY enabled DESC, name ASC`) as SiteRecord[];
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
		await db.begin(async (transaction) => {
			if (stepIds.length > 0) await transaction`DELETE FROM challenge_consumptions WHERE step_id IN ${transaction(stepIds)}`;
			if (flowIds.length > 0) await transaction`DELETE FROM challenge_steps WHERE flow_id IN ${transaction(flowIds)}`;
			await transaction`DELETE FROM challenge_flows WHERE site_id=${siteId}`;
			await transaction`DELETE FROM route_policies WHERE site_id=${siteId}`;
			await transaction`DELETE FROM access_sessions WHERE site_id=${siteId}`;
			await transaction`DELETE FROM site_access_users WHERE site_id=${siteId}`;
			await transaction`DELETE FROM site_access_settings WHERE site_id=${siteId}`;
			await transaction`DELETE FROM ip_rules WHERE site_id=${siteId}`;
			await transaction`DELETE FROM country_rules WHERE site_id=${siteId}`;
			await transaction`DELETE FROM request_events WHERE site_id=${siteId}`;
			await transaction`DELETE FROM bandwidth_minutes WHERE site_id=${siteId}`;
			await transaction`DELETE FROM acme_http_challenges WHERE site_id=${siteId}`;
			await transaction`DELETE FROM certificate_events WHERE site_id=${siteId}`;
			await transaction`DELETE FROM health_alert_outbox WHERE site_id=${siteId}`;
			await transaction`DELETE FROM origin_backend_health_events WHERE site_id=${siteId}`;
			await transaction`DELETE FROM origin_backend_health_status WHERE site_id=${siteId}`;
			await transaction`DELETE FROM origin_health_events WHERE site_id=${siteId}`;
			await transaction`DELETE FROM origin_health_status WHERE site_id=${siteId}`;
			await transaction`DELETE FROM site_origins WHERE site_id=${siteId}`;
			await transaction`DELETE FROM certificates WHERE site_id=${siteId}`;
			await transaction`DELETE FROM site_tls_settings WHERE site_id=${siteId}`;
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
	async insertHealthAlert(alert: HealthAlertOutboxRecord): Promise<void> {
		await db`INSERT INTO health_alert_outbox (id,site_id,event_id,event_type,payload_json,status,attempts,next_attempt_at,last_error,created_at,delivered_at) VALUES (${alert.id},${alert.site_id},${alert.event_id},${alert.event_type},${alert.payload_json},${alert.status},${alert.attempts},${alert.next_attempt_at},${alert.last_error},${alert.created_at},${alert.delivered_at})`;
	},
	async pendingHealthAlerts(now: number, limit: number): Promise<HealthAlertOutboxRecord[]> {
		return (await db`SELECT * FROM health_alert_outbox WHERE status='pending' AND next_attempt_at <= ${now} ORDER BY next_attempt_at ASC LIMIT ${limit}`) as HealthAlertOutboxRecord[];
	},
	async healthAlerts(siteId: string, limit = 25): Promise<HealthAlertOutboxRecord[]> {
		return (await db`SELECT * FROM health_alert_outbox WHERE site_id=${siteId} ORDER BY created_at DESC LIMIT ${limit}`) as HealthAlertOutboxRecord[];
	},
	async updateHealthAlertDelivery(
		id: string,
		status: "pending" | "delivered" | "failed",
		attempts: number,
		nextAttemptAt: number,
		error: string | null,
		deliveredAt: number | null,
	): Promise<void> {
		await db`UPDATE health_alert_outbox SET status=${status}, attempts=${attempts}, next_attempt_at=${nextAttemptAt}, last_error=${error}, delivered_at=${deliveredAt} WHERE id=${id}`;
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
		await db`INSERT INTO route_policies (id,site_id,name,path_pattern,methods_json,access_mode,challenge_policy_json,rate_limit_enabled,rate_limit_algorithm,rate_limit_window_ms,rate_limit_max,rate_limit_refill_rate,rate_limit_refill_interval_ms,rate_limit_precision_ms,rate_limit_key_mode,rate_limit_key_header,rate_limit_scope,websocket_policy_json,http_policy_json,priority,enabled,created_at,updated_at)
			VALUES (${policy.id},${policy.site_id},${policy.name},${policy.path_pattern},${policy.methods_json},${policy.access_mode},${policy.challenge_policy_json},${policy.rate_limit_enabled},${policy.rate_limit_algorithm},${policy.rate_limit_window_ms},${policy.rate_limit_max},${policy.rate_limit_refill_rate},${policy.rate_limit_refill_interval_ms},${policy.rate_limit_precision_ms},${policy.rate_limit_key_mode},${policy.rate_limit_key_header},${policy.rate_limit_scope},${policy.websocket_policy_json ?? null},${policy.http_policy_json ?? null},${policy.priority},${policy.enabled},${policy.created_at},${policy.updated_at})`;
	},
	async updateRoutePolicy(policy: RoutePolicyRecord): Promise<void> {
		await db`UPDATE route_policies SET name=${policy.name}, path_pattern=${policy.path_pattern}, methods_json=${policy.methods_json}, access_mode=${policy.access_mode}, challenge_policy_json=${policy.challenge_policy_json}, rate_limit_enabled=${policy.rate_limit_enabled}, rate_limit_algorithm=${policy.rate_limit_algorithm}, rate_limit_window_ms=${policy.rate_limit_window_ms}, rate_limit_max=${policy.rate_limit_max}, rate_limit_refill_rate=${policy.rate_limit_refill_rate}, rate_limit_refill_interval_ms=${policy.rate_limit_refill_interval_ms}, rate_limit_precision_ms=${policy.rate_limit_precision_ms}, rate_limit_key_mode=${policy.rate_limit_key_mode}, rate_limit_key_header=${policy.rate_limit_key_header}, rate_limit_scope=${policy.rate_limit_scope}, websocket_policy_json=${policy.websocket_policy_json ?? null}, http_policy_json=${policy.http_policy_json ?? null}, priority=${policy.priority}, enabled=${policy.enabled}, updated_at=${policy.updated_at} WHERE id=${policy.id} AND site_id=${policy.site_id}`;
	},
	async deleteRoutePolicy(id: string, siteId: string): Promise<void> {
		await db`DELETE FROM route_policies WHERE id=${id} AND site_id=${siteId}`;
	},
	async sessionByHash(siteId: string, hash: string): Promise<AccessSessionRecord | null> {
		const rows = (await db`SELECT * FROM access_sessions WHERE site_id=${siteId} AND token_hash=${hash} LIMIT 1`) as AccessSessionRecord[];
		return rows[0] ?? null;
	},
	async insertSession(session: AccessSessionRecord): Promise<void> {
		await db`INSERT INTO access_sessions (id,site_id,token_hash,initial_ip,last_ip,user_agent_hash,created_at,last_seen_at,expires_at,revoked_at,verification_summary_json,request_count,country_code,access_user_id,authenticated_at,origin_id)
		VALUES (${session.id},${session.site_id},${session.token_hash},${session.initial_ip},${session.last_ip},${session.user_agent_hash},${session.created_at},${session.last_seen_at},${session.expires_at},${session.revoked_at},${session.verification_summary_json},${session.request_count},${session.country_code},${session.access_user_id},${session.authenticated_at},${session.origin_id ?? null})`;
	},
	async authenticateSession(id: string, siteId: string, userId: string, now: number): Promise<void> {
		await db`UPDATE access_sessions SET access_user_id=${userId}, authenticated_at=${now} WHERE id=${id} AND site_id=${siteId} AND revoked_at IS NULL AND expires_at > ${now}`;
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
			created_at: now,
			updated_at: now,
		};
		try {
			await db`INSERT INTO site_access_settings (site_id,enabled,send_username_to_upstream,created_at,updated_at) VALUES (${siteId},0,0,${now},${now})`;
		} catch {
			return (await this.accessSettings(siteId)) ?? settings;
		}
		return settings;
	},
	async updateAccessSettings(settings: SiteAccessSettingsRecord): Promise<void> {
		await db`UPDATE site_access_settings SET enabled=${settings.enabled},send_username_to_upstream=${settings.send_username_to_upstream},updated_at=${settings.updated_at} WHERE site_id=${settings.site_id}`;
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
		await db`INSERT INTO access_users (id,username,password_hash,enabled,created_at,updated_at) VALUES (${user.id},${user.username},${user.password_hash},${user.enabled},${user.created_at},${user.updated_at})`;
	},
	async updateAccessUser(user: AccessUserRecord): Promise<void> {
		await db`UPDATE access_users SET username=${user.username},password_hash=${user.password_hash},enabled=${user.enabled},updated_at=${user.updated_at} WHERE id=${user.id}`;
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
	async touchSession(id: string, ip: string, now: number): Promise<void> {
		await db`UPDATE access_sessions SET last_ip=${ip}, last_seen_at=${now}, request_count=request_count+1 WHERE id=${id}`;
	},
	async revokeSession(id: string, now: number): Promise<void> {
		await db`UPDATE access_sessions SET revoked_at=${now} WHERE id=${id} AND revoked_at IS NULL`;
	},
	async revokeSessionForSite(id: string, siteId: string, now: number): Promise<void> {
		await db`UPDATE access_sessions SET revoked_at=${now} WHERE id=${id} AND site_id=${siteId} AND revoked_at IS NULL`;
	},
	async pagedSessions(query: SessionQuery): Promise<PageResult<AccessSessionRecord>> {
		const pattern = searchPattern(query.search);
		const now = Date.now();
		const siteFilter = query.siteId ? db`AND site_id=${query.siteId}` : db``;
		const searchFilter = pattern
			? db`AND (LOWER(id) LIKE ${pattern} OR LOWER(initial_ip) LIKE ${pattern} OR LOWER(last_ip) LIKE ${pattern} OR LOWER(user_agent_hash) LIKE ${pattern} OR LOWER(COALESCE(country_code,'ZZ')) LIKE ${pattern})`
			: db``;
		const countryFilter = query.countryCode ? db`AND COALESCE(country_code, 'ZZ')=${query.countryCode}` : db``;
		const stateFilter =
			query.state === "active"
				? db`AND revoked_at IS NULL AND expires_at > ${now}`
				: query.state === "expired"
					? db`AND revoked_at IS NULL AND expires_at <= ${now}`
					: query.state === "revoked"
						? db`AND revoked_at IS NOT NULL`
						: db``;
		const rangeFilter =
			query.since !== undefined && query.until !== undefined
				? db`AND created_at <= ${query.until} AND (expires_at >= ${query.since} OR last_seen_at >= ${query.since} OR (revoked_at IS NOT NULL AND revoked_at >= ${query.since}))`
				: db``;
		const order = db.unsafe(`${query.sortBy} ${query.sortDirection.toUpperCase()}`);
		const offset = (query.page - 1) * query.pageSize;
		const [countRow] = (await db`
      SELECT COUNT(*) AS count FROM access_sessions
      WHERE 1=1 ${siteFilter} ${searchFilter} ${countryFilter} ${stateFilter} ${rangeFilter}
    `) as Array<{ count: number | string }>;
		const items = (await db`
      SELECT * FROM access_sessions
      WHERE 1=1 ${siteFilter} ${searchFilter} ${countryFilter} ${stateFilter} ${rangeFilter}
      ORDER BY ${order}
      LIMIT ${query.pageSize} OFFSET ${offset}
    `) as AccessSessionRecord[];
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
		await db`INSERT INTO ip_rules (id,site_id,network_cidr,action,reason,created_at,expires_at) VALUES (${rule.id},${rule.site_id},${rule.network_cidr},${rule.action},${rule.reason},${rule.created_at},${rule.expires_at})`;
	},
	async deleteRule(id: string): Promise<void> {
		await db`DELETE FROM ip_rules WHERE id=${id}`;
	},
	async deleteRuleForSite(id: string, siteId: string): Promise<void> {
		await db`DELETE FROM ip_rules WHERE id=${id} AND site_id=${siteId}`;
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
	async updateSiteNetworkDefaults(siteId: string, defaultIpAction: string, defaultCountryAction: string, updatedAt: number): Promise<void> {
		await db`UPDATE sites SET default_ip_action=${defaultIpAction}, default_country_action=${defaultCountryAction}, updated_at=${updatedAt} WHERE id=${siteId}`;
	},
	async insertEvent(event: RequestEventRecord): Promise<void> {
		await db`INSERT INTO request_events (id,site_id,session_id,ip,method,path,status,decision,latency_ms,country_code,origin_id,cache_status,created_at) VALUES (${event.id},${event.site_id},${event.session_id},${event.ip},${event.method},${event.path},${event.status},${event.decision},${event.latency_ms},${event.country_code},${event.origin_id ?? null},${event.cache_status},${event.created_at})`;
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
	async pagedEvents(query: EventQuery): Promise<PageResult<RequestEventRecord>> {
		const pattern = searchPattern(query.search);
		const siteFilter = query.siteId ? db`AND site_id=${query.siteId}` : db``;
		const searchFilter = pattern
			? db`AND (LOWER(ip) LIKE ${pattern} OR LOWER(method) LIKE ${pattern} OR LOWER(path) LIKE ${pattern} OR LOWER(decision) LIKE ${pattern} OR LOWER(COALESCE(cache_status,'')) LIKE ${pattern} OR LOWER(COALESCE(session_id,'')) LIKE ${pattern} OR LOWER(COALESCE(country_code,'ZZ')) LIKE ${pattern})`
			: db``;
		const decisionFilter = query.decision ? db`AND decision=${query.decision}` : db``;
		const cacheStatusFilter = query.cacheStatus ? db`AND cache_status=${query.cacheStatus}` : db``;
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
      WHERE 1=1 ${siteFilter} ${searchFilter} ${countryFilter} ${decisionFilter} ${cacheStatusFilter} ${originFilter} ${methodFilter} ${statusFilter} ${sinceFilter} ${untilFilter}
    `) as Array<{ count: number | string }>;
		const items = (await db`
      SELECT * FROM request_events
      WHERE 1=1 ${siteFilter} ${searchFilter} ${countryFilter} ${decisionFilter} ${cacheStatusFilter} ${originFilter} ${methodFilter} ${statusFilter} ${sinceFilter} ${untilFilter}
      ORDER BY ${order}
      LIMIT ${query.pageSize} OFFSET ${offset}
    `) as RequestEventRecord[];
		return pageResult(items, countRow?.count, query.page, query.pageSize);
	},
	async trafficMetrics(
		siteId: string | undefined,
		since: number,
		until: number,
		bucketMs: number,
	): Promise<{
		series: TrafficMetricPoint[];
		decisions: Array<{ decision: string; count: number }>;
		methods: Array<{ method: string; count: number }>;
	}> {
		const siteFilter = siteId ? db`AND site_id=${siteId}` : db``;
		const bucketExpression =
			config.databaseUrl.startsWith("mysql://") || config.databaseUrl.startsWith("mariadb://")
				? db`FLOOR(created_at / ${bucketMs})`
				: db`CAST(created_at / ${bucketMs} AS BIGINT)`;
		const rows = (await db`
      SELECT
        ${bucketExpression} * ${bucketMs} AS bucket,
        COUNT(*) AS requests,
        SUM(CASE WHEN decision IN ('blocked','route-blocked','websocket-policy-denied','rate-limited','request-limited') THEN 1 ELSE 0 END) AS blocked,
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
		siteId: string | undefined,
		since: number,
		until: number,
		bucketMs: number,
	): Promise<{
		series: CacheMetricPoint[];
		totals: { hits: number; misses: number; bypasses: number; hitRatio: number; originRequestsAvoided: number };
		topPaths: Array<{ path: string; hits: number; misses: number; bypasses: number; hitRatio: number }>;
	}> {
		const siteFilter = siteId ? db`AND site_id=${siteId}` : db``;
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
	async bandwidthMetrics(
		siteId: string | undefined,
		since: number,
		until: number,
		bucketMs: number,
	): Promise<{
		series: Array<{ bucket: number; clientUpload: number; clientDownload: number; upstreamUpload: number; upstreamDownload: number }>;
		protocols: Array<{ protocol: string; clientBytes: number; upstreamBytes: number }>;
	}> {
		const siteFilter = siteId ? db`AND site_id=${siteId}` : db``;
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
		const searchFilter = pattern ? db`AND (LOWER(ip) LIKE ${pattern} OR LOWER(country_code) LIKE ${pattern})` : db``;
		const countryFilter = query.countryCode ? db`AND country_code=${query.countryCode}` : db``;
		const protocolFilter = query.protocol ? db`AND protocol=${query.protocol}` : db``;
		const order = db.unsafe(`${query.sortBy} ${query.sortDirection.toUpperCase()}`);
		const offset = (query.page - 1) * query.pageSize;
		const [countRow] = (await db`
      SELECT COUNT(*) AS count FROM (
        SELECT ip, country_code
        FROM bandwidth_minutes
        WHERE site_id=${query.siteId} AND bucket_start >= ${minuteSince} AND bucket_start <= ${query.until}
          AND ip <> '__other__' ${searchFilter} ${countryFilter} ${protocolFilter}
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
      WHERE site_id=${query.siteId} AND bucket_start >= ${minuteSince} AND bucket_start <= ${query.until}
        AND ip <> '__other__' ${searchFilter} ${countryFilter} ${protocolFilter}
      GROUP BY ip, country_code
      ORDER BY ${order}
      LIMIT ${query.pageSize} OFFSET ${offset}
    `) as BandwidthIpRow[];
		return pageResult(items, countRow?.count, query.page, query.pageSize);
	},
	async sessionMetrics(
		siteId: string | undefined,
		since: number,
		until: number,
		bucketMs: number,
	): Promise<{
		series: Array<{ bucket: number; created: number; expired: number; revoked: number; active: number }>;
		states: Array<{ label: string; count: number }>;
	}> {
		const siteFilter = siteId ? db`AND site_id=${siteId}` : db``;
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
        SUM(CASE WHEN decision IN ('route-blocked','websocket-policy-denied','request-limited') THEN 1 ELSE 0 END) AS blocked
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
	async overview(siteId: string | undefined, since: number, until: number): Promise<Record<string, number>> {
		const now = Date.now();
		const sessionSiteFilter = siteId ? db`AND site_id=${siteId}` : db``;
		const eventSiteFilter = siteId ? db`AND site_id=${siteId}` : db``;
		const ruleSiteFilter = siteId ? db`AND site_id=${siteId}` : db``;
		const flowSiteFilter = siteId ? db`AND site_id=${siteId}` : db``;
		const [sessions] =
			(await db`SELECT COUNT(*) AS count FROM access_sessions WHERE revoked_at IS NULL AND expires_at > ${now} ${sessionSiteFilter}`) as Array<{
				count: number | string;
			}>;
		const [eventStats] = (await db`
      SELECT
        COUNT(*) AS requests,
        SUM(CASE WHEN decision IN ('blocked','route-blocked','websocket-policy-denied','rate-limited','request-limited') THEN 1 ELSE 0 END) AS blocked,
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
	async geoMetrics(
		siteId: string | undefined,
		since: number,
		until: number,
	): Promise<{
		requests: Array<{ countryCode: string; count: number }>;
		sessions: Array<{ countryCode: string; count: number }>;
		bandwidth: Array<{ countryCode: string; count: number }>;
	}> {
		const siteFilter = siteId ? db`AND site_id=${siteId}` : db``;
		const minuteSince = Math.floor(since / 60_000) * 60_000;
		const requestRows = (await db`
      SELECT COALESCE(country_code, 'ZZ') AS country_code, COUNT(*) AS count
      FROM request_events
      WHERE created_at >= ${since} AND created_at <= ${until} ${siteFilter}
      GROUP BY COALESCE(country_code, 'ZZ')
      ORDER BY count DESC
    `) as Array<{ country_code: string; count: number | string }>;
		const sessionRows = (await db`
      SELECT COALESCE(country_code, 'ZZ') AS country_code, COUNT(*) AS count
      FROM access_sessions
      WHERE created_at >= ${since} AND created_at <= ${until} ${siteFilter}
      GROUP BY COALESCE(country_code, 'ZZ')
      ORDER BY count DESC
    `) as Array<{ country_code: string; count: number | string }>;
		const bandwidthRows = (await db`
      SELECT COALESCE(country_code, 'ZZ') AS country_code,
        COALESCE(SUM(client_received_bytes + client_sent_bytes),0) AS count
      FROM bandwidth_minutes
      WHERE bucket_start >= ${minuteSince} AND bucket_start <= ${until} ${siteFilter}
      GROUP BY COALESCE(country_code, 'ZZ')
      ORDER BY count DESC
    `) as Array<{ country_code: string; count: number | string }>;
		return {
			requests: requestRows.map((row) => ({ countryCode: row.country_code, count: toNumber(row.count) })),
			sessions: sessionRows.map((row) => ({ countryCode: row.country_code, count: toNumber(row.count) })),
			bandwidth: bandwidthRows.map((row) => ({ countryCode: row.country_code, count: toNumber(row.count) })),
		};
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
	async deleteHealthAlertsBeforeForSiteBatch(siteId: string, cutoff: number, limit: number): Promise<number> {
		const rows =
			(await db`SELECT id FROM health_alert_outbox WHERE site_id=${siteId} AND created_at < ${cutoff} AND status <> 'pending' ORDER BY created_at ASC LIMIT ${limit}`) as Array<{
				id: string;
			}>;
		if (rows.length === 0) return 0;
		await db`DELETE FROM health_alert_outbox WHERE id IN ${db(rows.map((row) => row.id))}`;
		return rows.length;
	},
	async deleteExpiredAdminSessionsBatch(now: number, limit: number): Promise<number> {
		const rows = (await db`SELECT id FROM admin_sessions WHERE expires_at <= ${now} ORDER BY expires_at ASC LIMIT ${limit}`) as Array<{ id: string }>;
		if (rows.length === 0) return 0;
		await db`DELETE FROM admin_sessions WHERE id IN ${db(rows.map((row) => row.id))}`;
		return rows.length;
	},
	async allStreams(): Promise<StreamRecord[]> {
		return (await db`SELECT * FROM streams ORDER BY incoming_port ASC`) as StreamRecord[];
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
				await transaction`UPDATE streams SET incoming_port=${stream.incoming_port},forward_host=${stream.forward_host},forward_port=${stream.forward_port},tcp_enabled=${stream.tcp_enabled},udp_enabled=${stream.udp_enabled},certificate_id=${stream.certificate_id},event_retention_days=${stream.event_retention_days},updated_at=${stream.updated_at} WHERE id=${stream.id}`;
			} else {
				await transaction`INSERT INTO streams (id,incoming_port,forward_host,forward_port,tcp_enabled,udp_enabled,certificate_id,event_retention_days,created_at,updated_at) VALUES (${stream.id},${stream.incoming_port},${stream.forward_host},${stream.forward_port},${stream.tcp_enabled},${stream.udp_enabled},${stream.certificate_id},${stream.event_retention_days},${stream.created_at},${stream.updated_at})`;
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
				await transaction`INSERT INTO stream_events (id,stream_id,incoming_port,connection_id,protocol,event_type,client_ip,client_port,country_code,reason,error,client_to_upstream_bytes,upstream_to_client_bytes,created_at) VALUES (${event.id},${event.stream_id},${event.incoming_port},${event.connection_id},${event.protocol},${event.event_type},${event.client_ip},${event.client_port},${event.country_code},${event.reason},${event.error},${event.client_to_upstream_bytes},${event.upstream_to_client_bytes},${event.created_at})`;
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
	async pagedStreamEvents(query: StreamEventQuery): Promise<PageResult<StreamEventRecord>> {
		const pattern = searchPattern(query.search);
		const streamFilter = query.streamId ? db`AND stream_id=${query.streamId}` : db``;
		const protocolFilter = query.protocol ? db`AND protocol=${query.protocol}` : db``;
		const typeFilter = query.eventType ? db`AND event_type=${query.eventType}` : db``;
		const countryFilter = query.countryCode ? db`AND COALESCE(country_code,'ZZ')=${query.countryCode}` : db``;
		const searchFilter = pattern
			? db`AND (LOWER(COALESCE(client_ip,'')) LIKE ${pattern} OR LOWER(COALESCE(reason,'')) LIKE ${pattern} OR LOWER(COALESCE(error,'')) LIKE ${pattern} OR LOWER(COALESCE(connection_id,'')) LIKE ${pattern})`
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
		const streamFilter = query.streamId ? db`AND stream_id=${query.streamId}` : db``;
		const protocolFilter = query.protocol ? db`AND protocol=${query.protocol}` : db``;
		const countryFilter = query.countryCode ? db`AND country_code=${query.countryCode}` : db``;
		const searchFilter = pattern ? db`AND (LOWER(ip) LIKE ${pattern} OR LOWER(country_code) LIKE ${pattern})` : db``;
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
		streamId: string | undefined,
		since: number,
		until: number,
	): Promise<{
		connections: number;
		disconnections: number;
		errors: number;
		uniqueIps: number;
		clientToUpstreamBytes: number;
		upstreamToClientBytes: number;
		countries: Array<{ countryCode: string; connections: number; bytes: number }>;
	}> {
		const eventStreamFilter = streamId ? db`AND stream_id=${streamId}` : db``;
		const bandwidthStreamFilter = streamId ? db`AND stream_id=${streamId}` : db``;
		const minuteSince = Math.floor(since / 60_000) * 60_000;
		const [events] =
			(await db`SELECT SUM(CASE WHEN event_type='connected' THEN 1 ELSE 0 END) AS connections,SUM(CASE WHEN event_type='disconnected' THEN 1 ELSE 0 END) AS disconnections,SUM(CASE WHEN event_type IN ('upstream-error','listener-error') THEN 1 ELSE 0 END) AS errors,COUNT(DISTINCT CASE WHEN event_type='connected' THEN client_ip ELSE NULL END) AS unique_ips FROM stream_events WHERE created_at >= ${since} AND created_at <= ${until} ${eventStreamFilter}`) as Array<
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
		const connectionsByCountry = new Map(connectionCountries.map((row) => [row.country_code, toNumber(row.connections)]));
		const countries = new Map<string, { countryCode: string; connections: number; bytes: number }>();
		for (const row of countryRows)
			countries.set(row.country_code, {
				countryCode: row.country_code,
				connections: connectionsByCountry.get(row.country_code) ?? 0,
				bytes: toNumber(row.bytes),
			});
		for (const row of connectionCountries)
			if (!countries.has(row.country_code))
				countries.set(row.country_code, { countryCode: row.country_code, connections: toNumber(row.connections), bytes: 0 });
		return {
			connections: toNumber(events?.connections),
			disconnections: toNumber(events?.disconnections),
			errors: toNumber(events?.errors),
			uniqueIps: toNumber(events?.unique_ips),
			clientToUpstreamBytes: toNumber(bandwidth?.client_to_upstream_bytes),
			upstreamToClientBytes: toNumber(bandwidth?.upstream_to_client_bytes),
			countries: [...countries.values()].sort((a, b) => b.bytes - a.bytes || b.connections - a.connections),
		};
	},
	async streamMetrics(
		streamId: string | undefined,
		since: number,
		until: number,
		bucketMs: number,
	): Promise<{
		series: Array<{
			bucket: number;
			connected: number;
			disconnected: number;
			errors: number;
			clientToUpstreamBytes: number;
			upstreamToClientBytes: number;
		}>;
	}> {
		const eventStreamFilter = streamId ? db`AND stream_id=${streamId}` : db``;
		const bandwidthStreamFilter = streamId ? db`AND stream_id=${streamId}` : db``;
		const eventBucket = metricBucketExpression("created_at", bucketMs);
		const bandwidthBucket = metricBucketExpression("bucket_start", bucketMs);
		const minuteSince = Math.floor(since / 60_000) * 60_000;
		const eventRows = (await db`
      SELECT ${eventBucket} * ${bucketMs} AS bucket,
        SUM(CASE WHEN event_type='connected' THEN 1 ELSE 0 END) AS connected,
        SUM(CASE WHEN event_type='disconnected' THEN 1 ELSE 0 END) AS disconnected,
        SUM(CASE WHEN event_type IN ('upstream-error','listener-error') THEN 1 ELSE 0 END) AS errors
      FROM stream_events
      WHERE created_at >= ${since} AND created_at <= ${until} ${eventStreamFilter}
      GROUP BY ${eventBucket}
      ORDER BY bucket ASC
    `) as Array<{
			bucket: number | string;
			connected: number | string;
			disconnected: number | string;
			errors: number | string;
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
		}
		for (const row of bandwidthRows) {
			const point = byBucket.get(toNumber(row.bucket));
			if (!point) continue;
			point.clientToUpstreamBytes = toNumber(row.client_to_upstream_bytes);
			point.upstreamToClientBytes = toNumber(row.upstream_to_client_bytes);
		}
		return { series };
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
		await db`INSERT INTO admin_sessions (id,token_hash,username,created_at,expires_at,last_seen_at) VALUES (${session.id},${session.token_hash},${session.username},${session.created_at},${session.expires_at},${session.last_seen_at})`;
	},
	async touchAdmin(id: string, now: number): Promise<void> {
		await db`UPDATE admin_sessions SET last_seen_at=${now} WHERE id=${id}`;
	},
	async deleteAdmin(hash: string): Promise<void> {
		await db`DELETE FROM admin_sessions WHERE token_hash=${hash}`;
	},
};
