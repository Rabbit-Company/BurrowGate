export type IpRuleAction = "allow" | "pass" | "block" | "challenge";
export type DefaultNetworkAction = "inherit" | Exclude<IpRuleAction, "pass">;
export type FlowStatus = "pending" | "completed" | "failed" | "expired";
export type StepStatus = "pending" | "completed" | "failed" | "expired";
export type SiteAccessMode = "challenge" | "bypass";
export type IpExtractionPreset = import("@rabbit-company/web-middleware/ip-extract").IpExtractionPreset;
export type RouteAccessMode = "inherit" | "challenge" | "bypass" | "block";
export type RateLimitAlgorithm = "fixed-window" | "sliding-window" | "token-bucket";
export type RateLimitKeyMode = "ip" | "session-or-ip" | "header-or-ip";
export type RateLimitScope = "policy" | "path" | "method-path";
export type SiteWebSocketMode = "allow" | "deny";
export type RouteWebSocketMode = "inherit" | SiteWebSocketMode;

export type ErrorResponseMode = "html" | "json";
export type OriginHealthState = "unknown" | "healthy" | "degraded" | "unhealthy" | "disabled";
export type OriginHealthFailureMode = "monitor" | "maintenance";
export type HealthAlertProvider = "generic" | "slack" | "discord" | "ntfy";
export type LoadBalancingAlgorithm = "failover" | "round-robin" | "weighted-round-robin";
export type TlsMode = "disabled" | "uploaded" | "letsencrypt";
export type CertificateSource = "uploaded" | "letsencrypt";
export type CertificateStatus = "pending" | "active" | "renewal-failed" | "expired" | "invalid";

export interface SiteTlsSettingsRecord {
	site_id: string;
	mode: TlsMode;
	force_https: number;
	acme_email: string | null;
	acme_directory_url: string | null;
	created_at: number;
	updated_at: number;
}

export interface CertificateRecord {
	id: string;
	site_id: string;
	source: CertificateSource;
	status: CertificateStatus;
	primary_domain: string;
	alternative_names_json: string;
	certificate_pem: string | null;
	encrypted_private_key: string | null;
	issuer: string | null;
	serial_number: string | null;
	valid_from: number | null;
	expires_at: number | null;
	next_renewal_at: number | null;
	last_attempt_at: number | null;
	last_error: string | null;
	created_at: number;
	updated_at: number;
}

export interface AcmeAccountRecord {
	id: string;
	directory_url: string;
	email: string | null;
	account_url: string | null;
	encrypted_account_key: string;
	terms_accepted_at: number;
	created_at: number;
	updated_at: number;
}

export interface AcmeHttpChallengeRecord {
	token: string;
	site_id: string;
	hostname: string;
	key_authorization: string;
	created_at: number;
	expires_at: number;
}

export interface CertificateEventRecord {
	id: string;
	site_id: string;
	certificate_id: string | null;
	level: "info" | "warning" | "error";
	message: string;
	details_json: string;
	created_at: number;
}

export interface ChallengePolicyStep {
	provider: string;
	config: Record<string, unknown>;
}

export interface SiteRecord {
	id: string;
	name: string;
	public_host: string;
	origin_url: string;
	origin_signing_secret: string;
	ip_extraction_preset: IpExtractionPreset;
	enabled: number;
	session_ttl_seconds: number;
	challenge_policy_json: string;
	default_access_mode: SiteAccessMode;
	event_retention_days: number;
	default_ip_action: DefaultNetworkAction;
	default_country_action: DefaultNetworkAction;
	error_response_mode: ErrorResponseMode;
	error_html_template: string;
	error_json_fields_json: string;
	challenge_html_template: string;
	health_check_enabled?: number;
	health_check_path?: string;
	health_check_interval_seconds?: number;
	health_check_timeout_ms?: number;
	health_check_failure_threshold?: number;
	health_check_recovery_threshold?: number;
	health_check_failure_mode?: OriginHealthFailureMode;
	health_alert_enabled?: number;
	health_alert_provider?: HealthAlertProvider;
	health_alert_webhook_url?: string | null;
	health_alert_webhook_secret?: string | null;
	load_balancing_algorithm?: LoadBalancingAlgorithm;
	load_balancing_affinity?: number;
	websocket_policy_json?: string | null;
	http_policy_json?: string | null;
	created_at: number;
	updated_at: number;
}

export interface SiteOriginRecord {
	id: string;
	site_id: string;
	name: string;
	origin_url: string;
	enabled: number;
	draining: number;
	priority: number;
	weight: number;
	health_check_path: string | null;
	is_primary: number;
	created_at: number;
	updated_at: number;
}

export interface OriginBackendHealthStatusRecord extends OriginHealthStatusRecord {
	origin_id: string;
}

export interface OriginBackendHealthEventRecord extends OriginHealthEventRecord {
	origin_id: string;
}

export interface OriginHealthStatusRecord {
	site_id: string;
	state: OriginHealthState;
	consecutive_failures: number;
	consecutive_successes: number;
	last_checked_at: number | null;
	last_healthy_at: number | null;
	last_unhealthy_at: number | null;
	last_status: number | null;
	last_latency_ms: number | null;
	last_error: string | null;
	updated_at: number;
}

export interface OriginHealthEventRecord {
	id: string;
	site_id: string;
	from_state: OriginHealthState;
	to_state: OriginHealthState;
	status: number | null;
	latency_ms: number | null;
	error: string | null;
	created_at: number;
}

export type HealthAlertOutboxStatus = "pending" | "delivered" | "failed";

export interface HealthAlertOutboxRecord {
	id: string;
	site_id: string;
	event_id: string;
	event_type: "origin_unhealthy" | "origin_recovered" | "pool_unhealthy" | "pool_recovered";
	payload_json: string;
	status: HealthAlertOutboxStatus;
	attempts: number;
	next_attempt_at: number;
	last_error: string | null;
	created_at: number;
	delivered_at: number | null;
}

export interface RoutePolicyRecord {
	id: string;
	site_id: string;
	name: string;
	path_pattern: string;
	methods_json: string;
	access_mode: RouteAccessMode;
	challenge_policy_json: string | null;
	rate_limit_enabled: number;
	rate_limit_algorithm: RateLimitAlgorithm;
	rate_limit_window_ms: number;
	rate_limit_max: number;
	rate_limit_refill_rate: number;
	rate_limit_refill_interval_ms: number;
	rate_limit_precision_ms: number;
	rate_limit_key_mode: RateLimitKeyMode;
	rate_limit_key_header: string | null;
	rate_limit_scope: RateLimitScope;
	websocket_policy_json?: string | null;
	http_policy_json?: string | null;
	priority: number;
	enabled: number;
	created_at: number;
	updated_at: number;
}

export interface AccessSessionRecord {
	id: string;
	site_id: string;
	token_hash: string;
	initial_ip: string;
	last_ip: string;
	user_agent_hash: string;
	created_at: number;
	last_seen_at: number;
	expires_at: number;
	revoked_at: number | null;
	verification_summary_json: string;
	request_count: number;
	country_code: string | null;
	access_user_id: string | null;
	authenticated_at: number | null;
	origin_id?: string | null;
}

export interface AccessUserRecord {
	id: string;
	username: string;
	password_hash: string;
	enabled: number;
	created_at: number;
	updated_at: number;
}

export interface SiteAccessSettingsRecord {
	site_id: string;
	enabled: number;
	send_username_to_upstream: number;
	created_at: number;
	updated_at: number;
}

export interface SiteAccessUserRecord {
	site_id: string;
	user_id: string;
	created_at: number;
}

export type BandwidthProtocol = "http" | "websocket";
export type StreamProtocol = "tcp" | "udp";
export type StreamEventType = "connected" | "disconnected" | "upstream-error" | "listener-error";

export interface BandwidthMinuteRecord {
	site_id: string;
	bucket_start: number;
	ip: string;
	country_code: string;
	protocol: BandwidthProtocol;
	client_received_bytes: number;
	client_sent_bytes: number;
	upstream_sent_bytes: number;
	upstream_received_bytes: number;
}

export interface StreamRecord {
	id: string;
	incoming_port: number;
	forward_host: string;
	forward_port: number;
	tcp_enabled: number;
	udp_enabled: number;
	certificate_id: string | null;
	event_retention_days: number;
	created_at: number;
	updated_at: number;
}

export interface StreamEventRecord {
	id: string;
	stream_id: string;
	incoming_port: number;
	connection_id: string | null;
	protocol: StreamProtocol;
	event_type: StreamEventType;
	client_ip: string | null;
	client_port: number | null;
	country_code: string | null;
	reason: string | null;
	error: string | null;
	client_to_upstream_bytes: number;
	upstream_to_client_bytes: number;
	created_at: number;
}

export interface StreamBandwidthMinuteRecord {
	stream_id: string;
	incoming_port: number;
	bucket_start: number;
	ip: string;
	country_code: string;
	protocol: StreamProtocol;
	client_to_upstream_bytes: number;
	upstream_to_client_bytes: number;
}

export interface ChallengeFlowRecord {
	id: string;
	site_id: string;
	return_path: string;
	client_ip: string;
	user_agent_hash: string;
	current_step: number;
	policy_json: string;
	status: FlowStatus;
	created_at: number;
	expires_at: number;
	completed_at: number | null;
}

export interface ChallengeStepRecord {
	id: string;
	flow_id: string;
	step_index: number;
	provider: string;
	config_json: string;
	private_data_json: string;
	public_data_json: string;
	status: StepStatus;
	attempts: number;
	created_at: number;
	expires_at: number;
	completed_at: number | null;
}

export interface IpRuleRecord {
	id: string;
	site_id: string;
	network_cidr: string;
	action: IpRuleAction;
	reason: string;
	created_at: number;
	expires_at: number | null;
}

export interface CountryRuleRecord {
	id: string;
	site_id: string;
	country_code: string;
	action: IpRuleAction;
	reason: string;
	created_at: number;
	expires_at: number | null;
}

export type HttpCacheStatus = "hit" | "miss" | "bypass";

export interface RequestEventRecord {
	id: string;
	site_id: string;
	session_id: string | null;
	ip: string;
	method: string;
	path: string;
	status: number;
	decision: string;
	latency_ms: number;
	country_code: string | null;
	origin_id?: string | null;
	cache_status: HttpCacheStatus | null;
	created_at: number;
}

export interface AdminSessionRecord {
	id: string;
	token_hash: string;
	username: string;
	created_at: number;
	expires_at: number;
	last_seen_at: number;
}

export interface GatewayState {
	site?: SiteRecord;
	accessSession?: AccessSessionRecord;
	clientIp?: string;
	[key: string]: unknown;
}
