import { config } from "../config.ts";
import { DEFAULT_ERROR_HTML_TEMPLATE, DEFAULT_ERROR_JSON_FIELDS } from "../services/error-response-service.ts";
import { DEFAULT_CHALLENGE_HTML_TEMPLATE } from "../services/challenge-page-service.ts";
import { db } from "./client.ts";

const schema = `
CREATE TABLE IF NOT EXISTS sites (
  id VARCHAR(64) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  public_host VARCHAR(255) NOT NULL UNIQUE,
  origin_url TEXT NOT NULL,
  origin_signing_secret TEXT NOT NULL,
  ip_extraction_preset VARCHAR(32) NOT NULL DEFAULT 'direct',
  enabled INTEGER NOT NULL DEFAULT 1,
  session_ttl_seconds INTEGER NOT NULL,
  challenge_policy_json TEXT NOT NULL,
  default_access_mode VARCHAR(32) NOT NULL DEFAULT 'challenge',
  event_retention_days INTEGER NOT NULL DEFAULT 7,
  default_ip_action VARCHAR(32) NOT NULL DEFAULT 'inherit',
  default_country_action VARCHAR(32) NOT NULL DEFAULT 'inherit',
  error_response_mode VARCHAR(16) NOT NULL DEFAULT 'json',
  error_html_template TEXT NULL,
  error_json_fields_json TEXT NULL,
	challenge_html_template TEXT NULL,
  health_check_enabled INTEGER NOT NULL DEFAULT 0,
  health_check_path VARCHAR(2048) NOT NULL DEFAULT '/health',
  health_check_interval_seconds INTEGER NOT NULL DEFAULT 30,
  health_check_timeout_ms INTEGER NOT NULL DEFAULT 3000,
  health_check_failure_threshold INTEGER NOT NULL DEFAULT 3,
  health_check_recovery_threshold INTEGER NOT NULL DEFAULT 2,
  health_check_failure_mode VARCHAR(16) NOT NULL DEFAULT 'monitor',
  health_alert_enabled INTEGER NOT NULL DEFAULT 0,
  health_alert_provider VARCHAR(16) NOT NULL DEFAULT 'generic',
  health_alert_webhook_url TEXT NULL,
  health_alert_webhook_secret TEXT NULL,
  load_balancing_algorithm VARCHAR(32) NOT NULL DEFAULT 'failover',
  load_balancing_affinity INTEGER NOT NULL DEFAULT 1,
  websocket_policy_json TEXT NULL,
  http_policy_json TEXT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS route_policies (
  id VARCHAR(64) PRIMARY KEY,
  site_id VARCHAR(64) NOT NULL,
  name VARCHAR(255) NOT NULL,
  path_pattern TEXT NOT NULL,
  methods_json TEXT NOT NULL,
  access_mode VARCHAR(32) NOT NULL,
  challenge_policy_json TEXT NULL,
  rate_limit_enabled INTEGER NOT NULL DEFAULT 0,
  rate_limit_algorithm VARCHAR(32) NOT NULL DEFAULT 'sliding-window',
  rate_limit_window_ms BIGINT NOT NULL DEFAULT 60000,
  rate_limit_max INTEGER NOT NULL DEFAULT 60,
  rate_limit_refill_rate INTEGER NOT NULL DEFAULT 1,
  rate_limit_refill_interval_ms BIGINT NOT NULL DEFAULT 1000,
  rate_limit_precision_ms INTEGER NOT NULL DEFAULT 100,
  rate_limit_key_mode VARCHAR(32) NOT NULL DEFAULT 'ip',
  rate_limit_key_header VARCHAR(255) NULL,
  rate_limit_scope VARCHAR(32) NOT NULL DEFAULT 'policy',
  websocket_policy_json TEXT NULL,
  http_policy_json TEXT NULL,
  priority INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS access_sessions (
  id VARCHAR(64) PRIMARY KEY,
  site_id VARCHAR(64) NOT NULL,
  token_hash VARCHAR(64) NOT NULL UNIQUE,
  initial_ip VARCHAR(128) NOT NULL,
  last_ip VARCHAR(128) NOT NULL,
  user_agent_hash VARCHAR(64) NOT NULL,
  created_at BIGINT NOT NULL,
  last_seen_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  revoked_at BIGINT NULL,
  verification_summary_json TEXT NOT NULL,
  request_count BIGINT NOT NULL DEFAULT 0,
  country_code VARCHAR(2) NULL,
  access_user_id VARCHAR(64) NULL,
  authenticated_at BIGINT NULL,
  origin_id VARCHAR(64) NULL
);
CREATE TABLE IF NOT EXISTS access_users (
  id VARCHAR(64) PRIMARY KEY,
  username VARCHAR(255) NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  totp_required INTEGER NOT NULL DEFAULT 0,
  totp_secret_encrypted TEXT NULL,
  totp_enrolled_at BIGINT NULL,
  api_token_hash VARCHAR(64) NULL,
  api_token_created_at BIGINT NULL
);
CREATE TABLE IF NOT EXISTS site_access_settings (
  site_id VARCHAR(64) PRIMARY KEY,
  enabled INTEGER NOT NULL DEFAULT 0,
  send_username_to_upstream INTEGER NOT NULL DEFAULT 0,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS site_access_users (
  site_id VARCHAR(64) NOT NULL,
  user_id VARCHAR(64) NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (site_id, user_id)
);
CREATE TABLE IF NOT EXISTS challenge_flows (
  id VARCHAR(64) PRIMARY KEY,
  site_id VARCHAR(64) NOT NULL,
  return_path TEXT NOT NULL,
  client_ip VARCHAR(128) NOT NULL,
  user_agent_hash VARCHAR(64) NOT NULL,
  current_step INTEGER NOT NULL DEFAULT 0,
  policy_json TEXT NOT NULL,
  status VARCHAR(32) NOT NULL,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  completed_at BIGINT NULL
);
CREATE TABLE IF NOT EXISTS challenge_steps (
  id VARCHAR(64) PRIMARY KEY,
  flow_id VARCHAR(64) NOT NULL,
  step_index INTEGER NOT NULL,
  provider VARCHAR(128) NOT NULL,
  config_json TEXT NOT NULL,
  private_data_json TEXT NOT NULL,
  public_data_json TEXT NOT NULL,
  status VARCHAR(32) NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  completed_at BIGINT NULL,
  UNIQUE(flow_id, step_index)
);
CREATE TABLE IF NOT EXISTS challenge_consumptions (
  step_id VARCHAR(64) PRIMARY KEY,
  consumed_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS ip_rules (
  id VARCHAR(64) PRIMARY KEY,
  site_id VARCHAR(64) NOT NULL,
  network_cidr VARCHAR(160) NOT NULL,
  action VARCHAR(32) NOT NULL,
  reason TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NULL
);
CREATE TABLE IF NOT EXISTS country_rules (
  id VARCHAR(64) PRIMARY KEY,
  site_id VARCHAR(64) NOT NULL,
  country_code VARCHAR(2) NOT NULL,
  action VARCHAR(32) NOT NULL,
  reason TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NULL,
  UNIQUE(site_id, country_code)
);
CREATE TABLE IF NOT EXISTS stream_ip_rules (
  id VARCHAR(64) PRIMARY KEY,
  stream_id VARCHAR(64) NOT NULL,
  network_cidr VARCHAR(160) NOT NULL,
  action VARCHAR(32) NOT NULL,
  reason TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NULL
);
CREATE TABLE IF NOT EXISTS stream_country_rules (
  id VARCHAR(64) PRIMARY KEY,
  stream_id VARCHAR(64) NOT NULL,
  country_code VARCHAR(2) NOT NULL,
  action VARCHAR(32) NOT NULL,
  reason TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NULL,
  UNIQUE(stream_id, country_code)
);
CREATE TABLE IF NOT EXISTS request_events (
  id VARCHAR(64) PRIMARY KEY,
  site_id VARCHAR(64) NOT NULL,
  session_id VARCHAR(64) NULL,
  ip VARCHAR(128) NOT NULL,
  method VARCHAR(16) NOT NULL,
  path TEXT NOT NULL,
  status INTEGER NOT NULL,
  decision VARCHAR(64) NOT NULL,
  latency_ms INTEGER NOT NULL,
  country_code VARCHAR(2) NULL,
  origin_id VARCHAR(64) NULL,
	cache_status VARCHAR(16) NULL,
	protection_status VARCHAR(16) NULL,
	protection_rule_id VARCHAR(128) NULL,
	protection_category VARCHAR(64) NULL,
	protection_severity VARCHAR(16) NULL,
	protection_ruleset_id VARCHAR(128) NULL,
	protection_ruleset_version VARCHAR(64) NULL,
	protection_matches_json TEXT NULL,
	access_username VARCHAR(255) NULL,
	referer TEXT NULL,
	referer_host VARCHAR(255) NULL,
  created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS bandwidth_minutes (
  site_id VARCHAR(64) NOT NULL,
  bucket_start BIGINT NOT NULL,
  ip VARCHAR(128) NOT NULL,
  country_code VARCHAR(2) NOT NULL DEFAULT 'ZZ',
  protocol VARCHAR(16) NOT NULL,
  client_received_bytes BIGINT NOT NULL DEFAULT 0,
  client_sent_bytes BIGINT NOT NULL DEFAULT 0,
  upstream_sent_bytes BIGINT NOT NULL DEFAULT 0,
  upstream_received_bytes BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (site_id, bucket_start, ip, country_code, protocol)
);
CREATE TABLE IF NOT EXISTS admin_sessions (
  id VARCHAR(64) PRIMARY KEY,
  token_hash VARCHAR(64) NOT NULL UNIQUE,
  username VARCHAR(255) NOT NULL,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  last_seen_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS admin_users (
  id VARCHAR(64) PRIMARY KEY,
  username VARCHAR(255) NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role VARCHAR(32) NOT NULL DEFAULT 'member',
  totp_secret_encrypted TEXT NULL,
  totp_enrolled_at BIGINT NULL,
  must_enroll_totp INTEGER NOT NULL DEFAULT 1,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  created_by_user_id VARCHAR(64) NULL
);
CREATE TABLE IF NOT EXISTS admin_recovery_codes (
  id VARCHAR(64) PRIMARY KEY,
  user_id VARCHAR(64) NOT NULL,
  code_hash VARCHAR(64) NOT NULL,
  created_at BIGINT NOT NULL,
  used_at BIGINT NULL
);
CREATE TABLE IF NOT EXISTS admin_user_site_permissions (
  user_id VARCHAR(64) NOT NULL,
  site_id VARCHAR(64) NOT NULL,
  level VARCHAR(16) NOT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  PRIMARY KEY (user_id, site_id)
);
CREATE TABLE IF NOT EXISTS admin_user_stream_permissions (
  user_id VARCHAR(64) NOT NULL,
  stream_id VARCHAR(64) NOT NULL,
  level VARCHAR(16) NOT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  PRIMARY KEY (user_id, stream_id)
);
CREATE TABLE IF NOT EXISTS admin_audit_log (
  id VARCHAR(64) PRIMARY KEY,
  actor_user_id VARCHAR(64) NULL,
  actor_username VARCHAR(255) NOT NULL,
  action VARCHAR(64) NOT NULL,
  resource_type VARCHAR(32) NULL,
  resource_id VARCHAR(64) NULL,
  summary TEXT NOT NULL,
  detail_json TEXT NULL,
  ip VARCHAR(128) NOT NULL,
  created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS site_tls_settings (
  site_id VARCHAR(64) PRIMARY KEY,
  mode VARCHAR(32) NOT NULL DEFAULT 'disabled',
  force_https INTEGER NOT NULL DEFAULT 0,
  acme_email VARCHAR(512) NULL,
  acme_directory_url TEXT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS certificates (
  id VARCHAR(64) PRIMARY KEY,
  site_id VARCHAR(64) NOT NULL UNIQUE,
  source VARCHAR(32) NOT NULL,
  status VARCHAR(32) NOT NULL,
  primary_domain VARCHAR(255) NOT NULL,
  alternative_names_json TEXT NOT NULL,
  certificate_pem TEXT NULL,
  encrypted_private_key TEXT NULL,
  issuer TEXT NULL,
  serial_number VARCHAR(255) NULL,
  valid_from BIGINT NULL,
  expires_at BIGINT NULL,
  next_renewal_at BIGINT NULL,
  last_attempt_at BIGINT NULL,
  last_error TEXT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS acme_accounts (
  id VARCHAR(64) PRIMARY KEY,
  directory_url TEXT NOT NULL UNIQUE,
  email VARCHAR(512) NULL,
  account_url TEXT NULL,
  encrypted_account_key TEXT NOT NULL,
  terms_accepted_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS acme_http_challenges (
  token VARCHAR(512) PRIMARY KEY,
  site_id VARCHAR(64) NOT NULL,
  hostname VARCHAR(255) NOT NULL,
  key_authorization TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS certificate_events (
  id VARCHAR(64) PRIMARY KEY,
  site_id VARCHAR(64) NOT NULL,
  certificate_id VARCHAR(64) NULL,
  level VARCHAR(32) NOT NULL,
  message TEXT NOT NULL,
  details_json TEXT NOT NULL,
  created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS streams (
  id VARCHAR(64) PRIMARY KEY,
  incoming_port INTEGER NOT NULL,
  forward_host VARCHAR(255) NOT NULL,
  forward_port INTEGER NOT NULL,
  tcp_enabled INTEGER NOT NULL DEFAULT 1,
  udp_enabled INTEGER NOT NULL DEFAULT 0,
  certificate_id VARCHAR(64) NULL,
  event_retention_days INTEGER NOT NULL DEFAULT 7,
  default_ip_action VARCHAR(32) NOT NULL DEFAULT 'inherit',
  default_country_action VARCHAR(32) NOT NULL DEFAULT 'inherit',
  max_connections_per_ip INTEGER NOT NULL DEFAULT 0,
  connection_rate_limit_enabled INTEGER NOT NULL DEFAULT 0,
  connection_rate_limit_algorithm VARCHAR(32) NOT NULL DEFAULT 'sliding-window',
  connection_rate_limit_window_ms BIGINT NOT NULL DEFAULT 60000,
  connection_rate_limit_max INTEGER NOT NULL DEFAULT 60,
  connection_rate_limit_refill_rate INTEGER NOT NULL DEFAULT 10,
  connection_rate_limit_refill_interval_ms BIGINT NOT NULL DEFAULT 1000,
  connection_rate_limit_precision_ms INTEGER NOT NULL DEFAULT 100,
  udp_amplification_max_ratio INTEGER NOT NULL DEFAULT 0,
  protection_policy_json TEXT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS stream_bindings (
  stream_id VARCHAR(64) NOT NULL,
  protocol VARCHAR(8) NOT NULL,
  incoming_port INTEGER NOT NULL,
  PRIMARY KEY (protocol, incoming_port),
  UNIQUE (stream_id, protocol)
);
CREATE TABLE IF NOT EXISTS stream_events (
  id VARCHAR(64) PRIMARY KEY,
  stream_id VARCHAR(64) NOT NULL,
  incoming_port INTEGER NOT NULL,
  connection_id VARCHAR(64) NULL,
  protocol VARCHAR(8) NOT NULL,
  event_type VARCHAR(32) NOT NULL,
  client_ip VARCHAR(128) NULL,
  client_port INTEGER NULL,
  country_code VARCHAR(2) NULL,
  reason VARCHAR(255) NULL,
  error TEXT NULL,
  protection_rule_id VARCHAR(128) NULL,
  client_to_upstream_bytes BIGINT NOT NULL DEFAULT 0,
  upstream_to_client_bytes BIGINT NOT NULL DEFAULT 0,
  created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS stream_bandwidth_minutes (
  stream_id VARCHAR(64) NOT NULL,
  incoming_port INTEGER NOT NULL,
  bucket_start BIGINT NOT NULL,
  ip VARCHAR(128) NOT NULL,
  country_code VARCHAR(2) NOT NULL,
  protocol VARCHAR(8) NOT NULL,
  client_to_upstream_bytes BIGINT NOT NULL DEFAULT 0,
  upstream_to_client_bytes BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (stream_id, incoming_port, bucket_start, ip, country_code, protocol)
);
CREATE TABLE IF NOT EXISTS site_origins (
  id VARCHAR(64) PRIMARY KEY,
  site_id VARCHAR(64) NOT NULL,
  name VARCHAR(255) NOT NULL,
  origin_url TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  draining INTEGER NOT NULL DEFAULT 0,
  priority INTEGER NOT NULL DEFAULT 0,
  weight INTEGER NOT NULL DEFAULT 1,
  health_check_path VARCHAR(2048) NULL,
  is_primary INTEGER NOT NULL DEFAULT 0,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  UNIQUE(site_id, name)
);
CREATE TABLE IF NOT EXISTS origin_backend_health_status (
  origin_id VARCHAR(64) PRIMARY KEY,
  site_id VARCHAR(64) NOT NULL,
  state VARCHAR(16) NOT NULL,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  consecutive_successes INTEGER NOT NULL DEFAULT 0,
  last_checked_at BIGINT NULL,
  last_healthy_at BIGINT NULL,
  last_unhealthy_at BIGINT NULL,
  last_status INTEGER NULL,
  last_latency_ms INTEGER NULL,
  last_error TEXT NULL,
  updated_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS origin_backend_health_events (
  id VARCHAR(64) PRIMARY KEY,
  site_id VARCHAR(64) NOT NULL,
  origin_id VARCHAR(64) NOT NULL,
  from_state VARCHAR(16) NOT NULL,
  to_state VARCHAR(16) NOT NULL,
  status INTEGER NULL,
  latency_ms INTEGER NULL,
  error TEXT NULL,
  created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS origin_health_status (
  site_id VARCHAR(64) PRIMARY KEY,
  state VARCHAR(16) NOT NULL,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  consecutive_successes INTEGER NOT NULL DEFAULT 0,
  last_checked_at BIGINT NULL,
  last_healthy_at BIGINT NULL,
  last_unhealthy_at BIGINT NULL,
  last_status INTEGER NULL,
  last_latency_ms INTEGER NULL,
  last_error TEXT NULL,
  updated_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS origin_health_events (
  id VARCHAR(64) PRIMARY KEY,
  site_id VARCHAR(64) NOT NULL,
  from_state VARCHAR(16) NOT NULL,
  to_state VARCHAR(16) NOT NULL,
  status INTEGER NULL,
  latency_ms INTEGER NULL,
  error TEXT NULL,
  created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS admin_sso_settings (
  id VARCHAR(16) PRIMARY KEY,
  enabled INTEGER NOT NULL DEFAULT 0,
  enforce_sso INTEGER NOT NULL DEFAULT 0,
  issuer_url TEXT NULL,
  client_id TEXT NULL,
  client_secret_encrypted TEXT NULL,
  scopes VARCHAR(512) NOT NULL DEFAULT 'openid email profile',
  button_label VARCHAR(255) NOT NULL DEFAULT 'Single sign-on',
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS site_sso_settings (
  site_id VARCHAR(64) PRIMARY KEY,
  enabled INTEGER NOT NULL DEFAULT 0,
  enforce_sso INTEGER NOT NULL DEFAULT 0,
  issuer_url TEXT NULL,
  client_id TEXT NULL,
  client_secret_encrypted TEXT NULL,
  scopes VARCHAR(512) NOT NULL DEFAULT 'openid email profile',
  button_label VARCHAR(255) NOT NULL DEFAULT 'Single sign-on',
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS health_alert_outbox (
  id VARCHAR(64) PRIMARY KEY,
  site_id VARCHAR(64) NOT NULL,
  event_id VARCHAR(64) NOT NULL,
  event_type VARCHAR(32) NOT NULL,
  payload_json TEXT NOT NULL,
  status VARCHAR(16) NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at BIGINT NOT NULL,
  last_error TEXT NULL,
  created_at BIGINT NOT NULL,
  delivered_at BIGINT NULL
);
`;

const indexes = [
	"CREATE INDEX IF NOT EXISTS idx_sites_enabled_name ON sites (enabled, name)",
	"CREATE INDEX IF NOT EXISTS idx_route_policies_site_priority ON route_policies (site_id, enabled, priority)",
	"CREATE INDEX IF NOT EXISTS idx_route_policies_site_updated ON route_policies (site_id, updated_at)",
	"CREATE INDEX IF NOT EXISTS idx_request_events_site_created ON request_events (site_id, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_request_events_created ON request_events (created_at)",
	"CREATE INDEX IF NOT EXISTS idx_request_events_site_decision_created ON request_events (site_id, decision, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_request_events_site_status_created ON request_events (site_id, status, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_request_events_site_method_created ON request_events (site_id, method, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_request_events_site_ip_created ON request_events (site_id, ip, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_request_events_site_country_created ON request_events (site_id, country_code, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_request_events_site_origin_created ON request_events (site_id, origin_id, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_request_events_site_cache_created ON request_events (site_id, cache_status, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_request_events_site_protection_created ON request_events (site_id, protection_status, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_request_events_site_protection_rule_created ON request_events (site_id, protection_rule_id, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_request_events_site_referer_host_created ON request_events (site_id, referer_host, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_bandwidth_site_bucket ON bandwidth_minutes (site_id, bucket_start)",
	"CREATE INDEX IF NOT EXISTS idx_bandwidth_site_ip_bucket ON bandwidth_minutes (site_id, ip, bucket_start)",
	"CREATE INDEX IF NOT EXISTS idx_bandwidth_site_country_bucket ON bandwidth_minutes (site_id, country_code, bucket_start)",
	"CREATE INDEX IF NOT EXISTS idx_access_sessions_site_created ON access_sessions (site_id, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_access_sessions_site_last_seen ON access_sessions (site_id, last_seen_at)",
	"CREATE INDEX IF NOT EXISTS idx_access_sessions_site_revoked ON access_sessions (site_id, revoked_at)",
	"CREATE INDEX IF NOT EXISTS idx_access_sessions_site_expires ON access_sessions (site_id, expires_at)",
	"CREATE INDEX IF NOT EXISTS idx_access_sessions_site_state ON access_sessions (site_id, revoked_at, expires_at)",
	"CREATE INDEX IF NOT EXISTS idx_access_sessions_site_ip ON access_sessions (site_id, last_ip)",
	"CREATE INDEX IF NOT EXISTS idx_access_sessions_access_user ON access_sessions (access_user_id, revoked_at, expires_at)",
	"CREATE INDEX IF NOT EXISTS idx_access_users_enabled_username ON access_users (enabled, username)",
	"CREATE INDEX IF NOT EXISTS idx_access_users_api_token ON access_users (api_token_hash)",
	"CREATE INDEX IF NOT EXISTS idx_site_access_users_user ON site_access_users (user_id, site_id)",
	"CREATE INDEX IF NOT EXISTS idx_access_sessions_site_country_created ON access_sessions (site_id, country_code, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_access_sessions_site_terminal ON access_sessions (site_id, expires_at, revoked_at)",
	"CREATE INDEX IF NOT EXISTS idx_ip_rules_site_created ON ip_rules (site_id, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_ip_rules_site_action_created ON ip_rules (site_id, action, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_ip_rules_site_expiry ON ip_rules (site_id, expires_at)",
	"CREATE INDEX IF NOT EXISTS idx_ip_rules_site_rule_id ON ip_rules (site_id, rule_id)",
	"CREATE INDEX IF NOT EXISTS idx_country_rules_site_created ON country_rules (site_id, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_country_rules_site_action ON country_rules (site_id, action, country_code)",
	"CREATE INDEX IF NOT EXISTS idx_stream_ip_rules_stream_created ON stream_ip_rules (stream_id, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_stream_ip_rules_stream_action_created ON stream_ip_rules (stream_id, action, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_stream_ip_rules_stream_expiry ON stream_ip_rules (stream_id, expires_at)",
	"CREATE INDEX IF NOT EXISTS idx_stream_country_rules_stream_created ON stream_country_rules (stream_id, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_stream_country_rules_stream_action ON stream_country_rules (stream_id, action, country_code)",
	"CREATE INDEX IF NOT EXISTS idx_challenge_flows_site_created ON challenge_flows (site_id, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_challenge_steps_expiry ON challenge_steps (expires_at)",
	"CREATE INDEX IF NOT EXISTS idx_challenge_consumptions_created ON challenge_consumptions (consumed_at)",
	"CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires ON admin_sessions (expires_at)",
	"CREATE INDEX IF NOT EXISTS idx_tls_settings_mode ON site_tls_settings (mode, force_https)",
	"CREATE INDEX IF NOT EXISTS idx_certificates_status_expiry ON certificates (status, expires_at)",
	"CREATE INDEX IF NOT EXISTS idx_certificates_source_renewal ON certificates (source, next_renewal_at)",
	"CREATE INDEX IF NOT EXISTS idx_acme_challenges_site_expiry ON acme_http_challenges (site_id, expires_at)",
	"CREATE INDEX IF NOT EXISTS idx_acme_challenges_expiry ON acme_http_challenges (expires_at)",
	"CREATE INDEX IF NOT EXISTS idx_certificate_events_site_created ON certificate_events (site_id, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_streams_port ON streams (incoming_port)",
	"CREATE INDEX IF NOT EXISTS idx_streams_certificate ON streams (certificate_id)",
	"CREATE INDEX IF NOT EXISTS idx_stream_events_stream_created ON stream_events (stream_id, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_stream_events_client_created ON stream_events (client_ip, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_stream_events_port_created ON stream_events (incoming_port, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_stream_events_protection_rule_id ON stream_events (protection_rule_id)",
	"CREATE INDEX IF NOT EXISTS idx_stream_bandwidth_stream_bucket ON stream_bandwidth_minutes (stream_id, bucket_start)",
	"CREATE INDEX IF NOT EXISTS idx_stream_bandwidth_ip_bucket ON stream_bandwidth_minutes (ip, bucket_start)",
	"CREATE INDEX IF NOT EXISTS idx_origin_health_events_site_created ON origin_health_events (site_id, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_health_alert_outbox_due ON health_alert_outbox (status, next_attempt_at)",
	"CREATE INDEX IF NOT EXISTS idx_health_alert_outbox_site_created ON health_alert_outbox (site_id, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_site_origins_site_priority ON site_origins (site_id, enabled, priority)",
	"CREATE INDEX IF NOT EXISTS idx_origin_backend_health_site_state ON origin_backend_health_status (site_id, state)",
	"CREATE INDEX IF NOT EXISTS idx_origin_backend_health_events_origin_created ON origin_backend_health_events (origin_id, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_admin_users_enabled_username ON admin_users (enabled, username)",
	"CREATE INDEX IF NOT EXISTS idx_admin_recovery_codes_user ON admin_recovery_codes (user_id, used_at)",
	"CREATE INDEX IF NOT EXISTS idx_admin_user_site_permissions_site ON admin_user_site_permissions (site_id, user_id)",
	"CREATE INDEX IF NOT EXISTS idx_admin_user_stream_permissions_stream ON admin_user_stream_permissions (stream_id, user_id)",
	"CREATE INDEX IF NOT EXISTS idx_admin_audit_log_created ON admin_audit_log (created_at)",
	"CREATE INDEX IF NOT EXISTS idx_admin_audit_log_actor_created ON admin_audit_log (actor_user_id, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_admin_audit_log_resource ON admin_audit_log (resource_type, resource_id, created_at)",
	"CREATE INDEX IF NOT EXISTS idx_admin_sessions_user ON admin_sessions (user_id, expires_at)",
	"CREATE INDEX IF NOT EXISTS idx_admin_users_sso_subject ON admin_users (sso_subject)",
	"CREATE INDEX IF NOT EXISTS idx_access_users_sso_subject ON access_users (sso_subject)",
	"CREATE INDEX IF NOT EXISTS idx_admin_sessions_sso_sid ON admin_sessions (sso_sid)",
	"CREATE INDEX IF NOT EXISTS idx_access_sessions_sso_sid ON access_sessions (site_id, sso_sid)",
];

function isMySql(): boolean {
	return config.databaseUrl.startsWith("mysql://") || config.databaseUrl.startsWith("mariadb://");
}

function duplicateColumnError(error: unknown): boolean {
	const message = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
	return message.includes("duplicate column") || message.includes("already exists") || (message.includes("column name") && message.includes("duplicate"));
}

async function ensureSiteColumns(): Promise<void> {
	const statements = [
		"ALTER TABLE sites ADD COLUMN ip_extraction_preset VARCHAR(32) NULL",
		"ALTER TABLE sites ADD COLUMN default_access_mode VARCHAR(32) NOT NULL DEFAULT 'challenge'",
		"ALTER TABLE sites ADD COLUMN event_retention_days INTEGER NULL",
		"ALTER TABLE sites ADD COLUMN default_ip_action VARCHAR(32) NOT NULL DEFAULT 'inherit'",
		"ALTER TABLE sites ADD COLUMN default_country_action VARCHAR(32) NOT NULL DEFAULT 'inherit'",
		"ALTER TABLE sites ADD COLUMN error_response_mode VARCHAR(16) NOT NULL DEFAULT 'json'",
		"ALTER TABLE sites ADD COLUMN error_html_template TEXT NULL",
		"ALTER TABLE sites ADD COLUMN error_json_fields_json TEXT NULL",
		"ALTER TABLE sites ADD COLUMN challenge_html_template TEXT NULL",
		"ALTER TABLE sites ADD COLUMN health_check_enabled INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE sites ADD COLUMN health_check_path VARCHAR(2048) NOT NULL DEFAULT '/health'",
		"ALTER TABLE sites ADD COLUMN health_check_interval_seconds INTEGER NOT NULL DEFAULT 30",
		"ALTER TABLE sites ADD COLUMN health_check_timeout_ms INTEGER NOT NULL DEFAULT 3000",
		"ALTER TABLE sites ADD COLUMN health_check_failure_threshold INTEGER NOT NULL DEFAULT 3",
		"ALTER TABLE sites ADD COLUMN health_check_recovery_threshold INTEGER NOT NULL DEFAULT 2",
		"ALTER TABLE sites ADD COLUMN health_check_failure_mode VARCHAR(16) NOT NULL DEFAULT 'monitor'",
		"ALTER TABLE sites ADD COLUMN health_alert_enabled INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE sites ADD COLUMN health_alert_provider VARCHAR(16) NOT NULL DEFAULT 'generic'",
		"ALTER TABLE sites ADD COLUMN health_alert_webhook_url TEXT NULL",
		"ALTER TABLE sites ADD COLUMN health_alert_webhook_secret TEXT NULL",
		"ALTER TABLE sites ADD COLUMN load_balancing_algorithm VARCHAR(32) NOT NULL DEFAULT 'failover'",
		"ALTER TABLE sites ADD COLUMN load_balancing_affinity INTEGER NOT NULL DEFAULT 1",
		"ALTER TABLE sites ADD COLUMN websocket_policy_json TEXT NULL",
		"ALTER TABLE sites ADD COLUMN http_policy_json TEXT NULL",
	];
	for (const statement of statements) {
		try {
			await db.unsafe(statement);
		} catch (error) {
			if (!duplicateColumnError(error)) throw error;
		}
	}
	await db`UPDATE sites SET ip_extraction_preset=${config.dashboardProxyPreset} WHERE ip_extraction_preset IS NULL`;
	await db`UPDATE sites SET event_retention_days=${config.eventRetentionDays} WHERE event_retention_days IS NULL`;
	await db`UPDATE sites SET error_html_template=${DEFAULT_ERROR_HTML_TEMPLATE} WHERE error_html_template IS NULL`;
	await db`UPDATE sites SET error_json_fields_json=${JSON.stringify(DEFAULT_ERROR_JSON_FIELDS)} WHERE error_json_fields_json IS NULL`;
	await db`UPDATE sites SET challenge_html_template=${DEFAULT_CHALLENGE_HTML_TEMPLATE} WHERE challenge_html_template IS NULL`;
}

async function ensureRoutePolicyColumns(): Promise<void> {
	for (const statement of [
		"ALTER TABLE route_policies ADD COLUMN websocket_policy_json TEXT NULL",
		"ALTER TABLE route_policies ADD COLUMN http_policy_json TEXT NULL",
	]) {
		try {
			await db.unsafe(statement);
		} catch (error) {
			if (!duplicateColumnError(error)) throw error;
		}
	}
}

async function ensureIpRuleColumns(): Promise<void> {
	try {
		await db.unsafe("ALTER TABLE ip_rules ADD COLUMN rule_id VARCHAR(128) NULL");
	} catch (error) {
		if (!duplicateColumnError(error)) throw error;
	}
}

async function ensureStreamColumns(): Promise<void> {
	const statements = [
		"ALTER TABLE streams ADD COLUMN default_ip_action VARCHAR(32) NOT NULL DEFAULT 'inherit'",
		"ALTER TABLE streams ADD COLUMN default_country_action VARCHAR(32) NOT NULL DEFAULT 'inherit'",
		"ALTER TABLE streams ADD COLUMN max_connections_per_ip INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE streams ADD COLUMN connection_rate_limit_enabled INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE streams ADD COLUMN connection_rate_limit_algorithm VARCHAR(32) NOT NULL DEFAULT 'sliding-window'",
		"ALTER TABLE streams ADD COLUMN connection_rate_limit_window_ms BIGINT NOT NULL DEFAULT 60000",
		"ALTER TABLE streams ADD COLUMN connection_rate_limit_max INTEGER NOT NULL DEFAULT 60",
		"ALTER TABLE streams ADD COLUMN connection_rate_limit_refill_rate INTEGER NOT NULL DEFAULT 10",
		"ALTER TABLE streams ADD COLUMN connection_rate_limit_refill_interval_ms BIGINT NOT NULL DEFAULT 1000",
		"ALTER TABLE streams ADD COLUMN connection_rate_limit_precision_ms INTEGER NOT NULL DEFAULT 100",
		"ALTER TABLE streams ADD COLUMN udp_amplification_max_ratio INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE streams ADD COLUMN protection_policy_json TEXT NULL",
	];
	for (const statement of statements) {
		try {
			await db.unsafe(statement);
		} catch (error) {
			if (!duplicateColumnError(error)) throw error;
		}
	}
}

async function ensureGeoIpColumns(): Promise<void> {
	const statements = [
		"ALTER TABLE request_events ADD COLUMN country_code VARCHAR(2) NULL",
		"ALTER TABLE access_sessions ADD COLUMN country_code VARCHAR(2) NULL",
	];
	for (const statement of statements) {
		try {
			await db.unsafe(statement);
		} catch (error) {
			if (!duplicateColumnError(error)) throw error;
		}
	}
}

async function ensureAccessSessionColumns(): Promise<void> {
	const statements = [
		"ALTER TABLE access_sessions ADD COLUMN access_user_id VARCHAR(64) NULL",
		"ALTER TABLE access_sessions ADD COLUMN authenticated_at BIGINT NULL",
		"ALTER TABLE access_sessions ADD COLUMN origin_id VARCHAR(64) NULL",
	];
	for (const statement of statements) {
		try {
			await db.unsafe(statement);
		} catch (error) {
			if (!duplicateColumnError(error)) throw error;
		}
	}
}

async function ensureAccessUserColumns(): Promise<void> {
	const statements = [
		"ALTER TABLE access_users ADD COLUMN totp_required INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE access_users ADD COLUMN totp_secret_encrypted TEXT NULL",
		"ALTER TABLE access_users ADD COLUMN totp_enrolled_at BIGINT NULL",
		"ALTER TABLE access_users ADD COLUMN api_token_hash VARCHAR(64) NULL",
		"ALTER TABLE access_users ADD COLUMN api_token_created_at BIGINT NULL",
	];
	for (const statement of statements) {
		try {
			await db.unsafe(statement);
		} catch (error) {
			if (!duplicateColumnError(error)) throw error;
		}
	}
}

async function ensureSsoSessionColumns(): Promise<void> {
	const statements = ["ALTER TABLE admin_sessions ADD COLUMN sso_sid VARCHAR(255) NULL", "ALTER TABLE access_sessions ADD COLUMN sso_sid VARCHAR(255) NULL"];
	for (const statement of statements) {
		try {
			await db.unsafe(statement);
		} catch (error) {
			if (!duplicateColumnError(error)) throw error;
		}
	}
}

async function ensureAdminUserSsoColumns(): Promise<void> {
	const statements = [
		"ALTER TABLE admin_users ADD COLUMN sso_subject VARCHAR(512) NULL",
		"ALTER TABLE admin_users ADD COLUMN auth_source VARCHAR(16) NOT NULL DEFAULT 'password'",
	];
	for (const statement of statements) {
		try {
			await db.unsafe(statement);
		} catch (error) {
			if (!duplicateColumnError(error)) throw error;
		}
	}
}

async function ensureAccessUserSsoColumns(): Promise<void> {
	const statements = [
		"ALTER TABLE access_users ADD COLUMN sso_subject VARCHAR(512) NULL",
		"ALTER TABLE access_users ADD COLUMN auth_source VARCHAR(16) NOT NULL DEFAULT 'password'",
	];
	for (const statement of statements) {
		try {
			await db.unsafe(statement);
		} catch (error) {
			if (!duplicateColumnError(error)) throw error;
		}
	}
}

async function ensureAdminSessionColumns(): Promise<void> {
	try {
		await db.unsafe("ALTER TABLE admin_sessions ADD COLUMN user_id VARCHAR(64) NULL");
	} catch (error) {
		if (!duplicateColumnError(error)) throw error;
	}
}

async function ensureStreamEventColumns(): Promise<void> {
	try {
		await db.unsafe("ALTER TABLE stream_events ADD COLUMN protection_rule_id VARCHAR(128) NULL");
	} catch (error) {
		if (!duplicateColumnError(error)) throw error;
	}
}

async function ensureRequestEventColumns(): Promise<void> {
	for (const statement of [
		"ALTER TABLE request_events ADD COLUMN origin_id VARCHAR(64) NULL",
		"ALTER TABLE request_events ADD COLUMN cache_status VARCHAR(16) NULL",
		"ALTER TABLE request_events ADD COLUMN protection_status VARCHAR(16) NULL",
		"ALTER TABLE request_events ADD COLUMN protection_rule_id VARCHAR(128) NULL",
		"ALTER TABLE request_events ADD COLUMN protection_category VARCHAR(64) NULL",
		"ALTER TABLE request_events ADD COLUMN protection_severity VARCHAR(16) NULL",
		"ALTER TABLE request_events ADD COLUMN protection_ruleset_id VARCHAR(128) NULL",
		"ALTER TABLE request_events ADD COLUMN protection_ruleset_version VARCHAR(64) NULL",
		"ALTER TABLE request_events ADD COLUMN protection_matches_json TEXT NULL",
		"ALTER TABLE request_events ADD COLUMN access_username VARCHAR(255) NULL",
		"ALTER TABLE request_events ADD COLUMN referer TEXT NULL",
		"ALTER TABLE request_events ADD COLUMN referer_host VARCHAR(255) NULL",
	]) {
		try {
			await db.unsafe(statement);
		} catch (error) {
			if (!duplicateColumnError(error)) throw error;
		}
	}
}

async function ensurePrimaryOrigins(): Promise<void> {
	const sites = (await db`SELECT id,name,origin_url,created_at,updated_at FROM sites`) as Array<{
		id: string;
		name: string;
		origin_url: string;
		created_at: number;
		updated_at: number;
	}>;
	for (const site of sites) {
		const existing = (await db`SELECT id FROM site_origins WHERE site_id=${site.id} AND is_primary=1 LIMIT 1`) as Array<{ id: string }>;
		if (existing.length > 0) continue;
		const id = `origin_${crypto.randomUUID()}`;
		await db`INSERT INTO site_origins (id,site_id,name,origin_url,enabled,draining,priority,weight,health_check_path,is_primary,created_at,updated_at) VALUES (${id},${site.id},${`${site.name} primary`},${site.origin_url},1,0,0,1,${null},1,${site.created_at},${site.updated_at})`;
	}
}

function duplicateIndexError(error: unknown): boolean {
	const message = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
	return message.includes("already exists") || message.includes("duplicate key name") || message.includes("duplicate index");
}

async function createIndexes(): Promise<void> {
	for (const index of indexes) {
		const statement = isMySql() ? index.replace(" IF NOT EXISTS", "") : index;
		try {
			await db.unsafe(statement);
		} catch (error) {
			if (!duplicateIndexError(error)) throw error;
		}
	}
}

export async function migrate(): Promise<void> {
	await db.unsafe(schema);
	await ensureSiteColumns();
	await ensureRoutePolicyColumns();
	await ensureIpRuleColumns();
	await ensureStreamColumns();
	await ensureGeoIpColumns();
	await ensureAccessUserColumns();
	await ensureAccessSessionColumns();
	await ensureAdminUserSsoColumns();
	await ensureAccessUserSsoColumns();
	await ensureSsoSessionColumns();
	await ensureAdminSessionColumns();
	await ensureRequestEventColumns();
	await ensureStreamEventColumns();
	await ensurePrimaryOrigins();
	if (config.databaseUrl.startsWith("sqlite") || config.databaseUrl.startsWith("file") || config.databaseUrl === ":memory:") {
		await db.unsafe("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;");
	}
	await createIndexes();
}
