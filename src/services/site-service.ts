import { challengeRegistry } from "../challenges/index.ts";
import { config, parseIpExtractionPreset } from "../config.ts";
import { repository } from "../db/repository.ts";
import type {
	ChallengePolicyStep,
	DefaultNetworkAction,
	ErrorResponseMode,
	HealthAlertProvider,
	OriginHealthFailureMode,
	LoadBalancingAlgorithm,
	OriginType,
	OutboundFetchProtocol,
	IpExtractionPreset,
	NotificationEventType,
	PendingChangeRecord,
	SiteAccessMode,
	SiteOriginRecord,
	SiteRecord,
} from "../types.ts";
import { randomId, randomToken } from "../utils/crypto.ts";
import { normalizeHost } from "../utils/http.ts";
import { normalizeStaticRoot, staticIndexFile } from "./origin-pool-service.ts";
import { assertTlsHostnameAvailable, certificateCoversHostname, siteHostname } from "./certificate-service.ts";
import { currentPendingChange, parseScheduleTime, stagePendingChange } from "./pending-change-service.ts";
import { requestTlsReload } from "./tls-listener-service.ts";
import {
	DEFAULT_ERROR_HTML_TEMPLATE,
	DEFAULT_ERROR_JSON_FIELDS,
	validateErrorHtmlTemplate,
	validateErrorJsonFields,
	validateErrorResponseMode,
	type ErrorJsonField,
} from "./error-response-service.ts";
import { DEFAULT_CHALLENGE_HTML_TEMPLATE, parseStoredChallengeTemplates, validateChallengeHtmlTemplate } from "./challenge-page-service.ts";
import { encryptSecret } from "./secret-encryption-service.ts";
import { serializeSiteWebSocketPolicy, siteWebSocketPolicyView, type SiteWebSocketPolicyView } from "./websocket-policy-service.ts";
import { serializeSiteHttpPolicy, siteHttpPolicyView, type SiteHttpPolicyView } from "./http-policy-service.ts";
import { staticAssetCache } from "./static-cache-service.ts";
import { NOTIFICATION_EVENT_TYPES } from "./stream-notification-policy-service.ts";
import { serializeBotPolicy, storedBotPolicy, type BotPolicy } from "./bot-service.ts";
import { serializeNetworkPrivacyPolicy, storedNetworkPrivacyPolicy, type NetworkPrivacyPolicy } from "./network-privacy-service.ts";

export interface SiteInput {
	name?: unknown;
	publicHost?: unknown;
	originType?: unknown;
	originUrl?: unknown;
	staticRoot?: unknown;
	staticIndexFile?: unknown;
	staticSpaFallback?: unknown;
	enabled?: unknown;
	sessionTtlSeconds?: unknown;
	challengePolicy?: unknown;
	challengeAutoBan?: unknown;
	originSigningSecret?: unknown;
	defaultAccessMode?: unknown;
	eventRetentionDays?: unknown;
	defaultIpAction?: unknown;
	defaultCountryAction?: unknown;
	errorResponseMode?: unknown;
	errorHtmlTemplate?: unknown;
	challengeHtmlTemplate?: unknown;
	challengeHtmlTemplates?: unknown;
	errorJsonFields?: unknown;
	healthCheck?: unknown;
	loadBalancer?: unknown;
	outboundFetchProtocol?: unknown;
	ipExtractionPreset?: unknown;
	websocket?: unknown;
	http?: unknown;
	botPolicy?: unknown;
	networkPrivacyPolicy?: unknown;
	effectiveAt?: unknown;
}

export interface SiteView {
	id: string;
	name: string;
	publicHost: string;
	originType: OriginType;
	originUrl: string | null;
	staticRoot: string | null;
	staticIndexFile: string | null;
	staticSpaFallback: boolean;
	ipExtractionPreset: IpExtractionPreset;
	enabled: boolean;
	sessionTtlSeconds: number;
	challengePolicy: ChallengePolicyStep[];
	challengeAutoBan: {
		enabled: boolean;
		maxFailures: number;
		banSeconds: number;
	};
	defaultAccessMode: SiteAccessMode;
	eventRetentionDays: number;
	defaultIpAction: DefaultNetworkAction;
	defaultCountryAction: DefaultNetworkAction;
	errorResponse: {
		mode: ErrorResponseMode;
		htmlTemplate: string;
		jsonFields: ErrorJsonField[];
	};
	challengePage: { htmlTemplate: string; templates: Record<string, string> };
	healthCheck: {
		enabled: boolean;
		path: string;
		intervalSeconds: number;
		timeoutMs: number;
		failureThreshold: number;
		recoveryThreshold: number;
		failureMode: OriginHealthFailureMode;
		alerts: { enabled: boolean; provider: HealthAlertProvider; webhookConfigured: boolean; eventTypes: Record<NotificationEventType, boolean> };
	};
	loadBalancer: { algorithm: LoadBalancingAlgorithm; affinity: boolean };
	outboundFetchProtocol: OutboundFetchProtocol;
	websocket: SiteWebSocketPolicyView;
	http: SiteHttpPolicyView;
	botPolicy: BotPolicy;
	networkPrivacyPolicy: NetworkPrivacyPolicy;
	createdAt: number;
	updatedAt: number;
}

function requiredString(value: unknown, label: string, maximum: number): string {
	const result = String(value ?? "").trim();
	if (!result) throw new Error(`${label} is required`);
	if (result.length > maximum) throw new Error(`${label} must be at most ${maximum} characters`);
	return result;
}

function normalizePublicHost(value: unknown): string {
	const raw = requiredString(value, "Public host", 255);
	if (raw.includes("://")) throw new Error("Public host must not include a URL scheme");
	let parsed: URL;
	try {
		parsed = new URL(`http://${raw}`);
	} catch {
		throw new Error("Public host must be a valid hostname, optionally with a port");
	}
	if (parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) {
		throw new Error("Public host must contain only a hostname and optional port");
	}
	return normalizeHost(parsed.host);
}

function normalizeOriginUrl(value: unknown): string {
	const raw = requiredString(value, "Origin URL", 2_048);
	let parsed: URL;
	try {
		parsed = new URL(raw);
	} catch {
		throw new Error("Origin URL must be a valid absolute URL");
	}
	if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("Origin URL must use HTTP or HTTPS");
	if (parsed.username || parsed.password) throw new Error("Origin URL must not contain credentials");
	if (parsed.search || parsed.hash) throw new Error("Origin URL must not contain a query string or fragment");
	return parsed.toString().replace(/\/$/u, parsed.pathname === "/" ? "" : "/");
}

function normalizeSiteOriginType(value: unknown, fallback: OriginType = "proxy"): OriginType {
	const raw = value === undefined ? fallback : String(value).trim().toLowerCase();
	if (raw === "proxy" || raw === "static") return raw;
	throw new Error("Origin type must be proxy or static");
}

/**
 * A site's primary origin lives in both `sites` (origin_type/origin_url, for
 * quick access and backward compatibility) and `site_origins` (the same two
 * fields plus the static-only knobs). Resolving them together here keeps
 * createSite/updateSite and the primary-origin row from disagreeing on type.
 */
function resolveSiteOriginFields(
	input: SiteInput,
	existing?: SiteRecord,
	existingPrimaryOrigin?: SiteOriginRecord | null,
): { origin_type: OriginType; origin_url: string } & Pick<SiteOriginRecord, "static_index_file" | "static_spa_fallback"> {
	const originType = normalizeSiteOriginType(input.originType, existing?.origin_type ?? "proxy");
	const existingStatic = existingPrimaryOrigin?.origin_type === "static" ? existingPrimaryOrigin : null;
	if (originType === "static") {
		return {
			origin_type: "static",
			origin_url: normalizeStaticRoot(input.staticRoot, existing?.origin_type === "static" ? existing.origin_url : undefined),
			static_index_file: staticIndexFile(input.staticIndexFile, existingStatic?.static_index_file ?? "index.html"),
			static_spa_fallback: enabledValue(input.staticSpaFallback, existingStatic?.static_spa_fallback === 1) ? 1 : 0,
		};
	}
	return {
		origin_type: "proxy",
		origin_url: normalizeOriginUrl(input.originUrl ?? existing?.origin_url),
		static_index_file: null,
		static_spa_fallback: 0,
	};
}

function enabledValue(value: unknown, fallback: boolean): boolean {
	if (value === undefined) return fallback;
	if (typeof value === "boolean") return value;
	if (value === 1 || value === "1" || value === "true") return true;
	if (value === 0 || value === "0" || value === "false") return false;
	throw new Error("Enabled must be a boolean");
}

function defaultAccessMode(value: unknown, fallback: SiteAccessMode): SiteAccessMode {
	if (value === undefined) return fallback;
	const mode = String(value).trim().toLowerCase();
	if (mode === "challenge" || mode === "bypass") return mode;
	throw new Error("Default access mode must be challenge or bypass");
}

export function parseDefaultNetworkAction(value: unknown, fallback: DefaultNetworkAction): DefaultNetworkAction {
	if (value === undefined) return fallback;
	const action = String(value).trim().toLowerCase();
	if (action === "inherit" || action === "allow" || action === "block" || action === "challenge") return action;
	throw new Error("Default network action must be inherit, allow, block, or challenge");
}

function sessionTtl(value: unknown, fallback: number): number {
	const result = value === undefined ? fallback : Number(value);
	if (!Number.isInteger(result) || result < 60 || result > 2_592_000) {
		throw new Error("Session lifetime must be an integer from 60 to 2592000 seconds");
	}
	return result;
}

function eventRetentionDays(value: unknown, fallback: number): number {
	const result = value === undefined ? fallback : Number(value);
	if (!Number.isInteger(result) || result < 1 || result > 365) {
		throw new Error("Event retention must be an integer from 1 to 365 days");
	}
	return result;
}

function signingSecret(value: unknown): string | undefined {
	const result = String(value ?? "").trim();
	if (!result) return undefined;
	if (result.length < 32 || result.length > 512) {
		throw new Error("Origin signing secret must contain between 32 and 512 characters");
	}
	return result;
}

interface ParsedHealthCheck {
	enabled: boolean;
	path: string;
	intervalSeconds: number;
	timeoutMs: number;
	failureThreshold: number;
	recoveryThreshold: number;
	failureMode: OriginHealthFailureMode;
	alertEnabled: boolean;
	alertProvider: HealthAlertProvider;
	webhookUrl?: string;
	webhookSecret?: string;
	clearWebhook: boolean;
	notificationEventTypes: Record<NotificationEventType, boolean>;
}

function boundedInteger(value: unknown, fallback: number, label: string, minimum: number, maximum: number): number {
	const result = value === undefined ? fallback : Number(value);
	if (!Number.isInteger(result) || result < minimum || result > maximum) throw new Error(`${label} must be an integer from ${minimum} to ${maximum}`);
	return result;
}

function healthPath(value: unknown, fallback: string): string {
	const path = String(value ?? fallback).trim();
	if (!path.startsWith("/") || path.startsWith("//") || path.length > 2_048) {
		throw new Error("Health-check path must begin with one slash and be at most 2048 characters");
	}
	const parsed = new URL(path, "http://health.invalid");
	if (parsed.origin !== "http://health.invalid" || parsed.hash) throw new Error("Health-check path must not contain a hostname or fragment");
	return `${parsed.pathname}${parsed.search}`;
}

function healthFailureMode(value: unknown, fallback: OriginHealthFailureMode): OriginHealthFailureMode {
	const mode = String(value ?? fallback)
		.trim()
		.toLowerCase();
	if (mode === "monitor" || mode === "maintenance") return mode;
	throw new Error("Health-check failure behavior must be monitor or maintenance");
}

function healthAlertProvider(value: unknown, fallback: HealthAlertProvider): HealthAlertProvider {
	const provider = String(value ?? fallback)
		.trim()
		.toLowerCase();
	if (["generic", "slack", "discord", "ntfy"].includes(provider)) return provider as HealthAlertProvider;
	throw new Error("Health alert provider must be generic, slack, discord, or ntfy");
}

function loadBalancerSettings(value: unknown, existing?: SiteRecord): { algorithm: LoadBalancingAlgorithm; affinity: boolean } {
	if (value !== undefined && (!value || typeof value !== "object" || Array.isArray(value))) throw new Error("Load-balancer settings must be an object");
	const input = (value ?? {}) as Record<string, unknown>;
	const algorithm = String(input.algorithm ?? existing?.load_balancing_algorithm ?? "failover")
		.trim()
		.toLowerCase();
	if (!["failover", "round-robin", "weighted-round-robin"].includes(algorithm)) {
		throw new Error("Load-balancing algorithm must be failover, round-robin, or weighted-round-robin");
	}
	return {
		algorithm: algorithm as LoadBalancingAlgorithm,
		affinity: enabledValue(input.affinity, existing?.load_balancing_affinity !== 0),
	};
}

function outboundFetchProtocol(value: unknown, fallback: OutboundFetchProtocol): OutboundFetchProtocol {
	if (value === undefined) return fallback;
	const protocol = String(value).trim().toLowerCase();
	if (protocol === "http1" || protocol === "http2" || protocol === "http3") return protocol;
	throw new Error("Outbound fetch protocol must be http1, http2, or http3");
}

export function outboundFetchProtocolOption(site: SiteRecord): Pick<BunFetchRequestInit, "protocol"> {
	const protocol = site.outbound_fetch_protocol;
	if (protocol !== "http2" && protocol !== "http3") return {};
	return { protocol: protocol as BunFetchRequestInit["protocol"] };
}

function webhookValue(value: unknown, label: string): string | undefined {
	const raw = String(value ?? "").trim();
	if (!raw) return undefined;
	if (raw.length > 4_096) throw new Error(`${label} must be at most 4096 characters`);
	let parsed: URL;
	try {
		parsed = new URL(raw);
	} catch {
		throw new Error(`${label} must be a valid absolute URL`);
	}
	if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) {
		throw new Error(`${label} must use HTTP or HTTPS and must not contain URL credentials`);
	}
	return parsed.toString();
}

function existingNotificationEventTypes(existing?: SiteRecord): Record<NotificationEventType, boolean> {
	const defaults = Object.fromEntries(NOTIFICATION_EVENT_TYPES.map((type) => [type, true])) as Record<NotificationEventType, boolean>;
	if (!existing?.notification_event_types_json) return defaults;
	try {
		const stored = JSON.parse(existing.notification_event_types_json) as Record<string, unknown>;
		for (const type of NOTIFICATION_EVENT_TYPES) if (stored[type] === false) defaults[type] = false;
	} catch {
		// fall through to defaults
	}
	return defaults;
}

function notificationEventTypes(value: unknown, existing?: SiteRecord): Record<NotificationEventType, boolean> {
	if (value === undefined) return existingNotificationEventTypes(existing);
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Notification event-type settings must be an object");
	const input = value as Record<string, unknown>;
	for (const key of Object.keys(input)) {
		if (!NOTIFICATION_EVENT_TYPES.includes(key as NotificationEventType)) throw new Error(`Unknown notification event type: ${key}`);
	}
	const result = existingNotificationEventTypes(existing);
	for (const type of NOTIFICATION_EVENT_TYPES) if (type in input) result[type] = Boolean(input[type]);
	return result;
}

function parseHealthCheck(value: unknown, existing?: SiteRecord): ParsedHealthCheck {
	if (value !== undefined && (!value || typeof value !== "object" || Array.isArray(value))) throw new Error("Health-check settings must be an object");
	const input = (value ?? {}) as Record<string, unknown>;
	const alertInput = input.alerts === undefined ? {} : input.alerts;
	if (!alertInput || typeof alertInput !== "object" || Array.isArray(alertInput)) throw new Error("Health alert settings must be an object");
	const alerts = alertInput as Record<string, unknown>;
	const clearWebhook = enabledValue(alerts.clearWebhook, false);
	const webhookSecret = String(alerts.webhookSecret ?? "").trim() || undefined;
	if (webhookSecret && webhookSecret.length > 4_096) throw new Error("Health alert webhook signing secret must be at most 4096 characters");
	const eventTypes = notificationEventTypes(alerts.eventTypes, existing);
	return {
		notificationEventTypes: eventTypes,
		enabled: enabledValue(input.enabled, existing?.health_check_enabled === 1),
		path: healthPath(input.path, existing?.health_check_path ?? "/health"),
		intervalSeconds: boundedInteger(input.intervalSeconds, existing?.health_check_interval_seconds ?? 10, "Health-check interval", 3, 3_600),
		timeoutMs: boundedInteger(input.timeoutMs, existing?.health_check_timeout_ms ?? 3_000, "Health-check timeout", 250, 60_000),
		failureThreshold: boundedInteger(input.failureThreshold, existing?.health_check_failure_threshold ?? 3, "Health-check failure threshold", 1, 20),
		recoveryThreshold: boundedInteger(input.recoveryThreshold, existing?.health_check_recovery_threshold ?? 2, "Health-check recovery threshold", 1, 20),
		failureMode: healthFailureMode(input.failureMode, existing?.health_check_failure_mode ?? "monitor"),
		alertEnabled: enabledValue(alerts.enabled, existing?.health_alert_enabled === 1),
		alertProvider: healthAlertProvider(alerts.provider, existing?.health_alert_provider ?? "generic"),
		webhookUrl: webhookValue(alerts.webhookUrl, "Health alert webhook URL"),
		webhookSecret,
		clearWebhook,
	};
}

const MAX_CHALLENGE_AUTO_BAN_SECONDS = 2_592_000; // 30 days

interface ParsedChallengeAutoBan {
	enabled: boolean;
	maxFailures: number;
	banSeconds: number;
}

function parseChallengeAutoBan(value: unknown, existing?: SiteRecord): ParsedChallengeAutoBan {
	if (value !== undefined && (!value || typeof value !== "object" || Array.isArray(value))) {
		throw new Error("Challenge auto-ban settings must be an object");
	}
	const input = (value ?? {}) as Record<string, unknown>;
	return {
		enabled: enabledValue(input.enabled, existing?.challenge_auto_ban_enabled === 1),
		maxFailures: boundedInteger(input.maxFailures, existing?.challenge_auto_ban_max_failures ?? 5, "Challenge auto-ban max failures", 1, 1_000),
		banSeconds: boundedInteger(
			input.banSeconds,
			existing?.challenge_auto_ban_seconds ?? 3_600,
			"Challenge auto-ban duration",
			1,
			MAX_CHALLENGE_AUTO_BAN_SECONDS,
		),
	};
}

/**
 * Per-provider template overrides. Merges onto the existing stored map (like serializeSiteHttpPolicy's
 * bandwidthLimit spread) rather than replacing it outright - the admin UI only sends the providers the
 * user actually touched in this edit session, so a full replace would silently wipe out every other
 * provider's saved override. A present key is validated with the same rules as the legacy single
 * template; a blank value removes that provider's override (falls back to the next layer in
 * renderChallengePage's resolution chain) rather than being stored as an invalid empty template.
 */
function parseChallengeHtmlTemplates(value: unknown, existing?: SiteRecord): Record<string, string> {
	const current = existing ? parseStoredChallengeTemplates(existing.challenge_html_templates_json) : {};
	if (value === undefined) return current;
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Challenge page templates must be an object");
	const result = { ...current };
	for (const [provider, entry] of Object.entries(value as Record<string, unknown>)) {
		const template = String(entry ?? "").trim();
		if (!template) {
			delete result[provider];
			continue;
		}
		result[provider] = validateChallengeHtmlTemplate(template);
	}
	return result;
}

export function parseChallengePolicy(value: unknown, fallback?: ChallengePolicyStep[]): ChallengePolicyStep[] {
	let parsed = value;
	if (typeof parsed === "string") {
		try {
			parsed = JSON.parse(parsed);
		} catch {
			throw new Error("Challenge policy must be valid JSON");
		}
	}
	if (parsed === undefined && fallback) return fallback;
	if (!Array.isArray(parsed) || parsed.length < 1 || parsed.length > 16) {
		throw new Error("Challenge policy must contain between 1 and 16 challenge steps");
	}
	return parsed.map((item, index) => {
		if (!item || typeof item !== "object" || Array.isArray(item)) {
			throw new Error(`Challenge step ${index + 1} must be an object`);
		}
		const record = item as Record<string, unknown>;
		const providerName = requiredString(record.provider, `Challenge step ${index + 1} provider`, 128);
		const provider = challengeRegistry.get(providerName);
		const providerConfig = record.config === undefined ? {} : record.config;
		if (!providerConfig || typeof providerConfig !== "object" || Array.isArray(providerConfig)) {
			throw new Error(`Challenge step ${index + 1} config must be an object`);
		}
		provider.validateConfig?.(providerConfig as Record<string, unknown>);
		return { provider: providerName, config: providerConfig as Record<string, unknown> };
	});
}

export async function normalizeChallengePolicyForStorage(steps: ChallengePolicyStep[]): Promise<ChallengePolicyStep[]> {
	const result: ChallengePolicyStep[] = [];
	for (const step of steps) {
		const provider = challengeRegistry.get(step.provider);
		const normalizedConfig = provider.normalizeConfigForStorage ? await provider.normalizeConfigForStorage(step.config) : step.config;
		result.push({ provider: step.provider, config: normalizedConfig });
	}
	return result;
}

function policyFromRecord(site: SiteRecord): ChallengePolicyStep[] {
	return parseChallengePolicy(site.challenge_policy_json);
}

function errorJsonFieldsFromRecord(site: SiteRecord): ErrorJsonField[] {
	try {
		return validateErrorJsonFields(site.error_json_fields_json || undefined);
	} catch {
		return [...DEFAULT_ERROR_JSON_FIELDS];
	}
}

export function siteView(site: SiteRecord, primaryOrigin?: SiteOriginRecord | null): SiteView {
	const isStatic = (site.origin_type ?? "proxy") === "static";
	return {
		id: site.id,
		name: site.name,
		publicHost: site.public_host,
		originType: site.origin_type ?? "proxy",
		originUrl: isStatic ? null : site.origin_url,
		staticRoot: isStatic ? site.origin_url : null,
		staticIndexFile: isStatic ? (primaryOrigin?.static_index_file ?? "index.html") : null,
		staticSpaFallback: isStatic && primaryOrigin?.static_spa_fallback === 1,
		ipExtractionPreset: site.ip_extraction_preset ?? "direct",
		enabled: site.enabled === 1,
		sessionTtlSeconds: Number(site.session_ttl_seconds),
		challengePolicy: policyFromRecord(site),
		challengeAutoBan: {
			enabled: site.challenge_auto_ban_enabled === 1,
			maxFailures: Number(site.challenge_auto_ban_max_failures ?? 5),
			banSeconds: Number(site.challenge_auto_ban_seconds ?? 3_600),
		},
		defaultAccessMode: site.default_access_mode ?? "challenge",
		eventRetentionDays: Number(site.event_retention_days ?? config.eventRetentionDays),
		defaultIpAction: site.default_ip_action ?? "inherit",
		defaultCountryAction: site.default_country_action ?? "inherit",
		errorResponse: {
			mode: site.error_response_mode ?? "json",
			htmlTemplate: site.error_html_template || DEFAULT_ERROR_HTML_TEMPLATE,
			jsonFields: errorJsonFieldsFromRecord(site),
		},
		challengePage: {
			htmlTemplate: site.challenge_html_template || DEFAULT_CHALLENGE_HTML_TEMPLATE,
			templates: parseStoredChallengeTemplates(site.challenge_html_templates_json),
		},
		healthCheck: {
			enabled: site.health_check_enabled === 1,
			path: site.health_check_path ?? "/health",
			intervalSeconds: Number(site.health_check_interval_seconds ?? 10),
			timeoutMs: Number(site.health_check_timeout_ms ?? 3_000),
			failureThreshold: Number(site.health_check_failure_threshold ?? 3),
			recoveryThreshold: Number(site.health_check_recovery_threshold ?? 2),
			failureMode: site.health_check_failure_mode ?? "monitor",
			alerts: {
				enabled: site.health_alert_enabled === 1,
				provider: site.health_alert_provider ?? "generic",
				webhookConfigured: Boolean(site.health_alert_webhook_url),
				eventTypes: existingNotificationEventTypes(site),
			},
		},
		loadBalancer: {
			algorithm: site.load_balancing_algorithm ?? "failover",
			affinity: site.load_balancing_affinity !== 0,
		},
		outboundFetchProtocol: site.outbound_fetch_protocol ?? "http1",
		websocket: siteWebSocketPolicyView(site),
		http: siteHttpPolicyView(site),
		botPolicy: storedBotPolicy(site.bot_policy_json),
		networkPrivacyPolicy: storedNetworkPrivacyPolicy(site.network_privacy_policy_json),
		createdAt: Number(site.created_at),
		updatedAt: Number(site.updated_at),
	};
}

export async function createSite(input: SiteInput): Promise<{ site: SiteRecord; generatedSigningSecret: string | null }> {
	const publicHost = normalizePublicHost(input.publicHost);
	if (await repository.siteByPublicHost(publicHost)) throw new Error("A site with this public host already exists");
	const providedSecret = signingSecret(input.originSigningSecret);
	const generatedSigningSecret = providedSecret ? null : randomToken(48);
	const now = Date.now();
	const health = parseHealthCheck(input.healthCheck);
	const challengeAutoBan = parseChallengeAutoBan(input.challengeAutoBan);
	const loadBalancer = loadBalancerSettings(input.loadBalancer);
	if (health.alertEnabled && !health.webhookUrl) throw new Error("A webhook URL is required when health alerts are enabled");
	const originFields = resolveSiteOriginFields(input);
	const site: SiteRecord = {
		id: randomId("site"),
		name: requiredString(input.name, "Site name", 255),
		public_host: publicHost,
		origin_type: originFields.origin_type,
		origin_url: originFields.origin_url,
		origin_signing_secret: providedSecret ?? generatedSigningSecret!,
		ip_extraction_preset: parseIpExtractionPreset(input.ipExtractionPreset),
		enabled: enabledValue(input.enabled, true) ? 1 : 0,
		session_ttl_seconds: sessionTtl(input.sessionTtlSeconds, config.defaultSite.sessionTtlSeconds),
		challenge_policy_json: JSON.stringify(
			await normalizeChallengePolicyForStorage(
				parseChallengePolicy(input.challengePolicy, [{ provider: "pow-sha256", config: { difficulty: config.defaultSite.powDifficulty } }]),
			),
		),
		challenge_auto_ban_enabled: challengeAutoBan.enabled ? 1 : 0,
		challenge_auto_ban_max_failures: challengeAutoBan.maxFailures,
		challenge_auto_ban_seconds: challengeAutoBan.banSeconds,
		default_access_mode: defaultAccessMode(input.defaultAccessMode, config.defaultSite.accessMode),
		event_retention_days: eventRetentionDays(input.eventRetentionDays, config.eventRetentionDays),
		default_ip_action: parseDefaultNetworkAction(input.defaultIpAction, "inherit"),
		default_country_action: parseDefaultNetworkAction(input.defaultCountryAction, "inherit"),
		error_response_mode: validateErrorResponseMode(input.errorResponseMode, "json"),
		error_html_template: validateErrorHtmlTemplate(input.errorHtmlTemplate),
		challenge_html_template: validateChallengeHtmlTemplate(input.challengeHtmlTemplate),
		challenge_html_templates_json: JSON.stringify(parseChallengeHtmlTemplates(input.challengeHtmlTemplates)),
		health_check_enabled: health.enabled ? 1 : 0,
		health_check_path: health.path,
		health_check_interval_seconds: health.intervalSeconds,
		health_check_timeout_ms: health.timeoutMs,
		health_check_failure_threshold: health.failureThreshold,
		health_check_recovery_threshold: health.recoveryThreshold,
		health_check_failure_mode: health.failureMode,
		health_alert_enabled: health.alertEnabled ? 1 : 0,
		health_alert_provider: health.alertProvider,
		health_alert_webhook_url: health.webhookUrl ? await encryptSecret(health.webhookUrl) : null,
		health_alert_webhook_secret: health.webhookSecret ? await encryptSecret(health.webhookSecret) : null,
		notification_event_types_json: JSON.stringify(health.notificationEventTypes),
		load_balancing_algorithm: loadBalancer.algorithm,
		load_balancing_affinity: loadBalancer.affinity ? 1 : 0,
		outbound_fetch_protocol: outboundFetchProtocol(input.outboundFetchProtocol, "http1"),
		websocket_policy_json: serializeSiteWebSocketPolicy(input.websocket),
		http_policy_json: serializeSiteHttpPolicy(input.http),
		bot_policy_json: serializeBotPolicy(input.botPolicy),
		network_privacy_policy_json: serializeNetworkPrivacyPolicy(input.networkPrivacyPolicy),
		error_json_fields_json: JSON.stringify(validateErrorJsonFields(input.errorJsonFields, DEFAULT_ERROR_JSON_FIELDS)),
		created_at: now,
		updated_at: now,
	};
	await repository.insertSite(site);
	await repository.insertOrigin({
		id: randomId("origin"),
		site_id: site.id,
		name: `${site.name} primary`,
		origin_type: originFields.origin_type,
		origin_url: site.origin_url,
		static_index_file: originFields.static_index_file,
		static_spa_fallback: originFields.static_spa_fallback,
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
	});
	await repository.ensureTlsSettings(site.id, now);
	return { site, generatedSigningSecret };
}

/** A hostname change only needs to defer the HTTPS listener rebuild when this site actually has a certificate serving it over HTTPS. */
export function siteRestartRequired(existing: SiteRecord, updated: SiteRecord, hasCertificate: boolean): boolean {
	return updated.public_host !== existing.public_host && config.https.enabled && hasCertificate;
}

async function syncPrimaryOrigin(
	siteId: string,
	record: SiteRecord,
	staticFields: Pick<SiteOriginRecord, "static_index_file" | "static_spa_fallback">,
): Promise<void> {
	const primary = await repository.primaryOrigin(siteId);
	if (!primary) return;
	const originType = record.origin_type ?? "proxy";
	const typeChanged = primary.origin_type !== originType;
	if (
		typeChanged ||
		primary.origin_url !== record.origin_url ||
		primary.static_index_file !== staticFields.static_index_file ||
		primary.static_spa_fallback !== staticFields.static_spa_fallback ||
		(primary.name.endsWith(" primary") && primary.name !== `${record.name} primary`)
	) {
		await repository.updateOrigin({
			...primary,
			name: primary.name.endsWith(" primary") ? `${record.name} primary` : primary.name,
			origin_type: originType,
			origin_url: record.origin_url,
			...staticFields,
			...(typeChanged && originType === "static" ? { mtls_enabled: 0, mtls_certificate_pem: null, mtls_encrypted_private_key: null, mtls_ca_pem: null } : {}),
			updated_at: record.updated_at,
		});
	}
}

export async function updateSite(
	id: string,
	input: SiteInput,
	createdBy: string | null = null,
): Promise<{ site: SiteRecord; pendingChange: PendingChangeRecord | null }> {
	const existing = await repository.siteById(id);
	if (!existing) throw new Error("Site not found");
	const publicHost = normalizePublicHost(input.publicHost ?? existing.public_host);
	const conflict = await repository.siteByPublicHost(publicHost);
	if (conflict && conflict.id !== id) throw new Error("A site with this public host already exists");
	const existingPolicy = policyFromRecord(existing);
	const health = parseHealthCheck(input.healthCheck, existing);
	const challengeAutoBan = parseChallengeAutoBan(input.challengeAutoBan, existing);
	const loadBalancer = loadBalancerSettings(input.loadBalancer, existing);
	const encryptedWebhookUrl = health.clearWebhook ? null : health.webhookUrl ? await encryptSecret(health.webhookUrl) : existing.health_alert_webhook_url;
	if (health.alertEnabled && !encryptedWebhookUrl) throw new Error("A webhook URL is required when health alerts are enabled");
	const originFields = resolveSiteOriginFields(input, existing, await repository.primaryOrigin(id));
	const updated: SiteRecord = {
		...existing,
		name: requiredString(input.name ?? existing.name, "Site name", 255),
		public_host: publicHost,
		origin_type: originFields.origin_type,
		origin_url: originFields.origin_url,
		origin_signing_secret: signingSecret(input.originSigningSecret) ?? existing.origin_signing_secret,
		ip_extraction_preset: parseIpExtractionPreset(input.ipExtractionPreset, existing.ip_extraction_preset ?? "direct"),
		enabled: enabledValue(input.enabled, existing.enabled === 1) ? 1 : 0,
		session_ttl_seconds: sessionTtl(input.sessionTtlSeconds, existing.session_ttl_seconds),
		challenge_policy_json: JSON.stringify(await normalizeChallengePolicyForStorage(parseChallengePolicy(input.challengePolicy, existingPolicy))),
		challenge_auto_ban_enabled: challengeAutoBan.enabled ? 1 : 0,
		challenge_auto_ban_max_failures: challengeAutoBan.maxFailures,
		challenge_auto_ban_seconds: challengeAutoBan.banSeconds,
		default_access_mode: defaultAccessMode(input.defaultAccessMode, existing.default_access_mode ?? "challenge"),
		event_retention_days: eventRetentionDays(input.eventRetentionDays, existing.event_retention_days ?? config.eventRetentionDays),
		default_ip_action: parseDefaultNetworkAction(input.defaultIpAction, existing.default_ip_action ?? "inherit"),
		default_country_action: parseDefaultNetworkAction(input.defaultCountryAction, existing.default_country_action ?? "inherit"),
		error_response_mode: validateErrorResponseMode(input.errorResponseMode, existing.error_response_mode ?? "json"),
		error_html_template: validateErrorHtmlTemplate(input.errorHtmlTemplate, existing.error_html_template || DEFAULT_ERROR_HTML_TEMPLATE),
		challenge_html_template: validateChallengeHtmlTemplate(input.challengeHtmlTemplate, existing.challenge_html_template || DEFAULT_CHALLENGE_HTML_TEMPLATE),
		challenge_html_templates_json: JSON.stringify(parseChallengeHtmlTemplates(input.challengeHtmlTemplates, existing)),
		health_check_enabled: health.enabled ? 1 : 0,
		health_check_path: health.path,
		health_check_interval_seconds: health.intervalSeconds,
		health_check_timeout_ms: health.timeoutMs,
		health_check_failure_threshold: health.failureThreshold,
		health_check_recovery_threshold: health.recoveryThreshold,
		health_check_failure_mode: health.failureMode,
		health_alert_enabled: health.alertEnabled ? 1 : 0,
		health_alert_provider: health.alertProvider,
		health_alert_webhook_url: encryptedWebhookUrl,
		health_alert_webhook_secret: health.clearWebhook
			? null
			: health.webhookSecret
				? await encryptSecret(health.webhookSecret)
				: existing.health_alert_webhook_secret,
		notification_event_types_json: JSON.stringify(health.notificationEventTypes),
		load_balancing_algorithm: loadBalancer.algorithm,
		load_balancing_affinity: loadBalancer.affinity ? 1 : 0,
		outbound_fetch_protocol: outboundFetchProtocol(input.outboundFetchProtocol, existing.outbound_fetch_protocol ?? "http1"),
		websocket_policy_json: serializeSiteWebSocketPolicy(input.websocket, existing.websocket_policy_json),
		http_policy_json: serializeSiteHttpPolicy(input.http, existing.http_policy_json),
		bot_policy_json: serializeBotPolicy(input.botPolicy, existing.bot_policy_json),
		network_privacy_policy_json: serializeNetworkPrivacyPolicy(input.networkPrivacyPolicy, existing.network_privacy_policy_json),
		error_json_fields_json: JSON.stringify(validateErrorJsonFields(input.errorJsonFields, errorJsonFieldsFromRecord(existing))),
		updated_at: Date.now(),
	};
	const tlsSettings = await repository.ensureTlsSettings(id);
	const certificate = await repository.certificateBySite(id);
	if (updated.enabled === 1 && (tlsSettings.mode !== "disabled" || certificate)) {
		await assertTlsHostnameAvailable(updated);
	}
	if (
		updated.public_host !== existing.public_host &&
		certificate?.certificate_pem &&
		!certificateCoversHostname(certificate.certificate_pem, siteHostname(updated))
	) {
		throw new Error("The active certificate does not cover the new public hostname. Replace or remove the certificate before changing this hostname.");
	}

	const restartRequired = siteRestartRequired(existing, updated, Boolean(certificate));
	const applyAt = parseScheduleTime(input.effectiveAt);

	if (restartRequired && applyAt) {
		const existingPending = await currentPendingChange("site", id);
		if (existingPending) {
			throw new Error(`A hostname change is already scheduled for ${new Date(existingPending.apply_at).toLocaleString()}. Cancel or apply it first.`);
		}
		const deferred: SiteRecord = { ...updated, public_host: existing.public_host };
		await repository.updateSite(deferred);
		staticAssetCache.purge({ siteId: id });
		await syncPrimaryOrigin(id, deferred, originFields);
		const pendingChange = await stagePendingChange(
			"site",
			id,
			{ publicHost: updated.public_host },
			`Public host: ${existing.public_host} -> ${updated.public_host}`,
			applyAt,
			createdBy,
		);
		return { site: deferred, pendingChange };
	}

	await repository.updateSite(updated);
	staticAssetCache.purge({ siteId: id });
	await syncPrimaryOrigin(id, updated, originFields);
	return { site: updated, pendingChange: null };
}

export async function applyPendingSiteChange(siteId: string, changes: Record<string, unknown>): Promise<void> {
	const existing = await repository.siteById(siteId);
	if (!existing) return;
	const publicHost = normalizePublicHost(changes.publicHost ?? existing.public_host);
	const conflict = await repository.siteByPublicHost(publicHost);
	if (conflict && conflict.id !== siteId) throw new Error("A site with this public host already exists");
	const merged: SiteRecord = { ...existing, public_host: publicHost, updated_at: Date.now() };
	const certificate = await repository.certificateBySite(siteId);
	if (certificate?.certificate_pem && !certificateCoversHostname(certificate.certificate_pem, siteHostname(merged))) {
		throw new Error("The active certificate no longer covers the new public hostname");
	}
	await repository.updateSite(merged);
	staticAssetCache.purge({ siteId });
	await requestTlsReload();
}

export interface SiteNotificationPolicyView {
	enabled: boolean;
	provider: HealthAlertProvider;
	webhookConfigured: boolean;
	eventTypes: Record<NotificationEventType, boolean>;
}

function siteNotificationPolicyView(site: SiteRecord): SiteNotificationPolicyView {
	return {
		enabled: site.health_alert_enabled === 1,
		provider: site.health_alert_provider ?? "generic",
		webhookConfigured: Boolean(site.health_alert_webhook_url),
		eventTypes: existingNotificationEventTypes(site),
	};
}

export async function siteNotificationPolicy(id: string): Promise<SiteNotificationPolicyView> {
	const site = await repository.siteById(id);
	if (!site) throw new Error("Site not found");
	return siteNotificationPolicyView(site);
}

/**
 * Slim counterpart to updateSite that only touches the notification-related columns, so the
 * dedicated Notifications admin page can save without re-submitting (or re-validating TLS/origin
 * for) the rest of the site.
 */
export async function updateSiteNotificationPolicy(id: string, input: unknown): Promise<SiteNotificationPolicyView> {
	const existing = await repository.siteById(id);
	if (!existing) throw new Error("Site not found");
	const health = parseHealthCheck({ alerts: input }, existing);
	const encryptedWebhookUrl = health.clearWebhook ? null : health.webhookUrl ? await encryptSecret(health.webhookUrl) : existing.health_alert_webhook_url;
	if (health.alertEnabled && !encryptedWebhookUrl) throw new Error("A webhook URL is required when notifications are enabled");
	const updated: SiteRecord = {
		...existing,
		health_alert_enabled: health.alertEnabled ? 1 : 0,
		health_alert_provider: health.alertProvider,
		health_alert_webhook_url: encryptedWebhookUrl,
		health_alert_webhook_secret: health.clearWebhook
			? null
			: health.webhookSecret
				? await encryptSecret(health.webhookSecret)
				: existing.health_alert_webhook_secret,
		notification_event_types_json: JSON.stringify(health.notificationEventTypes),
		updated_at: Date.now(),
	};
	await repository.updateSite(updated);
	return siteNotificationPolicyView(updated);
}

export async function resolveSiteForHost(host: string): Promise<SiteRecord | null> {
	const normalized = normalizeHost(host);
	const direct = await repository.siteByHost(normalized);
	if (direct) return direct;

	let incomingHostname: string;
	try {
		incomingHostname = new URL(`http://${normalized}`).hostname.toLowerCase();
	} catch {
		return null;
	}

	// HTTPS SNI cannot distinguish sites by port. A hostname-only fallback is
	// safe only when exactly one enabled site uses that hostname. This also
	// makes hostname configurations with an explicit HTTP port reachable through
	// an HTTPS listener whose Host header is simply localhost.
	const matches = (await repository.allSites()).filter((site) => {
		if (site.enabled !== 1) return false;
		try {
			return new URL(`http://${site.public_host}`).hostname.toLowerCase() === incomingHostname;
		} catch {
			return false;
		}
	});
	return matches.length === 1 ? matches[0]! : null;
}

export async function seedDefaultSite(): Promise<void> {
	if (config.ha.enabled && config.ha.role === "replica") return;
	if (!config.seedDefaultSite || (await repository.allSites()).length) return;
	await createSite({
		name: config.defaultSite.name,
		publicHost: config.defaultSite.publicHost,
		originUrl: config.defaultSite.originUrl,
		enabled: true,
		sessionTtlSeconds: config.defaultSite.sessionTtlSeconds,
		challengePolicy: [{ provider: "pow-sha256", config: { difficulty: config.defaultSite.powDifficulty } }],
		defaultAccessMode: config.defaultSite.accessMode,
		eventRetentionDays: config.eventRetentionDays,
	});
}
