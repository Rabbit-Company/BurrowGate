import { challengeRegistry } from "../challenges/index.ts";
import { config, parseIpExtractionPreset } from "../config.ts";
import { repository } from "../db/repository.ts";
import { Logger } from "../logger.ts";
import type {
	ChallengePolicyStep,
	DefaultNetworkAction,
	ErrorResponseMode,
	HealthAlertProvider,
	OriginHealthFailureMode,
	LoadBalancingAlgorithm,
	IpExtractionPreset,
	SiteAccessMode,
	SiteRecord,
} from "../types.ts";
import { randomId, randomToken } from "../utils/crypto.ts";
import { normalizeHost } from "../utils/http.ts";
import { assertTlsHostnameAvailable, certificateCoversHostname, siteHostname } from "./certificate-service.ts";
import {
	DEFAULT_ERROR_HTML_TEMPLATE,
	DEFAULT_ERROR_JSON_FIELDS,
	validateErrorHtmlTemplate,
	validateErrorJsonFields,
	validateErrorResponseMode,
	type ErrorJsonField,
} from "./error-response-service.ts";
import { DEFAULT_CHALLENGE_HTML_TEMPLATE, validateChallengeHtmlTemplate } from "./challenge-page-service.ts";
import { encryptSecret } from "./secret-encryption-service.ts";

export interface SiteInput {
	name?: unknown;
	publicHost?: unknown;
	originUrl?: unknown;
	enabled?: unknown;
	sessionTtlSeconds?: unknown;
	challengePolicy?: unknown;
	originSigningSecret?: unknown;
	defaultAccessMode?: unknown;
	eventRetentionDays?: unknown;
	defaultIpAction?: unknown;
	defaultCountryAction?: unknown;
	errorResponseMode?: unknown;
	errorHtmlTemplate?: unknown;
	challengeHtmlTemplate?: unknown;
	errorJsonFields?: unknown;
	healthCheck?: unknown;
	loadBalancer?: unknown;
	ipExtractionPreset?: unknown;
}

export interface SiteView {
	id: string;
	name: string;
	publicHost: string;
	originUrl: string;
	ipExtractionPreset: IpExtractionPreset;
	enabled: boolean;
	sessionTtlSeconds: number;
	challengePolicy: ChallengePolicyStep[];
	defaultAccessMode: SiteAccessMode;
	eventRetentionDays: number;
	defaultIpAction: DefaultNetworkAction;
	defaultCountryAction: DefaultNetworkAction;
	errorResponse: {
		mode: ErrorResponseMode;
		htmlTemplate: string;
		jsonFields: ErrorJsonField[];
	};
	challengePage: { htmlTemplate: string };
	healthCheck: {
		enabled: boolean;
		path: string;
		intervalSeconds: number;
		timeoutMs: number;
		failureThreshold: number;
		recoveryThreshold: number;
		failureMode: OriginHealthFailureMode;
		alerts: { enabled: boolean; provider: HealthAlertProvider; webhookConfigured: boolean };
	};
	loadBalancer: { algorithm: LoadBalancingAlgorithm; affinity: boolean };
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

function parseHealthCheck(value: unknown, existing?: SiteRecord): ParsedHealthCheck {
	if (value !== undefined && (!value || typeof value !== "object" || Array.isArray(value))) throw new Error("Health-check settings must be an object");
	const input = (value ?? {}) as Record<string, unknown>;
	const alertInput = input.alerts === undefined ? {} : input.alerts;
	if (!alertInput || typeof alertInput !== "object" || Array.isArray(alertInput)) throw new Error("Health alert settings must be an object");
	const alerts = alertInput as Record<string, unknown>;
	const clearWebhook = enabledValue(alerts.clearWebhook, false);
	const webhookSecret = String(alerts.webhookSecret ?? "").trim() || undefined;
	if (webhookSecret && webhookSecret.length > 4_096) throw new Error("Health alert webhook signing secret must be at most 4096 characters");
	return {
		enabled: enabledValue(input.enabled, existing?.health_check_enabled === 1),
		path: healthPath(input.path, existing?.health_check_path ?? "/health"),
		intervalSeconds: boundedInteger(input.intervalSeconds, existing?.health_check_interval_seconds ?? 30, "Health-check interval", 10, 3_600),
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

export function siteView(site: SiteRecord): SiteView {
	return {
		id: site.id,
		name: site.name,
		publicHost: site.public_host,
		originUrl: site.origin_url,
		ipExtractionPreset: site.ip_extraction_preset ?? "direct",
		enabled: site.enabled === 1,
		sessionTtlSeconds: Number(site.session_ttl_seconds),
		challengePolicy: policyFromRecord(site),
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
		},
		healthCheck: {
			enabled: site.health_check_enabled === 1,
			path: site.health_check_path ?? "/health",
			intervalSeconds: Number(site.health_check_interval_seconds ?? 30),
			timeoutMs: Number(site.health_check_timeout_ms ?? 3_000),
			failureThreshold: Number(site.health_check_failure_threshold ?? 3),
			recoveryThreshold: Number(site.health_check_recovery_threshold ?? 2),
			failureMode: site.health_check_failure_mode ?? "monitor",
			alerts: {
				enabled: site.health_alert_enabled === 1,
				provider: site.health_alert_provider ?? "generic",
				webhookConfigured: Boolean(site.health_alert_webhook_url),
			},
		},
		loadBalancer: {
			algorithm: site.load_balancing_algorithm ?? "failover",
			affinity: site.load_balancing_affinity !== 0,
		},
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
	const loadBalancer = loadBalancerSettings(input.loadBalancer);
	if (health.alertEnabled && !health.webhookUrl) throw new Error("A webhook URL is required when health alerts are enabled");
	const site: SiteRecord = {
		id: randomId("site"),
		name: requiredString(input.name, "Site name", 255),
		public_host: publicHost,
		origin_url: normalizeOriginUrl(input.originUrl),
		origin_signing_secret: providedSecret ?? generatedSigningSecret!,
		ip_extraction_preset: parseIpExtractionPreset(input.ipExtractionPreset),
		enabled: enabledValue(input.enabled, true) ? 1 : 0,
		session_ttl_seconds: sessionTtl(input.sessionTtlSeconds, config.defaultSite.sessionTtlSeconds),
		challenge_policy_json: JSON.stringify(
			parseChallengePolicy(input.challengePolicy, [{ provider: "pow-sha256", config: { difficulty: config.defaultSite.powDifficulty } }]),
		),
		default_access_mode: defaultAccessMode(input.defaultAccessMode, config.defaultSite.accessMode),
		event_retention_days: eventRetentionDays(input.eventRetentionDays, config.eventRetentionDays),
		default_ip_action: parseDefaultNetworkAction(input.defaultIpAction, "inherit"),
		default_country_action: parseDefaultNetworkAction(input.defaultCountryAction, "inherit"),
		error_response_mode: validateErrorResponseMode(input.errorResponseMode, "json"),
		error_html_template: validateErrorHtmlTemplate(input.errorHtmlTemplate),
		challenge_html_template: validateChallengeHtmlTemplate(input.challengeHtmlTemplate),
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
		load_balancing_algorithm: loadBalancer.algorithm,
		load_balancing_affinity: loadBalancer.affinity ? 1 : 0,
		error_json_fields_json: JSON.stringify(validateErrorJsonFields(input.errorJsonFields, DEFAULT_ERROR_JSON_FIELDS)),
		created_at: now,
		updated_at: now,
	};
	await repository.insertSite(site);
	await repository.insertOrigin({
		id: randomId("origin"),
		site_id: site.id,
		name: `${site.name} primary`,
		origin_url: site.origin_url,
		enabled: 1,
		draining: 0,
		priority: 0,
		weight: 1,
		health_check_path: null,
		is_primary: 1,
		created_at: now,
		updated_at: now,
	});
	await repository.ensureTlsSettings(site.id, now);
	return { site, generatedSigningSecret };
}

export async function updateSite(id: string, input: SiteInput): Promise<SiteRecord> {
	const existing = await repository.siteById(id);
	if (!existing) throw new Error("Site not found");
	const publicHost = normalizePublicHost(input.publicHost ?? existing.public_host);
	const conflict = await repository.siteByPublicHost(publicHost);
	if (conflict && conflict.id !== id) throw new Error("A site with this public host already exists");
	const existingPolicy = policyFromRecord(existing);
	const health = parseHealthCheck(input.healthCheck, existing);
	const loadBalancer = loadBalancerSettings(input.loadBalancer, existing);
	const encryptedWebhookUrl = health.clearWebhook ? null : health.webhookUrl ? await encryptSecret(health.webhookUrl) : existing.health_alert_webhook_url;
	if (health.alertEnabled && !encryptedWebhookUrl) throw new Error("A webhook URL is required when health alerts are enabled");
	const updated: SiteRecord = {
		...existing,
		name: requiredString(input.name ?? existing.name, "Site name", 255),
		public_host: publicHost,
		origin_url: normalizeOriginUrl(input.originUrl ?? existing.origin_url),
		origin_signing_secret: signingSecret(input.originSigningSecret) ?? existing.origin_signing_secret,
		ip_extraction_preset: parseIpExtractionPreset(input.ipExtractionPreset, existing.ip_extraction_preset ?? "direct"),
		enabled: enabledValue(input.enabled, existing.enabled === 1) ? 1 : 0,
		session_ttl_seconds: sessionTtl(input.sessionTtlSeconds, existing.session_ttl_seconds),
		challenge_policy_json: JSON.stringify(parseChallengePolicy(input.challengePolicy, existingPolicy)),
		default_access_mode: defaultAccessMode(input.defaultAccessMode, existing.default_access_mode ?? "challenge"),
		event_retention_days: eventRetentionDays(input.eventRetentionDays, existing.event_retention_days ?? config.eventRetentionDays),
		default_ip_action: parseDefaultNetworkAction(input.defaultIpAction, existing.default_ip_action ?? "inherit"),
		default_country_action: parseDefaultNetworkAction(input.defaultCountryAction, existing.default_country_action ?? "inherit"),
		error_response_mode: validateErrorResponseMode(input.errorResponseMode, existing.error_response_mode ?? "json"),
		error_html_template: validateErrorHtmlTemplate(input.errorHtmlTemplate, existing.error_html_template || DEFAULT_ERROR_HTML_TEMPLATE),
		challenge_html_template: validateChallengeHtmlTemplate(input.challengeHtmlTemplate, existing.challenge_html_template || DEFAULT_CHALLENGE_HTML_TEMPLATE),
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
		load_balancing_algorithm: loadBalancer.algorithm,
		load_balancing_affinity: loadBalancer.affinity ? 1 : 0,
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
	await repository.updateSite(updated);
	const primary = await repository.primaryOrigin(id);
	if (primary && (primary.origin_url !== updated.origin_url || (primary.name.endsWith(" primary") && primary.name !== `${updated.name} primary`))) {
		await repository.updateOrigin({
			...primary,
			name: primary.name.endsWith(" primary") ? `${updated.name} primary` : primary.name,
			origin_url: updated.origin_url,
			updated_at: updated.updated_at,
		});
	}
	return updated;
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
