import { challengeRegistry } from "../challenges/index.ts";
import { config } from "../config.ts";
import { repository } from "../db/repository.ts";
import type { ChallengePolicyStep, DefaultNetworkAction, SiteAccessMode, SiteRecord } from "../types.ts";
import { randomId, randomToken } from "../utils/crypto.ts";
import { normalizeHost } from "../utils/http.ts";
import { assertTlsHostnameAvailable, certificateCoversHostname, siteHostname } from "./certificate-service.ts";

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
}

export interface SiteView {
	id: string;
	name: string;
	publicHost: string;
	originUrl: string;
	enabled: boolean;
	sessionTtlSeconds: number;
	challengePolicy: ChallengePolicyStep[];
	defaultAccessMode: SiteAccessMode;
	eventRetentionDays: number;
	defaultIpAction: DefaultNetworkAction;
	defaultCountryAction: DefaultNetworkAction;
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

export function siteView(site: SiteRecord): SiteView {
	return {
		id: site.id,
		name: site.name,
		publicHost: site.public_host,
		originUrl: site.origin_url,
		enabled: site.enabled === 1,
		sessionTtlSeconds: Number(site.session_ttl_seconds),
		challengePolicy: policyFromRecord(site),
		defaultAccessMode: site.default_access_mode ?? "challenge",
		eventRetentionDays: Number(site.event_retention_days ?? config.eventRetentionDays),
		defaultIpAction: site.default_ip_action ?? "inherit",
		defaultCountryAction: site.default_country_action ?? "inherit",
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
	const site: SiteRecord = {
		id: randomId("site"),
		name: requiredString(input.name, "Site name", 255),
		public_host: publicHost,
		origin_url: normalizeOriginUrl(input.originUrl),
		origin_signing_secret: providedSecret ?? generatedSigningSecret!,
		enabled: enabledValue(input.enabled, true) ? 1 : 0,
		session_ttl_seconds: sessionTtl(input.sessionTtlSeconds, config.defaultSite.sessionTtlSeconds),
		challenge_policy_json: JSON.stringify(
			parseChallengePolicy(input.challengePolicy, [{ provider: "pow-sha256", config: { difficulty: config.defaultSite.powDifficulty } }]),
		),
		default_access_mode: defaultAccessMode(input.defaultAccessMode, config.defaultSite.accessMode),
		event_retention_days: eventRetentionDays(input.eventRetentionDays, config.eventRetentionDays),
		default_ip_action: parseDefaultNetworkAction(input.defaultIpAction, "inherit"),
		default_country_action: parseDefaultNetworkAction(input.defaultCountryAction, "inherit"),
		created_at: now,
		updated_at: now,
	};
	await repository.insertSite(site);
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
	const updated: SiteRecord = {
		...existing,
		name: requiredString(input.name ?? existing.name, "Site name", 255),
		public_host: publicHost,
		origin_url: normalizeOriginUrl(input.originUrl ?? existing.origin_url),
		origin_signing_secret: signingSecret(input.originSigningSecret) ?? existing.origin_signing_secret,
		enabled: enabledValue(input.enabled, existing.enabled === 1) ? 1 : 0,
		session_ttl_seconds: sessionTtl(input.sessionTtlSeconds, existing.session_ttl_seconds),
		challenge_policy_json: JSON.stringify(parseChallengePolicy(input.challengePolicy, existingPolicy)),
		default_access_mode: defaultAccessMode(input.defaultAccessMode, existing.default_access_mode ?? "challenge"),
		event_retention_days: eventRetentionDays(input.eventRetentionDays, existing.event_retention_days ?? config.eventRetentionDays),
		default_ip_action: parseDefaultNetworkAction(input.defaultIpAction, existing.default_ip_action ?? "inherit"),
		default_country_action: parseDefaultNetworkAction(input.defaultCountryAction, existing.default_country_action ?? "inherit"),
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
	if (updated.event_retention_days < (existing.event_retention_days ?? config.eventRetentionDays)) {
		try {
			await repository.deleteEventsBeforeForSite(updated.id, Date.now() - updated.event_retention_days * 86_400_000);
		} catch (error) {
			console.error(`[BurrowGate] Immediate event-retention cleanup failed for ${updated.id}`, error);
		}
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
