import { AsyncLocalStorage } from "node:async_hooks";

export type ProxyPreset = "direct" | "nginx" | "cloudflare" | "aws" | "development";
export type CookieSecureMode = "auto" | "always" | "never";
export type RequestTransport = "http" | "https";

const requestTransportContext = new AsyncLocalStorage<RequestTransport>();

function envNumber(name: string, fallback: number, min = Number.MIN_SAFE_INTEGER, max = Number.MAX_SAFE_INTEGER): number {
	const raw = process.env[name];
	if (!raw) return fallback;
	const value = Number(raw);
	if (!Number.isFinite(value) || value < min || value > max) {
		throw new Error(`${name} must be a number between ${min} and ${max}`);
	}
	return value;
}

function envBoolean(name: string, fallback: boolean): boolean {
	const raw = process.env[name];
	if (!raw) return fallback;
	if (["1", "true", "yes", "on"].includes(raw.toLowerCase())) return true;
	if (["0", "false", "no", "off"].includes(raw.toLowerCase())) return false;
	throw new Error(`${name} must be true or false`);
}

function proxyPreset(value: string | undefined): ProxyPreset {
	const preset = (value ?? "direct") as ProxyPreset;
	if (!["direct", "nginx", "cloudflare", "aws", "development"].includes(preset)) {
		throw new Error(`Unsupported BG_PROXY_PRESET: ${preset}`);
	}
	return preset;
}

function siteAccessMode(value: string | undefined): "challenge" | "bypass" {
	const mode = (value ?? "challenge").trim().toLowerCase();
	if (mode === "challenge" || mode === "bypass") return mode;
	throw new Error("BG_DEFAULT_ACCESS_MODE must be challenge or bypass");
}

function cookieSecureMode(value: string | undefined): CookieSecureMode {
	const normalized = (value ?? "auto").trim().toLowerCase();
	if (["auto"].includes(normalized)) return "auto";
	if (["1", "true", "yes", "on", "always"].includes(normalized)) return "always";
	if (["0", "false", "no", "off", "never"].includes(normalized)) return "never";
	throw new Error("BG_COOKIE_SECURE must be auto, true, or false");
}

const legacyPort = envNumber("BG_PORT", 80, 1, 65535);
const dataDirectory = process.env.BG_DATA_DIR?.trim() || "./data";

export const config = {
	environment: process.env.BG_ENV ?? "production",
	host: process.env.BG_HOST ?? "0.0.0.0",
	dataDirectory,
	// BG_PORT remains a backwards-compatible alias for the HTTP listener.
	port: legacyPort,
	http: {
		enabled: envBoolean("BG_HTTP_ENABLED", true),
		port: envNumber("BG_HTTP_PORT", legacyPort, 1, 65535),
		publicPort: envNumber("BG_HTTP_PUBLIC_PORT", 80, 1, 65535),
	},
	https: {
		enabled: envBoolean("BG_HTTPS_ENABLED", true),
		port: envNumber("BG_HTTPS_PORT", 443, 1, 65535),
		publicPort: envNumber("BG_HTTPS_PUBLIC_PORT", 443, 1, 65535),
		listenerDrainTimeoutMs: envNumber("BG_TLS_LISTENER_DRAIN_TIMEOUT_MS", 5_000, 100, 60_000),
	},
	databaseUrl: process.env.DATABASE_URL ?? "sqlite://./data/burrowgate.db",
	proxyPreset: proxyPreset(process.env.BG_PROXY_PRESET),
	cookieSecureMode: cookieSecureMode(process.env.BG_COOKIE_SECURE),
	originTimeoutMs: envNumber("BG_ORIGIN_TIMEOUT_MS", 30_000, 1_000, 300_000),
	websocket: {
		enabled: envBoolean("BG_WEBSOCKET_ENABLED", true),
		connectTimeoutMs: envNumber("BG_WEBSOCKET_CONNECT_TIMEOUT_MS", 15_000, 1_000, 120_000),
		idleTimeoutSeconds: envNumber("BG_WEBSOCKET_IDLE_TIMEOUT_SECONDS", 120, 10, 960),
		maxPayloadBytes: envNumber("BG_WEBSOCKET_MAX_PAYLOAD_BYTES", 16 * 1_024 * 1_024, 1_024, 256 * 1_024 * 1_024),
		backpressureLimitBytes: envNumber("BG_WEBSOCKET_BACKPRESSURE_LIMIT_BYTES", 16 * 1_024 * 1_024, 1_024, 256 * 1_024 * 1_024),
		upstreamBufferLimitBytes: envNumber("BG_WEBSOCKET_UPSTREAM_BUFFER_LIMIT_BYTES", 16 * 1_024 * 1_024, 1_024, 256 * 1_024 * 1_024),
		preOpenQueueLimitBytes: envNumber("BG_WEBSOCKET_PREOPEN_QUEUE_LIMIT_BYTES", 1 * 1_024 * 1_024, 1_024, 64 * 1_024 * 1_024),
	},
	challengeTtlSeconds: envNumber("BG_CHALLENGE_TTL_SECONDS", 180, 30, 86_400),
	challengeMinDisplayMs: envNumber("BG_CHALLENGE_MIN_DISPLAY_MS", 0, 0, 86_400_000),
	maxChallengeAttempts: envNumber("BG_MAX_CHALLENGE_ATTEMPTS", 8, 1, 100),
	eventRetentionDays: envNumber("BG_EVENT_RETENTION_DAYS", 7, 1, 365),
	bandwidth: {
		flushIntervalMs: envNumber("BG_BANDWIDTH_FLUSH_INTERVAL_MS", 10_000, 1_000, 300_000),
		maxPendingKeys: envNumber("BG_BANDWIDTH_MAX_PENDING_KEYS", 50_000, 100, 1_000_000),
	},
	accessLoginMaxFailureKeys: envNumber("BG_ACCESS_LOGIN_MAX_FAILURE_KEYS", 50_000, 100, 1_000_000),
	streams: {
		connectTimeoutSeconds: envNumber("BG_STREAM_CONNECT_TIMEOUT_SECONDS", 15, 1, 300),
		idleTimeoutSeconds: envNumber("BG_STREAM_IDLE_TIMEOUT_SECONDS", 300, 10, 86_400),
		udpPeerIdleTimeoutSeconds: envNumber("BG_STREAM_UDP_PEER_IDLE_TIMEOUT_SECONDS", 60, 5, 3_600),
		maxBufferedBytes: envNumber("BG_STREAM_MAX_BUFFERED_BYTES", 1 * 1_024 * 1_024, 1_024, 64 * 1_024 * 1_024),
		maxUdpPeersPerStream: envNumber("BG_STREAM_MAX_UDP_PEERS", 10_000, 1, 1_000_000),
		maxPendingDatagrams: envNumber("BG_STREAM_MAX_PENDING_DATAGRAMS", 256, 1, 65_536),
		maxPendingEvents: envNumber("BG_STREAM_MAX_PENDING_EVENTS", 100_000, 100, 1_000_000),
	},
	geoip: {
		enabled: envBoolean("BG_GEOIP_ENABLED", true),
		databasePath: process.env.BG_GEOIP_DATABASE_PATH?.trim() || `${dataDirectory}/geoip/GeoLite2-Country.mmdb`,
		cacheEntries: envNumber("BG_GEOIP_CACHE_ENTRIES", 4_096, 1, 1_000_000),
		backfillBatchSize: envNumber("BG_GEOIP_BACKFILL_BATCH_SIZE", 500, 0, 10_000),
		retrySeconds: envNumber("BG_GEOIP_RETRY_SECONDS", 30, 5, 3_600),
	},
	maintenance: {
		intervalSeconds: envNumber("BG_MAINTENANCE_INTERVAL_SECONDS", 3_600, 60, 86_400),
		cleanupIntervalSeconds: envNumber("BG_MAINTENANCE_CLEANUP_INTERVAL_SECONDS", 60, 10, 86_400),
		cleanupBatchSize: envNumber("BG_MAINTENANCE_CLEANUP_BATCH_SIZE", 250, 10, 1_000),
		cleanupPauseMs: envNumber("BG_MAINTENANCE_CLEANUP_PAUSE_MS", 25, 0, 5_000),
		cleanupTimeBudgetMs: envNumber("BG_MAINTENANCE_CLEANUP_TIME_BUDGET_MS", 5_000, 100, 60_000),
	},
	adminPageSize: envNumber("BG_ADMIN_PAGE_SIZE", 50, 10, 200),
	masterKey: process.env.BG_MASTER_KEY?.trim() || (null as string | null),
	masterKeyFile: process.env.BG_MASTER_KEY_FILE?.trim() || (null as string | null),
	bootstrapTls: envBoolean("BG_BOOTSTRAP_TLS_ENABLED", true),
	acme: {
		directoryUrl: process.env.BG_ACME_DIRECTORY_URL?.trim() || "https://acme-v02.api.letsencrypt.org/directory",
		email: process.env.BG_ACME_EMAIL?.trim() || null,
		checkIntervalSeconds: envNumber("BG_ACME_CHECK_INTERVAL_SECONDS", 43_200, 300, 86_400),
		renewBeforeDays: envNumber("BG_ACME_RENEW_BEFORE_DAYS", 30, 1, 60),
		challengeTtlSeconds: envNumber("BG_ACME_CHALLENGE_TTL_SECONDS", 900, 60, 3_600),
		skipInternalChallengeVerification: envBoolean("BG_ACME_SKIP_INTERNAL_CHALLENGE_VERIFICATION", false),
	},
	admin: {
		username: process.env.BG_ADMIN_USERNAME?.trim() || "admin",
		password: process.env.BG_ADMIN_PASSWORD?.trim() || "",
		sessionTtlSeconds: envNumber("BG_ADMIN_SESSION_TTL_SECONDS", 28_800, 300, 604_800),
	},
	seedDefaultSite: envBoolean("BG_SEED_DEFAULT_SITE", false),
	defaultSite: {
		name: process.env.BG_DEFAULT_SITE_NAME ?? "Default site",
		publicHost: (process.env.BG_DEFAULT_PUBLIC_HOST ?? "localhost").toLowerCase(),
		originUrl: process.env.BG_DEFAULT_ORIGIN ?? "http://127.0.0.1:3000",
		sessionTtlSeconds: envNumber("BG_DEFAULT_SESSION_TTL_SECONDS", 43_200, 60, 2_592_000),
		powDifficulty: envNumber("BG_DEFAULT_POW_DIFFICULTY", 18, 8, 63),
		accessMode: siteAccessMode(process.env.BG_DEFAULT_ACCESS_MODE),
	},
};

/**
 * Run request handling with the listener transport attached to the current
 * asynchronous execution context. This preserves Bun's original Request object
 * for server.requestIP() and WebSocket upgrades while avoiding dependence on
 * framework URL reconstruction or spoofable forwarded headers.
 */
export function withRequestTransport<T>(transport: RequestTransport, callback: () => T): T {
	return requestTransportContext.run(transport, callback);
}

export function requestTransport(request: Request): RequestTransport {
	const listenerTransport = requestTransportContext.getStore();
	if (listenerTransport) return listenerTransport;
	return new URL(request.url).protocol === "https:" ? "https" : "http";
}

export function requestIsSecure(request: Request): boolean {
	return requestTransport(request) === "https";
}

export function secureCookieForRequest(request: Request): boolean {
	if (config.cookieSecureMode === "always") return true;
	if (config.cookieSecureMode === "never") return false;
	return requestIsSecure(request);
}

export function cookieCanBeIssuedForRequest(request: Request): boolean {
	return config.cookieSecureMode !== "always" || requestIsSecure(request);
}

export function insecureCookieConfigurationMessage(): string {
	return "This request uses HTTP, but BG_COOKIE_SECURE is set to true/always. Use HTTPS or change BG_COOKIE_SECURE to auto if this site must support HTTP.";
}

export function visitorCookieName(secure: boolean): string {
	return secure ? "__Host-bg_session" : "bg_session";
}

export function adminCookieName(secure: boolean): string {
	return secure ? "__Host-bg_admin" : "bg_admin";
}

export const visitorCookieNames = ["__Host-bg_session", "bg_session"] as const;
export const adminCookieNames = ["__Host-bg_admin", "bg_admin"] as const;
