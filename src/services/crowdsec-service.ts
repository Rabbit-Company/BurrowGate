import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import packageMetadata from "../../package.json" with { type: "json" };
import { config } from "../config.ts";
import { repository } from "../db/repository.ts";
import { Logger } from "../logger.ts";
import type { CrowdSecSettingsRecord, CrowdSecUnknownRemediation } from "../types.ts";
import { crowdSecDecisions, type CrowdSecDecision, type CrowdSecStoreStats, type RawCrowdSecDecision } from "./crowdsec-decision-store.ts";
import { normalizeAppSecUrl, type AppSecConnection } from "./crowdsec-appsec-service.ts";
import { notificationService } from "./notification-service.ts";
import { openMetrics } from "./openmetrics-service.ts";
import { decryptSecret, encryptSecret } from "./secret-encryption-service.ts";

/**
 * Pulls decisions from a CrowdSec Local API and keeps `crowdSecDecisions` current.
 *
 * Uses the streaming endpoint, not the per-request query endpoint. Live mode would put an HTTP
 * round-trip inside every request and make the LAPI a hard availability dependency of the proxy.
 *
 * Everything here fails open. An unreachable LAPI leaves the last known decisions in place, where
 * their own expiry ages them out, and boot never waits on it.
 */

const CACHE_DIRECTORY = join(config.dataDirectory, "crowdsec");
const SNAPSHOT_PATH = join(CACHE_DIRECTORY, "decisions.json");
const SNAPSHOT_VERSION = 1;
const USER_AGENT = `burrowgate/${packageMetadata.version}`;
const MAX_ERROR_LENGTH = 500;

export const CROWDSEC_SCOPE_OPTIONS = ["ip", "range", "country", "as"] as const;
export type CrowdSecScopeOption = (typeof CROWDSEC_SCOPE_OPTIONS)[number];

export interface CrowdSecStatus {
	enabled: boolean;
	configured: boolean;
	lapiUrl: string | null;
	apiKeyConfigured: boolean;
	verifyTls: boolean;
	pollIntervalSeconds: number;
	fullSyncIntervalSeconds: number;
	requestTimeoutMs: number;
	scopes: string[];
	unknownRemediation: CrowdSecUnknownRemediation;
	alertAfterMinutes: number;
	lastPolledAt: number | null;
	lastSuccessAt: number | null;
	lastPollStatus: "ok" | "error" | null;
	lastPollError: string | null;
	consecutiveFailures: number;
	nextPollIsFullSync: boolean;
	decisions: CrowdSecStoreStats;
	truncated: boolean;
	appsecUrl: string | null;
	appsecTimeoutMs: number;
	appsecFailOpen: boolean;
	appsecMaxBodyBytes: number;
}

export interface CrowdSecTestResult {
	ok: boolean;
	message: string;
	decisionCount?: number;
}

interface StreamResponse {
	new: RawCrowdSecDecision[];
	deleted: RawCrowdSecDecision[];
}

/** Trims a LAPI base URL to its origin-plus-prefix form. */
export function normalizeLapiUrl(value: unknown): string {
	const raw = String(value ?? "").trim();
	if (!raw) throw new Error("Enter the CrowdSec Local API URL");
	let parsed: URL;
	try {
		parsed = new URL(raw);
	} catch {
		throw new Error("The CrowdSec Local API URL must be a valid URL, for example http://127.0.0.1:8080");
	}
	if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
		throw new Error("The CrowdSec Local API URL must use http or https");
	}
	return `${parsed.origin}${parsed.pathname.replace(/\/+$/u, "")}`;
}

export function parseCrowdSecScopes(value: unknown, fallback = "ip,range"): string {
	if (value === undefined || value === null) return fallback;
	const list = Array.isArray(value) ? value : String(value).split(",");
	const selected: string[] = [];
	for (const entry of list) {
		const scope = String(entry).trim().toLowerCase();
		if (!scope) continue;
		if (!(CROWDSEC_SCOPE_OPTIONS as readonly string[]).includes(scope)) throw new Error(`Unsupported CrowdSec scope: ${scope}`);
		if (!selected.includes(scope)) selected.push(scope);
	}
	if (!selected.length) throw new Error("Select at least one CrowdSec decision scope");
	return selected.join(",");
}

export function parseUnknownRemediation(value: unknown, fallback: CrowdSecUnknownRemediation = "ban"): CrowdSecUnknownRemediation {
	if (value === undefined || value === null || value === "") return fallback;
	const normalized = String(value).trim().toLowerCase();
	if (normalized === "ban" || normalized === "captcha" || normalized === "ignore") return normalized;
	throw new Error("The fallback for unknown remediations must be ban, captcha, or ignore");
}

function boundedError(error: unknown): string {
	const message = error instanceof Error ? error.message : String(error);
	return message.slice(0, MAX_ERROR_LENGTH);
}

export class CrowdSecService {
	private timer: ReturnType<typeof setInterval> | null = null;
	private sweepTimer: ReturnType<typeof setInterval> | null = null;
	/** The poll currently in flight, if any. See `poll` for why this is shared rather than skipped. */
	private inFlight: Promise<void> | null = null;
	private settings: CrowdSecSettingsRecord | null = null;
	private timerIntervalSeconds = 0;

	/**
	 * Forces the next poll to be a full `startup=true` snapshot.
	 *
	 * The delta cursor is state on the LAPI's side, so anything interrupting the sequence (a
	 * CrowdSec restart, a network blip) leaves our copy subtly wrong until a snapshot resets it.
	 */
	private needsFullSync = true;
	private lastFullSyncAt = 0;
	private consecutiveFailures = 0;
	private failingSince: number | null = null;
	private downAlertSent = false;
	private truncated = false;
	/** Notified after a poll changes the decision set. Registered from index.ts to avoid an import cycle. */
	private changeListeners: Array<() => void | Promise<void>> = [];
	private appSec: (AppSecConnection & { failOpen: boolean; maxBodyBytes: number }) | null = null;

	async reload(): Promise<void> {
		this.settings = await repository.ensureCrowdSecSettings();
		this.needsFullSync = true;
		// Without this, a newly-pointed-at Local API inherits the old one's failure streak and can
		// fire a "down" notification on its very first poll.
		this.consecutiveFailures = 0;
		this.failingSince = null;
		this.downAlertSent = false;
		await this.refreshAppSecConnection();
		this.applyTimer();
	}

	private async refreshAppSecConnection(): Promise<void> {
		const settings = this.settings;
		if (!config.crowdsec.enabled || !settings || settings.enabled !== 1 || !settings.appsec_url || !settings.api_key_encrypted) {
			this.appSec = null;
			return;
		}
		try {
			this.appSec = {
				url: settings.appsec_url,
				apiKey: await decryptSecret(settings.api_key_encrypted),
				timeoutMs: settings.appsec_timeout_ms,
				verifyTls: settings.verify_tls === 1,
				failOpen: settings.appsec_fail_open !== 0,
				maxBodyBytes: settings.appsec_max_body_bytes,
			};
		} catch (error) {
			this.appSec = null;
			Logger.error("CrowdSec: unable to prepare the AppSec connection", { error });
		}
	}

	private active(settings: CrowdSecSettingsRecord | null): settings is CrowdSecSettingsRecord {
		return config.crowdsec.enabled && settings !== null && settings.enabled === 1 && !!settings.lapi_url && !!settings.api_key_encrypted;
	}

	private applyTimer(): void {
		const settings = this.settings;
		if (!this.active(settings)) {
			if (this.timer) {
				clearInterval(this.timer);
				this.timer = null;
				this.timerIntervalSeconds = 0;
			}
			// Enforcement stops on disable rather than lingering until the decisions expire.
			crowdSecDecisions.clear();
			this.publishMetrics();
			return;
		}
		if (this.timer && this.timerIntervalSeconds === settings.poll_interval_seconds) return;
		if (this.timer) clearInterval(this.timer);
		this.timerIntervalSeconds = settings.poll_interval_seconds;
		this.timer = setInterval(() => void this.poll(), settings.poll_interval_seconds * 1_000);
		(this.timer as unknown as { unref?: () => void }).unref?.();
		void this.poll();
	}

	/**
	 * Restores the last snapshot from disk, then starts polling. The snapshot is what keeps a
	 * restart from opening a hole when the LAPI is also down.
	 */
	async start(): Promise<void> {
		if (!config.crowdsec.enabled) return;
		try {
			this.settings = await repository.ensureCrowdSecSettings();
		} catch (error) {
			Logger.error("CrowdSec: unable to load settings", { error });
			return;
		}
		if (this.active(this.settings)) await this.restoreSnapshot();
		await this.refreshAppSecConnection();
		this.applyTimer();
		if (!this.sweepTimer) {
			this.sweepTimer = setInterval(() => {
				const removed = crowdSecDecisions.sweepExpired();
				if (removed) Logger.debug(`CrowdSec: swept ${removed} expired decisions`);
			}, config.crowdsec.sweepIntervalMs);
			(this.sweepTimer as unknown as { unref?: () => void }).unref?.();
		}
	}

	stop(): void {
		if (this.timer) clearInterval(this.timer);
		if (this.sweepTimer) clearInterval(this.sweepTimer);
		this.timer = null;
		this.sweepTimer = null;
		this.timerIntervalSeconds = 0;
	}

	private async apiKey(settings: CrowdSecSettingsRecord): Promise<string> {
		if (!settings.api_key_encrypted) throw new Error("No CrowdSec bouncer API key is configured");
		return await decryptSecret(settings.api_key_encrypted);
	}

	private async request(settings: CrowdSecSettingsRecord, path: string, apiKey: string): Promise<Response> {
		const url = `${settings.lapi_url}${path}`;
		return await fetch(url, {
			method: "GET",
			headers: {
				"x-api-key": apiKey,
				accept: "application/json",
				"user-agent": USER_AGENT,
			},
			tls: { rejectUnauthorized: settings.verify_tls === 1 },
			signal: AbortSignal.timeout(settings.request_timeout_ms),
		} as RequestInit & { tls?: { rejectUnauthorized: boolean } });
	}

	/** The LAPI sends `null`, not `[]`, for an empty side of a delta, so both arrays are normalised. */
	private async readStream(response: Response): Promise<StreamResponse> {
		const body = (await response.json()) as { new?: unknown; deleted?: unknown } | null;
		return {
			new: Array.isArray(body?.new) ? (body.new as RawCrowdSecDecision[]) : [],
			deleted: Array.isArray(body?.deleted) ? (body.deleted as RawCrowdSecDecision[]) : [],
		};
	}

	private describeHttpFailure(status: number): string {
		if (status === 401 || status === 403) return `The CrowdSec Local API rejected the bouncer API key (HTTP ${status})`;
		if (status === 404) return "The CrowdSec Local API has no /v1/decisions/stream endpoint at that URL (HTTP 404)";
		return `The CrowdSec Local API returned HTTP ${status}`;
	}

	/**
	 * Runs one poll. A call made while another is running joins it rather than starting a second,
	 * so polls cannot pile up while callers still await a real result instead of a no-op.
	 */
	async poll(): Promise<void> {
		if (this.inFlight) return await this.inFlight;
		if (!this.active(this.settings)) return;
		this.inFlight = this.runPoll();
		try {
			await this.inFlight;
		} finally {
			this.inFlight = null;
		}
	}

	private async runPoll(): Promise<void> {
		const settings = this.settings;
		if (!this.active(settings)) return;
		const startedAt = Date.now();

		try {
			const apiKey = await this.apiKey(settings);
			const dueForFullSync = Date.now() - this.lastFullSyncAt >= settings.full_sync_interval_seconds * 1_000;
			const startup = this.needsFullSync || dueForFullSync;
			const scopes = encodeURIComponent(settings.scopes);
			const response = await this.request(settings, `/v1/decisions/stream?startup=${startup}&scopes=${scopes}`, apiKey);
			if (!response.ok) throw new Error(this.describeHttpFailure(response.status));

			const stream = await this.readStream(response);
			let changed = false;
			if (startup) {
				const capped = this.cap(stream.new);
				await crowdSecDecisions.applySnapshotYielding(capped, Date.now(), settings.unknown_remediation, config.crowdsec.snapshotChunkSize);
				this.lastFullSyncAt = Date.now();
				changed = true;
				Logger.info(`CrowdSec: loaded a full snapshot of ${crowdSecDecisions.stats().total} decisions`);
			} else {
				const { added, removed } = crowdSecDecisions.applyDelta(stream.new, stream.deleted, Date.now(), settings.unknown_remediation);
				changed = added > 0;
				if (added || removed) Logger.debug(`CrowdSec: applied delta (+${added} / -${removed})`);
			}

			this.needsFullSync = false;
			await this.onSuccess(startedAt, startup);
			// Only new decisions can newly block something, so a delete-only delta needs no sweep.
			if (changed) await this.notifyDecisionsChanged();
		} catch (error) {
			// Any failure invalidates the delta sequence, so the next poll starts over from a snapshot.
			this.needsFullSync = true;
			await this.onFailure(startedAt, error);
		}
	}

	/** Applies the in-memory decision ceiling, so a runaway blocklist cannot exhaust the heap. */
	private cap(decisions: RawCrowdSecDecision[]): RawCrowdSecDecision[] {
		if (decisions.length <= config.crowdsec.maxDecisions) {
			this.truncated = false;
			return decisions;
		}
		this.truncated = true;
		Logger.warn(
			`CrowdSec: the Local API returned ${decisions.length} decisions, above the ${config.crowdsec.maxDecisions} ceiling; keeping the first ${config.crowdsec.maxDecisions}. Raise BG_CROWDSEC_MAX_DECISIONS or narrow the blocklist subscriptions.`,
		);
		return decisions.slice(0, config.crowdsec.maxDecisions);
	}

	private async onSuccess(startedAt: number, wasFullSync: boolean): Promise<void> {
		const recovered = this.downAlertSent;
		const failures = this.consecutiveFailures;
		this.consecutiveFailures = 0;
		this.failingSince = null;
		this.downAlertSent = false;

		const total = crowdSecDecisions.stats().total;
		await repository.updateCrowdSecPollResult(startedAt, Date.now(), "ok", null, total).catch((error) => {
			Logger.warn("CrowdSec: unable to record the poll result", { error });
		});
		if (this.settings) {
			this.settings.last_polled_at = startedAt;
			this.settings.last_success_at = Date.now();
			this.settings.last_poll_status = "ok";
			this.settings.last_poll_error = null;
			this.settings.last_decision_count = total;
		}

		openMetrics.recordCrowdSecPoll("ok");
		this.publishMetrics();

		if (recovered) {
			Logger.info(`CrowdSec: the Local API is reachable again after ${failures} failed polls`);
			await notificationService
				.recordGlobalEvent("crowdsec_lapi_up", "info", `CrowdSec Local API reachable again; ${total} decisions loaded.`, { decisions: total }, Date.now())
				.catch((error) => Logger.warn("CrowdSec: unable to record the recovery notification", { error }));
		}
		if (wasFullSync) await this.persistSnapshot();
	}

	private async onFailure(startedAt: number, error: unknown): Promise<void> {
		this.consecutiveFailures += 1;
		this.failingSince ??= startedAt;
		const message = boundedError(error);

		// First failure at warn, the rest at debug, so an hour-long outage is not hundreds of warnings.
		if (this.consecutiveFailures === 1) Logger.warn("CrowdSec: poll failed; keeping the decisions already loaded", { error: message });
		else Logger.debug(`CrowdSec: poll failed (${this.consecutiveFailures} in a row)`, { error: message });

		await repository
			.updateCrowdSecPollResult(startedAt, this.settings?.last_success_at ?? null, "error", message, crowdSecDecisions.stats().total)
			.catch(() => undefined);
		if (this.settings) {
			this.settings.last_polled_at = startedAt;
			this.settings.last_poll_status = "error";
			this.settings.last_poll_error = message;
		}

		openMetrics.recordCrowdSecPoll("error");
		this.publishMetrics();

		const alertAfterMinutes = this.settings?.alert_after_minutes ?? 0;
		if (alertAfterMinutes > 0 && !this.downAlertSent && this.failingSince !== null && Date.now() - this.failingSince >= alertAfterMinutes * 60_000) {
			this.downAlertSent = true;
			const minutes = Math.round((Date.now() - this.failingSince) / 60_000);
			await notificationService
				.recordGlobalEvent(
					"crowdsec_lapi_down",
					"warning",
					`CrowdSec Local API unreachable for ${minutes} minutes. BurrowGate is still enforcing the last decisions it loaded.`,
					{ error: message, failures: this.consecutiveFailures, decisions: crowdSecDecisions.stats().total },
					Date.now(),
				)
				.catch((notifyError) => Logger.warn("CrowdSec: unable to record the outage notification", { error: notifyError }));
		}
	}

	private async persistSnapshot(): Promise<void> {
		try {
			const decisions = crowdSecDecisions.export();
			const payload = JSON.stringify({ version: SNAPSHOT_VERSION, savedAt: Date.now(), decisions });
			await mkdir(CACHE_DIRECTORY, { recursive: true, mode: 0o700 });
			const temporaryPath = `${SNAPSHOT_PATH}.${process.pid}.tmp`;
			await writeFile(temporaryPath, payload, { encoding: "utf8", mode: 0o600 });
			await rename(temporaryPath, SNAPSHOT_PATH);
		} catch (error) {
			Logger.warn("CrowdSec: unable to persist the decision snapshot", { error });
		}
	}

	/**
	 * Stored expiries are absolute, so they go back as `until` timestamps and the store drops
	 * anything that lapsed while the process was down.
	 */
	private async restoreSnapshot(): Promise<void> {
		try {
			const parsed = JSON.parse(await readFile(SNAPSHOT_PATH, "utf8")) as { version?: number; decisions?: CrowdSecDecision[] };
			if (parsed.version !== SNAPSHOT_VERSION || !Array.isArray(parsed.decisions)) return;
			const raw: RawCrowdSecDecision[] = parsed.decisions.map((entry) => ({
				id: entry.id,
				type: entry.remediation,
				scope: entry.scope,
				value: entry.value,
				origin: entry.origin,
				scenario: entry.scenario,
				until: entry.expiresAt === null ? undefined : new Date(entry.expiresAt).toISOString(),
			}));
			const loaded = await crowdSecDecisions.applySnapshotYielding(raw, Date.now(), "ban", config.crowdsec.snapshotChunkSize);
			if (loaded) Logger.info(`CrowdSec: restored ${loaded} decisions from the last snapshot while the first poll runs`);
		} catch {
			// No snapshot yet, or an unreadable one. The first poll will build a fresh set.
		}
	}

	/** Verifies a candidate configuration without storing it. */
	async testConnection(lapiUrl: string, apiKey: string | null, verifyTls: boolean, timeoutMs = 5_000): Promise<CrowdSecTestResult> {
		try {
			const existing = await repository.ensureCrowdSecSettings();
			const probe: CrowdSecSettingsRecord = {
				...existing,
				lapi_url: normalizeLapiUrl(lapiUrl),
				verify_tls: verifyTls ? 1 : 0,
				request_timeout_ms: timeoutMs,
			};
			const key = await this.resolveApiKey(apiKey);
			if (!key) return { ok: false, message: "No bouncer API key is configured yet. Paste one above to test the connection." };
			const response = await this.request(probe, "/v1/decisions/stream?startup=true&scopes=ip,range", key);
			if (!response.ok) return { ok: false, message: this.describeHttpFailure(response.status) };
			const stream = await this.readStream(response);
			return { ok: true, message: `Connected. The Local API is currently serving ${stream.new.length} decisions.`, decisionCount: stream.new.length };
		} catch (error) {
			return { ok: false, message: boundedError(error) };
		}
	}

	/**
	 * The key to test with: whatever was typed into the form, falling back to the stored one.
	 *
	 * The stored key is still never sent to the browser. It does not need to be, because the test
	 * runs on the server, which already holds it.
	 */
	async resolveApiKey(supplied: string | null | undefined): Promise<string | null> {
		const typed = supplied?.trim();
		if (typed) return typed;
		const settings = this.settings ?? (await repository.ensureCrowdSecSettings());
		if (!settings.api_key_encrypted) return null;
		try {
			return await decryptSecret(settings.api_key_encrypted);
		} catch (error) {
			Logger.error("CrowdSec: unable to decrypt the stored API key", { error });
			return null;
		}
	}

	onDecisionsChanged(listener: () => void | Promise<void>): void {
		this.changeListeners.push(listener);
	}

	private publishMetrics(): void {
		const stats = crowdSecDecisions.stats();
		openMetrics.setCrowdSecState({
			enabled: this.active(this.settings),
			lastPolledAt: this.settings?.last_polled_at ?? null,
			lastSuccessAt: this.settings?.last_success_at ?? null,
			decisionsByScope: stats.byScope,
		});
	}

	private async notifyDecisionsChanged(): Promise<void> {
		for (const listener of this.changeListeners) {
			try {
				await listener();
			} catch (error) {
				Logger.error("CrowdSec: a decision-change listener failed", { error });
			}
		}
	}

	/** Backs the admin "Refresh now" button. */
	async refreshNow(): Promise<void> {
		this.needsFullSync = true;
		await this.poll();
	}

	status(): CrowdSecStatus {
		const settings = this.settings;
		return {
			enabled: config.crowdsec.enabled && settings?.enabled === 1,
			configured: !!settings?.lapi_url && !!settings?.api_key_encrypted,
			lapiUrl: settings?.lapi_url ?? null,
			apiKeyConfigured: !!settings?.api_key_encrypted,
			verifyTls: settings?.verify_tls !== 0,
			pollIntervalSeconds: settings?.poll_interval_seconds ?? 10,
			fullSyncIntervalSeconds: settings?.full_sync_interval_seconds ?? 1_800,
			requestTimeoutMs: settings?.request_timeout_ms ?? 5_000,
			scopes: (settings?.scopes ?? "ip,range").split(","),
			unknownRemediation: settings?.unknown_remediation ?? "ban",
			alertAfterMinutes: settings?.alert_after_minutes ?? 15,
			lastPolledAt: settings?.last_polled_at ?? null,
			lastSuccessAt: settings?.last_success_at ?? null,
			lastPollStatus: settings?.last_poll_status ?? null,
			lastPollError: settings?.last_poll_error ?? null,
			consecutiveFailures: this.consecutiveFailures,
			nextPollIsFullSync: this.needsFullSync,
			decisions: crowdSecDecisions.stats(),
			truncated: this.truncated,
			appsecUrl: settings?.appsec_url ?? null,
			appsecTimeoutMs: settings?.appsec_timeout_ms ?? 200,
			appsecFailOpen: settings?.appsec_fail_open !== 0,
			appsecMaxBodyBytes: settings?.appsec_max_body_bytes ?? 65_536,
		};
	}

	/**
	 * The AppSec connection for the request path, or null when it is not usable.
	 *
	 * Cached in memory so the hot path never touches the database, and the key is decrypted once
	 * per settings reload rather than once per request.
	 */
	appSecConnection(): (AppSecConnection & { failOpen: boolean; maxBodyBytes: number }) | null {
		return this.appSec;
	}

	/** Backs the admin page's lookup box. */
	lookup(ip: string, countryCode: string | null, asn: number | null): CrowdSecDecision | null {
		return crowdSecDecisions.lookup(ip, countryCode, asn);
	}
}

export const crowdSecService = new CrowdSecService();

export interface CrowdSecSettingsInput {
	enabled?: unknown;
	lapiUrl?: unknown;
	apiKey?: unknown;
	verifyTls?: unknown;
	pollIntervalSeconds?: unknown;
	fullSyncIntervalSeconds?: unknown;
	requestTimeoutMs?: unknown;
	scopes?: unknown;
	unknownRemediation?: unknown;
	alertAfterMinutes?: unknown;
	appsecUrl?: unknown;
	appsecTimeoutMs?: unknown;
	appsecFailOpen?: unknown;
	appsecMaxBodyBytes?: unknown;
}

function boundedInteger(value: unknown, fallback: number, minimum: number, maximum: number, label: string): number {
	if (value === undefined || value === null || value === "") return fallback;
	const parsed = Number(value);
	if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
		throw new Error(`${label} must be a whole number between ${minimum} and ${maximum}`);
	}
	return parsed;
}

function booleanish(value: unknown, fallback: boolean): boolean {
	if (value === undefined || value === null || value === "") return fallback;
	if (typeof value === "boolean") return value;
	const normalized = String(value).trim().toLowerCase();
	if (["1", "true", "yes", "on"].includes(normalized)) return true;
	if (["0", "false", "no", "off"].includes(normalized)) return false;
	throw new Error("Expected a true or false value");
}

/**
 * Validates and stores the settings, then reloads the poller. The API key is write-only: omitting
 * it keeps the stored one, and it is never sent back out.
 */
export async function saveCrowdSecSettings(input: CrowdSecSettingsInput): Promise<CrowdSecStatus> {
	const existing = await repository.ensureCrowdSecSettings();
	const enabled = booleanish(input.enabled, existing.enabled === 1);

	const lapiUrl = input.lapiUrl === undefined || input.lapiUrl === null ? existing.lapi_url : normalizeLapiUrl(input.lapiUrl);
	const apiKeyInput = typeof input.apiKey === "string" ? input.apiKey.trim() : "";
	const apiKeyEncrypted = apiKeyInput ? await encryptSecret(apiKeyInput) : existing.api_key_encrypted;

	if (enabled && !lapiUrl) throw new Error("Set the CrowdSec Local API URL before enabling the integration");
	if (enabled && !apiKeyEncrypted) throw new Error("Add a CrowdSec bouncer API key before enabling the integration");

	const record: CrowdSecSettingsRecord = {
		...existing,
		enabled: enabled ? 1 : 0,
		lapi_url: lapiUrl,
		api_key_encrypted: apiKeyEncrypted,
		verify_tls: booleanish(input.verifyTls, existing.verify_tls === 1) ? 1 : 0,
		poll_interval_seconds: boundedInteger(input.pollIntervalSeconds, existing.poll_interval_seconds, 2, 3_600, "The poll interval"),
		full_sync_interval_seconds: boundedInteger(input.fullSyncIntervalSeconds, existing.full_sync_interval_seconds, 60, 86_400, "The full resync interval"),
		request_timeout_ms: boundedInteger(input.requestTimeoutMs, existing.request_timeout_ms, 500, 60_000, "The request timeout"),
		scopes: parseCrowdSecScopes(input.scopes, existing.scopes),
		unknown_remediation: parseUnknownRemediation(input.unknownRemediation, existing.unknown_remediation),
		alert_after_minutes: boundedInteger(input.alertAfterMinutes, existing.alert_after_minutes, 0, 1_440, "The outage alert delay"),
		// An empty string clears the URL, which switches AppSec off without touching any site policy.
		appsec_url:
			input.appsecUrl === undefined || input.appsecUrl === null
				? existing.appsec_url
				: String(input.appsecUrl).trim() === ""
					? null
					: normalizeAppSecUrl(input.appsecUrl),
		appsec_timeout_ms: boundedInteger(input.appsecTimeoutMs, existing.appsec_timeout_ms, 10, 10_000, "The AppSec timeout"),
		appsec_fail_open: booleanish(input.appsecFailOpen, existing.appsec_fail_open !== 0) ? 1 : 0,
		appsec_max_body_bytes: boundedInteger(input.appsecMaxBodyBytes, existing.appsec_max_body_bytes, 0, 10_485_760, "The AppSec body limit"),
		updated_at: Date.now(),
	};

	await repository.saveCrowdSecSettings(record);
	await crowdSecService.reload();
	return crowdSecService.status();
}
