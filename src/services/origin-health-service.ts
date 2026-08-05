import { repository } from "../db/repository.ts";
import { Logger } from "../logger.ts";
import type {
	HealthAlertOutboxRecord,
	OriginBackendHealthEventRecord,
	OriginBackendHealthStatusRecord,
	OriginHealthEventRecord,
	OriginHealthState,
	OriginHealthStatusRecord,
	SiteOriginRecord,
	SiteRecord,
} from "../types.ts";
import { hmacSha256Hex, randomId } from "../utils/crypto.ts";
import { decryptSecret } from "./secret-encryption-service.ts";
import { openMetrics } from "./openmetrics-service.ts";

const TICK_MS = 1_000;
const STATUS_PERSIST_INTERVAL_MS = 5 * 60_000;
const MAX_CONCURRENT_CHECKS = 10;
const ALERT_POLL_MS = 2_000;
const MAX_ALERT_ATTEMPTS = 8;

export interface HealthCheckResult {
	healthy: boolean;
	status: number | null;
	latencyMs: number;
	error: string | null;
	checkedAt: number;
}

interface RuntimeOriginHealth {
	site: SiteRecord;
	origin: SiteOriginRecord;
	status: OriginBackendHealthStatusRecord;
	nextCheckAt: number;
	running: boolean;
	lastPersistedAt: number;
	settingsKey: string;
}

export function originHealthTarget(originUrl: string, path: string): URL {
	const origin = new URL(originUrl);
	return new URL(path, origin.origin);
}

export function advanceOriginHealthState(
	current: OriginHealthStatusRecord,
	result: HealthCheckResult,
	failureThreshold: number,
	recoveryThreshold: number,
): OriginHealthStatusRecord {
	const next: OriginHealthStatusRecord = {
		...current,
		last_checked_at: result.checkedAt,
		last_status: result.status,
		last_latency_ms: Math.max(0, Math.round(result.latencyMs)),
		last_error: result.error,
		updated_at: result.checkedAt,
	};
	if (result.healthy) {
		next.consecutive_failures = 0;
		next.consecutive_successes = current.consecutive_successes + 1;
		next.last_healthy_at = result.checkedAt;
		if (current.state === "unhealthy") next.state = next.consecutive_successes >= recoveryThreshold ? "healthy" : "unhealthy";
		else next.state = next.consecutive_successes >= recoveryThreshold ? "healthy" : "degraded";
		return next;
	}
	next.consecutive_successes = 0;
	next.consecutive_failures = current.consecutive_failures + 1;
	if (next.consecutive_failures >= failureThreshold) {
		next.state = "unhealthy";
		if (current.state !== "unhealthy") next.last_unhealthy_at = result.checkedAt;
	} else {
		next.state = current.state === "unhealthy" ? "unhealthy" : "degraded";
	}
	return next;
}

function emptyStatus(siteId: string, state: OriginHealthState, now = Date.now()): OriginHealthStatusRecord {
	return {
		site_id: siteId,
		state,
		consecutive_failures: 0,
		consecutive_successes: 0,
		last_checked_at: null,
		last_healthy_at: null,
		last_unhealthy_at: null,
		last_status: null,
		last_latency_ms: null,
		last_error: null,
		updated_at: now,
	};
}

function emptyBackendStatus(origin: SiteOriginRecord, state: OriginHealthState, now = Date.now()): OriginBackendHealthStatusRecord {
	return { ...emptyStatus(origin.site_id, state, now), origin_id: origin.id };
}

/** Preserve a confirmed incident across origin configuration changes. */
export function healthStatusAfterConfigurationChange(
	siteId: string,
	current: OriginHealthStatusRecord | undefined,
	enabled: boolean,
	now = Date.now(),
): OriginHealthStatusRecord {
	if (!current) return emptyStatus(siteId, enabled ? "unknown" : "disabled", now);
	return {
		...current,
		state: enabled ? (current.state === "unhealthy" ? "unhealthy" : "unknown") : "disabled",
		consecutive_failures: 0,
		consecutive_successes: 0,
		updated_at: now,
	};
}

function settingsKey(site: SiteRecord, origin: SiteOriginRecord): string {
	return [
		site.enabled,
		site.health_check_enabled,
		site.health_check_path,
		site.health_check_interval_seconds,
		site.health_check_timeout_ms,
		site.health_check_failure_threshold,
		site.health_check_recovery_threshold,
		origin.enabled,
		origin.origin_url,
		origin.health_check_path,
	].join("\n");
}

function boundedError(error: unknown, maximum = 1_000): string {
	const message = error instanceof Error ? error.message : String(error);
	return message.slice(0, maximum);
}

function jitter(intervalMs: number): number {
	return Math.round(intervalMs * (0.9 + Math.random() * 0.2));
}

function healthSummary(status: OriginHealthStatusRecord) {
	return {
		state: status.state,
		consecutiveFailures: Number(status.consecutive_failures),
		consecutiveSuccesses: Number(status.consecutive_successes),
		lastCheckedAt: status.last_checked_at === null ? null : Number(status.last_checked_at),
		lastHealthyAt: status.last_healthy_at === null ? null : Number(status.last_healthy_at),
		lastUnhealthyAt: status.last_unhealthy_at === null ? null : Number(status.last_unhealthy_at),
		lastStatus: status.last_status === null ? null : Number(status.last_status),
		lastLatencyMs: status.last_latency_ms === null ? null : Number(status.last_latency_ms),
		lastError: status.last_error,
	};
}

function aggregateState(statuses: OriginBackendHealthStatusRecord[], healthEnabled: boolean): OriginHealthState {
	if (!healthEnabled) return "disabled";
	if (statuses.length === 0) return "unhealthy";
	if (statuses.some((status) => status.state === "healthy")) return "healthy";
	if (statuses.some((status) => status.state === "degraded")) return "degraded";
	if (statuses.some((status) => status.state === "unknown" || status.state === "disabled")) return "unknown";
	return "unhealthy";
}

export class OriginHealthManager {
	private readonly runtime = new Map<string, RuntimeOriginHealth>();
	private readonly poolStatuses = new Map<string, OriginHealthStatusRecord>();
	private activeChecks = 0;
	private alertWorkerRunning = false;

	async initialize(): Promise<void> {
		const [sites, origins, persistedBackends, persistedPools] = await Promise.all([
			repository.allSites(),
			repository.allOrigins(),
			repository.allBackendHealthStatuses(),
			repository.allOriginHealthStatuses(),
		]);
		const sitesById = new Map(sites.map((site) => [site.id, site]));
		const backendById = new Map(persistedBackends.map((status) => [status.origin_id, status]));
		for (const origin of origins) {
			const site = sitesById.get(origin.site_id);
			if (!site) continue;
			this.setRuntimeOrigin(site, origin, backendById.get(origin.id), false);
		}
		const persistedPoolBySite = new Map(persistedPools.map((status) => [status.site_id, status]));
		for (const site of sites) this.recomputePool(site, persistedPoolBySite.get(site.id), true);
	}

	start(): void {
		const checkTimer = setInterval(() => void this.tick(), TICK_MS);
		(checkTimer as unknown as { unref?: () => void }).unref?.();
		const alertTimer = setInterval(() => void this.deliverPendingAlerts(), ALERT_POLL_MS);
		(alertTimer as unknown as { unref?: () => void }).unref?.();
		void this.tick();
		void this.deliverPendingAlerts();
	}

	summary(siteId: string) {
		const status = this.poolStatuses.get(siteId) ?? emptyStatus(siteId, "disabled");
		return {
			...healthSummary(status),
			origins: [...this.runtime.values()]
				.filter((runtime) => runtime.site.id === siteId)
				.map((runtime) => ({
					id: runtime.origin.id,
					name: runtime.origin.name,
					...healthSummary(runtime.status),
				})),
		};
	}

	originState(originId: string): OriginHealthState {
		return this.runtime.get(originId)?.status.state ?? "unknown";
	}

	isMaintenanceMode(siteId: string): boolean {
		const runtimes = [...this.runtime.values()].filter((runtime) => runtime.site.id === siteId && runtime.origin.enabled === 1);
		const site = runtimes[0]?.site;
		return Boolean(site && site.health_check_failure_mode === "maintenance" && this.poolStatuses.get(siteId)?.state === "unhealthy");
	}

	async events(siteId: string, limit = 50): Promise<OriginHealthEventRecord[]> {
		return await repository.originHealthEvents(siteId, Math.min(200, Math.max(1, limit)));
	}

	async backendEvents(siteId: string, limit = 100): Promise<OriginBackendHealthEventRecord[]> {
		return await repository.backendHealthEvents(siteId, Math.min(200, Math.max(1, limit)));
	}

	async refreshSite(siteId: string): Promise<void> {
		const site = await repository.siteById(siteId);
		if (!site) {
			this.removeSite(siteId);
			return;
		}
		const origins = await repository.originsForSite(siteId);
		const originIds = new Set(origins.map((origin) => origin.id));
		for (const [originId, runtime] of this.runtime) {
			if (runtime.site.id !== siteId || originIds.has(originId)) continue;
			this.runtime.delete(originId);
			openMetrics.clearOriginBackendHealth(siteId, originId);
		}
		for (const origin of origins) this.setRuntimeOrigin(site, origin, this.runtime.get(origin.id)?.status, true);
		this.recomputePool(site, this.poolStatuses.get(siteId), true);
		await repository.saveOriginHealthStatus(this.poolStatuses.get(siteId)!);
	}

	removeSite(siteId: string): void {
		for (const [originId, runtime] of this.runtime) {
			if (runtime.site.id !== siteId) continue;
			this.runtime.delete(originId);
			openMetrics.clearOriginBackendHealth(siteId, originId);
		}
		this.poolStatuses.delete(siteId);
		openMetrics.clearOriginHealth(siteId);
	}

	async checkNow(siteId: string, originId?: string): Promise<ReturnType<OriginHealthManager["summary"]>> {
		await this.refreshSite(siteId);
		const targets = [...this.runtime.values()].filter(
			(runtime) => runtime.site.id === siteId && runtime.origin.enabled === 1 && (!originId || runtime.origin.id === originId),
		);
		if (targets.length === 0) throw new Error(originId ? "Origin not found or disabled" : "No enabled origins are configured for this site");
		if (targets.some((runtime) => runtime.running)) throw new Error("An origin health check is already running");
		if (targets[0]!.site.health_check_enabled !== 1) throw new Error("Origin health checks are disabled for this site");
		for (const runtime of targets) await this.runCheck(runtime);
		return this.summary(siteId);
	}

	private setRuntimeOrigin(site: SiteRecord, origin: SiteOriginRecord, previous: OriginBackendHealthStatusRecord | undefined, immediate: boolean): void {
		const existing = this.runtime.get(origin.id);
		const key = settingsKey(site, origin);
		if (existing && existing.settingsKey === key) {
			existing.site = site;
			existing.origin = origin;
			return;
		}
		const enabled = site.enabled === 1 && site.health_check_enabled === 1 && origin.enabled === 1;
		const base = healthStatusAfterConfigurationChange(site.id, previous, enabled);
		const status: OriginBackendHealthStatusRecord = { ...base, origin_id: origin.id };
		this.runtime.set(origin.id, {
			site,
			origin,
			status,
			nextCheckAt: enabled ? Date.now() + (immediate ? 0 : Math.round(Math.random() * 1_000)) : Number.POSITIVE_INFINITY,
			running: false,
			lastPersistedAt: Number(previous?.updated_at ?? 0),
			settingsKey: key,
		});
		openMetrics.setOriginBackendHealth(site.id, origin.id, status.state);
	}

	private recomputePool(site: SiteRecord, previous: OriginHealthStatusRecord | undefined, preserveIncident: boolean): OriginHealthStatusRecord {
		const statuses = [...this.runtime.values()]
			.filter((runtime) => runtime.site.id === site.id && runtime.origin.enabled === 1)
			.map((runtime) => runtime.status);
		const state = aggregateState(statuses, site.enabled === 1 && site.health_check_enabled === 1);
		const now = Date.now();
		const latest = [...statuses].sort((left, right) => Number(right.last_checked_at ?? 0) - Number(left.last_checked_at ?? 0))[0];
		const pool: OriginHealthStatusRecord = {
			...(previous ?? emptyStatus(site.id, state, now)),
			state:
				preserveIncident && site.enabled === 1 && site.health_check_enabled === 1 && previous?.state === "unhealthy" && state !== "healthy"
					? "unhealthy"
					: state,
			consecutive_failures: statuses.reduce((sum, status) => sum + Number(status.consecutive_failures), 0),
			consecutive_successes: statuses.reduce((sum, status) => sum + Number(status.consecutive_successes), 0),
			last_checked_at: latest?.last_checked_at ?? previous?.last_checked_at ?? null,
			last_healthy_at: statuses.reduce<number | null>((latestAt, status) => Math.max(latestAt ?? 0, Number(status.last_healthy_at ?? 0)) || null, null),
			last_unhealthy_at: state === "unhealthy" && previous?.state !== "unhealthy" ? now : (previous?.last_unhealthy_at ?? null),
			last_status: latest?.last_status ?? null,
			last_latency_ms: latest?.last_latency_ms ?? null,
			last_error: state === "unhealthy" ? "No healthy origin is available" : null,
			updated_at: now,
		};
		this.poolStatuses.set(site.id, pool);
		openMetrics.setOriginHealth(site.id, pool.state);
		return pool;
	}

	private async tick(): Promise<void> {
		const now = Date.now();
		for (const runtime of this.runtime.values()) {
			if (this.activeChecks >= MAX_CONCURRENT_CHECKS) break;
			if (runtime.running || runtime.nextCheckAt > now || runtime.site.enabled !== 1 || runtime.site.health_check_enabled !== 1 || runtime.origin.enabled !== 1)
				continue;
			void this.runCheck(runtime);
		}
	}

	private async performCheck(runtime: RuntimeOriginHealth): Promise<HealthCheckResult> {
		const started = performance.now();
		const checkedAt = Date.now();
		try {
			const path = runtime.origin.health_check_path || runtime.site.health_check_path || "/health";
			const response = await fetch(originHealthTarget(runtime.origin.origin_url, path), {
				method: "GET",
				headers: { accept: "*/*", "user-agent": "BurrowGate-HealthCheck/1.0" },
				redirect: "manual",
				signal: AbortSignal.timeout(Number(runtime.site.health_check_timeout_ms ?? 3_000)),
			});
			await response.body?.cancel().catch(() => undefined);
			const healthy = response.status >= 200 && response.status < 300;
			return {
				healthy,
				status: response.status,
				latencyMs: performance.now() - started,
				error: healthy ? null : `Health endpoint returned HTTP ${response.status}`,
				checkedAt,
			};
		} catch (error) {
			return { healthy: false, status: null, latencyMs: performance.now() - started, error: boundedError(error), checkedAt };
		}
	}

	private async runCheck(runtime: RuntimeOriginHealth): Promise<void> {
		runtime.running = true;
		this.activeChecks += 1;
		try {
			const result = await this.performCheck(runtime);
			if (this.runtime.get(runtime.origin.id) !== runtime) return;
			const previousBackend = runtime.status;
			const previousPool = this.poolStatuses.get(runtime.site.id) ?? emptyStatus(runtime.site.id, "unknown");
			const advanced = advanceOriginHealthState(
				previousBackend,
				result,
				Number(runtime.site.health_check_failure_threshold ?? 3),
				Number(runtime.site.health_check_recovery_threshold ?? 2),
			);
			const nextBackend: OriginBackendHealthStatusRecord = { ...advanced, origin_id: runtime.origin.id };
			runtime.status = nextBackend;
			const backendTransitioned = previousBackend.state !== nextBackend.state;
			openMetrics.recordOriginHealthCheck(runtime.site.id, runtime.origin.id, result.healthy, result.latencyMs);
			openMetrics.setOriginBackendHealth(runtime.site.id, runtime.origin.id, nextBackend.state);
			if (backendTransitioned || result.checkedAt - runtime.lastPersistedAt >= STATUS_PERSIST_INTERVAL_MS) {
				await repository.saveBackendHealthStatus(nextBackend);
				runtime.lastPersistedAt = result.checkedAt;
			}
			const backendEvent = backendTransitioned ? this.backendEvent(runtime, previousBackend.state, nextBackend, result) : null;
			if (backendEvent) await repository.insertBackendHealthEvent(backendEvent);
			const nextPool = this.recomputePool(runtime.site, previousPool, false);
			const poolTransitioned = previousPool.state !== nextPool.state;
			if (poolTransitioned) {
				await repository.saveOriginHealthStatus(nextPool);
				const event = this.poolEvent(runtime.site, previousPool.state, nextPool, result);
				await repository.insertOriginHealthEvent(event);
				if (nextPool.state === "unhealthy") await this.queueAlert(runtime.site, event.id, "pool_unhealthy", null, result, nextPool.state);
				else if (previousPool.state === "unhealthy" && nextPool.state === "healthy")
					await this.queueAlert(runtime.site, event.id, "pool_recovered", null, result, nextPool.state);
			}
			if (backendTransitioned && !poolTransitioned) {
				const eventType =
					nextBackend.state === "unhealthy"
						? "origin_unhealthy"
						: previousBackend.state === "unhealthy" && nextBackend.state === "healthy"
							? "origin_recovered"
							: null;
				if (eventType && backendEvent) await this.queueAlert(runtime.site, backendEvent.id, eventType, runtime.origin, result, nextBackend.state);
			}
		} catch (error) {
			Logger.error("[BurrowGate] Unable to persist origin health check", { siteId: runtime.site.id, originId: runtime.origin.id, error });
		} finally {
			runtime.running = false;
			this.activeChecks = Math.max(0, this.activeChecks - 1);
			runtime.nextCheckAt = Date.now() + jitter(Number(runtime.site.health_check_interval_seconds ?? 30) * 1_000);
		}
	}

	private backendEvent(
		runtime: RuntimeOriginHealth,
		fromState: OriginHealthState,
		status: OriginBackendHealthStatusRecord,
		result: HealthCheckResult,
	): OriginBackendHealthEventRecord {
		return {
			id: randomId("backend_health_evt"),
			site_id: runtime.site.id,
			origin_id: runtime.origin.id,
			from_state: fromState,
			to_state: status.state,
			status: result.status,
			latency_ms: Math.round(result.latencyMs),
			error: result.error,
			created_at: result.checkedAt,
		};
	}

	private poolEvent(site: SiteRecord, fromState: OriginHealthState, status: OriginHealthStatusRecord, result: HealthCheckResult): OriginHealthEventRecord {
		return {
			id: randomId("health_evt"),
			site_id: site.id,
			from_state: fromState,
			to_state: status.state,
			status: result.status,
			latency_ms: Math.round(result.latencyMs),
			error: status.last_error,
			created_at: result.checkedAt,
		};
	}

	private async queueAlert(
		site: SiteRecord,
		eventId: string,
		eventType: HealthAlertOutboxRecord["event_type"],
		origin: SiteOriginRecord | null,
		result: HealthCheckResult,
		state: OriginHealthState,
	): Promise<void> {
		if (site.health_alert_enabled !== 1 || !site.health_alert_webhook_url) return;
		const payload = {
			id: eventId,
			type: eventType,
			site: { id: site.id, name: site.name, publicHost: site.public_host },
			origin: origin ? { id: origin.id, name: origin.name, url: new URL(origin.origin_url).origin } : null,
			state,
			status: result.status,
			latencyMs: Math.round(result.latencyMs),
			reason: result.error,
			detectedAt: result.checkedAt,
		};
		await repository.insertHealthAlert({
			id: randomId("health_alert"),
			site_id: site.id,
			event_id: eventId,
			event_type: eventType,
			payload_json: JSON.stringify(payload),
			status: "pending",
			attempts: 0,
			next_attempt_at: Date.now(),
			last_error: null,
			created_at: Date.now(),
			delivered_at: null,
		});
	}

	private async deliverPendingAlerts(): Promise<void> {
		if (this.alertWorkerRunning) return;
		this.alertWorkerRunning = true;
		try {
			for (const alert of await repository.pendingHealthAlerts(Date.now(), 5)) await this.deliverAlert(alert);
		} catch (error) {
			Logger.error("[BurrowGate] Unable to process health alert outbox", { error });
		} finally {
			this.alertWorkerRunning = false;
		}
	}

	private async deliverAlert(alert: HealthAlertOutboxRecord): Promise<void> {
		const site = await repository.siteById(alert.site_id);
		const attempts = Number(alert.attempts) + 1;
		if (!site || site.health_alert_enabled !== 1 || !site.health_alert_webhook_url) {
			await repository.updateHealthAlertDelivery(alert.id, "failed", attempts, Date.now(), "Health alert destination is no longer enabled", null);
			openMetrics.recordHealthAlert(alert.site_id, "failed");
			return;
		}
		try {
			const url = await decryptSecret(site.health_alert_webhook_url);
			const secret = site.health_alert_webhook_secret ? await decryptSecret(site.health_alert_webhook_secret) : null;
			const payload = JSON.parse(alert.payload_json) as { origin?: { name?: string } | null; reason?: string };
			const originName = payload.origin?.name ? ` ${payload.origin.name}` : "";
			const messages: Record<HealthAlertOutboxRecord["event_type"], string> = {
				origin_unhealthy: `BurrowGate:${originName} origin for ${site.name} is unhealthy (${payload.reason ?? "health check failed"}).`,
				origin_recovered: `BurrowGate:${originName} origin for ${site.name} recovered.`,
				pool_unhealthy: `BurrowGate: all origins for ${site.name} are unavailable.`,
				pool_recovered: `BurrowGate: the origin pool for ${site.name} recovered.`,
			};
			const message = messages[alert.event_type];
			const down = alert.event_type === "origin_unhealthy" || alert.event_type === "pool_unhealthy";
			const headers = new Headers({ "x-burrowgate-event-id": alert.event_id, "user-agent": "BurrowGate-Alerts/1.0" });
			let body: string;
			if (site.health_alert_provider === "slack") {
				headers.set("content-type", "application/json");
				body = JSON.stringify({ text: message });
			} else if (site.health_alert_provider === "discord") {
				headers.set("content-type", "application/json");
				body = JSON.stringify({ content: message });
			} else if (site.health_alert_provider === "ntfy") {
				headers.set("content-type", "text/plain; charset=utf-8");
				headers.set("title", down ? `Origin down: ${site.name}` : `Origin recovered: ${site.name}`);
				headers.set("priority", down ? "high" : "default");
				headers.set("tags", down ? "warning" : "white_check_mark");
				body = message;
			} else {
				headers.set("content-type", "application/json");
				body = alert.payload_json;
			}
			if (secret) headers.set("x-burrowgate-signature", `sha256=${await hmacSha256Hex(secret, body)}`);
			const response = await fetch(url, { method: "POST", headers, body, redirect: "manual", signal: AbortSignal.timeout(5_000) });
			await response.body?.cancel().catch(() => undefined);
			if (response.status < 200 || response.status >= 300) throw new Error(`Webhook returned HTTP ${response.status}`);
			await repository.updateHealthAlertDelivery(alert.id, "delivered", attempts, Date.now(), null, Date.now());
			openMetrics.recordHealthAlert(alert.site_id, "delivered");
		} catch (error) {
			const terminal = attempts >= MAX_ALERT_ATTEMPTS;
			const delay = Math.min(60 * 60_000, 5_000 * 2 ** Math.max(0, attempts - 1));
			await repository.updateHealthAlertDelivery(
				alert.id,
				terminal ? "failed" : "pending",
				attempts,
				Date.now() + delay + Math.round(Math.random() * 1_000),
				boundedError(error),
				null,
			);
			openMetrics.recordHealthAlert(alert.site_id, terminal ? "failed" : "retry");
		}
	}
}

export const originHealthManager = new OriginHealthManager();
