import { repository } from "../db/repository.ts";
import { Logger } from "../logger.ts";
import type { HealthAlertOutboxRecord, OriginHealthEventRecord, OriginHealthState, OriginHealthStatusRecord, SiteRecord } from "../types.ts";
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

interface RuntimeHealth {
	site: SiteRecord;
	status: OriginHealthStatusRecord;
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

/**
 * Preserve a confirmed outage across origin, path, and threshold changes.
 * Resetting an unhealthy site to unknown would discard the open incident and
 * prevent the successful replacement origin from producing a recovery alert.
 */
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

function settingsKey(site: SiteRecord): string {
	return [
		site.enabled,
		site.origin_url,
		site.health_check_enabled,
		site.health_check_path,
		site.health_check_interval_seconds,
		site.health_check_timeout_ms,
		site.health_check_failure_threshold,
		site.health_check_recovery_threshold,
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

export class OriginHealthManager {
	private readonly runtime = new Map<string, RuntimeHealth>();
	private activeChecks = 0;
	private alertWorkerRunning = false;

	async initialize(): Promise<void> {
		const [sites, persisted] = await Promise.all([repository.allSites(), repository.allOriginHealthStatuses()]);
		const statusBySite = new Map(persisted.map((status) => [status.site_id, status]));
		for (const site of sites) {
			const enabled = site.enabled === 1 && site.health_check_enabled === 1;
			const previous = statusBySite.get(site.id);
			const status = healthStatusAfterConfigurationChange(site.id, previous, enabled);
			this.runtime.set(site.id, {
				site,
				status,
				nextCheckAt: enabled ? Date.now() + Math.round(Math.random() * 1_000) : Number.POSITIVE_INFINITY,
				running: false,
				lastPersistedAt: Number(previous?.updated_at ?? 0),
				settingsKey: settingsKey(site),
			});
			openMetrics.setOriginHealth(site.id, status.state);
		}
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
		const runtime = this.runtime.get(siteId);
		return runtime ? healthSummary(runtime.status) : healthSummary(emptyStatus(siteId, "disabled"));
	}

	isMaintenanceMode(siteId: string): boolean {
		const runtime = this.runtime.get(siteId);
		return Boolean(runtime && runtime.site.health_check_failure_mode === "maintenance" && runtime.status.state === "unhealthy");
	}

	async events(siteId: string, limit = 50): Promise<OriginHealthEventRecord[]> {
		return await repository.originHealthEvents(siteId, Math.min(200, Math.max(1, limit)));
	}

	async refreshSite(siteId: string): Promise<void> {
		const site = await repository.siteById(siteId);
		if (!site) {
			this.runtime.delete(siteId);
			openMetrics.clearOriginHealth(siteId);
			return;
		}
		const current = this.runtime.get(siteId);
		const nextKey = settingsKey(site);
		if (current && current.settingsKey === nextKey) {
			current.site = site;
			return;
		}
		const enabled = site.enabled === 1 && site.health_check_enabled === 1;
		const status = healthStatusAfterConfigurationChange(site.id, current?.status, enabled);
		this.runtime.set(site.id, {
			site,
			status,
			nextCheckAt: enabled ? Date.now() : Number.POSITIVE_INFINITY,
			running: false,
			lastPersistedAt: 0,
			settingsKey: nextKey,
		});
		await repository.saveOriginHealthStatus(status);
		openMetrics.setOriginHealth(site.id, status.state);
	}

	async checkNow(siteId: string): Promise<ReturnType<typeof healthSummary>> {
		await this.refreshSite(siteId);
		const runtime = this.runtime.get(siteId);
		if (!runtime) throw new Error("Site not found");
		if (runtime.site.enabled !== 1 || runtime.site.health_check_enabled !== 1) throw new Error("Origin health checks are disabled for this site");
		if (runtime.running) throw new Error("An origin health check is already running for this site");
		await this.runCheck(runtime);
		return healthSummary(runtime.status);
	}

	private async tick(): Promise<void> {
		const now = Date.now();
		for (const runtime of this.runtime.values()) {
			if (this.activeChecks >= MAX_CONCURRENT_CHECKS) break;
			if (runtime.running || runtime.nextCheckAt > now || runtime.site.enabled !== 1 || runtime.site.health_check_enabled !== 1) continue;
			void this.runCheck(runtime);
		}
	}

	private async performCheck(site: SiteRecord): Promise<HealthCheckResult> {
		const started = performance.now();
		const checkedAt = Date.now();
		try {
			const response = await fetch(originHealthTarget(site.origin_url, site.health_check_path ?? "/health"), {
				method: "GET",
				headers: { accept: "*/*", "user-agent": "BurrowGate-HealthCheck/1.0" },
				redirect: "manual",
				signal: AbortSignal.timeout(Number(site.health_check_timeout_ms ?? 3_000)),
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

	private async runCheck(runtime: RuntimeHealth): Promise<void> {
		runtime.running = true;
		this.activeChecks += 1;
		try {
			const result = await this.performCheck(runtime.site);
			const previous = runtime.status;
			const next = advanceOriginHealthState(
				previous,
				result,
				Number(runtime.site.health_check_failure_threshold ?? 3),
				Number(runtime.site.health_check_recovery_threshold ?? 2),
			);
			runtime.status = next;
			const transitioned = previous.state !== next.state;
			openMetrics.recordOriginHealthCheck(runtime.site.id, result.healthy, result.latencyMs);
			openMetrics.setOriginHealth(runtime.site.id, next.state);
			if (transitioned || result.checkedAt - runtime.lastPersistedAt >= STATUS_PERSIST_INTERVAL_MS) {
				await repository.saveOriginHealthStatus(next);
				runtime.lastPersistedAt = result.checkedAt;
			}
			if (transitioned) await this.recordTransition(runtime.site, previous.state, next, result);
		} catch (error) {
			Logger.error("[BurrowGate] Unable to persist origin health check", { siteId: runtime.site.id, error });
		} finally {
			runtime.running = false;
			this.activeChecks = Math.max(0, this.activeChecks - 1);
			runtime.nextCheckAt = Date.now() + jitter(Number(runtime.site.health_check_interval_seconds ?? 30) * 1_000);
		}
	}

	private async recordTransition(site: SiteRecord, fromState: OriginHealthState, status: OriginHealthStatusRecord, result: HealthCheckResult): Promise<void> {
		const event: OriginHealthEventRecord = {
			id: randomId("health_evt"),
			site_id: site.id,
			from_state: fromState,
			to_state: status.state,
			status: result.status,
			latency_ms: Math.round(result.latencyMs),
			error: result.error,
			created_at: result.checkedAt,
		};
		await repository.insertOriginHealthEvent(event);
		const eventType =
			status.state === "unhealthy" && fromState !== "unhealthy"
				? "origin_unhealthy"
				: fromState === "unhealthy" && status.state === "healthy"
					? "origin_recovered"
					: null;
		if (!eventType || site.health_alert_enabled !== 1 || !site.health_alert_webhook_url) return;
		const payload = {
			id: event.id,
			type: eventType,
			site: { id: site.id, name: site.name, publicHost: site.public_host },
			origin: new URL(site.origin_url).origin,
			state: status.state,
			previousState: fromState,
			healthPath: site.health_check_path ?? "/health",
			status: result.status,
			latencyMs: Math.round(result.latencyMs),
			reason: result.error,
			detectedAt: result.checkedAt,
		};
		await repository.insertHealthAlert({
			id: randomId("health_alert"),
			site_id: site.id,
			event_id: event.id,
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
			const payload = JSON.parse(alert.payload_json) as Record<string, unknown>;
			const down = alert.event_type === "origin_unhealthy";
			const message = down
				? `BurrowGate: ${site.name} origin is unhealthy (${String(payload.reason ?? "health check failed")}).`
				: `BurrowGate: ${site.name} origin recovered.`;
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
