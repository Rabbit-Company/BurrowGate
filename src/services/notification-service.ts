import { repository } from "../db/repository.ts";
import { Logger } from "../logger.ts";
import type {
	HealthAlertProvider,
	NotificationEventType,
	NotificationSeverity,
	PendingNotificationDeliveryRecord,
	SiteRecord,
	StreamRecord,
} from "../types.ts";
import { hmacSha256Hex, randomId } from "../utils/crypto.ts";
import { decryptSecret } from "./secret-encryption-service.ts";
import { openMetrics } from "./openmetrics-service.ts";
import { resolveStreamNotificationPolicy } from "./stream-notification-policy-service.ts";

const ALERT_POLL_MS = 2_000;
const MAX_ALERT_ATTEMPTS = 8;

const DOWN_EVENT_TYPES = new Set<NotificationEventType>([
	"origin_unhealthy",
	"pool_unhealthy",
	"internet_down",
	"ip_banned",
	"stream_origin_unhealthy",
	"stream_ip_banned",
	"system_resource_high",
]);

interface DeliveryTarget {
	name: string;
	provider: HealthAlertProvider;
	webhookUrl: string;
	webhookSecret: string | null;
}

function boundedError(error: unknown, maximum = 1_000): string {
	const message = error instanceof Error ? error.message : String(error);
	return message.slice(0, maximum);
}

function formatEventTimestamp(ms: number): string {
	return `${new Date(ms)
		.toISOString()
		.replace("T", " ")
		.replace(/\.\d{3}Z$/, "")} UTC`;
}

/** Missing key = enabled, so upgrading a site/stream never silently drops alerts it already relied on. */
export function isNotificationEventTypeEnabled(eventTypes: Record<string, unknown> | null | undefined, type: NotificationEventType): boolean {
	if (!eventTypes) return true;
	return eventTypes[type] !== false;
}

function siteEventTypes(site: SiteRecord): Record<string, unknown> | null {
	if (!site.notification_event_types_json) return null;
	try {
		return JSON.parse(site.notification_event_types_json) as Record<string, unknown>;
	} catch {
		return null;
	}
}

interface DeliveryField {
	name: string;
	value: string;
}

/** Structured fields pulled from the event payload, for the providers that can render them (Discord embeds, Slack attachments). */
function deliveryFields(delivery: PendingNotificationDeliveryRecord): DeliveryField[] {
	let payload: Record<string, unknown>;
	try {
		payload = JSON.parse(delivery.payload_json) as Record<string, unknown>;
	} catch {
		return [];
	}
	const fields: DeliveryField[] = [];
	switch (delivery.type) {
		case "ip_banned":
		case "stream_ip_banned":
			if (typeof payload.ip === "string") fields.push({ name: "IP", value: payload.ip });
			if (typeof payload.expiresAt === "number") fields.push({ name: "Expires", value: formatEventTimestamp(payload.expiresAt) });
			if (typeof payload.ruleId === "string") fields.push({ name: "Rule", value: payload.ruleId });
			break;
		case "origin_unhealthy":
		case "origin_recovered": {
			const origin = payload.origin as Record<string, unknown> | null;
			if (origin && typeof origin.name === "string") fields.push({ name: "Origin", value: origin.name });
			if (typeof payload.status === "number") fields.push({ name: "HTTP status", value: String(payload.status) });
			if (typeof payload.reason === "string" && payload.reason) fields.push({ name: "Reason", value: payload.reason });
			break;
		}
		case "internet_down":
		case "internet_up":
			if (Array.isArray(payload.targets)) fields.push({ name: "Targets", value: payload.targets.join(", ") });
			break;
		case "stream_origin_unhealthy":
		case "stream_origin_recovered":
			if (typeof payload.forwardHost === "string") fields.push({ name: "Forward target", value: `${payload.forwardHost}:${payload.forwardPort}` });
			break;
		case "system_resource_high":
		case "system_resource_normal":
			if (typeof payload.resource === "string") fields.push({ name: "Resource", value: payload.resource });
			if (typeof payload.value === "string") fields.push({ name: "Value", value: payload.value });
			if (typeof payload.thresholdValue === "string") fields.push({ name: "Threshold", value: payload.thresholdValue });
			break;
	}
	return fields;
}

function discordColor(severity: NotificationSeverity): number {
	switch (severity) {
		case "critical":
			return 0xed4245;
		case "warning":
			return 0xfaa61a;
		case "info":
			return 0x57f287;
	}
}

function slackColor(severity: NotificationSeverity): string {
	switch (severity) {
		case "critical":
			return "danger";
		case "warning":
			return "warning";
		case "info":
			return "good";
	}
}

function eventTitle(type: NotificationEventType, targetName: string): string {
	switch (type) {
		case "origin_unhealthy":
			return `Origin down: ${targetName}`;
		case "origin_recovered":
			return `Origin recovered: ${targetName}`;
		case "pool_unhealthy":
			return `All origins down: ${targetName}`;
		case "pool_recovered":
			return `Origins recovered: ${targetName}`;
		case "internet_down":
			return "Internet connectivity down";
		case "internet_up":
			return "Internet connectivity restored";
		case "ip_banned":
			return `IP auto-banned: ${targetName}`;
		case "stream_origin_unhealthy":
			return `Stream origin down: ${targetName}`;
		case "stream_origin_recovered":
			return `Stream origin recovered: ${targetName}`;
		case "stream_ip_banned":
			return `IP auto-banned: ${targetName}`;
		case "system_resource_high":
			return `System resource alert: ${targetName}`;
		case "system_resource_normal":
			return `System resource normal: ${targetName}`;
	}
}

class NotificationService {
	private workerRunning = false;

	start(): void {
		const timer = setInterval(() => void this.deliverPending(), ALERT_POLL_MS);
		(timer as unknown as { unref?: () => void }).unref?.();
		void this.deliverPending();
	}

	async recordSiteEvent(
		site: SiteRecord,
		type: NotificationEventType,
		severity: NotificationSeverity,
		summary: string,
		payload: Record<string, unknown>,
		occurredAt: number,
	): Promise<void> {
		const eventId = randomId("notif_evt");
		await repository.insertNotificationEvent({
			id: eventId,
			site_id: site.id,
			stream_id: null,
			type,
			severity,
			summary,
			payload_json: JSON.stringify(payload),
			occurred_at: occurredAt,
			created_at: Date.now(),
		});
		await this.queueSiteDelivery(site, eventId, type);
	}

	async recordStreamEvent(
		stream: StreamRecord,
		type: NotificationEventType,
		severity: NotificationSeverity,
		summary: string,
		payload: Record<string, unknown>,
		occurredAt: number,
	): Promise<void> {
		const eventId = randomId("notif_evt");
		await repository.insertNotificationEvent({
			id: eventId,
			site_id: null,
			stream_id: stream.id,
			type,
			severity,
			summary,
			payload_json: JSON.stringify(payload),
			occurred_at: occurredAt,
			created_at: Date.now(),
		});
		await this.queueStreamDelivery(stream, eventId, type);
	}

	async recordGlobalEvent(
		type: NotificationEventType,
		severity: NotificationSeverity,
		summary: string,
		payload: Record<string, unknown>,
		occurredAt: number,
	): Promise<void> {
		const eventId = randomId("notif_evt");
		await repository.insertNotificationEvent({
			id: eventId,
			site_id: null,
			stream_id: null,
			type,
			severity,
			summary,
			payload_json: JSON.stringify(payload),
			occurred_at: occurredAt,
			created_at: Date.now(),
		});
		for (const site of await repository.allSites()) await this.queueSiteDelivery(site, eventId, type);
		for (const stream of await repository.allStreams()) await this.queueStreamDelivery(stream, eventId, type);
	}

	private async queueSiteDelivery(site: SiteRecord, eventId: string, type: NotificationEventType): Promise<void> {
		if (site.health_alert_enabled !== 1 || !site.health_alert_webhook_url) return;
		if (!isNotificationEventTypeEnabled(siteEventTypes(site), type)) return;
		await this.insertOutbox(eventId, { site_id: site.id, stream_id: null });
	}

	private async queueStreamDelivery(stream: StreamRecord, eventId: string, type: NotificationEventType): Promise<void> {
		const policy = resolveStreamNotificationPolicy(stream);
		if (!policy.enabled || !policy.webhookUrl) return;
		if (!isNotificationEventTypeEnabled(policy.eventTypes, type)) return;
		await this.insertOutbox(eventId, { site_id: null, stream_id: stream.id });
	}

	private async insertOutbox(eventId: string, target: { site_id: string | null; stream_id: string | null }): Promise<void> {
		await repository.insertNotificationOutbox({
			id: randomId("notif_out"),
			event_id: eventId,
			site_id: target.site_id,
			stream_id: target.stream_id,
			status: "pending",
			attempts: 0,
			next_attempt_at: Date.now(),
			last_error: null,
			created_at: Date.now(),
			delivered_at: null,
		});
	}

	private async deliverPending(): Promise<void> {
		if (this.workerRunning) return;
		this.workerRunning = true;
		try {
			for (const delivery of await repository.pendingNotificationOutbox(Date.now(), 5)) await this.deliverOne(delivery);
		} catch (error) {
			Logger.error("[BurrowGate] Unable to process notification outbox", { error });
		} finally {
			this.workerRunning = false;
		}
	}

	private async resolveTarget(delivery: PendingNotificationDeliveryRecord): Promise<DeliveryTarget | null> {
		if (delivery.site_id) {
			const site = await repository.siteById(delivery.site_id);
			if (!site || site.health_alert_enabled !== 1 || !site.health_alert_webhook_url) return null;
			return {
				name: site.name,
				provider: site.health_alert_provider ?? "generic",
				webhookUrl: site.health_alert_webhook_url,
				webhookSecret: site.health_alert_webhook_secret ?? null,
			};
		}
		const stream = delivery.stream_id ? await repository.streamById(delivery.stream_id) : null;
		if (!stream) return null;
		const policy = resolveStreamNotificationPolicy(stream);
		if (!policy.enabled || !policy.webhookUrl) return null;
		return { name: stream.name, provider: policy.provider, webhookUrl: policy.webhookUrl, webhookSecret: policy.webhookSecret };
	}

	private metricLabel(delivery: PendingNotificationDeliveryRecord): string {
		return delivery.site_id ?? `stream:${delivery.stream_id}`;
	}

	private async deliverOne(delivery: PendingNotificationDeliveryRecord): Promise<void> {
		const attempts = Number(delivery.attempts) + 1;
		const target = await this.resolveTarget(delivery);
		if (!target) {
			await repository.updateNotificationOutboxDelivery(delivery.id, "failed", attempts, Date.now(), "Notification destination is no longer enabled", null);
			openMetrics.recordNotificationDelivery(this.metricLabel(delivery), "failed");
			return;
		}
		try {
			const url = await decryptSecret(target.webhookUrl);
			const secret = target.webhookSecret ? await decryptSecret(target.webhookSecret) : null;
			const down = DOWN_EVENT_TYPES.has(delivery.type);
			const occurredAt = Number(delivery.occurred_at);
			const title = eventTitle(delivery.type, target.name);
			const fields = deliveryFields(delivery);
			const headers = new Headers({ "x-burrowgate-event-id": delivery.event_id, "user-agent": "BurrowGate-Alerts/1.0" });
			let body: string;
			if (target.provider === "slack") {
				headers.set("content-type", "application/json");
				body = JSON.stringify({
					text: title,
					attachments: [
						{
							color: slackColor(delivery.severity),
							title,
							text: delivery.summary,
							fields: fields.map((field) => ({ title: field.name, value: field.value, short: true })),
							ts: Math.floor(occurredAt / 1_000),
						},
					],
				});
			} else if (target.provider === "discord") {
				headers.set("content-type", "application/json");
				body = JSON.stringify({
					embeds: [
						{
							title,
							description: delivery.summary,
							color: discordColor(delivery.severity),
							fields: fields.map((field) => ({ name: field.name, value: field.value, inline: true })),
							timestamp: new Date(occurredAt).toISOString(),
							footer: { text: "BurrowGate" },
						},
					],
				});
			} else if (target.provider === "ntfy") {
				headers.set("content-type", "text/plain; charset=utf-8");
				headers.set("title", title);
				headers.set("priority", down ? "high" : "default");
				headers.set("tags", down ? "warning" : "white_check_mark");
				body = `${delivery.summary}\n\nOccurred: ${formatEventTimestamp(occurredAt)}`;
			} else {
				headers.set("content-type", "application/json");
				body = JSON.stringify({
					id: delivery.event_id,
					type: delivery.type,
					severity: delivery.severity,
					summary: delivery.summary,
					occurredAt,
					payload: JSON.parse(delivery.payload_json),
				});
			}
			if (secret) headers.set("x-burrowgate-signature", `sha256=${await hmacSha256Hex(secret, body)}`);
			const response = await fetch(url, { method: "POST", headers, body, redirect: "manual", signal: AbortSignal.timeout(5_000) });
			await response.body?.cancel().catch(() => undefined);
			if (response.status < 200 || response.status >= 300) throw new Error(`Webhook returned HTTP ${response.status}`);
			await repository.updateNotificationOutboxDelivery(delivery.id, "delivered", attempts, Date.now(), null, Date.now());
			openMetrics.recordNotificationDelivery(this.metricLabel(delivery), "delivered");
		} catch (error) {
			const terminal = attempts >= MAX_ALERT_ATTEMPTS;
			const delay = Math.min(60 * 60_000, 5_000 * 2 ** Math.max(0, attempts - 1));
			await repository.updateNotificationOutboxDelivery(
				delivery.id,
				terminal ? "failed" : "pending",
				attempts,
				Date.now() + delay + Math.round(Math.random() * 1_000),
				boundedError(error),
				null,
			);
			openMetrics.recordNotificationDelivery(this.metricLabel(delivery), terminal ? "failed" : "retry");
		}
	}
}

export const notificationService = new NotificationService();
