import type { HealthAlertProvider, NotificationEventType, NotificationOutboxStatus, StreamNotificationPolicy, StreamRecord } from "../types.ts";

export const NOTIFICATION_EVENT_TYPES: NotificationEventType[] = [
	"origin_unhealthy",
	"origin_recovered",
	"pool_unhealthy",
	"pool_recovered",
	"internet_down",
	"internet_up",
	"ip_banned",
	"stream_origin_unhealthy",
	"stream_origin_recovered",
	"stream_ip_banned",
];

export const NOTIFICATION_OUTBOX_STATUSES: NotificationOutboxStatus[] = ["pending", "delivered", "failed"];

function defaultEventTypes(): Record<NotificationEventType, boolean> {
	return Object.fromEntries(NOTIFICATION_EVENT_TYPES.map((type) => [type, true])) as Record<NotificationEventType, boolean>;
}

function defaultStreamNotificationPolicy(): StreamNotificationPolicy {
	return { enabled: false, provider: "generic", webhookUrl: null, webhookSecret: null, eventTypes: defaultEventTypes() };
}

function parseJson(value: string | null | undefined): Record<string, unknown> {
	if (!value) return {};
	try {
		const parsed = JSON.parse(value) as unknown;
		return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {};
	} catch {
		return {};
	}
}

function parseProvider(value: unknown, fallback: HealthAlertProvider): HealthAlertProvider {
	const provider = String(value ?? fallback)
		.trim()
		.toLowerCase();
	if (provider === "generic" || provider === "slack" || provider === "discord" || provider === "ntfy") return provider;
	throw new Error("Notification webhook type must be generic, slack, discord, or ntfy");
}

function parseEventTypes(value: unknown, fallback: Record<NotificationEventType, boolean>): Record<NotificationEventType, boolean> {
	const result = { ...fallback };
	if (value === undefined) return result;
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Notification event-type settings must be an object");
	const input = value as Record<string, unknown>;
	for (const key of Object.keys(input)) {
		if (!NOTIFICATION_EVENT_TYPES.includes(key as NotificationEventType)) throw new Error(`Unknown notification event type: ${key}`);
	}
	for (const type of NOTIFICATION_EVENT_TYPES) if (type in input) result[type] = Boolean(input[type]);
	return result;
}

export function storedStreamNotificationPolicy(value: string | null | undefined): StreamNotificationPolicy {
	const stored = parseJson(value);
	const fallback = defaultStreamNotificationPolicy();
	return {
		enabled: typeof stored.enabled === "boolean" ? stored.enabled : fallback.enabled,
		provider: parseProvider(stored.provider, fallback.provider),
		webhookUrl: typeof stored.webhookUrl === "string" ? stored.webhookUrl : fallback.webhookUrl,
		webhookSecret: typeof stored.webhookSecret === "string" ? stored.webhookSecret : fallback.webhookSecret,
		eventTypes: parseEventTypes(stored.eventTypes, fallback.eventTypes),
	};
}

const resolvedCache = new Map<string, { raw: string | null; policy: StreamNotificationPolicy }>();

export function resolveStreamNotificationPolicy(stream: StreamRecord): StreamNotificationPolicy {
	const raw = stream.notification_policy_json ?? null;
	const cached = resolvedCache.get(stream.id);
	if (cached && cached.raw === raw) return cached.policy;
	const policy = storedStreamNotificationPolicy(raw);
	resolvedCache.set(stream.id, { raw, policy });
	return policy;
}

/**
 * Validates the plain (unencrypted) input fields, returning them alongside the still-decided
 * webhookUrl/webhookSecret/clearWebhook state. Encryption and persistence are the route handler's
 * job (mirroring site-service.ts's updateSite), since this module stays synchronous like its
 * bandwidth/protection-policy siblings.
 */
export interface ParsedStreamNotificationPolicyInput {
	enabled: boolean;
	provider: HealthAlertProvider;
	webhookUrl?: string;
	webhookSecret?: string;
	clearWebhook: boolean;
	eventTypes: Record<NotificationEventType, boolean>;
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

function enabledValue(value: unknown, fallback: boolean): boolean {
	if (value === undefined) return fallback;
	if (typeof value === "boolean") return value;
	if (value === "true" || value === "1" || value === 1) return true;
	if (value === "false" || value === "0" || value === 0 || value === "") return false;
	throw new Error("Enabled must be a boolean");
}

export function parseStreamNotificationPolicyInput(input: unknown, existing: string | null | undefined): ParsedStreamNotificationPolicyInput {
	if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Notification policy settings must be an object");
	const body = input as Record<string, unknown>;
	const existingPolicy = storedStreamNotificationPolicy(existing);
	const clearWebhook = enabledValue(body.clearWebhook, false);
	const webhookSecret = String(body.webhookSecret ?? "").trim() || undefined;
	if (webhookSecret && webhookSecret.length > 4_096) throw new Error("Notification webhook signing secret must be at most 4096 characters");
	return {
		enabled: enabledValue(body.enabled, existingPolicy.enabled),
		provider: parseProvider(body.provider, existingPolicy.provider),
		webhookUrl: webhookValue(body.webhookUrl, "Notification webhook URL"),
		webhookSecret,
		clearWebhook,
		eventTypes: parseEventTypes(body.eventTypes, existingPolicy.eventTypes),
	};
}
