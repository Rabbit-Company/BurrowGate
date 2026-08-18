import type { Web } from "@rabbit-company/web";
import { getClientIp } from "@rabbit-company/web-middleware/ip-extract";
import { repository } from "../db/repository.ts";
import { config } from "../config.ts";
import { getAdminSession } from "../services/session-service.ts";
import { buildStream, pickStreamRestartFields, streamRestartDiffers, streamView, type StreamInput } from "../services/stream-service.ts";
import {
	applyPendingChangeNow,
	cancelPendingChange,
	currentPendingChange,
	parseScheduleTime,
	pendingChangeView,
	pendingChangesFor,
	pendingOrFailedChangeFor,
	stagePendingChange,
} from "../services/pending-change-service.ts";
import { streamHealthManager } from "../services/stream-health-service.ts";
import { streamProxyManager } from "../services/stream-proxy-service.ts";
import { flushStreamMonitoring } from "../services/stream-monitoring-service.ts";
import { geoIpStatus } from "../services/geoip-service.ts";
import { addStreamAsnRule, addStreamCountryRule, addStreamIpRule, invalidateStreamNetworkPolicy } from "../services/stream-ip-rule-service.ts";
import { invalidateStreamRateLimiter } from "../services/stream-rate-limit-service.ts";
import { resolveStreamProtectionPolicy, serializeStreamProtectionPolicy } from "../services/stream-protection-policy-service.ts";
import { resolveStreamBandwidthPolicy, serializeStreamBandwidthPolicy } from "../services/stream-bandwidth-policy-service.ts";
import {
	NOTIFICATION_EVENT_TYPES,
	parseStreamNotificationPolicyInput,
	resolveStreamNotificationPolicy,
	storedStreamNotificationPolicy,
} from "../services/stream-notification-policy-service.ts";
import { encryptSecret } from "../services/secret-encryption-service.ts";
import { streamRuleSetCatalog } from "../services/stream-protection-service.ts";
import type {
	NotificationEventType,
	NotificationOutboxStatus,
	StreamDefaultNetworkAction,
	StreamEventType,
	StreamProtocol,
	StreamRecord,
	StreamRuleAction,
} from "../types.ts";
import { htmlResponse, jsonResponse, sameOriginRequest } from "../utils/http.ts";
import { streamsAdminPage } from "../ui/streams-admin-page.ts";
import {
	isAdministrator,
	requireAdministrator,
	requireLevel,
	resolveAdminUser,
	streamAccessLevel,
	type AuthenticatedAdmin,
} from "../services/admin-permission-service.ts";
import { recordAdminAudit } from "../services/admin-audit-service.ts";

const METRIC_BUCKETS_MS = [
	60_000, 300_000, 900_000, 1_800_000, 3_600_000, 7_200_000, 10_800_000, 21_600_000, 43_200_000, 86_400_000, 172_800_000, 345_600_000, 604_800_000,
] as const;

const STREAM_LONG_LIVED_MIN_DURATION_MS = 10_000;

async function guard(request: Request): Promise<Response | { user: AuthenticatedAdmin }> {
	const session = await getAdminSession(request);
	const user = session ? await resolveAdminUser(session) : null;
	return user ? { user } : jsonResponse({ error: "Unauthorized" }, 401);
}

function mutationGuard(request: Request): Response | null {
	if (!sameOriginRequest(request) || request.headers.get("x-burrowgate-admin") !== "1") {
		return jsonResponse({ error: "CSRF validation failed" }, 403);
	}
	return null;
}

function integerParam(url: URL, name: string, fallback: number, minimum: number, maximum: number): number {
	const value = Number(url.searchParams.get(name));
	return Number.isInteger(value) ? Math.min(maximum, Math.max(minimum, value)) : fallback;
}

function stringParam(url: URL, name: string): string | undefined {
	return url.searchParams.get(name)?.trim() || undefined;
}

function protocolParam(url: URL): StreamProtocol | undefined {
	const value = stringParam(url, "protocol");
	return value === "tcp" || value === "udp" ? value : undefined;
}

function notificationTypeParam(url: URL): NotificationEventType | undefined {
	const value = stringParam(url, "type");
	return value && (NOTIFICATION_EVENT_TYPES as string[]).includes(value) ? (value as NotificationEventType) : undefined;
}

function notificationStatusParam(url: URL): NotificationOutboxStatus | undefined {
	const value = stringParam(url, "status");
	return value === "pending" || value === "delivered" || value === "failed" ? value : undefined;
}

function notificationSortBy(url: URL): "created_at" | "occurred_at" | "type" | "status" {
	const value = stringParam(url, "sortBy");
	return value === "occurred_at" || value === "type" || value === "status" ? value : "created_at";
}

function eventTypeParam(url: URL): StreamEventType | undefined {
	const value = stringParam(url, "eventType");
	return value === "connected" ||
		value === "disconnected" ||
		value === "upstream-error" ||
		value === "listener-error" ||
		value === "blocked" ||
		value === "throttled" ||
		value === "monitored"
		? value
		: undefined;
}

async function streamsVisibleToUser(user: AuthenticatedAdmin): Promise<StreamRecord[]> {
	return isAdministrator(user) ? repository.allStreams() : repository.adminStreamsForUser(user.id);
}

async function selectedStream(url: URL, user: AuthenticatedAdmin): Promise<{ stream: StreamRecord | null; error: Response | null }> {
	const requestedId = stringParam(url, "streamId");
	if (!requestedId) return { stream: null, error: null };
	const stream = await repository.streamById(requestedId);
	if (!stream) return { stream: null, error: jsonResponse({ error: "Selected stream was not found" }, 404) };
	if ((await streamAccessLevel(user, stream.id)) === "none") return { stream: null, error: jsonResponse({ error: "Forbidden" }, 403) };
	return { stream, error: null };
}

const NO_ACCESS_STREAM_ID = "__no-accessible-stream__";

async function scopeStreamIds(user: AuthenticatedAdmin): Promise<string[] | undefined> {
	if (isAdministrator(user)) return undefined;
	const streams = await streamsVisibleToUser(user);
	return streams.map((stream) => stream.id);
}

async function streamsScopeId(selection: { stream: StreamRecord | null }, user: AuthenticatedAdmin): Promise<string | string[] | undefined> {
	if (selection.stream) return selection.stream.id;
	const ids = await scopeStreamIds(user);
	if (ids === undefined) return undefined;
	return ids.length > 0 ? ids : NO_ACCESS_STREAM_ID;
}

function parseStreamDefaultNetworkAction(value: unknown, fallback: StreamDefaultNetworkAction): StreamDefaultNetworkAction {
	if (value === undefined) return fallback;
	const action = String(value).trim().toLowerCase();
	if (action === "inherit" || action === "allow" || action === "block") return action;
	throw new Error("Default network action must be inherit, allow, or block");
}

function streamRuleActionParam(url: URL): StreamRuleAction | undefined {
	const value = stringParam(url, "action");
	return value === "allow" || value === "block" ? value : undefined;
}

function eventSortBy(
	url: URL,
):
	| "created_at"
	| "event_type"
	| "protocol"
	| "incoming_port"
	| "client_ip"
	| "country_code"
	| "asn"
	| "reason"
	| "protection_rule_id"
	| "connection_id"
	| "client_to_upstream_bytes"
	| "upstream_to_client_bytes" {
	const value = stringParam(url, "sortBy");
	return value === "event_type" ||
		value === "protocol" ||
		value === "incoming_port" ||
		value === "client_ip" ||
		value === "country_code" ||
		value === "asn" ||
		value === "reason" ||
		value === "protection_rule_id" ||
		value === "connection_id" ||
		value === "client_to_upstream_bytes" ||
		value === "upstream_to_client_bytes"
		? value
		: "created_at";
}

function bandwidthSortBy(
	url: URL,
): "protocol" | "incoming_port" | "ip" | "country_code" | "client_to_upstream_bytes" | "upstream_to_client_bytes" | "total_bytes" {
	const value = stringParam(url, "sortBy");
	return value === "protocol" ||
		value === "incoming_port" ||
		value === "ip" ||
		value === "country_code" ||
		value === "client_to_upstream_bytes" ||
		value === "upstream_to_client_bytes"
		? value
		: "total_bytes";
}

function sortDirection(url: URL): "asc" | "desc" {
	return stringParam(url, "sortDirection") === "asc" ? "asc" : "desc";
}

function ruleSortBy(url: URL): "created_at" | "expires_at" | "network_cidr" | "action" {
	const value = stringParam(url, "sortBy");
	return value === "expires_at" || value === "network_cidr" || value === "action" ? value : "created_at";
}

function ruleStateParam(url: URL): "active" | "expired" | undefined {
	const value = stringParam(url, "state");
	return value === "active" || value === "expired" ? value : undefined;
}

function range(url: URL): { since: number; until: number } {
	const now = Date.now();
	const rawUntil = Number(url.searchParams.get("to"));
	const until = Number.isFinite(rawUntil) && rawUntil > 0 ? Math.min(rawUntil, now + 300_000) : now;
	const rawSince = Number(url.searchParams.get("from"));
	const requestedSince = Number.isFinite(rawSince) && rawSince >= 0 ? rawSince : until - 86_400_000;
	return { since: Math.max(0, Math.min(requestedSince, until - 60_000)), until };
}

function metricBucketSize(durationMs: number): number {
	const minimum = Math.max(60_000, Math.ceil(durationMs / 120));
	return METRIC_BUCKETS_MS.find((candidate) => candidate >= minimum) ?? 604_800_000;
}

async function body(request: Request): Promise<StreamInput> {
	const value = await request.json();
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Stream payload must be an object");
	return value as StreamInput;
}

function certificateView(certificate: Awaited<ReturnType<typeof repository.streamCertificateOptions>>[number]) {
	return {
		id: certificate.id,
		primaryDomain: certificate.primary_domain,
		alternativeNames: JSON.parse(certificate.alternative_names_json || "[]") as string[],
		expiresAt: Number(certificate.expires_at),
		siteName: certificate.site_name,
		publicHost: certificate.public_host,
	};
}

async function saveAndActivate(stream: StreamRecord, previous?: StreamRecord): Promise<void> {
	await repository.saveStream(stream);
	try {
		await streamProxyManager.apply(stream);
	} catch (error) {
		if (previous) await repository.saveStream(previous);
		else await repository.deleteStream(stream.id);
		throw error;
	}
	await streamHealthManager.refresh(stream.id);
}

function summarizeStreamRestartChange(previous: StreamRecord, candidate: StreamRecord): string {
	const parts: string[] = [];
	if (previous.tcp_enabled !== candidate.tcp_enabled) parts.push(`TCP ${candidate.tcp_enabled === 1 ? "enabled" : "disabled"}`);
	if (previous.udp_enabled !== candidate.udp_enabled) parts.push(`UDP ${candidate.udp_enabled === 1 ? "enabled" : "disabled"}`);
	if (previous.incoming_port !== candidate.incoming_port) parts.push(`Incoming port: ${previous.incoming_port} -> ${candidate.incoming_port}`);
	if (previous.forward_host !== candidate.forward_host) parts.push(`Forward host: ${previous.forward_host} -> ${candidate.forward_host}`);
	if (previous.forward_port !== candidate.forward_port) parts.push(`Forward port: ${previous.forward_port} -> ${candidate.forward_port}`);
	if (previous.certificate_id !== candidate.certificate_id) parts.push("Certificate changed");
	if (previous.proxy_protocol !== candidate.proxy_protocol) parts.push(`PROXY protocol: ${previous.proxy_protocol} -> ${candidate.proxy_protocol}`);
	return parts.join(", ") || "Listener configuration changed";
}

function mutationError(error: unknown, fallback: string): Response {
	const raw = error instanceof Error ? error.message : fallback;
	const message = /unique|duplicate|constraint/iu.test(raw) ? "That protocol and incoming port are already assigned to another stream" : raw;
	return jsonResponse({ error: message }, 400);
}

export function registerStreamAdminRoutes(app: Web<any>): void {
	app.get("/_burrowgate/admin/streams", async (ctx) =>
		(await getAdminSession(ctx.req)) ? htmlResponse(streamsAdminPage()) : Response.redirect(new URL("/_burrowgate/admin/login", ctx.req.url).href, 302),
	);

	app.get(
		"/_burrowgate/static/streams-admin.js",
		() => new Response(Bun.file("public/streams-admin.js"), { headers: { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-store" } }),
	);

	app.get("/_burrowgate/api/admin/streams", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const streams = await streamsVisibleToUser(user);
		return jsonResponse({
			items: streams.map(streamView),
			pendingChanges: (
				await pendingChangesFor(
					"stream",
					streams.map((stream) => stream.id),
				)
			).map(pendingChangeView),
			certificates: (await repository.streamCertificateOptions()).map(certificateView),
			statuses: streamProxyManager.statusesView(),
			defaults: {
				retentionDays: config.eventRetentionDays,
				udpPeerIdleTimeoutSeconds: config.streams.udpPeerIdleTimeoutSeconds,
			},
		});
	});

	app.post("/_burrowgate/api/admin/streams", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const forbidden = requireAdministrator(user);
		if (forbidden) return forbidden;
		try {
			const stream = await buildStream(await body(ctx.req));
			await saveAndActivate(stream);
			await recordAdminAudit({
				actor: user,
				action: "stream.create",
				resourceType: "stream",
				resourceId: stream.id,
				summary: `Created stream ${stream.name} (port ${stream.incoming_port})`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse({ stream: streamView(stream), statuses: streamProxyManager.statusesView() }, 201);
		} catch (error) {
			return mutationError(error, "Unable to create stream");
		}
	});

	app.addRoute("PUT", "/_burrowgate/api/admin/streams/:id", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const previous = await repository.streamById(ctx.params.id);
		if (!previous) return jsonResponse({ error: "Stream not found" }, 404);
		const denied = requireLevel(await streamAccessLevel(user, previous.id), "manage");
		if (denied) return denied;
		try {
			const payload = await body(ctx.req);
			const candidate = await buildStream(payload, previous);
			const restartRequired = streamRestartDiffers(previous, candidate);
			const applyAt = parseScheduleTime((payload as StreamInput).effectiveAt);
			if (restartRequired && applyAt) {
				const existingPending = await currentPendingChange("stream", previous.id);
				if (existingPending) {
					throw new Error(`A change is already scheduled for ${new Date(existingPending.apply_at).toLocaleString()}. Cancel or apply it first.`);
				}
				const immediate: StreamRecord = { ...candidate, ...pickStreamRestartFields(previous) };
				await saveAndActivate(immediate, previous);
				invalidateStreamRateLimiter(immediate.id);
				const pendingChange = await stagePendingChange(
					"stream",
					previous.id,
					pickStreamRestartFields(candidate),
					summarizeStreamRestartChange(previous, candidate),
					applyAt,
					user.username,
				);
				await recordAdminAudit({
					actor: user,
					action: "stream.update",
					resourceType: "stream",
					resourceId: immediate.id,
					summary: `Updated stream ${immediate.name} (${pendingChange.summary}, scheduled)`,
					ip: getClientIp(ctx) ?? "unknown",
				});
				return jsonResponse({
					stream: streamView(immediate),
					pendingChange: pendingChangeView(pendingChange),
					statuses: streamProxyManager.statusesView(),
				});
			}
			await saveAndActivate(candidate, previous);
			invalidateStreamRateLimiter(candidate.id);
			await recordAdminAudit({
				actor: user,
				action: "stream.update",
				resourceType: "stream",
				resourceId: candidate.id,
				summary: `Updated stream ${candidate.name} (port ${candidate.incoming_port})`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse({ stream: streamView(candidate), pendingChange: null, statuses: streamProxyManager.statusesView() });
		} catch (error) {
			return mutationError(error, "Unable to update stream");
		}
	});

	app.post("/_burrowgate/api/admin/streams/:id/pending-change/apply-now", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const denied = requireLevel(await streamAccessLevel(user, ctx.params.id), "manage");
		if (denied) return denied;
		try {
			const pending = await pendingOrFailedChangeFor("stream", ctx.params.id);
			if (!pending) return jsonResponse({ error: "No pending change for this stream" }, 404);
			await applyPendingChangeNow(pending.id);
			const stream = await repository.streamById(ctx.params.id);
			await recordAdminAudit({
				actor: user,
				action: "stream.pending-change.apply-now",
				resourceType: "stream",
				resourceId: ctx.params.id,
				summary: `Applied scheduled change now: ${pending.summary}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse({ stream: stream ? streamView(stream) : null, statuses: streamProxyManager.statusesView() });
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to apply the pending change" }, 400);
		}
	});

	app.delete("/_burrowgate/api/admin/streams/:id/pending-change", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const denied = requireLevel(await streamAccessLevel(user, ctx.params.id), "manage");
		if (denied) return denied;
		try {
			const pending = await pendingOrFailedChangeFor("stream", ctx.params.id);
			if (!pending) return jsonResponse({ error: "No pending change for this stream" }, 404);
			await cancelPendingChange(pending.id);
			await recordAdminAudit({
				actor: user,
				action: "stream.pending-change.cancel",
				resourceType: "stream",
				resourceId: ctx.params.id,
				summary: `Cancelled scheduled change: ${pending.summary}`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse({ ok: true });
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to cancel the pending change" }, 400);
		}
	});

	app.delete("/_burrowgate/api/admin/streams/:id", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const forbidden = requireAdministrator(user);
		if (forbidden) return forbidden;
		const stream = await repository.streamById(ctx.params.id);
		if (!stream) return jsonResponse({ error: "Stream not found" }, 404);
		await streamProxyManager.remove(stream.id);
		await flushStreamMonitoring();
		await repository.deleteStream(stream.id);
		streamHealthManager.remove(stream.id);
		invalidateStreamRateLimiter(stream.id);
		await recordAdminAudit({
			actor: user,
			action: "stream.delete",
			resourceType: "stream",
			resourceId: stream.id,
			summary: `Deleted stream ${stream.name} (port ${stream.incoming_port})`,
			ip: getClientIp(ctx) ?? "unknown",
		});
		return jsonResponse({ deleted: true });
	});

	app.get("/_burrowgate/api/admin/streams/active", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		if (isAdministrator(user)) {
			return jsonResponse({ items: streamProxyManager.activeConnections(), statuses: streamProxyManager.statusesView() });
		}
		const visibleStreamIds = new Set((await streamsVisibleToUser(user)).map((stream) => stream.id));
		return jsonResponse({
			items: streamProxyManager.activeConnections().filter((connection) => visibleStreamIds.has(connection.streamId)),
			statuses: streamProxyManager.statusesView(),
		});
	});

	app.get("/_burrowgate/api/admin/streams/overview", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		await flushStreamMonitoring();
		const url = new URL(ctx.req.url);
		const selection = await selectedStream(url, user);
		if (selection.error) return selection.error;
		const scopeStreamId = await streamsScopeId(selection, user);
		const visibleStreamIds = isAdministrator(user) ? null : new Set((await streamsVisibleToUser(user)).map((stream) => stream.id));
		const selectedRange = range(url);
		return jsonResponse({
			...(await repository.streamOverview(scopeStreamId, selectedRange.since, selectedRange.until)),
			active: streamProxyManager.activeConnections().filter((connection) => !visibleStreamIds || visibleStreamIds.has(connection.streamId)),
			geoip: geoIpStatus(),
			rangeFrom: selectedRange.since,
			rangeTo: selectedRange.until,
		});
	});

	app.get("/_burrowgate/api/admin/streams/metrics", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		await flushStreamMonitoring();
		const url = new URL(ctx.req.url);
		const selection = await selectedStream(url, user);
		if (selection.error) return selection.error;
		const scopeStreamId = await streamsScopeId(selection, user);
		const selectedRange = range(url);
		const durationMs = selectedRange.until - selectedRange.since;
		const bucketMs = metricBucketSize(durationMs);
		const visibleStreams = await streamsVisibleToUser(user);
		const comparison = await repository.streamsComparisonMetrics(
			visibleStreams.map((stream) => stream.id),
			selectedRange.since,
			selectedRange.until,
		);
		const blockReasons = await repository.streamBlockReasonMetrics(scopeStreamId, selectedRange.since, selectedRange.until);
		const protocolBreakdown = await repository.streamProtocolMetrics(scopeStreamId, selectedRange.since, selectedRange.until);
		const longLived = await repository.streamLongLivedMetrics(
			scopeStreamId,
			selectedRange.since,
			selectedRange.until,
			bucketMs,
			STREAM_LONG_LIVED_MIN_DURATION_MS,
		);
		const health = await repository.streamOriginLatencyMetrics(scopeStreamId, selectedRange.since, selectedRange.until, bucketMs);
		// Duration is only known once a connection closes, so long-running connections that are
		// still open are invisible to the DB query above until they eventually disconnect. Fold
		// still-open connections that already exceed the threshold into the current bucket so the
		// chart doesn't under-report the most recent activity while it's still in progress.
		const now = Date.now();
		const nowBucket = Math.floor(now / bucketMs) * bucketMs;
		const latestPoint = longLived.series.find((point) => point.bucket === nowBucket);
		if (latestPoint) {
			latestPoint.connected += streamProxyManager
				.activeConnections()
				.filter((connection) => now - connection.connectedAt >= STREAM_LONG_LIVED_MIN_DURATION_MS)
				.filter(
					(connection) =>
						!scopeStreamId || (Array.isArray(scopeStreamId) ? scopeStreamId.includes(connection.streamId) : connection.streamId === scopeStreamId),
				).length;
		}
		return jsonResponse({
			...(await repository.streamMetrics(scopeStreamId, selectedRange.since, selectedRange.until, bucketMs)),
			comparison,
			blockReasons,
			protocolBreakdown,
			longLivedSeries: longLived.series,
			healthSeries: health.series,
			rangeFrom: selectedRange.since,
			rangeTo: selectedRange.until,
			rangeDurationMs: durationMs,
			bucketMs,
		});
	});

	app.get("/_burrowgate/api/admin/streams/ip-metrics-tab", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const url = new URL(ctx.req.url);
		const scope = stringParam(url, "scope");
		if (scope !== "blocked") return jsonResponse({ error: "Invalid scope" }, 400);
		const selection = await selectedStream(url, user);
		if (selection.error) return selection.error;
		const scopeStreamId = await streamsScopeId(selection, user);
		const selectedRange = range(url);
		const ips = await repository.streamTabIpMetrics(scopeStreamId, selectedRange.since, selectedRange.until, scope);
		return jsonResponse({
			rangeFrom: selectedRange.since,
			rangeTo: selectedRange.until,
			rangeDurationMs: selectedRange.until - selectedRange.since,
			ips,
		});
	});

	app.get("/_burrowgate/api/admin/streams/ip-bandwidth-metrics-tab", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const url = new URL(ctx.req.url);
		const selection = await selectedStream(url, user);
		if (selection.error) return selection.error;
		const scopeStreamId = await streamsScopeId(selection, user);
		const selectedRange = range(url);
		const ips = await repository.streamTabBandwidthIpMetrics(scopeStreamId, selectedRange.since, selectedRange.until);
		return jsonResponse({
			rangeFrom: selectedRange.since,
			rangeTo: selectedRange.until,
			rangeDurationMs: selectedRange.until - selectedRange.since,
			ips,
		});
	});

	app.get("/_burrowgate/api/admin/streams/error-metrics-tab", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const url = new URL(ctx.req.url);
		const selection = await selectedStream(url, user);
		if (selection.error) return selection.error;
		const scopeStreamId = await streamsScopeId(selection, user);
		const selectedRange = range(url);
		const errors = await repository.streamErrorReasonMetrics(scopeStreamId, selectedRange.since, selectedRange.until);
		return jsonResponse({
			rangeFrom: selectedRange.since,
			rangeTo: selectedRange.until,
			rangeDurationMs: selectedRange.until - selectedRange.since,
			errors,
		});
	});

	app.get("/_burrowgate/api/admin/streams/events", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		await flushStreamMonitoring();
		const url = new URL(ctx.req.url);
		const selection = await selectedStream(url, user);
		if (selection.error) return selection.error;
		const scopeStreamId = await streamsScopeId(selection, user);
		const selectedRange = range(url);
		const asn = Number(stringParam(url, "asn"));
		return jsonResponse(
			await repository.pagedStreamEvents({
				streamId: scopeStreamId,
				page: integerParam(url, "page", 1, 1, 1_000_000),
				pageSize: integerParam(url, "pageSize", config.adminPageSize, 10, 200),
				search: stringParam(url, "search"),
				protocol: protocolParam(url),
				eventType: eventTypeParam(url),
				countryCode: stringParam(url, "country")?.toUpperCase(),
				...(Number.isInteger(asn) && asn > 0 ? { asn } : {}),
				sortBy: eventSortBy(url),
				sortDirection: sortDirection(url),
				...selectedRange,
			}),
		);
	});

	app.get("/_burrowgate/api/admin/streams/bandwidth", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		await flushStreamMonitoring();
		const url = new URL(ctx.req.url);
		const selection = await selectedStream(url, user);
		if (selection.error) return selection.error;
		const scopeStreamId = await streamsScopeId(selection, user);
		return jsonResponse(
			await repository.pagedStreamBandwidth({
				streamId: scopeStreamId,
				page: integerParam(url, "page", 1, 1, 1_000_000),
				pageSize: integerParam(url, "pageSize", config.adminPageSize, 10, 200),
				search: stringParam(url, "search"),
				protocol: protocolParam(url),
				countryCode: stringParam(url, "country")?.toUpperCase(),
				sortBy: bandwidthSortBy(url),
				sortDirection: sortDirection(url),
				...range(url),
			}),
		);
	});

	app.get("/_burrowgate/api/admin/streams/network-policy", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const selection = await selectedStream(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.stream) return jsonResponse({ error: "No stream configured" }, 400);
		return jsonResponse({
			defaultIpAction: selection.stream.default_ip_action ?? "inherit",
			defaultCountryAction: selection.stream.default_country_action ?? "inherit",
			countryRules: await repository.streamCountryRules(selection.stream.id),
			asnRules: await repository.streamAsnRules(selection.stream.id),
			geoip: geoIpStatus(),
		});
	});

	app.addRoute("PUT", "/_burrowgate/api/admin/streams/network-policy", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedStream(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.stream) return jsonResponse({ error: "No stream configured" }, 400);
		const networkPolicyDenied = requireLevel(await streamAccessLevel(user, selection.stream.id), "manage");
		if (networkPolicyDenied) return networkPolicyDenied;
		try {
			const body = (await ctx.req.json()) as { defaultIpAction?: StreamDefaultNetworkAction; defaultCountryAction?: StreamDefaultNetworkAction };
			const defaultIpAction = parseStreamDefaultNetworkAction(body.defaultIpAction, selection.stream.default_ip_action ?? "inherit");
			const defaultCountryAction = parseStreamDefaultNetworkAction(body.defaultCountryAction, selection.stream.default_country_action ?? "inherit");
			await repository.updateStreamNetworkDefaults(selection.stream.id, defaultIpAction, defaultCountryAction, Date.now());
			invalidateStreamNetworkPolicy(selection.stream.id);
			await streamProxyManager.enforceNetworkPolicy({ ...selection.stream, default_ip_action: defaultIpAction, default_country_action: defaultCountryAction });
			await recordAdminAudit({
				actor: user,
				action: "stream_network_policy.update",
				resourceType: "stream",
				resourceId: selection.stream.id,
				summary: `Updated default network policy for stream ${selection.stream.name} (port ${selection.stream.incoming_port})`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse({ defaultIpAction, defaultCountryAction });
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to update network policy" }, 400);
		}
	});

	app.post("/_burrowgate/api/admin/streams/country-rules", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedStream(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.stream) return jsonResponse({ error: "No stream configured" }, 400);
		const countryRuleDenied = requireLevel(await streamAccessLevel(user, selection.stream.id), "manage");
		if (countryRuleDenied) return countryRuleDenied;
		const body = (await ctx.req.json()) as { countryCode?: string; action?: StreamRuleAction; reason?: string; expiresAt?: number | string | null };
		if (!body.countryCode || !["allow", "block"].includes(body.action ?? "")) {
			return jsonResponse({ error: "Invalid country rule" }, 400);
		}
		const expiresAt = body.expiresAt === null || body.expiresAt === undefined || body.expiresAt === "" ? null : Number(body.expiresAt);
		if (expiresAt !== null && (!Number.isFinite(expiresAt) || expiresAt <= Date.now())) {
			return jsonResponse({ error: "Expiration must be in the future" }, 400);
		}
		try {
			const rule = await addStreamCountryRule(selection.stream.id, body.countryCode, body.action!, body.reason ?? "", expiresAt);
			await streamProxyManager.enforceNetworkPolicy(selection.stream);
			await recordAdminAudit({
				actor: user,
				action: "stream_country_rule.create",
				resourceType: "stream_country_rule",
				resourceId: rule.id,
				summary: `Added country rule (${rule.action}) for ${rule.country_code} on stream ${selection.stream.name} (port ${selection.stream.incoming_port})`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse(rule, 201);
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Invalid country rule" }, 400);
		}
	});

	app.delete("/_burrowgate/api/admin/streams/country-rules/:id", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedStream(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.stream) return jsonResponse({ error: "No stream configured" }, 400);
		const countryRuleDenied = requireLevel(await streamAccessLevel(user, selection.stream.id), "manage");
		if (countryRuleDenied) return countryRuleDenied;
		await repository.deleteStreamCountryRuleForStream(ctx.params.id!, selection.stream.id);
		invalidateStreamNetworkPolicy(selection.stream.id);
		await recordAdminAudit({
			actor: user,
			action: "stream_country_rule.delete",
			resourceType: "stream_country_rule",
			resourceId: ctx.params.id!,
			summary: `Deleted a country rule on stream ${selection.stream.name} (port ${selection.stream.incoming_port})`,
			ip: getClientIp(ctx) ?? "unknown",
		});
		return jsonResponse({ deleted: true });
	});

	app.post("/_burrowgate/api/admin/streams/asn-rules", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedStream(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.stream) return jsonResponse({ error: "No stream configured" }, 400);
		const asnRuleDenied = requireLevel(await streamAccessLevel(user, selection.stream.id), "manage");
		if (asnRuleDenied) return asnRuleDenied;
		const body = (await ctx.req.json()) as { asn?: number | string; action?: StreamRuleAction; reason?: string; expiresAt?: number | string | null };
		if (!body.asn || !["allow", "block"].includes(body.action ?? "")) {
			return jsonResponse({ error: "Invalid ASN rule" }, 400);
		}
		const expiresAt = body.expiresAt === null || body.expiresAt === undefined || body.expiresAt === "" ? null : Number(body.expiresAt);
		if (expiresAt !== null && (!Number.isFinite(expiresAt) || expiresAt <= Date.now())) {
			return jsonResponse({ error: "Expiration must be in the future" }, 400);
		}
		try {
			const rule = await addStreamAsnRule(selection.stream.id, body.asn, body.action!, body.reason ?? "", expiresAt);
			await streamProxyManager.enforceNetworkPolicy(selection.stream);
			await recordAdminAudit({
				actor: user,
				action: "stream_asn_rule.create",
				resourceType: "stream_asn_rule",
				resourceId: rule.id,
				summary: `Added ASN rule (${rule.action}) for AS${rule.asn} on stream ${selection.stream.name} (port ${selection.stream.incoming_port})`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse(rule, 201);
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Invalid ASN rule" }, 400);
		}
	});

	app.delete("/_burrowgate/api/admin/streams/asn-rules/:id", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedStream(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.stream) return jsonResponse({ error: "No stream configured" }, 400);
		const asnRuleDenied = requireLevel(await streamAccessLevel(user, selection.stream.id), "manage");
		if (asnRuleDenied) return asnRuleDenied;
		await repository.deleteStreamAsnRuleForStream(ctx.params.id!, selection.stream.id);
		invalidateStreamNetworkPolicy(selection.stream.id);
		await recordAdminAudit({
			actor: user,
			action: "stream_asn_rule.delete",
			resourceType: "stream_asn_rule",
			resourceId: ctx.params.id!,
			summary: `Deleted an ASN rule on stream ${selection.stream.name} (port ${selection.stream.incoming_port})`,
			ip: getClientIp(ctx) ?? "unknown",
		});
		return jsonResponse({ deleted: true });
	});

	app.get("/_burrowgate/api/admin/streams/ip-rules", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const url = new URL(ctx.req.url);
		const selection = await selectedStream(url, user);
		if (selection.error) return selection.error;
		if (!selection.stream) return jsonResponse({ items: [], page: 1, pageSize: config.adminPageSize, total: 0, totalPages: 1 });
		return jsonResponse(
			await repository.pagedStreamRules({
				streamId: selection.stream.id,
				page: integerParam(url, "page", 1, 1, 1_000_000),
				pageSize: integerParam(url, "pageSize", config.adminPageSize, 10, 200),
				search: stringParam(url, "search"),
				action: streamRuleActionParam(url),
				state: ruleStateParam(url),
				sortBy: ruleSortBy(url),
				sortDirection: sortDirection(url),
			}),
		);
	});

	app.post("/_burrowgate/api/admin/streams/ip-rules", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedStream(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.stream) return jsonResponse({ error: "No stream configured" }, 400);
		const ipRuleDenied = requireLevel(await streamAccessLevel(user, selection.stream.id), "manage");
		if (ipRuleDenied) return ipRuleDenied;
		const body = (await ctx.req.json()) as { networkCidr?: string; action?: StreamRuleAction; reason?: string; expiresAt?: number | string | null };
		if (!body.networkCidr || !["allow", "block"].includes(body.action ?? "")) {
			return jsonResponse({ error: "Invalid rule" }, 400);
		}
		const parsedExpiresAt = body.expiresAt === null || body.expiresAt === undefined || body.expiresAt === "" ? null : Number(body.expiresAt);
		if (parsedExpiresAt !== null && (!Number.isFinite(parsedExpiresAt) || parsedExpiresAt <= Date.now())) {
			return jsonResponse({ error: "Expiration must be in the future" }, 400);
		}
		try {
			const rule = await addStreamIpRule(selection.stream.id, body.networkCidr, body.action!, body.reason ?? "", parsedExpiresAt);
			await streamProxyManager.enforceNetworkPolicy(selection.stream);
			await recordAdminAudit({
				actor: user,
				action: "stream_ip_rule.create",
				resourceType: "stream_ip_rule",
				resourceId: rule.id,
				summary: `Added IP rule (${rule.action}) for ${rule.network_cidr} on stream ${selection.stream.name} (port ${selection.stream.incoming_port})`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse(rule, 201);
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Invalid rule" }, 400);
		}
	});

	app.delete("/_burrowgate/api/admin/streams/ip-rules/:id", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedStream(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.stream) return jsonResponse({ error: "No stream configured" }, 400);
		const ipRuleDenied = requireLevel(await streamAccessLevel(user, selection.stream.id), "manage");
		if (ipRuleDenied) return ipRuleDenied;
		await repository.deleteStreamRuleForStream(ctx.params.id!, selection.stream.id);
		invalidateStreamNetworkPolicy(selection.stream.id);
		await recordAdminAudit({
			actor: user,
			action: "stream_ip_rule.delete",
			resourceType: "stream_ip_rule",
			resourceId: ctx.params.id!,
			summary: `Deleted an IP rule on stream ${selection.stream.name} (port ${selection.stream.incoming_port})`,
			ip: getClientIp(ctx) ?? "unknown",
		});
		return jsonResponse({ deleted: true });
	});

	app.post("/_burrowgate/api/admin/streams/ip-rules/bulk-delete", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedStream(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.stream) return jsonResponse({ error: "No stream configured" }, 400);
		const ipRuleDenied = requireLevel(await streamAccessLevel(user, selection.stream.id), "manage");
		if (ipRuleDenied) return ipRuleDenied;
		const body = (await ctx.req.json()) as { ids?: unknown };
		const ids = Array.isArray(body.ids) ? body.ids.filter((id): id is string => typeof id === "string") : [];
		if (ids.length === 0 || ids.length > 200) return jsonResponse({ error: "Provide 1 to 200 rule IDs" }, 400);
		const deleted = await repository.deleteStreamRulesForStream(ids, selection.stream.id);
		invalidateStreamNetworkPolicy(selection.stream.id);
		await recordAdminAudit({
			actor: user,
			action: "stream_ip_rule.bulk_delete",
			resourceType: "stream",
			resourceId: selection.stream.id,
			summary: `Deleted ${deleted} IP rule(s) on stream ${selection.stream.name} (port ${selection.stream.incoming_port})`,
			ip: getClientIp(ctx) ?? "unknown",
		});
		return jsonResponse({ deleted });
	});

	app.get("/_burrowgate/api/admin/streams/protection-catalog", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		return jsonResponse({ items: streamRuleSetCatalog() });
	});

	app.get("/_burrowgate/api/admin/streams/protection-policy", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const selection = await selectedStream(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.stream) return jsonResponse({ error: "No stream configured" }, 400);
		return jsonResponse(resolveStreamProtectionPolicy(selection.stream));
	});

	app.addRoute("PUT", "/_burrowgate/api/admin/streams/protection-policy", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedStream(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.stream) return jsonResponse({ error: "No stream configured" }, 400);
		const protectionPolicyDenied = requireLevel(await streamAccessLevel(user, selection.stream.id), "manage");
		if (protectionPolicyDenied) return protectionPolicyDenied;
		try {
			const body = await ctx.req.json();
			const protectionPolicyJson = serializeStreamProtectionPolicy(body, selection.stream.protection_policy_json);
			await repository.updateStreamProtectionPolicy(selection.stream.id, protectionPolicyJson, Date.now());
			streamProxyManager.refreshRecord({ ...selection.stream, protection_policy_json: protectionPolicyJson });
			await recordAdminAudit({
				actor: user,
				action: "stream_protection_policy.update",
				resourceType: "stream",
				resourceId: selection.stream.id,
				summary: `Updated protection policy for stream ${selection.stream.name} (port ${selection.stream.incoming_port})`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse(resolveStreamProtectionPolicy({ ...selection.stream, protection_policy_json: protectionPolicyJson }));
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to update protection policy" }, 400);
		}
	});

	app.get("/_burrowgate/api/admin/streams/bandwidth-limit-policy", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const selection = await selectedStream(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.stream) return jsonResponse({ error: "No stream configured" }, 400);
		return jsonResponse(resolveStreamBandwidthPolicy(selection.stream));
	});

	app.addRoute("PUT", "/_burrowgate/api/admin/streams/bandwidth-limit-policy", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedStream(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.stream) return jsonResponse({ error: "No stream configured" }, 400);
		const bandwidthPolicyDenied = requireLevel(await streamAccessLevel(user, selection.stream.id), "manage");
		if (bandwidthPolicyDenied) return bandwidthPolicyDenied;
		try {
			const body = await ctx.req.json();
			const bandwidthPolicyJson = serializeStreamBandwidthPolicy(body, selection.stream.bandwidth_policy_json);
			await repository.updateStreamBandwidthPolicy(selection.stream.id, bandwidthPolicyJson, Date.now());
			streamProxyManager.refreshRecord({ ...selection.stream, bandwidth_policy_json: bandwidthPolicyJson });
			await recordAdminAudit({
				actor: user,
				action: "stream_bandwidth_policy.update",
				resourceType: "stream",
				resourceId: selection.stream.id,
				summary: `Updated bandwidth limit policy for stream ${selection.stream.name} (port ${selection.stream.incoming_port})`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			return jsonResponse(resolveStreamBandwidthPolicy({ ...selection.stream, bandwidth_policy_json: bandwidthPolicyJson }));
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to update bandwidth limit policy" }, 400);
		}
	});

	app.get("/_burrowgate/api/admin/streams/notification-policy", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const selection = await selectedStream(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.stream) return jsonResponse({ error: "No stream configured" }, 400);
		const policy = resolveStreamNotificationPolicy(selection.stream);
		return jsonResponse({ enabled: policy.enabled, provider: policy.provider, webhookConfigured: Boolean(policy.webhookUrl), eventTypes: policy.eventTypes });
	});

	app.addRoute("PUT", "/_burrowgate/api/admin/streams/notification-policy", async (ctx: any) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const csrf = mutationGuard(ctx.req);
		if (csrf) return csrf;
		const { user } = guarded;
		const selection = await selectedStream(new URL(ctx.req.url), user);
		if (selection.error) return selection.error;
		if (!selection.stream) return jsonResponse({ error: "No stream configured" }, 400);
		const notificationPolicyDenied = requireLevel(await streamAccessLevel(user, selection.stream.id), "manage");
		if (notificationPolicyDenied) return notificationPolicyDenied;
		try {
			const body = await ctx.req.json();
			const parsed = parseStreamNotificationPolicyInput(body, selection.stream.notification_policy_json);
			const existingPolicy = storedStreamNotificationPolicy(selection.stream.notification_policy_json);
			const webhookUrl = parsed.clearWebhook ? null : parsed.webhookUrl ? await encryptSecret(parsed.webhookUrl) : existingPolicy.webhookUrl;
			if (parsed.enabled && !webhookUrl) throw new Error("A webhook URL is required when notifications are enabled");
			const webhookSecret = parsed.clearWebhook ? null : parsed.webhookSecret ? await encryptSecret(parsed.webhookSecret) : existingPolicy.webhookSecret;
			const notificationPolicyJson = JSON.stringify({
				enabled: parsed.enabled,
				provider: parsed.provider,
				webhookUrl,
				webhookSecret,
				eventTypes: parsed.eventTypes,
			});
			await repository.updateStreamNotificationPolicy(selection.stream.id, notificationPolicyJson, Date.now());
			await recordAdminAudit({
				actor: user,
				action: "stream_notification_policy.update",
				resourceType: "stream",
				resourceId: selection.stream.id,
				summary: `Updated notification policy for stream ${selection.stream.name} (port ${selection.stream.incoming_port})`,
				ip: getClientIp(ctx) ?? "unknown",
			});
			const policy = resolveStreamNotificationPolicy({ ...selection.stream, notification_policy_json: notificationPolicyJson });
			return jsonResponse({ enabled: policy.enabled, provider: policy.provider, webhookConfigured: Boolean(policy.webhookUrl), eventTypes: policy.eventTypes });
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to update notification policy" }, 400);
		}
	});

	app.get("/_burrowgate/api/admin/streams/notifications", async (ctx) => {
		const guarded = await guard(ctx.req);
		if (guarded instanceof Response) return guarded;
		const { user } = guarded;
		const url = new URL(ctx.req.url);
		const selection = await selectedStream(url, user);
		if (selection.error) return selection.error;
		if (!selection.stream) return jsonResponse({ error: "No stream configured" }, 400);
		const result = await repository.pagedNotificationsForStream({
			streamId: selection.stream.id,
			page: integerParam(url, "page", 1, 1, 1_000_000),
			pageSize: integerParam(url, "pageSize", 25, 10, 200),
			search: stringParam(url, "search"),
			type: notificationTypeParam(url),
			status: notificationStatusParam(url),
			sortBy: notificationSortBy(url),
			sortDirection: sortDirection(url),
		});
		return jsonResponse({
			...result,
			items: result.items.map((event) => ({
				id: event.id,
				type: event.type,
				severity: event.severity,
				summary: event.summary,
				status: event.delivery_status,
				attempts: Number(event.delivery_attempts),
				lastError: event.delivery_last_error,
				occurredAt: Number(event.occurred_at),
				createdAt: Number(event.created_at),
				deliveredAt: event.delivered_at === null ? null : Number(event.delivered_at),
			})),
		});
	});
}
