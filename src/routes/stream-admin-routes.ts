import type { Web } from "@rabbit-company/web";
import { repository } from "../db/repository.ts";
import { config } from "../config.ts";
import { getAdminSession } from "../services/session-service.ts";
import { buildStream, streamView, type StreamInput } from "../services/stream-service.ts";
import { streamProxyManager } from "../services/stream-proxy-service.ts";
import { flushStreamMonitoring } from "../services/stream-monitoring-service.ts";
import { geoIpStatus } from "../services/geoip-service.ts";
import type { StreamEventType, StreamProtocol, StreamRecord } from "../types.ts";
import { htmlResponse, jsonResponse, sameOriginRequest } from "../utils/http.ts";
import { streamsAdminPage } from "../ui/streams-admin-page.ts";

const METRIC_BUCKETS_MS = [
	60_000, 300_000, 900_000, 1_800_000, 3_600_000, 7_200_000, 10_800_000, 21_600_000, 43_200_000, 86_400_000, 172_800_000, 345_600_000, 604_800_000,
] as const;

async function guard(request: Request): Promise<Response | null> {
	return (await getAdminSession(request)) ? null : jsonResponse({ error: "Unauthorized" }, 401);
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

function eventTypeParam(url: URL): StreamEventType | undefined {
	const value = stringParam(url, "eventType");
	return value === "connected" || value === "disconnected" || value === "upstream-error" || value === "listener-error" ? value : undefined;
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
	| "reason"
	| "client_to_upstream_bytes"
	| "upstream_to_client_bytes" {
	const value = stringParam(url, "sortBy");
	return value === "event_type" ||
		value === "protocol" ||
		value === "incoming_port" ||
		value === "client_ip" ||
		value === "country_code" ||
		value === "reason" ||
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
		const denied = await guard(ctx.req);
		if (denied) return denied;
		return jsonResponse({
			items: (await repository.allStreams()).map(streamView),
			certificates: (await repository.streamCertificateOptions()).map(certificateView),
			statuses: streamProxyManager.statusesView(),
			defaults: {
				retentionDays: config.eventRetentionDays,
				udpPeerIdleTimeoutSeconds: config.streams.udpPeerIdleTimeoutSeconds,
			},
		});
	});

	app.post("/_burrowgate/api/admin/streams", async (ctx) => {
		const denied = (await guard(ctx.req)) ?? mutationGuard(ctx.req);
		if (denied) return denied;
		try {
			const stream = await buildStream(await body(ctx.req));
			await saveAndActivate(stream);
			return jsonResponse({ stream: streamView(stream), statuses: streamProxyManager.statusesView() }, 201);
		} catch (error) {
			return mutationError(error, "Unable to create stream");
		}
	});

	app.addRoute("PUT", "/_burrowgate/api/admin/streams/:id", async (ctx: any) => {
		const denied = (await guard(ctx.req)) ?? mutationGuard(ctx.req);
		if (denied) return denied;
		const previous = await repository.streamById(ctx.params.id);
		if (!previous) return jsonResponse({ error: "Stream not found" }, 404);
		try {
			const stream = await buildStream(await body(ctx.req), previous);
			await saveAndActivate(stream, previous);
			if (stream.event_retention_days < previous.event_retention_days) {
				await repository.deleteStreamDataBefore(stream.id, Date.now() - stream.event_retention_days * 86_400_000);
			}
			return jsonResponse({ stream: streamView(stream), statuses: streamProxyManager.statusesView() });
		} catch (error) {
			return mutationError(error, "Unable to update stream");
		}
	});

	app.delete("/_burrowgate/api/admin/streams/:id", async (ctx: any) => {
		const denied = (await guard(ctx.req)) ?? mutationGuard(ctx.req);
		if (denied) return denied;
		const stream = await repository.streamById(ctx.params.id);
		if (!stream) return jsonResponse({ error: "Stream not found" }, 404);
		await streamProxyManager.remove(stream.id);
		await flushStreamMonitoring();
		await repository.deleteStream(stream.id);
		return jsonResponse({ deleted: true });
	});

	app.get("/_burrowgate/api/admin/streams/active", async (ctx) => {
		const denied = await guard(ctx.req);
		if (denied) return denied;
		return jsonResponse({ items: streamProxyManager.activeConnections(), statuses: streamProxyManager.statusesView() });
	});

	app.get("/_burrowgate/api/admin/streams/overview", async (ctx) => {
		const denied = await guard(ctx.req);
		if (denied) return denied;
		await flushStreamMonitoring();
		const url = new URL(ctx.req.url);
		const selectedRange = range(url);
		return jsonResponse({
			...(await repository.streamOverview(stringParam(url, "streamId"), selectedRange.since, selectedRange.until)),
			active: streamProxyManager.activeConnections(),
			geoip: geoIpStatus(),
			rangeFrom: selectedRange.since,
			rangeTo: selectedRange.until,
		});
	});

	app.get("/_burrowgate/api/admin/streams/metrics", async (ctx) => {
		const denied = await guard(ctx.req);
		if (denied) return denied;
		await flushStreamMonitoring();
		const url = new URL(ctx.req.url);
		const selectedRange = range(url);
		const durationMs = selectedRange.until - selectedRange.since;
		const bucketMs = metricBucketSize(durationMs);
		return jsonResponse({
			...(await repository.streamMetrics(stringParam(url, "streamId"), selectedRange.since, selectedRange.until, bucketMs)),
			rangeFrom: selectedRange.since,
			rangeTo: selectedRange.until,
			rangeDurationMs: durationMs,
			bucketMs,
		});
	});

	app.get("/_burrowgate/api/admin/streams/events", async (ctx) => {
		const denied = await guard(ctx.req);
		if (denied) return denied;
		await flushStreamMonitoring();
		const url = new URL(ctx.req.url);
		const selectedRange = range(url);
		return jsonResponse(
			await repository.pagedStreamEvents({
				streamId: stringParam(url, "streamId"),
				page: integerParam(url, "page", 1, 1, 1_000_000),
				pageSize: integerParam(url, "pageSize", config.adminPageSize, 10, 200),
				search: stringParam(url, "search"),
				protocol: protocolParam(url),
				eventType: eventTypeParam(url),
				countryCode: stringParam(url, "country")?.toUpperCase(),
				sortBy: eventSortBy(url),
				sortDirection: sortDirection(url),
				...selectedRange,
			}),
		);
	});

	app.get("/_burrowgate/api/admin/streams/bandwidth", async (ctx) => {
		const denied = await guard(ctx.req);
		if (denied) return denied;
		await flushStreamMonitoring();
		const url = new URL(ctx.req.url);
		return jsonResponse(
			await repository.pagedStreamBandwidth({
				streamId: stringParam(url, "streamId"),
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
}
