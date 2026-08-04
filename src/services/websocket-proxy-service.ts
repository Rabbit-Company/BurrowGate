import { ipExtract } from "@rabbit-company/web-middleware/ip-extract";
import { config, type RequestTransport } from "../config.ts";
import { repository } from "../db/repository.ts";
import type { AccessSessionRecord, SiteRecord } from "../types.ts";
import { jsonResponse, normalizeHost, requestHost } from "../utils/http.ts";
import { createFlow } from "./challenge-service.ts";
import { siteHostname } from "./certificate-service.ts";
import { recordEvent } from "./event-service.ts";
import { siteErrorResponse } from "./error-response-service.ts";
import { evaluateIp } from "./ip-rule-service.ts";
import { upstreamHeaders, upstreamUrl, type OriginAccessStatus } from "./proxy-service.ts";
import { resolveRoutePolicy } from "./route-policy-service.ts";
import { applyRouteRateLimit } from "./rate-limit-service.ts";
import { findAccessSession, userAgentHash } from "./session-service.ts";
import { resolveSiteForHost } from "./site-service.ts";
import type { HeadersInit } from "bun";
import { Logger } from "../logger.ts";

export type ProxiedWebSocketMessage = string | ArrayBuffer | Uint8Array;

export interface WebSocketBridgeData {
	id: string;
	siteId: string;
	sessionId: string | null;
	clientIp: string;
	targetUrl: string;
	openedAt: number;
	upstream: WebSocket;
	downstream: Bun.ServerWebSocket<WebSocketBridgeData> | null;
	preOpenQueue: ProxiedWebSocketMessage[];
	preOpenQueueBytes: number;
	closed: boolean;
	sessionExpiresAt: number | null;
	sessionExpiryTimer: ReturnType<typeof setTimeout> | null;
}

export interface WebSocketUpgradeServer {
	requestIP(request: Request): { address: string } | null;
	upgrade(request: Request, options: { data: WebSocketBridgeData; headers?: HeadersInit }): boolean;
}

function connectionHasUpgrade(request: Request): boolean {
	const connection = request.headers.get("connection") ?? "";
	return connection.split(",").some((token) => token.trim().toLowerCase() === "upgrade");
}

export function isWebSocketUpgrade(request: Request): boolean {
	return request.method === "GET" && request.headers.get("upgrade")?.trim().toLowerCase() === "websocket" && connectionHasUpgrade(request);
}

export function websocketUpstreamUrl(site: SiteRecord, request: Request): URL {
	const target = upstreamUrl(site, request);
	if (target.protocol === "http:") target.protocol = "ws:";
	else if (target.protocol === "https:") target.protocol = "wss:";
	else throw new Error(`Unsupported WebSocket origin protocol: ${target.protocol}`);
	return target;
}

export async function websocketUpstreamHeaders(
	request: Request,
	site: SiteRecord,
	ip: string,
	session: AccessSessionRecord | null,
	accessStatus: OriginAccessStatus = session ? "verified" : "allowlisted",
	transport?: RequestTransport,
): Promise<Headers> {
	const headers = await upstreamHeaders(request, site, ip, session, accessStatus, transport);

	// Bun creates a fresh upstream WebSocket handshake. Never reuse key/version
	// or compression negotiation from the downstream handshake. Compression is
	// negotiated independently on each side of the bridge.
	headers.delete("accept-encoding");
	headers.delete("content-length");
	headers.delete("sec-websocket-key");
	headers.delete("sec-websocket-version");
	headers.delete("sec-websocket-extensions");

	return headers;
}

function headersObject(headers: Headers): Record<string, string> {
	return Object.fromEntries(headers.entries());
}

interface BunWebSocketConstructor {
	new (url: string, options: { headers: Record<string, string> }): WebSocket;
}

function messageByteLength(message: ProxiedWebSocketMessage): number {
	if (typeof message === "string") return Buffer.byteLength(message);
	return message.byteLength;
}

function truncateCloseReason(reason: string): string {
	let value = reason;
	while (value && Buffer.byteLength(value) > 123) value = value.slice(0, -1);
	return value;
}

function downstreamCloseCode(code: number): number {
	if (code >= 1000 && code <= 4999 && ![1004, 1005, 1006, 1015].includes(code)) return code;
	return 1011;
}

function upstreamCloseCode(code: number): number {
	return code === 1000 || (code >= 3000 && code <= 4999) ? code : 1000;
}

function closeBridge(bridge: WebSocketBridgeData, code: number, reason: string, initiator: "upstream" | "downstream" | "proxy"): void {
	if (bridge.closed) return;
	bridge.closed = true;
	if (bridge.sessionExpiryTimer) {
		clearTimeout(bridge.sessionExpiryTimer);
		bridge.sessionExpiryTimer = null;
	}
	const safeReason = truncateCloseReason(reason);

	if (initiator !== "upstream" && bridge.upstream.readyState < WebSocket.CLOSING) {
		try {
			bridge.upstream.close(upstreamCloseCode(code), safeReason);
		} catch {
			bridge.upstream.close();
		}
	}

	const downstream = bridge.downstream;
	if (initiator !== "downstream" && downstream && downstream.readyState < WebSocket.CLOSING) {
		try {
			downstream.close(downstreamCloseCode(code), safeReason);
		} catch {
			downstream.close(1011, "WebSocket proxy closed");
		}
	}
}

function forwardToDownstream(bridge: WebSocketBridgeData, message: ProxiedWebSocketMessage): void {
	if (bridge.closed) return;
	const downstream = bridge.downstream;
	if (!downstream || downstream.readyState !== WebSocket.OPEN) {
		const size = messageByteLength(message);
		if (bridge.preOpenQueueBytes + size > config.websocket.preOpenQueueLimitBytes) {
			closeBridge(bridge, 1013, "WebSocket proxy pre-open queue exceeded", "proxy");
			return;
		}
		bridge.preOpenQueue.push(message);
		bridge.preOpenQueueBytes += size;
		return;
	}

	const result = downstream.send(message);
	// Bun returns 0 when a message was dropped. A -1 return value means the
	// message was accepted but backpressure is active, so it must not be resent.
	if (result === 0) closeBridge(bridge, 1011, "WebSocket downstream send failed", "proxy");
}

function flushPreOpenQueue(bridge: WebSocketBridgeData): void {
	if (bridge.closed || !bridge.downstream) return;
	const queued = bridge.preOpenQueue;
	bridge.preOpenQueue = [];
	bridge.preOpenQueueBytes = 0;
	for (const message of queued) {
		forwardToDownstream(bridge, message);
		if (bridge.closed) break;
	}
}

const websocketIpExtract = ipExtract(config.proxyPreset);

async function clientIpForUpgrade(request: Request, server: WebSocketUpgradeServer): Promise<string> {
	const directIp = server.requestIP(request)?.address;
	const context = { req: request, clientIp: directIp } as Parameters<typeof websocketIpExtract>[0];

	try {
		await websocketIpExtract(context, async () => {});
	} catch (error) {
		Logger.error("Failed to extract WebSocket client IP", { error });
	}

	return context.clientIp ?? directIp ?? "unknown";
}

export function offeredWebSocketProtocols(request: Request): string[] {
	const value = request.headers.get("sec-websocket-protocol");
	if (!value) return [];
	return value
		.split(",")
		.map((protocol) => protocol.trim())
		.filter(Boolean);
}

async function openUpstreamWebSocket(target: URL, headers: Headers, request: Request): Promise<WebSocket> {
	return await new Promise<WebSocket>((resolve, reject) => {
		let settled = false;
		const BunWebSocket = WebSocket as unknown as BunWebSocketConstructor;
		const socket = new BunWebSocket(target.toString(), { headers: headersObject(headers) });
		socket.binaryType = "arraybuffer";

		const finish = (error?: Error): void => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			request.signal.removeEventListener("abort", onAbort);
			socket.removeEventListener("open", onOpen);
			socket.removeEventListener("error", onError);
			socket.removeEventListener("close", onCloseBeforeOpen);
			if (error) reject(error);
			else resolve(socket);
		};
		const onOpen = (): void => finish();
		const onError = (): void => finish(new Error(`Unable to connect to WebSocket origin ${target.host}`));
		const onCloseBeforeOpen = (event: CloseEvent): void => {
			finish(new Error(`WebSocket origin closed during handshake (${event.code || "no status"})`));
		};
		const onAbort = (): void => {
			try {
				socket.close();
			} catch {
				/* no-op */
			}
			finish(new Error("Downstream WebSocket request was aborted"));
		};
		const timer = setTimeout(() => {
			try {
				socket.close();
			} catch {
				/* no-op */
			}
			finish(new Error(`WebSocket origin handshake timed out after ${config.websocket.connectTimeoutMs} ms`));
		}, config.websocket.connectTimeoutMs);

		socket.addEventListener("open", onOpen, { once: true });
		socket.addEventListener("error", onError, { once: true });
		socket.addEventListener("close", onCloseBeforeOpen, { once: true });
		request.signal.addEventListener("abort", onAbort, { once: true });
	});
}

function attachUpstreamBridgeEvents(bridge: WebSocketBridgeData): void {
	bridge.upstream.addEventListener("message", (event: MessageEvent) => {
		const value = event.data;
		if (typeof value === "string" || value instanceof ArrayBuffer) {
			forwardToDownstream(bridge, value);
			return;
		}
		if (ArrayBuffer.isView(value)) {
			forwardToDownstream(bridge, new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
			return;
		}
		if (value instanceof Blob) {
			void value
				.arrayBuffer()
				.then((buffer) => forwardToDownstream(bridge, buffer))
				.catch(() => closeBridge(bridge, 1011, "Unable to read upstream WebSocket message", "proxy"));
		}
	});
	bridge.upstream.addEventListener("close", (event: CloseEvent) => {
		closeBridge(bridge, downstreamCloseCode(event.code), event.reason || "WebSocket origin closed", "upstream");
	});
	bridge.upstream.addEventListener("error", () => {
		closeBridge(bridge, 1011, "WebSocket origin error", "upstream");
	});
}

export function selectedProtocolHeaders(upstream: Pick<WebSocket, "protocol">): HeadersInit | undefined {
	return upstream.protocol ? new Headers({ "sec-websocket-protocol": upstream.protocol }) : undefined;
}

function scheduleSessionExpiry(bridge: WebSocketBridgeData): void {
	if (bridge.closed || bridge.sessionExpiresAt === null) return;
	const remaining = bridge.sessionExpiresAt - Date.now();
	if (remaining <= 0) {
		closeBridge(bridge, 4001, "BurrowGate session expired", "proxy");
		return;
	}

	// JavaScript timers are commonly limited to a signed 32-bit delay. Re-arm
	// long sessions in chunks so a large configured TTL cannot overflow.
	bridge.sessionExpiryTimer = setTimeout(() => scheduleSessionExpiry(bridge), Math.min(remaining, 2_147_000_000));
}

export async function handleWebSocketUpgrade(
	request: Request,
	server: WebSocketUpgradeServer,
	transport: RequestTransport = new URL(request.url).protocol === "https:" ? "https" : "http",
): Promise<Response | undefined> {
	const started = performance.now();
	const incomingUrl = new URL(request.url);
	if (incomingUrl.pathname.startsWith("/_burrowgate/")) {
		return jsonResponse({ error: "No BurrowGate control-plane WebSocket is registered for this path" }, 404);
	}
	const host = normalizeHost(requestHost(request));
	const site = await resolveSiteForHost(host);
	if (!site) return jsonResponse({ error: `No BurrowGate site is configured for ${host}` }, 421);

	const ip = await clientIpForUpgrade(request, server);
	const url = incomingUrl;
	const eventBase: {
		siteId: string;
		ip: string;
		method: string;
		path: string;
		countryCode?: string | null;
	} = {
		siteId: site.id,
		ip,
		method: request.method,
		path: url.pathname + url.search,
	};

	if (!config.websocket.enabled) {
		await recordEvent({ ...eventBase, sessionId: null, status: 501, decision: "websocket-disabled", latencyMs: Math.round(performance.now() - started) });
		return siteErrorResponse(site, request, {
			status: 501,
			code: "websocket_disabled",
			error: "WebSocket proxying is disabled",
			clientIp: ip,
			reason: "This BurrowGate instance is not configured to proxy WebSocket connections.",
		});
	}

	if (transport === "http" && config.https.enabled) {
		const tlsSettings = await repository.ensureTlsSettings(site.id);
		if (tlsSettings.force_https === 1 && tlsSettings.mode !== "disabled") {
			const certificate = await repository.certificateBySite(site.id);
			if (certificate?.status === "active" && Number(certificate.expires_at ?? 0) > Date.now()) {
				const port = config.https.publicPort === 443 ? "" : `:${config.https.publicPort}`;
				const location = `https://${siteHostname(site)}${port}${url.pathname}${url.search}`;
				return new Response(null, { status: 308, headers: { location, "cache-control": "no-store" } });
			}
		}
	}

	const ipRule = await evaluateIp(site, ip);
	eventBase.countryCode = ipRule.countryCode;
	if (ipRule.action === "block") {
		await recordEvent({ ...eventBase, sessionId: null, status: 403, decision: "blocked", latencyMs: Math.round(performance.now() - started) });
		return siteErrorResponse(site, request, {
			status: 403,
			code: "network_blocked",
			error: "Access blocked by BurrowGate",
			clientIp: ip,
			reason: ipRule.reason || "This request was blocked by network policy.",
		});
	}

	const route = await resolveRoutePolicy(site, request.method, url.pathname);
	if (route.accessMode === "block") {
		await recordEvent({ ...eventBase, sessionId: null, status: 403, decision: "route-blocked", latencyMs: Math.round(performance.now() - started) });
		return siteErrorResponse(site, request, {
			status: 403,
			code: "route_blocked",
			error: "This WebSocket route is blocked by BurrowGate",
			clientIp: ip,
			routePolicy: route.policy?.name,
			reason: route.policy?.name ? `Blocked by route policy ${route.policy.name}.` : "This WebSocket route is not available.",
		});
	}

	const needsSession = route.accessMode === "challenge" || ipRule.action === "challenge" || route.policy?.rate_limit_key_mode === "session-or-ip";
	const candidateSession = needsSession ? await findAccessSession(request, site, ip) : null;
	const rateLimit = await applyRouteRateLimit(route.policy, request, ip, candidateSession);
	if (rateLimit.limited) {
		await recordEvent({
			...eventBase,
			sessionId: candidateSession?.id ?? null,
			status: 429,
			decision: "rate-limited",
			latencyMs: Math.round(performance.now() - started),
		});
		return siteErrorResponse(
			site,
			request,
			{
				status: 429,
				code: "rate_limited",
				error: "Too many requests",
				clientIp: ip,
				routePolicy: route.policy?.name,
				reason: "The WebSocket connection rate limit was exceeded.",
				retryAfterSeconds: rateLimit.retryAfterSeconds,
			},
			rateLimit.headers,
		);
	}

	const effectiveAccess = ipRule.action === "allow" ? "bypass" : ipRule.action === "challenge" ? "challenge" : route.accessMode;
	const session = effectiveAccess === "challenge" ? candidateSession : null;
	if (effectiveAccess === "challenge" && !session) {
		const flow = await createFlow(site, url.pathname + url.search, ip, await userAgentHash(request), route.challengePolicy);
		const verificationUrl = `/_burrowgate/verify?flow=${encodeURIComponent(flow.id)}`;
		await recordEvent({ ...eventBase, sessionId: null, status: 428, decision: "challenge-required", latencyMs: Math.round(performance.now() - started) });
		const headers = new Headers(rateLimit.headers);
		headers.set("burrowgate-verification", verificationUrl);
		return siteErrorResponse(
			site,
			request,
			{
				status: 428,
				code: "verification_required",
				error: "Verification is required before opening this WebSocket",
				clientIp: ip,
				routePolicy: route.policy?.name,
				reason: "Complete verification before opening this WebSocket again.",
				verificationUrl,
			},
			headers,
		);
	}

	const accessStatus: OriginAccessStatus = ipRule.action === "allow" ? "allowlisted" : effectiveAccess === "bypass" ? "bypass" : "verified";
	const target = websocketUpstreamUrl(site, request);
	try {
		const headers = await websocketUpstreamHeaders(request, site, ip, session, accessStatus, transport);
		const upstream = await openUpstreamWebSocket(target, headers, request);
		const offeredProtocols = offeredWebSocketProtocols(request);
		if (offeredProtocols.length > 0 && !upstream.protocol) {
			try {
				upstream.close(1000, "Upstream did not select a WebSocket subprotocol");
			} catch {
				/* no-op */
			}
			throw new Error(`WebSocket origin ${target.host} did not select any offered subprotocol`);
		}
		if (upstream.protocol && !offeredProtocols.includes(upstream.protocol)) {
			try {
				upstream.close(1002, "Invalid upstream WebSocket subprotocol");
			} catch {
				/* no-op */
			}
			throw new Error(`WebSocket origin selected an unoffered subprotocol: ${upstream.protocol}`);
		}

		const bridge: WebSocketBridgeData = {
			id: crypto.randomUUID(),
			siteId: site.id,
			sessionId: session?.id ?? null,
			clientIp: ip,
			targetUrl: target.toString(),
			openedAt: Date.now(),
			upstream,
			downstream: null,
			preOpenQueue: [],
			preOpenQueueBytes: 0,
			closed: false,
			sessionExpiresAt: session?.expires_at ?? null,
			sessionExpiryTimer: null,
		};
		attachUpstreamBridgeEvents(bridge);

		const upgradeHeaders = new Headers(rateLimit.headers);
		if (upstream.protocol) upgradeHeaders.set("sec-websocket-protocol", upstream.protocol);
		const upgraded = server.upgrade(request, [...upgradeHeaders].length > 0 ? { data: bridge, headers: upgradeHeaders } : { data: bridge });
		if (!upgraded) {
			closeBridge(bridge, 1011, "BurrowGate could not upgrade the downstream connection", "proxy");
			await recordEvent({
				...eventBase,
				sessionId: session?.id ?? null,
				status: 400,
				decision: "websocket-upgrade-failed",
				latencyMs: Math.round(performance.now() - started),
			});
			return siteErrorResponse(
				site,
				request,
				{
					status: 400,
					code: "websocket_upgrade_invalid",
					error: "Invalid WebSocket upgrade request",
					clientIp: ip,
					routePolicy: route.policy?.name,
					reason: "The downstream connection could not be upgraded to WebSocket.",
				},
				rateLimit.headers,
			);
		}

		const decision = accessStatus === "allowlisted" ? "websocket-allowlisted" : accessStatus === "bypass" ? "websocket-unprotected" : "websocket-proxied";
		await recordEvent({ ...eventBase, sessionId: session?.id ?? null, status: 101, decision, latencyMs: Math.round(performance.now() - started) });
		return undefined;
	} catch (error) {
		await recordEvent({
			...eventBase,
			sessionId: session?.id ?? null,
			status: 502,
			decision: "websocket-origin-error",
			latencyMs: Math.round(performance.now() - started),
		});
		Logger.error(`WebSocket proxy failed for ${target}`, { error });
		return siteErrorResponse(
			site,
			request,
			{
				status: 502,
				code: "websocket_origin_unavailable",
				error: "Protected WebSocket origin is unavailable",
				clientIp: ip,
				routePolicy: route.policy?.name,
				reason: "BurrowGate could not connect to the configured WebSocket origin.",
			},
			rateLimit.headers,
		);
	}
}

export const websocketProxyHandler: Bun.WebSocketHandler<WebSocketBridgeData> = {
	data: {} as WebSocketBridgeData,
	idleTimeout: config.websocket.idleTimeoutSeconds,
	maxPayloadLength: config.websocket.maxPayloadBytes,
	backpressureLimit: config.websocket.backpressureLimitBytes,
	closeOnBackpressureLimit: true,
	sendPings: true,
	perMessageDeflate: true,

	open(ws) {
		const bridge = ws.data;
		bridge.downstream = ws;
		if (bridge.closed || bridge.upstream.readyState !== WebSocket.OPEN) {
			ws.close(1011, "WebSocket origin is no longer available");
			return;
		}
		flushPreOpenQueue(bridge);
		scheduleSessionExpiry(bridge);
	},

	message(ws, message) {
		const bridge = ws.data;
		if (bridge.closed || bridge.upstream.readyState !== WebSocket.OPEN) {
			closeBridge(bridge, 1011, "WebSocket origin is unavailable", "proxy");
			return;
		}
		const size = messageByteLength(message);
		if (bridge.upstream.bufferedAmount + size > config.websocket.upstreamBufferLimitBytes) {
			closeBridge(bridge, 1013, "WebSocket origin is receiving data too slowly", "proxy");
			return;
		}
		try {
			bridge.upstream.send(message);
		} catch {
			closeBridge(bridge, 1011, "Unable to forward WebSocket message", "proxy");
		}
	},

	close(ws, code, reason) {
		closeBridge(ws.data, code, reason || "WebSocket client closed", "downstream");
	},

	drain(ws) {
		flushPreOpenQueue(ws.data);
	},
};
