import { IP_EXTRACTION_PRESETS, ipExtract, type IpExtractionPreset } from "@rabbit-company/web-middleware/ip-extract";
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
import {
	accessIdentityCookieNames,
	accessIdentitySetCookies,
	accessSettingsForSite,
	authenticatedAccessUser,
	clearAccessIdentityCookies,
} from "./access-list-service.ts";
import { resolveSiteForHost } from "./site-service.ts";
import type { HeadersInit } from "bun";
import { Logger } from "../logger.ts";
import { recordBandwidth } from "./bandwidth-service.ts";
import { originHealthManager } from "./origin-health-service.ts";
import { loadBalancer } from "./load-balancer-service.ts";
import type { ResolvedWebSocketPolicy } from "./websocket-policy-service.ts";
import {
	inspectManagedRequest,
	type ManagedProtectionMatch,
	type ManagedProtectionSeverity,
	type ManagedProtectionStatus,
} from "./managed-protection-service.ts";

export type ProxiedWebSocketMessage = string | ArrayBuffer | Uint8Array;

export interface WebSocketBridgeData {
	id: string;
	siteId: string;
	sessionId: string | null;
	clientIp: string;
	countryCode: string | null;
	targetUrl: string;
	openedAt: number;
	upstream: WebSocket;
	downstream: Bun.ServerWebSocket<WebSocketBridgeData> | null;
	preOpenQueue: ProxiedWebSocketMessage[];
	preOpenQueueBytes: number;
	closed: boolean;
	sessionExpiresAt: number | null;
	sessionExpiryTimer: ReturnType<typeof setTimeout> | null;
	idleTimer: ReturnType<typeof setTimeout> | null;
	websocketPolicy: ResolvedWebSocketPolicy;
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

export function websocketUpstreamUrl(site: SiteRecord, request: Request, originUrl = site.origin_url): URL {
	const target = upstreamUrl({ ...site, origin_url: originUrl }, request);
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
	authenticatedUsername: string | null = null,
	sendUsernameToUpstream = false,
): Promise<Headers> {
	const headers = await upstreamHeaders(request, site, ip, session, accessStatus, transport, authenticatedUsername, sendUsernameToUpstream);

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
	if (bridge.idleTimer) {
		clearTimeout(bridge.idleTimer);
		bridge.idleTimer = null;
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

function touchBridgeActivity(bridge: WebSocketBridgeData): void {
	if (bridge.closed) return;
	if (bridge.idleTimer) clearTimeout(bridge.idleTimer);
	bridge.idleTimer = setTimeout(
		() => closeBridge(bridge, 1001, "WebSocket connection was idle for too long", "proxy"),
		bridge.websocketPolicy.idleTimeoutSeconds * 1_000,
	);
}

function forwardToDownstream(bridge: WebSocketBridgeData, message: ProxiedWebSocketMessage): void {
	if (bridge.closed) return;
	const size = messageByteLength(message);
	if (size > bridge.websocketPolicy.maxPayloadBytes) {
		closeBridge(bridge, 1009, "WebSocket message exceeds the configured limit", "proxy");
		return;
	}
	touchBridgeActivity(bridge);
	const downstream = bridge.downstream;
	if (!downstream || downstream.readyState !== WebSocket.OPEN) {
		if (bridge.preOpenQueueBytes + size > bridge.websocketPolicy.preOpenQueueBytes) {
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
	else {
		recordBandwidth(
			{ siteId: bridge.siteId, ip: bridge.clientIp, countryCode: bridge.countryCode, protocol: "websocket" },
			{ clientSentBytes: messageByteLength(message) },
		);
	}
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

const websocketIpExtractors = new Map<IpExtractionPreset, ReturnType<typeof ipExtract>>(
	(Object.keys(IP_EXTRACTION_PRESETS) as IpExtractionPreset[]).map((preset) => [preset, ipExtract(preset)]),
);

export async function clientIpForUpgrade(request: Request, server: WebSocketUpgradeServer, preset: IpExtractionPreset): Promise<string> {
	const directIp = server.requestIP(request)?.address;
	const extractor = websocketIpExtractors.get(preset)!;
	const context = { req: request, clientIp: directIp } as Parameters<typeof extractor>[0];

	try {
		await extractor(context, async () => {});
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

async function openUpstreamWebSocket(target: URL, headers: Headers, request: Request, connectTimeoutMs: number): Promise<WebSocket> {
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
			finish(new Error(`WebSocket origin handshake timed out after ${connectTimeoutMs} ms`));
		}, connectTimeoutMs);

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
			recordBandwidth(
				{ siteId: bridge.siteId, ip: bridge.clientIp, countryCode: bridge.countryCode, protocol: "websocket" },
				{ upstreamReceivedBytes: messageByteLength(value) },
			);
			forwardToDownstream(bridge, value);
			return;
		}
		if (ArrayBuffer.isView(value)) {
			const message = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
			recordBandwidth(
				{ siteId: bridge.siteId, ip: bridge.clientIp, countryCode: bridge.countryCode, protocol: "websocket" },
				{ upstreamReceivedBytes: message.byteLength },
			);
			forwardToDownstream(bridge, message);
			return;
		}
		if (value instanceof Blob) {
			void value
				.arrayBuffer()
				.then((buffer) => {
					recordBandwidth(
						{ siteId: bridge.siteId, ip: bridge.clientIp, countryCode: bridge.countryCode, protocol: "websocket" },
						{ upstreamReceivedBytes: buffer.byteLength },
					);
					forwardToDownstream(bridge, buffer);
				})
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

	const ip = await clientIpForUpgrade(request, server, site.ip_extraction_preset ?? "direct");
	const url = incomingUrl;
	const eventBase: {
		siteId: string;
		ip: string;
		method: string;
		path: string;
		countryCode?: string | null;
		protectionStatus?: ManagedProtectionStatus | null;
		protectionRuleId?: string | null;
		protectionCategory?: string | null;
		protectionSeverity?: ManagedProtectionSeverity | null;
		protectionRulesetId?: string | null;
		protectionRulesetVersion?: string | null;
		protectionMatches?: ManagedProtectionMatch[] | null;
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

	if (originHealthManager.isMaintenanceMode(site.id)) {
		await recordEvent({
			...eventBase,
			sessionId: null,
			status: 503,
			decision: "origin-unhealthy",
			latencyMs: Math.round(performance.now() - started),
		});
		return siteErrorResponse(
			site,
			request,
			{
				status: 503,
				code: "origin_unhealthy",
				error: "Protected origin is temporarily unavailable",
				clientIp: ip,
				reason: "BurrowGate is online, but the configured origin did not pass its health checks.",
				retryAfterSeconds: Number(site.health_check_interval_seconds ?? 30),
			},
			{ "retry-after": String(site.health_check_interval_seconds ?? 30), "x-burrowgate-error-code": "origin_unhealthy" },
		);
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
	if (route.websocket.mode === "deny") {
		await recordEvent({
			...eventBase,
			sessionId: null,
			status: 403,
			decision: "websocket-policy-denied",
			latencyMs: Math.round(performance.now() - started),
		});
		return siteErrorResponse(site, request, {
			status: 403,
			code: "websocket_not_allowed",
			error: "WebSocket connections are not allowed for this route",
			clientIp: ip,
			routePolicy: route.policy?.name,
			reason: route.policy?.name ? `WebSocket access is denied by route policy ${route.policy.name}.` : "WebSocket access is disabled for this site.",
		});
	}
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
	const protection = await inspectManagedRequest(request, route.http.protection);
	if (protection.status !== "disabled") {
		eventBase.protectionStatus = protection.status;
		eventBase.protectionRuleId = protection.primaryMatch?.ruleId ?? null;
		eventBase.protectionCategory = protection.primaryMatch?.category ?? null;
		eventBase.protectionSeverity = protection.primaryMatch?.severity ?? null;
		eventBase.protectionRulesetId = protection.rulesetId;
		eventBase.protectionRulesetVersion = protection.rulesetVersion;
		eventBase.protectionMatches = protection.matches;
	}
	if (protection.status === "blocked") {
		await recordEvent({
			...eventBase,
			sessionId: null,
			status: 403,
			decision: "managed-protection-blocked",
			latencyMs: Math.round(performance.now() - started),
		});
		return siteErrorResponse(site, request, {
			status: 403,
			code: "managed_request_blocked",
			error: "WebSocket request blocked by BurrowGate",
			clientIp: ip,
			routePolicy: route.policy?.name,
			reason: "The WebSocket handshake matched a managed request-protection rule.",
		});
	}
	const accessSettings = await accessSettingsForSite(site.id);
	const accessAuthenticationEnabled = accessSettings.enabled === 1;

	const needsSession =
		accessAuthenticationEnabled ||
		route.accessMode === "challenge" ||
		ipRule.action === "challenge" ||
		route.policy?.rate_limit_key_mode === "session-or-ip" ||
		site.load_balancing_affinity !== 0;
	const candidateSession = needsSession ? await findAccessSession(request, site, ip) : null;

	const effectiveAccess = ipRule.action === "allow" ? "bypass" : ipRule.action === "challenge" ? "challenge" : route.accessMode;
	const session = effectiveAccess === "challenge" || accessAuthenticationEnabled ? candidateSession : null;
	if ((effectiveAccess === "challenge" || accessAuthenticationEnabled) && !session) {
		const flow = await createFlow(site, url.pathname + url.search, ip, await userAgentHash(request), route.challengePolicy);
		const verificationUrl = `/_burrowgate/verify?flow=${encodeURIComponent(flow.id)}`;
		await recordEvent({ ...eventBase, sessionId: null, status: 428, decision: "challenge-required", latencyMs: Math.round(performance.now() - started) });
		const headers = new Headers();
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

	const accessUser = accessAuthenticationEnabled ? await authenticatedAccessUser(site.id, session) : null;
	if (accessAuthenticationEnabled && !accessUser) {
		const loginUrl = `/_burrowgate/access/login?return=${encodeURIComponent(url.pathname + url.search)}`;
		await recordEvent({
			...eventBase,
			sessionId: session?.id ?? null,
			status: 428,
			decision: "access-login-required",
			latencyMs: Math.round(performance.now() - started),
		});
		return siteErrorResponse(
			site,
			request,
			{
				status: 428,
				code: "access_login_required",
				error: "Sign-in is required before opening this WebSocket",
				clientIp: ip,
				routePolicy: route.policy?.name,
				reason: "Complete BurrowGate sign-in before opening this WebSocket again.",
				verificationUrl: loginUrl,
			},
			{ "burrowgate-login": loginUrl },
		);
	}

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

	const accessStatus: OriginAccessStatus = accessAuthenticationEnabled
		? "verified"
		: ipRule.action === "allow"
			? "allowlisted"
			: effectiveAccess === "bypass"
				? "bypass"
				: "verified";
	let selectedOrigin = await loadBalancer.selectOrigin(site, candidateSession, ip);
	if (!selectedOrigin) {
		await recordEvent({
			...eventBase,
			sessionId: session?.id ?? null,
			status: 503,
			decision: "origin-pool-unavailable",
			latencyMs: Math.round(performance.now() - started),
		});
		return siteErrorResponse(site, request, {
			status: 503,
			code: "origin_pool_unavailable",
			error: "No WebSocket origin is available",
			clientIp: ip,
			reason: "Every configured origin is unhealthy, disabled, or draining.",
			retryAfterSeconds: Number(site.health_check_interval_seconds ?? 30),
		});
	}
	let target = websocketUpstreamUrl(site, request, selectedOrigin.origin_url);
	try {
		const headers = await websocketUpstreamHeaders(
			request,
			site,
			ip,
			session,
			accessStatus,
			transport,
			accessUser?.username ?? null,
			accessSettings.send_username_to_upstream === 1,
		);
		let upstream: WebSocket;
		try {
			upstream = await openUpstreamWebSocket(target, headers, request, route.websocket.connectTimeoutMs);
			loadBalancer.clearPassiveFailure(selectedOrigin.id);
		} catch (firstError) {
			loadBalancer.reportPassiveFailure(selectedOrigin.id);
			const replacement = await loadBalancer.selectOrigin(site, candidateSession, ip, { excludeOriginIds: new Set([selectedOrigin.id]) });
			if (!replacement) throw firstError;
			selectedOrigin = replacement;
			target = websocketUpstreamUrl(site, request, selectedOrigin.origin_url);
			upstream = await openUpstreamWebSocket(target, headers, request, route.websocket.connectTimeoutMs);
			loadBalancer.clearPassiveFailure(selectedOrigin.id);
		}
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
			countryCode: eventBase.countryCode ?? null,
			targetUrl: target.toString(),
			openedAt: Date.now(),
			upstream,
			downstream: null,
			preOpenQueue: [],
			preOpenQueueBytes: 0,
			closed: false,
			sessionExpiresAt: session?.expires_at ?? null,
			sessionExpiryTimer: null,
			idleTimer: null,
			websocketPolicy: route.websocket,
		};
		attachUpstreamBridgeEvents(bridge);

		const upgradeHeaders = new Headers(rateLimit.headers);
		if (accessUser && session && accessSettings.send_username_to_upstream === 1) {
			for (const cookie of await accessIdentitySetCookies(request, site, session, accessUser.username)) upgradeHeaders.append("set-cookie", cookie);
		} else if (accessIdentityCookieNames.some((name) => request.headers.get("cookie")?.includes(`${name}=`))) {
			for (const cookie of clearAccessIdentityCookies(request)) upgradeHeaders.append("set-cookie", cookie);
		}
		if (upstream.protocol) upgradeHeaders.set("sec-websocket-protocol", upstream.protocol);
		const upgraded = server.upgrade(request, [...upgradeHeaders].length > 0 ? { data: bridge, headers: upgradeHeaders } : { data: bridge });
		if (!upgraded) {
			closeBridge(bridge, 1011, "BurrowGate could not upgrade the downstream connection", "proxy");
			await recordEvent({
				...eventBase,
				sessionId: session?.id ?? null,
				status: 400,
				decision: "websocket-upgrade-failed",
				originId: selectedOrigin.id,
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

		const decision = accessUser
			? "websocket-authenticated"
			: accessStatus === "allowlisted"
				? "websocket-allowlisted"
				: accessStatus === "bypass"
					? "websocket-unprotected"
					: "websocket-proxied";
		await recordEvent({
			...eventBase,
			sessionId: session?.id ?? null,
			status: 101,
			decision,
			originId: selectedOrigin.id,
			latencyMs: Math.round(performance.now() - started),
		});
		return undefined;
	} catch (error) {
		loadBalancer.reportPassiveFailure(selectedOrigin.id);
		await recordEvent({
			...eventBase,
			sessionId: session?.id ?? null,
			status: 502,
			decision: "websocket-origin-error",
			originId: selectedOrigin.id,
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
		touchBridgeActivity(bridge);
	},

	message(ws, message) {
		const bridge = ws.data;
		if (bridge.closed || bridge.upstream.readyState !== WebSocket.OPEN) {
			closeBridge(bridge, 1011, "WebSocket origin is unavailable", "proxy");
			return;
		}
		const size = messageByteLength(message);
		if (size > bridge.websocketPolicy.maxPayloadBytes) {
			closeBridge(bridge, 1009, "WebSocket message exceeds the configured limit", "proxy");
			return;
		}
		touchBridgeActivity(bridge);
		recordBandwidth({ siteId: bridge.siteId, ip: bridge.clientIp, countryCode: bridge.countryCode, protocol: "websocket" }, { clientReceivedBytes: size });
		if (bridge.upstream.bufferedAmount + size > bridge.websocketPolicy.upstreamBufferBytes) {
			closeBridge(bridge, 1013, "WebSocket origin is receiving data too slowly", "proxy");
			return;
		}
		try {
			bridge.upstream.send(message);
			recordBandwidth({ siteId: bridge.siteId, ip: bridge.clientIp, countryCode: bridge.countryCode, protocol: "websocket" }, { upstreamSentBytes: size });
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
