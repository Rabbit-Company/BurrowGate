import { config, requestTransport, visitorCookieNames, type RequestTransport } from "../config.ts";
import type { AccessSessionRecord, SiteRecord } from "../types.ts";

export type OriginAccessStatus = "verified" | "allowlisted" | "bypass";
import { removeCookieFromHeader, setCookieInHeader } from "../utils/cookies.ts";
import { hmacSha256Hex } from "../utils/crypto.ts";
import { copyProxyHeaders, requestHost } from "../utils/http.ts";
import { resolveRequestId, siteErrorResponse } from "./error-response-service.ts";
import { UNKNOWN_COUNTRY_CODE } from "./geoip-service.ts";
import { accessIdentityCookieNames, accessIdentityCookieValues } from "./access-list-service.ts";
import { meteredBody, recordBandwidth, type BandwidthContext } from "./bandwidth-service.ts";
import { recordBandwidthLimitBytes } from "./bandwidth-limit-service.ts";
import { captureBufferedBody, tapBodyForCapture, type CapturedBody } from "./body-capture-service.ts";
import { applyHeaderPolicy, isBodyCaptureActive, resolveHttpPolicy, type ResolvedHttpPolicy } from "./http-policy-service.ts";
import { outboundFetchProtocolOption } from "./site-service.ts";
import { rememberOriginResponse } from "./static-cache-service.ts";

// Buffer ordinary forms and API payloads so Bun can derive an exact upstream
// Content-Length even after the incoming body has passed through the proxy.
// Larger uploads keep streaming to avoid unbounded per-request memory use.
const FIXED_LENGTH_BODY_BUFFER_LIMIT = 1 * 1_024 * 1_024;

export class RequestBodyTooLargeError extends Error {
	constructor(readonly maximumBytes: number) {
		super(`Request body exceeds the configured limit of ${maximumBytes} bytes`);
		this.name = "RequestBodyTooLargeError";
	}
}

export function upstreamUrl(site: SiteRecord, request: Request): URL {
	return upstreamUrlForOrigin(site.origin_url, request);
}

export function upstreamUrlForOrigin(originUrl: string, request: Request): URL {
	const incoming = new URL(request.url);
	const base = new URL(originUrl);
	const prefix = base.pathname.endsWith("/") ? base.pathname.slice(0, -1) : base.pathname;

	base.pathname = `${prefix}${incoming.pathname}` || "/";
	base.search = incoming.search;
	return base;
}

/**
 * Build the request headers sent to the protected origin.
 *
 * BurrowGate removes client-controlled forwarding headers and replaces them
 * with values derived from the actual incoming request. It also makes the
 * accepted response encodings explicit. Bun fetch() otherwise supplies its own
 * Accept-Encoding header when one is absent, which could make the origin send
 * an encoding that the downstream client never advertised.
 */
export async function upstreamHeaders(
	request: Request,
	site: SiteRecord,
	ip: string,
	session: AccessSessionRecord | null,
	accessStatus: OriginAccessStatus = session ? "verified" : "allowlisted",
	transport?: RequestTransport,
	authenticatedUsername: string | null = null,
	sendUsernameToUpstream = false,
	countryCode: string | null = null,
): Promise<Headers> {
	const headers = copyProxyHeaders(request.headers);

	headers.delete("forwarded");
	headers.delete("x-forwarded-for");
	headers.delete("x-forwarded-host");
	headers.delete("x-forwarded-port");
	headers.delete("x-forwarded-proto");
	headers.delete("x-forwarded-protocol");
	headers.delete("x-real-ip");

	let cookie = headers.get("cookie");
	for (const name of visitorCookieNames) cookie = removeCookieFromHeader(cookie, name);
	for (const name of accessIdentityCookieNames) cookie = removeCookieFromHeader(cookie, name);
	if (sendUsernameToUpstream && authenticatedUsername && session) {
		const identity = await accessIdentityCookieValues(site, session, authenticatedUsername);
		cookie = setCookieInHeader(cookie, accessIdentityCookieNames[0], identity.username);
		cookie = setCookieInHeader(cookie, accessIdentityCookieNames[1], identity.signature);
	}
	if (cookie) headers.set("cookie", cookie);
	else headers.delete("cookie");

	// BurrowGate access credentials authenticate the edge and must never be
	// disclosed to the protected origin. Preserve unrelated Authorization
	// schemes because applications may use Basic/Bearer authentication.
	if (headers.get("authorization")?.startsWith("Burrow ")) headers.delete("authorization");
	headers.delete("x-burrow-token");
	// Identity assertions are owned by BurrowGate. Never allow a client to
	// provide or override them, even when identity forwarding is disabled.
	headers.delete("x-burrowgate-authenticated-user");
	headers.delete("x-burrowgate-identity-signature");

	const acceptedEncoding = request.headers.get("accept-encoding");
	headers.set("accept-encoding", acceptedEncoding?.trim() || "identity");

	const incoming = new URL(request.url);
	const externalTransport = transport ?? requestTransport(request);
	const externalHost = requestHost(request);
	let externalPort = externalTransport === "https" ? "443" : "80";
	try {
		externalPort = new URL(`${externalTransport}://${externalHost}`).port || externalPort;
	} catch {
		// The site resolver validates request hosts before proxying. Retain the
		// transport's default port if a custom caller supplies an invalid host.
	}
	headers.set("host", externalHost);
	headers.set("x-real-ip", ip);
	headers.set("x-forwarded-for", ip);
	headers.set("x-forwarded-host", externalHost);
	headers.set("x-forwarded-port", externalPort);
	headers.set("x-forwarded-proto", externalTransport);
	headers.set("x-forwarded-protocol", externalTransport);
	headers.set("x-burrowgate-request-id", resolveRequestId(request));

	const timestamp = Math.floor(Date.now() / 1_000).toString();
	const sessionId = session?.id ?? accessStatus;
	const country = countryCode ?? UNKNOWN_COUNTRY_CODE;
	const canonical = [request.method, incoming.pathname + incoming.search, sessionId, ip, country, timestamp].join("\n");

	headers.set("x-burrowgate-verified", accessStatus === "bypass" ? "false" : "true");
	headers.set("x-burrowgate-access-mode", accessStatus);
	headers.set("x-burrowgate-session-id", sessionId);
	headers.set("x-burrowgate-client-ip", ip);
	headers.set("x-burrowgate-country", country);
	headers.set("x-burrowgate-timestamp", timestamp);
	headers.set("x-burrowgate-signature", await hmacSha256Hex(site.origin_signing_secret, canonical));
	if (sendUsernameToUpstream && authenticatedUsername) {
		const identityCanonical = [request.method, incoming.pathname + incoming.search, sessionId, ip, country, timestamp, authenticatedUsername].join("\n");
		headers.set("x-burrowgate-authenticated-user", authenticatedUsername);
		headers.set("x-burrowgate-identity-signature", await hmacSha256Hex(site.origin_signing_secret, identityCanonical));
	}

	return headers;
}

function downstreamHeaders(response: Response, target: URL, incoming: URL, transport: RequestTransport): Headers {
	const headers = copyProxyHeaders(response.headers);

	// Headers iteration can combine Set-Cookie values. Re-add them through Bun's
	// getSetCookie() extension so each cookie remains a separate response header.
	headers.delete("set-cookie");
	const getSetCookie = (
		response.headers as Headers & {
			getSetCookie?: () => string[];
		}
	).getSetCookie;

	for (const value of getSetCookie?.call(response.headers) ?? []) {
		headers.append("set-cookie", value);
	}

	const location = headers.get("location");
	if (location) {
		try {
			const parsed = new URL(location, target);
			if (parsed.host === target.host) {
				parsed.protocol = `${transport}:`;
				parsed.host = incoming.host;
				parsed.port = incoming.port;
				headers.set("location", parsed.toString());
			}
		} catch {
			// Preserve malformed or non-URL Location values exactly as received.
		}
	}

	return headers;
}

interface UpstreamRequestBody {
	body: RequestInit["body"];
	bufferedBytes: number;
	limitState: { exceeded: boolean };
	capturedRequestBody: Promise<CapturedBody | null>;
}

async function upstreamRequestBody(
	request: Request,
	headers: Headers,
	bandwidth: BandwidthContext,
	site: SiteRecord,
	ip: string,
	bandwidthLimit: ResolvedHttpPolicy["bandwidthLimit"],
	maxBodyBytes: number,
	captureMaxBytes: number,
	captureContentTypes: readonly string[],
): Promise<UpstreamRequestBody> {
	const limitState = { exceeded: false };
	if (["GET", "HEAD"].includes(request.method) || !request.body) {
		return { body: null, bufferedBytes: 0, limitState, capturedRequestBody: Promise.resolve(null) };
	}

	const contentType = request.headers.get("content-type");
	const contentEncoding = request.headers.get("content-encoding");
	const rawContentLength = request.headers.get("content-length");
	const contentLength = rawContentLength === null ? null : Number(rawContentLength);
	if (contentLength !== null && Number.isSafeInteger(contentLength) && contentLength >= 0 && contentLength <= FIXED_LENGTH_BODY_BUFFER_LIMIT) {
		const body = new Uint8Array(await request.arrayBuffer());
		if (maxBodyBytes > 0 && body.byteLength > maxBodyBytes) {
			recordBandwidth(bandwidth, { clientReceivedBytes: body.byteLength });
			recordBandwidthLimitBytes(bandwidthLimit, site, ip, body.byteLength);
			throw new RequestBodyTooLargeError(maxBodyBytes);
		}
		headers.set("content-length", String(body.byteLength));
		return {
			body,
			bufferedBytes: body.byteLength,
			limitState,
			capturedRequestBody: Promise.resolve(captureBufferedBody(body, contentType, captureMaxBytes, contentEncoding, captureContentTypes)),
		};
	}

	let receivedBytes = 0;
	const limited = request.body.pipeThrough(
		new TransformStream<Uint8Array, Uint8Array>({
			transform(chunk, controller) {
				receivedBytes += chunk.byteLength;
				recordBandwidth(bandwidth, { clientReceivedBytes: chunk.byteLength });
				recordBandwidthLimitBytes(bandwidthLimit, site, ip, chunk.byteLength);
				if (maxBodyBytes > 0 && receivedBytes > maxBodyBytes) {
					limitState.exceeded = true;
					controller.error(new RequestBodyTooLargeError(maxBodyBytes));
					return;
				}
				recordBandwidth(bandwidth, { upstreamSentBytes: chunk.byteLength });
				controller.enqueue(chunk);
			},
		}),
	);
	const { body, captured } = tapBodyForCapture(limited, contentType, captureMaxBytes, contentEncoding, captureContentTypes);
	return {
		body,
		bufferedBytes: 0,
		limitState,
		capturedRequestBody: captured,
	};
}

export async function proxyRequest(
	request: Request,
	site: SiteRecord,
	ip: string,
	session: AccessSessionRecord | null,
	accessStatus: OriginAccessStatus = session ? "verified" : "allowlisted",
	authenticatedUsername: string | null = null,
	sendUsernameToUpstream = false,
	countryCode: string | null = null,
	originUrl: string = site.origin_url,
	httpPolicy: ResolvedHttpPolicy = resolveHttpPolicy(site),
): Promise<{ response: Response; capturedRequestBody: CapturedBody | null; capturedResponseBody: Promise<CapturedBody | null> | null }> {
	if (request.headers.get("upgrade")?.toLowerCase() === "websocket") {
		// Upgrade requests are intercepted by TlsListenerManager before Web-JS
		// dispatch. This is only a defensive response if a custom listener calls
		// the HTTP proxy directly.
		const response = siteErrorResponse(
			site,
			request,
			{
				status: 426,
				code: "websocket_upgrade_required",
				error: "WebSocket upgrade required",
				clientIp: ip,
				reason: "WebSocket upgrades must be handled by the BurrowGate listener.",
			},
			{ upgrade: "websocket" },
		);
		return { response, capturedRequestBody: null, capturedResponseBody: null };
	}

	const incoming = new URL(request.url);
	const transport = requestTransport(request);
	const target = upstreamUrlForOrigin(originUrl, request);
	const headers = await upstreamHeaders(request, site, ip, session, accessStatus, transport, authenticatedUsername, sendUsernameToUpstream, countryCode);
	applyHeaderPolicy(headers, httpPolicy.requestHeaders);
	const bandwidth: BandwidthContext = { siteId: site.id, ip, countryCode, protocol: "http" };
	const bodyCaptureActive = isBodyCaptureActive(httpPolicy.bodyCapture);
	const requestBody = await upstreamRequestBody(
		request,
		headers,
		bandwidth,
		site,
		ip,
		httpPolicy.bandwidthLimit,
		httpPolicy.limits.maxBodyBytes,
		bodyCaptureActive ? httpPolicy.bodyCapture.maxRequestBytes : 0,
		httpPolicy.bodyCapture.contentTypes,
	);

	let response: Response;
	try {
		response = await fetch(target, {
			method: request.method,
			headers,
			body: requestBody.body,
			redirect: "manual",
			signal: AbortSignal.timeout(config.originTimeoutMs),

			// A reverse proxy must preserve the representation received from the
			// origin. With Bun's default `decompress: true`, the body is decoded while
			// Content-Encoding/Content-Length still describe the compressed payload.
			// Forwarding that combination makes browsers attempt a second decode and
			// results in ERR_CONTENT_DECODING_FAILED.
			decompress: false,
			...outboundFetchProtocolOption(site),
		});
	} catch (error) {
		if (requestBody.limitState.exceeded) throw new RequestBodyTooLargeError(httpPolicy.limits.maxBodyBytes);
		throw error;
	}
	if (requestBody.bufferedBytes > 0) {
		recordBandwidth(bandwidth, {
			clientReceivedBytes: requestBody.bufferedBytes,
			upstreamSentBytes: requestBody.bufferedBytes,
		});
		recordBandwidthLimitBytes(httpPolicy.bandwidthLimit, site, ip, requestBody.bufferedBytes);
	}

	const { body: tappedBody, captured: capturedResponseBody } = tapBodyForCapture(
		response.body,
		response.headers.get("content-type"),
		bodyCaptureActive ? httpPolicy.bodyCapture.maxResponseBytes : 0,
		response.headers.get("content-encoding"),
		httpPolicy.bodyCapture.contentTypes,
	);
	const responseBody = meteredBody(
		tappedBody,
		bandwidth,
		(bytes) => ({ upstreamReceivedBytes: bytes, clientSentBytes: bytes }),
		(context, delta) => {
			recordBandwidth(context, delta);
			recordBandwidthLimitBytes(httpPolicy.bandwidthLimit, site, ip, delta.clientSentBytes ?? 0);
		},
	);
	const responseHeaders = downstreamHeaders(response, target, incoming, transport);
	applyHeaderPolicy(responseHeaders, httpPolicy.responseHeaders);
	return {
		response: rememberOriginResponse(
			new Response(responseBody, {
				status: response.status,
				statusText: response.statusText,
				headers: responseHeaders,
			}),
			response,
		),
		capturedRequestBody: await requestBody.capturedRequestBody,
		capturedResponseBody: bodyCaptureActive && httpPolicy.bodyCapture.maxResponseBytes > 0 ? capturedResponseBody : null,
	};
}
