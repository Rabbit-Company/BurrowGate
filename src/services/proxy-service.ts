import { config, requestTransport, visitorCookieNames, type RequestTransport } from "../config.ts";
import type { AccessSessionRecord, SiteRecord } from "../types.ts";

export type OriginAccessStatus = "verified" | "allowlisted" | "bypass";
import { removeCookieFromHeader } from "../utils/cookies.ts";
import { hmacSha256Hex } from "../utils/crypto.ts";
import { copyProxyHeaders } from "../utils/http.ts";
import { siteErrorResponse } from "./error-response-service.ts";

export function upstreamUrl(site: SiteRecord, request: Request): URL {
	const incoming = new URL(request.url);
	const base = new URL(site.origin_url);
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
): Promise<Headers> {
	const headers = copyProxyHeaders(request.headers);

	headers.delete("host");
	headers.delete("x-forwarded-for");
	headers.delete("x-forwarded-host");
	headers.delete("x-forwarded-proto");

	let cookie = headers.get("cookie");
	for (const name of visitorCookieNames) cookie = removeCookieFromHeader(cookie, name);
	if (cookie) headers.set("cookie", cookie);
	else headers.delete("cookie");

	// BurrowGate access credentials authenticate the edge and must never be
	// disclosed to the protected origin. Preserve unrelated Authorization
	// schemes because applications may use Basic/Bearer authentication.
	if (headers.get("authorization")?.startsWith("Burrow ")) headers.delete("authorization");
	headers.delete("x-burrow-token");

	const acceptedEncoding = request.headers.get("accept-encoding");
	headers.set("accept-encoding", acceptedEncoding?.trim() || "identity");

	const incoming = new URL(request.url);
	const externalTransport = transport ?? requestTransport(request);
	headers.set("x-forwarded-for", ip);
	headers.set("x-forwarded-host", incoming.host);
	headers.set("x-forwarded-proto", externalTransport);

	const timestamp = Math.floor(Date.now() / 1_000).toString();
	const sessionId = session?.id ?? accessStatus;
	const canonical = [request.method, incoming.pathname + incoming.search, sessionId, ip, timestamp].join("\n");

	headers.set("x-burrowgate-verified", accessStatus === "bypass" ? "false" : "true");
	headers.set("x-burrowgate-access-mode", accessStatus);
	headers.set("x-burrowgate-session-id", sessionId);
	headers.set("x-burrowgate-client-ip", ip);
	headers.set("x-burrowgate-timestamp", timestamp);
	headers.set("x-burrowgate-signature", await hmacSha256Hex(site.origin_signing_secret, canonical));

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
				headers.set("location", parsed.toString());
			}
		} catch {
			// Preserve malformed or non-URL Location values exactly as received.
		}
	}

	return headers;
}

export async function proxyRequest(
	request: Request,
	site: SiteRecord,
	ip: string,
	session: AccessSessionRecord | null,
	accessStatus: OriginAccessStatus = session ? "verified" : "allowlisted",
): Promise<Response> {
	if (request.headers.get("upgrade")?.toLowerCase() === "websocket") {
		// Upgrade requests are intercepted by TlsListenerManager before Web-JS
		// dispatch. This is only a defensive response if a custom listener calls
		// the HTTP proxy directly.
		return siteErrorResponse(
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
	}

	const incoming = new URL(request.url);
	const transport = requestTransport(request);
	const target = upstreamUrl(site, request);
	const headers = await upstreamHeaders(request, site, ip, session, accessStatus, transport);
	const hasBody = !["GET", "HEAD"].includes(request.method);

	const response = await fetch(target, {
		method: request.method,
		headers,
		body: hasBody ? request.body : null,
		redirect: "manual",
		signal: AbortSignal.timeout(config.originTimeoutMs),

		// A reverse proxy must preserve the representation received from the
		// origin. With Bun's default `decompress: true`, the body is decoded while
		// Content-Encoding/Content-Length still describe the compressed payload.
		// Forwarding that combination makes browsers attempt a second decode and
		// results in ERR_CONTENT_DECODING_FAILED.
		decompress: false,
	});

	return new Response(response.body, {
		status: response.status,
		statusText: response.statusText,
		headers: downstreamHeaders(response, target, incoming, transport),
	});
}
