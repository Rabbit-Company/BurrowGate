import type { HeadersInit } from "bun";

const HOP_BY_HOP_HEADERS = new Set([
	"connection",
	"keep-alive",
	"proxy-authenticate",
	"proxy-authorization",
	"proxy-connection",
	"te",
	"trailer",
	"transfer-encoding",
	"upgrade",
]);

export function copyProxyHeaders(source: Headers): Headers {
	const target = new Headers();
	for (const [name, value] of source) {
		if (!HOP_BY_HOP_HEADERS.has(name.toLowerCase())) target.append(name, value);
	}
	return target;
}

export function jsonResponse(data: unknown, status = 200, headers?: HeadersInit): Response {
	const resultHeaders = new Headers(headers);
	resultHeaders.set("content-type", "application/json; charset=utf-8");
	resultHeaders.set("cache-control", "no-store");
	return new Response(JSON.stringify(data), { status, headers: resultHeaders });
}

export const DEFAULT_CSP =
	"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

export function htmlResponse(html: string, status = 200, headers?: HeadersInit, csp: string = DEFAULT_CSP): Response {
	const resultHeaders = new Headers(headers);
	resultHeaders.set("content-type", "text/html; charset=utf-8");
	resultHeaders.set("cache-control", "no-store");
	resultHeaders.set("x-content-type-options", "nosniff");
	resultHeaders.set("referrer-policy", "same-origin");
	resultHeaders.set("content-security-policy", csp);
	return new Response(html, { status, headers: resultHeaders });
}

export function appendSetCookies(response: Response, cookies: string[]): Response {
	if (cookies.length === 0) return response;
	const headers = new Headers(response.headers);
	for (const cookie of cookies) headers.append("set-cookie", cookie);
	return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

export function safeReturnPath(value: string | null | undefined): string {
	if (!value || !value.startsWith("/") || value.startsWith("//")) return "/";
	return value;
}

export function normalizeHost(value: string): string {
	return value.trim().toLowerCase().replace(/\.$/u, "");
}

export function requestHost(request: Request): string {
	return normalizeHost(request.headers.get("host") ?? new URL(request.url).host);
}

export function sameOriginRequest(request: Request): boolean {
	const origin = request.headers.get("origin");
	if (!origin) return true;
	try {
		return normalizeHost(new URL(origin).host) === requestHost(request);
	} catch {
		return false;
	}
}
