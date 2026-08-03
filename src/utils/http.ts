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

export function htmlResponse(html: string, status = 200, headers?: HeadersInit): Response {
	const resultHeaders = new Headers(headers);
	resultHeaders.set("content-type", "text/html; charset=utf-8");
	resultHeaders.set("cache-control", "no-store");
	resultHeaders.set("x-content-type-options", "nosniff");
	resultHeaders.set("referrer-policy", "same-origin");
	resultHeaders.set(
		"content-security-policy",
		"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
	);
	return new Response(html, { status, headers: resultHeaders });
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
