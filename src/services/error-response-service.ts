import type { HeadersInit } from "bun";
import type { ErrorResponseMode, SiteRecord } from "../types.ts";
import { requestHost } from "../utils/http.ts";

export const ERROR_JSON_FIELD_OPTIONS = [
	{ name: "error", label: "Error message", description: "Human-readable description of the error." },
	{ name: "code", label: "Error code", description: "Stable BurrowGate error identifier for API clients." },
	{ name: "status", label: "HTTP status", description: "Numeric HTTP status code." },
	{ name: "statusText", label: "HTTP status text", description: "Standard HTTP status description." },
	{ name: "requestId", label: "Request ID", description: "Identifier that can be used when investigating logs." },
	{ name: "timestamp", label: "Timestamp", description: "ISO-8601 time when the response was generated." },
	{ name: "method", label: "HTTP method", description: "Request method such as GET or POST." },
	{ name: "path", label: "Request path", description: "Requested path and query string." },
	{ name: "host", label: "Public host", description: "Hostname used for the request." },
	{ name: "siteName", label: "Site name", description: "Name configured for the protected site." },
	{ name: "clientIp", label: "Client IP", description: "IP address BurrowGate evaluated for the request." },
	{ name: "reason", label: "Reason", description: "Optional network or policy reason." },
	{ name: "routePolicy", label: "Route policy", description: "Name of the matching route policy when available." },
	{ name: "verificationUrl", label: "Verification URL", description: "URL where the client can complete verification." },
	{ name: "retryAfterSeconds", label: "Retry after", description: "Seconds until a rate-limited client should retry." },
] as const;

export type ErrorJsonField = (typeof ERROR_JSON_FIELD_OPTIONS)[number]["name"];

export const DEFAULT_ERROR_JSON_FIELDS: ErrorJsonField[] = [
	"error",
	"code",
	"status",
	"requestId",
	"reason",
	"routePolicy",
	"verificationUrl",
	"retryAfterSeconds",
];

export const ERROR_TEMPLATE_PLACEHOLDERS = [
	{ name: "status", description: "Numeric HTTP status code." },
	{ name: "statusText", description: "Standard HTTP status description." },
	{ name: "code", description: "Stable BurrowGate error identifier." },
	{ name: "error", description: "Human-readable error message." },
	{ name: "requestId", description: "Request identifier for log investigation." },
	{ name: "timestamp", description: "ISO-8601 response timestamp." },
	{ name: "method", description: "HTTP request method." },
	{ name: "path", description: "Requested path and query string." },
	{ name: "host", description: "Public request host." },
	{ name: "siteName", description: "Configured site name." },
	{ name: "clientIp", description: "Evaluated client IP address." },
	{ name: "reason", description: "Optional network or policy reason." },
	{ name: "routePolicy", description: "Matching route-policy name." },
	{ name: "verificationUrl", description: "Verification URL when a challenge is required." },
	{ name: "retryAfterSeconds", description: "Rate-limit retry delay in seconds." },
	{ name: "homeUrl", description: "Root URL of the protected site." },
] as const;

export const DEFAULT_ERROR_HTML_TEMPLATE = `<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<meta name="color-scheme" content="dark">
	<title>{{status}} {{statusText}} - {{siteName}}</title>
	<style>
		:root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
		* { box-sizing: border-box; }
		body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px; color: #e5e7eb; background: radial-gradient(circle at top, #312e81 0, #111827 42%, #030712 100%); }
		main { width: min(620px, 100%); padding: 36px; border: 1px solid rgba(148, 163, 184, .22); border-radius: 20px; background: rgba(15, 23, 42, .9); box-shadow: 0 24px 80px rgba(0, 0, 0, .4); }
		.brand { display: flex; align-items: center; gap: 12px; margin-bottom: 30px; font-weight: 700; }
		.logo { width: 42px; height: 42px; flex: none; background: url("data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20viewBox%3D%220%200%2064%2064%22%20role%3D%22img%22%20aria-label%3D%22BurrowGate%22%3E%3Cdefs%3E%3ClinearGradient%20id%3D%22bg%22%20x1%3D%2210%22%20y1%3D%228%22%20x2%3D%2254%22%20y2%3D%2256%22%20gradientUnits%3D%22userSpaceOnUse%22%3E%3Cstop%20stop-color%3D%22%238b5cf6%22%2F%3E%3Cstop%20offset%3D%221%22%20stop-color%3D%22%2322d3ee%22%2F%3E%3C%2FlinearGradient%3E%3C%2Fdefs%3E%3Crect%20width%3D%2264%22%20height%3D%2264%22%20rx%3D%2216%22%20fill%3D%22url%28%23bg%29%22%2F%3E%3Cg%20transform%3D%22translate%2814%2014%29%20scale%281.5%29%22%20fill%3D%22none%22%20stroke%3D%22%230b1020%22%20stroke-width%3D%222%22%20stroke-linecap%3D%22round%22%20stroke-linejoin%3D%22round%22%3E%3Cpath%20d%3D%22M5%2021h14a2%202%200%200%200%202%20-2v-7a9%209%200%200%200%20-18%200v7a2%202%200%200%200%202%202%22%2F%3E%3Cpath%20d%3D%22M8%2021v-9a4%204%200%201%201%208%200v9%22%2F%3E%3Cpath%20d%3D%22M3%2017h4%22%2F%3E%3Cpath%20d%3D%22M17%2017h4%22%2F%3E%3C%2Fg%3E%3C%2Fsvg%3E") center / contain no-repeat; }
		.status { margin: 0; color: #a78bfa; font-size: clamp(48px, 12vw, 84px); line-height: 1; }
		h1 { margin: 12px 0 10px; font-size: clamp(24px, 5vw, 36px); }
		p { margin: 0; color: #94a3b8; line-height: 1.65; }
		.meta { display: grid; gap: 8px; margin-top: 28px; padding-top: 22px; border-top: 1px solid rgba(148, 163, 184, .18); font-size: 13px; color: #64748b; }
		.actions { margin-top: 28px; }
		a { display: inline-flex; padding: 11px 16px; border-radius: 10px; background: #7c3aed; color: white; text-decoration: none; font-weight: 600; }
	</style>
</head>
<body>
	<main>
		<div class="brand"><span class="logo"></span><span>BurrowGate</span></div>
		<div class="status">{{status}}</div>
		<h1>{{error}}</h1>
		<p>{{reason}}</p>
		<div class="actions"><a href="{{homeUrl}}">Return to website</a></div>
		<div class="meta">
			<span>Request ID: {{requestId}}</span>
			<span>{{method}} {{path}}</span>
		</div>
	</main>
</body>
</html>`;

const STATUS_TEXT: Record<number, string> = {
	400: "Bad Request",
	401: "Unauthorized",
	403: "Forbidden",
	404: "Not Found",
	409: "Conflict",
	410: "Gone",
	421: "Misdirected Request",
	426: "Upgrade Required",
	428: "Precondition Required",
	429: "Too Many Requests",
	500: "Internal Server Error",
	501: "Not Implemented",
	502: "Bad Gateway",
	503: "Service Unavailable",
	504: "Gateway Timeout",
};

export interface SiteErrorInput {
	status: number;
	code: string;
	error: string;
	clientIp?: string | null | undefined;
	reason?: string | null | undefined;
	routePolicy?: string | null | undefined;
	verificationUrl?: string | null | undefined;
	retryAfterSeconds?: number | null | undefined;
	requestId?: string | null | undefined;
}

interface ErrorContext {
	status: number;
	statusText: string;
	code: string;
	error: string;
	requestId: string;
	timestamp: string;
	method: string;
	path: string;
	host: string;
	siteName: string;
	clientIp: string;
	reason: string;
	routePolicy: string;
	verificationUrl: string;
	retryAfterSeconds: number | "";
	homeUrl: string;
}

function escapeHtml(value: unknown): string {
	return String(value ?? "")
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;")
		.replaceAll("'", "&#39;");
}

function requestId(request: Request, supplied?: string | null): string {
	return supplied?.trim() || request.headers.get("x-request-id")?.trim() || request.headers.get("x-correlation-id")?.trim() || crypto.randomUUID();
}

function contextFor(site: SiteRecord, request: Request, input: SiteErrorInput): ErrorContext {
	const url = new URL(request.url);
	const host = requestHost(request);
	const protocol = url.protocol === "https:" ? "https:" : "http:";
	return {
		status: input.status,
		statusText: STATUS_TEXT[input.status] ?? "Request Failed",
		code: input.code,
		error: input.error,
		requestId: requestId(request, input.requestId),
		timestamp: new Date().toISOString(),
		method: request.method,
		path: url.pathname + url.search,
		host,
		siteName: site.name,
		clientIp: input.clientIp ?? "",
		reason: input.reason ?? "",
		routePolicy: input.routePolicy ?? "",
		verificationUrl: input.verificationUrl ?? "",
		retryAfterSeconds: input.retryAfterSeconds ?? "",
		homeUrl: `${protocol}//${host}/`,
	};
}

function htmlFromTemplate(template: string, context: ErrorContext): string {
	let result = template;
	for (const placeholder of ERROR_TEMPLATE_PLACEHOLDERS) {
		const key = placeholder.name as keyof ErrorContext;
		result = result.replaceAll(`{{${placeholder.name}}}`, escapeHtml(context[key]));
	}
	return result;
}

function jsonFields(site: SiteRecord): ErrorJsonField[] {
	try {
		return validateErrorJsonFields(JSON.parse(site.error_json_fields_json || "null"));
	} catch {
		return [...DEFAULT_ERROR_JSON_FIELDS];
	}
}

function jsonData(site: SiteRecord, context: ErrorContext): Record<string, unknown> {
	const data: Record<string, unknown> = {};
	for (const field of jsonFields(site)) {
		const value = context[field as keyof ErrorContext];
		if (value !== "" && value !== null && value !== undefined) data[field] = value;
	}
	return data;
}

export function validateErrorResponseMode(value: unknown, fallback: ErrorResponseMode): ErrorResponseMode {
	if (value === undefined) return fallback;
	const mode = String(value).trim().toLowerCase();
	if (mode === "html" || mode === "json") return mode;
	throw new Error("Error response mode must be html or json");
}

export function validateErrorHtmlTemplate(value: unknown, fallback = DEFAULT_ERROR_HTML_TEMPLATE): string {
	if (value === undefined) return fallback;
	const template = String(value);
	if (!template.trim()) throw new Error("HTML error template cannot be empty");
	if (template.length > 131_072) throw new Error("HTML error template must be at most 131072 characters");
	return template;
}

export function validateErrorJsonFields(value: unknown, fallback: ErrorJsonField[] = DEFAULT_ERROR_JSON_FIELDS): ErrorJsonField[] {
	if (value === undefined || value === null) return [...fallback];
	let parsed = value;
	if (typeof parsed === "string") {
		try {
			parsed = JSON.parse(parsed);
		} catch {
			throw new Error("JSON error fields must be valid JSON");
		}
	}
	if (!Array.isArray(parsed) || parsed.length < 1) throw new Error("Select at least one JSON error field");
	const allowed = new Set(ERROR_JSON_FIELD_OPTIONS.map((option) => option.name));
	const fields = [...new Set(parsed.map((field) => String(field)))];
	if (fields.some((field) => !allowed.has(field as ErrorJsonField))) throw new Error("JSON error fields contain an unsupported value");
	return fields as ErrorJsonField[];
}

export function siteErrorResponse(site: SiteRecord, request: Request, input: SiteErrorInput, headers?: HeadersInit): Response {
	const context = contextFor(site, request, input);
	const responseHeaders = new Headers(headers);
	responseHeaders.set("cache-control", "no-store");
	responseHeaders.set("x-content-type-options", "nosniff");
	responseHeaders.set("x-burrowgate-error-code", input.code);
	responseHeaders.set("x-request-id", context.requestId);

	if ((site.error_response_mode ?? "json") === "html") {
		responseHeaders.set("content-type", "text/html; charset=utf-8");
		responseHeaders.set("referrer-policy", "no-referrer");
		responseHeaders.set(
			"content-security-policy",
			"default-src 'none'; style-src 'unsafe-inline'; img-src data: https:; font-src data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
		);
		return new Response(htmlFromTemplate(site.error_html_template || DEFAULT_ERROR_HTML_TEMPLATE, context), {
			status: input.status,
			headers: responseHeaders,
		});
	}

	responseHeaders.set("content-type", "application/json; charset=utf-8");
	return new Response(JSON.stringify(jsonData(site, context)), {
		status: input.status,
		headers: responseHeaders,
	});
}
