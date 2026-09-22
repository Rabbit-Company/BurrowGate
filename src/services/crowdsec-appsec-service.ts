import { Logger } from "../logger.ts";

/**
 * Client for CrowdSec's AppSec component, the WAF half of CrowdSec.
 *
 * Unlike decisions, which are polled and answered from memory, AppSec inspects the live request.
 * That means an HTTP round-trip inside the request path, which is why it is off by default and
 * opted into per site or per route rather than enabled globally.
 *
 * Protocol (docs.crowdsec.net/docs/appsec/protocol): the original request's headers are forwarded
 * as-is alongside a set of `X-Crowdsec-Appsec-*` headers carrying the metadata. A request with no
 * body is sent as GET, one with a body as POST. 200 allows, 403 carries the action to take, and
 * 401 or 500 mean the component itself failed.
 */

export type AppSecStatus = "disabled" | "clean" | "monitored" | "blocked" | "error";
export type AppSecAction = "allow" | "ban" | "captcha" | "challenge" | "log";

export interface AppSecResult {
	status: AppSecStatus;
	action: AppSecAction | null;
	/** The status code AppSec asked us to answer with, when it returned one. */
	httpStatus: number | null;
	error: string | null;
	durationMs: number;
}

export interface AppSecRequestInput {
	ip: string;
	url: URL;
	method: string;
	headers: Headers;
	httpVersion: string | null;
	/** Already-buffered body, or null when the request had none or it was too large to buffer. */
	body: Uint8Array | null;
}

export interface AppSecConnection {
	url: string;
	apiKey: string;
	timeoutMs: number;
	verifyTls: boolean;
}

/**
 * Headers that must not be copied to AppSec.
 *
 * Hop-by-hop headers describe our connection to the client, not the request, and `content-length`
 * has to match whatever body we actually forward rather than the original.
 */
const SKIPPED_HEADERS = new Set([
	"connection",
	"keep-alive",
	"proxy-authenticate",
	"proxy-authorization",
	"te",
	"trailer",
	"transfer-encoding",
	"upgrade",
	"content-length",
	"host",
]);

/** CrowdSec expects the HTTP version as an integer, so "1.1" becomes 11. */
export function appSecHttpVersion(version: string | null | undefined): string {
	const normalized = String(version ?? "1.1").trim();
	if (normalized.startsWith("2")) return "20";
	if (normalized.startsWith("3")) return "30";
	if (normalized === "1.0" || normalized === "10") return "10";
	return "11";
}

export function buildAppSecHeaders(input: AppSecRequestInput, apiKey: string): Headers {
	const headers = new Headers();
	for (const [name, value] of input.headers) {
		if (SKIPPED_HEADERS.has(name.toLowerCase())) continue;
		headers.set(name, value);
	}
	headers.set("x-crowdsec-appsec-ip", input.ip);
	headers.set("x-crowdsec-appsec-uri", `${input.url.pathname}${input.url.search}`);
	headers.set("x-crowdsec-appsec-host", input.url.host);
	headers.set("x-crowdsec-appsec-verb", input.method.toUpperCase());
	headers.set("x-crowdsec-appsec-api-key", apiKey);
	headers.set("x-crowdsec-appsec-user-agent", input.headers.get("user-agent") ?? "");
	headers.set("x-crowdsec-appsec-http-version", appSecHttpVersion(input.httpVersion));
	return headers;
}

function normalizeAction(value: unknown): AppSecAction | null {
	const action = String(value ?? "")
		.trim()
		.toLowerCase();
	if (action === "allow" || action === "ban" || action === "captcha" || action === "challenge" || action === "log") return action;
	return null;
}

/** Trims an AppSec base URL, rejecting anything unusable. */
export function normalizeAppSecUrl(value: unknown): string {
	const raw = String(value ?? "").trim();
	if (!raw) throw new Error("Enter the CrowdSec AppSec URL");
	let parsed: URL;
	try {
		parsed = new URL(raw);
	} catch {
		throw new Error("The CrowdSec AppSec URL must be a valid URL, for example http://127.0.0.1:7422");
	}
	if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw new Error("The CrowdSec AppSec URL must use http or https");
	return `${parsed.origin}${parsed.pathname.replace(/\/+$/u, "")}`;
}

/**
 * Sends one request to AppSec for inspection.
 *
 * Never throws. A component that is unreachable, slow, or misconfigured returns `error` and the
 * caller decides whether that means allow or deny, because failing closed on a WAF outage would
 * take a site down and failing open is the safer default for most deployments.
 */
export async function inspectWithAppSec(input: AppSecRequestInput, connection: AppSecConnection): Promise<AppSecResult> {
	const startedAt = performance.now();
	try {
		const headers = buildAppSecHeaders(input, connection.apiKey);
		const hasBody = input.body !== null && input.body.byteLength > 0;
		const response = await fetch(connection.url, {
			method: hasBody ? "POST" : "GET",
			headers,
			body: hasBody ? input.body : undefined,
			tls: { rejectUnauthorized: connection.verifyTls },
			signal: AbortSignal.timeout(connection.timeoutMs),
		} as RequestInit & { tls?: { rejectUnauthorized: boolean } });

		const durationMs = performance.now() - startedAt;
		if (response.status === 200) {
			await response.body?.cancel().catch(() => undefined);
			return { status: "clean", action: "allow", httpStatus: null, error: null, durationMs };
		}
		if (response.status === 403) {
			const body = (await response.json().catch(() => null)) as { action?: unknown; http_status?: unknown } | null;
			const action = normalizeAction(body?.action) ?? "ban";
			const httpStatus = Number(body?.http_status);
			return {
				status: "blocked",
				action,
				httpStatus: Number.isInteger(httpStatus) && httpStatus >= 400 && httpStatus <= 599 ? httpStatus : 403,
				error: null,
				durationMs,
			};
		}
		await response.body?.cancel().catch(() => undefined);
		if (response.status === 401) return { status: "error", action: null, httpStatus: null, error: "AppSec rejected the API key", durationMs };
		return { status: "error", action: null, httpStatus: null, error: `AppSec returned HTTP ${response.status}`, durationMs };
	} catch (error) {
		const durationMs = performance.now() - startedAt;
		const message = error instanceof Error ? error.message : String(error);
		return { status: "error", action: null, httpStatus: null, error: message.slice(0, 300), durationMs };
	}
}

/** Verifies an AppSec endpoint for the admin "Test connection" button. */
export async function testAppSecConnection(url: string, apiKey: string, verifyTls: boolean, timeoutMs = 2_000): Promise<{ ok: boolean; message: string }> {
	try {
		const connection = { url: normalizeAppSecUrl(url), apiKey, verifyTls, timeoutMs };
		const result = await inspectWithAppSec(
			{
				ip: "127.0.0.1",
				url: new URL("http://localhost/"),
				method: "GET",
				headers: new Headers({ "user-agent": "burrowgate-appsec-test" }),
				httpVersion: "1.1",
				body: null,
			},
			connection,
		);
		if (result.status === "error") return { ok: false, message: result.error ?? "AppSec did not answer" };
		return { ok: true, message: `Connected. AppSec answered in ${Math.round(result.durationMs)}ms.` };
	} catch (error) {
		return { ok: false, message: error instanceof Error ? error.message : "Unable to reach AppSec" };
	}
}

/** Why a request's body was or was not handed to AppSec, recorded so the traffic log can explain it. */
export type AppSecBodyOutcome = "none" | "inspected" | "oversized" | "unknown-length" | "disabled" | "error";

/**
 * Reads a request body for inspection, up to `maxBytes`.
 *
 * The body is only buffered when `content-length` says it is small enough. A chunked body has no
 * declared length, and reading it to find out would mean buffering an upload of arbitrary size
 * into memory, so those are left untouched for the proxy to stream as usual and inspected on
 * their headers and URI alone. The original stream is never partially consumed, because a
 * consumed body cannot be forwarded to the origin.
 */
export async function bufferBodyForAppSec(request: Request, maxBytes: number): Promise<{ body: Uint8Array | null; outcome: AppSecBodyOutcome }> {
	if (!request.body || ["GET", "HEAD"].includes(request.method.toUpperCase())) return { body: null, outcome: "none" };
	if (maxBytes <= 0) return { body: null, outcome: "disabled" };

	const raw = request.headers.get("content-length");
	const declared = raw === null ? null : Number(raw);
	if (declared === null || !Number.isSafeInteger(declared) || declared < 0) return { body: null, outcome: "unknown-length" };
	if (declared > maxBytes) return { body: null, outcome: "oversized" };

	try {
		return { body: new Uint8Array(await request.arrayBuffer()), outcome: "inspected" };
	} catch (error) {
		Logger.debug("CrowdSec AppSec: unable to buffer the request body", { error });
		return { body: null, outcome: "error" };
	}
}
