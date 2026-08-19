import { config } from "../config.ts";
import { parseCapturedHeaders, REDACTED_HEADER_PLACEHOLDER } from "./header-capture-service.ts";
import type { RequestEventRecord, SiteRecord } from "../types.ts";

const RESULT_BODY_BYTE_CEILING = 65_536;
const MAX_REDIRECTS = 10;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

// Framing headers are recomputed by fetch and must never be replayed from a capture.
const NON_REPLAYABLE_HEADERS = new Set(["host", "content-length", "connection", "transfer-encoding", "upgrade"]);

export class ResendTargetError extends Error {}

export interface ResendHop {
	method: string;
	path: string;
	status: number;
	location: string | null;
	followed: boolean;
	notFollowedReason: "off-site" | "redirect-limit" | "no-location" | "unparseable-location" | null;
}

export interface ResendResult {
	status: number;
	headers: [string, string][];
	body: string;
	bodyTruncated: boolean;
	hops: ResendHop[];
}

function publicHostname(site: SiteRecord): string {
	try {
		return new URL(`http://${site.public_host}`).hostname.toLowerCase();
	} catch {
		return site.public_host.trim().toLowerCase();
	}
}

function targetBaseUrl(site: SiteRecord): string {
	if (config.https.enabled) return `https://${site.public_host}`;
	if (config.http.enabled) return `http://${site.public_host}`;
	throw new ResendTargetError("Neither HTTP nor HTTPS listener is enabled, so requests cannot be resent.");
}

export async function resendCapturedRequest(
	event: RequestEventRecord,
	site: SiteRecord,
	overrides: { headers?: Record<string, string>; body?: string | null },
): Promise<ResendResult> {
	const headers = new Headers();
	const overrideNames = new Map(Object.entries(overrides.headers ?? {}).map(([name, value]) => [name.toLowerCase(), value]));
	for (const [name, value] of parseCapturedHeaders(event.request_headers)) {
		const lower = name.toLowerCase();
		if (NON_REPLAYABLE_HEADERS.has(lower) || lower.startsWith("x-forwarded-") || lower.startsWith("x-burrowgate-")) continue;
		if (value === REDACTED_HEADER_PLACEHOLDER && !overrideNames.has(lower)) continue;
		headers.set(name, value);
	}
	for (const [name, value] of overrideNames) headers.set(name, value);

	let method = event.method.toUpperCase();
	let body = ["GET", "HEAD"].includes(method) ? null : overrides.body !== undefined ? overrides.body : (event.request_body ?? null);

	if (body !== null && !headers.has("content-type") && event.request_content_type) {
		headers.set("content-type", event.request_content_type);
	}

	let path = event.path;
	const hops: ResendHop[] = [];
	const base = targetBaseUrl(site);

	let response: Response;
	for (let hop = 0; ; hop += 1) {
		try {
			response = await fetch(`${base}${path}`, {
				method,
				headers,
				body,
				redirect: "manual",
				tls: {
					rejectUnauthorized: false,
				},
				signal: AbortSignal.timeout(config.originTimeoutMs),
			});
		} catch (error) {
			throw new ResendTargetError(error instanceof Error ? error.message : "Resend request failed");
		}

		const location = response.headers.get("location");
		const hopRecord: ResendHop = { method, path, status: response.status, location, followed: false, notFollowedReason: null };
		hops.push(hopRecord);

		if (!REDIRECT_STATUSES.has(response.status)) break;
		if (hop >= MAX_REDIRECTS) {
			hopRecord.notFollowedReason = "redirect-limit";
			break;
		}
		if (!location) {
			hopRecord.notFollowedReason = "no-location";
			break;
		}
		let target: URL;
		try {
			target = new URL(location, `${base}${path}`);
		} catch {
			hopRecord.notFollowedReason = "unparseable-location";
			break;
		}
		if (target.hostname.toLowerCase() !== publicHostname(site)) {
			hopRecord.notFollowedReason = "off-site";
			break;
		}
		hopRecord.followed = true;
		await response.text().catch(() => {});
		path = `${target.pathname}${target.search}`;
		if (response.status === 303 || (response.status !== 307 && response.status !== 308 && method !== "GET" && method !== "HEAD")) {
			method = "GET";
			body = null;
		}
	}

	const rawBody = await response.text();
	const truncated = rawBody.length > RESULT_BODY_BYTE_CEILING;
	return {
		status: response.status,
		headers: [...response.headers],
		body: truncated ? rawBody.slice(0, RESULT_BODY_BYTE_CEILING) : rawBody,
		bodyTruncated: truncated,
		hops,
	};
}
