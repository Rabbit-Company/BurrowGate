import type { Stats } from "node:fs";
import { stat } from "node:fs/promises";
import { join, normalize, sep } from "node:path";
import type { SiteOriginRecord, SiteRecord } from "../types.ts";
import { siteErrorResponse } from "./error-response-service.ts";
import { applyCorsResponseHeaders, applyHeaderPolicy, type ResolvedHttpPolicy } from "./http-policy-service.ts";
import { meteredBody, recordBandwidth, type BandwidthContext } from "./bandwidth-service.ts";
import { recordBandwidthLimitBytes } from "./bandwidth-limit-service.ts";

const RANGE_PATTERN = /^bytes=(\d*)-(\d*)$/;

interface ResolvedStaticFile {
	path: string;
	stats: Stats;
}

/**
 * Resolves a request path to a file under `root`, rejecting anything that
 * escapes it (traversal via "..", absolute paths, symlink-free by construction
 * since we never follow the client's path past a plain join+normalize). A
 * directory hit falls through to `indexFile` inside it.
 */
async function resolveStaticFile(root: string, urlPath: string, indexFile: string): Promise<ResolvedStaticFile | null> {
	let decoded: string;
	try {
		decoded = decodeURIComponent(urlPath);
	} catch {
		return null;
	}
	if (decoded.includes("\0")) return null;

	const candidate = normalize(join(root, decoded));
	if (candidate !== root && !candidate.startsWith(root + sep)) return null;

	try {
		const info = await stat(candidate);
		if (info.isFile()) return { path: candidate, stats: info };
		if (!info.isDirectory()) return null;
	} catch {
		return null;
	}

	const indexPath = join(candidate, indexFile);
	try {
		const indexInfo = await stat(indexPath);
		return indexInfo.isFile() ? { path: indexPath, stats: indexInfo } : null;
	} catch {
		return null;
	}
}

/** A weak validator derived from size and modification time */
function computeEtag(size: number, mtimeMs: number): string {
	return `W/"${size.toString(16)}-${Math.floor(mtimeMs).toString(16)}"`;
}

function etagMatches(headerValue: string, etag: string): boolean {
	const unweighted = etag.replace(/^W\//, "");
	return headerValue
		.split(",")
		.map((token) => token.trim())
		.some((token) => token === "*" || token.replace(/^W\//, "") === unweighted);
}

/** True when the request's conditional headers indicate the cached representation is still fresh (i.e. reply 304). */
function isNotModified(request: Request, etag: string, mtimeMs: number): boolean {
	const ifNoneMatch = request.headers.get("if-none-match");
	if (ifNoneMatch !== null) return etagMatches(ifNoneMatch, etag);

	const ifModifiedSince = request.headers.get("if-modified-since");
	if (!ifModifiedSince) return false;
	const since = Date.parse(ifModifiedSince);
	if (Number.isNaN(since)) return false;
	return Math.floor(mtimeMs / 1000) * 1000 <= since;
}

export async function serveStaticOrigin(
	request: Request,
	site: SiteRecord,
	origin: SiteOriginRecord,
	ip: string,
	countryCode: string | null,
	httpPolicy: ResolvedHttpPolicy,
): Promise<Response> {
	if (!["GET", "HEAD"].includes(request.method)) {
		return siteErrorResponse(site, request, {
			status: 405,
			code: "method_not_allowed",
			error: "Method not allowed",
			clientIp: ip,
			reason: "Static origins only serve GET and HEAD requests.",
		});
	}

	const root = origin.origin_url;
	const indexFile = origin.static_index_file || "index.html";
	const url = new URL(request.url);

	let resolved = await resolveStaticFile(root, url.pathname, indexFile);
	// Clean URLs: "/report" serves "report.html" when there's no exact file or
	// directory match. Skipped for a trailing slash, since that already means
	// "look for an index file in this directory".
	if (!resolved && !url.pathname.endsWith("/")) {
		resolved = await resolveStaticFile(root, `${url.pathname}.html`, indexFile);
	}
	if (!resolved && origin.static_spa_fallback === 1) {
		resolved = await resolveStaticFile(root, "/", indexFile);
	}
	if (!resolved) {
		return siteErrorResponse(site, request, {
			status: 404,
			code: "not_found",
			error: "Not found",
			clientIp: ip,
			reason: "The requested file does not exist on the static origin.",
		});
	}

	const size = resolved.stats.size;
	const etag = computeEtag(size, resolved.stats.mtimeMs);
	const lastModified = new Date(Math.floor(resolved.stats.mtimeMs / 1000) * 1000).toUTCString();

	const headers = new Headers();
	headers.set("accept-ranges", "bytes");
	headers.set("etag", etag);
	headers.set("last-modified", lastModified);
	applyHeaderPolicy(headers, httpPolicy.responseHeaders);
	applyCorsResponseHeaders(headers, request, httpPolicy.cors);

	if (isNotModified(request, etag, resolved.stats.mtimeMs)) {
		return new Response(null, { status: 304, headers });
	}

	const file = Bun.file(resolved.path);
	let body: Blob = file;
	let status = 200;

	const rangeHeader = request.method === "GET" ? request.headers.get("range") : null;
	if (rangeHeader) {
		const match = RANGE_PATTERN.exec(rangeHeader.trim());
		if (!match) {
			return new Response(null, { status: 416, headers: { "content-range": `bytes */${size}` } });
		}
		let start = match[1] ? Number(match[1]) : NaN;
		let end = match[2] ? Number(match[2]) : NaN;
		if (Number.isNaN(start)) {
			start = Math.max(size - end, 0);
			end = size - 1;
		} else if (Number.isNaN(end)) {
			end = size - 1;
		}
		if (Number.isNaN(start) || Number.isNaN(end) || start > end || start >= size) {
			return new Response(null, { status: 416, headers: { "content-range": `bytes */${size}` } });
		}
		end = Math.min(end, size - 1);
		body = file.slice(start, end + 1);
		status = 206;
		headers.set("content-range", `bytes ${start}-${end}/${size}`);
	}

	headers.set("content-type", file.type || "application/octet-stream");
	headers.set("content-length", String(body.size));

	if (request.method === "HEAD") {
		return new Response(null, { status, headers });
	}

	const bandwidth: BandwidthContext = { siteId: site.id, ip, countryCode, protocol: "http" };
	const responseBody = meteredBody(
		body.stream(),
		bandwidth,
		(bytes) => ({ upstreamReceivedBytes: bytes, clientSentBytes: bytes }),
		(context, delta) => {
			recordBandwidth(context, delta);
			recordBandwidthLimitBytes(httpPolicy.bandwidthLimit, site, ip, delta.clientSentBytes ?? 0);
		},
	);

	return new Response(responseBody, { status, headers });
}
