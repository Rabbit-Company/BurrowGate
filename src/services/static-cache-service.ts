import { config, visitorCookieNames } from "../config.ts";
import type { RoutePolicyRecord, SiteRecord } from "../types.ts";
import { parseCookies } from "../utils/cookies.ts";
import { accessIdentityCookieNames } from "./access-list-service.ts";
import type { SiteStaticCachePolicy } from "./http-policy-service.ts";
import { openMetrics } from "./openmetrics-service.ts";

export type CacheLookupOutcome = "disabled" | "bypass" | "miss" | "hit";

export interface StaticCacheLookup {
	outcome: CacheLookupOutcome;
	response?: Response;
	key?: string;
	bodyBytes?: number;
	originId?: string | null;
}

export interface StaticCacheMetrics {
	hits: number;
	misses: number;
	bypasses: number;
	stores: number;
	evictions: number;
	expired: number;
	purges: number;
	purgedEntries: number;
	bytesServed: number;
	entries: number;
	bytes: number;
	hitRatio: number;
	maxEntries: number;
	maxBytes: number;
}

interface CacheCounters {
	hits: number;
	misses: number;
	bypasses: number;
	stores: number;
	evictions: number;
	expired: number;
	purges: number;
	purgedEntries: number;
	bytesServed: number;
}

interface CacheEntry {
	key: string;
	siteId: string;
	routePolicyId: string | null;
	pathname: string;
	status: number;
	statusText: string;
	headers: Array<[string, string]>;
	body: Uint8Array;
	sizeBytes: number;
	storedAt: number;
	expiresAt: number;
	initialAgeSeconds: number;
	originId: string | null;
}

export interface CacheScope {
	siteId?: string;
	routePolicyId?: string;
	pathPrefix?: string;
}

interface CacheLimits {
	maxEntries: number;
	maxBytes: number;
}

interface OriginResponseMetadata {
	status: number;
	hasBody: boolean;
	headers: Headers;
}

const allowedInternalCookies = new Set<string>([...visitorCookieNames, ...accessIdentityCookieNames]);
const originResponseMetadata = new WeakMap<Response, OriginResponseMetadata>();
const emptyCounters = (): CacheCounters => ({
	hits: 0,
	misses: 0,
	bypasses: 0,
	stores: 0,
	evictions: 0,
	expired: 0,
	purges: 0,
	purgedEntries: 0,
	bytesServed: 0,
});
const textEncoder = new TextEncoder();

function cachedSizeBytes(headers: Array<[string, string]>, bodyBytes: number): number {
	return headers.reduce((bytes, [name, value]) => bytes + textEncoder.encode(name).byteLength + textEncoder.encode(value).byteLength + 4, bodyBytes);
}

function cacheControlDirectives(value: string | null): Map<string, string | true> {
	const result = new Map<string, string | true>();
	for (const part of (value ?? "").split(",")) {
		const [rawName, ...rawValue] = part.trim().split("=");
		const name = rawName?.trim().toLowerCase();
		if (!name) continue;
		result.set(name, rawValue.length ? rawValue.join("=").trim().replace(/^"|"$/gu, "") : true);
	}
	return result;
}

function requestHasApplicationCookies(request: Request): boolean {
	for (const name of parseCookies(request.headers.get("cookie")).keys()) if (!allowedInternalCookies.has(name)) return true;
	return false;
}

function requestEncodingVariant(request: Request): string {
	return (request.headers.get("accept-encoding") ?? "identity").trim().toLowerCase().replace(/\s+/gu, " ").slice(0, 512);
}

function cacheKey(request: Request, site: SiteRecord, route: RoutePolicyRecord | null): string {
	const url = new URL(request.url);
	return JSON.stringify([
		site.id,
		Number(site.updated_at),
		route?.id ?? null,
		Number(route?.updated_at ?? 0),
		url.pathname,
		url.search,
		requestEncodingVariant(request),
	]);
}

function requestBypassReason(request: Request, policy: SiteStaticCachePolicy): string | null {
	if (!(["GET", "HEAD"] as string[]).includes(request.method)) return "method";
	const url = new URL(request.url);
	const pathname = url.pathname.toLowerCase();
	if (!policy.extensions.some((extension) => pathname.endsWith(extension))) return "extension";
	if (request.headers.has("authorization") || requestHasApplicationCookies(request)) return "credentials";
	if (request.headers.has("range") || request.headers.has("if-range")) return "range";
	if (["if-match", "if-none-match", "if-modified-since", "if-unmodified-since"].some((name) => request.headers.has(name))) return "conditional";
	const requestCacheControl = cacheControlDirectives(request.headers.get("cache-control"));
	if (
		requestCacheControl.has("no-cache") ||
		requestCacheControl.has("no-store") ||
		requestCacheControl.get("max-age") === "0" ||
		request.headers.get("pragma")?.toLowerCase().includes("no-cache")
	)
		return "refresh";
	return null;
}

function responseTtlMs(response: Response, policy: SiteStaticCachePolicy, now: number): number | null {
	const metadata = originResponseMetadata.get(response) ?? { status: response.status, hasBody: Boolean(response.body), headers: response.headers };
	if (metadata.status !== 200 || !metadata.hasBody || metadata.headers.has("set-cookie") || metadata.headers.has("content-range")) return null;
	if (metadata.headers.get("content-disposition")?.toLowerCase().includes("attachment")) return null;
	const contentType = (metadata.headers.get("content-type")?.split(";", 1)[0] ?? "").trim().toLowerCase();
	const safeContentType =
		contentType.startsWith("image/") ||
		contentType.startsWith("font/") ||
		[
			"text/css",
			"text/javascript",
			"application/javascript",
			"application/x-javascript",
			"application/wasm",
			"application/octet-stream",
			"application/xml",
			"text/xml",
			"text/plain",
			"application/font-woff",
			"application/vnd.ms-fontobject",
		].includes(contentType);
	if (!safeContentType) return null;
	const vary = (metadata.headers.get("vary") ?? "")
		.split(",")
		.map((name) => name.trim().toLowerCase())
		.filter(Boolean);
	if (vary.some((name) => name !== "accept-encoding")) return null;
	const directives = cacheControlDirectives(metadata.headers.get("cache-control"));
	if (["no-store", "no-cache", "private"].some((directive) => directives.has(directive))) return null;
	const originTtl = directives.get("s-maxage") ?? directives.get("max-age");
	let ttlSeconds = policy.ttlSeconds;
	if (typeof originTtl === "string") {
		const parsed = Number(originTtl);
		if (!Number.isFinite(parsed) || parsed <= 0) return null;
		ttlSeconds = Math.min(ttlSeconds, Math.floor(parsed));
	} else if (metadata.headers.has("expires")) {
		const expiresAt = Date.parse(metadata.headers.get("expires")!);
		const responseDate = Date.parse(metadata.headers.get("date") ?? "");
		const reference = Number.isFinite(responseDate) ? responseDate : now;
		if (!Number.isFinite(expiresAt) || expiresAt <= reference) return null;
		ttlSeconds = Math.min(ttlSeconds, Math.floor((expiresAt - reference) / 1_000));
	}
	const age = Math.max(0, Number(metadata.headers.get("age") ?? 0) || 0);
	return Math.max(0, ttlSeconds * 1_000 - age * 1_000);
}

export function rememberOriginResponse(proxiedResponse: Response, originResponse: Response): Response {
	originResponseMetadata.set(proxiedResponse, {
		status: originResponse.status,
		hasBody: Boolean(originResponse.body),
		headers: new Headers(originResponse.headers),
	});
	return proxiedResponse;
}

async function readLimitedBody(body: ReadableStream<Uint8Array>, maximumBytes: number): Promise<Uint8Array | null> {
	const reader = body.getReader();
	const chunks: Uint8Array[] = [];
	let length = 0;
	try {
		while (true) {
			const result = await reader.read();
			if (result.done) break;
			length += result.value.byteLength;
			if (length > maximumBytes) {
				await reader.cancel("Static cache object limit exceeded");
				return null;
			}
			chunks.push(result.value);
		}
	} finally {
		reader.releaseLock();
	}
	const bodyBytes = new Uint8Array(length);
	let offset = 0;
	for (const chunk of chunks) {
		bodyBytes.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return bodyBytes;
}

export class StaticAssetCache {
	private readonly entries = new Map<string, CacheEntry>();
	private readonly counters = new Map<string, CacheCounters>();
	private readonly pending = new Set<Promise<void>>();
	private totalBytes = 0;
	private lastExpirySweepAt = 0;

	constructor(private readonly limits: CacheLimits = { maxEntries: config.httpCache.maxEntries, maxBytes: config.httpCache.maxBytes }) {}

	private siteCounters(siteId: string): CacheCounters {
		let counters = this.counters.get(siteId);
		if (!counters) {
			counters = emptyCounters();
			this.counters.set(siteId, counters);
		}
		return counters;
	}

	private storageForSite(siteId: string): { entries: number; bytes: number } {
		let entries = 0;
		let bytes = 0;
		for (const entry of this.entries.values()) {
			if (entry.siteId !== siteId) continue;
			entries += 1;
			bytes += entry.sizeBytes;
		}
		return { entries, bytes };
	}

	private syncStorage(siteId: string): void {
		const storage = this.storageForSite(siteId);
		openMetrics.setHttpCacheStorage(siteId, storage.entries, storage.bytes);
	}

	private deleteEntry(key: string, reason?: "capacity" | "expired" | "purge"): CacheEntry | null {
		const entry = this.entries.get(key);
		if (!entry) return null;
		this.entries.delete(key);
		this.totalBytes -= entry.sizeBytes;
		const counters = this.siteCounters(entry.siteId);
		if (reason === "capacity") counters.evictions += 1;
		if (reason === "expired") counters.expired += 1;
		if (reason) openMetrics.recordHttpCacheEviction(entry.siteId, reason);
		this.syncStorage(entry.siteId);
		return entry;
	}

	private sweepExpired(now: number): void {
		if (now - this.lastExpirySweepAt < 60_000) return;
		this.lastExpirySweepAt = now;
		for (const [key, entry] of this.entries) if (entry.expiresAt <= now) this.deleteEntry(key, "expired");
	}

	lookup(request: Request, site: SiteRecord, route: RoutePolicyRecord | null, policy: SiteStaticCachePolicy, now = Date.now()): StaticCacheLookup {
		if (policy.mode !== "enabled") return { outcome: "disabled" };
		this.sweepExpired(now);
		if (requestBypassReason(request, policy)) {
			this.siteCounters(site.id).bypasses += 1;
			openMetrics.recordHttpCacheRequest(site.id, "bypass");
			return { outcome: "bypass" };
		}
		const key = cacheKey(request, site, route);
		const entry = this.entries.get(key);
		if (entry && entry.expiresAt <= now) this.deleteEntry(key, "expired");
		const current = this.entries.get(key);
		if (!current) {
			this.siteCounters(site.id).misses += 1;
			openMetrics.recordHttpCacheRequest(site.id, "miss");
			return { outcome: "miss", key };
		}
		this.entries.delete(key);
		this.entries.set(key, current);
		const body = request.method === "HEAD" ? null : current.body.slice();
		const headers = new Headers(current.headers);
		headers.set("age", String(current.initialAgeSeconds + Math.max(0, Math.floor((now - current.storedAt) / 1_000))));
		headers.set("x-burrowgate-cache", "HIT");
		const counters = this.siteCounters(site.id);
		counters.hits += 1;
		const servedBytes = body?.byteLength ?? 0;
		counters.bytesServed += servedBytes;
		openMetrics.recordHttpCacheRequest(site.id, "hit", servedBytes);
		return {
			outcome: "hit",
			response: new Response(body, { status: current.status, statusText: current.statusText, headers }),
			bodyBytes: servedBytes,
			originId: current.originId,
		};
	}

	observeResponse(
		request: Request,
		response: Response,
		lookup: StaticCacheLookup,
		site: SiteRecord,
		route: RoutePolicyRecord | null,
		policy: SiteStaticCachePolicy,
		originId: string | null,
		now = Date.now(),
	): Response {
		if (lookup.outcome === "disabled") return response;
		const headers = new Headers(response.headers);
		headers.set("x-burrowgate-cache", lookup.outcome === "miss" ? "MISS" : "BYPASS");
		if (lookup.outcome !== "miss" || request.method !== "GET" || !lookup.key) {
			return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
		}
		const ttlMs = responseTtlMs(response, policy, now);
		const declaredLength = Number(response.headers.get("content-length"));
		if (ttlMs === null || ttlMs <= 0 || (Number.isFinite(declaredLength) && declaredLength > policy.maxObjectBytes)) {
			return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
		}
		const [clientBody, cacheBody] = response.body!.tee();
		const storedHeaders = [...response.headers] as Array<[string, string]>;
		const task = readLimitedBody(cacheBody, policy.maxObjectBytes)
			.then((body) => {
				if (!body) return;
				this.store({
					key: lookup.key!,
					siteId: site.id,
					routePolicyId: route?.id ?? null,
					pathname: new URL(request.url).pathname,
					status: response.status,
					statusText: response.statusText,
					headers: storedHeaders,
					body,
					sizeBytes: cachedSizeBytes(storedHeaders, body.byteLength),
					storedAt: now,
					expiresAt: now + ttlMs,
					initialAgeSeconds: Math.max(0, Math.floor(Number(originResponseMetadata.get(response)?.headers.get("age") ?? response.headers.get("age") ?? 0) || 0)),
					originId,
				});
			})
			.catch(() => {})
			.finally(() => this.pending.delete(task));
		this.pending.add(task);
		return new Response(clientBody, { status: response.status, statusText: response.statusText, headers });
	}

	private store(entry: CacheEntry): void {
		const replaced = this.entries.get(entry.key);
		if (replaced) {
			this.entries.delete(entry.key);
			this.totalBytes -= replaced.sizeBytes;
		}
		this.entries.set(entry.key, entry);
		this.totalBytes += entry.sizeBytes;
		this.siteCounters(entry.siteId).stores += 1;
		openMetrics.recordHttpCacheStore(entry.siteId);
		while (this.entries.size > this.limits.maxEntries || this.totalBytes > this.limits.maxBytes) {
			const oldest = this.entries.keys().next().value as string | undefined;
			if (!oldest) break;
			this.deleteEntry(oldest, "capacity");
		}
		this.syncStorage(entry.siteId);
	}

	purge(scope: CacheScope = {}): number {
		const affectedSites = new Map<string, number>();
		let removed = 0;
		for (const [key, entry] of this.entries) {
			if (scope.siteId && entry.siteId !== scope.siteId) continue;
			if (scope.routePolicyId && entry.routePolicyId !== scope.routePolicyId) continue;
			if (scope.pathPrefix && !entry.pathname.startsWith(scope.pathPrefix)) continue;
			this.entries.delete(key);
			this.totalBytes -= entry.sizeBytes;
			removed += 1;
			affectedSites.set(entry.siteId, (affectedSites.get(entry.siteId) ?? 0) + 1);
		}
		if (scope.siteId && !affectedSites.has(scope.siteId)) affectedSites.set(scope.siteId, 0);
		for (const [siteId, count] of affectedSites) {
			const counters = this.siteCounters(siteId);
			counters.purges += 1;
			counters.purgedEntries += count;
			openMetrics.recordHttpCacheEviction(siteId, "purge", count);
			this.syncStorage(siteId);
		}
		return removed;
	}

	metrics(siteId?: string): StaticCacheMetrics {
		const selected = siteId ? [this.siteCounters(siteId)] : [...this.counters.values()];
		const counters = selected.reduce((total, item) => {
			for (const key of Object.keys(total) as Array<keyof CacheCounters>) total[key] += item[key];
			return total;
		}, emptyCounters());
		const storage = siteId ? this.storageForSite(siteId) : { entries: this.entries.size, bytes: this.totalBytes };
		const lookups = counters.hits + counters.misses;
		return { ...counters, ...storage, hitRatio: lookups > 0 ? counters.hits / lookups : 0, maxEntries: this.limits.maxEntries, maxBytes: this.limits.maxBytes };
	}

	removeSite(siteId: string): void {
		this.purge({ siteId });
		this.counters.delete(siteId);
		openMetrics.setHttpCacheStorage(siteId, 0, 0);
	}

	async waitForIdle(): Promise<void> {
		await Promise.all([...this.pending]);
	}
}

export const staticAssetCache = new StaticAssetCache();
