import { config } from "../config.ts";
import { isTextContentType } from "./body-capture-service.ts";
import type { RoutePolicyRecord, SiteRecord } from "../types.ts";

export interface HeaderAssignment {
	name: string;
	value: string;
}

export interface HeaderMutationPolicy {
	set: HeaderAssignment[];
	remove: string[];
}

export interface RequestLimits {
	maxBodyBytes: number;
	maxRequestTargetBytes: number;
	maxHeaderBytes: number;
}

export type SiteStaticCacheMode = "disabled" | "enabled";
export type RouteStaticCacheMode = "inherit" | SiteStaticCacheMode;

export interface SiteStaticCachePolicy {
	mode: SiteStaticCacheMode;
	ttlSeconds: number;
	maxObjectBytes: number;
	extensions: string[];
}

export interface RouteStaticCachePolicy {
	mode: RouteStaticCacheMode;
	ttlSeconds: number | null;
	maxObjectBytes: number | null;
	extensions: string[] | null;
}

export type ManagedProtectionMode = "disabled" | "monitor" | "block";
export type RouteManagedProtectionMode = "inherit" | ManagedProtectionMode;

export interface SiteManagedProtectionPolicy {
	mode: ManagedProtectionMode;
	rulesetId: string;
	excludedRuleIds: string[];
}

export interface RouteManagedProtectionPolicy {
	mode: RouteManagedProtectionMode;
	excludedRuleIds: string[];
}

export interface ResolvedManagedProtectionPolicy {
	mode: ManagedProtectionMode;
	rulesetId: string;
	excludedRuleIds: string[];
}

export type SiteBodyCaptureMode = "disabled" | "enabled";
export type RouteBodyCaptureMode = "inherit" | SiteBodyCaptureMode;

export interface SiteBodyCapturePolicy {
	mode: SiteBodyCaptureMode;
	maxRequestBytes: number;
	maxResponseBytes: number;
	expiresAt: number | null;
	contentTypes: string[];
}

export interface RouteBodyCapturePolicy {
	mode: RouteBodyCaptureMode;
	maxRequestBytes: number | null;
	maxResponseBytes: number | null;
	contentTypes: string[] | null;
	expiresAt: number | null;
}

export type BanDurationSeverity = "low" | "medium" | "high" | "critical";

export interface SiteBanDurationsPolicy {
	low: number;
	medium: number;
	high: number;
	critical: number;
}

export interface RouteBanDurationsPolicy {
	low: number | null;
	medium: number | null;
	high: number | null;
	critical: number | null;
}

export interface SiteBandwidthLimitPolicy {
	enabled: boolean;
	maxBytes: number;
	windowSeconds: number;
	banSeconds: number;
}

export interface RouteBandwidthLimitPolicy {
	enabled: boolean | null;
	maxBytes: number | null;
	windowSeconds: number | null;
	banSeconds: number | null;
}

export interface ResolvedBandwidthLimitPolicy {
	enabled: boolean;
	maxBytes: number;
	windowSeconds: number;
	banSeconds: number;
	scopeId: string;
}

export const DEFAULT_STATIC_CACHE_EXTENSIONS = [
	".css",
	".js",
	".mjs",
	".png",
	".jpg",
	".jpeg",
	".gif",
	".webp",
	".avif",
	".svg",
	".ico",
	".woff",
	".woff2",
	".ttf",
	".otf",
	".eot",
	".wasm",
	".txt",
	".xml",
] as const;

export const DEFAULT_BODY_CAPTURE_CONTENT_TYPES = [
	"text/plain",
	"text/html",
	"text/css",
	"text/javascript",
	"application/javascript",
	"application/json",
	"application/xml",
	"application/x-www-form-urlencoded",
] as const;

export interface SiteHttpPolicyView {
	requestHeaders: HeaderMutationPolicy;
	responseHeaders: HeaderMutationPolicy;
	limits: RequestLimits;
	cache: SiteStaticCachePolicy;
	protection: SiteManagedProtectionPolicy;
	banDurations: SiteBanDurationsPolicy;
	bandwidthLimit: SiteBandwidthLimitPolicy;
	bodyCapture: SiteBodyCapturePolicy;
}

export interface RouteHttpPolicyView {
	requestHeaders: HeaderMutationPolicy;
	responseHeaders: HeaderMutationPolicy;
	limits: { [K in keyof RequestLimits]: number | null };
	cache: RouteStaticCachePolicy;
	protection: RouteManagedProtectionPolicy;
	banDurations: RouteBanDurationsPolicy;
	bandwidthLimit: RouteBandwidthLimitPolicy;
	bodyCapture: RouteBodyCapturePolicy;
}

export interface ResolvedHttpPolicy extends Omit<SiteHttpPolicyView, "protection" | "bandwidthLimit"> {
	protection: ResolvedManagedProtectionPolicy;
	bandwidthLimit: ResolvedBandwidthLimitPolicy;
}

export type RequestLimitViolation = {
	status: 413 | 414 | 431;
	code: "request_body_too_large" | "request_target_too_large" | "request_headers_too_large";
	message: string;
};

interface StoredSitePolicy extends SiteHttpPolicyView {}
interface StoredRoutePolicy extends RouteHttpPolicyView {}

const HTTP_TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u;
const MAX_RULES_PER_DIRECTION = 64;
const MAX_HEADER_NAME_LENGTH = 128;
const MAX_HEADER_VALUE_LENGTH = 8_192;

const limitDefinitions = {
	maxBodyBytes: { label: "Maximum request body", maximum: 1_099_511_627_776 },
	maxRequestTargetBytes: { label: "Maximum request target", maximum: 1_048_576 },
	maxHeaderBytes: { label: "Maximum request headers", maximum: 1_048_576 },
} as const;
const staticCacheObjectCeiling = Math.min(config.httpCache.maxObjectBytes, config.httpCache.maxBytes);
const bodyCaptureByteCeiling = config.bodyCapture.maxBytesCeiling;

// These fields control connection framing, origin routing, or BurrowGate's
// authenticated forwarding boundary. They must remain proxy-owned.
const protectedRequestHeaders = new Set([
	"connection",
	"content-length",
	"forwarded",
	"host",
	"keep-alive",
	"proxy-authenticate",
	"proxy-authorization",
	"proxy-connection",
	"te",
	"trailer",
	"transfer-encoding",
	"upgrade",
	"x-forwarded-for",
	"x-forwarded-host",
	"x-forwarded-port",
	"x-forwarded-proto",
	"x-forwarded-protocol",
	"x-real-ip",
]);

const protectedResponseSetHeaders = new Set([
	"connection",
	"content-encoding",
	"content-length",
	"keep-alive",
	"proxy-authenticate",
	"proxy-authorization",
	"proxy-connection",
	"set-cookie",
	"te",
	"trailer",
	"transfer-encoding",
	"upgrade",
]);

const defaultSitePolicy = (): StoredSitePolicy => ({
	requestHeaders: { set: [], remove: [] },
	responseHeaders: { set: [], remove: [] },
	limits: { maxBodyBytes: 0, maxRequestTargetBytes: 0, maxHeaderBytes: 0 },
	cache: {
		mode: "disabled",
		ttlSeconds: 3_600,
		maxObjectBytes: Math.min(5 * 1_024 * 1_024, staticCacheObjectCeiling),
		extensions: [...DEFAULT_STATIC_CACHE_EXTENSIONS],
	},
	protection: { mode: "monitor", rulesetId: "default", excludedRuleIds: [] },
	banDurations: { low: 0, medium: 600, high: 3_600, critical: 86_400 },
	bandwidthLimit: { enabled: false, maxBytes: 50 * 1_024 * 1_024, windowSeconds: 60, banSeconds: 3_600 },
	bodyCapture: {
		mode: "disabled",
		maxRequestBytes: 4_096,
		maxResponseBytes: 4_096,
		expiresAt: null,
		contentTypes: [...DEFAULT_BODY_CAPTURE_CONTENT_TYPES],
	},
});

const defaultRoutePolicy = (): StoredRoutePolicy => ({
	requestHeaders: { set: [], remove: [] },
	responseHeaders: { set: [], remove: [] },
	limits: { maxBodyBytes: null, maxRequestTargetBytes: null, maxHeaderBytes: null },
	cache: { mode: "inherit", ttlSeconds: null, maxObjectBytes: null, extensions: null },
	protection: { mode: "inherit", excludedRuleIds: [] },
	banDurations: { low: null, medium: null, high: null, critical: null },
	bandwidthLimit: { enabled: null, maxBytes: null, windowSeconds: null, banSeconds: null },
	bodyCapture: { mode: "inherit", maxRequestBytes: null, maxResponseBytes: null, expiresAt: null, contentTypes: null },
});

function protectionMode(
	value: unknown,
	route: boolean,
	fallback: ManagedProtectionMode | RouteManagedProtectionMode,
): ManagedProtectionMode | RouteManagedProtectionMode {
	if (value === undefined) return fallback;
	const mode = String(value).trim().toLowerCase();
	if (["disabled", "monitor", "block"].includes(mode) || (route && mode === "inherit")) {
		return mode as ManagedProtectionMode | RouteManagedProtectionMode;
	}
	throw new Error(`Managed protection mode must be ${route ? "inherit, disabled, monitor, or block" : "disabled, monitor, or block"}`);
}

function protectionRuleIds(value: unknown, fallback: readonly string[] = []): string[] {
	if (value === undefined || value === null || value === "") return [...fallback];
	const raw = Array.isArray(value) ? value : String(value).split(/[\s,]+/u);
	const ids = [...new Set(raw.map((item) => String(item).trim().toUpperCase()).filter(Boolean))];
	if (ids.length > 256) throw new Error("Managed protection supports at most 256 excluded rule IDs");
	for (const id of ids) if (!/^[A-Z0-9][A-Z0-9._:-]{0,127}$/u.test(id)) throw new Error(`Invalid managed protection rule ID: ${id}`);
	return ids;
}

function protectionRulesetId(value: unknown, fallback: string): string {
	const id = String(value ?? fallback)
		.trim()
		.toLowerCase();
	if (!/^[a-z0-9][a-z0-9._-]{0,127}$/u.test(id)) throw new Error("Managed protection ruleset ID is invalid");
	return id;
}

function parseSiteProtection(value: unknown): SiteManagedProtectionPolicy {
	const defaults = defaultSitePolicy().protection;
	const input = value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
	return {
		mode: protectionMode(input.mode, false, defaults.mode) as ManagedProtectionMode,
		rulesetId: protectionRulesetId(input.rulesetId, defaults.rulesetId),
		excludedRuleIds: protectionRuleIds(input.excludedRuleIds, defaults.excludedRuleIds),
	};
}

function parseRouteProtection(value: unknown): RouteManagedProtectionPolicy {
	const input = value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
	return {
		mode: protectionMode(input.mode, true, "inherit") as RouteManagedProtectionMode,
		excludedRuleIds: protectionRuleIds(input.excludedRuleIds),
	};
}

const MAX_BAN_DURATION_SECONDS = 2_592_000; // 30 days

function parseSiteBanDurations(value: unknown): SiteBanDurationsPolicy {
	const defaults = defaultSitePolicy().banDurations;
	const input = value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
	return {
		low: cacheInteger(input.low, "Low severity ban duration", defaults.low, 0, MAX_BAN_DURATION_SECONDS, false)!,
		medium: cacheInteger(input.medium, "Medium severity ban duration", defaults.medium, 0, MAX_BAN_DURATION_SECONDS, false)!,
		high: cacheInteger(input.high, "High severity ban duration", defaults.high, 0, MAX_BAN_DURATION_SECONDS, false)!,
		critical: cacheInteger(input.critical, "Critical severity ban duration", defaults.critical, 0, MAX_BAN_DURATION_SECONDS, false)!,
	};
}

function parseRouteBanDurations(value: unknown): RouteBanDurationsPolicy {
	const input = value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
	return {
		low: cacheInteger(input.low, "Low severity ban duration", null, 0, MAX_BAN_DURATION_SECONDS, true),
		medium: cacheInteger(input.medium, "Medium severity ban duration", null, 0, MAX_BAN_DURATION_SECONDS, true),
		high: cacheInteger(input.high, "High severity ban duration", null, 0, MAX_BAN_DURATION_SECONDS, true),
		critical: cacheInteger(input.critical, "Critical severity ban duration", null, 0, MAX_BAN_DURATION_SECONDS, true),
	};
}

const MAX_BANDWIDTH_LIMIT_BYTES = 1_099_511_627_776; // 1 TiB
const MAX_BANDWIDTH_LIMIT_WINDOW_SECONDS = 3_600;

function bandwidthLimitBoolean(value: unknown, fallback: boolean): boolean {
	if (value === undefined) return fallback;
	if (typeof value === "boolean") return value;
	if (value === "true" || value === "1" || value === 1) return true;
	if (value === "false" || value === "0" || value === 0 || value === "") return false;
	throw new Error("Bandwidth limit enabled must be a boolean");
}

function routeBandwidthLimitBoolean(value: unknown): boolean | null {
	if (value === undefined || value === null || value === "") return null;
	return bandwidthLimitBoolean(value, false);
}

function parseSiteBandwidthLimit(value: unknown): SiteBandwidthLimitPolicy {
	const defaults = defaultSitePolicy().bandwidthLimit;
	const input = value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
	return {
		enabled: bandwidthLimitBoolean(input.enabled, defaults.enabled),
		maxBytes: cacheInteger(input.maxBytes, "Bandwidth limit threshold", defaults.maxBytes, 1, MAX_BANDWIDTH_LIMIT_BYTES, false)!,
		windowSeconds: cacheInteger(input.windowSeconds, "Bandwidth limit window", defaults.windowSeconds, 1, MAX_BANDWIDTH_LIMIT_WINDOW_SECONDS, false)!,
		banSeconds: cacheInteger(input.banSeconds, "Bandwidth limit ban duration", defaults.banSeconds, 0, MAX_BAN_DURATION_SECONDS, false)!,
	};
}

function parseRouteBandwidthLimit(value: unknown): RouteBandwidthLimitPolicy {
	const input = value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
	return {
		enabled: routeBandwidthLimitBoolean(input.enabled),
		maxBytes: cacheInteger(input.maxBytes, "Route bandwidth limit threshold", null, 1, MAX_BANDWIDTH_LIMIT_BYTES, true),
		windowSeconds: cacheInteger(input.windowSeconds, "Route bandwidth limit window", null, 1, MAX_BANDWIDTH_LIMIT_WINDOW_SECONDS, true),
		banSeconds: cacheInteger(input.banSeconds, "Route bandwidth limit ban duration", null, 0, MAX_BAN_DURATION_SECONDS, true),
	};
}

function cacheMode(value: unknown, route: boolean, fallback: SiteStaticCacheMode | RouteStaticCacheMode): SiteStaticCacheMode | RouteStaticCacheMode {
	if (value === undefined) return fallback;
	const mode = String(value).trim().toLowerCase();
	if (mode === "enabled" || mode === "disabled" || (route && mode === "inherit")) return mode as SiteStaticCacheMode | RouteStaticCacheMode;
	throw new Error(`Static cache mode must be ${route ? "inherit, enabled, or disabled" : "enabled or disabled"}`);
}

function cacheInteger(value: unknown, label: string, fallback: number | null, minimum: number, maximum: number, nullable: boolean): number | null {
	if (nullable && (value === undefined || value === null || value === "")) return null;
	const result = value === undefined ? fallback : Number(value);
	if (!Number.isSafeInteger(result) || Number(result) < minimum || Number(result) > maximum) {
		throw new Error(`${label} must be an integer from ${minimum} to ${maximum}`);
	}
	return Number(result);
}

function cacheExtensions(value: unknown, nullable: boolean, fallback: readonly string[] | null): string[] | null {
	if (nullable && (value === undefined || value === null || value === "")) return null;
	if (value === undefined) return fallback ? [...fallback] : null;
	const raw = Array.isArray(value) ? value : String(value).split(/[\s,]+/u);
	const extensions = [...new Set(raw.map((item) => String(item).trim().toLowerCase()).filter(Boolean))];
	if (extensions.length < 1 || extensions.length > 64) throw new Error("Static cache extensions must contain from 1 to 64 values");
	for (const extension of extensions) {
		if (extension.length > 32 || !/^\.[a-z0-9][a-z0-9._-]*$/u.test(extension)) throw new Error(`Invalid static cache extension: ${extension}`);
	}
	return extensions;
}

function parseSiteCache(value: unknown): SiteStaticCachePolicy {
	const defaults = defaultSitePolicy().cache;
	const input = value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
	return {
		mode: cacheMode(input.mode, false, defaults.mode) as SiteStaticCacheMode,
		ttlSeconds: cacheInteger(input.ttlSeconds, "Static cache TTL", defaults.ttlSeconds, 1, 604_800, false)!,
		maxObjectBytes: cacheInteger(input.maxObjectBytes, "Static cache maximum object size", defaults.maxObjectBytes, 1_024, staticCacheObjectCeiling, false)!,
		extensions: cacheExtensions(input.extensions, false, defaults.extensions)!,
	};
}

function parseRouteCache(value: unknown): RouteStaticCachePolicy {
	const input = value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
	return {
		mode: cacheMode(input.mode, true, "inherit") as RouteStaticCacheMode,
		ttlSeconds: cacheInteger(input.ttlSeconds, "Route static cache TTL", null, 1, 604_800, true),
		maxObjectBytes: cacheInteger(input.maxObjectBytes, "Route static cache maximum object size", null, 1_024, staticCacheObjectCeiling, true),
		extensions: cacheExtensions(input.extensions, true, null),
	};
}

function bodyCaptureMode(value: unknown, route: boolean, fallback: SiteBodyCaptureMode | RouteBodyCaptureMode): SiteBodyCaptureMode | RouteBodyCaptureMode {
	if (value === undefined) return fallback;
	const mode = String(value).trim().toLowerCase();
	if (mode === "enabled" || mode === "disabled" || (route && mode === "inherit")) return mode as SiteBodyCaptureMode | RouteBodyCaptureMode;
	throw new Error(`Body capture mode must be ${route ? "inherit, enabled, or disabled" : "enabled or disabled"}`);
}

function bodyCaptureBytes(value: unknown, label: string, fallback: number | null, nullable: boolean): number | null {
	if (nullable && (value === undefined || value === null || value === "")) return null;
	const result = value === undefined ? fallback : Number(value);
	if (!Number.isSafeInteger(result) || Number(result) < 0 || Number(result) > bodyCaptureByteCeiling) {
		throw new Error(`${label} must be an integer from 0 to ${bodyCaptureByteCeiling} bytes`);
	}
	return Number(result);
}

function bodyCaptureExpiresAt(value: unknown, fallback: number | null): number | null {
	if (value === undefined) return fallback;
	if (value === null || value === "") return null;
	const result = Number(value);
	if (!Number.isSafeInteger(result) || result < 0) throw new Error("Body capture expiration must be a valid timestamp");
	return result;
}

const BODY_CAPTURE_CONTENT_TYPE_PATTERN = /^[a-z0-9][a-z0-9.+-]*\/[a-z0-9][a-z0-9.+-]*$/u;

function bodyCaptureContentTypes(value: unknown, nullable: boolean, fallback: readonly string[] | null): string[] | null {
	if (nullable && (value === undefined || value === null || value === "")) return null;
	if (value === undefined) return fallback ? [...fallback] : null;
	const raw = Array.isArray(value) ? value : String(value).split(/[\s,]+/u);
	const contentTypes = [...new Set(raw.map((item) => String(item).split(";")[0]!.trim().toLowerCase()).filter(Boolean))];
	if (contentTypes.length > 32) throw new Error("Body capture content types supports at most 32 values");
	for (const contentType of contentTypes) {
		if (contentType === "*") continue;
		if (contentType.length > 128 || !BODY_CAPTURE_CONTENT_TYPE_PATTERN.test(contentType) || !isTextContentType(contentType)) {
			throw new Error(`Body capture only supports text-based content types: ${contentType}`);
		}
	}
	return contentTypes;
}

function parseSiteBodyCapture(value: unknown): SiteBodyCapturePolicy {
	const defaults = defaultSitePolicy().bodyCapture;
	const input = value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
	return {
		mode: bodyCaptureMode(input.mode, false, defaults.mode) as SiteBodyCaptureMode,
		maxRequestBytes: bodyCaptureBytes(input.maxRequestBytes, "Site maximum request body", defaults.maxRequestBytes, false)!,
		maxResponseBytes: bodyCaptureBytes(input.maxResponseBytes, "Site maximum response body", defaults.maxResponseBytes, false)!,
		expiresAt: bodyCaptureExpiresAt(input.expiresAt, defaults.expiresAt),
		contentTypes: bodyCaptureContentTypes(input.contentTypes, false, defaults.contentTypes)!,
	};
}

function parseRouteBodyCapture(value: unknown): RouteBodyCapturePolicy {
	const input = value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
	return {
		mode: bodyCaptureMode(input.mode, true, "inherit") as RouteBodyCaptureMode,
		maxRequestBytes: bodyCaptureBytes(input.maxRequestBytes, "Route maximum request body", null, true),
		maxResponseBytes: bodyCaptureBytes(input.maxResponseBytes, "Route maximum response body", null, true),
		expiresAt: bodyCaptureExpiresAt(input.expiresAt, null),
		contentTypes: bodyCaptureContentTypes(input.contentTypes, true, null),
	};
}

function objectValue(value: unknown, label: string): Record<string, unknown> {
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
	return value as Record<string, unknown>;
}

function parseJson(value: string | null | undefined): Record<string, unknown> {
	if (!value) return {};
	try {
		const parsed = JSON.parse(value) as unknown;
		return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {};
	} catch {
		return {};
	}
}

function normalizedHeaderName(value: unknown, label: string): string {
	const name = String(value ?? "")
		.trim()
		.toLowerCase();
	if (!name || name.length > MAX_HEADER_NAME_LENGTH || !HTTP_TOKEN.test(name)) throw new Error(`${label} contains an invalid header name`);
	return name;
}

function assertMutableHeader(name: string, direction: "request" | "response", operation: "set" | "remove"): void {
	if (direction === "request" && (protectedRequestHeaders.has(name) || name.startsWith("x-burrowgate-"))) {
		throw new Error(`Request header ${name} is managed by BurrowGate and cannot be changed`);
	}
	if (direction === "response" && operation === "set" && (protectedResponseSetHeaders.has(name) || name.startsWith("x-burrowgate-"))) {
		throw new Error(`Response header ${name} is managed by BurrowGate and cannot be changed`);
	}
}

function parseHeaderPolicy(value: unknown, label: string, direction: "request" | "response"): HeaderMutationPolicy {
	if (value === undefined || value === null) return { set: [], remove: [] };
	const record = objectValue(value, label);
	const setInput = record.set ?? [];
	const removeInput = record.remove ?? [];
	if (!Array.isArray(setInput) || !Array.isArray(removeInput)) throw new Error(`${label} set and remove values must be arrays`);
	if (setInput.length > MAX_RULES_PER_DIRECTION || removeInput.length > MAX_RULES_PER_DIRECTION) {
		throw new Error(`${label} supports at most ${MAX_RULES_PER_DIRECTION} set and remove rules`);
	}
	const assignments = new Map<string, HeaderAssignment>();
	for (const item of setInput) {
		const assignment = objectValue(item, `${label} set rule`);
		const name = normalizedHeaderName(assignment.name, label);
		assertMutableHeader(name, direction, "set");
		const headerValue = String(assignment.value ?? "");
		if (headerValue.length > MAX_HEADER_VALUE_LENGTH || /[\r\n\0]/u.test(headerValue)) throw new Error(`${label} ${name} has an invalid value`);
		assignments.set(name, { name, value: headerValue });
	}
	const removals = new Set<string>();
	for (const item of removeInput) {
		const name = normalizedHeaderName(item, label);
		assertMutableHeader(name, direction, "remove");
		if (assignments.has(name)) throw new Error(`${label} cannot both set and remove ${name}`);
		removals.add(name);
	}
	return { set: [...assignments.values()], remove: [...removals] };
}

function limitValue(key: keyof RequestLimits, value: unknown, nullable: boolean): number | null {
	if (nullable && (value === undefined || value === null || value === "")) return null;
	const result = Number(value ?? 0);
	const definition = limitDefinitions[key];
	if (!Number.isSafeInteger(result) || result < 0 || result > definition.maximum) {
		throw new Error(`${definition.label} must be an integer from 0 to ${definition.maximum} bytes`);
	}
	return result;
}

function parseSitePolicy(value: unknown): StoredSitePolicy {
	const input = value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
	const limits = input.limits && typeof input.limits === "object" && !Array.isArray(input.limits) ? (input.limits as Record<string, unknown>) : {};
	return {
		requestHeaders: parseHeaderPolicy(input.requestHeaders, "Request header policy", "request"),
		responseHeaders: parseHeaderPolicy(input.responseHeaders, "Response header policy", "response"),
		limits: {
			maxBodyBytes: limitValue("maxBodyBytes", limits.maxBodyBytes, false)!,
			maxRequestTargetBytes: limitValue("maxRequestTargetBytes", limits.maxRequestTargetBytes, false)!,
			maxHeaderBytes: limitValue("maxHeaderBytes", limits.maxHeaderBytes, false)!,
		},
		cache: parseSiteCache(input.cache),
		protection: parseSiteProtection(input.protection),
		banDurations: parseSiteBanDurations(input.banDurations),
		bandwidthLimit: parseSiteBandwidthLimit(input.bandwidthLimit),
		bodyCapture: parseSiteBodyCapture(input.bodyCapture),
	};
}

function parseRoutePolicy(value: unknown): StoredRoutePolicy {
	const input = value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
	const limits = input.limits && typeof input.limits === "object" && !Array.isArray(input.limits) ? (input.limits as Record<string, unknown>) : {};
	return {
		requestHeaders: parseHeaderPolicy(input.requestHeaders, "Route request header policy", "request"),
		responseHeaders: parseHeaderPolicy(input.responseHeaders, "Route response header policy", "response"),
		limits: {
			maxBodyBytes: limitValue("maxBodyBytes", limits.maxBodyBytes, true),
			maxRequestTargetBytes: limitValue("maxRequestTargetBytes", limits.maxRequestTargetBytes, true),
			maxHeaderBytes: limitValue("maxHeaderBytes", limits.maxHeaderBytes, true),
		},
		cache: parseRouteCache(input.cache),
		protection: parseRouteProtection(input.protection),
		banDurations: parseRouteBanDurations(input.banDurations),
		bandwidthLimit: parseRouteBandwidthLimit(input.bandwidthLimit),
		bodyCapture: parseRouteBodyCapture(input.bodyCapture),
	};
}

function storedSitePolicy(value: string | null | undefined): StoredSitePolicy {
	try {
		return parseSitePolicy(parseJson(value));
	} catch {
		return defaultSitePolicy();
	}
}

function storedRoutePolicy(value: string | null | undefined): StoredRoutePolicy {
	try {
		return parseRoutePolicy(parseJson(value));
	} catch {
		return defaultRoutePolicy();
	}
}

export function serializeSiteHttpPolicy(input: unknown, existing?: string | null): string {
	if (input === undefined) return JSON.stringify(storedSitePolicy(existing));
	if (input === null) return JSON.stringify(defaultSitePolicy());
	const value = objectValue(input, "Site HTTP policy");
	const current = storedSitePolicy(existing);
	const suppliedLimits = value.limits === undefined ? {} : objectValue(value.limits, "Site request limits");
	const suppliedCache = value.cache === undefined ? {} : objectValue(value.cache, "Site static cache policy");
	const suppliedProtection = value.protection === undefined ? {} : objectValue(value.protection, "Site managed protection policy");
	const suppliedBanDurations = value.banDurations === undefined ? {} : objectValue(value.banDurations, "Site ban duration policy");
	const suppliedBandwidthLimit = value.bandwidthLimit === undefined ? {} : objectValue(value.bandwidthLimit, "Site bandwidth limit policy");
	const suppliedBodyCapture = value.bodyCapture === undefined ? {} : objectValue(value.bodyCapture, "Site body capture policy");
	return JSON.stringify(
		parseSitePolicy({
			requestHeaders: "requestHeaders" in value ? value.requestHeaders : current.requestHeaders,
			responseHeaders: "responseHeaders" in value ? value.responseHeaders : current.responseHeaders,
			limits: { ...current.limits, ...suppliedLimits },
			cache: { ...current.cache, ...suppliedCache },
			protection: { ...current.protection, ...suppliedProtection },
			banDurations: { ...current.banDurations, ...suppliedBanDurations },
			bandwidthLimit: { ...current.bandwidthLimit, ...suppliedBandwidthLimit },
			bodyCapture: { ...current.bodyCapture, ...suppliedBodyCapture },
		}),
	);
}

export function serializeRouteHttpPolicy(input: unknown, existing?: string | null): string {
	if (input === undefined) return JSON.stringify(storedRoutePolicy(existing));
	if (input === null) return JSON.stringify(defaultRoutePolicy());
	const value = objectValue(input, "Route HTTP policy");
	const current = storedRoutePolicy(existing);
	const suppliedLimits = value.limits === undefined ? {} : objectValue(value.limits, "Route request limits");
	const suppliedCache = value.cache === undefined ? {} : objectValue(value.cache, "Route static cache policy");
	const suppliedProtection = value.protection === undefined ? {} : objectValue(value.protection, "Route managed protection policy");
	const suppliedBanDurations = value.banDurations === undefined ? {} : objectValue(value.banDurations, "Route ban duration policy");
	const suppliedBandwidthLimit = value.bandwidthLimit === undefined ? {} : objectValue(value.bandwidthLimit, "Route bandwidth limit policy");
	const suppliedBodyCapture = value.bodyCapture === undefined ? {} : objectValue(value.bodyCapture, "Route body capture policy");
	return JSON.stringify(
		parseRoutePolicy({
			requestHeaders: "requestHeaders" in value ? value.requestHeaders : current.requestHeaders,
			responseHeaders: "responseHeaders" in value ? value.responseHeaders : current.responseHeaders,
			limits: { ...current.limits, ...suppliedLimits },
			cache: { ...current.cache, ...suppliedCache },
			protection: { ...current.protection, ...suppliedProtection },
			banDurations: { ...current.banDurations, ...suppliedBanDurations },
			bandwidthLimit: { ...current.bandwidthLimit, ...suppliedBandwidthLimit },
			bodyCapture: { ...current.bodyCapture, ...suppliedBodyCapture },
		}),
	);
}

export function siteHttpPolicyView(site: SiteRecord): SiteHttpPolicyView {
	return storedSitePolicy(site.http_policy_json);
}

export function routeHttpPolicyView(policy: RoutePolicyRecord): RouteHttpPolicyView {
	return storedRoutePolicy(policy.http_policy_json);
}

function mergeHeaderPolicies(site: HeaderMutationPolicy, route: HeaderMutationPolicy): HeaderMutationPolicy {
	const operations = new Map<string, { operation: "set"; value: string } | { operation: "remove" }>();
	for (const assignment of site.set) operations.set(assignment.name, { operation: "set", value: assignment.value });
	for (const name of site.remove) operations.set(name, { operation: "remove" });
	for (const assignment of route.set) operations.set(assignment.name, { operation: "set", value: assignment.value });
	for (const name of route.remove) operations.set(name, { operation: "remove" });
	const result: HeaderMutationPolicy = { set: [], remove: [] };
	for (const [name, operation] of operations) {
		if (operation.operation === "set") result.set.push({ name, value: operation.value });
		else result.remove.push(name);
	}
	return result;
}

export function resolveHttpPolicy(site: SiteRecord, policy?: RoutePolicyRecord | null): ResolvedHttpPolicy {
	const sitePolicy = storedSitePolicy(site.http_policy_json);
	const routePolicy = policy ? storedRoutePolicy(policy.http_policy_json) : defaultRoutePolicy();
	return {
		requestHeaders: mergeHeaderPolicies(sitePolicy.requestHeaders, routePolicy.requestHeaders),
		responseHeaders: mergeHeaderPolicies(sitePolicy.responseHeaders, routePolicy.responseHeaders),
		limits: {
			maxBodyBytes: routePolicy.limits.maxBodyBytes ?? sitePolicy.limits.maxBodyBytes,
			maxRequestTargetBytes: routePolicy.limits.maxRequestTargetBytes ?? sitePolicy.limits.maxRequestTargetBytes,
			maxHeaderBytes: routePolicy.limits.maxHeaderBytes ?? sitePolicy.limits.maxHeaderBytes,
		},
		cache: {
			mode: routePolicy.cache.mode === "inherit" ? sitePolicy.cache.mode : routePolicy.cache.mode,
			ttlSeconds: routePolicy.cache.ttlSeconds ?? sitePolicy.cache.ttlSeconds,
			maxObjectBytes: Math.min(routePolicy.cache.maxObjectBytes ?? sitePolicy.cache.maxObjectBytes, config.httpCache.maxObjectBytes, config.httpCache.maxBytes),
			extensions: routePolicy.cache.extensions ?? sitePolicy.cache.extensions,
		},
		protection: {
			mode: routePolicy.protection.mode === "inherit" ? sitePolicy.protection.mode : routePolicy.protection.mode,
			rulesetId: sitePolicy.protection.rulesetId,
			excludedRuleIds: [...new Set([...sitePolicy.protection.excludedRuleIds, ...routePolicy.protection.excludedRuleIds])],
		},
		banDurations: {
			low: routePolicy.banDurations.low ?? sitePolicy.banDurations.low,
			medium: routePolicy.banDurations.medium ?? sitePolicy.banDurations.medium,
			high: routePolicy.banDurations.high ?? sitePolicy.banDurations.high,
			critical: routePolicy.banDurations.critical ?? sitePolicy.banDurations.critical,
		},
		bandwidthLimit: {
			enabled: routePolicy.bandwidthLimit.enabled ?? sitePolicy.bandwidthLimit.enabled,
			maxBytes: routePolicy.bandwidthLimit.maxBytes ?? sitePolicy.bandwidthLimit.maxBytes,
			windowSeconds: routePolicy.bandwidthLimit.windowSeconds ?? sitePolicy.bandwidthLimit.windowSeconds,
			banSeconds: routePolicy.bandwidthLimit.banSeconds ?? sitePolicy.bandwidthLimit.banSeconds,
			scopeId: policy?.id ?? site.id,
		},
		bodyCapture: {
			mode: routePolicy.bodyCapture.mode === "inherit" ? sitePolicy.bodyCapture.mode : routePolicy.bodyCapture.mode,
			maxRequestBytes: Math.min(routePolicy.bodyCapture.maxRequestBytes ?? sitePolicy.bodyCapture.maxRequestBytes, bodyCaptureByteCeiling),
			maxResponseBytes: Math.min(routePolicy.bodyCapture.maxResponseBytes ?? sitePolicy.bodyCapture.maxResponseBytes, bodyCaptureByteCeiling),
			expiresAt: routePolicy.bodyCapture.expiresAt ?? sitePolicy.bodyCapture.expiresAt,
			contentTypes: routePolicy.bodyCapture.contentTypes ?? sitePolicy.bodyCapture.contentTypes,
		},
	};
}

export function isBodyCaptureActive(policy: SiteBodyCapturePolicy): boolean {
	return policy.mode === "enabled" && (policy.expiresAt === null || policy.expiresAt > Date.now());
}

export function applyHeaderPolicy(headers: Headers, policy: HeaderMutationPolicy): void {
	for (const name of policy.remove) headers.delete(name);
	for (const assignment of policy.set) headers.set(assignment.name, assignment.value);
}

function byteLength(value: string): number {
	return new TextEncoder().encode(value).byteLength;
}

export function requestLimitViolation(request: Request, limits: RequestLimits): RequestLimitViolation | null {
	const url = new URL(request.url);
	if (limits.maxRequestTargetBytes > 0 && byteLength(`${url.pathname}${url.search}`) > limits.maxRequestTargetBytes) {
		return { status: 414, code: "request_target_too_large", message: "The request target exceeds this route's configured limit." };
	}
	if (limits.maxHeaderBytes > 0) {
		let headerBytes = 2;
		for (const [name, value] of request.headers) headerBytes += byteLength(name) + 2 + byteLength(value) + 2;
		if (headerBytes > limits.maxHeaderBytes) {
			return { status: 431, code: "request_headers_too_large", message: "The request headers exceed this route's configured limit." };
		}
	}
	if (limits.maxBodyBytes > 0) {
		const contentLength = request.headers.get("content-length");
		if (contentLength && /^\d+$/u.test(contentLength) && Number(contentLength) > limits.maxBodyBytes) {
			return { status: 413, code: "request_body_too_large", message: "The request body exceeds this route's configured limit." };
		}
	}
	return null;
}

export function instanceStaticCacheDefaults(): SiteStaticCachePolicy & { maxEntries: number; maxBytes: number; instanceMaxObjectBytes: number } {
	return {
		...defaultSitePolicy().cache,
		maxEntries: config.httpCache.maxEntries,
		maxBytes: config.httpCache.maxBytes,
		instanceMaxObjectBytes: staticCacheObjectCeiling,
	};
}

export function instanceBodyCaptureDefaults(): SiteBodyCapturePolicy & { instanceMaxBytesCeiling: number } {
	return {
		...defaultSitePolicy().bodyCapture,
		instanceMaxBytesCeiling: bodyCaptureByteCeiling,
	};
}
