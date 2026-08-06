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

export interface SiteHttpPolicyView {
	requestHeaders: HeaderMutationPolicy;
	responseHeaders: HeaderMutationPolicy;
	limits: RequestLimits;
}

export interface RouteHttpPolicyView {
	requestHeaders: HeaderMutationPolicy;
	responseHeaders: HeaderMutationPolicy;
	limits: { [K in keyof RequestLimits]: number | null };
}

export interface ResolvedHttpPolicy extends SiteHttpPolicyView {}

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
});

const defaultRoutePolicy = (): StoredRoutePolicy => ({
	requestHeaders: { set: [], remove: [] },
	responseHeaders: { set: [], remove: [] },
	limits: { maxBodyBytes: null, maxRequestTargetBytes: null, maxHeaderBytes: null },
});

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
	if (direction === "response" && operation === "set" && protectedResponseSetHeaders.has(name)) {
		throw new Error(`Response header ${name} cannot be set by a header policy`);
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
	return JSON.stringify(
		parseSitePolicy({
			requestHeaders: "requestHeaders" in value ? value.requestHeaders : current.requestHeaders,
			responseHeaders: "responseHeaders" in value ? value.responseHeaders : current.responseHeaders,
			limits: { ...current.limits, ...suppliedLimits },
		}),
	);
}

export function serializeRouteHttpPolicy(input: unknown, existing?: string | null): string {
	if (input === undefined) return JSON.stringify(storedRoutePolicy(existing));
	if (input === null) return JSON.stringify(defaultRoutePolicy());
	const value = objectValue(input, "Route HTTP policy");
	const current = storedRoutePolicy(existing);
	const suppliedLimits = value.limits === undefined ? {} : objectValue(value.limits, "Route request limits");
	return JSON.stringify(
		parseRoutePolicy({
			requestHeaders: "requestHeaders" in value ? value.requestHeaders : current.requestHeaders,
			responseHeaders: "responseHeaders" in value ? value.responseHeaders : current.responseHeaders,
			limits: { ...current.limits, ...suppliedLimits },
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
	};
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
