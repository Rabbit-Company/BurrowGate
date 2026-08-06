import { repository } from "../db/repository.ts";
import type {
	ChallengePolicyStep,
	RateLimitAlgorithm,
	RateLimitKeyMode,
	RateLimitScope,
	RouteAccessMode,
	RoutePolicyRecord,
	SiteAccessMode,
	SiteRecord,
} from "../types.ts";
import { randomId } from "../utils/crypto.ts";
import { parseChallengePolicy } from "./site-service.ts";
import {
	resolveWebSocketPolicy,
	routeWebSocketPolicyView,
	serializeRouteWebSocketPolicy,
	type ResolvedWebSocketPolicy,
	type RouteWebSocketPolicyView,
} from "./websocket-policy-service.ts";

const ALLOWED_METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);

const HTTP_TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u;

export interface RoutePolicyInput {
	name?: unknown;
	pathPattern?: unknown;
	methods?: unknown;
	accessMode?: unknown;
	challengePolicy?: unknown;
	rateLimitEnabled?: unknown;
	rateLimitAlgorithm?: unknown;
	rateLimitWindowMs?: unknown;
	rateLimitMax?: unknown;
	rateLimitRefillRate?: unknown;
	rateLimitRefillIntervalMs?: unknown;
	rateLimitPrecisionMs?: unknown;
	rateLimitKeyMode?: unknown;
	rateLimitKeyHeader?: unknown;
	rateLimitScope?: unknown;
	priority?: unknown;
	enabled?: unknown;
	websocket?: unknown;
}

export interface RoutePolicyView {
	id: string;
	siteId: string;
	name: string;
	pathPattern: string;
	methods: string[];
	accessMode: RouteAccessMode;
	challengePolicy: ChallengePolicyStep[] | null;
	rateLimit: {
		enabled: boolean;
		algorithm: RateLimitAlgorithm;
		windowMs: number;
		max: number;
		refillRate: number;
		refillIntervalMs: number;
		precisionMs: number;
		keyMode: RateLimitKeyMode;
		keyHeader: string | null;
		scope: RateLimitScope;
	};
	websocket: RouteWebSocketPolicyView;
	priority: number;
	enabled: boolean;
	createdAt: number;
	updatedAt: number;
}

export interface ResolvedRoutePolicy {
	policy: RoutePolicyRecord | null;
	accessMode: Exclude<RouteAccessMode, "inherit">;
	challengePolicy: ChallengePolicyStep[];
	websocket: ResolvedWebSocketPolicy;
}

function requiredString(value: unknown, label: string, maximum: number): string {
	const result = String(value ?? "").trim();
	if (!result) throw new Error(`${label} is required`);
	if (result.length > maximum) throw new Error(`${label} must be at most ${maximum} characters`);
	return result;
}

function booleanValue(value: unknown, fallback: boolean): boolean {
	if (value === undefined) return fallback;
	if (typeof value === "boolean") return value;
	if (value === 1 || value === "1" || value === "true") return true;
	if (value === 0 || value === "0" || value === "false") return false;
	throw new Error("Boolean value expected");
}

function integerValue(value: unknown, label: string, fallback: number, minimum: number, maximum: number): number {
	const number = value === undefined || value === "" ? fallback : Number(value);
	if (!Number.isInteger(number) || number < minimum || number > maximum) {
		throw new Error(`${label} must be an integer from ${minimum} to ${maximum}`);
	}
	return number;
}

function accessMode(value: unknown, fallback: RouteAccessMode): RouteAccessMode {
	const mode = value === undefined ? fallback : String(value).trim().toLowerCase();
	if (["inherit", "challenge", "bypass", "block"].includes(mode)) return mode as RouteAccessMode;
	throw new Error("Access mode must be inherit, challenge, bypass, or block");
}

function algorithm(value: unknown, fallback: RateLimitAlgorithm): RateLimitAlgorithm {
	const result = value === undefined ? fallback : String(value).trim().toLowerCase();
	if (["fixed-window", "sliding-window", "token-bucket"].includes(result)) return result as RateLimitAlgorithm;
	throw new Error("Rate-limit algorithm must be fixed-window, sliding-window, or token-bucket");
}

function keyMode(value: unknown, fallback: RateLimitKeyMode): RateLimitKeyMode {
	const result = value === undefined ? fallback : String(value).trim().toLowerCase();
	if (["ip", "session-or-ip", "header-or-ip"].includes(result)) return result as RateLimitKeyMode;
	throw new Error("Rate-limit key mode must be ip, session-or-ip, or header-or-ip");
}

function scope(value: unknown, fallback: RateLimitScope): RateLimitScope {
	const result = value === undefined ? fallback : String(value).trim().toLowerCase();
	if (["policy", "path", "method-path"].includes(result)) return result as RateLimitScope;
	throw new Error("Rate-limit scope must be policy, path, or method-path");
}

export function normalizePathPattern(value: unknown): string {
	const pattern = requiredString(value, "Path pattern", 2_048);
	if (!pattern.startsWith("/")) throw new Error("Path pattern must start with /");
	if (pattern.includes("?") || pattern.includes("#")) {
		throw new Error("Path pattern must not contain a query string or fragment");
	}
	if (/\s/u.test(pattern)) throw new Error("Path pattern must not contain whitespace");
	return pattern;
}

export function parseRouteMethods(value: unknown): string[] {
	if (value === undefined || value === null || value === "") return [];
	const raw = Array.isArray(value) ? value : String(value).split(",");
	const methods = [...new Set(raw.map((item) => String(item).trim().toUpperCase()).filter(Boolean))];
	if (methods.includes("*")) return [];
	for (const method of methods) {
		if (!ALLOWED_METHODS.has(method)) throw new Error(`Unsupported HTTP method: ${method}`);
	}
	return methods;
}

function parseStoredMethods(policy: RoutePolicyRecord): string[] {
	try {
		return parseRouteMethods(JSON.parse(policy.methods_json));
	} catch {
		return [];
	}
}

function optionalChallengePolicy(value: unknown, fallback: ChallengePolicyStep[] | null): ChallengePolicyStep[] | null {
	if (value === undefined) return fallback;
	if (value === null || value === "") return null;
	return parseChallengePolicy(value);
}

function headerName(value: unknown, mode: RateLimitKeyMode, fallback: string | null): string | null {
	const raw =
		value === undefined
			? fallback
			: String(value ?? "")
					.trim()
					.toLowerCase();
	if (mode !== "header-or-ip") return null;
	if (!raw) throw new Error("Header name is required when rate limiting by header");
	if (raw.length > 128 || !HTTP_TOKEN.test(raw)) throw new Error("Rate-limit header name is invalid");
	return raw;
}

function parseStoredPolicy(value: string | null): ChallengePolicyStep[] | null {
	if (!value) return null;
	return parseChallengePolicy(value);
}

export function routePolicyView(policy: RoutePolicyRecord): RoutePolicyView {
	return {
		id: policy.id,
		siteId: policy.site_id,
		name: policy.name,
		pathPattern: policy.path_pattern,
		methods: parseStoredMethods(policy),
		accessMode: policy.access_mode,
		challengePolicy: parseStoredPolicy(policy.challenge_policy_json),
		rateLimit: {
			enabled: policy.rate_limit_enabled === 1,
			algorithm: policy.rate_limit_algorithm,
			windowMs: Number(policy.rate_limit_window_ms),
			max: Number(policy.rate_limit_max),
			refillRate: Number(policy.rate_limit_refill_rate),
			refillIntervalMs: Number(policy.rate_limit_refill_interval_ms),
			precisionMs: Number(policy.rate_limit_precision_ms),
			keyMode: policy.rate_limit_key_mode,
			keyHeader: policy.rate_limit_key_header,
			scope: policy.rate_limit_scope,
		},
		websocket: routeWebSocketPolicyView(policy),
		priority: Number(policy.priority),
		enabled: policy.enabled === 1,
		createdAt: Number(policy.created_at),
		updatedAt: Number(policy.updated_at),
	};
}

function buildRecord(siteId: string, input: RoutePolicyInput, existing?: RoutePolicyRecord): RoutePolicyRecord {
	const now = Date.now();
	const selectedKeyMode = keyMode(input.rateLimitKeyMode, existing?.rate_limit_key_mode ?? "ip");
	const selectedAccessMode = accessMode(input.accessMode, existing?.access_mode ?? "inherit");
	const selectedChallengePolicy = optionalChallengePolicy(input.challengePolicy, existing ? parseStoredPolicy(existing.challenge_policy_json) : null);

	// Validate route-specific challenge configuration at write time even when
	// the route is currently set to another mode. This lets administrators
	// prepare a policy before enabling it without persisting malformed JSON.
	if (selectedAccessMode === "challenge" && selectedChallengePolicy === null) {
		// Null intentionally means inherit the site's challenge chain.
	}

	return {
		id: existing?.id ?? randomId("route"),
		site_id: siteId,
		name: requiredString(input.name ?? existing?.name, "Policy name", 255),
		path_pattern: normalizePathPattern(input.pathPattern ?? existing?.path_pattern),
		methods_json: JSON.stringify(parseRouteMethods(input.methods ?? (existing ? parseStoredMethods(existing) : []))),
		access_mode: selectedAccessMode,
		challenge_policy_json: selectedChallengePolicy ? JSON.stringify(selectedChallengePolicy) : null,
		rate_limit_enabled: booleanValue(input.rateLimitEnabled, existing?.rate_limit_enabled === 1) ? 1 : 0,
		rate_limit_algorithm: algorithm(input.rateLimitAlgorithm, existing?.rate_limit_algorithm ?? "sliding-window"),
		rate_limit_window_ms: integerValue(input.rateLimitWindowMs, "Rate-limit window", existing?.rate_limit_window_ms ?? 60_000, 100, 86_400_000),
		rate_limit_max: integerValue(input.rateLimitMax, "Rate-limit maximum", existing?.rate_limit_max ?? 120, 1, 1_000_000),
		rate_limit_refill_rate: integerValue(input.rateLimitRefillRate, "Token refill rate", existing?.rate_limit_refill_rate ?? 10, 1, 1_000_000),
		rate_limit_refill_interval_ms: integerValue(
			input.rateLimitRefillIntervalMs,
			"Token refill interval",
			existing?.rate_limit_refill_interval_ms ?? 1_000,
			10,
			86_400_000,
		),
		rate_limit_precision_ms: integerValue(input.rateLimitPrecisionMs, "Sliding-window precision", existing?.rate_limit_precision_ms ?? 100, 10, 60_000),
		rate_limit_key_mode: selectedKeyMode,
		rate_limit_key_header: headerName(input.rateLimitKeyHeader, selectedKeyMode, existing?.rate_limit_key_header ?? null),
		rate_limit_scope: scope(input.rateLimitScope, existing?.rate_limit_scope ?? "policy"),
		websocket_policy_json: serializeRouteWebSocketPolicy(input.websocket, existing?.websocket_policy_json),
		priority: integerValue(input.priority, "Priority", existing?.priority ?? 0, -100_000, 100_000),
		enabled: booleanValue(input.enabled, existing?.enabled === 1) ? 1 : 0,
		created_at: existing?.created_at ?? now,
		updated_at: now,
	};
}

export async function createRoutePolicy(siteId: string, input: RoutePolicyInput): Promise<RoutePolicyRecord> {
	if (!(await repository.siteById(siteId))) throw new Error("Site not found");
	const policy = buildRecord(siteId, input);
	await repository.insertRoutePolicy(policy);
	invalidateRoutePolicyCache(siteId);
	return policy;
}

export async function updateRoutePolicy(siteId: string, id: string, input: RoutePolicyInput): Promise<RoutePolicyRecord> {
	const existing = await repository.routePolicyById(id, siteId);
	if (!existing) throw new Error("Route policy not found");
	const policy = buildRecord(siteId, input, existing);
	await repository.updateRoutePolicy(policy);
	invalidateRoutePolicyCache(siteId);
	return policy;
}

export async function deleteRoutePolicy(siteId: string, id: string): Promise<void> {
	const existing = await repository.routePolicyById(id, siteId);
	if (!existing) throw new Error("Route policy not found");
	await repository.deleteRoutePolicy(id, siteId);
	invalidateRoutePolicyCache(siteId);
}

function escapeRegex(value: string): string {
	return value.replace(/[.+^${}()|[\]\\]/gu, "\\$&");
}

const matcherCache = new Map<string, RegExp>();
const routePolicyCache = new Map<string, { expiresAt: number; policies: RoutePolicyRecord[] }>();
const ROUTE_POLICY_CACHE_TTL_MS = 5_000;

export function invalidateRoutePolicyCache(siteId: string): void {
	routePolicyCache.delete(siteId);
}

export function invalidateDeletedSiteRoutePolicies(siteId: string, patterns: string[]): void {
	routePolicyCache.delete(siteId);
	for (const pattern of patterns) matcherCache.delete(pattern);
}

async function policiesForSite(siteId: string): Promise<RoutePolicyRecord[]> {
	const cached = routePolicyCache.get(siteId);
	if (cached && cached.expiresAt > Date.now()) return cached.policies;
	const policies = await repository.routePolicies(siteId);
	routePolicyCache.set(siteId, { expiresAt: Date.now() + ROUTE_POLICY_CACHE_TTL_MS, policies });
	return policies;
}

export function pathPatternMatches(pattern: string, pathname: string): boolean {
	let matcher = matcherCache.get(pattern);
	if (!matcher) {
		const doubleStar = "\u0000";
		const singleStar = "\u0001";
		let source: string;
		if (pattern.endsWith("/**")) {
			const base = pattern.slice(0, -3);
			source = `${escapeRegex(base).replaceAll("*", singleStar).replaceAll(singleStar, "[^/]*")}(?:/.*)?`;
		} else {
			source = escapeRegex(pattern).replaceAll("**", doubleStar).replaceAll("*", singleStar).replaceAll(doubleStar, ".*").replaceAll(singleStar, "[^/]*");
		}
		matcher = new RegExp(`^${source}$`, "u");
		matcherCache.set(pattern, matcher);
	}
	return matcher.test(pathname);
}

function specificity(policy: RoutePolicyRecord): number {
	const literal = policy.path_pattern.replaceAll("**", "").replaceAll("*", "").length;
	const methods = parseStoredMethods(policy);
	return literal * 100 + (methods.length ? 10 : 0) - (policy.path_pattern.includes("**") ? 2 : 0);
}

export function routePolicyMatches(policy: RoutePolicyRecord, method: string, pathname: string): boolean {
	if (policy.enabled !== 1) return false;
	const methods = parseStoredMethods(policy);
	if (methods.length > 0 && !methods.includes(method.toUpperCase())) return false;
	return pathPatternMatches(policy.path_pattern, pathname);
}

export async function matchingRoutePolicy(siteId: string, method: string, pathname: string): Promise<RoutePolicyRecord | null> {
	const matches = (await policiesForSite(siteId)).filter((policy) => routePolicyMatches(policy, method, pathname));
	matches.sort(
		(left, right) =>
			Number(right.priority) - Number(left.priority) || specificity(right) - specificity(left) || Number(left.created_at) - Number(right.created_at),
	);
	return matches[0] ?? null;
}

function siteChallengePolicy(site: SiteRecord): ChallengePolicyStep[] {
	return parseChallengePolicy(site.challenge_policy_json);
}

export async function resolveRoutePolicy(site: SiteRecord, method: string, pathname: string): Promise<ResolvedRoutePolicy> {
	const policy = await matchingRoutePolicy(site.id, method, pathname);
	const configuredMode = policy?.access_mode ?? "inherit";
	const accessMode = configuredMode === "inherit" ? (site.default_access_mode as SiteAccessMode) : configuredMode;
	return {
		policy,
		accessMode,
		challengePolicy: policy?.challenge_policy_json ? parseChallengePolicy(policy.challenge_policy_json) : siteChallengePolicy(site),
		websocket: resolveWebSocketPolicy(site, policy),
	};
}
