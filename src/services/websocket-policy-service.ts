import { config } from "../config.ts";
import type { RoutePolicyRecord, RouteWebSocketMode, SiteRecord, SiteWebSocketMode } from "../types.ts";

export interface WebSocketTransportLimits {
	connectTimeoutMs: number;
	idleTimeoutSeconds: number;
	maxPayloadBytes: number;
	preOpenQueueBytes: number;
	upstreamBufferBytes: number;
}

export interface SiteWebSocketPolicyView extends WebSocketTransportLimits {
	mode: SiteWebSocketMode;
	available: boolean;
}

export interface RouteWebSocketPolicyView {
	mode: RouteWebSocketMode;
	connectTimeoutMs: number | null;
	idleTimeoutSeconds: number | null;
	maxPayloadBytes: number | null;
	preOpenQueueBytes: number | null;
	upstreamBufferBytes: number | null;
}

export interface ResolvedWebSocketPolicy extends WebSocketTransportLimits {
	mode: SiteWebSocketMode;
}

interface StoredSitePolicy extends Partial<WebSocketTransportLimits> {
	mode: SiteWebSocketMode;
}

interface StoredRoutePolicy extends Partial<WebSocketTransportLimits> {
	mode: RouteWebSocketMode;
}

const limitDefinitions = {
	connectTimeoutMs: { label: "WebSocket connect timeout", minimum: 1_000, maximum: config.websocket.connectTimeoutMs },
	idleTimeoutSeconds: { label: "WebSocket idle timeout", minimum: 10, maximum: config.websocket.idleTimeoutSeconds },
	maxPayloadBytes: { label: "WebSocket maximum payload", minimum: 1_024, maximum: config.websocket.maxPayloadBytes },
	preOpenQueueBytes: { label: "WebSocket pre-open queue", minimum: 1_024, maximum: config.websocket.preOpenQueueLimitBytes },
	upstreamBufferBytes: { label: "WebSocket upstream buffer", minimum: 1_024, maximum: config.websocket.upstreamBufferLimitBytes },
} as const;

function objectValue(value: unknown, label: string): Record<string, unknown> {
	if (value === null) return {};
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
	return value as Record<string, unknown>;
}

function siteMode(value: unknown, fallback: SiteWebSocketMode): SiteWebSocketMode {
	if (value === undefined) return fallback;
	const mode = String(value).trim().toLowerCase();
	if (mode === "allow" || mode === "deny") return mode;
	throw new Error("Site WebSocket mode must be allow or deny");
}

function routeMode(value: unknown, fallback: RouteWebSocketMode): RouteWebSocketMode {
	if (value === undefined) return fallback;
	const mode = String(value).trim().toLowerCase();
	if (mode === "inherit" || mode === "allow" || mode === "deny") return mode;
	throw new Error("Route WebSocket mode must be inherit, allow, or deny");
}

function limitValue<K extends keyof WebSocketTransportLimits>(key: K, value: unknown): number | undefined {
	if (value === undefined || value === null || value === "") return undefined;
	const definition = limitDefinitions[key];
	const result = Number(value);
	if (!Number.isInteger(result) || result < definition.minimum || result > definition.maximum) {
		throw new Error(`${definition.label} must be an integer from ${definition.minimum} to ${definition.maximum}`);
	}
	return result;
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

function storedSitePolicy(value: string | null | undefined): StoredSitePolicy {
	const parsed = parseJson(value);
	const result: StoredSitePolicy = { mode: parsed.mode === "deny" ? "deny" : "allow" };
	for (const key of Object.keys(limitDefinitions) as Array<keyof WebSocketTransportLimits>) {
		try {
			const limit = limitValue(key, parsed[key]);
			if (limit !== undefined) result[key] = limit;
		} catch {
			// Invalid legacy values inherit the safe instance default.
		}
	}
	return result;
}

function storedRoutePolicy(value: string | null | undefined): StoredRoutePolicy {
	const parsed = parseJson(value);
	const mode = parsed.mode;
	const result: StoredRoutePolicy = { mode: mode === "allow" || mode === "deny" ? mode : "inherit" };
	for (const key of Object.keys(limitDefinitions) as Array<keyof WebSocketTransportLimits>) {
		try {
			const limit = limitValue(key, parsed[key]);
			if (limit !== undefined) result[key] = limit;
		} catch {
			// Invalid legacy values inherit the parent policy.
		}
	}
	return result;
}

function mergeLimits<T extends StoredSitePolicy | StoredRoutePolicy>(current: T, input: Record<string, unknown>): T {
	const merged = { ...current };
	for (const key of Object.keys(limitDefinitions) as Array<keyof WebSocketTransportLimits>) {
		if (!(key in input)) continue;
		const limit = limitValue(key, input[key]);
		if (limit === undefined) delete merged[key];
		else merged[key] = limit;
	}
	return merged;
}

export function serializeSiteWebSocketPolicy(input: unknown, existing?: string | null): string {
	if (input === undefined) return JSON.stringify(storedSitePolicy(existing));
	const value = objectValue(input, "Site WebSocket settings");
	const current = input === null ? ({ mode: "allow" } as StoredSitePolicy) : storedSitePolicy(existing);
	const merged = mergeLimits(current, value);
	merged.mode = siteMode(value.mode, current.mode);
	return JSON.stringify(merged);
}

export function serializeRouteWebSocketPolicy(input: unknown, existing?: string | null): string {
	if (input === undefined) return JSON.stringify(storedRoutePolicy(existing));
	const value = objectValue(input, "Route WebSocket settings");
	const current = input === null ? ({ mode: "inherit" } as StoredRoutePolicy) : storedRoutePolicy(existing);
	const merged = mergeLimits(current, value);
	merged.mode = routeMode(value.mode, current.mode);
	return JSON.stringify(merged);
}

export function siteWebSocketPolicyView(site: SiteRecord): SiteWebSocketPolicyView {
	const stored = storedSitePolicy(site.websocket_policy_json);
	return {
		mode: stored.mode,
		available: config.websocket.enabled,
		connectTimeoutMs: stored.connectTimeoutMs ?? config.websocket.connectTimeoutMs,
		idleTimeoutSeconds: stored.idleTimeoutSeconds ?? config.websocket.idleTimeoutSeconds,
		maxPayloadBytes: stored.maxPayloadBytes ?? config.websocket.maxPayloadBytes,
		preOpenQueueBytes: stored.preOpenQueueBytes ?? config.websocket.preOpenQueueLimitBytes,
		upstreamBufferBytes: stored.upstreamBufferBytes ?? config.websocket.upstreamBufferLimitBytes,
	};
}

export function routeWebSocketPolicyView(policy: RoutePolicyRecord): RouteWebSocketPolicyView {
	const stored = storedRoutePolicy(policy.websocket_policy_json);
	return {
		mode: stored.mode,
		connectTimeoutMs: stored.connectTimeoutMs ?? null,
		idleTimeoutSeconds: stored.idleTimeoutSeconds ?? null,
		maxPayloadBytes: stored.maxPayloadBytes ?? null,
		preOpenQueueBytes: stored.preOpenQueueBytes ?? null,
		upstreamBufferBytes: stored.upstreamBufferBytes ?? null,
	};
}

export function resolveWebSocketPolicy(site: SiteRecord, policy?: RoutePolicyRecord | null): ResolvedWebSocketPolicy {
	const sitePolicy = siteWebSocketPolicyView(site);
	const routePolicy = policy ? storedRoutePolicy(policy.websocket_policy_json) : null;
	const configuredMode = routePolicy && routePolicy.mode !== "inherit" ? routePolicy.mode : sitePolicy.mode;
	return {
		mode: config.websocket.enabled ? configuredMode : "deny",
		connectTimeoutMs: routePolicy?.connectTimeoutMs ?? sitePolicy.connectTimeoutMs,
		idleTimeoutSeconds: routePolicy?.idleTimeoutSeconds ?? sitePolicy.idleTimeoutSeconds,
		maxPayloadBytes: routePolicy?.maxPayloadBytes ?? sitePolicy.maxPayloadBytes,
		preOpenQueueBytes: routePolicy?.preOpenQueueBytes ?? sitePolicy.preOpenQueueBytes,
		upstreamBufferBytes: routePolicy?.upstreamBufferBytes ?? sitePolicy.upstreamBufferBytes,
	};
}

export function instanceWebSocketDefaults(): SiteWebSocketPolicyView {
	return {
		mode: "allow",
		available: config.websocket.enabled,
		connectTimeoutMs: config.websocket.connectTimeoutMs,
		idleTimeoutSeconds: config.websocket.idleTimeoutSeconds,
		maxPayloadBytes: config.websocket.maxPayloadBytes,
		preOpenQueueBytes: config.websocket.preOpenQueueLimitBytes,
		upstreamBufferBytes: config.websocket.upstreamBufferLimitBytes,
	};
}
