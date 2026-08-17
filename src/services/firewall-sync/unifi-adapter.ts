import { config } from "../../config.ts";
import { parseCidr, splitCidrsByFamily } from "../../utils/ip.ts";
import { decryptSecret } from "../secret-encryption-service.ts";

export interface UnifiProviderConfig {
	controllerUrl: string;
	apiBasePath: string;
	site: string;
	listName: string;
	apiKeyEncrypted: string;
	verifyTls: boolean;
}

/**
 * API-key auth is only supported on UniFi OS consoles (UDM/Cloud Gateway/UniFi OS Server), which always front the
 * Network application behind this prefix - a blank value would hit the console's own web UI instead of the API.
 */
export function normalizeApiBasePath(value: unknown): string {
	return typeof value === "string" && value.trim() ? value.trim().replace(/\/+$/u, "") : "/proxy/network";
}

export function parseUnifiProviderConfig(value: unknown): UnifiProviderConfig {
	const raw = (value ?? {}) as Record<string, unknown>;
	return {
		controllerUrl: typeof raw.controllerUrl === "string" ? raw.controllerUrl.trim().replace(/\/+$/u, "") : "",
		apiBasePath: normalizeApiBasePath(raw.apiBasePath),
		// No "default" fallback: the Integration API is ID-scoped, so this must be the site UUID picked via "Load sites".
		site: typeof raw.site === "string" ? raw.site.trim() : "",
		listName: typeof raw.listName === "string" && raw.listName.trim() ? raw.listName.trim() : "BurrowGate-Banned-IPs",
		apiKeyEncrypted: typeof raw.apiKeyEncrypted === "string" ? raw.apiKeyEncrypted : "",
		verifyTls: raw.verifyTls !== false,
	};
}

interface RequestSpec {
	url: string;
	init: RequestInit & { tls?: { rejectUnauthorized: boolean } };
}

type TrafficMatchingListType = "IPV4_ADDRESSES" | "IPV6_ADDRESSES";

/**
 * `Create or update traffic matching list` in the UniFi OpenAPI spec (developer.ui.com) rejects an empty `items`
 * array (`minItems: 1`). These are RFC 5737 / RFC 3849 documentation-only ranges that can never be a real client
 * source, used as a stand-in so a fully-expired ban list can still be pushed as "effectively empty".
 */
const PLACEHOLDER_IPV4 = "192.0.2.255/32";
const PLACEHOLDER_IPV6 = "2001:db8::1/128";

function integrationApiUrl(cfg: Pick<UnifiProviderConfig, "controllerUrl" | "apiBasePath">, path: string): string {
	return `${cfg.controllerUrl}${cfg.apiBasePath}/integration${path}`;
}

function sitesUrl(cfg: Pick<UnifiProviderConfig, "controllerUrl" | "apiBasePath">): string {
	return integrationApiUrl(cfg, "/v1/sites");
}

function trafficMatchingListsUrl(cfg: UnifiProviderConfig, listId?: string): string {
	const base = integrationApiUrl(cfg, `/v1/sites/${encodeURIComponent(cfg.site)}/traffic-matching-lists`);
	return listId ? `${base}/${encodeURIComponent(listId)}` : base;
}

function baseInit(cfg: Pick<UnifiProviderConfig, "verifyTls">, apiKey: string): RequestSpec["init"] {
	return {
		headers: { "X-API-Key": apiKey, accept: "application/json" },
		tls: { rejectUnauthorized: cfg.verifyTls },
		signal: AbortSignal.timeout(config.firewallSync.requestTimeoutMs),
	};
}

/** Maps a bare IP or CIDR to the `IPv4/IPv6 matching` item shape - a full-width prefix becomes a single address match, anything narrower becomes a subnet match. */
export function buildTrafficMatchingListItem(cidr: string): { type: "IP_ADDRESS" | "SUBNET"; value: string } {
	const parsed = parseCidr(cidr);
	const isHostAddress = parsed !== null && parsed.prefix === parsed.bits;
	return isHostAddress ? { type: "IP_ADDRESS", value: cidr.split("/")[0]! } : { type: "SUBNET", value: cidr };
}

export function buildTrafficMatchingListItems(cidrs: string[], placeholder: string): Array<{ type: "IP_ADDRESS" | "SUBNET"; value: string }> {
	return (cidrs.length > 0 ? cidrs : [placeholder]).map(buildTrafficMatchingListItem);
}

export function unifiListTrafficMatchingListsRequest(cfg: UnifiProviderConfig, apiKey: string): RequestSpec {
	return { url: trafficMatchingListsUrl(cfg), init: baseInit(cfg, apiKey) };
}

export function unifiCreateTrafficMatchingListRequest(
	cfg: UnifiProviderConfig,
	apiKey: string,
	name: string,
	type: TrafficMatchingListType,
	items: Array<{ type: string; value: string }>,
): RequestSpec {
	return {
		url: trafficMatchingListsUrl(cfg),
		init: {
			...baseInit(cfg, apiKey),
			method: "POST",
			headers: { ...baseInit(cfg, apiKey).headers, "content-type": "application/json" },
			body: JSON.stringify({ name, type, items }),
		},
	};
}

export function unifiUpdateTrafficMatchingListRequest(
	cfg: UnifiProviderConfig,
	apiKey: string,
	listId: string,
	name: string,
	type: TrafficMatchingListType,
	items: Array<{ type: string; value: string }>,
): RequestSpec {
	return {
		url: trafficMatchingListsUrl(cfg, listId),
		init: {
			...baseInit(cfg, apiKey),
			method: "PUT",
			headers: { ...baseInit(cfg, apiKey).headers, "content-type": "application/json" },
			body: JSON.stringify({ name, type, items }),
		},
	};
}

export function unifiDeleteTrafficMatchingListRequest(cfg: UnifiProviderConfig, apiKey: string, listId: string): RequestSpec {
	return { url: trafficMatchingListsUrl(cfg, listId), init: { ...baseInit(cfg, apiKey), method: "DELETE" } };
}

/** Integration API list responses use a `{ offset, limit, count, totalCount, data: [...] }` envelope; tolerate a bare array too. */
export function parseUnifiListEnvelope(body: unknown): Array<Record<string, unknown>> {
	if (Array.isArray(body)) return body as Array<Record<string, unknown>>;
	const wrapped = body as { data?: unknown };
	if (Array.isArray(wrapped?.data)) return wrapped.data as Array<Record<string, unknown>>;
	return [];
}

export function unifiListSitesRequest(cfg: Pick<UnifiProviderConfig, "controllerUrl" | "apiBasePath" | "verifyTls">, apiKey: string): RequestSpec {
	return { url: sitesUrl(cfg), init: baseInit(cfg, apiKey) };
}

export interface UnifiSiteOption {
	id: string;
	name: string;
}

export function parseUnifiSitesResponse(body: unknown): UnifiSiteOption[] {
	return parseUnifiListEnvelope(body).map((row) => ({
		id: String(row.id ?? row._id ?? ""),
		name: String(row.name ?? row.desc ?? row.description ?? row.id ?? "unnamed"),
	}));
}

function looksLikeHtml(text: string): boolean {
	return /^\s*<(!doctype|html)/iu.test(text);
}

async function fetchJson(spec: RequestSpec): Promise<unknown> {
	const response = await fetch(spec.url, spec.init as RequestInit);
	const text = await response.text();
	if (looksLikeHtml(text)) {
		throw new Error(
			`Got the UniFi OS web UI instead of an API response (HTTP ${response.status}). Check the controller URL and API base path - it should almost always be "/proxy/network".`,
		);
	}
	if (!response.ok) throw new Error(`HTTP ${response.status}: ${text.slice(0, 300)}`);
	try {
		return text ? JSON.parse(text) : null;
	} catch {
		throw new Error(`Unexpected non-JSON response: ${text.slice(0, 300)}`);
	}
}

/** UniFi enforces name uniqueness across *all* traffic matching lists on a site regardless of type, so the IPv4 and IPv6 lists can't share a name. */
export function unifiTrafficMatchingListName(baseName: string, type: TrafficMatchingListType): string {
	return type === "IPV6_ADDRESSES" ? `${baseName} (IPv6)` : baseName;
}

async function findManagedList(cfg: UnifiProviderConfig, apiKey: string, name: string, type: TrafficMatchingListType): Promise<Record<string, unknown> | null> {
	const lists = parseUnifiListEnvelope(await fetchJson(unifiListTrafficMatchingListsRequest(cfg, apiKey)));
	return lists.find((list) => list.name === name && list.type === type) ?? null;
}

async function reconcileFamily(cfg: UnifiProviderConfig, apiKey: string, type: TrafficMatchingListType, cidrs: string[], placeholder: string): Promise<void> {
	const name = unifiTrafficMatchingListName(cfg.listName, type);
	const existing = await findManagedList(cfg, apiKey, name, type);
	const items = buildTrafficMatchingListItems(cidrs, placeholder);
	const spec = existing
		? unifiUpdateTrafficMatchingListRequest(cfg, apiKey, String(existing.id ?? ""), name, type, items)
		: unifiCreateTrafficMatchingListRequest(cfg, apiKey, name, type, items);
	await fetchJson(spec);
}

export async function unifiReconcile(configJson: string, cidrs: string[]): Promise<void> {
	const cfg = parseUnifiProviderConfig(JSON.parse(configJson));
	if (!cfg.controllerUrl) throw new Error("UniFi controller URL is not configured");
	if (!cfg.site) throw new Error("No UniFi site selected - use “Load sites” and pick one");
	if (!cfg.apiKeyEncrypted) throw new Error("UniFi API key is not configured");
	const apiKey = await decryptSecret(cfg.apiKeyEncrypted);
	const { v4, v6 } = splitCidrsByFamily(cidrs);
	await reconcileFamily(cfg, apiKey, "IPV4_ADDRESSES", v4, PLACEHOLDER_IPV4);
	await reconcileFamily(cfg, apiKey, "IPV6_ADDRESSES", v6, PLACEHOLDER_IPV6);
}

/** Deletes one family's managed list if it exists. Returns an error message on failure (e.g. still referenced by a Firewall Policy) instead of throwing, so the other family still gets a chance to clean up. */
async function deleteFamilyIfExists(cfg: UnifiProviderConfig, apiKey: string, type: TrafficMatchingListType): Promise<string | null> {
	const name = unifiTrafficMatchingListName(cfg.listName, type);
	const existing = await findManagedList(cfg, apiKey, name, type);
	if (!existing) return null;
	try {
		await fetchJson(unifiDeleteTrafficMatchingListRequest(cfg, apiKey, String(existing.id ?? "")));
		return null;
	} catch (error) {
		return error instanceof Error ? error.message : String(error);
	}
}

/**
 * Best-effort: removes the managed IPv4/IPv6 Traffic Matching Lists. If a list is still referenced by a
 * Firewall Policy the user created, UniFi will refuse the delete - that's surfaced as an error (so the admin UI
 * can warn "remove the policy first"), but callers should still remove the local provider row regardless.
 */
export async function unifiTeardown(configJson: string): Promise<void> {
	const cfg = parseUnifiProviderConfig(JSON.parse(configJson));
	if (!cfg.controllerUrl || !cfg.site || !cfg.apiKeyEncrypted) return;
	const apiKey = await decryptSecret(cfg.apiKeyEncrypted);
	const errors = (await Promise.all([deleteFamilyIfExists(cfg, apiKey, "IPV4_ADDRESSES"), deleteFamilyIfExists(cfg, apiKey, "IPV6_ADDRESSES")])).filter(
		(error): error is string => error !== null,
	);
	if (errors.length > 0) throw new Error(errors.join("; "));
}

export interface UnifiListSitesInput {
	controllerUrl: string;
	apiBasePath: string;
	verifyTls: boolean;
	apiKey?: string;
	existingConfigJson?: string | null;
}

/** Used by the admin UI's "Load sites" button - works against unsaved form values, falling back to the stored key when the field was left blank while editing. */
export async function unifiListSites(input: UnifiListSitesInput): Promise<UnifiSiteOption[]> {
	const cfg = {
		controllerUrl: input.controllerUrl.trim().replace(/\/+$/u, ""),
		apiBasePath: normalizeApiBasePath(input.apiBasePath),
		verifyTls: input.verifyTls,
	};
	if (!cfg.controllerUrl) throw new Error("Controller URL is required");
	let apiKey = input.apiKey?.trim() ?? "";
	if (!apiKey) {
		const existing = input.existingConfigJson ? parseUnifiProviderConfig(JSON.parse(input.existingConfigJson)) : null;
		if (!existing?.apiKeyEncrypted) throw new Error("API key is required");
		apiKey = await decryptSecret(existing.apiKeyEncrypted);
	}
	const sites = parseUnifiSitesResponse(await fetchJson(unifiListSitesRequest(cfg, apiKey)));
	if (sites.length === 0) throw new Error("Connected, but no sites were returned");
	return sites;
}

export async function unifiTestConnection(configJson: string): Promise<{ ok: boolean; message: string }> {
	const cfg = parseUnifiProviderConfig(JSON.parse(configJson));
	if (!cfg.controllerUrl) return { ok: false, message: "Controller URL is required" };
	if (!cfg.site) return { ok: false, message: "No UniFi site selected - use “Load sites” and pick one" };
	if (!cfg.apiKeyEncrypted) return { ok: false, message: "API key is required" };
	try {
		const apiKey = await decryptSecret(cfg.apiKeyEncrypted);
		const existingV4 = await findManagedList(cfg, apiKey, unifiTrafficMatchingListName(cfg.listName, "IPV4_ADDRESSES"), "IPV4_ADDRESSES");
		return {
			ok: true,
			message: existingV4
				? `Connected. Managed list '${cfg.listName}' found. Point a Firewall Policy's source IP filter at it (Traffic Matching List).`
				: `Connected. List '${cfg.listName}' will be created on first sync - then point a Firewall Policy's source IP filter at it (Traffic Matching List).`,
		};
	} catch (error) {
		return { ok: false, message: error instanceof Error ? error.message : String(error) };
	}
}
