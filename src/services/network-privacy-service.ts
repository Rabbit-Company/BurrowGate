import { mkdir, readFile, readdir, rename, stat, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { config } from "../config.ts";
import { Logger } from "../logger.ts";
import type { RoutePolicyRecord, SiteRecord } from "../types.ts";
import { parseIp } from "../utils/ip.ts";

export type NetworkPrivacyMode = "disabled" | "monitor" | "block";
export type NetworkPrivacyPolicy = Record<string, NetworkPrivacyMode>;

export interface NetworkPrivacyCategoryMeta {
	id: string;
	label: string;
	description: string;
}

export interface NetworkPrivacyIdentity {
	categories: string[];
}

export interface NetworkPrivacyEvaluation {
	identity: NetworkPrivacyIdentity | null;
	blockedCategory: string | null;
}

export interface NetworkPrivacyData {
	tor: Set<string>;
	asn: Map<string, Set<number>>;
}

const CATEGORY_ID_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const CATEGORY_FILE_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*\.txt$/u;

const TOR_CATEGORY: NetworkPrivacyCategoryMeta = {
	id: "tor",
	label: "Tor exit node",
	description: "Published Tor exit relay addresses.",
};

const TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist";
const ASN_LISTS_BASE_URL = "https://cdn.rabbit-company.com/burrowgate/asn-lists";
const ASN_LISTS_MANIFEST_URL = `${ASN_LISTS_BASE_URL}/manifest.json`;
const REFRESH_INTERVAL_MS = 24 * 60 * 60 * 1_000;
const CACHE_DIRECTORY = join(config.dataDirectory, "network-privacy");
const TOR_CACHE_PATH = join(CACHE_DIRECTORY, "tor-exit-nodes.txt");
const MANIFEST_CACHE_PATH = join(CACHE_DIRECTORY, "manifest.json");
const ASN_CACHE_PREFIX = "asn-";

let torExitNodes = new Set<string>();
let asnData = new Map<string, Set<number>>();
let asnCategories: NetworkPrivacyCategoryMeta[] = [];
let refreshTimer: ReturnType<typeof setInterval> | null = null;

function ipKey(ip: string): string | null {
	const parsed = parseIp(ip);
	return parsed ? `${parsed.version}:${parsed.value.toString(16)}` : null;
}

export function parseTorExitList(body: string): Set<string> {
	const result = new Set<string>();
	for (const line of body.split(/\r?\n/u)) {
		const key = ipKey(line.trim());
		if (key) result.add(key);
	}
	return result;
}

export function parseAsnList(body: string): Set<number> {
	const result = new Set<number>();
	for (const line of body.split(/\r?\n/u)) {
		const match = /^(\d+)\s+\S.*$/u.exec(line.trim());
		if (!match) continue;
		const asn = Number(match[1]);
		if (!Number.isSafeInteger(asn) || asn <= 0) continue;
		result.add(asn);
	}
	return result;
}

export interface AsnListManifestCategory {
	id: string;
	label: string;
	description: string;
	file: string;
}

export interface AsnListManifest {
	generatedAt: string | null;
	categories: AsnListManifestCategory[];
}

export function mergeAsnListCategories(remote: AsnListManifestCategory[], cached: AsnListManifestCategory[]): AsnListManifestCategory[] {
	const remoteIds = new Set(remote.map((category) => category.id));
	return [...remote, ...cached.filter((category) => !remoteIds.has(category.id))];
}

function parseAsnListManifest(body: string): AsnListManifest {
	const parsed = JSON.parse(body) as unknown;
	if (!parsed || typeof parsed !== "object" || !Array.isArray((parsed as { categories?: unknown }).categories)) {
		throw new Error("manifest.json is missing a categories array");
	}
	const categories: AsnListManifestCategory[] = [];
	for (const entry of (parsed as { categories: unknown[] }).categories) {
		if (!entry || typeof entry !== "object") continue;
		const { id, label, description, file } = entry as Record<string, unknown>;
		if (typeof id !== "string" || !CATEGORY_ID_PATTERN.test(id)) {
			Logger.warn(`Network privacy: ignoring ASN list category with an invalid ID`, { id });
			continue;
		}
		if (typeof file !== "string" || !CATEGORY_FILE_PATTERN.test(file)) {
			Logger.warn(`Network privacy: ignoring ASN list category "${id}" with an invalid file reference`, { file });
			continue;
		}
		categories.push({
			id,
			label: typeof label === "string" && label ? label : id,
			description: typeof description === "string" ? description : "",
			file,
		});
	}
	if (!categories.length) throw new Error("manifest.json contained no usable categories");
	const generatedAt = (parsed as { generatedAt?: unknown }).generatedAt;
	return { generatedAt: typeof generatedAt === "string" ? generatedAt : null, categories };
}

function mode(value: unknown, fallback: NetworkPrivacyMode): NetworkPrivacyMode {
	if (value === undefined) return fallback;
	const normalized = String(value).trim().toLowerCase();
	if (normalized === "disabled" || normalized === "monitor" || normalized === "block") return normalized;
	throw new Error("Network privacy mode must be disabled, monitor, or block");
}

export function parseNetworkPrivacyPolicy(value: unknown, fallback: NetworkPrivacyPolicy = {}): NetworkPrivacyPolicy {
	if (value === undefined) return { ...fallback };
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Network privacy policy must be an object");
	const input = value as Record<string, unknown>;
	const result: NetworkPrivacyPolicy = {};
	for (const key of new Set([...Object.keys(fallback), ...Object.keys(input)])) {
		if (key !== "tor" && !CATEGORY_ID_PATTERN.test(key)) continue;
		result[key] = mode(input[key], fallback[key] ?? "disabled");
	}
	return result;
}

export function storedNetworkPrivacyPolicy(json: string | null | undefined, fallback: NetworkPrivacyPolicy = {}): NetworkPrivacyPolicy {
	if (!json) return { ...fallback };
	try {
		return parseNetworkPrivacyPolicy(JSON.parse(json), fallback);
	} catch {
		return { ...fallback };
	}
}

export function serializeNetworkPrivacyPolicy(value: unknown, fallback?: string | null): string {
	return JSON.stringify(parseNetworkPrivacyPolicy(value, storedNetworkPrivacyPolicy(fallback)));
}

export function serializeRouteNetworkPrivacyPolicy(value: unknown, fallback?: string | null): string | null {
	if (value === undefined) return fallback ?? null;
	if (value === null || value === "") return null;
	return JSON.stringify(parseNetworkPrivacyPolicy(value));
}

export function resolvedNetworkPrivacyPolicy(site: SiteRecord, route: RoutePolicyRecord | null): NetworkPrivacyPolicy {
	return route?.network_privacy_policy_json
		? storedNetworkPrivacyPolicy(route.network_privacy_policy_json)
		: storedNetworkPrivacyPolicy(site.network_privacy_policy_json);
}

function currentData(): NetworkPrivacyData {
	return { tor: torExitNodes, asn: asnData };
}

export function identifyNetworkPrivacy(
	ip: string,
	asn: number | null,
	policy: NetworkPrivacyPolicy,
	data: NetworkPrivacyData = currentData(),
): NetworkPrivacyIdentity | null {
	const categories: string[] = [];
	if ((policy.tor ?? "disabled") !== "disabled") {
		const key = ipKey(ip);
		if (key && data.tor.has(key)) categories.push("tor");
	}
	if (asn !== null) {
		for (const [categoryId, asns] of data.asn) {
			if ((policy[categoryId] ?? "disabled") === "disabled") continue;
			if (asns.has(asn)) categories.push(categoryId);
		}
	}
	return categories.length ? { categories } : null;
}

export function blockedNetworkPrivacyCategory(identity: NetworkPrivacyIdentity | null, policy: NetworkPrivacyPolicy): string | null {
	return identity?.categories.find((category) => policy[category] === "block") ?? null;
}

export function networkPrivacyBlockIsBypassed(source: string, action: string | null): boolean {
	return ["ip-rule", "asn-rule"].includes(source) && (action === "allow" || action === "pass");
}

export function evaluateNetworkPrivacy(
	ip: string,
	asn: number | null,
	policy: NetworkPrivacyPolicy,
	source: string,
	action: string | null,
	data?: NetworkPrivacyData,
): NetworkPrivacyEvaluation {
	const identity = identifyNetworkPrivacy(ip, asn, policy, data);
	return {
		identity,
		blockedCategory: networkPrivacyBlockIsBypassed(source, action) ? null : blockedNetworkPrivacyCategory(identity, policy),
	};
}

export function networkPrivacyCategoryCatalog(): NetworkPrivacyCategoryMeta[] {
	return [TOR_CATEGORY, ...asnCategories];
}

export function networkPrivacyCategoryLabel(category: string): string {
	if (category === "tor") return TOR_CATEGORY.label;
	return asnCategories.find((entry) => entry.id === category)?.label ?? category;
}

async function atomicWrite(path: string, body: string): Promise<void> {
	await mkdir(CACHE_DIRECTORY, { recursive: true, mode: 0o700 });
	const temporaryPath = `${path}.${process.pid}.tmp`;
	await writeFile(temporaryPath, body, { encoding: "utf8", mode: 0o600 });
	await rename(temporaryPath, path);
}

function asnCachePath(categoryId: string): string {
	return join(CACHE_DIRECTORY, `${ASN_CACHE_PREFIX}${categoryId}.txt`);
}

async function loadCachedLists(): Promise<void> {
	try {
		const cached = await readFile(TOR_CACHE_PATH, "utf8");
		const parsed = parseTorExitList(cached);
		if (parsed.size) torExitNodes = parsed;
	} catch {}

	let manifest: AsnListManifest;
	try {
		manifest = parseAsnListManifest(await readFile(MANIFEST_CACHE_PATH, "utf8"));
	} catch {
		return;
	}
	asnCategories = manifest.categories.map(({ id, label, description }) => ({ id, label, description }));

	const loaded = new Map<string, Set<number>>();
	for (const category of manifest.categories) {
		try {
			const cached = await readFile(asnCachePath(category.id), "utf8");
			const parsed = parseAsnList(cached);
			if (parsed.size) loaded.set(category.id, parsed);
		} catch {}
	}
	if (loaded.size) asnData = loaded;
}

async function fetchText(url: string): Promise<string> {
	const response = await fetch(url, { headers: { accept: "text/plain,application/json" }, signal: AbortSignal.timeout(15_000) });
	if (!response.ok) throw new Error(`HTTP ${response.status}`);
	return await response.text();
}

/** Milliseconds since `path` was last written, or null if it doesn't exist. */
async function fileAge(path: string): Promise<number | null> {
	try {
		return Date.now() - (await stat(path)).mtimeMs;
	} catch {
		return null;
	}
}

async function refreshTorExitNodes(): Promise<void> {
	const age = await fileAge(TOR_CACHE_PATH);
	if (age !== null && age < REFRESH_INTERVAL_MS && torExitNodes.size) return;
	const body = await fetchText(TOR_EXIT_LIST_URL);
	const parsed = parseTorExitList(body);
	if (!parsed.size) throw new Error("Tor exit list contained no valid IP addresses");
	torExitNodes = parsed;
	await atomicWrite(TOR_CACHE_PATH, body);
	Logger.info(`Network privacy: loaded ${parsed.size} Tor exit nodes`);
}

async function pruneStaleAsnCacheFiles(keep: Set<string>): Promise<void> {
	let entries: string[] = [];
	try {
		entries = await readdir(CACHE_DIRECTORY);
	} catch {
		return;
	}
	for (const entry of entries) {
		if (!entry.startsWith(ASN_CACHE_PREFIX) || !entry.endsWith(".txt")) continue;
		const categoryId = entry.slice(ASN_CACHE_PREFIX.length, -".txt".length);
		if (keep.has(categoryId)) continue;
		await unlink(join(CACHE_DIRECTORY, entry)).catch(() => {});
	}
}

async function readCachedManifest(): Promise<AsnListManifest | null> {
	try {
		return parseAsnListManifest(await readFile(MANIFEST_CACHE_PATH, "utf8"));
	} catch {
		return null;
	}
}

async function loadAsnCategoryFromDisk(categoryId: string): Promise<Set<number> | null> {
	try {
		const parsed = parseAsnList(await readFile(asnCachePath(categoryId), "utf8"));
		return parsed.size ? parsed : null;
	} catch {
		return null;
	}
}

async function refreshAsnLists(): Promise<void> {
	const age = await fileAge(MANIFEST_CACHE_PATH);
	if (age !== null && age < REFRESH_INTERVAL_MS && asnData.size) return;

	const manifestBody = await fetchText(ASN_LISTS_MANIFEST_URL);
	const remote = parseAsnListManifest(manifestBody);
	const remoteIds = new Set(remote.categories.map((category) => category.id));

	const cached = await readCachedManifest();
	const merged = mergeAsnListCategories(remote.categories, cached?.categories ?? []);
	const localOnly = merged.filter((category) => !remoteIds.has(category.id));
	const unchanged = remote.generatedAt !== null && remote.generatedAt === cached?.generatedAt;

	await atomicWrite(MANIFEST_CACHE_PATH, JSON.stringify({ generatedAt: remote.generatedAt, categories: merged }, null, 2) + "\n");
	asnCategories = merged.map(({ id, label, description }) => ({ id, label, description }));

	const remoteResults: (readonly [string, Set<number>])[] = unchanged
		? remote.categories.map((category) => [category.id, asnData.get(category.id) ?? new Set<number>()] as const)
		: await Promise.all(
				remote.categories.map(async (category) => {
					try {
						const body = await fetchText(`${ASN_LISTS_BASE_URL}/${category.file}`);
						const parsed = parseAsnList(body);
						await atomicWrite(asnCachePath(category.id), body);
						return [category.id, parsed] as const;
					} catch (error) {
						Logger.warn(`Network privacy: failed to refresh the "${category.id}" ASN list; keeping the previous list`, { error });
						return [category.id, asnData.get(category.id) ?? new Set<number>()] as const;
					}
				}),
			);

	const localResults = await Promise.all(
		localOnly.map(async (category) => [category.id, (await loadAsnCategoryFromDisk(category.id)) ?? asnData.get(category.id) ?? new Set<number>()] as const),
	);

	asnData = new Map([...remoteResults, ...localResults]);
	await pruneStaleAsnCacheFiles(new Set(merged.map((category) => category.id)));
	Logger.info(
		unchanged
			? `Network privacy: ASN list manifest unchanged since the last refresh; keeping the cached category lists${localOnly.length ? ` (${localOnly.length} local-only)` : ""}`
			: `Network privacy: loaded ${remote.categories.length} ASN categories from the CDN (${[...asnData.values()].reduce((sum, set) => sum + set.size, 0)} ASNs total${localOnly.length ? `, plus ${localOnly.length} local-only` : ""})`,
	);
}

export async function refreshNetworkPrivacyData(): Promise<void> {
	await Promise.all([
		refreshTorExitNodes().catch((error) => Logger.warn("Network privacy: failed to refresh Tor exit nodes; keeping the previous list", { error })),
		refreshAsnLists().catch((error) => Logger.warn("Network privacy: failed to refresh ASN list manifest; keeping the previous lists", { error })),
	]);
}

export async function startNetworkPrivacyRefresh(): Promise<void> {
	await loadCachedLists();
	void refreshNetworkPrivacyData();
	if (refreshTimer) return;
	refreshTimer = setInterval(() => void refreshNetworkPrivacyData(), REFRESH_INTERVAL_MS);
	refreshTimer.unref?.();
}
