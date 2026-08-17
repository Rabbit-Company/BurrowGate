import { config } from "../config.ts";
import { repository } from "../db/repository.ts";
import { Logger } from "../logger.ts";
import type { FirewallSyncProviderRecord, FirewallSyncProviderType, FirewallSyncStatus, FirewallSyncWhitelistCidrRecord } from "../types.ts";
import { randomId, sha256Hex } from "../utils/crypto.ts";
import { isPrivateIp, parseCidr, type ParsedCidr } from "../utils/ip.ts";
import { encryptSecret } from "./secret-encryption-service.ts";
import { nftablesReconcile, nftablesTeardown, nftablesTestConnection, parseNftablesProviderConfig } from "./firewall-sync/nftables-adapter.ts";
import { parseUnifiProviderConfig, unifiReconcile, unifiTeardown, unifiTestConnection } from "./firewall-sync/unifi-adapter.ts";

export function dedupeCidrsByRecency(rows: Array<{ network_cidr: string; created_at: number }>): string[] {
	const seen = new Set<string>();
	const result: string[] = [];
	for (const row of [...rows].sort((a, b) => b.created_at - a.created_at)) {
		if (seen.has(row.network_cidr)) continue;
		seen.add(row.network_cidr);
		result.push(row.network_cidr);
	}
	return result;
}

/** Is `candidate` entirely contained within (or equal to) `container`? Same masking logic as cidrContains, generalized to CIDR-vs-CIDR. */
function cidrWithin(candidate: ParsedCidr, container: ParsedCidr): boolean {
	if (candidate.version !== container.version) return false;
	if (container.prefix > candidate.prefix) return false;
	const shift = BigInt(candidate.bits - container.prefix);
	const maskedCandidateNetwork = shift === 0n ? candidate.network : (candidate.network >> shift) << shift;
	return maskedCandidateNetwork === container.network;
}

export interface FilterBannableCidrsResult {
	bannable: string[];
	excludedPrivateCount: number;
	excludedWhitelistedCount: number;
}

/** Never-ban filtering (see the "Never-ban whitelist" design note): private/loopback ranges are always excluded, on top of the admin-managed whitelist. */
export function filterBannableCidrsDetailed(cidrs: string[], whitelist: FirewallSyncWhitelistCidrRecord[]): FilterBannableCidrsResult {
	const whitelistCidrs = whitelist.map((entry) => parseCidr(entry.network_cidr)).filter((parsed): parsed is ParsedCidr => parsed !== null);
	const bannable: string[] = [];
	let excludedPrivateCount = 0;
	let excludedWhitelistedCount = 0;
	for (const cidr of cidrs) {
		const [address] = cidr.split("/");
		if (address && isPrivateIp(address)) {
			excludedPrivateCount += 1;
			continue;
		}
		const parsed = parseCidr(cidr);
		if (!parsed) continue;
		if (whitelistCidrs.some((whitelistCidr) => cidrWithin(parsed, whitelistCidr))) {
			excludedWhitelistedCount += 1;
			continue;
		}
		bannable.push(cidr);
	}
	return { bannable, excludedPrivateCount, excludedWhitelistedCount };
}

export function filterBannableCidrs(cidrs: string[], whitelist: FirewallSyncWhitelistCidrRecord[]): string[] {
	return filterBannableCidrsDetailed(cidrs, whitelist).bannable;
}

export async function aggregateBannedCidrs(now = Date.now()): Promise<string[]> {
	const [rows, whitelist] = await Promise.all([repository.activeBannedCidrRows(now), repository.allFirewallSyncWhitelistCidrs()]);
	return filterBannableCidrs(dedupeCidrsByRecency(rows), whitelist);
}

export interface AggregateBannedCidrsDetail extends FilterBannableCidrsResult {
	totalActiveCount: number;
}

/** Used by the admin preview so exclusions (private-range, whitelisted) are visible instead of just silently missing. */
export async function aggregateBannedCidrsDetailed(now = Date.now()): Promise<AggregateBannedCidrsDetail> {
	const [rows, whitelist] = await Promise.all([repository.activeBannedCidrRows(now), repository.allFirewallSyncWhitelistCidrs()]);
	const deduped = dedupeCidrsByRecency(rows);
	const detail = filterBannableCidrsDetailed(deduped, whitelist);
	return { ...detail, totalActiveCount: deduped.length };
}

export interface FirewallSyncAdapter {
	reconcile(configJson: string, cidrs: string[]): Promise<void>;
	testConnection(configJson: string): Promise<{ ok: boolean; message: string }>;
	/** Best-effort remote cleanup (e.g. drop the nftables table, delete the UniFi traffic matching lists) run when a provider is deleted. */
	teardown(configJson: string): Promise<void>;
}

const defaultAdapters: Record<FirewallSyncProviderType, FirewallSyncAdapter> = {
	unifi: { reconcile: unifiReconcile, testConnection: unifiTestConnection, teardown: unifiTeardown },
	nftables: { reconcile: nftablesReconcile, testConnection: nftablesTestConnection, teardown: nftablesTeardown },
};

export interface FirewallSyncProviderView {
	id: string;
	name: string;
	type: FirewallSyncProviderType;
	enabled: boolean;
	maxEntries: number;
	acknowledgedNoWhitelist: boolean;
	config: Record<string, unknown>;
	lastCheckedAt: number | null;
	lastSyncedAt: number | null;
	lastSyncStatus: FirewallSyncStatus | null;
	lastSyncError: string | null;
	lastAppliedCount: number;
}

function redactConfig(type: FirewallSyncProviderType, configJson: string): Record<string, unknown> {
	const parsed = JSON.parse(configJson) as Record<string, unknown>;
	if (type === "unifi") {
		const { apiKeyEncrypted, ...rest } = parsed;
		return { ...rest, apiKeyConfigured: typeof apiKeyEncrypted === "string" && apiKeyEncrypted.length > 0 };
	}
	return parsed;
}

export function firewallSyncProviderView(record: FirewallSyncProviderRecord): FirewallSyncProviderView {
	return {
		id: record.id,
		name: record.name,
		type: record.type,
		enabled: record.enabled === 1,
		maxEntries: record.max_entries,
		acknowledgedNoWhitelist: record.acknowledged_no_whitelist === 1,
		config: redactConfig(record.type, record.config_json),
		lastCheckedAt: record.last_checked_at,
		lastSyncedAt: record.last_synced_at,
		lastSyncStatus: record.last_sync_status,
		lastSyncError: record.last_sync_error,
		lastAppliedCount: record.last_applied_count,
	};
}

export interface FirewallSyncProviderInput {
	name?: unknown;
	type?: unknown;
	enabled?: unknown;
	maxEntries?: unknown;
	acknowledgedNoWhitelist?: unknown;
	config?: unknown;
}

function booleanValue(value: unknown, fallback: boolean): boolean {
	if (value === undefined) return fallback;
	if (typeof value === "boolean") return value;
	if (value === 1 || value === "1" || value === "true") return true;
	if (value === 0 || value === "0" || value === "false") return false;
	throw new Error("Boolean value expected");
}

async function buildConfigJson(type: FirewallSyncProviderType, input: unknown, existingConfigJson: string | null): Promise<string> {
	const raw = (input ?? {}) as Record<string, unknown>;
	if (type === "unifi") {
		const existing = existingConfigJson ? parseUnifiProviderConfig(JSON.parse(existingConfigJson)) : null;
		const apiKeyInput = typeof raw.apiKey === "string" ? raw.apiKey.trim() : "";
		const apiKeyEncrypted = apiKeyInput ? await encryptSecret(apiKeyInput) : (existing?.apiKeyEncrypted ?? "");
		const parsed = parseUnifiProviderConfig({ ...existing, ...raw, apiKeyEncrypted });
		if (!parsed.controllerUrl) throw new Error("Controller URL is required");
		return JSON.stringify(parsed);
	}
	const existing = existingConfigJson ? parseNftablesProviderConfig(JSON.parse(existingConfigJson)) : null;
	return JSON.stringify(parseNftablesProviderConfig({ ...existing, ...raw }));
}

function defaultMaxEntries(type: FirewallSyncProviderType): number {
	return type === "unifi" ? config.firewallSync.defaultUnifiMaxEntries : config.firewallSync.defaultNftablesMaxEntries;
}

export async function createFirewallSyncProvider(input: FirewallSyncProviderInput): Promise<FirewallSyncProviderRecord> {
	const type = input.type as FirewallSyncProviderType;
	if (type !== "unifi" && type !== "nftables") throw new Error("Unsupported provider type");
	const name = String(input.name ?? "").trim();
	if (!name) throw new Error("Name is required");
	const now = Date.now();
	const record: FirewallSyncProviderRecord = {
		id: randomId("firewall_sync_provider"),
		name,
		type,
		enabled: booleanValue(input.enabled, false) ? 1 : 0,
		max_entries: Number.isInteger(input.maxEntries) ? Number(input.maxEntries) : defaultMaxEntries(type),
		config_json: await buildConfigJson(type, input.config, null),
		acknowledged_no_whitelist: booleanValue(input.acknowledgedNoWhitelist, false) ? 1 : 0,
		last_checked_at: null,
		last_synced_at: null,
		last_sync_status: null,
		last_sync_error: null,
		last_applied_count: 0,
		last_applied_hash: null,
		created_at: now,
		updated_at: now,
	};
	await repository.insertFirewallSyncProvider(record);
	return record;
}

export async function updateFirewallSyncProvider(id: string, input: FirewallSyncProviderInput): Promise<FirewallSyncProviderRecord> {
	const existing = await repository.firewallSyncProviderById(id);
	if (!existing) throw new Error("Provider not found");
	const name = input.name === undefined ? existing.name : String(input.name ?? "").trim();
	if (!name) throw new Error("Name is required");
	const enabled = booleanValue(input.enabled, existing.enabled === 1);
	const acknowledgedNoWhitelist = booleanValue(input.acknowledgedNoWhitelist, existing.acknowledged_no_whitelist === 1);
	if (enabled && !acknowledgedNoWhitelist) {
		const whitelist = await repository.allFirewallSyncWhitelistCidrs();
		if (whitelist.length === 0) throw new Error("Add at least one whitelist IP, or explicitly acknowledge the risk, before enabling a provider");
	}
	const maxEntries = Number.isInteger(input.maxEntries) ? Number(input.maxEntries) : existing.max_entries;
	const configJson = input.config === undefined ? existing.config_json : await buildConfigJson(existing.type, input.config, existing.config_json);
	await repository.updateFirewallSyncProviderConfig(id, name, enabled ? 1 : 0, maxEntries, configJson, acknowledgedNoWhitelist ? 1 : 0, Date.now());
	return (await repository.firewallSyncProviderById(id))!;
}

export interface FirewallSyncWhitelistCidrView {
	id: string;
	networkCidr: string;
	note: string | null;
	createdAt: number;
}

function whitelistView(record: FirewallSyncWhitelistCidrRecord): FirewallSyncWhitelistCidrView {
	return { id: record.id, networkCidr: record.network_cidr, note: record.note, createdAt: record.created_at };
}

export async function listFirewallSyncWhitelistCidrs(): Promise<FirewallSyncWhitelistCidrView[]> {
	return (await repository.allFirewallSyncWhitelistCidrs()).map(whitelistView);
}

export async function addFirewallSyncWhitelistCidr(networkCidr: string, note: string | null): Promise<FirewallSyncWhitelistCidrView> {
	const trimmed = networkCidr.trim();
	if (!parseCidr(trimmed)) throw new Error("Enter a valid IP address or CIDR range");
	const record: FirewallSyncWhitelistCidrRecord = {
		id: randomId("firewall_whitelist"),
		network_cidr: trimmed,
		note: note?.trim() || null,
		created_at: Date.now(),
	};
	await repository.insertFirewallSyncWhitelistCidr(record);
	return whitelistView(record);
}

export async function removeFirewallSyncWhitelistCidr(id: string): Promise<void> {
	await repository.deleteFirewallSyncWhitelistCidr(id);
}

class FirewallSyncService {
	private running = false;
	private timer: ReturnType<typeof setInterval> | null = null;

	constructor(private readonly adapters: Record<FirewallSyncProviderType, FirewallSyncAdapter> = defaultAdapters) {}

	start(): void {
		if (this.timer || !config.firewallSync.enabled) return;
		this.timer = setInterval(() => void this.tick(), config.firewallSync.intervalMs);
		(this.timer as unknown as { unref?: () => void }).unref?.();
		void this.tick();
	}

	private async tick(): Promise<void> {
		if (this.running) return;
		this.running = true;
		try {
			const providers = (await repository.allFirewallSyncProviders()).filter((provider) => provider.enabled === 1);
			if (providers.length === 0) return;
			const desired = await aggregateBannedCidrs();
			for (const provider of providers) {
				try {
					await this.reconcileProvider(provider, desired);
				} catch (error) {
					Logger.error("[BurrowGate] Firewall sync provider reconcile failed unexpectedly", { provider: provider.id, error });
				}
			}
		} catch (error) {
			Logger.error("[BurrowGate] Unable to run firewall sync tick", { error });
		} finally {
			this.running = false;
		}
	}

	private async reconcileProvider(provider: FirewallSyncProviderRecord, desiredAll: string[], force = false): Promise<void> {
		const capped = desiredAll.slice(0, Math.max(0, provider.max_entries));
		const hash = await sha256Hex(capped.join(","));
		const checkedAt = Date.now();
		if (!force && hash === provider.last_applied_hash) {
			await repository.updateFirewallSyncProviderResult(
				provider.id,
				checkedAt,
				provider.last_synced_at,
				provider.last_sync_status,
				provider.last_sync_error,
				provider.last_applied_count,
				provider.last_applied_hash,
			);
			return;
		}
		try {
			await this.adapters[provider.type].reconcile(provider.config_json, capped);
			await repository.updateFirewallSyncProviderResult(provider.id, checkedAt, checkedAt, "ok", null, capped.length, hash);
		} catch (error) {
			const message = error instanceof Error ? error.message.slice(0, 1_000) : String(error).slice(0, 1_000);
			await repository.updateFirewallSyncProviderResult(
				provider.id,
				checkedAt,
				provider.last_synced_at,
				"error",
				message,
				provider.last_applied_count,
				provider.last_applied_hash,
			);
			Logger.error("[BurrowGate] Firewall sync push failed", { provider: provider.id, type: provider.type, error: message });
		}
	}

	/** Explicit manual action, so it always pushes for real - bypassing the tick's hash-based skip, which only exists to cut automatic polling load. */
	async syncNow(providerId: string): Promise<void> {
		const provider = await repository.firewallSyncProviderById(providerId);
		if (!provider) throw new Error("Provider not found");
		await this.reconcileProvider(provider, await aggregateBannedCidrs(), true);
	}

	async testConnection(providerId: string): Promise<{ ok: boolean; message: string }> {
		const provider = await repository.firewallSyncProviderById(providerId);
		if (!provider) throw new Error("Provider not found");
		return await this.adapters[provider.type].testConnection(provider.config_json);
	}

	/**
	 * Best-effort remote teardown before removing the local row - otherwise a deleted provider leaves its
	 * nftables table (or UniFi traffic matching lists) behind forever, still silently blocking traffic.
	 * A teardown failure (e.g. a UniFi list still referenced by a Firewall Policy) is reported back but does
	 * NOT block deleting the local row, so a broken/unreachable provider can always be removed from BurrowGate.
	 */
	async deleteProvider(providerId: string): Promise<{ teardownError: string | null }> {
		const provider = await repository.firewallSyncProviderById(providerId);
		let teardownError: string | null = null;
		if (provider) {
			try {
				await this.adapters[provider.type].teardown(provider.config_json);
			} catch (error) {
				teardownError = error instanceof Error ? error.message : String(error);
				Logger.error("[BurrowGate] Firewall sync provider teardown failed", { provider: providerId, type: provider.type, error: teardownError });
			}
		}
		await repository.deleteFirewallSyncProvider(providerId);
		return { teardownError };
	}
}

export const firewallSyncService = new FirewallSyncService();
export { FirewallSyncService };
