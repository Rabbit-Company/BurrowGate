import { repository } from "../db/repository.ts";
import type { DnsProviderRecord, DnsProviderType } from "../types.ts";
import { randomId } from "../utils/crypto.ts";
import { encryptSecret } from "./secret-encryption-service.ts";
import { parseRfc2136ProviderConfig, rfc2136CreateTxtRecord, rfc2136DeleteTxtRecord, rfc2136TestConnection } from "./dns-01/rfc2136-adapter.ts";

export interface DnsProviderAdapter {
	createTxtRecord(configJson: string, recordName: string, value: string): Promise<void>;
	deleteTxtRecord(configJson: string, recordName: string, value: string): Promise<void>;
	testConnection(configJson: string): Promise<{ ok: boolean; message: string }>;
}

const adapters: Record<DnsProviderType, DnsProviderAdapter> = {
	rfc2136: { createTxtRecord: rfc2136CreateTxtRecord, deleteTxtRecord: rfc2136DeleteTxtRecord, testConnection: rfc2136TestConnection },
};

export function dnsProviderAdapter(type: DnsProviderType): DnsProviderAdapter {
	return adapters[type];
}

export interface DnsProviderView {
	id: string;
	name: string;
	type: DnsProviderType;
	config: Record<string, unknown>;
	createdAt: number;
	updatedAt: number;
}

function redactConfig(configJson: string): Record<string, unknown> {
	const { tsigSecretEncrypted, ...rest } = JSON.parse(configJson) as Record<string, unknown>;
	return { ...rest, tsigSecretConfigured: typeof tsigSecretEncrypted === "string" && tsigSecretEncrypted.length > 0 };
}

export function dnsProviderView(record: DnsProviderRecord): DnsProviderView {
	return {
		id: record.id,
		name: record.name,
		type: record.type,
		config: redactConfig(record.config_json),
		createdAt: record.created_at,
		updatedAt: record.updated_at,
	};
}

export interface DnsProviderInput {
	name?: unknown;
	type?: unknown;
	config?: unknown;
}

async function buildConfigJson(input: unknown, existingConfigJson: string | null): Promise<string> {
	const raw = (input ?? {}) as Record<string, unknown>;
	const existing = existingConfigJson ? parseRfc2136ProviderConfig(JSON.parse(existingConfigJson)) : null;
	const secretInput = typeof raw.tsigSecret === "string" ? raw.tsigSecret.trim() : "";
	const tsigSecretEncrypted = secretInput ? await encryptSecret(secretInput) : (existing?.tsigSecretEncrypted ?? "");
	const parsed = parseRfc2136ProviderConfig({ ...existing, ...raw, tsigSecretEncrypted });
	if (!parsed.server) throw new Error("DNS server is required");
	if (!parsed.zone) throw new Error("Zone is required");
	if (!parsed.tsigKeyName) throw new Error("TSIG key name is required");
	if (!parsed.tsigSecretEncrypted) throw new Error("TSIG secret is required");
	return JSON.stringify(parsed);
}

export async function createDnsProvider(input: DnsProviderInput): Promise<DnsProviderRecord> {
	const type = input.type as DnsProviderType;
	if (type !== "rfc2136") throw new Error("Unsupported DNS provider type");
	const name = String(input.name ?? "").trim();
	if (!name) throw new Error("Name is required");
	const now = Date.now();
	const record: DnsProviderRecord = {
		id: randomId("dns_provider"),
		name,
		type,
		config_json: await buildConfigJson(input.config, null),
		created_at: now,
		updated_at: now,
	};
	await repository.insertDnsProvider(record);
	return record;
}

export async function updateDnsProvider(id: string, input: DnsProviderInput): Promise<DnsProviderRecord> {
	const existing = await repository.dnsProviderById(id);
	if (!existing) throw new Error("DNS provider not found");
	const name = input.name === undefined ? existing.name : String(input.name ?? "").trim();
	if (!name) throw new Error("Name is required");
	const configJson = input.config === undefined ? existing.config_json : await buildConfigJson(input.config, existing.config_json);
	await repository.updateDnsProviderConfig(id, name, configJson, Date.now());
	return (await repository.dnsProviderById(id))!;
}

export async function deleteDnsProvider(id: string): Promise<void> {
	const dependentSites = await repository.sitesUsingDnsProvider(id);
	if (dependentSites.length > 0) {
		const names = dependentSites.map((site) => site.name).join(", ");
		throw new Error(
			`This DNS provider is used for DNS-01 issuance by site${dependentSites.length === 1 ? "" : "s"} ${names}. Switch those sites off DNS-01 first.`,
		);
	}
	await repository.deleteDnsProvider(id);
}

export async function testDnsProvider(id: string): Promise<{ ok: boolean; message: string }> {
	const provider = await repository.dnsProviderById(id);
	if (!provider) throw new Error("DNS provider not found");
	return await dnsProviderAdapter(provider.type).testConnection(provider.config_json);
}
