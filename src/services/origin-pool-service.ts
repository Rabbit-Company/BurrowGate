import { repository } from "../db/repository.ts";
import type { SiteOriginRecord, SiteRecord } from "../types.ts";
import { randomId } from "../utils/crypto.ts";
import { encryptSecret } from "./secret-encryption-service.ts";
import { generateClientCertificate, generateOriginCertificate, validateCaBundle, validateClientCertificatePair } from "./origin-mtls-service.ts";

export interface OriginInput {
	name?: unknown;
	originUrl?: unknown;
	enabled?: unknown;
	draining?: unknown;
	priority?: unknown;
	weight?: unknown;
	healthCheckPath?: unknown;
	mtlsEnabled?: unknown;
	mtlsCertificatePem?: unknown;
	mtlsPrivateKeyPem?: unknown;
	mtlsCaPem?: unknown;
}

function booleanValue(value: unknown, fallback: boolean, label: string): boolean {
	if (value === undefined) return fallback;
	if (typeof value === "boolean") return value;
	if (value === 1 || value === "1" || value === "true") return true;
	if (value === 0 || value === "0" || value === "false") return false;
	throw new Error(`${label} must be a boolean`);
}

function requiredString(value: unknown, fallback: string | undefined, label: string, maximum: number): string {
	const result = String(value ?? fallback ?? "").trim();
	if (!result) throw new Error(`${label} is required`);
	if (result.length > maximum) throw new Error(`${label} must be at most ${maximum} characters`);
	return result;
}

function integerValue(value: unknown, fallback: number, label: string, minimum: number, maximum: number): number {
	const result = value === undefined ? fallback : Number(value);
	if (!Number.isInteger(result) || result < minimum || result > maximum) throw new Error(`${label} must be an integer from ${minimum} to ${maximum}`);
	return result;
}

export function normalizePoolOriginUrl(value: unknown, fallback?: string): string {
	const raw = requiredString(value, fallback, "Origin URL", 2_048);
	let parsed: URL;
	try {
		parsed = new URL(raw);
	} catch {
		throw new Error("Origin URL must be a valid absolute URL");
	}
	if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("Origin URL must use HTTP or HTTPS");
	if (parsed.username || parsed.password) throw new Error("Origin URL must not contain credentials");
	if (parsed.search || parsed.hash) throw new Error("Origin URL must not contain a query string or fragment");
	return parsed.toString().replace(/\/$/u, parsed.pathname === "/" ? "" : "/");
}

function healthPath(value: unknown, fallback: string | null): string | null {
	if (value === undefined) return fallback;
	const raw = String(value ?? "").trim();
	if (!raw) return null;
	if (!raw.startsWith("/") || raw.startsWith("//") || raw.length > 2_048) {
		throw new Error("Origin health-check path must begin with one slash and be at most 2048 characters");
	}
	const parsed = new URL(raw, "http://health.invalid");
	if (parsed.origin !== "http://health.invalid" || parsed.hash) throw new Error("Origin health-check path must not contain a hostname or fragment");
	return `${parsed.pathname}${parsed.search}`;
}

async function uniqueName(siteId: string, name: string, existingId?: string): Promise<void> {
	const conflict = (await repository.originsForSite(siteId)).find((origin) => origin.name.toLowerCase() === name.toLowerCase() && origin.id !== existingId);
	if (conflict) throw new Error("An origin with this name already exists for the site");
}

export function originView(origin: SiteOriginRecord) {
	return {
		id: origin.id,
		name: origin.name,
		originUrl: origin.origin_url,
		enabled: origin.enabled === 1,
		draining: origin.draining === 1,
		priority: Number(origin.priority),
		weight: Number(origin.weight),
		healthCheckPath: origin.health_check_path,
		isPrimary: origin.is_primary === 1,
		mtls: {
			enabled: origin.mtls_enabled === 1,
			configured: Boolean(origin.mtls_certificate_pem && origin.mtls_encrypted_private_key),
			caConfigured: Boolean(origin.mtls_ca_pem),
		},
		createdAt: Number(origin.created_at),
		updatedAt: Number(origin.updated_at),
	};
}

async function resolveMtlsFields(
	input: OriginInput,
	existing?: SiteOriginRecord,
): Promise<Pick<SiteOriginRecord, "mtls_enabled" | "mtls_certificate_pem" | "mtls_encrypted_private_key" | "mtls_ca_pem">> {
	const enabled = booleanValue(input.mtlsEnabled, existing ? existing.mtls_enabled === 1 : false, "mTLS enabled");
	let certificatePem = existing?.mtls_certificate_pem ?? null;
	let encryptedPrivateKey = existing?.mtls_encrypted_private_key ?? null;
	const suppliedCert = typeof input.mtlsCertificatePem === "string" ? input.mtlsCertificatePem.trim() : "";
	const suppliedKey = typeof input.mtlsPrivateKeyPem === "string" ? input.mtlsPrivateKeyPem.trim() : "";
	if (suppliedCert || suppliedKey) {
		if (!suppliedCert || !suppliedKey) throw new Error("Both a client certificate and a private key are required to replace the mTLS credential");
		const validated = validateClientCertificatePair(suppliedCert, suppliedKey);
		certificatePem = validated.certificatePem;
		encryptedPrivateKey = await encryptSecret(validated.privateKeyPem);
	}
	if (enabled && (!certificatePem || !encryptedPrivateKey)) {
		throw new Error("A client certificate and private key are required to enable mTLS for this origin");
	}
	let caPem = existing?.mtls_ca_pem ?? null;
	const suppliedCa = typeof input.mtlsCaPem === "string" ? input.mtlsCaPem.trim() : "";
	if (suppliedCa) caPem = validateCaBundle(suppliedCa);
	return {
		mtls_enabled: enabled ? 1 : 0,
		mtls_certificate_pem: certificatePem,
		mtls_encrypted_private_key: encryptedPrivateKey,
		mtls_ca_pem: caPem,
	};
}

export async function createOrigin(siteId: string, input: OriginInput): Promise<SiteOriginRecord> {
	if (!(await repository.siteById(siteId))) throw new Error("Site not found");
	const name = requiredString(input.name, undefined, "Origin name", 255);
	await uniqueName(siteId, name);
	const mtls = await resolveMtlsFields(input);
	const now = Date.now();
	const origin: SiteOriginRecord = {
		id: randomId("origin"),
		site_id: siteId,
		name,
		origin_url: normalizePoolOriginUrl(input.originUrl),
		enabled: booleanValue(input.enabled, true, "Origin enabled") ? 1 : 0,
		draining: booleanValue(input.draining, false, "Origin draining") ? 1 : 0,
		priority: integerValue(input.priority, 10, "Origin priority", 0, 10_000),
		weight: integerValue(input.weight, 1, "Origin weight", 1, 1_000),
		health_check_path: healthPath(input.healthCheckPath, null),
		is_primary: 0,
		...mtls,
		created_at: now,
		updated_at: now,
	};
	await repository.insertOrigin(origin);
	return origin;
}

export async function updateOrigin(siteId: string, id: string, input: OriginInput): Promise<SiteOriginRecord> {
	const existing = await repository.originById(id, siteId);
	if (!existing) throw new Error("Origin not found");
	const name = requiredString(input.name, existing.name, "Origin name", 255);
	await uniqueName(siteId, name, id);
	const mtls = await resolveMtlsFields(input, existing);
	const updated: SiteOriginRecord = {
		...existing,
		name,
		origin_url: normalizePoolOriginUrl(input.originUrl, existing.origin_url),
		enabled: booleanValue(input.enabled, existing.enabled === 1, "Origin enabled") ? 1 : 0,
		draining: booleanValue(input.draining, existing.draining === 1, "Origin draining") ? 1 : 0,
		priority: integerValue(input.priority, Number(existing.priority), "Origin priority", 0, 10_000),
		weight: integerValue(input.weight, Number(existing.weight), "Origin weight", 1, 1_000),
		health_check_path: healthPath(input.healthCheckPath, existing.health_check_path),
		...mtls,
		updated_at: Date.now(),
	};
	await repository.updateOrigin(updated);
	if (updated.is_primary === 1 && updated.origin_url !== existing.origin_url) {
		const site = await repository.siteById(siteId);
		if (site) await repository.updateSite({ ...site, origin_url: updated.origin_url, updated_at: updated.updated_at });
	}
	return updated;
}

export async function generateOriginMtlsCertificate(siteId: string, id: string): Promise<SiteOriginRecord> {
	const existing = await repository.originById(id, siteId);
	if (!existing) throw new Error("Origin not found");
	const { certificatePem, privateKeyPem } = await generateClientCertificate(`burrowgate-origin-${existing.id}`);
	return updateOrigin(siteId, id, { mtlsEnabled: true, mtlsCertificatePem: certificatePem, mtlsPrivateKeyPem: privateKeyPem });
}

export async function generateOriginServerCertificate(
	site: SiteRecord,
	siteId: string,
	id: string,
): Promise<{ origin: SiteOriginRecord; privateKeyPem: string }> {
	const existing = await repository.originById(id, siteId);
	if (!existing) throw new Error("Origin not found");
	const { certificatePem, privateKeyPem } = await generateOriginCertificate(site, existing);
	const origin = await updateOrigin(siteId, id, { mtlsCaPem: certificatePem });
	return { origin, privateKeyPem };
}

export async function deleteOrigin(siteId: string, id: string): Promise<void> {
	const origin = await repository.originById(id, siteId);
	if (!origin) throw new Error("Origin not found");
	if (origin.is_primary === 1) throw new Error("The primary origin cannot be deleted; update it from the site settings instead");
	await repository.deleteOrigin(id, siteId);
	await repository.assignSessionsFromOrigin(id, null);
	await repository.deleteBackendHealthStatus(id);
}
