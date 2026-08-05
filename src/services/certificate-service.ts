import { X509Certificate, createPrivateKey, createPublicKey, timingSafeEqual } from "node:crypto";
import { config } from "../config.ts";
import { repository } from "../db/repository.ts";
import type { CertificateEventRecord, CertificateRecord, CertificateSource, SiteRecord, SiteTlsSettingsRecord, TlsMode } from "../types.ts";
import { randomId } from "../utils/crypto.ts";
import { decryptSecret, encryptSecret } from "./secret-encryption-service.ts";
import type { TlsCertificateOption } from "./bootstrap-tls-service.ts";

const CERTIFICATE_PATTERN = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/gu;
const ALLOWED_TLS_MODES: readonly TlsMode[] = ["disabled", "uploaded", "letsencrypt"];

export interface CertificateMetadata {
	certificatePem: string;
	privateKeyPem: string;
	primaryDomain: string;
	alternativeNames: string[];
	issuer: string;
	serialNumber: string;
	validFrom: number;
	expiresAt: number;
}

export interface TlsSiteView {
	settings: {
		mode: TlsMode;
		forceHttps: boolean;
		acmeEmail: string | null;
		acmeDirectoryUrl: string | null;
	};
	certificate: null | {
		id: string;
		source: CertificateSource;
		status: string;
		primaryDomain: string;
		alternativeNames: string[];
		issuer: string | null;
		serialNumber: string | null;
		validFrom: number | null;
		expiresAt: number | null;
		nextRenewalAt: number | null;
		lastAttemptAt: number | null;
		lastError: string | null;
		updatedAt: number;
	};
	events: Array<{ id: string; level: string; message: string; details: unknown; createdAt: number }>;
	listener: {
		httpEnabled: boolean;
		httpPort: number;
		publicHttpPort: number;
		httpsEnabled: boolean;
		httpsPort: number;
		publicHttpsPort: number;
		bootstrapTlsEnabled: boolean;
	};
	defaults: { acmeDirectoryUrl: string; acmeEmail: string | null; staging: boolean };
}

export async function recordCertificateEvent(
	siteId: string,
	certificateId: string | null,
	level: CertificateEventRecord["level"],
	message: string,
	details: unknown = {},
): Promise<void> {
	await repository.insertCertificateEvent({
		id: randomId("cert_evt"),
		site_id: siteId,
		certificate_id: certificateId,
		level,
		message,
		details_json: JSON.stringify(details),
		created_at: Date.now(),
	});
}

export function siteHostname(site: SiteRecord): string {
	return new URL(`http://${site.public_host}`).hostname.toLowerCase();
}

function parseAlternativeNames(certificate: X509Certificate): string[] {
	const result = new Set<string>();
	const value = certificate.subjectAltName ?? "";
	for (const match of value.matchAll(/(?:DNS:|IP Address:)([^,]+)/gu)) result.add(match[1]!.trim().toLowerCase());
	return [...result];
}

export function certificateCoversHostname(certificatePem: string, expectedHostname: string): boolean {
	const certificates = certificatePem.match(CERTIFICATE_PATTERN);
	if (!certificates?.length) return false;
	try {
		return Boolean(new X509Certificate(certificates[0]!).checkHost(expectedHostname));
	} catch {
		return false;
	}
}

export function validateCertificatePair(certificatePem: string, privateKeyPem: string, expectedHostname: string): CertificateMetadata {
	if (certificatePem.length > 512_000) throw new Error("Certificate PEM must be at most 512 KB");
	if (privateKeyPem.length > 256_000) throw new Error("Private-key PEM must be at most 256 KB");
	const certificates = certificatePem.match(CERTIFICATE_PATTERN);
	if (!certificates?.length) throw new Error("Certificate PEM does not contain a certificate");
	let certificate: X509Certificate;
	try {
		certificate = new X509Certificate(certificates[0]!);
	} catch {
		throw new Error("Certificate PEM is invalid");
	}
	let privateKey;
	try {
		privateKey = createPrivateKey(privateKeyPem);
	} catch {
		throw new Error("Private-key PEM is invalid or unsupported");
	}
	const certificateKey = certificate.publicKey.export({ format: "der", type: "spki" });
	const suppliedKey = createPublicKey(privateKey).export({ format: "der", type: "spki" });
	if (certificateKey.length !== suppliedKey.length || !timingSafeEqual(certificateKey, suppliedKey)) {
		throw new Error("The private key does not match the certificate");
	}
	if (!certificate.checkHost(expectedHostname)) {
		throw new Error(`The certificate does not cover ${expectedHostname}`);
	}
	const validFrom = Date.parse(certificate.validFrom);
	const expiresAt = Date.parse(certificate.validTo);
	if (!Number.isFinite(validFrom) || !Number.isFinite(expiresAt)) throw new Error("Certificate validity dates are invalid");
	if (expiresAt <= Date.now()) throw new Error("Certificate is already expired");
	const alternativeNames = parseAlternativeNames(certificate);
	return {
		certificatePem: certificates.join("\n"),
		privateKeyPem: privateKeyPem.trim(),
		primaryDomain: expectedHostname,
		alternativeNames: alternativeNames.length ? alternativeNames : [expectedHostname],
		issuer: certificate.issuer,
		serialNumber: certificate.serialNumber,
		validFrom,
		expiresAt,
	};
}

export async function assertTlsHostnameAvailable(site: SiteRecord): Promise<void> {
	const hostname = siteHostname(site);
	const conflicts = (await repository.allSites()).filter((candidate) => {
		if (candidate.id === site.id || candidate.enabled !== 1) return false;
		try {
			return siteHostname(candidate) === hostname;
		} catch {
			return false;
		}
	});
	if (conflicts.length) {
		throw new Error(`TLS cannot be enabled for ${hostname} because another enabled site uses the same hostname. HTTPS SNI cannot distinguish sites by port.`);
	}
}

export async function saveCertificate(input: {
	site: SiteRecord;
	source: CertificateSource;
	certificatePem: string;
	privateKeyPem: string;
	lastAttemptAt?: number | null;
}): Promise<CertificateRecord> {
	await assertTlsHostnameAvailable(input.site);
	const metadata = validateCertificatePair(input.certificatePem, input.privateKeyPem, siteHostname(input.site));
	const existing = await repository.certificateBySite(input.site.id);
	const now = Date.now();
	const record: CertificateRecord = {
		id: existing?.id ?? randomId("cert"),
		site_id: input.site.id,
		source: input.source,
		status: "active",
		primary_domain: metadata.primaryDomain,
		alternative_names_json: JSON.stringify(metadata.alternativeNames),
		certificate_pem: metadata.certificatePem,
		encrypted_private_key: await encryptSecret(metadata.privateKeyPem),
		issuer: metadata.issuer,
		serial_number: metadata.serialNumber,
		valid_from: metadata.validFrom,
		expires_at: metadata.expiresAt,
		next_renewal_at: input.source === "letsencrypt" ? metadata.expiresAt - config.acme.renewBeforeDays * 86_400_000 : null,
		last_attempt_at: input.lastAttemptAt ?? now,
		last_error: null,
		created_at: existing?.created_at ?? now,
		updated_at: now,
	};
	await repository.saveCertificate(record);
	return record;
}

export async function certificateTlsOptions(): Promise<TlsCertificateOption[]> {
	const records = await repository.activeCertificates();
	const result: TlsCertificateOption[] = [];
	for (const record of records) {
		if (!record.certificate_pem || !record.encrypted_private_key) continue;
		result.push({
			serverName: new URL(`http://${record.public_host}`).hostname,
			cert: record.certificate_pem,
			key: await decryptSecret(record.encrypted_private_key),
		});
	}
	return result;
}

export async function streamCertificateTlsOption(certificateId: string): Promise<Bun.TLSOptions> {
	const record = await repository.certificateById(certificateId);
	if (!record || record.status !== "active" || Number(record.expires_at ?? 0) <= Date.now() || !record.certificate_pem || !record.encrypted_private_key) {
		throw new Error("The stream TLS certificate is unavailable or expired");
	}
	return { cert: record.certificate_pem, key: await decryptSecret(record.encrypted_private_key) };
}

export async function tlsSettings(siteId: string): Promise<SiteTlsSettingsRecord> {
	return await repository.ensureTlsSettings(siteId);
}

export async function updateTlsSettings(
	site: SiteRecord,
	input: {
		mode?: unknown;
		forceHttps?: unknown;
		acmeEmail?: unknown;
		acmeDirectoryUrl?: unknown;
	},
): Promise<SiteTlsSettingsRecord> {
	const existing = await repository.ensureTlsSettings(site.id);
	const rawMode = input.mode === undefined ? existing.mode : String(input.mode);
	if (!ALLOWED_TLS_MODES.includes(rawMode as TlsMode)) throw new Error("TLS mode must be disabled, uploaded, or letsencrypt");
	const forceHttps = rawMode === "disabled" ? false : input.forceHttps === undefined ? existing.force_https === 1 : Boolean(input.forceHttps);
	const acmeEmail = input.acmeEmail === undefined ? existing.acme_email : String(input.acmeEmail ?? "").trim() || null;
	if (acmeEmail && !/^\S+@\S+\.\S+$/u.test(acmeEmail)) throw new Error("ACME email address is invalid");
	const acmeDirectoryUrl = input.acmeDirectoryUrl === undefined ? existing.acme_directory_url : String(input.acmeDirectoryUrl ?? "").trim() || null;
	if (acmeDirectoryUrl) {
		const parsed = new URL(acmeDirectoryUrl);
		if (parsed.protocol !== "https:") throw new Error("ACME directory URL must use HTTPS");
	}
	const now = Date.now();
	const settings: SiteTlsSettingsRecord = {
		...existing,
		mode: rawMode as TlsMode,
		force_https: forceHttps ? 1 : 0,
		acme_email: acmeEmail,
		acme_directory_url: acmeDirectoryUrl,
		updated_at: now,
	};
	await repository.saveTlsSettings(settings);
	return settings;
}

export async function tlsView(site: SiteRecord): Promise<TlsSiteView> {
	const settings = await repository.ensureTlsSettings(site.id);
	const certificate = await repository.certificateBySite(site.id);
	const events = await repository.certificateEvents(site.id);
	return {
		settings: {
			mode: settings.mode,
			forceHttps: settings.force_https === 1,
			acmeEmail: settings.acme_email,
			acmeDirectoryUrl: settings.acme_directory_url,
		},
		certificate: certificate
			? {
					id: certificate.id,
					source: certificate.source,
					status: certificate.expires_at !== null && certificate.expires_at <= Date.now() ? "expired" : certificate.status,
					primaryDomain: certificate.primary_domain,
					alternativeNames: JSON.parse(certificate.alternative_names_json) as string[],
					issuer: certificate.issuer,
					serialNumber: certificate.serial_number,
					validFrom: certificate.valid_from,
					expiresAt: certificate.expires_at,
					nextRenewalAt: certificate.next_renewal_at,
					lastAttemptAt: certificate.last_attempt_at,
					lastError: certificate.last_error,
					updatedAt: certificate.updated_at,
				}
			: null,
		events: events.map((event) => ({
			id: event.id,
			level: event.level,
			message: event.message,
			details: JSON.parse(event.details_json || "{}") as unknown,
			createdAt: event.created_at,
		})),
		listener: {
			httpEnabled: config.http.enabled,
			httpPort: config.http.port,
			publicHttpPort: config.http.publicPort,
			httpsEnabled: config.https.enabled,
			httpsPort: config.https.port,
			publicHttpsPort: config.https.publicPort,
			bootstrapTlsEnabled: config.bootstrapTls,
		},
		defaults: {
			acmeDirectoryUrl: config.acme.directoryUrl,
			acmeEmail: config.acme.email,
			staging: config.acme.directoryUrl.includes("staging"),
		},
	};
}
