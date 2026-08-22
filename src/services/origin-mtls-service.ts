import { execFile } from "node:child_process";
import { X509Certificate, createPrivateKey, createPublicKey, timingSafeEqual } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { isIP } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import type { SiteOriginRecord, SiteRecord } from "../types.ts";
import { siteHostname } from "./certificate-service.ts";
import { decryptSecret } from "./secret-encryption-service.ts";

const execFileAsync = promisify(execFile);

const CERTIFICATE_PATTERN = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/gu;

export interface ClientCertificatePair {
	certificatePem: string;
	privateKeyPem: string;
}

export function validateClientCertificatePair(certificatePem: string, privateKeyPem: string): ClientCertificatePair {
	if (certificatePem.length > 512_000) throw new Error("Client certificate PEM must be at most 512 KB");
	if (privateKeyPem.length > 256_000) throw new Error("Client private-key PEM must be at most 256 KB");
	const certificates = certificatePem.match(CERTIFICATE_PATTERN);
	if (!certificates?.length) throw new Error("Client certificate PEM does not contain a certificate");
	let certificate: X509Certificate;
	try {
		certificate = new X509Certificate(certificates[0]!);
	} catch {
		throw new Error("Client certificate PEM is invalid");
	}
	let privateKey;
	try {
		privateKey = createPrivateKey(privateKeyPem);
	} catch {
		throw new Error("Client private-key PEM is invalid or unsupported");
	}
	const certificateKey = certificate.publicKey.export({ format: "der", type: "spki" });
	const suppliedKey = createPublicKey(privateKey).export({ format: "der", type: "spki" });
	if (certificateKey.length !== suppliedKey.length || !timingSafeEqual(certificateKey, suppliedKey)) {
		throw new Error("The private key does not match the client certificate");
	}
	const expiresAt = Date.parse(certificate.validTo);
	if (Number.isFinite(expiresAt) && expiresAt <= Date.now()) throw new Error("Client certificate is already expired");
	return { certificatePem: certificates.join("\n"), privateKeyPem: privateKeyPem.trim() };
}

export function validateCaBundle(caPem: string): string {
	if (caPem.length > 512_000) throw new Error("Trusted CA PEM must be at most 512 KB");
	const certificates = caPem.match(CERTIFICATE_PATTERN);
	if (!certificates?.length) throw new Error("Trusted CA PEM does not contain a certificate");
	for (const block of certificates) {
		try {
			new X509Certificate(block);
		} catch {
			throw new Error("Trusted CA PEM contains an invalid certificate");
		}
	}
	return certificates.join("\n");
}

const DEFAULT_CERTIFICATE_VALIDITY_DAYS = 5_475; // 15 years

async function generateSelfSignedCertificate(subjectAltNames: string[], commonName: string, days: number): Promise<ClientCertificatePair> {
	const dir = await mkdtemp(join(tmpdir(), "burrowgate-cert-"));
	const certPath = join(dir, "cert.pem");
	const keyPath = join(dir, "key.pem");
	try {
		const args = [
			"req",
			"-x509",
			"-newkey",
			"rsa:2048",
			"-sha256",
			"-nodes",
			"-days",
			String(days),
			"-subj",
			`/CN=${commonName}`,
			"-keyout",
			keyPath,
			"-out",
			certPath,
		];
		if (subjectAltNames.length) args.push("-addext", `subjectAltName=${subjectAltNames.join(",")}`);
		try {
			await execFileAsync("openssl", args);
		} catch {
			throw new Error("Unable to generate a certificate. Ensure OpenSSL is installed on the BurrowGate host.");
		}
		const [certificatePem, privateKeyPem] = await Promise.all([readFile(certPath, "utf8"), readFile(keyPath, "utf8")]);
		return validateClientCertificatePair(certificatePem, privateKeyPem);
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
}

export async function generateClientCertificate(commonName: string, days = DEFAULT_CERTIFICATE_VALIDITY_DAYS): Promise<ClientCertificatePair> {
	return generateSelfSignedCertificate([], commonName, days);
}

export async function generateOriginCertificate(
	site: SiteRecord,
	origin: SiteOriginRecord,
	days = DEFAULT_CERTIFICATE_VALIDITY_DAYS,
): Promise<ClientCertificatePair> {
	const hostname = siteHostname(site);
	const originHost = new URL(origin.origin_url).hostname;
	const sanEntries = new Set([`DNS:${hostname}`]);
	sanEntries.add(isIP(originHost) ? `IP:${originHost}` : `DNS:${originHost}`);
	return generateSelfSignedCertificate([...sanEntries], hostname, days);
}

export async function originMtlsFetchOptions(origin: SiteOriginRecord | null): Promise<Pick<BunFetchRequestInit, "tls">> {
	if (!origin) return {};
	const tls: NonNullable<BunFetchRequestInit["tls"]> = {};
	if (origin.mtls_enabled === 1 && origin.mtls_certificate_pem && origin.mtls_encrypted_private_key) {
		tls.cert = origin.mtls_certificate_pem;
		tls.key = await decryptSecret(origin.mtls_encrypted_private_key);
	}
	if (origin.mtls_ca_pem) tls.ca = origin.mtls_ca_pem;
	return Object.keys(tls).length ? { tls } : {};
}
