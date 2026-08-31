import { execFile } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { chmod, mkdir, readFile, rm } from "node:fs/promises";
import { isIP } from "node:net";
import { join } from "node:path";
import { promisify } from "node:util";
import { config } from "../config.ts";
import { Logger } from "../logger.ts";

const execFileAsync = promisify(execFile);

export interface HaTlsCertificate {
	cert: string;
	key: string;
}

export function pinnedHaCaPath(): string {
	return join(config.dataDirectory, "tls", "ha-primary-ca.pem");
}

export async function pinPrimaryHaCertificate(certificate: string): Promise<void> {
	if (!certificate.trim()) throw new Error("The primary HA certificate is empty");
	await mkdir(join(config.dataDirectory, "tls"), { recursive: true, mode: 0o700 });
	await Bun.write(pinnedHaCaPath(), certificate);
}

export async function deletePinnedHaCertificate(): Promise<void> {
	await rm(pinnedHaCaPath(), { force: true }).catch((error) => Logger.warn("HA: failed to remove the pinned primary certificate", { error }));
}

export async function readPinnedHaCertificate(): Promise<string | null> {
	if (config.ha.caFile)
		return await Bun.file(config.ha.caFile)
			.text()
			.catch(() => null);
	return await Bun.file(pinnedHaCaPath())
		.text()
		.catch(() => null);
}

export async function pinnedHaTlsOptions(): Promise<{ ca: string; checkServerIdentity: () => undefined } | undefined> {
	const pinned = await readPinnedHaCertificate();
	return pinned ? { ca: pinned, checkServerIdentity: () => undefined } : undefined;
}

const CERTIFICATE_VALIDITY_DAYS = 3_650;

function haCertificateSubjectAltName(): string {
	const entries = ["DNS:localhost", "IP:127.0.0.1"];
	if (config.ha.selfAdminUrl) {
		try {
			const host = new URL(config.ha.selfAdminUrl).hostname;
			if (host && host !== "localhost" && host !== "127.0.0.1") entries.push(isIP(host) ? `IP:${host}` : `DNS:${host}`);
		} catch {}
	}
	return entries.join(",");
}

function certificateCoversConfiguredAddress(certPem: string): boolean {
	if (!config.ha.selfAdminUrl) return true;
	let host: string;
	try {
		host = new URL(config.ha.selfAdminUrl).hostname;
	} catch {
		return true;
	}
	if (!host || host === "localhost" || host === "127.0.0.1") return true;
	const expectedEntry = isIP(host) ? `IP Address:${host}` : `DNS:${host}`;
	try {
		return (new X509Certificate(certPem).subjectAltName ?? "").includes(expectedEntry);
	} catch {
		return false;
	}
}

async function readablePair(certPath: string, keyPath: string): Promise<HaTlsCertificate | null> {
	try {
		const [cert, key] = await Promise.all([readFile(certPath, "utf8"), readFile(keyPath, "utf8")]);
		return { cert, key };
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
		return null;
	}
}

let cachedCertificatePromise: Promise<HaTlsCertificate> | null = null;

export async function haTlsCertificate(): Promise<HaTlsCertificate> {
	cachedCertificatePromise ??= resolveHaTlsCertificate();
	try {
		return await cachedCertificatePromise;
	} catch (error) {
		cachedCertificatePromise = null;
		throw error;
	}
}

export function resetHaTlsCertificateCache(): void {
	cachedCertificatePromise = null;
}

async function resolveHaTlsCertificate(): Promise<HaTlsCertificate> {
	if (config.ha.tlsCertFile && config.ha.tlsKeyFile) {
		const provided = await readablePair(config.ha.tlsCertFile, config.ha.tlsKeyFile);
		if (provided) return provided;
		throw new Error(`Unable to read BG_HA_TLS_CERT_FILE/BG_HA_TLS_KEY_FILE (${config.ha.tlsCertFile}, ${config.ha.tlsKeyFile})`);
	}

	const directory = join(config.dataDirectory, "tls");
	const certPath = join(directory, "ha-cert.pem");
	const keyPath = join(directory, "ha-key.pem");
	await mkdir(directory, { recursive: true, mode: 0o700 });

	const existing = await readablePair(certPath, keyPath);
	if (existing && certificateCoversConfiguredAddress(existing.cert)) return existing;
	if (existing) Logger.info("HA: the existing self-signed certificate does not cover this node's current admin URL, regenerating.");

	await Promise.all([rm(certPath, { force: true }), rm(keyPath, { force: true })]);
	await execFileAsync("openssl", [
		"req",
		"-x509",
		"-newkey",
		"rsa:2048",
		"-sha256",
		"-nodes",
		"-days",
		String(CERTIFICATE_VALIDITY_DAYS),
		"-subj",
		"/CN=BurrowGate HA",
		"-addext",
		`subjectAltName=${haCertificateSubjectAltName()}`,
		"-keyout",
		keyPath,
		"-out",
		certPath,
	]);
	await chmod(keyPath, 0o600);
	const generated = await readablePair(certPath, keyPath);
	if (!generated) throw new Error("Generated HA certificate could not be read");
	Logger.info("Generated a self-signed certificate for the HA replication link.");
	return generated;
}
