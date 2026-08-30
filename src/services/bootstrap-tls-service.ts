import { execFile } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { chmod, mkdir, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { config } from "../config.ts";
import { Logger } from "../logger.ts";
import { haTlsCertificate } from "./ha-tls-service.ts";

const execFileAsync = promisify(execFile);

export interface TlsCertificateOption {
	serverName?: string;
	cert: string;
	key: string;
}

async function readablePair(certPath: string, keyPath: string): Promise<TlsCertificateOption | null> {
	try {
		const [cert, key] = await Promise.all([readFile(certPath, "utf8"), readFile(keyPath, "utf8")]);
		const parsed = new X509Certificate(cert);
		if (Date.parse(parsed.validTo) <= Date.now() + 7 * 86_400_000) return null;
		return { cert, key };
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
		return null;
	}
}

export async function bootstrapTlsOption(): Promise<TlsCertificateOption | null> {
	if (!config.bootstrapTls) return null;
	if (config.ha.enabled) {
		try {
			return await haTlsCertificate();
		} catch (error) {
			Logger.error("[BurrowGate] Unable to prepare this node's HA certificate for the dashboard's bootstrap TLS fallback", { error });
			return null;
		}
	}
	const directory = join(config.dataDirectory, "tls");
	const certPath = join(directory, "bootstrap-cert.pem");
	const keyPath = join(directory, "bootstrap-key.pem");
	await mkdir(directory, { recursive: true, mode: 0o700 });

	const existing = await readablePair(certPath, keyPath);
	if (existing) return existing;

	await Promise.all([rm(certPath, { force: true }), rm(keyPath, { force: true })]);
	try {
		await execFileAsync("openssl", [
			"req",
			"-x509",
			"-newkey",
			"rsa:2048",
			"-sha256",
			"-nodes",
			"-days",
			"90",
			"-subj",
			"/CN=BurrowGate Bootstrap",
			"-addext",
			"subjectAltName=DNS:localhost,IP:127.0.0.1",
			"-keyout",
			keyPath,
			"-out",
			certPath,
		]);
		await chmod(keyPath, 0o600);
		const generated = await readablePair(certPath, keyPath);
		if (!generated) throw new Error("Generated bootstrap certificate could not be read");
		Logger.warn("[BurrowGate] Using a self-signed bootstrap certificate until a site certificate is uploaded or issued.");
		return generated;
	} catch (error) {
		Logger.error("[BurrowGate] Unable to generate the bootstrap TLS certificate. Install OpenSSL or set BG_BOOTSTRAP_TLS_ENABLED=false.", { error });
		return null;
	}
}
