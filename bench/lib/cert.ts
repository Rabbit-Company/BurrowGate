/**
 * Generates (and caches under bench/tmp) a throwaway self-signed cert for the
 * TLS handshake benchmark, using the same `openssl req -x509` shape as
 * src/services/bootstrap-tls-service.ts so the benchmark reflects the actual
 * certificate BurrowGate would terminate with.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export interface SelfSignedCert {
	cert: string;
	key: string;
}

export async function ensureBenchCertificate(dir: string): Promise<SelfSignedCert> {
	const certPath = `${dir}/bench-cert.pem`;
	const keyPath = `${dir}/bench-key.pem`;

	// Always construct a fresh Bun.file() handle right before reading, rather
	// than reusing one obtained earlier in this function. (Bug in Bun)
	if ((await Bun.file(certPath).exists()) && (await Bun.file(keyPath).exists())) {
		return { cert: await Bun.file(certPath).text(), key: await Bun.file(keyPath).text() };
	}

	await Bun.$`mkdir -p ${dir}`.quiet();
	await execFileAsync("openssl", [
		"req",
		"-x509",
		"-newkey",
		"rsa:2048",
		"-sha256",
		"-nodes",
		"-days",
		"1",
		"-subj",
		"/CN=bench.localhost",
		"-keyout",
		keyPath,
		"-out",
		certPath,
	]);

	return { cert: await Bun.file(certPath).text(), key: await Bun.file(keyPath).text() };
}
