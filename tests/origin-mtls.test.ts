import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeAll, describe, expect, test } from "bun:test";
import { createSite } from "../src/services/site-service.ts";
import { X509Certificate } from "node:crypto";
import { createOrigin, generateOriginMtlsCertificate, generateOriginServerCertificate, originView, updateOrigin } from "../src/services/origin-pool-service.ts";
import {
	generateClientCertificate,
	generateOriginCertificate,
	originMtlsFetchOptions,
	validateCaBundle,
	validateClientCertificatePair,
} from "../src/services/origin-mtls-service.ts";
import { decryptSecret } from "../src/services/secret-encryption-service.ts";

let certificatePem: string;
let privateKeyPem: string;
let otherPrivateKeyPem: string;

async function generateSelfSignedPair(dir: string, name: string, commonName: string): Promise<{ certificatePem: string; privateKeyPem: string }> {
	const certPath = join(dir, `${name}-cert.pem`);
	const keyPath = join(dir, `${name}-key.pem`);
	const proc = Bun.spawnSync([
		"openssl",
		"req",
		"-x509",
		"-newkey",
		"rsa:2048",
		"-nodes",
		"-keyout",
		keyPath,
		"-out",
		certPath,
		"-days",
		"1",
		"-subj",
		`/CN=${commonName}`,
	]);
	if (proc.exitCode !== 0) throw new Error(`openssl failed: ${proc.stderr.toString()}`);
	return { certificatePem: await readFile(certPath, "utf8"), privateKeyPem: await readFile(keyPath, "utf8") };
}

beforeAll(async () => {
	const dir = await mkdtemp(join(tmpdir(), "burrowgate-mtls-test-"));
	const primary = await generateSelfSignedPair(dir, "primary", "test-client");
	const other = await generateSelfSignedPair(dir, "other", "other-client");
	certificatePem = primary.certificatePem;
	privateKeyPem = primary.privateKeyPem;
	otherPrivateKeyPem = other.privateKeyPem;
	await rm(dir, { recursive: true, force: true });
});

async function site() {
	return (await createSite({ name: "mTLS test", publicHost: `mtls-${crypto.randomUUID()}.test`, originUrl: "http://origin.test" })).site;
}

describe("validateClientCertificatePair", () => {
	test("accepts a valid self-signed certificate and matching key", () => {
		const result = validateClientCertificatePair(certificatePem, privateKeyPem);
		expect(result.certificatePem).toContain("BEGIN CERTIFICATE");
		expect(result.privateKeyPem).toContain("BEGIN PRIVATE KEY");
	});

	test("rejects a mismatched key", () => {
		expect(() => validateClientCertificatePair(certificatePem, otherPrivateKeyPem)).toThrow("does not match");
	});

	test("rejects malformed PEM", () => {
		expect(() => validateClientCertificatePair("not a certificate", privateKeyPem)).toThrow("does not contain a certificate");
		expect(() => validateClientCertificatePair(certificatePem, "not a key")).toThrow();
	});

	test("rejects oversized input", () => {
		expect(() => validateClientCertificatePair("x".repeat(600_000), privateKeyPem)).toThrow("at most 512 KB");
		expect(() => validateClientCertificatePair(certificatePem, "x".repeat(300_000))).toThrow("at most 256 KB");
	});
});

describe("validateCaBundle", () => {
	test("accepts a valid certificate", () => {
		expect(validateCaBundle(certificatePem)).toContain("BEGIN CERTIFICATE");
	});

	test("rejects malformed PEM", () => {
		expect(() => validateCaBundle("not a certificate")).toThrow("does not contain a certificate");
	});

	test("rejects oversized input", () => {
		expect(() => validateCaBundle("x".repeat(600_000))).toThrow("at most 512 KB");
	});
});

describe("origin mTLS create/update", () => {
	test("enabling without a certificate is rejected", async () => {
		const s = await site();
		await expect(createOrigin(s.id, { name: "no-cert", originUrl: "https://backend.test", mtlsEnabled: true })).rejects.toThrow("required to enable mTLS");
	});

	test("supplying a certificate persists it encrypted, never in plaintext", async () => {
		const s = await site();
		const origin = await createOrigin(s.id, {
			name: "with-cert",
			originUrl: "https://backend.test",
			mtlsEnabled: true,
			mtlsCertificatePem: certificatePem,
			mtlsPrivateKeyPem: privateKeyPem,
		});
		expect(origin.mtls_enabled).toBe(1);
		expect(origin.mtls_certificate_pem).toContain("BEGIN CERTIFICATE");
		expect(origin.mtls_encrypted_private_key).not.toContain("BEGIN PRIVATE KEY");
		expect(await decryptSecret(origin.mtls_encrypted_private_key!)).toContain("BEGIN PRIVATE KEY");

		const view = originView(origin);
		expect(view.mtls).toEqual({ enabled: true, configured: true, caConfigured: false });
		expect(JSON.stringify(view)).not.toContain("BEGIN PRIVATE KEY");
	});

	test("leaving PEM fields blank on update keeps the existing stored values", async () => {
		const s = await site();
		const created = await createOrigin(s.id, {
			name: "keep-existing",
			originUrl: "https://backend.test",
			mtlsEnabled: true,
			mtlsCertificatePem: certificatePem,
			mtlsPrivateKeyPem: privateKeyPem,
		});
		const updated = await updateOrigin(s.id, created.id, { name: "keep-existing", originUrl: "https://backend.test", mtlsEnabled: true });
		expect(updated.mtls_certificate_pem).toBe(created.mtls_certificate_pem);
		expect(updated.mtls_encrypted_private_key).toBe(created.mtls_encrypted_private_key);
	});

	test("disabling mTLS does not clear the stored certificate", async () => {
		const s = await site();
		const created = await createOrigin(s.id, {
			name: "toggle-off",
			originUrl: "https://backend.test",
			mtlsEnabled: true,
			mtlsCertificatePem: certificatePem,
			mtlsPrivateKeyPem: privateKeyPem,
		});
		const disabled = await updateOrigin(s.id, created.id, { name: "toggle-off", originUrl: "https://backend.test", mtlsEnabled: false });
		expect(disabled.mtls_enabled).toBe(0);
		expect(disabled.mtls_certificate_pem).toBe(created.mtls_certificate_pem);
		expect(disabled.mtls_encrypted_private_key).toBe(created.mtls_encrypted_private_key);
	});

	test("a trusted CA bundle can be stored alongside the client certificate", async () => {
		const s = await site();
		const origin = await createOrigin(s.id, {
			name: "with-ca",
			originUrl: "https://backend.test",
			mtlsEnabled: true,
			mtlsCertificatePem: certificatePem,
			mtlsPrivateKeyPem: privateKeyPem,
			mtlsCaPem: certificatePem,
		});
		expect(origin.mtls_ca_pem).toContain("BEGIN CERTIFICATE");
		expect(originView(origin).mtls.caConfigured).toBe(true);
	});
});

describe("originMtlsFetchOptions", () => {
	test("returns no tls override when disabled, unconfigured, or null", async () => {
		const s = await site();
		const disabled = await createOrigin(s.id, { name: "disabled", originUrl: "https://backend.test" });
		expect(await originMtlsFetchOptions(disabled)).toEqual({});
		expect(await originMtlsFetchOptions(null)).toEqual({});
	});

	test("returns the decrypted client cert/key when enabled, plus ca when configured", async () => {
		const s = await site();
		const origin = await createOrigin(s.id, {
			name: "enabled",
			originUrl: "https://backend.test",
			mtlsEnabled: true,
			mtlsCertificatePem: certificatePem,
			mtlsPrivateKeyPem: privateKeyPem,
			mtlsCaPem: certificatePem,
		});
		const options = await originMtlsFetchOptions(origin);
		expect(options.tls?.cert).toContain("BEGIN CERTIFICATE");
		expect(options.tls?.key).toContain("BEGIN PRIVATE KEY");
		expect(options.tls?.ca).toContain("BEGIN CERTIFICATE");
	});

	test("omits ca when no CA bundle is stored", async () => {
		const s = await site();
		const origin = await createOrigin(s.id, {
			name: "no-ca",
			originUrl: "https://backend.test",
			mtlsEnabled: true,
			mtlsCertificatePem: certificatePem,
			mtlsPrivateKeyPem: privateKeyPem,
		});
		const options = await originMtlsFetchOptions(origin);
		expect(options.tls?.ca).toBeUndefined();
	});

	test("applies ca even when mTLS (client cert) is disabled - the origin-cert-trust-only use case", async () => {
		const s = await site();
		const origin = await createOrigin(s.id, { name: "ca-only", originUrl: "https://backend.test", mtlsCaPem: certificatePem });
		expect(origin.mtls_enabled).toBe(0);
		const options = await originMtlsFetchOptions(origin);
		expect(options.tls?.ca).toContain("BEGIN CERTIFICATE");
		expect(options.tls?.cert).toBeUndefined();
		expect(options.tls?.key).toBeUndefined();
	});
});

describe("generateClientCertificate", () => {
	test("returns a valid, self-consistent certificate and key", async () => {
		const generated = await generateClientCertificate("burrowgate-origin-test", 1);
		expect(generated.certificatePem).toContain("BEGIN CERTIFICATE");
		expect(generated.privateKeyPem).toContain("BEGIN PRIVATE KEY");
		expect(() => validateClientCertificatePair(generated.certificatePem, generated.privateKeyPem)).not.toThrow();
	});
});

describe("generateOriginMtlsCertificate", () => {
	test("generates, encrypts, and enables mTLS on the origin", async () => {
		const s = await site();
		const created = await createOrigin(s.id, { name: "generate-me", originUrl: "https://backend.test" });
		const origin = await generateOriginMtlsCertificate(s.id, created.id);
		expect(origin.mtls_enabled).toBe(1);
		expect(origin.mtls_certificate_pem).toContain("BEGIN CERTIFICATE");
		expect(origin.mtls_encrypted_private_key).not.toContain("BEGIN PRIVATE KEY");
		expect(await decryptSecret(origin.mtls_encrypted_private_key!)).toContain("BEGIN PRIVATE KEY");
		expect(originView(origin).mtls.configured).toBe(true);
	});

	test("calling it again replaces the stored certificate", async () => {
		const s = await site();
		const created = await createOrigin(s.id, { name: "regenerate-me", originUrl: "https://backend.test" });
		const first = await generateOriginMtlsCertificate(s.id, created.id);
		const second = await generateOriginMtlsCertificate(s.id, created.id);
		expect(second.mtls_certificate_pem).not.toBe(first.mtls_certificate_pem);
		expect(second.mtls_encrypted_private_key).not.toBe(first.mtls_encrypted_private_key);
	});
});

describe("generateOriginCertificate", () => {
	test("returns a valid pair whose SAN covers the site's public hostname", async () => {
		const s = await site();
		const origin = await createOrigin(s.id, { name: "origin-cert-san", originUrl: "https://10.9.9.9:8443" });
		const generated = await generateOriginCertificate(s, origin, 1);
		expect(() => validateClientCertificatePair(generated.certificatePem, generated.privateKeyPem)).not.toThrow();
		const certificate = new X509Certificate(generated.certificatePem);
		const san = certificate.subjectAltName ?? "";
		expect(san.toLowerCase()).toContain(s.public_host.toLowerCase());
		expect(san).toContain("10.9.9.9");
	});
});

describe("generateOriginServerCertificate", () => {
	test("persists into mtls_ca_pem without touching client-cert fields, and returns the key only once", async () => {
		const s = await site();
		const created = await createOrigin(s.id, { name: "origin-cert-generate", originUrl: "https://backend.test" });
		const { origin, privateKeyPem: returnedKey } = await generateOriginServerCertificate(s, s.id, created.id);
		expect(origin.mtls_ca_pem).toContain("BEGIN CERTIFICATE");
		expect(origin.mtls_enabled).toBe(0);
		expect(origin.mtls_certificate_pem).toBeNull();
		expect(origin.mtls_encrypted_private_key).toBeNull();
		expect(returnedKey).toContain("BEGIN PRIVATE KEY");
		expect(JSON.stringify(originView(origin))).not.toContain("BEGIN PRIVATE KEY");
		// the returned private key must never be persisted anywhere on the record
		expect(JSON.stringify(origin)).not.toContain(returnedKey);
	});

	test("works independently of client-cert mTLS - a subsequent fetch trusts the origin without presenting a client cert", async () => {
		const s = await site();
		const created = await createOrigin(s.id, { name: "origin-cert-independent", originUrl: "https://backend.test" });
		const { origin } = await generateOriginServerCertificate(s, s.id, created.id);
		const options = await originMtlsFetchOptions(origin);
		expect(options.tls?.ca).toContain("BEGIN CERTIFICATE");
		expect(options.tls?.cert).toBeUndefined();
	});
});
