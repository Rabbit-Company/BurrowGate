import { afterEach, describe, expect, test } from "bun:test";
import { X509Certificate } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { config } from "../src/config.ts";
import { bootstrapTlsOption } from "../src/services/bootstrap-tls-service.ts";
import {
	haTlsCertificate,
	pinnedHaTlsOptions,
	pinPrimaryHaCertificate,
	readPinnedHaCertificate,
	resetHaTlsCertificateCache,
} from "../src/services/ha-tls-service.ts";

const originalDataDirectory = config.dataDirectory;
const originalCaFile = config.ha.caFile;
const originalBootstrapTls = config.bootstrapTls;
const originalHaEnabled = config.ha.enabled;
const originalHaTlsCertFile = config.ha.tlsCertFile;
const originalHaTlsKeyFile = config.ha.tlsKeyFile;
const originalSelfAdminUrl = config.ha.selfAdminUrl;
let tempDir = "";

afterEach(async () => {
	config.dataDirectory = originalDataDirectory;
	config.ha.caFile = originalCaFile;
	config.bootstrapTls = originalBootstrapTls;
	config.ha.enabled = originalHaEnabled;
	config.ha.tlsCertFile = originalHaTlsCertFile;
	config.ha.tlsKeyFile = originalHaTlsKeyFile;
	config.ha.selfAdminUrl = originalSelfAdminUrl;
	resetHaTlsCertificateCache();
	if (tempDir) {
		await rm(tempDir, { recursive: true, force: true });
		tempDir = "";
	}
});

describe("readPinnedHaCertificate / pinnedHaTlsOptions", () => {
	test("returns null/undefined when nothing has ever been pinned", async () => {
		tempDir = await mkdtemp(join(tmpdir(), "bg-ha-tls-test-"));
		config.dataDirectory = tempDir;

		expect(await readPinnedHaCertificate()).toBeNull();
		expect(await pinnedHaTlsOptions()).toBeUndefined();
	});

	test("returns the pinned certificate once one has been pinned", async () => {
		tempDir = await mkdtemp(join(tmpdir(), "bg-ha-tls-test-"));
		config.dataDirectory = tempDir;
		await pinPrimaryHaCertificate("pinned-cert-bytes");

		expect(await readPinnedHaCertificate()).toBe("pinned-cert-bytes");
		expect(await pinnedHaTlsOptions()).toMatchObject({ ca: "pinned-cert-bytes", checkServerIdentity: expect.any(Function) });
	});

	test("checkServerIdentity always returns undefined (never rejects) once pinned", async () => {
		tempDir = await mkdtemp(join(tmpdir(), "bg-ha-tls-test-"));
		config.dataDirectory = tempDir;
		await pinPrimaryHaCertificate("pinned-cert-bytes");

		const options = await pinnedHaTlsOptions();
		expect(options?.checkServerIdentity()).toBeUndefined();
	});

	test("BG_HA_CA_FILE takes precedence over the pinned file when both exist", async () => {
		tempDir = await mkdtemp(join(tmpdir(), "bg-ha-tls-test-"));
		config.dataDirectory = tempDir;
		await pinPrimaryHaCertificate("pinned-cert-bytes");
		const caFilePath = join(tempDir, "manual-ca.pem");
		await writeFile(caFilePath, "manually-provided-ca-bytes");
		config.ha.caFile = caFilePath;

		expect(await readPinnedHaCertificate()).toBe("manually-provided-ca-bytes");
	});
});

describe("bootstrapTlsOption reuses the HA mesh certificate when HA is enabled", () => {
	test("returns undefined when bootstrap TLS is disabled, regardless of HA", async () => {
		config.bootstrapTls = false;
		config.ha.enabled = true;

		expect(await bootstrapTlsOption()).toBeNull();
	});

	test("returns the exact same certificate and key as the HA mesh listener's own, not a separately generated one", async () => {
		tempDir = await mkdtemp(join(tmpdir(), "bg-ha-tls-test-"));
		config.dataDirectory = tempDir;
		config.bootstrapTls = true;
		config.ha.enabled = true;
		config.ha.tlsCertFile = null;
		config.ha.tlsKeyFile = null;

		const meshCertificate = await haTlsCertificate();
		const bootstrap = await bootstrapTlsOption();

		expect(bootstrap?.cert).toBe(meshCertificate.cert);
		expect(bootstrap?.key).toBe(meshCertificate.key);
	});

	test("falls back to its own separately generated certificate when HA is disabled", async () => {
		tempDir = await mkdtemp(join(tmpdir(), "bg-ha-tls-test-"));
		config.dataDirectory = tempDir;
		config.bootstrapTls = true;
		config.ha.enabled = false;

		const bootstrap = await bootstrapTlsOption();

		expect(bootstrap).not.toBeNull();
		expect(await Bun.file(join(tempDir, "tls", "ha-cert.pem")).exists()).toBe(false);
		expect(await Bun.file(join(tempDir, "tls", "bootstrap-cert.pem")).exists()).toBe(true);
	});
});

describe("haTlsCertificate caches for the life of the process", () => {
	test("a second call returns the exact same certificate even if the on-disk file changes in between", async () => {
		tempDir = await mkdtemp(join(tmpdir(), "bg-ha-tls-test-"));
		config.dataDirectory = tempDir;
		config.ha.tlsCertFile = null;
		config.ha.tlsKeyFile = null;

		const first = await haTlsCertificate();
		await rm(join(tempDir, "tls", "ha-cert.pem"), { force: true });
		await rm(join(tempDir, "tls", "ha-key.pem"), { force: true });
		const second = await haTlsCertificate();

		expect(second.cert).toBe(first.cert);
		expect(second.key).toBe(first.key);
	});

	test("resetHaTlsCertificateCache lets a later call pick up a genuinely new certificate", async () => {
		tempDir = await mkdtemp(join(tmpdir(), "bg-ha-tls-test-"));
		config.dataDirectory = tempDir;
		config.ha.tlsCertFile = null;
		config.ha.tlsKeyFile = null;

		const first = await haTlsCertificate();
		await rm(join(tempDir, "tls", "ha-cert.pem"), { force: true });
		await rm(join(tempDir, "tls", "ha-key.pem"), { force: true });
		resetHaTlsCertificateCache();
		const second = await haTlsCertificate();

		expect(second.cert).not.toBe(first.cert);
	});
});

describe("the generated certificate's SAN covers this node's actual reachable address", () => {
	test("includes this node's configured admin URL host as an IP SAN entry when it's an IP literal", async () => {
		tempDir = await mkdtemp(join(tmpdir(), "bg-ha-tls-test-"));
		config.dataDirectory = tempDir;
		config.ha.tlsCertFile = null;
		config.ha.tlsKeyFile = null;
		config.ha.selfAdminUrl = "https://10.20.30.40";

		const { cert } = await haTlsCertificate();

		const san = new X509Certificate(cert).subjectAltName ?? "";
		expect(san).toContain("IP Address:10.20.30.40");
		expect(san).toContain("127.0.0.1");
		expect(san).toContain("localhost");
	});

	test("includes this node's configured admin URL host as a DNS SAN entry when it's a hostname", async () => {
		tempDir = await mkdtemp(join(tmpdir(), "bg-ha-tls-test-"));
		config.dataDirectory = tempDir;
		config.ha.tlsCertFile = null;
		config.ha.tlsKeyFile = null;
		config.ha.selfAdminUrl = "https://primary.internal.example";

		const { cert } = await haTlsCertificate();

		const san = new X509Certificate(cert).subjectAltName ?? "";
		expect(san).toContain("DNS:primary.internal.example");
	});

	test("still generates a usable certificate (loopback SAN only) when no admin URL is configured yet", async () => {
		tempDir = await mkdtemp(join(tmpdir(), "bg-ha-tls-test-"));
		config.dataDirectory = tempDir;
		config.ha.tlsCertFile = null;
		config.ha.tlsKeyFile = null;
		config.ha.selfAdminUrl = null;

		const { cert } = await haTlsCertificate();

		const san = new X509Certificate(cert).subjectAltName ?? "";
		expect(san).toContain("127.0.0.1");
		expect(san).toContain("localhost");
	});

	test("regenerates instead of reusing an existing certificate whose SAN doesn't cover the current admin URL", async () => {
		tempDir = await mkdtemp(join(tmpdir(), "bg-ha-tls-test-"));
		config.dataDirectory = tempDir;
		config.ha.tlsCertFile = null;
		config.ha.tlsKeyFile = null;
		config.ha.selfAdminUrl = null;

		const stale = await haTlsCertificate();
		expect(new X509Certificate(stale.cert).subjectAltName ?? "").not.toContain("10.1.80.1");

		resetHaTlsCertificateCache();
		config.ha.selfAdminUrl = "https://10.1.80.1";
		const regenerated = await haTlsCertificate();

		expect(regenerated.cert).not.toBe(stale.cert);
		expect(new X509Certificate(regenerated.cert).subjectAltName ?? "").toContain("IP Address:10.1.80.1");
	});

	test("keeps reusing an existing certificate whose SAN already covers the current admin URL", async () => {
		tempDir = await mkdtemp(join(tmpdir(), "bg-ha-tls-test-"));
		config.dataDirectory = tempDir;
		config.ha.tlsCertFile = null;
		config.ha.tlsKeyFile = null;
		config.ha.selfAdminUrl = "https://10.1.80.1";

		const first = await haTlsCertificate();
		resetHaTlsCertificateCache();
		const second = await haTlsCertificate();

		expect(second.cert).toBe(first.cert);
	});
});
