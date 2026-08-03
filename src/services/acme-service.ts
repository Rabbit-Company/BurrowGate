import { isIP } from "node:net";
import { config } from "../config.ts";
import { repository } from "../db/repository.ts";
import type { AcmeAccountRecord, AcmeHttpChallengeRecord, SiteRecord } from "../types.ts";
import { randomId } from "../utils/crypto.ts";
import { recordCertificateEvent, saveCertificate, updateTlsSettings } from "./certificate-service.ts";
import { assertSecretEncryptionConfigured, decryptSecret, encryptSecret } from "./secret-encryption-service.ts";
import { requestTlsReload } from "./tls-listener-service.ts";

const issuanceLocks = new Set<string>();

interface AcmeModule {
	Client: new (options: Record<string, unknown>) => {
		createAccount(data: Record<string, unknown>): Promise<unknown>;
		updateAccount(data: Record<string, unknown>): Promise<unknown>;
		getAccountUrl(): string;
		auto(options: Record<string, unknown>): Promise<string>;
	};
	crypto: {
		createPrivateEcdsaKey(): Promise<Uint8Array | Buffer>;
		createCsr(data: Record<string, unknown>): Promise<[Uint8Array | Buffer, Uint8Array | Buffer]>;
	};
}

async function acmeModule(): Promise<AcmeModule> {
	return (await import("acme-client")) as unknown as AcmeModule;
}

function text(value: Uint8Array | Buffer): string {
	return Buffer.from(value).toString("utf8");
}

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

function validateAcmeHostname(site: SiteRecord): string {
	const parsed = new URL(`http://${site.public_host}`);
	const hostname = parsed.hostname.toLowerCase();
	if (parsed.port) throw new Error("Let's Encrypt HTTP-01 requires a public hostname without a custom port");
	if (hostname === "localhost" || hostname.endsWith(".local") || hostname.endsWith(".localhost") || isIP(hostname)) {
		throw new Error("Let's Encrypt requires a publicly reachable DNS hostname; use an uploaded development certificate for local addresses");
	}
	return hostname;
}

async function clientFor(directoryUrl: string, email: string): Promise<{ client: InstanceType<AcmeModule["Client"]>; account: AcmeAccountRecord }> {
	const acme = await acmeModule();
	const existing = await repository.acmeAccount(directoryUrl);
	if (existing) {
		const client = new acme.Client({
			directoryUrl,
			accountKey: await decryptSecret(existing.encrypted_account_key),
			...(existing.account_url ? { accountUrl: existing.account_url } : {}),
		});
		if (existing.email !== email) {
			await client.updateAccount({ contact: [`mailto:${email}`] });
			const updated = { ...existing, email, updated_at: Date.now() };
			await repository.saveAcmeAccount(updated);
			return { client, account: updated };
		}
		return { client, account: existing };
	}

	const keyPem = text(await acme.crypto.createPrivateEcdsaKey());
	const client = new acme.Client({ directoryUrl, accountKey: keyPem });
	await client.createAccount({ termsOfServiceAgreed: true, contact: [`mailto:${email}`] });
	const now = Date.now();
	const account: AcmeAccountRecord = {
		id: randomId("acme_account"),
		directory_url: directoryUrl,
		email,
		account_url: client.getAccountUrl(),
		encrypted_account_key: await encryptSecret(keyPem),
		terms_accepted_at: now,
		created_at: now,
		updated_at: now,
	};
	await repository.saveAcmeAccount(account);
	return { client, account };
}

export async function issueLetsEncryptCertificate(
	site: SiteRecord,
	input: {
		email?: string | null;
		directoryUrl?: string | null;
		forceHttps?: boolean;
		termsAccepted: boolean;
		renewal?: boolean;
	},
): Promise<void> {
	if (!input.termsAccepted && !input.renewal) throw new Error("You must accept the ACME provider's terms of service");
	if (issuanceLocks.has(site.id)) throw new Error("Certificate issuance is already running for this site");
	issuanceLocks.add(site.id);
	const attemptedAt = Date.now();
	const existingCertificate = await repository.certificateBySite(site.id);
	const settings = await repository.ensureTlsSettings(site.id);
	const email = (input.email ?? settings.acme_email ?? config.acme.email)?.trim();
	const directoryUrl = (input.directoryUrl ?? settings.acme_directory_url ?? config.acme.directoryUrl)?.trim();
	try {
		if (!config.http.enabled) {
			throw new Error("HTTP-01 issuance requires BurrowGate's HTTP listener to be enabled");
		}
		if (config.http.publicPort !== 80) {
			throw new Error("HTTP-01 issuance requires BG_HTTP_PUBLIC_PORT=80 so the hostname is reachable from the internet on port 80");
		}
		if (!email || !/^\S+@\S+\.\S+$/u.test(email)) throw new Error("A valid ACME contact email is required");
		if (!directoryUrl) throw new Error("An ACME directory URL is required");
		let parsedDirectory: URL;
		try {
			parsedDirectory = new URL(directoryUrl);
		} catch {
			throw new Error("ACME directory URL is invalid");
		}
		if (parsedDirectory.protocol !== "https:") throw new Error("ACME directory URL must use HTTPS");
		const hostname = validateAcmeHostname(site);
		await assertSecretEncryptionConfigured();
		await recordCertificateEvent(
			site.id,
			existingCertificate?.id ?? null,
			"info",
			input.renewal ? "Starting certificate renewal" : "Starting certificate issuance",
			{ hostname, directoryUrl },
		);

		const acme = await acmeModule();
		const { client } = await clientFor(directoryUrl, email);
		const [certificateKey, certificateCsr] = await acme.crypto.createCsr({ commonName: hostname, altNames: [hostname] });
		const certificatePem = await client.auto({
			csr: certificateCsr,
			email,
			termsOfServiceAgreed: true,
			challengePriority: ["http-01"],
			skipChallengeVerification: config.acme.skipInternalChallengeVerification,
			challengeCreateFn: async (authorization: any, challenge: any, keyAuthorization: string) => {
				if (challenge.type !== "http-01") throw new Error(`Unsupported ACME challenge type: ${challenge.type}`);
				const challengeHostname = String(authorization.identifier?.value ?? "").toLowerCase();
				if (challengeHostname !== hostname) throw new Error("ACME authorization hostname does not match the site hostname");
				const now = Date.now();
				const record: AcmeHttpChallengeRecord = {
					token: String(challenge.token),
					site_id: site.id,
					hostname,
					key_authorization: keyAuthorization,
					created_at: now,
					expires_at: now + config.acme.challengeTtlSeconds * 1_000,
				};
				await repository.saveAcmeChallenge(record);
				await recordCertificateEvent(site.id, existingCertificate?.id ?? null, "info", "Published HTTP-01 challenge", { hostname, token: record.token });
			},
			challengeRemoveFn: async (_authorization: any, challenge: any) => {
				await repository.deleteAcmeChallenge(String(challenge.token));
			},
		});

		const certificate = await saveCertificate({
			site,
			source: "letsencrypt",
			certificatePem,
			privateKeyPem: text(certificateKey),
			lastAttemptAt: attemptedAt,
		});
		await updateTlsSettings(site, {
			mode: "letsencrypt",
			forceHttps: input.forceHttps ?? settings.force_https === 1,
			acmeEmail: email,
			acmeDirectoryUrl: directoryUrl,
		});
		await repository.deleteAcmeChallengesForSite(site.id);
		await recordCertificateEvent(site.id, certificate.id, "info", input.renewal ? "Certificate renewed successfully" : "Certificate issued successfully", {
			expiresAt: certificate.expires_at,
			issuer: certificate.issuer,
		});
		await requestTlsReload();
	} catch (error) {
		const message = errorMessage(error);
		await repository.updateCertificateAttempt(site.id, attemptedAt, message);
		await recordCertificateEvent(
			site.id,
			existingCertificate?.id ?? null,
			"error",
			input.renewal ? "Certificate renewal failed" : "Certificate issuance failed",
			{ error: message },
		);
		throw error;
	} finally {
		await repository.deleteAcmeChallengesForSite(site.id).catch(() => undefined);
		issuanceLocks.delete(site.id);
	}
}

export async function renewDueCertificates(): Promise<void> {
	const records = await repository.dueAcmeCertificates(Date.now());
	for (const record of records) {
		const site = await repository.siteById(record.site_id);
		if (!site || issuanceLocks.has(site.id)) continue;
		const settings = await repository.ensureTlsSettings(site.id);
		try {
			await issueLetsEncryptCertificate(site, {
				email: settings.acme_email,
				directoryUrl: settings.acme_directory_url,
				forceHttps: settings.force_https === 1,
				termsAccepted: true,
				renewal: true,
			});
		} catch (error) {
			console.error(`[BurrowGate] ACME renewal failed for ${site.public_host}`, error);
		}
	}
}
