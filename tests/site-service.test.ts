import { describe, expect, test } from "bun:test";
import { repository } from "../src/db/repository.ts";
import { createSite, siteRestartRequired, updateSite } from "../src/services/site-service.ts";
import type { CertificateRecord, SiteRecord } from "../src/types.ts";

async function makeSite(publicHost: string): Promise<SiteRecord> {
	const { site } = await createSite({ name: "Test site", publicHost, originUrl: "https://origin.test" });
	return site;
}

function fakeCertificate(siteId: string): CertificateRecord {
	const now = Date.now();
	return {
		id: `cert_${siteId}`,
		site_id: siteId,
		source: "uploaded",
		status: "active",
		primary_domain: "placeholder.test",
		alternative_names_json: "[]",
		// No PEM material - this is enough to make `certificateBySite` return a truthy row
		// (so restart-staging kicks in) without needing real X.509 validation, since the
		// certificate-coverage re-check in updateSite only runs when certificate_pem is set.
		certificate_pem: null,
		encrypted_private_key: null,
		issuer: null,
		serial_number: null,
		valid_from: now,
		expires_at: now + 86_400_000,
		next_renewal_at: null,
		last_attempt_at: null,
		last_error: null,
		created_at: now,
		updated_at: now,
	};
}

describe("siteRestartRequired", () => {
	test("is false when the hostname is unchanged", () => {
		const existing = { public_host: "a.test" } as SiteRecord;
		const updated = { public_host: "a.test" } as SiteRecord;
		expect(siteRestartRequired(existing, updated, true)).toBe(false);
	});

	test("is false without an active certificate", () => {
		const existing = { public_host: "a.test" } as SiteRecord;
		const updated = { public_host: "b.test" } as SiteRecord;
		expect(siteRestartRequired(existing, updated, false)).toBe(false);
	});

	test("is true when the hostname changes and a certificate is present", () => {
		const existing = { public_host: "a.test" } as SiteRecord;
		const updated = { public_host: "b.test" } as SiteRecord;
		expect(siteRestartRequired(existing, updated, true)).toBe(true);
	});
});

describe("updateSite", () => {
	test("applies ordinary field changes immediately", async () => {
		const site = await makeSite("plain-update.test");
		const { site: updated, pendingChange } = await updateSite(site.id, {
			name: "Renamed site",
			publicHost: site.public_host,
			originUrl: "https://origin.test",
		});
		expect(pendingChange).toBeNull();
		expect(updated.name).toBe("Renamed site");
		expect((await repository.siteById(site.id))?.name).toBe("Renamed site");
	});

	test("applies a hostname change immediately when there is no certificate", async () => {
		const site = await makeSite("no-cert-source.test");
		const { site: updated, pendingChange } = await updateSite(site.id, {
			name: site.name,
			publicHost: "no-cert-target.test",
			originUrl: "https://origin.test",
		});
		expect(pendingChange).toBeNull();
		expect(updated.public_host).toBe("no-cert-target.test");
		expect((await repository.siteById(site.id))?.public_host).toBe("no-cert-target.test");
	});

	test("stages a hostname change with a certificate and a future effectiveAt, leaving the live host unchanged", async () => {
		const site = await makeSite("cert-source.test");
		await repository.saveCertificate(fakeCertificate(site.id));
		const effectiveAt = Date.now() + 3_600_000;

		const { site: immediate, pendingChange } = await updateSite(site.id, {
			name: site.name,
			publicHost: "cert-target.test",
			originUrl: "https://origin.test",
			effectiveAt,
		});

		expect(pendingChange).not.toBeNull();
		expect(JSON.parse(pendingChange?.changes_json ?? "{}")).toEqual({ publicHost: "cert-target.test" });
		expect(pendingChange?.apply_at).toBe(effectiveAt);
		expect(immediate.public_host).toBe("cert-source.test");
		expect((await repository.siteById(site.id))?.public_host).toBe("cert-source.test");
	});

	test("rejects a second scheduled hostname change while one is already pending", async () => {
		const site = await makeSite("cert-conflict-source.test");
		await repository.saveCertificate(fakeCertificate(site.id));
		const effectiveAt = Date.now() + 3_600_000;
		await updateSite(site.id, { name: site.name, publicHost: "cert-conflict-first.test", originUrl: "https://origin.test", effectiveAt });

		await expect(
			updateSite(site.id, {
				name: site.name,
				publicHost: "cert-conflict-second.test",
				originUrl: "https://origin.test",
				effectiveAt: effectiveAt + 60_000,
			}),
		).rejects.toThrow("already scheduled");
	});
});
