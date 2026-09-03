import { afterEach, describe, expect, test } from "bun:test";
import { config } from "../src/config.ts";
import { repository } from "../src/db/repository.ts";
import { createSite, outboundFetchProtocolOption, seedDefaultSite, siteRestartRequired, siteView, updateSite } from "../src/services/site-service.ts";
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

describe("outbound fetch protocol", () => {
	test("defaults to http1 on create when omitted", async () => {
		const site = await makeSite("outbound-default.test");
		expect(site.outbound_fetch_protocol).toBe("http1");
		expect(siteView(site).outboundFetchProtocol).toBe("http1");
	});

	test("accepts http1, http2, and http3 and round-trips through create/update/siteView", async () => {
		const site = await makeSite("outbound-roundtrip.test");
		for (const protocol of ["http2", "http3", "http1"] as const) {
			const { site: updated } = await updateSite(site.id, {
				name: site.name,
				publicHost: site.public_host,
				originUrl: site.origin_url,
				outboundFetchProtocol: protocol,
			});
			expect(updated.outbound_fetch_protocol).toBe(protocol);
			expect(siteView(updated).outboundFetchProtocol).toBe(protocol);
			expect((await repository.siteById(site.id))?.outbound_fetch_protocol).toBe(protocol);
		}
	});

	test("rejects an invalid protocol value", async () => {
		const site = await makeSite("outbound-invalid.test");
		await expect(
			updateSite(site.id, {
				name: site.name,
				publicHost: site.public_host,
				originUrl: site.origin_url,
				outboundFetchProtocol: "http99",
			}),
		).rejects.toThrow("Outbound fetch protocol must be http1, http2, or http3");
	});

	test("keeps the existing protocol when the field is omitted from an update", async () => {
		const site = await makeSite("outbound-preserve.test");
		await updateSite(site.id, { name: site.name, publicHost: site.public_host, originUrl: site.origin_url, outboundFetchProtocol: "http2" });
		const { site: updated } = await updateSite(site.id, { name: "Renamed", publicHost: site.public_host, originUrl: site.origin_url });
		expect(updated.outbound_fetch_protocol).toBe("http2");
	});
});

describe("outboundFetchProtocolOption", () => {
	test("omits the protocol option for http1 (default, current behavior)", () => {
		expect(outboundFetchProtocolOption({ outbound_fetch_protocol: "http1" } as SiteRecord)).toEqual({});
	});

	test("omits the protocol option when unset", () => {
		expect(outboundFetchProtocolOption({} as SiteRecord)).toEqual({});
	});

	test("passes protocol: http2 through", () => {
		expect(outboundFetchProtocolOption({ outbound_fetch_protocol: "http2" } as SiteRecord)).toEqual({ protocol: "http2" });
	});

	test("passes protocol: http3 through", () => {
		expect(outboundFetchProtocolOption({ outbound_fetch_protocol: "http3" } as SiteRecord)).toEqual({ protocol: "http3" } as unknown as Pick<
			BunFetchRequestInit,
			"protocol"
		>);
	});
});

describe("seedDefaultSite", () => {
	let previousEnabled: boolean;
	let previousRole: typeof config.ha.role;
	let previousSeed: boolean;

	afterEach(() => {
		config.ha.enabled = previousEnabled;
		config.ha.role = previousRole;
		config.seedDefaultSite = previousSeed;
	});

	test("does not seed (or throw) on a replica", async () => {
		previousEnabled = config.ha.enabled;
		previousRole = config.ha.role;
		previousSeed = config.seedDefaultSite;
		config.ha.enabled = true;
		config.ha.role = "replica";
		config.seedDefaultSite = true;
		const countBefore = (await repository.allSites()).length;

		await expect(seedDefaultSite()).resolves.toBeUndefined();
		expect((await repository.allSites()).length).toBe(countBefore);
	});
});

describe("per-provider challenge templates", () => {
	const validTemplate = (label: string) => `<html><body>${label}{{challengeScript}}</body></html>`;

	test("a fresh site has no per-provider overrides", async () => {
		const site = await makeSite("challenge-templates-fresh.test");
		expect(siteView(site).challengePage.templates).toEqual({});
	});

	test("setting one provider's template does not affect others", async () => {
		const site = await makeSite("challenge-templates-set.test");
		const { site: updated } = await updateSite(site.id, {
			name: site.name,
			publicHost: site.public_host,
			originUrl: site.origin_url,
			challengeHtmlTemplates: { snake: validTemplate("snake") },
		});
		expect(siteView(updated).challengePage.templates).toEqual({ snake: validTemplate("snake") });
	});

	test("a second update touching a different provider merges rather than replacing the first", async () => {
		const site = await makeSite("challenge-templates-merge.test");
		const first = await updateSite(site.id, {
			name: site.name,
			publicHost: site.public_host,
			originUrl: site.origin_url,
			challengeHtmlTemplates: { snake: validTemplate("snake") },
		});
		const { site: updated } = await updateSite(first.site.id, {
			name: site.name,
			publicHost: site.public_host,
			originUrl: site.origin_url,
			challengeHtmlTemplates: { password: validTemplate("password") },
		});
		expect(siteView(updated).challengePage.templates).toEqual({
			snake: validTemplate("snake"),
			password: validTemplate("password"),
		});
	});

	test("a blank value removes just that provider's override", async () => {
		const site = await makeSite("challenge-templates-clear.test");
		const first = await updateSite(site.id, {
			name: site.name,
			publicHost: site.public_host,
			originUrl: site.origin_url,
			challengeHtmlTemplates: { snake: validTemplate("snake"), password: validTemplate("password") },
		});
		const { site: updated } = await updateSite(first.site.id, {
			name: site.name,
			publicHost: site.public_host,
			originUrl: site.origin_url,
			challengeHtmlTemplates: { snake: "" },
		});
		expect(siteView(updated).challengePage.templates).toEqual({ password: validTemplate("password") });
	});

	test("omitting challengeHtmlTemplates entirely leaves existing overrides untouched", async () => {
		const site = await makeSite("challenge-templates-omit.test");
		const first = await updateSite(site.id, {
			name: site.name,
			publicHost: site.public_host,
			originUrl: site.origin_url,
			challengeHtmlTemplates: { snake: validTemplate("snake") },
		});
		const { site: updated } = await updateSite(first.site.id, { name: "Renamed", publicHost: site.public_host, originUrl: site.origin_url });
		expect(siteView(updated).challengePage.templates).toEqual({ snake: validTemplate("snake") });
	});

	test("rejects a per-provider template missing the required challengeScript placeholder", async () => {
		const site = await makeSite("challenge-templates-invalid.test");
		await expect(
			updateSite(site.id, {
				name: site.name,
				publicHost: site.public_host,
				originUrl: site.origin_url,
				challengeHtmlTemplates: { snake: "<html><body>no placeholder</body></html>" },
			}),
		).rejects.toThrow("challengeScript");
	});
});

describe("per-provider challenge text overrides", () => {
	test("a fresh site has no text overrides", async () => {
		const site = await makeSite("challenge-texts-fresh.test");
		expect(siteView(site).challengePage.textOverrides).toEqual({});
	});

	test("setting one provider's text key does not affect others", async () => {
		const site = await makeSite("challenge-texts-set.test");
		const { site: updated } = await updateSite(site.id, {
			name: site.name,
			publicHost: site.public_host,
			originUrl: site.origin_url,
			challengeTextOverrides: { snake: { goal: "Iss Äpfel" } },
		});
		expect(siteView(updated).challengePage.textOverrides).toEqual({ snake: { goal: "Iss Äpfel" } });
	});

	test("a second update touching a different provider merges rather than replacing the first", async () => {
		const site = await makeSite("challenge-texts-merge-provider.test");
		const first = await updateSite(site.id, {
			name: site.name,
			publicHost: site.public_host,
			originUrl: site.origin_url,
			challengeTextOverrides: { snake: { goal: "Iss Äpfel" } },
		});
		const { site: updated } = await updateSite(first.site.id, {
			name: site.name,
			publicHost: site.public_host,
			originUrl: site.origin_url,
			challengeTextOverrides: { password: { submitLabel: "Weiter" } },
		});
		expect(siteView(updated).challengePage.textOverrides).toEqual({
			snake: { goal: "Iss Äpfel" },
			password: { submitLabel: "Weiter" },
		});
	});

	test("overriding one key within a provider does not wipe that provider's other saved keys", async () => {
		const site = await makeSite("challenge-texts-merge-key.test");
		const first = await updateSite(site.id, {
			name: site.name,
			publicHost: site.public_host,
			originUrl: site.origin_url,
			challengeTextOverrides: { snake: { goal: "Iss Äpfel", wallHit: "Die Schlange traf eine Wand." } },
		});
		const { site: updated } = await updateSite(first.site.id, {
			name: site.name,
			publicHost: site.public_host,
			originUrl: site.origin_url,
			challengeTextOverrides: { snake: { selfHit: "Die Schlange hat sich selbst getroffen." } },
		});
		expect(siteView(updated).challengePage.textOverrides).toEqual({
			snake: {
				goal: "Iss Äpfel",
				wallHit: "Die Schlange traf eine Wand.",
				selfHit: "Die Schlange hat sich selbst getroffen.",
			},
		});
	});

	test("a blank value removes just that key, leaving the provider's other keys intact", async () => {
		const site = await makeSite("challenge-texts-clear-key.test");
		const first = await updateSite(site.id, {
			name: site.name,
			publicHost: site.public_host,
			originUrl: site.origin_url,
			challengeTextOverrides: { snake: { goal: "Iss Äpfel", wallHit: "Die Schlange traf eine Wand." } },
		});
		const { site: updated } = await updateSite(first.site.id, {
			name: site.name,
			publicHost: site.public_host,
			originUrl: site.origin_url,
			challengeTextOverrides: { snake: { wallHit: "" } },
		});
		expect(siteView(updated).challengePage.textOverrides).toEqual({ snake: { goal: "Iss Äpfel" } });
	});

	test("clearing every key of a provider drops that provider entirely", async () => {
		const site = await makeSite("challenge-texts-clear-provider.test");
		const first = await updateSite(site.id, {
			name: site.name,
			publicHost: site.public_host,
			originUrl: site.origin_url,
			challengeTextOverrides: { snake: { goal: "Iss Äpfel" }, password: { submitLabel: "Weiter" } },
		});
		const { site: updated } = await updateSite(first.site.id, {
			name: site.name,
			publicHost: site.public_host,
			originUrl: site.origin_url,
			challengeTextOverrides: { snake: { goal: "" } },
		});
		expect(siteView(updated).challengePage.textOverrides).toEqual({ password: { submitLabel: "Weiter" } });
	});

	test("omitting challengeTextOverrides entirely leaves existing overrides untouched", async () => {
		const site = await makeSite("challenge-texts-omit.test");
		const first = await updateSite(site.id, {
			name: site.name,
			publicHost: site.public_host,
			originUrl: site.origin_url,
			challengeTextOverrides: { snake: { goal: "Iss Äpfel" } },
		});
		const { site: updated } = await updateSite(first.site.id, { name: "Renamed", publicHost: site.public_host, originUrl: site.origin_url });
		expect(siteView(updated).challengePage.textOverrides).toEqual({ snake: { goal: "Iss Äpfel" } });
	});
});

describe("per-provider challenge CSP overrides", () => {
	test("a fresh site has no CSP overrides", async () => {
		const site = await makeSite("challenge-csp-fresh.test");
		expect(siteView(site).challengePage.cspOverrides).toEqual({});
	});

	test("setting one provider's field does not affect others", async () => {
		const site = await makeSite("challenge-csp-set.test");
		const { site: updated } = await updateSite(site.id, {
			name: site.name,
			publicHost: site.public_host,
			originUrl: site.origin_url,
			challengeCspOverrides: { slider: { imgSrc: "https://cdn.example.com" } },
		});
		expect(siteView(updated).challengePage.cspOverrides).toEqual({ slider: { imgSrc: ["https://cdn.example.com"] } });
	});

	test("a second update touching a different provider merges rather than replacing the first", async () => {
		const site = await makeSite("challenge-csp-merge-provider.test");
		const first = await updateSite(site.id, {
			name: site.name,
			publicHost: site.public_host,
			originUrl: site.origin_url,
			challengeCspOverrides: { slider: { imgSrc: "https://cdn.example.com" } },
		});
		const { site: updated } = await updateSite(first.site.id, {
			name: site.name,
			publicHost: site.public_host,
			originUrl: site.origin_url,
			challengeCspOverrides: { snake: { imgSrc: "https://other.example.com" } },
		});
		expect(siteView(updated).challengePage.cspOverrides).toEqual({
			slider: { imgSrc: ["https://cdn.example.com"] },
			snake: { imgSrc: ["https://other.example.com"] },
		});
	});

	test("overriding one field within a provider does not wipe that provider's other saved fields", async () => {
		const site = await makeSite("challenge-csp-merge-field.test");
		const first = await updateSite(site.id, {
			name: site.name,
			publicHost: site.public_host,
			originUrl: site.origin_url,
			challengeCspOverrides: { slider: { imgSrc: "https://cdn.example.com", scriptSrc: "https://scripts.example.com" } },
		});
		const { site: updated } = await updateSite(first.site.id, {
			name: site.name,
			publicHost: site.public_host,
			originUrl: site.origin_url,
			challengeCspOverrides: { slider: { connectSrc: "https://api.example.com" } },
		});
		expect(siteView(updated).challengePage.cspOverrides).toEqual({
			slider: {
				imgSrc: ["https://cdn.example.com"],
				scriptSrc: ["https://scripts.example.com"],
				connectSrc: ["https://api.example.com"],
			},
		});
	});

	test("a blank value removes just that field, leaving the provider's other fields intact", async () => {
		const site = await makeSite("challenge-csp-clear-field.test");
		const first = await updateSite(site.id, {
			name: site.name,
			publicHost: site.public_host,
			originUrl: site.origin_url,
			challengeCspOverrides: { slider: { imgSrc: "https://cdn.example.com", scriptSrc: "https://scripts.example.com" } },
		});
		const { site: updated } = await updateSite(first.site.id, {
			name: site.name,
			publicHost: site.public_host,
			originUrl: site.origin_url,
			challengeCspOverrides: { slider: { scriptSrc: "" } },
		});
		expect(siteView(updated).challengePage.cspOverrides).toEqual({ slider: { imgSrc: ["https://cdn.example.com"] } });
	});

	test("a multi-source field accepts several space-separated sources", async () => {
		const site = await makeSite("challenge-csp-multi.test");
		const { site: updated } = await updateSite(site.id, {
			name: site.name,
			publicHost: site.public_host,
			originUrl: site.origin_url,
			challengeCspOverrides: { slider: { imgSrc: "https://cdn-a.example.com https://cdn-b.example.com" } },
		});
		expect(siteView(updated).challengePage.cspOverrides).toEqual({
			slider: { imgSrc: ["https://cdn-a.example.com", "https://cdn-b.example.com"] },
		});
	});

	test("rejects an invalid CSP source expression", async () => {
		const site = await makeSite("challenge-csp-invalid.test");
		await expect(
			updateSite(site.id, {
				name: site.name,
				publicHost: site.public_host,
				originUrl: site.origin_url,
				challengeCspOverrides: { slider: { imgSrc: "*" } },
			}),
		).rejects.toThrow();
	});

	test("rejects an unknown CSP field name", async () => {
		const site = await makeSite("challenge-csp-unknown-field.test");
		await expect(
			updateSite(site.id, {
				name: site.name,
				publicHost: site.public_host,
				originUrl: site.origin_url,
				challengeCspOverrides: { slider: { bogusField: "https://cdn.example.com" } },
			}),
		).rejects.toThrow();
	});

	test("omitting challengeCspOverrides entirely leaves existing overrides untouched", async () => {
		const site = await makeSite("challenge-csp-omit.test");
		const first = await updateSite(site.id, {
			name: site.name,
			publicHost: site.public_host,
			originUrl: site.origin_url,
			challengeCspOverrides: { slider: { imgSrc: "https://cdn.example.com" } },
		});
		const { site: updated } = await updateSite(first.site.id, { name: "Renamed", publicHost: site.public_host, originUrl: site.origin_url });
		expect(siteView(updated).challengePage.cspOverrides).toEqual({ slider: { imgSrc: ["https://cdn.example.com"] } });
	});
});
