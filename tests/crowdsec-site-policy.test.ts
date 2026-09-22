import { describe, expect, test } from "bun:test";
import { repository } from "../src/db/repository.ts";
import { resolvedCrowdSecPolicy } from "../src/services/crowdsec-policy-service.ts";
import { createRoutePolicy, updateRoutePolicy } from "../src/services/route-policy-service.ts";
import { createSite, updateSite } from "../src/services/site-service.ts";

async function site(overrides: Record<string, unknown> = {}) {
	return (
		await createSite({
			name: "CrowdSec policy",
			publicHost: `cs-policy-${crypto.randomUUID()}.test`,
			originUrl: "http://origin.test",
			...overrides,
		})
	).site;
}

describe("site CrowdSec policy persistence", () => {
	test("a new site starts in monitor mode for both remediations", async () => {
		const created = await site();
		const stored = await repository.siteById(created.id);
		expect(resolvedCrowdSecPolicy(stored!, null)).toEqual({ ban: "monitor", captcha: "monitor", appsec: "disabled" });
	});

	test("a policy set at creation round-trips through the database", async () => {
		const created = await site({ crowdSecPolicy: { ban: "block", captcha: "challenge" } });
		const stored = await repository.siteById(created.id);
		expect(resolvedCrowdSecPolicy(stored!, null)).toEqual({ ban: "block", captcha: "challenge", appsec: "disabled" });
	});

	// A partial update merges against what is stored rather than resetting the omitted remediation
	// to its default, matching how the network privacy policy behaves.
	test("a partial update changes only the remediation it names", async () => {
		const created = await site({ crowdSecPolicy: { ban: "block", captcha: "challenge" } });
		await updateSite(created.id, { crowdSecPolicy: { ban: "disabled" } });
		const stored = await repository.siteById(created.id);
		expect(resolvedCrowdSecPolicy(stored!, null)).toEqual({ ban: "disabled", captcha: "challenge", appsec: "disabled" });
	});

	test("an update that does not mention the policy keeps the stored one", async () => {
		const created = await site({ crowdSecPolicy: { ban: "block", captcha: "challenge" } });
		await updateSite(created.id, { name: "Renamed" });
		const stored = await repository.siteById(created.id);
		expect(resolvedCrowdSecPolicy(stored!, null)).toEqual({ ban: "block", captcha: "challenge", appsec: "disabled" });
	});

	test("an invalid policy is rejected rather than stored", async () => {
		const created = await site();
		expect(updateSite(created.id, { crowdSecPolicy: { ban: "challenge" } })).rejects.toThrow();
	});
});

describe("route CrowdSec policy persistence", () => {
	test("a route without its own policy inherits the site's", async () => {
		const created = await site({ crowdSecPolicy: { ban: "block", captcha: "monitor" } });
		const route = await createRoutePolicy(created.id, { name: "API", pathPattern: "/api/**", accessMode: "inherit" });
		const storedSite = await repository.siteById(created.id);
		const storedRoute = await repository.routePolicyById(route.id, created.id);
		expect(storedRoute!.crowdsec_policy_json).toBeNull();
		expect(resolvedCrowdSecPolicy(storedSite!, storedRoute!)).toEqual({ ban: "block", captcha: "monitor", appsec: "disabled" });
	});

	test("a route policy replaces the site's for that route", async () => {
		const created = await site({ crowdSecPolicy: { ban: "block", captcha: "monitor" } });
		const route = await createRoutePolicy(created.id, {
			name: "Webhooks",
			pathPattern: "/hooks/**",
			accessMode: "inherit",
			crowdSecPolicy: { ban: "disabled", captcha: "disabled" },
		});
		const storedSite = await repository.siteById(created.id);
		const storedRoute = await repository.routePolicyById(route.id, created.id);
		expect(resolvedCrowdSecPolicy(storedSite!, storedRoute!)).toEqual({ ban: "disabled", captcha: "disabled", appsec: "disabled" });
		// The site's own policy is untouched by the route override.
		expect(resolvedCrowdSecPolicy(storedSite!, null)).toEqual({ ban: "block", captcha: "monitor", appsec: "disabled" });
	});

	test("clearing a route policy falls back to the site's again", async () => {
		const created = await site({ crowdSecPolicy: { ban: "block", captcha: "challenge" } });
		const route = await createRoutePolicy(created.id, {
			name: "Webhooks",
			pathPattern: "/hooks/**",
			accessMode: "inherit",
			crowdSecPolicy: { ban: "disabled", captcha: "disabled" },
		});
		await updateRoutePolicy(created.id, route.id, { crowdSecPolicy: null });
		const storedSite = await repository.siteById(created.id);
		const storedRoute = await repository.routePolicyById(route.id, created.id);
		expect(storedRoute!.crowdsec_policy_json).toBeNull();
		expect(resolvedCrowdSecPolicy(storedSite!, storedRoute!)).toEqual({ ban: "block", captcha: "challenge", appsec: "disabled" });
	});
});
