import { beforeAll, describe, expect, test } from "bun:test";
import { addCountryRule, addIpRule, evaluateIp } from "../src/services/ip-rule-service.ts";
import { addRouteCountryRule, addRouteIpRule, evaluateRouteIp, resolveNetworkDecision } from "../src/services/route-ip-rule-service.ts";
import { createRoutePolicy } from "../src/services/route-policy-service.ts";
import { createSite } from "../src/services/site-service.ts";
import type { RoutePolicyRecord, SiteRecord } from "../src/types.ts";

let site: SiteRecord;
let route: RoutePolicyRecord;

beforeAll(async () => {
	site = (await createSite({ name: "Route network rules", publicHost: `route-net-${crypto.randomUUID()}.test`, originUrl: "http://origin.test" })).site;
	route = await createRoutePolicy(site.id, { name: "API", pathPattern: "/api/**", accessMode: "inherit" });
});

describe("route-level IP/country rules", () => {
	test("a route allow rule overrides a conflicting site block for that route", async () => {
		await addIpRule(site.id, "203.0.113.0/24", "block", "site block", null);
		expect((await evaluateIp(site, "203.0.113.5")).action).toBe("block");

		await addRouteIpRule(route.id, "203.0.113.5", "allow", "trusted partner", null);
		const decision = await resolveNetworkDecision(site, route, "203.0.113.5");
		expect(decision.action).toBe("allow");
		expect(decision.scope).toBe("route");
	});

	test("falls back to the site decision when the route has no matching rule", async () => {
		await addIpRule(site.id, "198.51.100.0/24", "block", "site block", null);
		const decision = await resolveNetworkDecision(site, route, "198.51.100.7");
		expect(decision.action).toBe("block");
		expect(decision.scope).toBe("site");
	});

	test("a route default IP action applies when nothing more specific matches", async () => {
		const strictRoute = await createRoutePolicy(site.id, {
			name: "Strict",
			pathPattern: "/strict/**",
			accessMode: "inherit",
			defaultIpAction: "block",
		});
		const decision = await resolveNetworkDecision(site, strictRoute, "192.0.2.9");
		expect(decision.action).toBe("block");
		expect(decision.scope).toBe("route");
		expect(decision.source).toBe("ip-default");
	});

	test("a route country rule overrides the site's country rule", async () => {
		await addCountryRule(site.id, "XX", "block", "site private-network block", null);
		expect((await evaluateIp(site, "10.1.2.3")).action).toBe("block");

		await addRouteCountryRule(route.id, "XX", "allow", "internal tooling route", null);
		const decision = await resolveNetworkDecision(site, route, "10.1.2.3");
		expect(decision.action).toBe("allow");
		expect(decision.source).toBe("country-rule");
		expect(decision.scope).toBe("route");
	});

	test("evaluateRouteIp reports no decision for a route without rules or defaults", async () => {
		const openRoute = await createRoutePolicy(site.id, { name: "Open", pathPattern: "/open/**", accessMode: "inherit" });
		const decision = await evaluateRouteIp(openRoute, "203.0.113.99");
		expect(decision.action).toBeNull();
	});
});
