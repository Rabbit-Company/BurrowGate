import { beforeEach, describe, expect, test } from "bun:test";
import { crowdSecDecisions, type RawCrowdSecDecision } from "../src/services/crowdsec-decision-store.ts";
import {
	crowdSecBlockIsBypassed,
	crowdSecEventDetail,
	crowdSecReason,
	DEFAULT_CROWDSEC_POLICY,
	evaluateCrowdSec,
	parseCrowdSecPolicy,
	resolvedCrowdSecPolicy,
	serializeCrowdSecPolicy,
	serializeRouteCrowdSecPolicy,
	storedCrowdSecPolicy,
	type CrowdSecPolicy,
} from "../src/services/crowdsec-policy-service.ts";
import type { RoutePolicyRecord, SiteRecord } from "../src/types.ts";

function load(...decisions: Array<Partial<RawCrowdSecDecision> & { value: string }>): void {
	crowdSecDecisions.applySnapshot(
		decisions.map((entry, index) => ({
			id: index + 1,
			type: "ban",
			scope: "Ip",
			duration: "4h",
			origin: "CAPI",
			scenario: "crowdsecurity/http-probing",
			...entry,
		})),
	);
}

const policy = (overrides: Partial<CrowdSecPolicy> = {}): CrowdSecPolicy => ({ ...DEFAULT_CROWDSEC_POLICY, ...overrides });

beforeEach(() => {
	crowdSecDecisions.clear();
});

describe("parseCrowdSecPolicy", () => {
	test("defaults both remediations to monitor", () => {
		expect(parseCrowdSecPolicy(undefined)).toEqual({ ban: "monitor", captcha: "monitor", appsec: "disabled" });
		expect(parseCrowdSecPolicy({})).toEqual({ ban: "monitor", captcha: "monitor", appsec: "disabled" });
	});

	test("accepts the valid modes for each remediation", () => {
		expect(parseCrowdSecPolicy({ ban: "block", captcha: "challenge" })).toEqual({ ban: "block", captcha: "challenge", appsec: "disabled" });
		expect(parseCrowdSecPolicy({ ban: "disabled", captcha: "disabled" })).toEqual({ ban: "disabled", captcha: "disabled", appsec: "disabled" });
	});

	test("rejects a mode belonging to the other remediation", () => {
		expect(() => parseCrowdSecPolicy({ ban: "challenge" })).toThrow();
		expect(() => parseCrowdSecPolicy({ captcha: "block" })).toThrow();
	});

	test("rejects non-objects", () => {
		expect(() => parseCrowdSecPolicy("block")).toThrow();
		expect(() => parseCrowdSecPolicy([])).toThrow();
	});

	test("falls back to a safe policy when stored JSON is corrupt", () => {
		expect(storedCrowdSecPolicy("{not json")).toEqual({ ban: "monitor", captcha: "monitor", appsec: "disabled" });
		expect(storedCrowdSecPolicy(null)).toEqual({ ban: "monitor", captcha: "monitor", appsec: "disabled" });
	});
});

describe("policy serialization", () => {
	test("a site policy always serializes to a complete object", () => {
		expect(JSON.parse(serializeCrowdSecPolicy({ ban: "block" }))).toEqual({ ban: "block", captcha: "monitor", appsec: "disabled" });
	});

	test("a route policy serializes to null when cleared, so the site's applies", () => {
		expect(serializeRouteCrowdSecPolicy(null)).toBeNull();
		expect(serializeRouteCrowdSecPolicy("")).toBeNull();
	});

	test("an omitted route policy keeps whatever was stored", () => {
		expect(serializeRouteCrowdSecPolicy(undefined, '{"ban":"block","captcha":"disabled"}')).toBe('{"ban":"block","captcha":"disabled"}');
	});
});

describe("resolvedCrowdSecPolicy", () => {
	const site = { crowdsec_policy_json: '{"ban":"block","captcha":"monitor"}' } as SiteRecord;

	test("uses the site policy when the route has none", () => {
		expect(resolvedCrowdSecPolicy(site, null)).toEqual({ ban: "block", captcha: "monitor", appsec: "disabled" });
		expect(resolvedCrowdSecPolicy(site, { crowdsec_policy_json: null } as RoutePolicyRecord)).toEqual({ ban: "block", captcha: "monitor", appsec: "disabled" });
	});

	test("a route policy replaces the site's outright rather than merging", () => {
		const route = { crowdsec_policy_json: '{"ban":"disabled"}' } as RoutePolicyRecord;
		expect(resolvedCrowdSecPolicy(site, route)).toEqual({ ban: "disabled", captcha: "monitor", appsec: "disabled" });
	});
});

describe("evaluateCrowdSec", () => {
	test("returns nothing when no decision matches", () => {
		load({ value: "203.0.113.5" });
		expect(evaluateCrowdSec("198.51.100.1", null, null, policy({ ban: "block" }), "route", null)).toEqual({
			decision: null,
			enforcement: "none",
			bypassed: false,
		});
	});

	test("blocks a ban decision in block mode", () => {
		load({ value: "203.0.113.5" });
		const result = evaluateCrowdSec("203.0.113.5", null, null, policy({ ban: "block" }), "route", null);
		expect(result.enforcement).toBe("block");
		expect(result.decision?.scenario).toBe("crowdsecurity/http-probing");
	});

	test("monitor mode reports the decision without acting on it", () => {
		load({ value: "203.0.113.5" });
		const result = evaluateCrowdSec("203.0.113.5", null, null, policy({ ban: "monitor" }), "route", null);
		expect(result.enforcement).toBe("monitor");
		expect(result.decision).not.toBeNull();
	});

	test("disabled mode ignores the decision entirely", () => {
		load({ value: "203.0.113.5" });
		const result = evaluateCrowdSec("203.0.113.5", null, null, policy({ ban: "disabled", captcha: "disabled" }), "route", null);
		expect(result.enforcement).toBe("none");
		expect(result.decision).toBeNull();
	});

	test("a captcha decision becomes a challenge, independently of the ban mode", () => {
		load({ value: "203.0.113.5", type: "captcha" });
		const result = evaluateCrowdSec("203.0.113.5", null, null, policy({ ban: "disabled", captcha: "challenge" }), "route", null);
		expect(result.enforcement).toBe("challenge");
	});

	test("a captcha decision is only monitored when the captcha mode says so", () => {
		load({ value: "203.0.113.5", type: "captcha" });
		expect(evaluateCrowdSec("203.0.113.5", null, null, policy({ ban: "block", captcha: "monitor" }), "route", null).enforcement).toBe("monitor");
	});

	test("a ban mode of block does not escalate a captcha decision", () => {
		load({ value: "203.0.113.5", type: "captcha" });
		expect(evaluateCrowdSec("203.0.113.5", null, null, policy({ ban: "block", captcha: "disabled" }), "route", null).enforcement).toBe("none");
	});

	test("matches on the country and ASN the request already resolved", () => {
		load({ scope: "Country", value: "DE" });
		expect(evaluateCrowdSec("198.51.100.1", "DE", null, policy({ ban: "block" }), "route", null).enforcement).toBe("block");

		crowdSecDecisions.clear();
		load({ scope: "AS", value: "64496" });
		expect(evaluateCrowdSec("198.51.100.1", null, 64496, policy({ ban: "block" }), "route", null).enforcement).toBe("block");
	});
});

describe("allowlist precedence", () => {
	test("an explicit IP allow rule overrides a CrowdSec ban", () => {
		load({ value: "203.0.113.5" });
		const result = evaluateCrowdSec("203.0.113.5", null, null, policy({ ban: "block" }), "ip-rule", "allow");
		expect(result.enforcement).toBe("monitor");
		expect(result.bypassed).toBe(true);
		expect(result.decision).not.toBeNull();
	});

	test("an ASN pass rule overrides a CrowdSec ban", () => {
		load({ value: "203.0.113.5" });
		expect(evaluateCrowdSec("203.0.113.5", null, null, policy({ ban: "block" }), "asn-rule", "pass").enforcement).toBe("monitor");
	});

	test("an allowlist entry also overrides a captcha challenge", () => {
		load({ value: "203.0.113.5", type: "captcha" });
		const result = evaluateCrowdSec("203.0.113.5", null, null, policy({ captcha: "challenge" }), "ip-rule", "allow");
		expect(result.enforcement).toBe("monitor");
		expect(result.bypassed).toBe(true);
	});

	test("a country-level allow does not override CrowdSec, matching network privacy", () => {
		load({ value: "203.0.113.5" });
		expect(evaluateCrowdSec("203.0.113.5", null, null, policy({ ban: "block" }), "country-rule", "allow").enforcement).toBe("block");
	});

	test("a blocking IP rule is not treated as a bypass", () => {
		expect(crowdSecBlockIsBypassed("ip-rule", "block")).toBe(false);
		expect(crowdSecBlockIsBypassed("ip-rule", "allow")).toBe(true);
		expect(crowdSecBlockIsBypassed("country-default", "allow")).toBe(false);
	});
});

describe("event detail and reason text", () => {
	test("records what matched and what was done about it", () => {
		load({ value: "203.0.113.5", origin: "cscli", scenario: "manual" });
		const detail = crowdSecEventDetail(evaluateCrowdSec("203.0.113.5", null, null, policy({ ban: "block" }), "route", null));
		expect(detail).toEqual({
			remediation: "ban",
			scope: "ip",
			value: "203.0.113.5",
			origin: "cscli",
			scenario: "manual",
			enforcement: "block",
		});
	});

	test("flags a bypassed match so the dashboard can explain why nothing happened", () => {
		load({ value: "203.0.113.5" });
		const detail = crowdSecEventDetail(evaluateCrowdSec("203.0.113.5", null, null, policy({ ban: "block" }), "ip-rule", "allow"));
		expect(detail?.bypassed).toBe(true);
		expect(detail?.enforcement).toBe("monitor");
	});

	test("returns nothing when there was no match to record", () => {
		expect(crowdSecEventDetail({ decision: null, enforcement: "none", bypassed: false })).toBeNull();
	});

	test("names the community blocklist by its purpose rather than its acronym", () => {
		load({ value: "203.0.113.5", origin: "CAPI", scenario: "crowdsecurity/http-probing" });
		const decision = crowdSecDecisions.lookup("203.0.113.5", null, null)!;
		expect(crowdSecReason(decision)).toBe("This request was blocked by the CrowdSec community blocklist for crowdsecurity/http-probing.");
	});

	test("names a local origin directly", () => {
		load({ value: "203.0.113.5", origin: "cscli", scenario: "" });
		const decision = crowdSecDecisions.lookup("203.0.113.5", null, null)!;
		expect(crowdSecReason(decision)).toBe("This request was blocked by CrowdSec (cscli).");
	});
});

describe("cost when nothing is loaded", () => {
	test("an empty store short-circuits before any lookup work", () => {
		expect(evaluateCrowdSec("203.0.113.5", "DE", 64496, policy({ ban: "block" }), "route", null)).toEqual({
			decision: null,
			enforcement: "none",
			bypassed: false,
		});
	});

	test("a fully disabled policy short-circuits even with decisions loaded", () => {
		load({ value: "203.0.113.5" });
		expect(evaluateCrowdSec("203.0.113.5", null, null, policy({ ban: "disabled", captcha: "disabled" }), "route", null).decision).toBeNull();
	});
});
