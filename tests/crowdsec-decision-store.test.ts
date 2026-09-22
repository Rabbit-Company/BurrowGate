import { describe, expect, test } from "bun:test";
import {
	CrowdSecDecisionStore,
	decisionExpiry,
	normalizeRemediation,
	numericAddress,
	parseGoDurationMs,
	type RawCrowdSecDecision,
} from "../src/services/crowdsec-decision-store.ts";

function decision(overrides: Partial<RawCrowdSecDecision> & { value: string }): RawCrowdSecDecision {
	return {
		id: 1,
		type: "ban",
		scope: "Ip",
		duration: "4h",
		origin: "CAPI",
		scenario: "crowdsecurity/http-probing",
		...overrides,
	};
}

describe("parseGoDurationMs", () => {
	test("parses the compound durations the LAPI emits", () => {
		expect(parseGoDurationMs("4h")).toBe(4 * 3_600_000);
		expect(parseGoDurationMs("168h0m0s")).toBe(168 * 3_600_000);
		expect(parseGoDurationMs("3h59m51.7s")).toBe(3 * 3_600_000 + 59 * 60_000 + 51_700);
		expect(parseGoDurationMs("30m")).toBe(1_800_000);
		expect(parseGoDurationMs("1500ms")).toBe(1_500);
	});

	test("distinguishes minutes from milliseconds", () => {
		expect(parseGoDurationMs("5m")).toBe(300_000);
		expect(parseGoDurationMs("5ms")).toBe(5);
		expect(parseGoDurationMs("5m30s")).toBe(330_000);
	});

	test("handles negative durations for decisions that already lapsed", () => {
		expect(parseGoDurationMs("-1h")).toBe(-3_600_000);
		expect(parseGoDurationMs("-2m30s")).toBe(-150_000);
	});

	test("rejects input that only partially parses instead of silently truncating it", () => {
		expect(parseGoDurationMs("3h junk")).toBeNull();
		expect(parseGoDurationMs("forever")).toBeNull();
		expect(parseGoDurationMs("")).toBeNull();
		expect(parseGoDurationMs("12")).toBeNull();
	});
});

describe("decisionExpiry", () => {
	test("prefers duration over until", () => {
		const now = 1_000_000;
		expect(decisionExpiry({ duration: "1h", until: "2020-01-01T00:00:00Z" }, now)).toBe(now + 3_600_000);
	});

	test("falls back to until when duration is absent or unparseable", () => {
		const now = 1_000_000;
		expect(decisionExpiry({ until: "2030-01-01T00:00:00Z" }, now)).toBe(Date.parse("2030-01-01T00:00:00Z"));
		expect(decisionExpiry({ duration: "nonsense", until: "2030-01-01T00:00:00Z" }, now)).toBe(Date.parse("2030-01-01T00:00:00Z"));
	});

	test("returns null when neither field is usable, rather than an immortal ban", () => {
		expect(decisionExpiry({}, 1_000)).toBeNull();
		expect(decisionExpiry({ duration: "???" }, 1_000)).toBeNull();
	});
});

describe("normalizeRemediation", () => {
	test("maps the two remediations the ecosystem ships", () => {
		expect(normalizeRemediation("ban", "ban")).toBe("ban");
		expect(normalizeRemediation("captcha", "ban")).toBe("captcha");
		expect(normalizeRemediation("BAN", "ban")).toBe("ban");
	});

	test("routes anything else through the operator's fallback", () => {
		expect(normalizeRemediation("throttle", "ban")).toBe("ban");
		expect(normalizeRemediation("throttle", "captcha")).toBe("captcha");
		expect(normalizeRemediation("throttle", "ignore")).toBeNull();
	});
});

describe("numericAddress", () => {
	test("folds IPv4-mapped IPv6 down to IPv4 so a dual-stack listener still matches", () => {
		const mapped = numericAddress("::ffff:203.0.113.5");
		const plain = numericAddress("203.0.113.5");
		expect(mapped?.version).toBe(4);
		expect(mapped?.v4).toBe(plain!.v4);
	});

	test("rejects garbage", () => {
		expect(numericAddress("not-an-ip")).toBeNull();
		expect(numericAddress("")).toBeNull();
	});
});

describe("CrowdSecDecisionStore exact-IP matching", () => {
	test("matches an IPv4 decision", () => {
		const store = new CrowdSecDecisionStore();
		store.applySnapshot([decision({ value: "203.0.113.5" })]);
		expect(store.lookup("203.0.113.5", null, null)?.remediation).toBe("ban");
		expect(store.lookup("203.0.113.6", null, null)).toBeNull();
	});

	test("matches an IPv6 decision, including its compressed form", () => {
		const store = new CrowdSecDecisionStore();
		store.applySnapshot([decision({ value: "2001:db8:0:0:0:0:0:1" })]);
		expect(store.lookup("2001:db8::1", null, null)?.remediation).toBe("ban");
		expect(store.lookup("2001:db8::2", null, null)).toBeNull();
	});

	test("matches a decision on the v4 address when the client arrives IPv4-mapped", () => {
		const store = new CrowdSecDecisionStore();
		store.applySnapshot([decision({ value: "203.0.113.5" })]);
		expect(store.lookup("::ffff:203.0.113.5", null, null)?.remediation).toBe("ban");
	});

	test("reports empty until something is loaded", () => {
		const store = new CrowdSecDecisionStore();
		expect(store.empty).toBe(true);
		expect(store.lookup("203.0.113.5", "US", 64496)).toBeNull();
		store.applySnapshot([decision({ value: "203.0.113.5" })]);
		expect(store.empty).toBe(false);
	});
});

describe("CrowdSecDecisionStore range matching", () => {
	test("matches an address inside a v4 range", () => {
		const store = new CrowdSecDecisionStore();
		store.applySnapshot([decision({ scope: "Range", value: "203.0.113.0/24" })]);
		expect(store.lookup("203.0.113.77", null, null)?.value).toBe("203.0.113.0/24");
		expect(store.lookup("203.0.114.1", null, null)).toBeNull();
	});

	test("matches an address inside a v6 range", () => {
		const store = new CrowdSecDecisionStore();
		store.applySnapshot([decision({ scope: "Range", value: "2001:db8::/32" })]);
		expect(store.lookup("2001:db8:dead:beef::1", null, null)?.value).toBe("2001:db8::/32");
		expect(store.lookup("2001:db9::1", null, null)).toBeNull();
	});

	test("prefers the most specific range when several overlap", () => {
		const store = new CrowdSecDecisionStore();
		store.applySnapshot([
			decision({ id: 1, scope: "Range", value: "203.0.0.0/8", type: "captcha" }),
			decision({ id: 2, scope: "Range", value: "203.0.113.0/24", type: "ban" }),
		]);
		expect(store.lookup("203.0.113.5", null, null)?.value).toBe("203.0.113.0/24");
	});

	test("handles a /0 range covering everything", () => {
		const store = new CrowdSecDecisionStore();
		store.applySnapshot([decision({ scope: "Range", value: "0.0.0.0/0" })]);
		expect(store.lookup("198.51.100.23", null, null)?.value).toBe("0.0.0.0/0");
	});

	test("treats a /32 range as an exact address", () => {
		const store = new CrowdSecDecisionStore();
		store.applySnapshot([decision({ scope: "Range", value: "203.0.113.5/32" })]);
		expect(store.lookup("203.0.113.5", null, null)).not.toBeNull();
		expect(store.lookup("203.0.113.6", null, null)).toBeNull();
	});
});

describe("CrowdSecDecisionStore scope precedence", () => {
	test("an exact IP decision outranks a range covering it", () => {
		const store = new CrowdSecDecisionStore();
		store.applySnapshot([
			decision({ id: 1, scope: "Range", value: "203.0.113.0/24", type: "ban" }),
			decision({ id: 2, scope: "Ip", value: "203.0.113.5", type: "captcha" }),
		]);
		expect(store.lookup("203.0.113.5", null, null)?.remediation).toBe("captcha");
	});

	test("a range outranks an ASN, which outranks a country", () => {
		const store = new CrowdSecDecisionStore();
		store.applySnapshot([
			decision({ id: 1, scope: "Country", value: "DE", type: "ban" }),
			decision({ id: 2, scope: "AS", value: "64496", type: "captcha" }),
			decision({ id: 3, scope: "Range", value: "203.0.113.0/24", type: "ban" }),
		]);
		expect(store.lookup("203.0.113.5", "DE", 64496)?.scope).toBe("range");
		expect(store.lookup("198.51.100.1", "DE", 64496)?.scope).toBe("as");
		expect(store.lookup("198.51.100.1", "DE", 64497)?.scope).toBe("country");
	});

	test("accepts an AS value written with the AS prefix", () => {
		const store = new CrowdSecDecisionStore();
		store.applySnapshot([decision({ scope: "AS", value: "AS64496" })]);
		expect(store.lookup("198.51.100.1", null, 64496)?.scope).toBe("as");
	});

	test("matches a country case-insensitively", () => {
		const store = new CrowdSecDecisionStore();
		store.applySnapshot([decision({ scope: "Country", value: "de" })]);
		expect(store.lookup("198.51.100.1", "DE", null)?.scope).toBe("country");
	});
});

describe("CrowdSecDecisionStore expiry", () => {
	test("drops a decision once its duration runs out", () => {
		const store = new CrowdSecDecisionStore();
		const now = Date.now();
		store.applySnapshot([decision({ value: "203.0.113.5", duration: "1h" })], now);
		expect(store.lookup("203.0.113.5", null, null, now)).not.toBeNull();
		expect(store.lookup("203.0.113.5", null, null, now + 3_600_001)).toBeNull();
	});

	test("never admits an already-expired decision", () => {
		const store = new CrowdSecDecisionStore();
		expect(store.applySnapshot([decision({ value: "203.0.113.5", duration: "-1h" })])).toBe(0);
		expect(store.lookup("203.0.113.5", null, null)).toBeNull();
	});

	test("sweepExpired reclaims lapsed entries", () => {
		const store = new CrowdSecDecisionStore();
		const now = Date.now();
		store.applySnapshot([decision({ id: 1, value: "203.0.113.5", duration: "1h" }), decision({ id: 2, value: "203.0.113.6", duration: "10h" })], now);
		expect(store.sweepExpired(now + 3_600_001)).toBe(1);
		expect(store.stats().total).toBe(1);
	});
});

describe("CrowdSecDecisionStore delta application", () => {
	test("adds and removes decisions", () => {
		const store = new CrowdSecDecisionStore();
		store.applySnapshot([decision({ id: 1, value: "203.0.113.5" })]);
		store.applyDelta([decision({ id: 2, value: "203.0.113.6" })], []);
		expect(store.stats().total).toBe(2);
		store.applyDelta([], [decision({ id: 1, value: "203.0.113.5" })]);
		expect(store.lookup("203.0.113.5", null, null)).toBeNull();
		expect(store.lookup("203.0.113.6", null, null)).not.toBeNull();
	});

	test("removes a range decision by its CIDR value", () => {
		const store = new CrowdSecDecisionStore();
		store.applySnapshot([decision({ id: 1, scope: "Range", value: "203.0.113.0/24" })]);
		store.applyDelta([], [decision({ id: 1, scope: "Range", value: "203.0.113.0/24" })]);
		expect(store.lookup("203.0.113.5", null, null)).toBeNull();
		expect(store.stats().total).toBe(0);
	});

	test("a snapshot replaces everything rather than merging", () => {
		const store = new CrowdSecDecisionStore();
		store.applySnapshot([decision({ id: 1, value: "203.0.113.5" })]);
		store.applySnapshot([decision({ id: 2, value: "203.0.113.6" })]);
		expect(store.lookup("203.0.113.5", null, null)).toBeNull();
		expect(store.lookup("203.0.113.6", null, null)).not.toBeNull();
	});

	test("ignores a delete for something never held", () => {
		const store = new CrowdSecDecisionStore();
		store.applySnapshot([decision({ id: 1, value: "203.0.113.5" })]);
		store.applyDelta([], [decision({ id: 99, value: "198.51.100.1" })]);
		expect(store.lookup("203.0.113.5", null, null)).not.toBeNull();
	});
});

describe("CrowdSecDecisionStore overlapping decisions on one value", () => {
	test("keeps the stronger remediation visible", () => {
		const store = new CrowdSecDecisionStore();
		store.applySnapshot([decision({ id: 1, value: "203.0.113.5", type: "captcha" }), decision({ id: 2, value: "203.0.113.5", type: "ban" })]);
		expect(store.lookup("203.0.113.5", null, null)?.remediation).toBe("ban");
	});

	test("deleting the winner promotes the other decision instead of unblocking the address", () => {
		const store = new CrowdSecDecisionStore();
		store.applySnapshot([
			decision({ id: 1, value: "203.0.113.5", type: "captcha", origin: "cscli" }),
			decision({ id: 2, value: "203.0.113.5", type: "ban", origin: "CAPI" }),
		]);
		store.applyDelta([], [decision({ id: 2, value: "203.0.113.5", type: "ban" })]);
		const remaining = store.lookup("203.0.113.5", null, null);
		expect(remaining?.remediation).toBe("captcha");
		expect(remaining?.origin).toBe("cscli");
	});

	test("deleting the shadowed decision leaves the winner in place", () => {
		const store = new CrowdSecDecisionStore();
		store.applySnapshot([decision({ id: 1, value: "203.0.113.5", type: "captcha" }), decision({ id: 2, value: "203.0.113.5", type: "ban" })]);
		store.applyDelta([], [decision({ id: 1, value: "203.0.113.5", type: "captcha" })]);
		expect(store.lookup("203.0.113.5", null, null)?.remediation).toBe("ban");
	});

	test("deleting both clears the address", () => {
		const store = new CrowdSecDecisionStore();
		store.applySnapshot([decision({ id: 1, value: "203.0.113.5", type: "captcha" }), decision({ id: 2, value: "203.0.113.5", type: "ban" })]);
		store.applyDelta([], [decision({ id: 1, value: "203.0.113.5" }), decision({ id: 2, value: "203.0.113.5" })]);
		expect(store.lookup("203.0.113.5", null, null)).toBeNull();
		expect(store.stats().total).toBe(0);
	});

	test("re-sending the same decision id updates rather than duplicates it", () => {
		const store = new CrowdSecDecisionStore();
		store.applySnapshot([decision({ id: 1, value: "203.0.113.5", type: "captcha" })]);
		store.applyDelta([decision({ id: 1, value: "203.0.113.5", type: "ban" })], []);
		expect(store.lookup("203.0.113.5", null, null)?.remediation).toBe("ban");
		expect(store.stats().total).toBe(1);
	});
});

describe("CrowdSecDecisionStore malformed input", () => {
	test("skips decisions it cannot index", () => {
		const store = new CrowdSecDecisionStore();
		const accepted = store.applySnapshot([
			decision({ value: "not-an-ip" }),
			decision({ scope: "Range", value: "203.0.113.0/99" }),
			decision({ scope: "Country", value: "GERMANY" }),
			decision({ scope: "AS", value: "abc" }),
			decision({ scope: "Username", value: "someone" }),
			decision({ value: "" }),
			decision({ value: "203.0.113.5" }),
		]);
		expect(accepted).toBe(1);
		expect(store.lookup("203.0.113.5", null, null)).not.toBeNull();
	});

	test("survives an unknown client IP", () => {
		const store = new CrowdSecDecisionStore();
		store.applySnapshot([decision({ value: "203.0.113.5" })]);
		expect(store.lookup("unknown", null, null)).toBeNull();
	});
});

describe("CrowdSecDecisionStore stats and export", () => {
	test("counts by scope, remediation, and origin", () => {
		const store = new CrowdSecDecisionStore();
		store.applySnapshot([
			decision({ id: 1, value: "203.0.113.5", origin: "CAPI" }),
			decision({ id: 2, scope: "Range", value: "198.51.100.0/24", origin: "CAPI" }),
			decision({ id: 3, scope: "Country", value: "DE", type: "captcha", origin: "cscli" }),
		]);
		const stats = store.stats();
		expect(stats.total).toBe(3);
		expect(stats.byScope).toEqual({ ip: 1, range: 1, country: 1, as: 0 });
		expect(stats.byRemediation).toEqual({ ban: 2, captcha: 1 });
		expect(stats.byOrigin).toEqual({ CAPI: 2, cscli: 1 });
	});

	test("export round-trips through a snapshot restore", () => {
		const store = new CrowdSecDecisionStore();
		const now = Date.now();
		store.applySnapshot([decision({ id: 1, value: "203.0.113.5" }), decision({ id: 2, scope: "Range", value: "198.51.100.0/24" })], now);
		const exported = store.export();

		const restored = new CrowdSecDecisionStore();
		restored.applySnapshot(
			exported.map((entry) => ({
				id: entry.id,
				type: entry.remediation,
				scope: entry.scope,
				value: entry.value,
				origin: entry.origin,
				scenario: entry.scenario,
				until: entry.expiresAt === null ? undefined : new Date(entry.expiresAt).toISOString(),
			})),
			now,
		);
		expect(restored.stats().total).toBe(2);
		expect(restored.lookup("203.0.113.5", null, null, now)).not.toBeNull();
		expect(restored.lookup("198.51.100.7", null, null, now)).not.toBeNull();
	});
});
