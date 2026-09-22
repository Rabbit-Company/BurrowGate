import { afterEach, describe, expect, test } from "bun:test";
import { repository } from "../src/db/repository.ts";
import { crowdSecDecisions, type RawCrowdSecDecision } from "../src/services/crowdsec-decision-store.ts";
import {
	crowdSecStreamBlockedReason,
	DEFAULT_STREAM_CROWDSEC_POLICY,
	evaluateStreamCrowdSec,
	parseStreamCrowdSecPolicy,
	serializeStreamCrowdSecPolicy,
	storedStreamCrowdSecPolicy,
	type StreamCrowdSecPolicy,
} from "../src/services/crowdsec-policy-service.ts";
import { buildStream } from "../src/services/stream-service.ts";

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

const policy = (overrides: Partial<StreamCrowdSecPolicy> = {}): StreamCrowdSecPolicy => ({ ...DEFAULT_STREAM_CROWDSEC_POLICY, ...overrides });

afterEach(() => {
	crowdSecDecisions.clear();
});

describe("parseStreamCrowdSecPolicy", () => {
	test("defaults both remediations to monitor", () => {
		expect(parseStreamCrowdSecPolicy(undefined)).toEqual({ ban: "monitor", captcha: "monitor" });
	});

	test("captcha accepts block rather than challenge, because a stream has no challenge chain", () => {
		expect(parseStreamCrowdSecPolicy({ captcha: "block" })).toEqual({ ban: "monitor", captcha: "block" });
		expect(() => parseStreamCrowdSecPolicy({ captcha: "challenge" })).toThrow();
	});

	test("rejects non-objects and unknown modes", () => {
		expect(() => parseStreamCrowdSecPolicy("block")).toThrow();
		expect(() => parseStreamCrowdSecPolicy({ ban: "drop" })).toThrow();
	});

	test("falls back to a safe policy when stored JSON is corrupt", () => {
		expect(storedStreamCrowdSecPolicy("{not json")).toEqual({ ban: "monitor", captcha: "monitor" });
		expect(storedStreamCrowdSecPolicy(null)).toEqual({ ban: "monitor", captcha: "monitor" });
	});

	test("serializes to a complete object, merging against what is stored", () => {
		expect(JSON.parse(serializeStreamCrowdSecPolicy({ ban: "block" }))).toEqual({ ban: "block", captcha: "monitor" });
		expect(JSON.parse(serializeStreamCrowdSecPolicy({ ban: "disabled" }, '{"ban":"block","captcha":"block"}'))).toEqual({
			ban: "disabled",
			captcha: "block",
		});
	});
});

describe("evaluateStreamCrowdSec", () => {
	test("blocks a ban decision in block mode", () => {
		load({ value: "203.0.113.5" });
		expect(evaluateStreamCrowdSec("203.0.113.5", null, null, policy({ ban: "block" }), "route", null).enforcement).toBe("block");
	});

	test("monitor mode reports without acting", () => {
		load({ value: "203.0.113.5" });
		const result = evaluateStreamCrowdSec("203.0.113.5", null, null, policy({ ban: "monitor" }), "route", null);
		expect(result.enforcement).toBe("monitor");
		expect(result.decision).not.toBeNull();
	});

	test("a captcha decision does not block unless captcha mode says block", () => {
		load({ value: "203.0.113.5", type: "captcha" });
		expect(evaluateStreamCrowdSec("203.0.113.5", null, null, policy({ ban: "block", captcha: "monitor" }), "route", null).enforcement).toBe("monitor");
		expect(evaluateStreamCrowdSec("203.0.113.5", null, null, policy({ ban: "block", captcha: "block" }), "route", null).enforcement).toBe("block");
		expect(evaluateStreamCrowdSec("203.0.113.5", null, null, policy({ ban: "block", captcha: "disabled" }), "route", null).enforcement).toBe("none");
	});

	test("a stream Allow rule overrides a CrowdSec ban", () => {
		load({ value: "203.0.113.5" });
		const result = evaluateStreamCrowdSec("203.0.113.5", null, null, policy({ ban: "block" }), "ip-rule", "allow");
		expect(result.enforcement).toBe("monitor");
		expect(result.bypassed).toBe(true);
	});

	test("a country allow does not override, matching the stream privacy rule", () => {
		load({ value: "203.0.113.5" });
		expect(evaluateStreamCrowdSec("203.0.113.5", null, null, policy({ ban: "block" }), "country-rule", "allow").enforcement).toBe("block");
	});

	test("matches ranges, countries, and ASNs", () => {
		load({ scope: "Range", value: "203.0.113.0/24" });
		expect(evaluateStreamCrowdSec("203.0.113.77", null, null, policy({ ban: "block" }), "route", null).enforcement).toBe("block");

		crowdSecDecisions.clear();
		load({ scope: "AS", value: "64496" });
		expect(evaluateStreamCrowdSec("198.51.100.1", null, 64496, policy({ ban: "block" }), "route", null).enforcement).toBe("block");
	});

	test("short-circuits when nothing is loaded or the policy is off", () => {
		expect(evaluateStreamCrowdSec("203.0.113.5", "DE", 64496, policy({ ban: "block" }), "route", null).decision).toBeNull();
		load({ value: "203.0.113.5" });
		expect(evaluateStreamCrowdSec("203.0.113.5", null, null, policy({ ban: "disabled", captcha: "disabled" }), "route", null).decision).toBeNull();
	});
});

describe("crowdSecStreamBlockedReason", () => {
	test("names the community blocklist and the scenario", () => {
		load({ value: "203.0.113.5", origin: "CAPI", scenario: "crowdsecurity/ssh-bf" });
		const reason = crowdSecStreamBlockedReason(evaluateStreamCrowdSec("203.0.113.5", null, null, policy({ ban: "block" }), "route", null));
		expect(reason).toBe("Blocked by the CrowdSec community blocklist for crowdsecurity/ssh-bf");
	});

	test("returns nothing when the match was only monitored", () => {
		load({ value: "203.0.113.5" });
		expect(crowdSecStreamBlockedReason(evaluateStreamCrowdSec("203.0.113.5", null, null, policy({ ban: "monitor" }), "route", null))).toBeNull();
	});
});

describe("stream policy persistence", () => {
	let nextPort = 21_000 + Math.floor(Math.random() * 10_000);

	async function persistedStream() {
		const record = await buildStream({ name: `cs-${crypto.randomUUID()}`, incomingPort: nextPort++, forwardHost: "127.0.0.1", forwardPort: 9001 });
		await repository.saveStream(record);
		return record;
	}

	test("a new stream starts in monitor mode", async () => {
		const stream = await persistedStream();
		const stored = await repository.streamById(stream.id);
		expect(storedStreamCrowdSecPolicy(stored!.crowdsec_policy_json)).toEqual({ ban: "monitor", captcha: "monitor" });
	});

	test("the policy round-trips through updateStreamNetworkDefaults", async () => {
		const stream = await persistedStream();
		await repository.updateStreamNetworkDefaults(
			stream.id,
			"inherit",
			"inherit",
			Date.now(),
			stream.network_privacy_policy_json ?? "{}",
			serializeStreamCrowdSecPolicy({ ban: "block", captcha: "disabled" }),
		);
		const stored = await repository.streamById(stream.id);
		expect(storedStreamCrowdSecPolicy(stored!.crowdsec_policy_json)).toEqual({ ban: "block", captcha: "disabled" });
	});
});
