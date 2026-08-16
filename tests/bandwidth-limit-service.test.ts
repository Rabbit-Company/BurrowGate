import { beforeEach, describe, expect, test } from "bun:test";
import { bandwidthLimitEntryCount, clearBandwidthLimitEntries, recordBandwidthLimitBytes } from "../src/services/bandwidth-limit-service.ts";
import { evaluateIp } from "../src/services/ip-rule-service.ts";
import { createSite } from "../src/services/site-service.ts";
import type { ResolvedBandwidthLimitPolicy } from "../src/services/http-policy-service.ts";
import type { SiteRecord } from "../src/types.ts";

async function site(): Promise<SiteRecord> {
	return (await createSite({ name: "Bandwidth limit", publicHost: `bw-limit-${crypto.randomUUID()}.test`, originUrl: "http://origin.test" })).site;
}

function policyFor(siteRecord: SiteRecord, overrides: Partial<ResolvedBandwidthLimitPolicy> = {}): ResolvedBandwidthLimitPolicy {
	return { enabled: true, maxBytes: 1_000, windowSeconds: 60, banSeconds: 3_600, scopeId: siteRecord.id, ...overrides };
}

async function waitForBan(): Promise<void> {
	await new Promise((resolve) => setTimeout(resolve, 50));
}

beforeEach(() => {
	clearBandwidthLimitEntries();
});

describe("recordBandwidthLimitBytes", () => {
	test("does nothing while under the threshold", async () => {
		const s = await site();
		const policy = policyFor(s);
		recordBandwidthLimitBytes(policy, s, "203.0.113.1", 500);
		await waitForBan();
		expect((await evaluateIp(s, "203.0.113.1")).action).toBeNull();
	});

	test("bans the IP once the window total crosses maxBytes", async () => {
		const s = await site();
		const policy = policyFor(s);
		const now = Date.now();
		recordBandwidthLimitBytes(policy, s, "203.0.113.2", 600, now);
		recordBandwidthLimitBytes(policy, s, "203.0.113.2", 600, now);
		await waitForBan();
		const decision = await evaluateIp(s, "203.0.113.2");
		expect(decision.action).toBe("block");
		expect(decision.expiresAt).not.toBeNull();
	});

	test("does not create a second ban for further bytes in the same violated window", async () => {
		const s = await site();
		const policy = policyFor(s);
		const now = Date.now();
		recordBandwidthLimitBytes(policy, s, "203.0.113.3", 1_500, now);
		await waitForBan();
		recordBandwidthLimitBytes(policy, s, "203.0.113.3", 1_500, now);
		await waitForBan();
		const decision = await evaluateIp(s, "203.0.113.3");
		expect(decision.source).toBe("ip-rule");
		expect(decision.action).toBe("block");
	});

	test("a new window resets the counter", async () => {
		const s = await site();
		const policy = policyFor(s);
		const windowMs = policy.windowSeconds * 1_000;
		const now = Date.now();
		recordBandwidthLimitBytes(policy, s, "203.0.113.4", 900, now);
		recordBandwidthLimitBytes(policy, s, "203.0.113.4", 900, now + windowMs);
		await waitForBan();
		expect((await evaluateIp(s, "203.0.113.4")).action).toBeNull();
	});

	test("does nothing when disabled", async () => {
		const s = await site();
		const policy = policyFor(s, { enabled: false });
		recordBandwidthLimitBytes(policy, s, "203.0.113.5", 10_000);
		await waitForBan();
		expect((await evaluateIp(s, "203.0.113.5")).action).toBeNull();
		expect(bandwidthLimitEntryCount()).toBe(0);
	});

	test("ignores the unknown IP sentinel", async () => {
		const s = await site();
		const policy = policyFor(s);
		recordBandwidthLimitBytes(policy, s, "unknown", 10_000);
		expect(bandwidthLimitEntryCount()).toBe(0);
	});
});
