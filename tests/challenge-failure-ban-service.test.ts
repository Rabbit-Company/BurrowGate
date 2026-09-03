import { beforeEach, describe, expect, test } from "bun:test";
import {
	challengeFailureEntryCount,
	clearChallengeFailureEntries,
	recordChallengeFailure,
	recordChallengeSuccess,
} from "../src/services/challenge-failure-ban-service.ts";
import { evaluateIp } from "../src/services/ip-rule-service.ts";
import { createSite } from "../src/services/site-service.ts";
import type { SiteRecord } from "../src/types.ts";

async function site(overrides: { enabled?: boolean; maxFailures?: number; banSeconds?: number } = {}): Promise<SiteRecord> {
	const { enabled = true, maxFailures = 3, banSeconds = 3_600 } = overrides;
	return (
		await createSite({
			name: "Challenge auto-ban",
			publicHost: `challenge-ban-${crypto.randomUUID()}.test`,
			originUrl: "http://origin.test",
			challengeAutoBan: { enabled, maxFailures, banSeconds },
		})
	).site;
}

async function waitForBan(): Promise<void> {
	await new Promise((resolve) => setTimeout(resolve, 50));
}

beforeEach(() => {
	clearChallengeFailureEntries();
});

describe("recordChallengeFailure", () => {
	test("does nothing while under the threshold", async () => {
		const s = await site({ maxFailures: 3 });
		recordChallengeFailure(s, "203.0.113.1");
		recordChallengeFailure(s, "203.0.113.1");
		await waitForBan();
		expect((await evaluateIp(s, "203.0.113.1")).action).toBeNull();
	});

	test("bans the IP once the consecutive-failure count reaches the threshold", async () => {
		const s = await site({ maxFailures: 3, banSeconds: 1_800 });
		recordChallengeFailure(s, "203.0.113.2");
		recordChallengeFailure(s, "203.0.113.2");
		recordChallengeFailure(s, "203.0.113.2");
		await waitForBan();
		const decision = await evaluateIp(s, "203.0.113.2");
		expect(decision.action).toBe("block");
		expect(decision.expiresAt).not.toBeNull();
	});

	test("does not create a second ban for further failures in the same streak", async () => {
		const s = await site({ maxFailures: 2 });
		recordChallengeFailure(s, "203.0.113.3");
		recordChallengeFailure(s, "203.0.113.3");
		await waitForBan();
		recordChallengeFailure(s, "203.0.113.3");
		await waitForBan();
		const decision = await evaluateIp(s, "203.0.113.3");
		expect(decision.source).toBe("ip-rule");
		expect(decision.action).toBe("block");
	});

	test("a success resets the streak so a fresh run of failures is needed to ban", async () => {
		const s = await site({ maxFailures: 3 });
		recordChallengeFailure(s, "203.0.113.4");
		recordChallengeFailure(s, "203.0.113.4");
		recordChallengeSuccess(s, "203.0.113.4");
		recordChallengeFailure(s, "203.0.113.4");
		recordChallengeFailure(s, "203.0.113.4");
		await waitForBan();
		expect((await evaluateIp(s, "203.0.113.4")).action).toBeNull();
	});

	test("does nothing when disabled", async () => {
		const s = await site({ enabled: false, maxFailures: 1 });
		recordChallengeFailure(s, "203.0.113.5");
		await waitForBan();
		expect((await evaluateIp(s, "203.0.113.5")).action).toBeNull();
		expect(challengeFailureEntryCount()).toBe(0);
	});

	test("ignores the unknown IP sentinel", async () => {
		const s = await site({ maxFailures: 1 });
		recordChallengeFailure(s, "unknown");
		expect(challengeFailureEntryCount()).toBe(0);
	});
});
