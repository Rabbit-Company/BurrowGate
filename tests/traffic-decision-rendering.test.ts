import { describe, expect, test } from "bun:test";
import { adminPage } from "../src/ui/admin-page.ts";

/**
 * `decisionClass` in public/admin.js colours a traffic row from a hardcoded list, and anything it
 * does not recognise falls through to green. Adding a decision without updating that list therefore
 * renders a blocked request as if it succeeded, which is exactly what happened to `crowdsec-blocked`
 * and `appsec-blocked`. These tests tie the two together so the next one cannot slip through.
 */

const adminJs = await Bun.file("public/admin.js").text();

/** Every decision the Recent traffic filter offers, which is the catalog a user can actually select. */
function offeredDecisions(): string[] {
	const select = /<select id="eventDecision"[^>]*>(.*?)<\/select>/su.exec(adminPage())?.[1] ?? "";
	return [...select.matchAll(/<option value="([^"]+)"/gu)].map((match) => match[1]!).filter((value) => value.length > 0);
}

/** The list literal inside decisionClass that maps to the "bad" badge. */
function decisionsMarkedBad(): string[] {
	const body = /function decisionClass\(decision\) \{(.*?)return "bad";/su.exec(adminJs)?.[1] ?? "";
	return [...body.matchAll(/"([a-z-]+)"/gu)].map((match) => match[1]!);
}

describe("Recent traffic decision rendering", () => {
	test("the filter offers decisions and the classifier marks some of them bad", () => {
		expect(offeredDecisions().length).toBeGreaterThan(10);
		expect(decisionsMarkedBad().length).toBeGreaterThan(5);
	});

	/**
	 * A semantic rule rather than a fixed list, so it keeps working for decisions nobody has
	 * thought of yet: if a decision says it blocked, denied, or failed, it must not render green.
	 */
	test("every decision that denies a request is coloured as a failure", () => {
		const bad = new Set(decisionsMarkedBad());
		const denying = offeredDecisions().filter(
			(decision) => decision.includes("blocked") || decision.includes("denied") || decision.includes("unavailable") || decision.endsWith("-failed"),
		);
		expect(denying.length).toBeGreaterThan(5);
		expect(denying.filter((decision) => !bad.has(decision))).toEqual([]);
	});

	test("the CrowdSec and AppSec decisions specifically are not rendered as successes", () => {
		const bad = new Set(decisionsMarkedBad());
		for (const decision of ["crowdsec-blocked", "appsec-blocked", "appsec-unavailable"]) {
			expect(bad.has(decision), `${decision} renders green`).toBe(true);
		}
	});

	test("the classifier never marks a decision the filter does not offer", () => {
		const offered = new Set(offeredDecisions());
		expect(decisionsMarkedBad().filter((decision) => !offered.has(decision))).toEqual([]);
	});
});

describe("Recent traffic CrowdSec detail", () => {
	test("the traffic row renders the CrowdSec and AppSec verdicts", () => {
		expect(adminJs).toContain("crowdSecBadge(event.crowdsec)");
		expect(adminJs).toContain("appSecBadge(event.crowdsec)");
	});

	test("the API sends the parsed detail the badges read", async () => {
		const routes = await Bun.file("src/routes/admin-routes.ts").text();
		expect(routes).toContain("crowdsec: crowdSecDetail(event.crowdsec_json)");
	});
});
