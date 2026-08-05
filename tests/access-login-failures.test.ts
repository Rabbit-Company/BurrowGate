import { describe, expect, test } from "bun:test";
import { LoginFailureTracker } from "../src/services/access-list-service.ts";

describe("access login failure tracking", () => {
	test("evicts old keys instead of growing past its memory ceiling", () => {
		const tracker = new LoginFailureTracker(2, 1_000, 2);
		tracker.record(["first", "second"], 0);
		tracker.record(["third"], 1);

		expect(tracker.size).toBe(2);
		expect(tracker.status(["first"], 1)).toBe(0);
		tracker.record(["third"], 2);
		expect(tracker.status(["third"], 2)).toBe(1);
	});

	test("removes an expired key when it is checked", () => {
		const tracker = new LoginFailureTracker(10, 100, 1);
		tracker.record(["visitor"], 0);
		expect(tracker.status(["visitor"], 50)).toBe(1);
		expect(tracker.status(["visitor"], 100)).toBe(0);
		expect(tracker.size).toBe(0);
	});

	test("removes only entries belonging to a deleted site", () => {
		const tracker = new LoginFailureTracker(10, 1_000, 1);
		tracker.record(["site:one:ip:192.0.2.1", "site:two:ip:192.0.2.2"], 0);
		tracker.clearPrefix("site:one:");

		expect(tracker.status(["site:one:ip:192.0.2.1"], 1)).toBe(0);
		expect(tracker.status(["site:two:ip:192.0.2.2"], 1)).toBe(1);
		expect(tracker.size).toBe(1);
	});
});
