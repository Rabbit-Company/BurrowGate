import { beforeEach, describe, expect, test } from "bun:test";
import {
	clearStreamBandwidthLimitTracker,
	pruneStaleStreamBandwidthLimitEntries,
	recordStreamBandwidthLimitBytes,
	streamBandwidthLimitEntryCount,
} from "../src/services/stream-connection-tracker.ts";

const policy = { enabled: true, maxBytes: 1_000, windowSeconds: 60 };

beforeEach(() => {
	clearStreamBandwidthLimitTracker();
});

describe("recordStreamBandwidthLimitBytes", () => {
	test("returns false while under the threshold", () => {
		expect(recordStreamBandwidthLimitBytes("stream-a", "tcp", "203.0.113.1", 500, policy)).toBe(false);
	});

	test("returns true exactly once when the window total crosses maxBytes", () => {
		const now = Date.now();
		expect(recordStreamBandwidthLimitBytes("stream-a", "tcp", "203.0.113.2", 600, policy, now)).toBe(false);
		expect(recordStreamBandwidthLimitBytes("stream-a", "tcp", "203.0.113.2", 600, policy, now)).toBe(true);
		expect(recordStreamBandwidthLimitBytes("stream-a", "tcp", "203.0.113.2", 600, policy, now)).toBe(false);
	});

	test("tracks TCP and UDP independently for the same stream and IP", () => {
		const now = Date.now();
		expect(recordStreamBandwidthLimitBytes("stream-a", "tcp", "203.0.113.3", 1_500, policy, now)).toBe(true);
		expect(recordStreamBandwidthLimitBytes("stream-a", "udp", "203.0.113.3", 500, policy, now)).toBe(false);
	});

	test("a new window resets the counter and violation flag", () => {
		const windowMs = policy.windowSeconds * 1_000;
		const now = Date.now();
		expect(recordStreamBandwidthLimitBytes("stream-a", "tcp", "203.0.113.4", 1_500, policy, now)).toBe(true);
		expect(recordStreamBandwidthLimitBytes("stream-a", "tcp", "203.0.113.4", 500, policy, now + windowMs)).toBe(false);
	});

	test("does nothing when disabled", () => {
		expect(recordStreamBandwidthLimitBytes("stream-a", "tcp", "203.0.113.5", 10_000, { ...policy, enabled: false })).toBe(false);
		expect(streamBandwidthLimitEntryCount()).toBe(0);
	});

	test("ignores the unknown IP sentinel and non-positive byte counts", () => {
		expect(recordStreamBandwidthLimitBytes("stream-a", "tcp", "unknown", 10_000, policy)).toBe(false);
		expect(recordStreamBandwidthLimitBytes("stream-a", "tcp", "203.0.113.6", 0, policy)).toBe(false);
		expect(streamBandwidthLimitEntryCount()).toBe(0);
	});
});

describe("pruneStaleStreamBandwidthLimitEntries", () => {
	test("evicts entries whose window ended long ago and keeps recent ones", () => {
		const now = Date.now();
		recordStreamBandwidthLimitBytes("stream-a", "tcp", "203.0.113.7", 10, policy, now - 3 * 60 * 60 * 1_000);
		recordStreamBandwidthLimitBytes("stream-a", "tcp", "203.0.113.8", 10, policy, now);
		expect(streamBandwidthLimitEntryCount()).toBe(2);
		pruneStaleStreamBandwidthLimitEntries(now);
		expect(streamBandwidthLimitEntryCount()).toBe(1);
	});
});
