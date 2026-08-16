import { describe, expect, test } from "bun:test";
import { resolveStreamBandwidthPolicy, serializeStreamBandwidthPolicy, storedStreamBandwidthPolicy } from "../src/services/stream-bandwidth-policy-service.ts";
import type { StreamRecord } from "../src/types.ts";

describe("stream bandwidth policy", () => {
	test("defaults to disabled with a 50 MiB / 60s / 1h shape for both protocols", () => {
		const policy = storedStreamBandwidthPolicy(null);
		expect(policy.tcp).toEqual({ enabled: false, maxBytes: 50 * 1_024 * 1_024, windowSeconds: 60, banSeconds: 3_600 });
		expect(policy.udp).toEqual({ enabled: false, maxBytes: 50 * 1_024 * 1_024, windowSeconds: 60, banSeconds: 3_600 });
	});

	test("TCP and UDP are configured independently", () => {
		const json = serializeStreamBandwidthPolicy({
			tcp: { enabled: true, maxBytes: 1_000, windowSeconds: 30, banSeconds: 900 },
			udp: { enabled: false, maxBytes: 2_000, windowSeconds: 45, banSeconds: 1_800 },
		});
		const policy = storedStreamBandwidthPolicy(json);
		expect(policy.tcp).toEqual({ enabled: true, maxBytes: 1_000, windowSeconds: 30, banSeconds: 900 });
		expect(policy.udp).toEqual({ enabled: false, maxBytes: 2_000, windowSeconds: 45, banSeconds: 1_800 });
	});

	test("updating one protocol preserves the other's stored settings", () => {
		const existing = serializeStreamBandwidthPolicy({
			tcp: { enabled: true, maxBytes: 1_000, windowSeconds: 30, banSeconds: 900 },
			udp: { enabled: true, maxBytes: 2_000, windowSeconds: 45, banSeconds: 1_800 },
		});
		const updated = serializeStreamBandwidthPolicy({ tcp: { enabled: false, maxBytes: 1_000, windowSeconds: 30, banSeconds: 900 } }, existing);
		const policy = storedStreamBandwidthPolicy(updated);
		expect(policy.tcp.enabled).toBe(false);
		expect(policy.udp).toEqual({ enabled: true, maxBytes: 2_000, windowSeconds: 45, banSeconds: 1_800 });
	});

	test("rejects an out-of-range threshold", () => {
		expect(() => serializeStreamBandwidthPolicy({ tcp: { maxBytes: 0 } })).toThrow();
	});

	test("resolveStreamBandwidthPolicy reads from the stream record's bandwidth_policy_json", () => {
		const record = { bandwidth_policy_json: serializeStreamBandwidthPolicy({ tcp: { enabled: true } }) } as StreamRecord;
		expect(resolveStreamBandwidthPolicy(record).tcp.enabled).toBe(true);
		expect(resolveStreamBandwidthPolicy(record).udp.enabled).toBe(false);
	});
});
