import { describe, expect, test } from "bun:test";
import { addIpRule, banIpForBandwidthLimit, evaluateIp } from "../src/services/ip-rule-service.ts";
import { banStreamIpForBandwidthLimit, evaluateStreamIp } from "../src/services/stream-ip-rule-service.ts";
import { createSite } from "../src/services/site-service.ts";
import type { StreamRecord } from "../src/types.ts";

async function site() {
	return (await createSite({ name: "Bandwidth ban", publicHost: `bw-ban-${crypto.randomUUID()}.test`, originUrl: "http://origin.test" })).site;
}

function stream(overrides: Partial<StreamRecord> = {}): StreamRecord {
	const now = Date.now();
	return {
		id: `stream_${crypto.randomUUID()}`,
		incoming_port: 34567,
		forward_host: "origin.test",
		forward_port: 45678,
		tcp_enabled: 1,
		udp_enabled: 1,
		proxy_protocol: "disabled",
		certificate_id: null,
		event_retention_days: 7,
		default_ip_action: "inherit",
		default_country_action: "inherit",
		max_connections_per_ip: 0,
		connection_rate_limit_enabled: 0,
		connection_rate_limit_algorithm: "sliding-window",
		connection_rate_limit_window_ms: 60_000,
		connection_rate_limit_max: 60,
		connection_rate_limit_refill_rate: 10,
		connection_rate_limit_refill_interval_ms: 1_000,
		connection_rate_limit_precision_ms: 100,
		udp_amplification_max_ratio: 0,
		protection_policy_json: null,
		bandwidth_policy_json: null,
		origin_health_check_enabled: 0,
		origin_health_check_interval_seconds: 10,
		origin_health_check_timeout_ms: 3_000,
		created_at: now,
		updated_at: now,
		...overrides,
	};
}

describe("banIpForBandwidthLimit", () => {
	test("creates a temp block with the configured duration", async () => {
		const s = await site();
		const ban = await banIpForBandwidthLimit(s, "198.51.100.1", 50 * 1_024 * 1_024, 60, 1_800);
		expect(ban).not.toBeNull();
		expect(ban!.action).toBe("block");
		expect(ban!.expires_at).not.toBeNull();
		expect(ban!.expires_at! - Date.now()).toBeGreaterThan(1_700 * 1_000);
		expect(ban!.reason).toContain("50.0 MiB");

		const decision = await evaluateIp(s, "198.51.100.1");
		expect(decision.action).toBe("block");
	});

	test("skips banning an IP that already has an active block", async () => {
		const s = await site();
		await addIpRule(s.id, "198.51.100.2", "block", "manual block", null);
		const ban = await banIpForBandwidthLimit(s, "198.51.100.2", 1_000, 60, 1_800);
		expect(ban).toBeNull();
	});

	test("does nothing when banSeconds is zero or the IP is unknown", async () => {
		const s = await site();
		expect(await banIpForBandwidthLimit(s, "198.51.100.3", 1_000, 60, 0)).toBeNull();
		expect(await banIpForBandwidthLimit(s, "unknown", 1_000, 60, 1_800)).toBeNull();
	});
});

describe("banStreamIpForBandwidthLimit", () => {
	test("creates a protocol-specific temp block", async () => {
		const record = stream();
		const ban = await banStreamIpForBandwidthLimit(record, "198.51.100.10", "udp", 10 * 1_024 * 1_024, 30, 900);
		expect(ban).not.toBeNull();
		expect(ban!.action).toBe("block");
		expect(ban!.reason).toContain("UDP");

		const decision = await evaluateStreamIp(record, "198.51.100.10");
		expect(decision.action).toBe("block");
	});

	test("skips banning an IP that already has an active block on the stream", async () => {
		const record = stream();
		const first = await banStreamIpForBandwidthLimit(record, "198.51.100.11", "tcp", 1_000, 60, 900);
		expect(first).not.toBeNull();
		const second = await banStreamIpForBandwidthLimit(record, "198.51.100.11", "tcp", 1_000, 60, 900);
		expect(second).toBeNull();
	});
});
