import { describe, expect, test } from "bun:test";
import { ipAffinityOrigin } from "../src/services/load-balancer-service.ts";
import type { SiteOriginRecord } from "../src/types.ts";

function origin(id: string, weight = 1): SiteOriginRecord {
	return {
		id,
		site_id: "site-1",
		name: id,
		origin_type: "proxy",
		origin_url: `https://${id}.example.test`,
		static_index_file: null,
		static_spa_fallback: 0,
		enabled: 1,
		draining: 0,
		priority: 0,
		weight,
		health_check_path: null,
		is_primary: id === "origin-a" ? 1 : 0,
		mtls_enabled: 0,
		mtls_certificate_pem: null,
		mtls_encrypted_private_key: null,
		mtls_ca_pem: null,
		created_at: 1,
		updated_at: 1,
	};
}

describe("load-balancer IP affinity", () => {
	test("keeps the same client on the same origin regardless of pool ordering", () => {
		const pool = [origin("origin-a"), origin("origin-b"), origin("origin-c")];
		const first = ipAffinityOrigin(pool, "203.0.113.42", false);
		const reordered = ipAffinityOrigin([pool[2]!, pool[0]!, pool[1]!], "203.0.113.42", false);

		expect(first).not.toBeNull();
		expect(reordered?.id).toBe(first?.id);
	});

	test("honors origin weights for clients without a session", () => {
		const pool = [origin("origin-a", 1), origin("origin-b", 9)];
		const assignments = { "origin-a": 0, "origin-b": 0 };
		for (let index = 0; index < 1_000; index += 1) {
			const selected = ipAffinityOrigin(pool, `198.51.100.${index}`, true)!;
			assignments[selected.id as keyof typeof assignments] += 1;
		}

		expect(assignments["origin-b"]).toBeGreaterThan(assignments["origin-a"] * 5);
	});

	test("returns null for an unavailable pool", () => {
		expect(ipAffinityOrigin([], "192.0.2.1", false)).toBeNull();
	});
});
