import { describe, expect, test } from "bun:test";
import { ipAffinityOrigin, LoadBalancer } from "../src/services/load-balancer-service.ts";
import type { SiteOriginRecord, SiteRecord } from "../src/types.ts";

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

describe("load-balancer passive failure quarantine", () => {
	const site = {
		id: "site-1",
		load_balancing_algorithm: "failover",
		load_balancing_affinity: 0,
		health_check_failure_mode: "monitor",
	} as SiteRecord;

	function balancerWith(origins: SiteOriginRecord[]): LoadBalancer {
		const balancer = new LoadBalancer();
		const state = balancer as unknown as { originsBySite: Map<string, SiteOriginRecord[]> };
		state.originsBySite.set(site.id, origins);
		return balancer;
	}

	test("uses another origin while one is passively quarantined", async () => {
		const balancer = balancerWith([origin("origin-a"), origin("origin-b")]);
		balancer.reportPassiveFailure("origin-a");

		expect((await balancer.selectOrigin(site, null, "203.0.113.1"))?.id).toBe("origin-b");
	});

	test("keeps the last origin available instead of turning one request failure into site-wide 503s", async () => {
		const balancer = balancerWith([origin("origin-a")]);
		balancer.reportPassiveFailure("origin-a");

		expect((await balancer.selectOrigin(site, null, "203.0.113.1"))?.id).toBe("origin-a");
	});
});
