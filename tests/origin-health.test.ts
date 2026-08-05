import { describe, expect, test } from "bun:test";
import {
	advanceOriginHealthState,
	healthStatusAfterConfigurationChange,
	originHealthTarget,
	type HealthCheckResult,
} from "../src/services/origin-health-service.ts";
import type { OriginHealthStatusRecord } from "../src/types.ts";

function status(state: OriginHealthStatusRecord["state"] = "unknown"): OriginHealthStatusRecord {
	return {
		site_id: "site-1",
		state,
		consecutive_failures: 0,
		consecutive_successes: 0,
		last_checked_at: null,
		last_healthy_at: null,
		last_unhealthy_at: null,
		last_status: null,
		last_latency_ms: null,
		last_error: null,
		updated_at: 0,
	};
}

function result(healthy: boolean, checkedAt: number): HealthCheckResult {
	return {
		healthy,
		status: healthy ? 204 : 503,
		latencyMs: 12.4,
		error: healthy ? null : "Health endpoint returned HTTP 503",
		checkedAt,
	};
}

describe("origin health checks", () => {
	test("resolves the health path at the origin host instead of the proxy path prefix", () => {
		expect(originHealthTarget("https://origin.example/internal/app/", "/health?deep=1").toString()).toBe("https://origin.example/health?deep=1");
	});

	test("requires consecutive failures before becoming unhealthy", () => {
		const first = advanceOriginHealthState(status("healthy"), result(false, 1_000), 3, 2);
		const second = advanceOriginHealthState(first, result(false, 2_000), 3, 2);
		const third = advanceOriginHealthState(second, result(false, 3_000), 3, 2);
		expect(first.state).toBe("degraded");
		expect(second.state).toBe("degraded");
		expect(third.state).toBe("unhealthy");
		expect(third.last_unhealthy_at).toBe(3_000);
	});

	test("keeps maintenance active until the recovery threshold is met", () => {
		const unhealthy = { ...status("unhealthy"), consecutive_failures: 3, last_unhealthy_at: 1_000 };
		const first = advanceOriginHealthState(unhealthy, result(true, 2_000), 3, 2);
		const second = advanceOriginHealthState(first, result(true, 3_000), 3, 2);
		expect(first.state).toBe("unhealthy");
		expect(second.state).toBe("healthy");
		expect(second.last_unhealthy_at).toBe(1_000);
	});

	test("preserves an open incident when the origin configuration is corrected", () => {
		const unhealthy = { ...status("unhealthy"), consecutive_failures: 3, last_unhealthy_at: 1_000 };
		const reconfigured = healthStatusAfterConfigurationChange("site-1", unhealthy, true, 2_000);
		const firstSuccess = advanceOriginHealthState(reconfigured, result(true, 3_000), 3, 2);
		const recovered = advanceOriginHealthState(firstSuccess, result(true, 4_000), 3, 2);

		expect(reconfigured.state).toBe("unhealthy");
		expect(reconfigured.consecutive_failures).toBe(0);
		expect(firstSuccess.state).toBe("unhealthy");
		expect(recovered.state).toBe("healthy");
	});

	test("does not preserve an incident when checks are deliberately disabled", () => {
		const unhealthy = { ...status("unhealthy"), consecutive_failures: 3 };
		expect(healthStatusAfterConfigurationChange("site-1", unhealthy, false).state).toBe("disabled");
	});
});
