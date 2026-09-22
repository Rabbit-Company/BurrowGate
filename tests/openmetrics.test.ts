import { describe, expect, test } from "bun:test";
import { BurrowGateOpenMetrics, metricsRequestAuthorized } from "../src/services/openmetrics-service.ts";

describe("OpenMetrics exporter", () => {
	test("exports bounded HTTP and stream labels without client-level data", () => {
		const metrics = new BurrowGateOpenMetrics({ enabled: true, environment: "test", version: "test-version" });
		metrics.recordHttpRequest({
			siteId: "site-1",
			method: "attacker-controlled-method",
			status: 200,
			decision: "proxied",
			latencyMs: 25,
		});
		metrics.recordHttpCacheRequest("site-1", "hit", 512);
		metrics.recordHttpProtectionRequest("site-1", "monitored");
		metrics.recordHttpCacheStore("site-1");
		metrics.recordHttpCacheEviction("site-1", "capacity", 2);
		metrics.setHttpCacheStorage("site-1", 3, 1_024);
		metrics.recordStreamBandwidth(
			{ streamId: "stream-1", incomingPort: 443, ip: "203.0.113.10", countryCode: "SI", protocol: "tcp" },
			{ clientToUpstreamBytes: 42 },
		);
		metrics.setOriginHealth("site-1", "unhealthy");
		metrics.setOriginBackendHealth("site-1", "origin-1", "unhealthy");
		metrics.recordOriginHealthCheck("site-1", "origin-1", false, 125);
		metrics.recordNotificationDelivery("site-1", "retry");
		metrics.setCrowdSecState({
			enabled: true,
			lastPolledAt: 1_700_000_500_000,
			lastSuccessAt: 1_700_000_000_000,
			decisionsByScope: { ip: 42_000, range: 300, country: 2, as: 0 },
		});
		metrics.recordCrowdSecPoll("ok");
		metrics.recordCrowdSecPoll("error");

		const output = metrics.metricsText();
		expect(output).toContain('burrowgate_build_info{environment="test",version="test-version"} 1');
		expect(output).toContain('decision="proxied",method="OTHER",site_id="site-1",status_class="2xx"');
		expect(output).toContain('burrowgate_http_cache_requests_total{outcome="hit",site_id="site-1"} 1');
		expect(output).toContain('burrowgate_http_cache_served_bytes_total{site_id="site-1"} 512');
		expect(output).toContain('burrowgate_http_cache_entries{site_id="site-1"} 3');
		expect(output).toContain('burrowgate_http_cache_size_bytes{site_id="site-1"} 1024');
		expect(output).toContain('burrowgate_http_protection_requests_total{outcome="monitored",site_id="site-1"} 1');
		expect(output).toContain('direction="client_to_upstream",protocol="tcp",stream_id="stream-1"} 42');
		expect(output).toContain('burrowgate_origin_health_state{site_id="site-1",state="unhealthy"} 1');
		expect(output).toContain('burrowgate_origin_backend_health_state{origin_id="origin-1",site_id="site-1",state="unhealthy"} 1');
		expect(output).toContain('burrowgate_origin_health_checks_total{origin_id="origin-1",outcome="failure",site_id="site-1"} 1');
		expect(output).toContain('burrowgate_notification_deliveries_total{outcome="retry",site_id="site-1"} 1');
		expect(output).toContain("burrowgate_crowdsec_enabled 1");
		expect(output).toContain('burrowgate_crowdsec_decisions{scope="ip"} 42000');
		expect(output).toContain('burrowgate_crowdsec_decisions{scope="range"} 300');
		// Published as a raw timestamp so a query computes staleness with time() - x.
		expect(output).toContain("burrowgate_crowdsec_last_success_timestamp_seconds 1700000000");
		expect(output).toContain("burrowgate_crowdsec_last_poll_timestamp_seconds 1700000500");
		expect(output).toContain('burrowgate_crowdsec_polls_total{outcome="ok"} 1');
		expect(output).toContain('burrowgate_crowdsec_polls_total{outcome="error"} 1');
		expect(output).not.toContain("203.0.113.10");
		expect(output).not.toContain('country="SI"');
		expect(output.trimEnd().endsWith("# EOF")).toBe(true);
	});

	test("exports authoritative stream runtime state", () => {
		const metrics = new BurrowGateOpenMetrics({ enabled: true });
		metrics.setStreamRuntime({
			id: "stream-1",
			tcp: "active",
			udp: "error",
			activeTcpConnections: 3,
			activeUdpPeers: 0,
		});

		const output = metrics.metricsText();
		expect(output).toContain('burrowgate_stream_active_connections{protocol="tcp",stream_id="stream-1"} 3');
		expect(output).toContain('burrowgate_stream_listener_configured{protocol="udp",stream_id="stream-1"} 1');
		expect(output).toContain('burrowgate_stream_listener_up{protocol="udp",stream_id="stream-1"} 0');
	});

	test("supports an optional constant-time bearer token check", async () => {
		expect(await metricsRequestAuthorized(new Request("https://example.test/metrics"), null)).toBe(true);
		expect(await metricsRequestAuthorized(new Request("https://example.test/metrics"), "secret-token")).toBe(false);
		expect(
			await metricsRequestAuthorized(new Request("https://example.test/metrics", { headers: { authorization: "Bearer wrong-token" } }), "secret-token"),
		).toBe(false);
		expect(
			await metricsRequestAuthorized(new Request("https://example.test/metrics", { headers: { authorization: "Bearer secret-token" } }), "secret-token"),
		).toBe(true);
	});
});
