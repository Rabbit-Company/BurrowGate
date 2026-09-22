import { describe, expect, test } from "bun:test";
import { repository } from "../src/db/repository.ts";
import { recordEvent } from "../src/services/event-service.ts";
import { createSite } from "../src/services/site-service.ts";
import { randomId } from "../src/utils/crypto.ts";

/**
 * `insertEvent` writes an explicit column list, so a field added to the record type but not to that
 * SQL is dropped silently: TypeScript is satisfied, the insert succeeds, and the value vanishes.
 * That is exactly how the CrowdSec and AppSec detail went missing from every HTTP request. These
 * tests write through the real path and read back from the database, so the column list cannot
 * drift from the record again without a failure.
 */

async function site() {
	return (await createSite({ name: "CrowdSec events", publicHost: `cs-evt-${crypto.randomUUID()}.test`, originUrl: "http://origin.test" })).site;
}

describe("CrowdSec detail survives a write and read", () => {
	test("a decision match is stored with its scenario and origin", async () => {
		const created = await site();
		const requestId = randomId("evt");
		await recordEvent({
			siteId: created.id,
			sessionId: null,
			ip: "203.0.113.5",
			method: "GET",
			path: "/",
			status: 403,
			decision: "crowdsec-blocked",
			latencyMs: 3,
			requestId,
			crowdsec: { remediation: "ban", scope: "ip", value: "203.0.113.5", origin: "CAPI", scenario: "crowdsecurity/http-probing", enforcement: "block" },
		});

		const stored = await repository.eventById(requestId);
		expect(stored).not.toBeNull();
		const detail = JSON.parse(stored!.crowdsec_json ?? "null") as Record<string, unknown>;
		expect(detail).toMatchObject({ remediation: "ban", scope: "ip", origin: "CAPI", scenario: "crowdsecurity/http-probing", enforcement: "block" });
	});

	test("an AppSec verdict is stored with its action and body outcome", async () => {
		const created = await site();
		const requestId = randomId("evt");
		await recordEvent({
			siteId: created.id,
			sessionId: null,
			ip: "203.0.113.6",
			method: "POST",
			path: "/rpc2",
			status: 403,
			decision: "appsec-blocked",
			latencyMs: 4,
			requestId,
			appsec: { status: "blocked", action: "ban", mode: "block", body: "inspected", durationMs: 2 },
		});

		const stored = await repository.eventById(requestId);
		const detail = JSON.parse(stored!.crowdsec_json ?? "null") as { appsec?: Record<string, unknown> };
		expect(detail.appsec).toMatchObject({ status: "blocked", action: "ban", mode: "block", body: "inspected" });
	});

	test("a decision match and an AppSec verdict coexist in one record", async () => {
		const created = await site();
		const requestId = randomId("evt");
		await recordEvent({
			siteId: created.id,
			sessionId: null,
			ip: "203.0.113.7",
			method: "POST",
			path: "/rpc2",
			status: 403,
			decision: "appsec-blocked",
			latencyMs: 5,
			requestId,
			crowdsec: { remediation: "captcha", scope: "range", value: "203.0.113.0/24", origin: "cscli", scenario: "manual", enforcement: "monitor" },
			appsec: { status: "blocked", action: "ban", mode: "block", body: "inspected", durationMs: 1 },
		});

		const stored = await repository.eventById(requestId);
		const detail = JSON.parse(stored!.crowdsec_json ?? "null") as { remediation?: string; appsec?: { status?: string } };
		expect(detail.remediation).toBe("captcha");
		expect(detail.appsec?.status).toBe("blocked");
	});

	test("a request with neither stores null rather than an empty object", async () => {
		const created = await site();
		const requestId = randomId("evt");
		await recordEvent({
			siteId: created.id,
			sessionId: null,
			ip: "203.0.113.8",
			method: "GET",
			path: "/",
			status: 200,
			decision: "proxied",
			latencyMs: 1,
			requestId,
		});

		expect((await repository.eventById(requestId))!.crowdsec_json ?? null).toBeNull();
	});
});
