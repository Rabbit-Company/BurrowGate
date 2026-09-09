import { describe, expect, test } from "bun:test";
import { db } from "../src/db/client.ts";
import { repository } from "../src/db/repository.ts";
import { backfillEventPathOnly } from "../src/services/maintenance-service.ts";
import { monitoringData } from "../src/services/monitoring-service.ts";
import { createSite } from "../src/services/site-service.ts";

describe("request_events.path_only backfill", () => {
	async function legacyRow(siteId: string, path: string, at: number): Promise<void> {
		await db`INSERT INTO request_events (id,site_id,session_id,ip,method,path,status,decision,latency_ms,created_at)
		         VALUES (${`evt-legacy-${crypto.randomUUID()}`},${siteId},${null},'203.0.113.9','GET',${path},200,'allowed',10,${at})`;
	}

	test("maintenance fills path_only for rows written before the column existed", async () => {
		const site = (await createSite({ name: "Legacy", publicHost: `legacy-${crypto.randomUUID()}.test`, originUrl: "http://o.test" })).site;
		const at = Date.now() - 60_000;

		await legacyRow(site.id, "/legacy/page", at);
		await legacyRow(site.id, "/legacy/page?utm_source=news&session=s3cret", at);
		await legacyRow(site.id, "/legacy/other", at);

		const before = (await db`SELECT COUNT(*) AS count FROM request_events WHERE site_id=${site.id} AND path_only IS NULL`) as Array<{
			count: number | string;
		}>;
		expect(Number(before[0]!.count)).toBe(3);

		await backfillEventPathOnly();

		const after = (await db`SELECT COUNT(*) AS count FROM request_events WHERE site_id=${site.id} AND path_only IS NULL`) as Array<{
			count: number | string;
		}>;
		expect(Number(after[0]!.count)).toBe(0);
	});

	test("the backfill strips the query string, matching what insertEvent would have stored", async () => {
		const site = (await createSite({ name: "Legacy strip", publicHost: `legacy-${crypto.randomUUID()}.test`, originUrl: "http://o.test" })).site;
		const at = Date.now() - 60_000;

		await legacyRow(site.id, "/creator/alice?page=2", at);
		await backfillEventPathOnly();

		const rows = (await db`SELECT path, path_only FROM request_events WHERE site_id=${site.id}`) as Array<{ path: string; path_only: string }>;
		expect(rows).toHaveLength(1);
		expect(rows[0]!.path).toBe("/creator/alice?page=2");
		expect(rows[0]!.path_only).toBe("/creator/alice");
	});

	test("the backfill is bounded per batch and resumes on the next run", async () => {
		const site = (await createSite({ name: "Legacy batched", publicHost: `legacy-${crypto.randomUUID()}.test`, originUrl: "http://o.test" })).site;
		const at = Date.now() - 60_000;
		for (let i = 0; i < 5; i++) await legacyRow(site.id, `/batched/page-${i}`, at);

		const remaining = async () => {
			const rows = (await db`SELECT COUNT(*) AS count FROM request_events WHERE site_id=${site.id} AND path_only IS NULL`) as Array<{
				count: number | string;
			}>;
			return Number(rows[0]!.count);
		};

		expect(await remaining()).toBe(5);
		expect(await repository.backfillEventPathOnly(2)).toBe(2);
		expect(await remaining()).toBe(3);

		await backfillEventPathOnly(2);
		expect(await remaining()).toBe(0);
	});

	test("an over-long legacy path is truncated to the column width", async () => {
		const site = (await createSite({ name: "Legacy long", publicHost: `legacy-${crypto.randomUUID()}.test`, originUrl: "http://o.test" })).site;
		const long = `/${"a".repeat(3000)}`;

		await legacyRow(site.id, long, Date.now() - 60_000);
		await backfillEventPathOnly();

		const rows = (await db`SELECT path_only FROM request_events WHERE site_id=${site.id}`) as Array<{ path_only: string }>;
		expect(rows[0]!.path_only.length).toBe(2048);
		expect(long.startsWith(rows[0]!.path_only)).toBe(true);
	});

	test("backfilled history is visible to the paths view and to path scoping", async () => {
		const site = (await createSite({ name: "Legacy views", publicHost: `legacy-${crypto.randomUUID()}.test`, originUrl: "http://o.test" })).site;
		const at = Date.now() - 60_000;

		await legacyRow(site.id, "/creator/alice/post", at);
		await legacyRow(site.id, "/creator/alice/post?ref=x", at);
		await legacyRow(site.id, "/creator/bob/post", at);
		await backfillEventPathOnly();

		const paths = await monitoringData("paths", 24, site.id, Date.now());
		const labels = paths.rows.map((row) => row.label);
		expect(labels).toEqual(expect.arrayContaining(["/creator/alice/post", "/creator/bob/post"]));
		expect(labels.some((label) => label.includes("?"))).toBe(false);
		expect(paths.rows.find((row) => row.label === "/creator/alice/post")?.value).toBe(2);

		const overview = await monitoringData("overview", 24, site.id, Date.now());
		expect(overview.stats.find((stat) => stat.label === "Requests")?.value).toBe(3);

		const scoped = await monitoringData("overview", 24, site.id, Date.now(), { prefix: "/creator/alice" });
		expect(scoped.stats.find((stat) => stat.label === "Requests")?.value).toBe(2);
	});
});
