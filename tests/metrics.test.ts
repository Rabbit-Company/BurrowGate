import { describe, expect, test } from "bun:test";
import { fillCacheMetricSeries, fillTrafficMetricSeries, type CacheMetricPoint, type TrafficMetricPoint } from "../src/db/repository.ts";

function point(bucket: number, requests: number): TrafficMetricPoint {
	return { bucket, requests, blocked: 0, errors: 0, averageLatency: requests ? 25 : 0 };
}

describe("traffic metric bucket completion", () => {
	test("fills missing one-minute buckets with zero values", () => {
		const minute = 60_000;
		const start = Date.UTC(2026, 7, 3, 6, 0, 0);
		const rows = [point(start, 2), point(start + 2 * minute, 5)];
		const series = fillTrafficMetricSeries(rows, start, start + 3 * minute + 15_000, minute);

		expect(series).toHaveLength(4);
		expect(series.map((item) => item.requests)).toEqual([2, 0, 5, 0]);
		expect(series[1]).toEqual({
			bucket: start + minute,
			requests: 0,
			blocked: 0,
			errors: 0,
			averageLatency: 0,
		});
	});

	test("aligns an arbitrary start time to the containing bucket", () => {
		const minute = 60_000;
		const bucketStart = Date.UTC(2026, 7, 3, 6, 0, 0);
		const selectedStart = bucketStart + 20_000;
		const rows = [point(bucketStart, 3)];
		const series = fillTrafficMetricSeries(rows, selectedStart, bucketStart + minute + 40_000, minute);

		expect(series.map((item) => item.bucket)).toEqual([bucketStart, bucketStart + minute]);
		expect(series.map((item) => item.requests)).toEqual([3, 0]);
	});
});

describe("cache metric bucket completion", () => {
	test("fills missing buckets without changing recorded hit ratios", () => {
		const minute = 60_000;
		const start = Date.UTC(2026, 7, 6, 12, 0, 0);
		const rows: CacheMetricPoint[] = [
			{ bucket: start, hits: 3, misses: 1, bypasses: 2, hitRatio: 75 },
			{ bucket: start + 2 * minute, hits: 1, misses: 1, bypasses: 0, hitRatio: 50 },
		];
		const series = fillCacheMetricSeries(rows, start + 10_000, start + 2 * minute + 30_000, minute);

		expect(series).toHaveLength(3);
		expect(series[0]).toEqual(rows[0]);
		expect(series[1]).toEqual({ bucket: start + minute, hits: 0, misses: 0, bypasses: 0, hitRatio: 0 });
		expect(series[2]).toEqual(rows[1]);
	});
});
