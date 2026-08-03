import { describe, expect, test } from "bun:test";
import { fillTrafficMetricSeries, type TrafficMetricPoint } from "../src/db/repository.ts";

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
});
