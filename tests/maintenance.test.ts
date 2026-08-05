import { describe, expect, test } from "bun:test";
import { runCleanupTasks, type CleanupTask } from "../src/services/maintenance-service.ts";

describe("incremental maintenance", () => {
	test("round-robins full batches and pauses only after writes", async () => {
		let now = 0;
		const calls = { history: 0, empty: 0 };
		const historyCounts = [2, 1];
		const tasks: CleanupTask[] = [
			{ name: "history", run: async () => ((calls.history += 1), historyCounts.shift() ?? 0) },
			{ name: "empty", run: async () => ((calls.empty += 1), 0) },
		];
		const result = await runCleanupTasks(tasks, {
			batchSize: 2,
			pauseMs: 10,
			timeBudgetMs: 100,
			clock: () => now,
			wait: async (milliseconds) => {
				now += milliseconds;
			},
		});

		expect(result).toEqual({ deleted: 3, attemptedBatches: 3, errors: 0 });
		expect(calls).toEqual({ history: 2, empty: 1 });
		expect(now).toBe(10);
	});

	test("stops repeated cleanup work at the time budget", async () => {
		let now = 0;
		let calls = 0;
		const result = await runCleanupTasks([{ name: "backlog", run: async () => ((calls += 1), 5) }], {
			batchSize: 5,
			pauseMs: 10,
			timeBudgetMs: 25,
			clock: () => now,
			wait: async (milliseconds) => {
				now += milliseconds;
			},
		});

		expect(calls).toBe(3);
		expect(result.deleted).toBe(15);
	});
});
