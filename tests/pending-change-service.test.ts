import { describe, expect, test } from "bun:test";
import { config } from "../src/config.ts";
import { repository } from "../src/db/repository.ts";
import {
	applyDuePendingChanges,
	applyPendingChangeNow,
	cancelPendingChange,
	currentPendingChange,
	parseScheduleTime,
	pendingChangesFor,
	pendingOrFailedChangeFor,
	registerPendingChangeApplier,
	stagePendingChange,
} from "../src/services/pending-change-service.ts";

describe("parseScheduleTime", () => {
	const now = 1_700_000_000_000;

	test("treats blank input as apply-now", () => {
		expect(parseScheduleTime(undefined, now)).toBeNull();
		expect(parseScheduleTime(null, now)).toBeNull();
		expect(parseScheduleTime("", now)).toBeNull();
	});

	test("treats a near-immediate timestamp as apply-now", () => {
		expect(parseScheduleTime(now + 1_000, now)).toBeNull();
	});

	test("accepts a timestamp far enough in the future", () => {
		expect(parseScheduleTime(now + 60_000, now)).toBe(now + 60_000);
	});

	test("rejects a non-numeric value", () => {
		expect(() => parseScheduleTime("not-a-date", now)).toThrow();
	});

	test("rejects a timestamp beyond the one-year horizon", () => {
		expect(() => parseScheduleTime(now + 400 * 86_400_000, now)).toThrow("within the next year");
	});
});

describe("pending change lifecycle", () => {
	test("stages, applies when due, and clears the pending row", async () => {
		const calls: Array<{ entityId: string; changes: Record<string, unknown> }> = [];
		registerPendingChangeApplier("stream", async (entityId, changes) => {
			calls.push({ entityId, changes });
		});

		const staged = await stagePendingChange("stream", "stream-lifecycle-1", { forward_port: 4321 }, "Forward port change", Date.now() - 1_000, "admin");
		expect(await currentPendingChange("stream", "stream-lifecycle-1")).not.toBeNull();

		await applyDuePendingChanges();

		expect(calls).toEqual([{ entityId: "stream-lifecycle-1", changes: { forward_port: 4321 } }]);
		expect(await currentPendingChange("stream", "stream-lifecycle-1")).toBeNull();
		const finished = await repository.pendingChangeById(staged.id);
		expect(finished?.status).toBe("applied");
	});

	test("retries on failure and eventually marks the change failed", async () => {
		let attempts = 0;
		registerPendingChangeApplier("stream", async () => {
			attempts += 1;
			throw new Error("simulated failure");
		});

		const staged = await stagePendingChange("stream", "stream-lifecycle-2", { forward_port: 1 }, "Always fails", Date.now() - 1_000, null);

		for (let i = 0; i < config.pendingChanges.maxAttempts; i++) {
			await applyDuePendingChanges();
			const row = await repository.pendingChangeById(staged.id);
			if (row?.status === "failed") break;
			// Force the row due again immediately instead of waiting out the real retry backoff.
			await repository.updatePendingChangeStatus(staged.id, "pending", row!.attempts, Date.now(), row!.last_error, null);
		}

		const finalRow = await repository.pendingChangeById(staged.id);
		expect(finalRow?.status).toBe("failed");
		expect(finalRow?.attempts).toBe(config.pendingChanges.maxAttempts);
		expect(attempts).toBe(config.pendingChanges.maxAttempts);

		// A failed change is no longer an active schedule (staging a new one isn't blocked)...
		expect(await currentPendingChange("stream", "stream-lifecycle-2")).toBeNull();
		// ...but it's still visible for display and for apply-now/cancel to act on.
		expect((await pendingOrFailedChangeFor("stream", "stream-lifecycle-2"))?.id).toBe(staged.id);
		expect((await pendingChangesFor("stream", ["stream-lifecycle-2"])).map((row) => row.id)).toEqual([staged.id]);
	});

	test("apply-now can retry a failed change", async () => {
		let succeed = false;
		registerPendingChangeApplier("stream", async () => {
			if (!succeed) throw new Error("still failing");
		});

		const staged = await stagePendingChange("stream", "stream-lifecycle-retry", { forward_port: 1 }, "Retry me", Date.now() - 1_000, null);
		for (let i = 0; i < config.pendingChanges.maxAttempts; i++) {
			await applyDuePendingChanges();
			const row = await repository.pendingChangeById(staged.id);
			if (row?.status === "failed") break;
			await repository.updatePendingChangeStatus(staged.id, "pending", row!.attempts, Date.now(), row!.last_error, null);
		}
		expect((await repository.pendingChangeById(staged.id))?.status).toBe("failed");

		succeed = true;
		await applyPendingChangeNow(staged.id);
		expect(await repository.pendingChangeById(staged.id)).toBeNull();
		expect(await pendingOrFailedChangeFor("stream", "stream-lifecycle-retry")).toBeNull();
	});

	test("staging a new change clears a stale failed row for the same entity", async () => {
		registerPendingChangeApplier("stream", async () => {
			throw new Error("simulated failure");
		});
		const failed = await stagePendingChange("stream", "stream-lifecycle-restage", { forward_port: 1 }, "Will fail", Date.now() - 1_000, null);
		for (let i = 0; i < config.pendingChanges.maxAttempts; i++) {
			await applyDuePendingChanges();
			const row = await repository.pendingChangeById(failed.id);
			if (row?.status === "failed") break;
			await repository.updatePendingChangeStatus(failed.id, "pending", row!.attempts, Date.now(), row!.last_error, null);
		}
		expect((await repository.pendingChangeById(failed.id))?.status).toBe("failed");

		const restaged = await stagePendingChange("stream", "stream-lifecycle-restage", { forward_port: 2 }, "Fresh schedule", Date.now() + 3_600_000, null);

		expect(await repository.pendingChangeById(failed.id)).toBeNull();
		expect((await pendingOrFailedChangeFor("stream", "stream-lifecycle-restage"))?.id).toBe(restaged.id);
	});

	test("cancel removes the pending row without invoking the applier", async () => {
		let called = false;
		registerPendingChangeApplier("stream", async () => {
			called = true;
		});

		const staged = await stagePendingChange("stream", "stream-lifecycle-3", { forward_port: 2 }, "Cancel me", Date.now() + 3_600_000, null);
		await cancelPendingChange(staged.id);

		expect(await currentPendingChange("stream", "stream-lifecycle-3")).toBeNull();
		expect(await repository.pendingChangeById(staged.id)).toBeNull();
		expect(called).toBe(false);
	});

	test("apply-now invokes the applier immediately regardless of the scheduled time", async () => {
		const calls: Array<Record<string, unknown>> = [];
		registerPendingChangeApplier("stream", async (_entityId, changes) => {
			calls.push(changes);
		});

		const staged = await stagePendingChange("stream", "stream-lifecycle-4", { forward_port: 3 }, "Apply now", Date.now() + 3_600_000, null);
		await applyPendingChangeNow(staged.id);

		expect(calls).toEqual([{ forward_port: 3 }]);
		expect(await repository.pendingChangeById(staged.id)).toBeNull();
	});
});
