import { config } from "../config.ts";
import { repository } from "../db/repository.ts";
import { Logger } from "../logger.ts";
import type { PendingChangeEntityType, PendingChangeRecord } from "../types.ts";
import { randomId } from "../utils/crypto.ts";

const MIN_LEAD_MS = 30_000;
const MAX_LEAD_MS = 366 * 86_400_000;

type PendingChangeApplier = (entityId: string, changes: Record<string, unknown>) => Promise<void>;

const appliers = new Map<PendingChangeEntityType, PendingChangeApplier>();

export function registerPendingChangeApplier(type: PendingChangeEntityType, applier: PendingChangeApplier): void {
	appliers.set(type, applier);
}

/** Parses an admin-supplied schedule timestamp. Returns null ("apply now") for anything blank or not far enough in the future. */
export function parseScheduleTime(value: unknown, now = Date.now()): number | null {
	if (value === undefined || value === null || value === "") return null;
	const timestamp = Number(value);
	if (!Number.isFinite(timestamp) || !Number.isInteger(timestamp)) {
		throw new Error("Scheduled apply time must be a valid timestamp");
	}
	if (timestamp > now + MAX_LEAD_MS) throw new Error("Scheduled apply time must be within the next year");
	if (timestamp < now + MIN_LEAD_MS) return null;
	return timestamp;
}

export async function stagePendingChange(
	entityType: PendingChangeEntityType,
	entityId: string,
	changes: Record<string, unknown>,
	summary: string,
	applyAt: number,
	createdBy: string | null,
): Promise<PendingChangeRecord> {
	const now = Date.now();
	const record: PendingChangeRecord = {
		id: randomId("pending"),
		entity_type: entityType,
		entity_id: entityId,
		changes_json: JSON.stringify(changes),
		summary,
		apply_at: applyAt,
		status: "pending",
		attempts: 0,
		last_error: null,
		created_by: createdBy,
		created_at: now,
		applied_at: null,
	};
	await repository.deleteFailedPendingChangesFor(entityType, entityId);
	await repository.insertPendingChange(record);
	return record;
}

/** Strictly the active schedule slot - used to reject staging a second change while one is already pending. */
export async function currentPendingChange(entityType: PendingChangeEntityType, entityId: string): Promise<PendingChangeRecord | null> {
	return await repository.pendingChangeFor(entityType, entityId);
}

/** The entity's current change (pending or failed) for display and for apply-now/cancel to act on. */
export async function pendingOrFailedChangeFor(entityType: PendingChangeEntityType, entityId: string): Promise<PendingChangeRecord | null> {
	return await repository.pendingOrFailedChangeFor(entityType, entityId);
}

export async function pendingChangesFor(entityType: PendingChangeEntityType, entityIds: string[]): Promise<PendingChangeRecord[]> {
	return await repository.pendingChangesFor(entityType, entityIds);
}

export async function cancelPendingChange(id: string): Promise<void> {
	const existing = await repository.pendingChangeById(id);
	if (!existing) throw new Error("Pending change not found");
	await repository.deletePendingChange(id);
}

export async function applyPendingChangeNow(id: string): Promise<void> {
	const pending = await repository.pendingChangeById(id);
	if (!pending) throw new Error("Pending change not found");
	const applier = appliers.get(pending.entity_type);
	if (!applier) throw new Error(`No pending-change applier registered for ${pending.entity_type}`);
	await applier(pending.entity_id, JSON.parse(pending.changes_json) as Record<string, unknown>);
	await repository.deletePendingChange(id);
}

export function pendingChangeView(record: PendingChangeRecord) {
	return {
		id: record.id,
		entityType: record.entity_type,
		entityId: record.entity_id,
		changes: JSON.parse(record.changes_json) as Record<string, unknown>,
		summary: record.summary,
		applyAt: Number(record.apply_at),
		status: record.status,
		attempts: Number(record.attempts),
		lastError: record.last_error,
		createdBy: record.created_by,
		createdAt: Number(record.created_at),
		appliedAt: record.applied_at === null ? null : Number(record.applied_at),
	};
}

let running = false;

export async function applyDuePendingChanges(): Promise<void> {
	if (config.ha.enabled && config.ha.role === "replica") return;
	if (running) return;
	running = true;
	try {
		const due = await repository.duePendingChanges(Date.now(), 100);
		for (const row of due) {
			const applier = appliers.get(row.entity_type);
			if (!applier) continue;
			try {
				await applier(row.entity_id, JSON.parse(row.changes_json) as Record<string, unknown>);
				await repository.updatePendingChangeStatus(row.id, "applied", row.attempts, row.apply_at, null, Date.now());
				Logger.info(`Applied scheduled ${row.entity_type} change for ${row.entity_id}: ${row.summary}`);
			} catch (error) {
				const attempts = row.attempts + 1;
				const message = error instanceof Error ? error.message : String(error);
				if (attempts >= config.pendingChanges.maxAttempts) {
					await repository.updatePendingChangeStatus(row.id, "failed", attempts, row.apply_at, message, null);
					Logger.error(`Giving up on scheduled ${row.entity_type} change for ${row.entity_id} after ${attempts} attempts`, { error });
				} else {
					const nextAttemptAt = Date.now() + config.pendingChanges.retryBackoffSeconds * 1_000;
					await repository.updatePendingChangeStatus(row.id, "pending", attempts, nextAttemptAt, message, null);
					Logger.warn(`Scheduled ${row.entity_type} change for ${row.entity_id} failed, retrying`, { error });
				}
			}
		}
	} finally {
		running = false;
	}
}

export function startPendingChangeScheduler(): void {
	const timer = setInterval(() => void applyDuePendingChanges(), config.pendingChanges.pollIntervalSeconds * 1_000);
	(timer as unknown as { unref?: () => void }).unref?.();
}
