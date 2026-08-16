import { config } from "../config.ts";
import { repository } from "../db/repository.ts";
import { Logger } from "../logger.ts";
import { renewDueCertificates } from "./acme-service.ts";
import { backfillGeoIp } from "./geoip-service.ts";
import { invalidateNetworkPolicy } from "./ip-rule-service.ts";
import { openMetrics } from "./openmetrics-service.ts";
import { invalidateStreamNetworkPolicy } from "./stream-ip-rule-service.ts";

const DAY_MS = 86_400_000;
let cleanupRunning = false;
let housekeepingRunning = false;
let cleanupRotation = 0;

export interface CleanupTask {
	name: string;
	run(): Promise<number>;
}

export interface CleanupRunOptions {
	batchSize: number;
	pauseMs: number;
	timeBudgetMs: number;
	clock?: () => number;
	wait?: (milliseconds: number) => Promise<void>;
}

export interface CleanupRunResult {
	deleted: number;
	attemptedBatches: number;
	errors: number;
}

/**
 * Runs one small batch from each cleanup source before returning to a source
 * with more work. Pauses happen only after a write, keeping retention work
 * below the configured time budget while empty checks remain inexpensive.
 */
export async function runCleanupTasks(tasks: CleanupTask[], options: CleanupRunOptions): Promise<CleanupRunResult> {
	const clock = options.clock ?? performance.now;
	const wait = options.wait ?? (async (milliseconds: number) => await Bun.sleep(milliseconds));
	const startedAt = clock();
	const queue = [...tasks];
	let deleted = 0;
	let attemptedBatches = 0;
	let errors = 0;
	while (queue.length > 0 && (attemptedBatches === 0 || clock() - startedAt < options.timeBudgetMs)) {
		const task = queue.shift()!;
		attemptedBatches += 1;
		try {
			const count = await task.run();
			deleted += count;
			if (count >= options.batchSize) queue.push(task);
			if (count > 0 && options.pauseMs > 0 && queue.length > 0) await wait(options.pauseMs);
		} catch (error) {
			errors += 1;
			Logger.error(`[BurrowGate] Incremental cleanup failed for ${task.name}`, { error });
		}
	}
	return { deleted, attemptedBatches, errors };
}

async function cleanupTasks(now: number, batchSize: number): Promise<CleanupTask[]> {
	const tasks: CleanupTask[] = [
		{
			name: "expired challenge artifacts",
			run: async () => await repository.deleteExpiredChallengeArtifactsBatch(now, batchSize),
		},
		{
			name: "expired admin sessions",
			run: async () => await repository.deleteExpiredAdminSessionsBatch(now, batchSize),
		},
		{
			name: "expired ACME challenges",
			run: async () => await repository.deleteExpiredAcmeChallengesBatch(now, batchSize),
		},
	];
	for (const site of await repository.allSites()) {
		const retentionDays = Number(site.event_retention_days ?? config.eventRetentionDays);
		const cutoff = now - retentionDays * DAY_MS;
		tasks.push(
			{
				name: `request events for ${site.id}`,
				run: async () => await repository.deleteRequestEventsBeforeForSiteBatch(site.id, cutoff, batchSize),
			},
			{
				name: `bandwidth history for ${site.id}`,
				run: async () => await repository.deleteBandwidthBeforeForSiteBatch(site.id, cutoff, batchSize),
			},
			{
				name: `access sessions for ${site.id}`,
				run: async () => await repository.deleteSessionsBeforeForSiteBatch(site.id, cutoff, batchSize),
			},
			{
				name: `challenge flows for ${site.id}`,
				run: async () => await repository.deleteChallengeFlowsBeforeForSiteBatch(site.id, cutoff, batchSize),
			},
			{
				name: `expired network rules for ${site.id}`,
				run: async () => {
					const count = await repository.deleteExpiredRulesBeforeForSiteBatch(site.id, cutoff, batchSize);
					if (count > 0) invalidateNetworkPolicy(site.id);
					return count;
				},
			},
			{
				name: `certificate events for ${site.id}`,
				run: async () => await repository.deleteCertificateEventsBeforeForSiteBatch(site.id, cutoff, batchSize),
			},
			{
				name: `origin health events for ${site.id}`,
				run: async () => await repository.deleteOriginHealthEventsBeforeForSiteBatch(site.id, cutoff, batchSize),
			},
			{
				name: `origin health alerts for ${site.id}`,
				run: async () => await repository.deleteHealthAlertsBeforeForSiteBatch(site.id, cutoff, batchSize),
			},
			{
				name: `origin backend health events for ${site.id}`,
				run: async () => await repository.deleteBackendHealthEventsBeforeForSiteBatch(site.id, cutoff, batchSize),
			},
			{
				name: `origin latency history for ${site.id}`,
				run: async () => await repository.deleteOriginLatencyBeforeForSiteBatch(site.id, cutoff, batchSize),
			},
		);
	}
	tasks.push({
		name: "connectivity ping history",
		run: async () => await repository.deleteConnectivityPingBeforeBatch(now - config.connectivityMonitor.retentionDays * DAY_MS, batchSize),
	});
	for (const stream of await repository.allStreams()) {
		const cutoff = now - Number(stream.event_retention_days) * DAY_MS;
		tasks.push(
			{
				name: `stream events for ${stream.id}`,
				run: async () => await repository.deleteStreamEventsBeforeBatch(stream.id, cutoff, batchSize),
			},
			{
				name: `stream bandwidth for ${stream.id}`,
				run: async () => await repository.deleteStreamBandwidthBeforeBatch(stream.id, cutoff, batchSize),
			},
			{
				name: `stream origin latency for ${stream.id}`,
				run: async () => await repository.deleteStreamOriginLatencyBeforeBatch(stream.id, cutoff, batchSize),
			},
			{
				name: `expired network rules for stream ${stream.id}`,
				run: async () => {
					const count = await repository.deleteExpiredStreamRulesBeforeForStreamBatch(stream.id, cutoff, batchSize);
					if (count > 0) invalidateStreamNetworkPolicy(stream.id);
					return count;
				},
			},
		);
	}
	if (tasks.length > 1) {
		const offset = cleanupRotation % tasks.length;
		cleanupRotation = (cleanupRotation + Math.max(1, Math.ceil(tasks.length / 3))) % tasks.length;
		return [...tasks.slice(offset), ...tasks.slice(0, offset)];
	}
	return tasks;
}

export async function runRetentionCleanup(): Promise<void> {
	if (cleanupRunning) return;
	cleanupRunning = true;
	const now = Date.now();
	const startedAt = performance.now();
	let cleanupResult: CleanupRunResult = { deleted: 0, attemptedBatches: 0, errors: 0 };
	try {
		const tasks = await cleanupTasks(now, config.maintenance.cleanupBatchSize);
		cleanupResult = await runCleanupTasks(tasks, {
			batchSize: config.maintenance.cleanupBatchSize,
			pauseMs: config.maintenance.cleanupPauseMs,
			timeBudgetMs: config.maintenance.cleanupTimeBudgetMs,
		});
		if (cleanupResult.deleted > 0) Logger.info(`[BurrowGate] Incremental retention cleanup removed ${cleanupResult.deleted} row(s)`);
	} catch (error) {
		cleanupResult.errors += 1;
		Logger.error("[BurrowGate] Unable to prepare retention cleanup", { error });
	} finally {
		openMetrics.recordRetentionCleanup({ ...cleanupResult, durationMs: performance.now() - startedAt });
		cleanupRunning = false;
	}
}

async function runHousekeeping(): Promise<void> {
	if (housekeepingRunning) return;
	housekeepingRunning = true;
	try {
		await backfillGeoIp();
	} catch (error) {
		Logger.error("[BurrowGate] GeoIP backfill maintenance failed", { error });
	}
	try {
		await renewDueCertificates();
	} catch (error) {
		Logger.error("[BurrowGate] Certificate renewal maintenance failed", { error });
	} finally {
		housekeepingRunning = false;
	}
}

export async function runMaintenance(): Promise<void> {
	await runRetentionCleanup();
	await runHousekeeping();
}

export function startMaintenance(): void {
	const cleanupTimer = setInterval(() => void runRetentionCleanup(), config.maintenance.cleanupIntervalSeconds * 1_000);
	(cleanupTimer as unknown as { unref?: () => void }).unref?.();
	const housekeepingIntervalSeconds = Math.min(config.maintenance.intervalSeconds, config.acme.checkIntervalSeconds);
	const housekeepingTimer = setInterval(() => void runHousekeeping(), housekeepingIntervalSeconds * 1_000);
	(housekeepingTimer as unknown as { unref?: () => void }).unref?.();
}
