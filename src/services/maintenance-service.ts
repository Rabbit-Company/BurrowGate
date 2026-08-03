import { config } from "../config.ts";
import { repository } from "../db/repository.ts";
import { renewDueCertificates } from "./acme-service.ts";

const DAY_MS = 86_400_000;
let maintenanceRunning = false;

export async function runMaintenance(): Promise<void> {
	if (maintenanceRunning) return;
	maintenanceRunning = true;
	const now = Date.now();
	try {
		for (const site of await repository.allSites()) {
			const retentionDays = Number(site.event_retention_days ?? config.eventRetentionDays);
			await repository.deleteEventsBeforeForSite(site.id, now - retentionDays * DAY_MS);
		}
		await repository.deleteExpiredAcmeChallenges(now);
	} catch (error) {
		console.error("[BurrowGate] Retention cleanup failed", error);
	}
	try {
		await renewDueCertificates();
	} catch (error) {
		console.error("[BurrowGate] Certificate renewal maintenance failed", error);
	} finally {
		maintenanceRunning = false;
	}
}

export function startMaintenance(): void {
	const intervalSeconds = Math.min(config.maintenanceIntervalSeconds, config.acme.checkIntervalSeconds);
	const timer = setInterval(() => void runMaintenance(), intervalSeconds * 1_000);
	(timer as unknown as { unref?: () => void }).unref?.();
}
