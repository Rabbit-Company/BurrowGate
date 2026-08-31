import { Logger } from "../logger.ts";
import { flushBandwidthMetrics } from "./bandwidth-service.ts";
import { haElectionService } from "./ha-election-service.ts";
import { haMeshService } from "./ha-mesh-service.ts";
import { flushStreamMonitoring } from "./stream-monitoring-service.ts";
import { dailyFileLogs } from "./daily-file-log-service.ts";

let shuttingDown = false;

async function flushPendingMonitoringData(timeoutMs = 3_000): Promise<void> {
	await Promise.race([Promise.allSettled([flushStreamMonitoring(), flushBandwidthMetrics()]), new Promise((resolve) => setTimeout(resolve, timeoutMs))]);
}

export const processLifecycle = {
	async gracefulRestart(reason: string, exitCode = 0): Promise<never> {
		if (shuttingDown) {
			await new Promise(() => {});
		}
		shuttingDown = true;
		Logger.warn(`Shutting down (${reason}); flushing pending monitoring data before exit`);
		await flushPendingMonitoringData();
		await dailyFileLogs.flush();
		dailyFileLogs.stop();
		haElectionService.stop();
		await haMeshService.stop();
		process.exit(exitCode);
	},
};
