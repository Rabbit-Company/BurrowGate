import { repository } from "../db/repository.ts";

export const MONITORING_VIEWS = [
	"overview",
	"traffic",
	"blocked",
	"bandwidth",
	"cache",
	"protection",
	"latency",
	"geography",
	"cpu",
	"memory",
	"disk",
	"network",
] as const;
export type MonitoringView = (typeof MONITORING_VIEWS)[number];
type Point = { bucket: number; value: number | null };
type Stat = { label: string; value: number | null; unit: string };

export async function monitoringData(view: MonitoringView, hours: number, siteId?: string, now = Date.now()) {
	const since = now - hours * 3_600_000;
	// Bound payloads and database grouping to roughly 48 intervals per screen.
	const bucketMs = Math.max(60_000, Math.ceil((hours * 3_600_000) / 48 / 60_000) * 60_000);
	const systemView = ["cpu", "memory", "disk", "network"].includes(view);
	if (systemView && siteId) throw new Error("System views apply to the whole instance (leave Site ID empty)");
	const site = siteId ? await repository.siteById(siteId) : null;
	if (siteId && !site) throw new Error("Unknown site ID");
	let title = "Requests";
	let unit = "requests";
	let points: Point[] = [];
	let stats: Stat[] = [];
	let rows: Array<{ label: string; value: number }> = [];
	const stat = (label: string, value: number | null, suffix = unit): Stat => ({ label, value, unit: suffix });
	const sum = (values: number[]) => values.reduce((total, value) => total + value, 0);
	if (systemView) {
		const metrics = await repository.systemMetrics(since, now, bucketMs);
		const definition = {
			cpu: { title: "CPU usage", unit: "%", key: "cpuAvgPct", factor: 1 },
			memory: { title: "Memory usage", unit: "GiB", key: "memoryAvgBytes", factor: 1 / 1_073_741_824 },
			disk: { title: "Storage usage", unit: "GiB", key: "diskAvgBytes", factor: 1 / 1_073_741_824 },
			network: { title: "Network download", unit: "Mbps", key: "networkRxAvgBps", factor: 8 / 1_000_000 },
		}[view as "cpu" | "memory" | "disk" | "network"];
		title = definition.title;
		unit = definition.unit;
		const key = definition.key as "cpuAvgPct" | "memoryAvgBytes" | "diskAvgBytes" | "networkRxAvgBps";
		points = metrics.series.map((p) => ({ bucket: p.bucket, value: p[key] === null ? null : p[key]! * definition.factor }));
		const average = metrics.summary[key];
		stats = [stat("Average", average === null ? null : average * definition.factor)];
		if (view === "network")
			stats.push(stat("Average upload", metrics.summary.networkTxAvgBps === null ? null : (metrics.summary.networkTxAvgBps * 8) / 1_000_000));
		if (view === "memory")
			stats.push(stat("Total memory", metrics.summary.memoryTotalBytes === null ? null : metrics.summary.memoryTotalBytes / 1_073_741_824));
		if (view === "disk") stats.push(stat("Total storage", metrics.summary.diskTotalBytes === null ? null : metrics.summary.diskTotalBytes / 1_073_741_824));
	} else if (view === "bandwidth") {
		const metrics = await repository.bandwidthMetrics(siteId, since, now, bucketMs);
		title = "Client bandwidth";
		unit = "MiB";
		points = metrics.series.map((p) => ({ bucket: p.bucket, value: (p.clientDownload + p.clientUpload) / 1_048_576 }));
		stats = [
			stat("Download", sum(metrics.series.map((p) => p.clientDownload)) / 1_048_576),
			stat("Upload", sum(metrics.series.map((p) => p.clientUpload)) / 1_048_576),
		];
	} else if (view === "cache") {
		const metrics = await repository.cacheMetrics(siteId, since, now, bucketMs);
		title = "Cache hit ratio";
		unit = "%";
		points = metrics.series.map((p) => ({ bucket: p.bucket, value: p.hits + p.misses > 0 ? p.hitRatio : null }));
		stats = [
			stat("Hit ratio", metrics.totals.hits + metrics.totals.misses > 0 ? metrics.totals.hitRatio * 100 : null),
			stat("Hits", metrics.totals.hits, "requests"),
			stat("Misses", metrics.totals.misses, "requests"),
		];
	} else if (view === "protection") {
		const metrics = await repository.protectionMetrics(siteId, since, now, bucketMs);
		title = "Managed protection blocks";
		points = metrics.series.map((p) => ({ bucket: p.bucket, value: p.blocked }));
		stats = [stat("Blocked", metrics.totals.blocked), stat("Inspected", metrics.totals.inspected), stat("Would block", metrics.totals.monitored)];
	} else if (view === "geography") {
		title = "Top countries";
		const countries = await repository.tabGeoMetrics(siteId, since, now, "requests");
		rows = countries.slice(0, 6).map((c) => ({ label: c.countryCode === "ZZ" ? "Unknown" : c.countryCode, value: c.count }));
		stats = [stat("Requests", sum(countries.map((c) => c.count))), stat("Countries", countries.filter((c) => c.countryCode !== "ZZ").length, "")];
	} else {
		const metrics = await repository.trafficMetrics(siteId, since, now, bucketMs);
		const requests = sum(metrics.series.map((p) => p.requests));
		const blocked = sum(metrics.series.map((p) => p.blocked));
		const errors = sum(metrics.series.map((p) => p.errors));
		title = view === "overview" ? "Traffic overview" : view === "blocked" ? "Blocked requests" : view === "latency" ? "Request latency" : "Request traffic";
		unit = view === "latency" ? "ms" : "requests";
		points = metrics.series.map((p) => ({
			bucket: p.bucket,
			value: view === "latency" ? (p.requests ? p.averageLatency : null) : view === "blocked" ? p.blocked : p.requests,
		}));
		stats =
			view === "latency"
				? [stat("Average latency", requests ? sum(metrics.series.map((p) => p.averageLatency * p.requests)) / requests : null)]
				: [stat("Requests", requests), stat("Blocked", blocked), stat("Server errors", errors)];
	}
	const available = points.map((p) => p.value).filter((value): value is number => value !== null && Number.isFinite(value));
	const maximum = Math.max(0, ...available);
	return {
		schemaVersion: 1,
		view,
		title,
		unit,
		scope: systemView ? "System" : (site?.name ?? "All sites"),
		hours,
		generatedAt: new Date(now).toISOString(),
		from: new Date(since).toISOString(),
		to: new Date(now).toISOString(),
		bucketSeconds: bucketMs / 1000,
		// Preserve null samples: missing system/latency data must never appear as zero.
		hasData: view === "geography" ? rows.length > 0 : available.length > 0,
		maximum,
		stats,
		rows,
		points: points.map((p) => ({ timestamp: p.bucket, value: p.value, height: p.value === null || maximum === 0 ? 0 : Math.round((p.value / maximum) * 100) })),
	};
}
