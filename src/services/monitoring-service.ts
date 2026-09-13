import { repository, type RequestMetric, type RequestScope } from "../db/repository.ts";

export const MONITORING_VIEWS = [
	"overview",
	"traffic",
	"blocked",
	"bandwidth",
	"cache",
	"protection",
	"latency",
	"geography",
	"paths",
	"referrers",
	"cpu",
	"memory",
	"disk",
	"network",
] as const;
export type MonitoringView = (typeof MONITORING_VIEWS)[number];

export const MONITORING_METRICS = ["requests", "uniqueIps"] as const satisfies readonly RequestMetric[];
export type MonitoringMetric = (typeof MONITORING_METRICS)[number];

export const PATH_FILTERABLE_VIEWS: readonly MonitoringView[] = [
	"overview",
	"traffic",
	"blocked",
	"cache",
	"protection",
	"latency",
	"geography",
	"paths",
	"referrers",
];

const REFUSAL_VIEWS: readonly MonitoringView[] = ["blocked", "protection"];
const METRIC_VIEWS: readonly MonitoringView[] = ["overview", "traffic", "geography", "paths", "referrers"];
const TOP_ROWS = 100;

type Point = { bucket: number; value: number | null };
type Stat = { label: string; value: number | null; unit: string };

export async function monitoringData(
	view: MonitoringView,
	hours: number,
	siteId?: string,
	now = Date.now(),
	requestScope?: RequestScope,
	metric: MonitoringMetric = "requests",
) {
	const since = now - hours * 3_600_000;
	// Bound payloads and database grouping to roughly 48 intervals per screen.
	const bucketMs = Math.max(60_000, Math.ceil((hours * 3_600_000) / 48 / 60_000) * 60_000);
	const systemView = ["cpu", "memory", "disk", "network"].includes(view);
	if (systemView && siteId) throw new Error("System views apply to the whole instance (leave Site ID empty)");
	if (requestScope !== undefined && !PATH_FILTERABLE_VIEWS.includes(view))
		throw new Error(`The ${view} view is not backed by request paths, so pathPrefix cannot be applied`);
	if (requestScope?.prefix !== undefined && requestScope.exact !== undefined)
		throw new Error("pathPrefix and path are mutually exclusive: pass a subtree or a single page, not both");
	if (requestScope?.successfulOnly === true && REFUSAL_VIEWS.includes(view))
		throw new Error(`The ${view} view counts refused requests, so successfulOnly cannot be applied`);
	if (metric === "uniqueIps" && !METRIC_VIEWS.includes(view)) throw new Error(`The ${view} view does not support metric=uniqueIps`);
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
		const metrics = await repository.cacheMetrics(siteId, since, now, bucketMs, requestScope);
		title = "Cache hit ratio";
		unit = "%";
		points = metrics.series.map((p) => ({ bucket: p.bucket, value: p.hits + p.misses > 0 ? p.hitRatio : null }));
		stats = [
			stat("Hit ratio", metrics.totals.hits + metrics.totals.misses > 0 ? metrics.totals.hitRatio * 100 : null),
			stat("Hits", metrics.totals.hits, "requests"),
			stat("Misses", metrics.totals.misses, "requests"),
		];
	} else if (view === "protection") {
		const metrics = await repository.protectionMetrics(siteId, since, now, bucketMs, requestScope);
		title = "Managed protection blocks";
		points = metrics.series.map((p) => ({ bucket: p.bucket, value: p.blocked }));
		stats = [stat("Blocked", metrics.totals.blocked), stat("Inspected", metrics.totals.inspected), stat("Would block", metrics.totals.monitored)];
	} else if (view === "paths") {
		const unique = metric === "uniqueIps";
		title = unique ? "Top paths by unique IPs" : "Top paths";
		unit = unique ? "unique IPs" : "requests";
		const paths = await repository.tabPathMetrics(siteId, since, now, "requests", requestScope, TOP_ROWS, metric);
		rows = paths.map((entry) => ({ label: entry.path, value: entry.count }));
		stats = unique
			? [stat("Pages shown", paths.length, "")]
			: [stat("Requests in top paths", sum(paths.map((entry) => entry.count))), stat("Paths shown", paths.length, "")];
	} else if (view === "referrers") {
		const unique = metric === "uniqueIps";
		title = unique ? "Top referrers by unique IPs" : "Top referrers";
		unit = unique ? "unique IPs" : "requests";
		const referrers = await repository.tabRefererMetrics(siteId, since, now, "requests", requestScope, TOP_ROWS, metric);
		rows = referrers.map((entry) => ({ label: entry.refererHost, value: entry.count }));
		stats = unique
			? [stat("Sources shown", referrers.length, "")]
			: [stat("Requests from top sources", sum(referrers.map((entry) => entry.count))), stat("Sources shown", referrers.length, "")];
	} else if (view === "geography") {
		const unique = metric === "uniqueIps";
		title = unique ? "Top countries by unique IPs" : "Top countries";
		unit = unique ? "unique IPs" : "requests";
		const countries = await repository.tabGeoMetrics(siteId, since, now, "requests", requestScope, metric);
		rows = countries.map((c) => ({ label: c.countryCode, value: c.count }));
		stats = unique
			? [stat("Countries", countries.filter((c) => c.countryCode !== "ZZ").length, "")]
			: [stat("Requests", sum(countries.map((c) => c.count))), stat("Countries", countries.filter((c) => c.countryCode !== "ZZ").length, "")];
	} else {
		const metrics = await repository.trafficMetrics(siteId, since, now, bucketMs, requestScope);
		const unique = metric === "uniqueIps";
		const requests = sum(metrics.series.map((p) => p.requests));
		const blocked = sum(metrics.series.map((p) => p.blocked));
		const errors = sum(metrics.series.map((p) => p.errors));
		title = unique
			? "Unique IPs over time"
			: view === "overview"
				? "Traffic overview"
				: view === "blocked"
					? "Blocked requests"
					: view === "latency"
						? "Request latency"
						: "Request traffic";
		unit = unique ? "unique IPs" : view === "latency" ? "ms" : "requests";
		points = metrics.series.map((p) => ({
			bucket: p.bucket,
			value: unique ? p.uniqueIps : view === "latency" ? (p.requests ? p.averageLatency : null) : view === "blocked" ? p.blocked : p.requests,
		}));
		stats = unique
			? [stat("Unique IPs", metrics.uniqueIps, ""), stat("Requests", requests, "requests")]
			: view === "latency"
				? [stat("Average latency", requests ? sum(metrics.series.map((p) => p.averageLatency * p.requests)) / requests : null)]
				: [stat("Requests", requests), stat("Unique IPs", metrics.uniqueIps, ""), stat("Blocked", blocked), stat("Server errors", errors)];
	}
	const available = points.map((p) => p.value).filter((value): value is number => value !== null && Number.isFinite(value));
	const maximum = Math.max(0, ...available);
	return {
		schemaVersion: 1,
		view,
		metric,
		title,
		unit,
		pathPrefix: requestScope?.prefix ?? null,
		path: requestScope?.exact ?? null,
		successfulOnly: requestScope?.successfulOnly === true,
		scope: systemView ? "System" : (site?.name ?? "All sites"),
		hours,
		generatedAt: new Date(now).toISOString(),
		from: new Date(since).toISOString(),
		to: new Date(now).toISOString(),
		bucketSeconds: bucketMs / 1000,
		hasData: rows.length > 0 ? true : available.length > 0,
		maximum,
		stats,
		rows,
		points: points.map((p) => ({ timestamp: p.bucket, value: p.value, height: p.value === null || maximum === 0 ? 0 : Math.round((p.value / maximum) * 100) })),
	};
}
