import { existsSync, statfsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { config } from "../config.ts";
import { repository } from "../db/repository.ts";
import { Logger } from "../logger.ts";
import type { NotificationSeverity, SystemMetricSample } from "../types.ts";
import { notificationService } from "./notification-service.ts";
import { openMetrics } from "./openmetrics-service.ts";

const CGROUP_V2_CPU_MAX = "/sys/fs/cgroup/cpu.max";
const CGROUP_V2_CPU_STAT = "/sys/fs/cgroup/cpu.stat";
const CGROUP_V2_MEMORY_CURRENT = "/sys/fs/cgroup/memory.current";
const CGROUP_V2_MEMORY_MAX = "/sys/fs/cgroup/memory.max";
const CGROUP_V1_CPU_QUOTA = "/sys/fs/cgroup/cpu/cpu.cfs_quota_us";
const CGROUP_V1_CPU_PERIOD = "/sys/fs/cgroup/cpu/cpu.cfs_period_us";
const CGROUP_V1_CPUACCT_USAGE = "/sys/fs/cgroup/cpuacct/cpuacct.usage";
const CGROUP_V1_MEMORY_USAGE = "/sys/fs/cgroup/memory/memory.usage_in_bytes";
const CGROUP_V1_MEMORY_LIMIT = "/sys/fs/cgroup/memory/memory.limit_in_bytes";
const PROC_STAT = "/proc/stat";
const PROC_MEMINFO = "/proc/meminfo";
const PROC_NET_DEV = "/proc/net/dev";

// cgroup v1's "no limit" sentinel is a huge number close to the platform's word size (e.g. 9223372036854771712).
// Anything within an order of magnitude of Number.MAX_SAFE_INTEGER is effectively unlimited, not a real cap.
const CGROUP_V1_UNLIMITED_FLOOR = 1e18;

type CpuSource = { kind: "cgroup2" | "cgroup1"; cores: number } | { kind: "host" };
type MemorySource = "cgroup2" | "cgroup1" | "host";
type ResourceKey = "cpu" | "memory" | "disk" | "network";

interface UsageSample {
	used: number;
	total: number;
}

interface ResourceAlertState {
	state: "normal" | "high";
	consecutiveOver: number;
	consecutiveUnder: number;
}

const RESOURCE_LABELS: Record<ResourceKey, string> = {
	cpu: "CPU",
	memory: "Memory",
	disk: "Disk",
	network: "Network throughput",
};

function formatPercent(value: number): string {
	return `${value.toFixed(1)}%`;
}

function formatMbps(value: number): string {
	return `${value.toFixed(1)} Mbps`;
}

async function detectCpuSource(): Promise<CpuSource> {
	if (existsSync(CGROUP_V2_CPU_MAX)) {
		try {
			const [quotaRaw, periodRaw] = (await readFile(CGROUP_V2_CPU_MAX, "utf8")).trim().split(/\s+/);
			if (quotaRaw !== "max") {
				const quota = Number(quotaRaw);
				const period = Number(periodRaw);
				if (Number.isFinite(quota) && quota > 0 && Number.isFinite(period) && period > 0) return { kind: "cgroup2", cores: quota / period };
			}
		} catch {
			// fall through to the next detection strategy
		}
	}
	if (existsSync(CGROUP_V1_CPU_QUOTA) && existsSync(CGROUP_V1_CPU_PERIOD) && existsSync(CGROUP_V1_CPUACCT_USAGE)) {
		try {
			const quota = Number((await readFile(CGROUP_V1_CPU_QUOTA, "utf8")).trim());
			const period = Number((await readFile(CGROUP_V1_CPU_PERIOD, "utf8")).trim());
			if (Number.isFinite(quota) && quota > 0 && Number.isFinite(period) && period > 0) return { kind: "cgroup1", cores: quota / period };
		} catch {
			// fall through to the host-wide fallback
		}
	}
	return { kind: "host" };
}

async function detectMemorySource(): Promise<MemorySource> {
	if (existsSync(CGROUP_V2_MEMORY_MAX)) {
		try {
			const raw = (await readFile(CGROUP_V2_MEMORY_MAX, "utf8")).trim();
			if (raw !== "max" && Number(raw) > 0) return "cgroup2";
		} catch {
			// fall through
		}
	}
	if (existsSync(CGROUP_V1_MEMORY_LIMIT)) {
		try {
			const limit = Number((await readFile(CGROUP_V1_MEMORY_LIMIT, "utf8")).trim());
			if (Number.isFinite(limit) && limit > 0 && limit < CGROUP_V1_UNLIMITED_FLOOR) return "cgroup1";
		} catch {
			// fall through
		}
	}
	return "host";
}

async function readCgroupUsage(path: string): Promise<number | null> {
	try {
		const value = Number((await readFile(path, "utf8")).trim());
		return Number.isFinite(value) ? value : null;
	} catch {
		return null;
	}
}

async function readCgroup2UsageUsec(): Promise<number | null> {
	try {
		const text = await readFile(CGROUP_V2_CPU_STAT, "utf8");
		const match = text.match(/^usage_usec (\d+)/m);
		return match ? Number(match[1]) : null;
	} catch {
		return null;
	}
}

async function readHostCpuTicks(): Promise<{ total: number; idle: number } | null> {
	try {
		const text = await readFile(PROC_STAT, "utf8");
		const line = text.split("\n").find((entry) => entry.startsWith("cpu "));
		if (!line) return null;
		const fields = line.trim().split(/\s+/).slice(1).map(Number);
		if (fields.length < 4 || fields.some((value) => !Number.isFinite(value))) return null;
		const [user = 0, nice = 0, system = 0, idle = 0, iowait = 0, irq = 0, softirq = 0, steal = 0] = fields;
		return { total: user + nice + system + idle + iowait + irq + softirq + steal, idle: idle + iowait };
	} catch {
		return null;
	}
}

/** Samples CPU utilization as a percentage, adapting to whichever counters are available (cgroup v2, v1, or host-wide `/proc/stat`). */
class CpuSampler {
	private source: CpuSource | null = null;
	private previousUsage: number | null = null;
	private previousAtMs: number | null = null;
	private previousTotalTicks: number | null = null;
	private previousIdleTicks: number | null = null;

	async sample(): Promise<number | null> {
		if (!this.source) this.source = await detectCpuSource();
		if (this.source.kind === "host") return this.sampleHost();
		const usage = await (this.source.kind === "cgroup2" ? readCgroup2UsageUsec() : readCgroupUsage(CGROUP_V1_CPUACCT_USAGE));
		const unitsPerSecond = this.source.kind === "cgroup2" ? 1_000_000 : 1_000_000_000;
		return this.sampleCgroup(usage, unitsPerSecond, this.source.cores);
	}

	private sampleCgroup(usage: number | null, unitsPerSecond: number, cores: number): number | null {
		const nowMs = performance.now();
		if (usage === null) return null;
		const previousUsage = this.previousUsage;
		const previousAtMs = this.previousAtMs;
		this.previousUsage = usage;
		this.previousAtMs = nowMs;
		if (previousUsage === null || previousAtMs === null) return null;
		const deltaSeconds = (nowMs - previousAtMs) / 1_000;
		if (deltaSeconds <= 0) return null;
		const pct = ((usage - previousUsage) / unitsPerSecond / deltaSeconds / Math.max(cores, 0.01)) * 100;
		return Number.isFinite(pct) ? Math.max(0, Math.min(100, pct)) : null;
	}

	private async sampleHost(): Promise<number | null> {
		const ticks = await readHostCpuTicks();
		if (!ticks) return null;
		const previousTotal = this.previousTotalTicks;
		const previousIdle = this.previousIdleTicks;
		this.previousTotalTicks = ticks.total;
		this.previousIdleTicks = ticks.idle;
		if (previousTotal === null || previousIdle === null) return null;
		const deltaTotal = ticks.total - previousTotal;
		const deltaIdle = ticks.idle - previousIdle;
		if (deltaTotal <= 0) return null;
		const pct = (1 - deltaIdle / deltaTotal) * 100;
		return Number.isFinite(pct) ? Math.max(0, Math.min(100, pct)) : null;
	}
}

async function readMemorySample(source: MemorySource): Promise<UsageSample | null> {
	if (source === "cgroup2") {
		const [current, max] = await Promise.all([readCgroupUsage(CGROUP_V2_MEMORY_CURRENT), readCgroupUsage(CGROUP_V2_MEMORY_MAX)]);
		return current === null || max === null ? null : { used: current, total: max };
	}
	if (source === "cgroup1") {
		const [usage, limit] = await Promise.all([readCgroupUsage(CGROUP_V1_MEMORY_USAGE), readCgroupUsage(CGROUP_V1_MEMORY_LIMIT)]);
		return usage === null || limit === null ? null : { used: usage, total: limit };
	}
	try {
		const text = await readFile(PROC_MEMINFO, "utf8");
		const totalKb = text.match(/^MemTotal:\s+(\d+)/m);
		const availableKb = text.match(/^MemAvailable:\s+(\d+)/m);
		if (!totalKb || !availableKb) return null;
		const totalBytes = Number(totalKb[1]) * 1_024;
		const availableBytes = Number(availableKb[1]) * 1_024;
		return { used: Math.max(0, totalBytes - availableBytes), total: totalBytes };
	} catch {
		return null;
	}
}

function readDiskSample(): UsageSample | null {
	try {
		const stats = statfsSync(config.dataDirectory);
		return { used: (stats.blocks - stats.bfree) * stats.bsize, total: stats.blocks * stats.bsize };
	} catch {
		return null;
	}
}

async function readNetworkCounters(): Promise<{ rxBytes: number; txBytes: number } | null> {
	try {
		const text = await readFile(PROC_NET_DEV, "utf8");
		let rxBytes = 0;
		let txBytes = 0;
		for (const line of text.split("\n").slice(2)) {
			const [ifacePart, rest] = line.split(":");
			if (!ifacePart || rest === undefined) continue;
			const iface = ifacePart.trim();
			if (!iface || iface === "lo") continue;
			const fields = rest.trim().split(/\s+/).map(Number);
			if (fields.length < 9) continue;
			rxBytes += fields[0] ?? 0;
			txBytes += fields[8] ?? 0;
		}
		return { rxBytes, txBytes };
	} catch {
		return null;
	}
}

function emptyAlertState(): ResourceAlertState {
	return { state: "normal", consecutiveOver: 0, consecutiveUnder: 0 };
}

class SystemMonitor {
	private readonly cpuSampler = new CpuSampler();
	private memorySource: MemorySource | null = null;
	private previousNetwork: { rxBytes: number; txBytes: number; atMs: number } | null = null;
	private readonly alertStates = new Map<ResourceKey, ResourceAlertState>([
		["cpu", emptyAlertState()],
		["memory", emptyAlertState()],
		["disk", emptyAlertState()],
		["network", emptyAlertState()],
	]);
	private timer: ReturnType<typeof setInterval> | null = null;

	start(): void {
		if (this.timer || !config.systemMonitor.enabled) return;
		this.timer = setInterval(() => void this.tick(), config.systemMonitor.intervalSeconds * 1_000);
		(this.timer as unknown as { unref?: () => void }).unref?.();
		void this.tick();
	}

	private async tick(): Promise<void> {
		try {
			if (!this.memorySource) this.memorySource = await detectMemorySource();
			const [cpuPct, memory, disk, network] = await Promise.all([
				this.cpuSampler.sample(),
				readMemorySample(this.memorySource),
				readDiskSample(),
				readNetworkCounters(),
			]);
			const nowMs = performance.now();
			let networkRxBps = 0;
			let networkTxBps = 0;
			if (network) {
				const previous = this.previousNetwork;
				this.previousNetwork = { ...network, atMs: nowMs };
				if (previous) {
					const deltaSeconds = (nowMs - previous.atMs) / 1_000;
					if (deltaSeconds > 0) {
						const deltaRx = network.rxBytes - previous.rxBytes;
						const deltaTx = network.txBytes - previous.txBytes;
						networkRxBps = deltaRx >= 0 ? deltaRx / deltaSeconds : 0;
						networkTxBps = deltaTx >= 0 ? deltaTx / deltaSeconds : 0;
					}
				}
			}
			// cpuPct is null until the sampler has two data points to diff; skip persisting this tick rather than
			// writing a half-populated row (memory/disk/network may be ready before the first CPU delta is available).
			if (cpuPct === null || !memory || !disk) return;
			const sample: SystemMetricSample = {
				cpuPct,
				memoryUsedBytes: memory.used,
				memoryTotalBytes: memory.total,
				diskUsedBytes: disk.used,
				diskTotalBytes: disk.total,
				networkRxBps,
				networkTxBps,
			};
			const bucketStart = Math.floor(Date.now() / 60_000) * 60_000;
			await repository.addSystemMetricSample(bucketStart, sample);
			openMetrics.setSystemMetrics(sample);
			await this.evaluateThresholds(sample);
		} catch (error) {
			Logger.error("[BurrowGate] Unable to sample system metrics", { error });
		}
	}

	private async evaluateThresholds(sample: SystemMetricSample): Promise<void> {
		const memoryPct = sample.memoryTotalBytes > 0 ? (sample.memoryUsedBytes / sample.memoryTotalBytes) * 100 : null;
		const diskPct = sample.diskTotalBytes > 0 ? (sample.diskUsedBytes / sample.diskTotalBytes) * 100 : null;
		const networkMbps = ((sample.networkRxBps + sample.networkTxBps) * 8) / 1_000_000;
		await this.evaluateResource("cpu", sample.cpuPct, config.systemMonitor.cpuThresholdPct, formatPercent);
		await this.evaluateResource("memory", memoryPct, config.systemMonitor.memoryThresholdPct, formatPercent);
		await this.evaluateResource("disk", diskPct, config.systemMonitor.diskThresholdPct, formatPercent);
		await this.evaluateResource("network", networkMbps, config.systemMonitor.networkThresholdMbps, formatMbps);
	}

	private async evaluateResource(key: ResourceKey, value: number | null, thresholdValue: number, formatValue: (value: number) => string): Promise<void> {
		// A threshold of 0 means "not configured" (this is the network default, since link capacity isn't auto-detectable).
		if (value === null || thresholdValue <= 0) return;
		const state = this.alertStates.get(key)!;
		const over = value >= thresholdValue;
		if (over) {
			state.consecutiveOver += 1;
			state.consecutiveUnder = 0;
		} else {
			state.consecutiveUnder += 1;
			state.consecutiveOver = 0;
		}
		if (state.state !== "high" && over && state.consecutiveOver >= config.systemMonitor.failureThreshold) {
			state.state = "high";
			await this.notify(key, "system_resource_high", "warning", value, thresholdValue, formatValue);
		} else if (state.state === "high" && !over && state.consecutiveUnder >= config.systemMonitor.recoveryThreshold) {
			state.state = "normal";
			await this.notify(key, "system_resource_normal", "info", value, thresholdValue, formatValue);
		}
	}

	private async notify(
		key: ResourceKey,
		type: "system_resource_high" | "system_resource_normal",
		severity: NotificationSeverity,
		value: number,
		thresholdValue: number,
		formatValue: (value: number) => string,
	): Promise<void> {
		const label = RESOURCE_LABELS[key];
		const summary =
			type === "system_resource_high"
				? `BurrowGate: ${label} usage is high (${formatValue(value)}, threshold ${formatValue(thresholdValue)}).`
				: `BurrowGate: ${label} usage has returned to normal (${formatValue(value)}).`;
		await notificationService.recordGlobalEvent(
			type,
			severity,
			summary,
			{ resource: label, value: formatValue(value), thresholdValue: formatValue(thresholdValue) },
			Date.now(),
		);
	}
}

export const systemMonitor = new SystemMonitor();
