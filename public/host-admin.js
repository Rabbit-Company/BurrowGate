const ADMIN_API = "/_burrowgate/api/admin";
const mutationHeaders = { "x-burrowgate-admin": "1" };
const DATE_TIME_FORMAT_STORAGE_KEY = "burrowgate.admin.date-time-format";
const DATE_TIME_FORMATS = new Set(["iso-24", "dmy-24", "mdy-12", "browser"]);

const SECTIONS = ["connectivity", "system-cpu", "system-memory", "system-disk", "system-network-download", "system-network-upload"];

const byId = (id) => document.getElementById(id);
const escapeHtml = (value) =>
	String(value ?? "").replace(
		/[&<>"']/g,
		(character) =>
			({
				"&": "&amp;",
				"<": "&lt;",
				">": "&gt;",
				'"': "&quot;",
				"'": "&#39;",
			})[character],
	);

function twoDigits(value) {
	return String(value).padStart(2, "0");
}

function formatNumber(value) {
	return Number(value ?? 0).toLocaleString();
}

function formatBytes(value) {
	const bytes = Math.max(0, Number(value ?? 0));
	if (!Number.isFinite(bytes) || bytes === 0) return "0 B";
	const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
	const index = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
	const scaled = bytes / 1024 ** index;
	return `${scaled >= 100 || index === 0 ? Math.round(scaled).toLocaleString() : scaled.toFixed(scaled >= 10 ? 1 : 2)} ${units[index]}`;
}

function formatBitrate(value) {
	const bits = Math.max(0, Number(value ?? 0));
	if (!Number.isFinite(bits) || bits === 0) return "0 bps";
	const units = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"];
	const index = Math.min(units.length - 1, Math.floor(Math.log(bits) / Math.log(1000)));
	const scaled = bits / 1000 ** index;
	return `${scaled >= 100 || index === 0 ? Math.round(scaled).toLocaleString() : scaled.toFixed(scaled >= 10 ? 1 : 2)} ${units[index]}`;
}

function formatDuration(milliseconds) {
	const value = Number(milliseconds ?? 0);
	if (value < 1_000) return `${Math.round(value)} ms`;
	if (value < 60_000) return `${(value / 1_000).toFixed(1)} s`;
	return `${(value / 60_000).toFixed(1)} min`;
}

let dateTimeFormat = "iso-24";

function readDateTimeFormat() {
	try {
		const stored = localStorage.getItem(DATE_TIME_FORMAT_STORAGE_KEY);
		return DATE_TIME_FORMATS.has(stored) ? stored : "iso-24";
	} catch {
		return "iso-24";
	}
}

function initializeDateTimeFormat() {
	dateTimeFormat = readDateTimeFormat();
	byId("dateTimeFormat").value = dateTimeFormat;
}

function saveDateTimeFormat(value) {
	dateTimeFormat = DATE_TIME_FORMATS.has(value) ? value : "iso-24";
	try {
		localStorage.setItem(DATE_TIME_FORMAT_STORAGE_KEY, dateTimeFormat);
	} catch {
		// The preference still applies for this page when browser storage is unavailable.
	}
}

function formatDate(value) {
	if (value === null || value === undefined) return "Never";
	const date = value instanceof Date ? value : new Date(Number(value));
	if (Number.isNaN(date.getTime())) return "-";
	if (dateTimeFormat === "browser") return date.toLocaleString();
	const year = date.getFullYear();
	const month = twoDigits(date.getMonth() + 1);
	const day = twoDigits(date.getDate());
	const minutes = twoDigits(date.getMinutes());
	const seconds = twoDigits(date.getSeconds());
	if (dateTimeFormat === "mdy-12") {
		const suffix = date.getHours() >= 12 ? "PM" : "AM";
		const hours = twoDigits(date.getHours() % 12 || 12);
		return `${month}/${day}/${year} ${hours}:${minutes}:${seconds} ${suffix}`;
	}
	const time = `${twoDigits(date.getHours())}:${minutes}:${seconds}`;
	return dateTimeFormat === "dmy-24" ? `${day}/${month}/${year} ${time}` : `${year}-${month}-${day} ${time}`;
}

function formatTime(value = Date.now()) {
	const date = value instanceof Date ? value : new Date(Number(value));
	if (Number.isNaN(date.getTime())) return "-";
	if (dateTimeFormat === "browser") return date.toLocaleTimeString();
	const minutes = twoDigits(date.getMinutes());
	const seconds = twoDigits(date.getSeconds());
	if (dateTimeFormat === "mdy-12") {
		return `${twoDigits(date.getHours() % 12 || 12)}:${minutes}:${seconds} ${date.getHours() >= 12 ? "PM" : "AM"}`;
	}
	return `${twoDigits(date.getHours())}:${minutes}:${seconds}`;
}

function showToast(message, kind = "ok") {
	const toast = byId("toast");
	toast.textContent = message;
	toast.className = `toast ${kind}`;
	clearTimeout(showToast.timer);
	showToast.timer = setTimeout(() => toast.classList.add("hidden"), 3_500);
}

function markUpdated(prefix = "Updated") {
	byId("lastUpdated").textContent = `${prefix} ${formatTime()}`;
}

let selectedRangeFrom = 0;
let selectedRangeTo = 0;
let dateRangeIsAutomatic = true;

function toDateTimeLocal(value) {
	const date = new Date(Number(value));
	const pad = (part) => String(part).padStart(2, "0");
	return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function setDateRangeInputs(from, to) {
	selectedRangeFrom = Number(from);
	selectedRangeTo = Number(to);
	byId("dateFrom").value = toDateTimeLocal(selectedRangeFrom);
	byId("dateTo").value = toDateTimeLocal(selectedRangeTo);
	const maximum = toDateTimeLocal(Date.now() + 300_000);
	byId("dateFrom").max = maximum;
	byId("dateTo").max = maximum;
}

function persistDateRange() {
	const url = new URL(location.href);
	url.searchParams.set("from", String(selectedRangeFrom));
	url.searchParams.set("to", String(selectedRangeTo));
	history.replaceState(null, "", `${url.pathname}${url.search}${url.hash}`);
}

function initializeDateRange() {
	const url = new URL(location.href);
	const now = Date.now();
	const requestedTo = Number(url.searchParams.get("to"));
	const requestedFrom = Number(url.searchParams.get("from"));
	const explicitRange = Number.isFinite(requestedTo) && requestedTo > 0 && Number.isFinite(requestedFrom) && requestedFrom >= 0 && requestedFrom < requestedTo;
	dateRangeIsAutomatic = !explicitRange;
	const to = explicitRange ? requestedTo : now;
	const from = explicitRange ? requestedFrom : to - 24 * 3_600_000;
	setDateRangeInputs(from, to);
	if (explicitRange) persistDateRange();
	else {
		url.searchParams.delete("from");
		url.searchParams.delete("to");
		history.replaceState(null, "", `${url.pathname}${url.search}${url.hash}`);
	}
}

function readDateRangeInputs() {
	const from = new Date(byId("dateFrom").value).getTime();
	const to = new Date(byId("dateTo").value).getTime();
	if (!Number.isFinite(from) || !Number.isFinite(to)) throw new Error("Select both From and To date/time values.");
	if (to - from < 60_000) throw new Error("The selected range must be at least one minute.");
	if (to - from > 366 * 24 * 3_600_000) throw new Error("The selected range cannot exceed 366 days.");
	return { from, to };
}

function rangeQuery() {
	return { from: selectedRangeFrom, to: selectedRangeTo };
}

function queryString(parameters) {
	const search = new URLSearchParams();
	for (const [key, value] of Object.entries(parameters)) {
		if (value !== "" && value !== undefined && value !== null) search.set(key, String(value));
	}
	return search.toString();
}

async function api(path, options = {}) {
	const response = await fetch(`${ADMIN_API}${path}`, { ...options, headers: { ...mutationHeaders, ...(options.headers ?? {}) } });
	if (response.status === 401) {
		location.href = "/_burrowgate/admin/login";
		throw new Error("Unauthorized");
	}
	const data = await response.json();
	if (!response.ok) throw new Error(data.error ?? "Request failed");
	return data;
}

async function runWithButton(button, task) {
	button.disabled = true;
	try {
		await task();
	} finally {
		button.disabled = false;
	}
}

function chartTheme() {
	const styles = getComputedStyle(document.documentElement);
	const value = (name, fallback) => styles.getPropertyValue(name).trim() || fallback;
	return {
		grid: value("--chart-grid", "#273244"),
		text: value("--chart-text", "#94a3b8"),
		palette: [
			value("--chart-requests", "#8b5cf6"),
			value("--chart-latency", "#22d3ee"),
			value("--chart-blocked", "#f97316"),
			value("--chart-series-5", "#22c55e"),
			value("--chart-series-6", "#eab308"),
			value("--chart-series-7", "#ec4899"),
			value("--chart-errors", "#f43f5e"),
			value("--chart-series-8", "#64748b"),
		],
	};
}

function metricLabel(bucket, rangeDurationMs, detailed = false) {
	const date = new Date(Number(bucket));
	if (detailed) return formatDate(date);
	if (Number(rangeDurationMs) >= 24 * 3_600_000) {
		return date.toLocaleString([], {
			month: "short",
			day: "numeric",
			hour: "2-digit",
			minute: "2-digit",
			hour12: dateTimeFormat === "browser" ? undefined : dateTimeFormat === "mdy-12",
		});
	}
	return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: dateTimeFormat === "browser" ? undefined : dateTimeFormat === "mdy-12" });
}

function metricValueFormatter(format) {
	if (format === "duration") return (value) => formatDuration(Number(value));
	if (format === "bytes") return (value) => formatBytes(Number(value));
	if (format === "bitrate") return (value) => formatBitrate(Number(value));
	if (format === "percentage") return (value) => `${Number(value).toFixed(1)}%`;
	return (value) => formatNumber(Math.round(Number(value)));
}

function chartColor(key, index, theme) {
	const semantic = { min: 3, avg: 0, max: 6, timeoutPct: 6 };
	return theme.palette[semantic[key] ?? index % theme.palette.length];
}

function lineDataset(definition, index, points, theme) {
	const color = chartColor(definition.key, index, theme);
	return {
		label: definition.label,
		data: points.map((point) => Number(point[definition.key] ?? 0)),
		borderColor: color,
		backgroundColor: color,
		pointBackgroundColor: color,
		pointBorderColor: color,
		borderWidth: 2,
		pointRadius: 0,
		pointHoverRadius: 4,
		pointHitRadius: 16,
		tension: 0.25,
		fill: false,
	};
}

function chartOptions(definition, formatter) {
	const theme = chartTheme();
	const showLegend = definition.datasets.length > 1;
	return {
		responsive: true,
		maintainAspectRatio: false,
		resizeDelay: 150,
		animation: false,
		normalized: true,
		interaction: { mode: "index", intersect: false },
		plugins: {
			legend: {
				display: showLegend,
				position: "bottom",
				labels: { color: theme.text, usePointStyle: true, pointStyle: "line", boxWidth: 18, boxHeight: 3, padding: 18 },
			},
			tooltip: {
				enabled: true,
				mode: "index",
				intersect: false,
				callbacks: {
					title(items) {
						const item = items[0];
						const point = definition.data[item.dataIndex];
						return point?.bucket !== undefined
							? metricLabel(point.bucket, Number(activeMetrics?.rangeDurationMs ?? selectedRangeTo - selectedRangeFrom), true)
							: "";
					},
					label(context) {
						return `${context.dataset.label}: ${formatter(context.parsed.y)}`;
					},
				},
			},
		},
		scales: {
			x: {
				grid: { display: false },
				border: { color: theme.grid },
				ticks: {
					color: theme.text,
					autoSkip: true,
					maxRotation: 0,
					minRotation: 0,
					maxTicksLimit: Number(activeMetrics?.rangeDurationMs ?? selectedRangeTo - selectedRangeFrom) <= 3_600_000 ? 6 : 8,
				},
			},
			y: {
				beginAtZero: true,
				grid: { color: theme.grid },
				border: { display: false },
				ticks: {
					color: theme.text,
					precision: definition.valueFormat === "number" ? 0 : undefined,
					callback(value) {
						return formatter(value);
					},
				},
			},
		},
	};
}

function normalizeChartDefinition(definition) {
	const normalized = { ...definition, datasets: [...(definition.datasets ?? [])], data: (definition.data ?? []).map((point) => ({ ...point })) };
	if (normalized.datasets.length === 0) normalized.datasets.push({ key: "value", label: "No data" });
	if (normalized.data.length === 0) {
		const bucketMs = Number(activeMetrics?.bucketMs ?? 60_000);
		const bucketCount = Math.max(1, Number(activeMetrics?.bucketCount ?? 1));
		const endBucket = Math.floor(selectedRangeTo / bucketMs) * bucketMs;
		normalized.data = Array.from({ length: bucketCount }, (_, index) => ({ bucket: endBucket - (bucketCount - index - 1) * bucketMs }));
	}
	for (const point of normalized.data) {
		for (const dataset of normalized.datasets) {
			if (!Number.isFinite(Number(point[dataset.key]))) point[dataset.key] = 0;
		}
	}
	return normalized;
}

const dateRangeSelectionPlugin = {
	id: "burrowgateHostDateRangeSelection",
	afterDatasetsDraw(chart) {
		const selection = chart.$dateRangeSelection;
		if (!selection?.dragging) return;
		const { ctx, chartArea } = chart;
		const left = Math.max(chartArea.left, Math.min(selection.startX, selection.currentX));
		const right = Math.min(chartArea.right, Math.max(selection.startX, selection.currentX));
		ctx.save();
		ctx.fillStyle = "rgba(139, 92, 246, 0.18)";
		ctx.strokeStyle = "rgba(167, 139, 250, 0.9)";
		ctx.lineWidth = 1;
		ctx.fillRect(left, chartArea.top, Math.max(0, right - left), chartArea.bottom - chartArea.top);
		ctx.strokeRect(left + 0.5, chartArea.top + 0.5, Math.max(0, right - left - 1), chartArea.bottom - chartArea.top - 1);
		ctx.restore();
	},
};

function attachDateRangeSelection(chart, definition) {
	const canvas = chart.canvas;
	canvas.$dateRangeCleanup?.();
	canvas.parentElement?.classList.toggle("time-selectable", true);
	if (definition.data.length < 2) return;

	const selection = { dragging: false, startX: 0, currentX: 0, pointerId: null };
	chart.$dateRangeSelection = selection;
	const canvasX = (event) => {
		const rect = canvas.getBoundingClientRect();
		return (event.clientX - rect.left) * (chart.width / rect.width);
	};
	const insidePlot = (x, y) => {
		const rect = canvas.getBoundingClientRect();
		const scaledY = (y - rect.top) * (chart.height / rect.height);
		return x >= chart.chartArea.left && x <= chart.chartArea.right && scaledY >= chart.chartArea.top && scaledY <= chart.chartArea.bottom;
	};
	const stop = () => {
		selection.dragging = false;
		selection.pointerId = null;
		chart.draw();
	};

	const pointerDown = (event) => {
		if (event.button !== 0) return;
		const x = canvasX(event);
		if (!insidePlot(x, event.clientY)) return;
		selection.dragging = true;
		selection.startX = x;
		selection.currentX = x;
		selection.pointerId = event.pointerId;
		canvas.setPointerCapture?.(event.pointerId);
		event.preventDefault();
		chart.draw();
	};
	const pointerMove = (event) => {
		if (!selection.dragging || selection.pointerId !== event.pointerId) return;
		selection.currentX = canvasX(event);
		event.preventDefault();
		chart.draw();
	};
	const pointerUp = (event) => {
		if (!selection.dragging || selection.pointerId !== event.pointerId) return;
		selection.currentX = canvasX(event);
		const distance = Math.abs(selection.currentX - selection.startX);
		if (distance < 8) {
			stop();
			return;
		}
		const scale = chart.scales.x;
		const left = Math.max(chart.chartArea.left, Math.min(selection.startX, selection.currentX));
		const right = Math.min(chart.chartArea.right, Math.max(selection.startX, selection.currentX));
		const startIndex = Math.max(0, Math.min(definition.data.length - 1, Math.floor(Number(scale.getValueForPixel(left)))));
		const endIndex = Math.max(startIndex, Math.min(definition.data.length - 1, Math.ceil(Number(scale.getValueForPixel(right)))));
		const bucketMs = Number(activeMetrics?.bucketMs ?? 60_000);
		const from = Math.max(selectedRangeFrom, Number(definition.data[startIndex]?.bucket ?? selectedRangeFrom));
		const to = Math.min(selectedRangeTo, Number(definition.data[endIndex]?.bucket ?? selectedRangeTo) + bucketMs);
		stop();
		if (to - from >= 60_000 && (from !== selectedRangeFrom || to !== selectedRangeTo)) {
			void applyDateRangeValues(from, to, "Graph selection applied").catch((error) => showToast(error.message, "bad"));
		}
	};
	const pointerCancel = () => stop();
	canvas.addEventListener("pointerdown", pointerDown);
	canvas.addEventListener("pointermove", pointerMove);
	canvas.addEventListener("pointerup", pointerUp);
	canvas.addEventListener("pointercancel", pointerCancel);
	canvas.$dateRangeCleanup = () => {
		canvas.removeEventListener("pointerdown", pointerDown);
		canvas.removeEventListener("pointermove", pointerMove);
		canvas.removeEventListener("pointerup", pointerUp);
		canvas.removeEventListener("pointercancel", pointerCancel);
	};
}

function createChart(canvasId, definition) {
	if (!window.Chart) throw new Error("Chart.js failed to load");
	const theme = chartTheme();
	const formatter = metricValueFormatter(definition.valueFormat);
	const labels = definition.data.map((point) => metricLabel(point.bucket, Number(activeMetrics?.rangeDurationMs ?? selectedRangeTo - selectedRangeFrom)));
	const datasets = definition.datasets.map((dataset, index) => lineDataset(dataset, index, definition.data, theme));
	const chart = new window.Chart(byId(canvasId), {
		type: "line",
		data: { labels, datasets },
		options: chartOptions(definition, formatter),
		plugins: [dateRangeSelectionPlugin],
	});
	attachDateRangeSelection(chart, definition);
	return chart;
}

function summarizeChartDefinition(definition) {
	if (!definition?.datasets?.length || !definition.data?.length) return [];
	const useAverage = definition.valueFormat === "duration";
	return definition.datasets.map((dataset) => {
		const values = definition.data.map((point) => Number(point[dataset.key] ?? 0));
		const total = values.reduce((sum, value) => sum + value, 0);
		return { label: dataset.label, count: useAverage ? total / values.length : total };
	});
}

function renderSummaryList(containerId, items, formatter = formatNumber) {
	const container = byId(containerId);
	if (!items || items.length === 0) {
		container.innerHTML = "";
		return;
	}
	const max = Math.max(0, ...items.map((item) => Number(item.count) || 0));
	if (max === 0) {
		container.innerHTML = '<p class="muted">No summary data is available.</p>';
		return;
	}
	container.innerHTML = items
		.slice(0, 6)
		.map((item) => {
			const percentage = Math.max(1, (Number(item.count) / max) * 100);
			return `<div class="breakdown-row"><div class="row between"><span>${escapeHtml(item.label)}</span><strong>${formatter(item.count)}</strong></div><div class="breakdown-track"><div style="width:${percentage}%"></div></div></div>`;
		})
		.join("");
}

const sectionCache = {};
let activeMetrics = null;
let hostChart = null;
let chartViewSelection = "connectivity:primary";
let chartViewRequestId = 0;
let liveStatsRequestId = 0;
let liveErrorShownAt = 0;

const LIVE_REFRESH_STORAGE_KEY = "burrowgate.admin.host-live-refresh-ms";
const LIVE_REFRESH_OPTIONS = new Set([1_000, 3_000, 5_000, 10_000, 30_000]);
const DEFAULT_LIVE_REFRESH_MS = 3_000;
let livePollMs = DEFAULT_LIVE_REFRESH_MS;
let livePollTimer = null;
let livePollGeneration = 0;

function readLiveRefreshInterval() {
	try {
		const stored = Number(localStorage.getItem(LIVE_REFRESH_STORAGE_KEY));
		return LIVE_REFRESH_OPTIONS.has(stored) ? stored : DEFAULT_LIVE_REFRESH_MS;
	} catch {
		return DEFAULT_LIVE_REFRESH_MS;
	}
}

function initializeLiveRefreshInterval() {
	livePollMs = readLiveRefreshInterval();
	byId("liveRefreshInterval").value = String(livePollMs);
}

function saveLiveRefreshInterval(value) {
	livePollMs = LIVE_REFRESH_OPTIONS.has(Number(value)) ? Number(value) : DEFAULT_LIVE_REFRESH_MS;
	try {
		localStorage.setItem(LIVE_REFRESH_STORAGE_KEY, String(livePollMs));
	} catch {
		// The preference still applies for this page when browser storage is unavailable.
	}
}

async function fetchSection(section) {
	return api(`/metrics?${queryString({ ...rangeQuery(), section })}`);
}

async function fetchLiveStatus() {
	return api("/host/current");
}

function breakdownValue(metrics, prefix) {
	const entry = metrics?.breakdown?.find((item) => item.label.startsWith(prefix));
	return entry ? Number(entry.count) : null;
}

function renderRangeAverages() {
	const cpuAvg = breakdownValue(sectionCache["system-cpu"], "Average");
	byId("hostCpuDetail").textContent = cpuAvg === null ? "No data in this range" : `Avg in range: ${cpuAvg.toFixed(1)}%`;

	const downloadAvgMbps = breakdownValue(sectionCache["system-network-download"], "Average");
	byId("hostDownloadDetail").textContent = downloadAvgMbps === null ? "No data in this range" : `Avg in range: ${formatBitrate(downloadAvgMbps * 1_000_000)}`;

	const uploadAvgMbps = breakdownValue(sectionCache["system-network-upload"], "Average");
	byId("hostUploadDetail").textContent = uploadAvgMbps === null ? "No data in this range" : `Avg in range: ${formatBitrate(uploadAvgMbps * 1_000_000)}`;
}

function renderStats(status) {
	const cpuPct = status?.cpu?.pct;
	byId("hostCpuValue").textContent = cpuPct === null || cpuPct === undefined ? "-" : `${Number(cpuPct).toFixed(1)}%`;
	byId("hostCpuMeter").style.width = `${Math.max(0, Math.min(100, Number(cpuPct ?? 0)))}%`;

	const memUsed = status?.memory?.usedBytes;
	const memTotal = status?.memory?.totalBytes;
	const memPct = memUsed !== null && memUsed !== undefined && memTotal ? (memUsed / memTotal) * 100 : null;
	byId("hostMemoryValue").textContent = memPct === null ? "-" : `${memPct.toFixed(1)}%`;
	byId("hostMemoryDetail").textContent = memPct === null ? "No live data yet" : `${formatBytes(memUsed)} / ${formatBytes(memTotal)}`;
	byId("hostMemoryMeter").style.width = `${Math.max(0, Math.min(100, memPct ?? 0))}%`;

	const diskUsed = status?.disk?.usedBytes;
	const diskTotal = status?.disk?.totalBytes;
	const diskPct = diskUsed !== null && diskUsed !== undefined && diskTotal ? (diskUsed / diskTotal) * 100 : null;
	byId("hostDiskValue").textContent = diskPct === null ? "-" : `${diskPct.toFixed(1)}%`;
	byId("hostDiskDetail").textContent = diskPct === null ? "No live data yet" : `${formatBytes(diskUsed)} / ${formatBytes(diskTotal)}`;
	byId("hostDiskMeter").style.width = `${Math.max(0, Math.min(100, diskPct ?? 0))}%`;

	const rxBps = status?.network?.rxBps;
	const txBps = status?.network?.txBps;
	byId("hostDownloadValue").textContent = rxBps === null || rxBps === undefined ? "-" : formatBitrate(rxBps * 8);
	byId("hostUploadValue").textContent = txBps === null || txBps === undefined ? "-" : formatBitrate(txBps * 8);

	const pings = status?.connectivity ?? [];
	const checked = pings.filter((ping) => ping.checkedAt !== null);
	const latencies = checked.filter((ping) => !ping.timedOut && ping.latencyMs !== null).map((ping) => Number(ping.latencyMs));
	const avgLatency = latencies.length ? latencies.reduce((sum, value) => sum + value, 0) / latencies.length : null;
	byId("hostLatencyValue").textContent = avgLatency === null ? "-" : formatDuration(avgLatency);
	const timedOutCount = checked.filter((ping) => ping.timedOut).length;
	byId("hostLatencyDetail").textContent = checked.length ? `${((timedOutCount / checked.length) * 100).toFixed(1)}% timed out` : "No live data yet";
}

async function refreshLiveStats() {
	const requestId = ++liveStatsRequestId;
	try {
		const status = await fetchLiveStatus();
		if (requestId !== liveStatsRequestId) return;
		renderStats(status);
	} catch (error) {
		if (requestId !== liveStatsRequestId) return;
		const now = Date.now();
		if (now - liveErrorShownAt > 10_000) {
			liveErrorShownAt = now;
			showToast(error.message, "bad");
		}
	}
}

function startLivePolling() {
	const generation = ++livePollGeneration;
	clearTimeout(livePollTimer);
	const tick = async () => {
		if (generation !== livePollGeneration) return;
		await refreshLiveStats();
		if (generation !== livePollGeneration) return;
		livePollTimer = setTimeout(() => void tick(), livePollMs);
	};
	livePollTimer = setTimeout(() => void tick(), livePollMs);
}

function stopLivePolling() {
	livePollGeneration++;
	clearTimeout(livePollTimer);
	livePollTimer = null;
}

function parseChartViewKey(key) {
	const [section, slot] = key.split(":");
	return { section, slot };
}

async function refreshChartView() {
	const requestId = ++chartViewRequestId;
	const { section, slot } = parseChartViewKey(chartViewSelection);
	const metrics = sectionCache[section];
	if (requestId !== chartViewRequestId || !metrics) return;
	activeMetrics = metrics;

	const definition = normalizeChartDefinition(metrics[slot] ?? metrics.primary);
	const select = byId("chartView");
	byId("primaryChartTitle").textContent = select.selectedOptions[0]?.textContent ?? definition.title;
	byId("primaryChartSubtitle").textContent = definition.subtitle;
	byId("hostChartEmpty").classList.add("hidden");
	byId("hostChart").classList.remove("hidden");

	hostChart?.destroy();
	hostChart = createChart("hostChart", definition);
	const showExplicitBreakdown = slot === "secondary" && metrics.breakdown?.length;
	const summaryItems = showExplicitBreakdown ? metrics.breakdown : summarizeChartDefinition(definition);
	renderSummaryList("hostChartSummary", summaryItems, showExplicitBreakdown ? formatNumber : metricValueFormatter(definition.valueFormat));
}

async function loadAll() {
	const results = await Promise.allSettled(SECTIONS.map((section) => fetchSection(section)));
	results.forEach((result, index) => {
		if (result.status === "fulfilled") sectionCache[SECTIONS[index]] = result.value;
	});
	const failed = results.find((result) => result.status === "rejected");
	if (failed) showToast(failed.reason?.message ?? "Failed to load some host metrics.", "bad");
	renderRangeAverages();
	await refreshChartView();
}

async function applyDateRangeValues(from, to, updateLabel = "Dashboard updated") {
	dateRangeIsAutomatic = false;
	setDateRangeInputs(from, to);
	persistDateRange();
	await loadAll();
	markUpdated(updateLabel);
}

function bindActions() {
	byId("chartView").addEventListener("change", (event) => {
		chartViewSelection = event.currentTarget.value;
		void refreshChartView();
	});
	byId("dateTimeFormat").addEventListener("change", (event) => {
		saveDateTimeFormat(event.currentTarget.value);
		void loadAll()
			.then(() => showToast("Date format updated."))
			.catch((error) => showToast(error.message, "bad"));
	});
	byId("applyDateRange").addEventListener(
		"click",
		(event) =>
			void runWithButton(event.currentTarget, async () => {
				try {
					const range = readDateRangeInputs();
					await applyDateRangeValues(range.from, range.to);
				} catch (error) {
					showToast(error.message, "bad");
				}
			}),
	);
	byId("resetDateRange").addEventListener(
		"click",
		(event) =>
			void runWithButton(event.currentTarget, async () => {
				try {
					const to = Date.now();
					await applyDateRangeValues(to - 24 * 3_600_000, to, "Last 24 hours applied");
				} catch (error) {
					showToast(error.message, "bad");
				}
			}),
	);
	for (const id of ["dateFrom", "dateTo"]) {
		byId(id).addEventListener("keydown", (event) => {
			if (event.key === "Enter") byId("applyDateRange").click();
		});
	}
	byId("liveRefreshInterval").addEventListener("change", (event) => {
		saveLiveRefreshInterval(event.currentTarget.value);
		startLivePolling();
	});
	byId("refreshDashboard").addEventListener(
		"click",
		() =>
			void Promise.all([loadAll(), refreshLiveStats()])
				.then(() => markUpdated())
				.catch((error) => showToast(error.message, "bad")),
	);
	byId("logout").addEventListener("click", async () => {
		await api("/logout", { method: "POST" });
		location.href = "/_burrowgate/admin/login";
	});
	window.addEventListener(
		"pagehide",
		() => {
			hostChart?.destroy();
			stopLivePolling();
		},
		{ once: true },
	);
}

async function start() {
	initializeDateTimeFormat();
	initializeDateRange();
	initializeLiveRefreshInterval();
	bindActions();
	try {
		await Promise.all([loadAll(), refreshLiveStats()]);
		startLivePolling();
		markUpdated("Loaded");
	} catch (error) {
		showToast(error.message, "bad");
	}
}

void start();
