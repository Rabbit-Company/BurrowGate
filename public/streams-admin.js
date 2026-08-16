const ADMIN_API = "/_burrowgate/api/admin";
const mutationHeaders = { "x-burrowgate-admin": "1" };
const DATE_TIME_FORMAT_STORAGE_KEY = "burrowgate.admin.date-time-format";
const DATE_TIME_FORMATS = new Set(["iso-24", "dmy-24", "mdy-12", "browser"]);
const byId = (id) => document.getElementById(id);
const DEFAULT_BANDWIDTH_LIMIT = { enabled: false, maxBytes: 50 * 1024 * 1024, windowSeconds: 60, banSeconds: 3600 };

function mibToBytes(mib) {
	return mib === null || mib === undefined ? null : Math.round(mib * 1024 * 1024);
}

function bytesToMib(bytes) {
	return bytes === null || bytes === undefined ? null : bytes / (1024 * 1024);
}

let streams = [];
let currentAdmin = null;
let usersData = { items: [], sites: [], streams: [] };
let editingPermissionsUserId = null;
let certificates = [];
let statuses = [];
let selectedStreamId = "";
let rulesStreamId = "";
let streamCountryRules = [];
const selectedStreamRuleIds = new Set();
let protectionStreamId = "";
let protectionCatalog = [];
let healthStreamId = "";
let activeTab = "connections";
let eventPage = 1;
let bandwidthPage = 1;
let pageSize = 50;
let rangeFrom = 0;
let rangeTo = 0;
let geoMapGeometry = null;
let geoStatus = null;
let geoData = { active: [], events: [], bandwidth: [], blocked: [] };
let geoZoom = null;
const GEO_ZOOM_MAX_SCALE = 8;
let activeConnections = [];
let latestStreamMetrics = null;
let streamTrafficChart = null;
let streamChartViewSelection = "connections:primary";
let streamTopListScopeSelection = "blocked";
let streamTopListData = null;
let streamTopListRequestId = 0;
let dateTimeFormat = "iso-24";

const tableState = {
	connections: { sortBy: "connectedAt", sortDirection: "desc" },
	events: { sortBy: "created_at", sortDirection: "desc" },
	bandwidth: { sortBy: "total_bytes", sortDirection: "desc" },
	rules: { page: 1, pageSize: 50, sortBy: "created_at", sortDirection: "desc" },
	auditLog: { page: 1, pageSize: 50, sortBy: "created_at", sortDirection: "desc" },
};

const COLUMN_VISIBILITY_STORAGE_KEY = "burrowgate.streams-admin.column-visibility";

const COLUMN_REGISTRY = {
	connections: [
		{ key: "country", label: "Country" },
		{ key: "connected", label: "Connected" },
		{ key: "lastActivity", label: "Last activity" },
		{ key: "toOrigin", label: "To origin" },
		{ key: "toClient", label: "To client" },
	],
	events: [
		{ key: "country", label: "Country" },
		{ key: "event", label: "Event" },
		{ key: "reason", label: "Reason" },
		{ key: "rule", label: "Rule" },
		{ key: "toOrigin", label: "To origin" },
		{ key: "toClient", label: "To client" },
		{ key: "connectionId", label: "Connection ID", defaultVisible: false },
	],
	bandwidth: [
		{ key: "country", label: "Country" },
		{ key: "toOrigin", label: "To origin" },
		{ key: "toClient", label: "To client" },
		{ key: "total", label: "Total" },
	],
	rules: [
		{ key: "reason", label: "Reason" },
		{ key: "created", label: "Created" },
		{ key: "expires", label: "Expires" },
	],
};

function readColumnVisibility() {
	try {
		const stored = JSON.parse(localStorage.getItem(COLUMN_VISIBILITY_STORAGE_KEY) ?? "{}");
		return stored && typeof stored === "object" ? stored : {};
	} catch {
		return {};
	}
}

let columnVisibility = readColumnVisibility();

function saveColumnVisibility() {
	try {
		localStorage.setItem(COLUMN_VISIBILITY_STORAGE_KEY, JSON.stringify(columnVisibility));
	} catch {}
}

function isColumnVisible(tableKey, columnKey) {
	const stored = columnVisibility[tableKey]?.[columnKey];
	if (stored !== undefined) return stored;
	return COLUMN_REGISTRY[tableKey]?.find((column) => column.key === columnKey)?.defaultVisible !== false;
}

const TABLE_RELOADERS = {
	connections: () => renderActive(activeConnections),
	events: () => loadEvents(),
	bandwidth: () => loadBandwidth(),
	rules: () => loadStreamRules(),
};

function setColumnVisible(tableKey, columnKey, visible) {
	columnVisibility[tableKey] ??= {};
	columnVisibility[tableKey][columnKey] = visible;
	saveColumnVisibility();
	applyColumnVisibility(tableKey);
	TABLE_RELOADERS[tableKey]?.();
}

function applyColumnVisibility(tableKey) {
	for (const column of COLUMN_REGISTRY[tableKey] ?? []) {
		const visible = isColumnVisible(tableKey, column.key);
		document.querySelectorAll(`[data-column="${tableKey}:${column.key}"]`).forEach((element) => element.classList.toggle("hidden", !visible));
	}
}

function visibleColumnCount(tableKey, fixedCount) {
	const columns = COLUMN_REGISTRY[tableKey] ?? [];
	return fixedCount + columns.filter((column) => isColumnVisible(tableKey, column.key)).length;
}

function columnsMenuMarkup(tableKey) {
	const columns = COLUMN_REGISTRY[tableKey] ?? [];
	if (columns.length === 0) return "";
	const items = columns
		.map(
			(column) =>
				`<label class="columns-menu-item"><input type="checkbox" data-column-toggle="${tableKey}:${column.key}"${isColumnVisible(tableKey, column.key) ? " checked" : ""}> ${escapeHtml(column.label)}</label>`,
		)
		.join("");
	return `<details class="columns-menu-details"><summary class="button secondary compact">Columns</summary><div class="columns-menu">${items}</div></details>`;
}

function insertColumnsMenus(anchors) {
	for (const [tableKey, containerId] of Object.entries(anchors)) {
		const markup = columnsMenuMarkup(tableKey);
		if (!markup) continue;
		byId(containerId)?.insertAdjacentHTML("afterbegin", markup);
	}
	for (const tableKey of Object.keys(anchors)) applyColumnVisibility(tableKey);
}

function bindColumnsMenus() {
	document.addEventListener("change", (event) => {
		const target = event.target;
		if (!(target instanceof HTMLInputElement) || !target.dataset.columnToggle) return;
		const [tableKey, columnKey] = target.dataset.columnToggle.split(":");
		setColumnVisible(tableKey, columnKey, target.checked);
	});
	document.addEventListener("click", (event) => {
		for (const details of document.querySelectorAll("details.columns-menu-details[open]")) {
			if (!details.contains(event.target)) details.removeAttribute("open");
		}
	});
}

const escapeHtml = (value) =>
	String(value ?? "").replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);

function truncate(value, length = 72) {
	const text = String(value ?? "");
	return text.length > length ? `${text.slice(0, length - 1)}...` : text;
}

function setTableLoading(id, columns) {
	byId(id).innerHTML = `<tr><td colspan="${columns}" class="empty-cell"><span class="spinner"></span> Loading...</td></tr>`;
}

function setTableError(id, columns, error) {
	byId(id).innerHTML = `<tr><td colspan="${columns}" class="empty-cell error-text">${escapeHtml(error.message)}</td></tr>`;
}

function streamActionLabel(action) {
	return action === "allow" ? "allow" : action === "block" ? "block" : String(action ?? "-");
}

function ruleState(rule) {
	return rule.expires_at !== null && Number(rule.expires_at) <= Date.now() ? "expired" : "active";
}

function formatNumber(value) {
	return Number(value ?? 0).toLocaleString();
}

function formatBytes(value) {
	const bytes = Math.max(0, Number(value ?? 0));
	if (!Number.isFinite(bytes) || bytes === 0) return "0 B";
	const units = ["B", "KiB", "MiB", "GiB", "TiB"];
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

function bytesDefinitionToBitrate(definition, bucketMs) {
	if (definition.valueFormat !== "bytes" || !bucketMs) return definition;
	const bucketSeconds = bucketMs / 1000;
	return {
		...definition,
		valueFormat: "bitrate",
		data: definition.data.map((point) => {
			const converted = { ...point };
			for (const dataset of definition.datasets) converted[dataset.key] = (Number(point[dataset.key] ?? 0) * 8) / bucketSeconds;
			return converted;
		}),
	};
}

function twoDigits(value) {
	return String(value).padStart(2, "0");
}

function readDateTimeFormat() {
	try {
		const stored = localStorage.getItem(DATE_TIME_FORMAT_STORAGE_KEY);
		return stored && DATE_TIME_FORMATS.has(stored) ? stored : "iso-24";
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
	if (value === null || value === undefined) return "-";
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

function formatDuration(start, end = Date.now()) {
	const seconds = Math.max(0, Math.floor((Number(end) - Number(start)) / 1_000));
	if (seconds < 60) return `${seconds}s`;
	if (seconds < 3_600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
	return `${Math.floor(seconds / 3_600)}h ${Math.floor((seconds % 3_600) / 60)}m`;
}

function rangeDurationLabel(milliseconds) {
	const totalMinutes = Math.max(1, Math.round(Number(milliseconds) / 60_000));
	if (totalMinutes < 60) return `${totalMinutes}m`;
	const totalHours = totalMinutes / 60;
	if (totalHours < 48) {
		const hours = Math.floor(totalHours);
		const minutes = totalMinutes % 60;
		return minutes === 0 ? `${hours}h` : `${hours}h ${minutes}m`;
	}
	const days = Math.floor(totalHours / 24);
	const hours = Math.floor(totalHours % 24);
	return hours === 0 ? `${days}d` : `${days}d ${hours}h`;
}

function chartTheme() {
	const styles = getComputedStyle(document.documentElement);
	const value = (name, fallback) => styles.getPropertyValue(name).trim() || fallback;
	return {
		grid: value("--chart-grid", "#273244"),
		text: value("--chart-text", "#94a3b8"),
		palette: [
			value("--chart-requests", "#8b5cf6"),
			value("--chart-blocked", "#f97316"),
			value("--chart-errors", "#f43f5e"),
			value("--chart-latency", "#22d3ee"),
		],
	};
}

function metricLabel(bucket, detailed = false) {
	const date = new Date(Number(bucket));
	if (detailed) return formatDate(date);
	if (Number(latestStreamMetrics?.rangeDurationMs ?? rangeTo - rangeFrom) >= 24 * 3_600_000) {
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

const dateRangeSelectionPlugin = {
	id: "burrowgateStreamDateRangeSelection",
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
	canvas.parentElement?.classList.toggle("time-selectable", Boolean(definition.timeSeries));
	if (!definition.timeSeries || definition.data.length < 2) return;

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
		const bucketMs = Number(latestStreamMetrics?.bucketMs ?? 60_000);
		const from = Math.max(rangeFrom, Number(definition.data[startIndex]?.bucket ?? rangeFrom));
		const to = Math.min(rangeTo, Number(definition.data[endIndex]?.bucket ?? rangeTo) + bucketMs);
		stop();
		if (to - from >= 60_000 && (from !== rangeFrom || to !== rangeTo)) {
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

function createStreamChart(canvasId, definition) {
	if (!window.Chart) throw new Error("Chart.js failed to load");
	const theme = chartTheme();
	const formatter = streamValueFormatter(definition.valueFormat);
	const labels = definition.data.map((point) => (definition.timeSeries ? metricLabel(point.bucket) : String(point.label ?? "")));
	const isBar = definition.type === "bar";
	const datasets = definition.datasets.map((dataset, index) => {
		const color = theme.palette[index % theme.palette.length];
		const values = definition.data.map((point) => Number(point[dataset.key] ?? 0));
		if (isBar) {
			const perBarColor = definition.datasets.length === 1 ? definition.data.map((_, pointIndex) => theme.palette[pointIndex % theme.palette.length]) : color;
			return {
				label: dataset.label,
				data: values,
				backgroundColor: perBarColor,
				borderColor: perBarColor,
				borderWidth: 1,
				borderRadius: 5,
				maxBarThickness: 52,
			};
		}
		return {
			label: dataset.label,
			data: values,
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
	});
	const chart = new window.Chart(byId(canvasId), {
		type: isBar ? "bar" : "line",
		data: { labels, datasets },
		options: {
			responsive: true,
			resizeDelay: 150,
			animation: false,
			normalized: true,
			interaction: { mode: definition.timeSeries ? "index" : "nearest", intersect: false },
			plugins: {
				legend: {
					display: datasets.length > 1,
					position: "bottom",
					labels: { color: theme.text, usePointStyle: true, pointStyle: isBar ? "rectRounded" : "line", boxWidth: 18, boxHeight: 3, padding: 18 },
				},
				tooltip: {
					enabled: true,
					mode: definition.timeSeries ? "index" : "nearest",
					intersect: false,
					callbacks: {
						title(items) {
							const point = definition.data[items[0].dataIndex];
							return definition.timeSeries ? metricLabel(point?.bucket, true) : String(point?.label ?? "");
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
					ticks: { color: theme.text, autoSkip: true, maxRotation: 0, minRotation: 0, maxTicksLimit: 8 },
				},
				y: {
					beginAtZero: true,
					grid: { color: theme.grid },
					border: { display: false },
					ticks: { color: theme.text, precision: definition.valueFormat === "number" ? 0 : undefined, callback: formatter },
				},
			},
		},
		plugins: [dateRangeSelectionPlugin],
	});
	attachDateRangeSelection(chart, definition);
	return chart;
}

function formatLatencyMs(milliseconds) {
	const value = Number(milliseconds ?? 0);
	if (value < 1_000) return `${Math.round(value)} ms`;
	if (value < 60_000) return `${(value / 1_000).toFixed(1)} s`;
	return `${(value / 60_000).toFixed(1)} min`;
}

function streamValueFormatter(format) {
	if (format === "bytes") return (value) => formatBytes(Number(value));
	if (format === "bitrate") return (value) => formatBitrate(Number(value));
	if (format === "duration") return (value) => formatLatencyMs(Number(value));
	if (format === "percentage") return (value) => `${Number(value).toFixed(1)}%`;
	return (value) => formatNumber(Math.round(Number(value)));
}

function summarizeChartDefinition(definition) {
	if (!definition?.datasets?.length || !definition.data?.length) return [];
	if (definition.datasets.length === 1 && !definition.timeSeries) {
		const [dataset] = definition.datasets;
		return definition.data.map((point) => ({ label: String(point.label ?? ""), count: Number(point[dataset.key] ?? 0) }));
	}
	return definition.datasets.map((dataset) => {
		const total = definition.data.reduce((sum, point) => sum + Number(point[dataset.key] ?? 0), 0);
		return { label: dataset.label, count: total };
	});
}

function renderSummaryList(containerId, items, formatter) {
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

function streamChartCatalog(data, longLivedData) {
	return {
		"connections:primary": {
			title: "Stream traffic volume",
			subtitle: "Connections, disconnections, blocked connections, and proxy errors",
			emptyMessage: "No stream lifecycle activity in this range.",
			valueFormat: "number",
			timeSeries: true,
			datasets: [
				{ key: "connected", label: "Connected" },
				{ key: "blocked", label: "Blocked" },
				{ key: "errors", label: "Errors" },
				{ key: "disconnected", label: "Disconnected" },
			],
			data,
		},
		"connections:filtered": {
			title: "Stream traffic volume (open ≥10s)",
			subtitle: "Connections and disconnections open for at least 10 seconds (short pings and health checks are excluded)",
			emptyMessage: "No connections open at least 10 seconds in this range.",
			valueFormat: "number",
			timeSeries: true,
			datasets: [
				{ key: "connected", label: "Connected" },
				{ key: "disconnected", label: "Disconnected" },
			],
			data: longLivedData,
		},
		"connections:secondary": {
			title: "Stream data volume",
			subtitle: "Payload bytes transferred in both proxy directions",
			emptyMessage: "No stream bandwidth in this range.",
			valueFormat: "bytes",
			timeSeries: true,
			datasets: [
				{ key: "clientToUpstreamBytes", label: "To origin" },
				{ key: "upstreamToClientBytes", label: "To clients" },
			],
			data,
		},
		"bandwidth:primary": {
			title: "Client to origin bandwidth",
			subtitle: "Payload bytes received from stream clients and forwarded to origin",
			emptyMessage: "No client-to-origin bandwidth in this range.",
			valueFormat: "bytes",
			timeSeries: true,
			datasets: [{ key: "clientToUpstreamBytes", label: "To origin" }],
			data,
		},
		"bandwidth:secondary": {
			title: "Origin to client bandwidth",
			subtitle: "Payload bytes received from origin and returned to stream clients",
			emptyMessage: "No origin-to-client bandwidth in this range.",
			valueFormat: "bytes",
			timeSeries: true,
			datasets: [{ key: "upstreamToClientBytes", label: "To clients" }],
			data,
		},
	};
}

function streamComparisonCatalog(comparison) {
	const streamLabel = (id) => {
		const stream = streams.find((item) => item.id === id);
		return stream ? `${stream.name} (port ${stream.incomingPort})` : id;
	};
	const byConnections = [...comparison].sort((a, b) => b.connections - a.connections).slice(0, 15);
	const byBytes = [...comparison].sort((a, b) => b.bytes - a.bytes).slice(0, 15);
	return {
		"compare:primary": {
			title: "Connections by stream",
			subtitle: "Total connections per stream in the selected range",
			type: "bar",
			timeSeries: false,
			valueFormat: "number",
			emptyMessage: "No stream connections in this range.",
			datasets: [{ key: "count", label: "Connections" }],
			data: byConnections.map((item) => ({ label: streamLabel(item.streamId), count: item.connections })),
		},
		"compare:secondary": {
			title: "Bandwidth by stream",
			subtitle: "Total bytes transferred per stream in the selected range",
			type: "bar",
			timeSeries: false,
			valueFormat: "bytes",
			emptyMessage: "No stream bandwidth in this range.",
			datasets: [{ key: "count", label: "Bytes" }],
			data: byBytes.map((item) => ({ label: streamLabel(item.streamId), count: item.bytes })),
		},
	};
}

function streamBlockReasonCatalog(blockReasons) {
	return {
		"protection:primary": {
			title: "Blocked connections by reason",
			subtitle: "Why connections were blocked in the selected range",
			type: "bar",
			timeSeries: false,
			valueFormat: "number",
			emptyMessage: "No blocked connections in this range.",
			datasets: [{ key: "count", label: "Blocked" }],
			data: blockReasons.map((item) => ({ label: item.reason, count: item.count })),
		},
	};
}

function streamProtocolCatalog(protocolBreakdown) {
	const label = (protocol) => protocol.toUpperCase();
	return {
		"protocol:primary": {
			title: "Connections by protocol",
			subtitle: "Total connections per protocol in the selected range",
			type: "bar",
			timeSeries: false,
			valueFormat: "number",
			emptyMessage: "No connections in this range.",
			datasets: [{ key: "count", label: "Connections" }],
			data: protocolBreakdown.map((item) => ({ label: label(item.protocol), count: item.connections })),
		},
		"protocol:secondary": {
			title: "Bandwidth by protocol",
			subtitle: "Total bytes transferred per protocol in the selected range",
			type: "bar",
			timeSeries: false,
			valueFormat: "bytes",
			emptyMessage: "No bandwidth in this range.",
			datasets: [{ key: "count", label: "Bytes" }],
			data: protocolBreakdown.map((item) => ({ label: label(item.protocol), count: item.bytes })),
		},
	};
}

function streamHealthCatalog(healthSeries) {
	return {
		"health:primary": {
			title: "Origin TCP connect latency",
			subtitle: "Min / average / max connect time per interval",
			timeSeries: true,
			valueFormat: "duration",
			emptyMessage: "No health-check latency in this range.",
			datasets: [
				{ key: "minLatencyMs", label: "Min" },
				{ key: "avgLatencyMs", label: "Average" },
				{ key: "maxLatencyMs", label: "Max" },
			],
			data: healthSeries,
		},
		"health:secondary": {
			title: "Timed-out connect attempts",
			subtitle: "Share of checks that never connected",
			timeSeries: true,
			valueFormat: "percentage",
			emptyMessage: "No health checks in this range.",
			datasets: [{ key: "timeoutPct", label: "Timeout %" }],
			data: healthSeries,
		},
	};
}

function parseStreamChartViewKey(key) {
	const [group, slot, bitrate] = key.split(":");
	return { base: `${group}:${slot}`, isBitrate: bitrate === "bitrate" };
}

function renderStreamCharts() {
	if (!latestStreamMetrics) return;
	const data = latestStreamMetrics.series ?? [];
	const longLivedData = latestStreamMetrics.longLivedSeries ?? [];
	const catalog = {
		...streamChartCatalog(data, longLivedData),
		...streamComparisonCatalog(latestStreamMetrics.comparison ?? []),
		...streamBlockReasonCatalog(latestStreamMetrics.blockReasons ?? []),
		...streamProtocolCatalog(latestStreamMetrics.protocolBreakdown ?? []),
		...streamHealthCatalog(latestStreamMetrics.healthSeries ?? []),
	};
	const { base, isBitrate } = parseStreamChartViewKey(streamChartViewSelection);
	const definition = catalog[base] ?? catalog["connections:primary"];
	const display = isBitrate ? bytesDefinitionToBitrate(definition, latestStreamMetrics.bucketMs) : definition;

	const select = byId("streamChartView");
	byId("primaryChartTitle").textContent = select.selectedOptions[0]?.textContent ?? display.title;
	byId("primaryChartSubtitle").textContent = display.subtitle;
	byId("streamTrafficEmpty").textContent = display.emptyMessage;
	const hasData = display.datasets.some((dataset) => display.data.some((point) => Number(point[dataset.key]) > 0));
	byId("streamTrafficEmpty").classList.toggle("hidden", hasData);
	streamTrafficChart?.destroy();
	streamTrafficChart = createStreamChart("streamTrafficChart", display);
	renderSummaryList("streamPrimarySummary", summarizeChartDefinition(display), streamValueFormatter(display.valueFormat));
}

async function loadStreamMetrics() {
	latestStreamMetrics = await api(`/streams/metrics?${queryString({ streamId: selectedStreamId, ...rangeQuery() })}`);
	renderStreamCharts();
}

const STREAM_TOP_LIST_KIND = {
	blocked: {
		endpoint: "streams/ip-metrics-tab?scope=blocked",
		field: "ips",
		itemKey: "ip",
		title: "Top blocked IPs",
		subtitle: (rangeLabel) => `Source IPs blocked most often in the selected range (${rangeLabel})`,
		empty: "No blocked connections in this range.",
		formatCount: formatNumber,
	},
	bandwidth: {
		endpoint: "streams/ip-bandwidth-metrics-tab",
		field: "ips",
		itemKey: "ip",
		title: "Top IPs by bandwidth",
		subtitle: (rangeLabel) => `Source IPs generating the most bandwidth in the selected range (${rangeLabel})`,
		empty: "No bandwidth activity in this range.",
		formatCount: formatBytes,
	},
	errors: {
		endpoint: "streams/error-metrics-tab",
		field: "errors",
		itemKey: "error",
		title: "Top error reasons",
		subtitle: (rangeLabel) => `Upstream and listener error messages seen most often in the selected range (${rangeLabel})`,
		empty: "No upstream or listener errors in this range.",
		formatCount: formatNumber,
	},
};

async function loadStreamTopList() {
	const requestId = ++streamTopListRequestId;
	const kind = STREAM_TOP_LIST_KIND[streamTopListScopeSelection];
	const result = await api(`/${kind.endpoint}${kind.endpoint.includes("?") ? "&" : "?"}${queryString({ streamId: selectedStreamId, ...rangeQuery() })}`);
	if (requestId !== streamTopListRequestId) return;
	streamTopListData = result;
	renderStreamTopList();
}

function renderStreamTopList() {
	const kind = STREAM_TOP_LIST_KIND[streamTopListScopeSelection];
	if (!streamTopListData) return;
	const items = streamTopListData[kind.field] ?? [];
	const total = items.reduce((sum, item) => sum + Number(item.count), 0);
	const rangeLabel = rangeDurationLabel(streamTopListData.rangeDurationMs ?? rangeTo - rangeFrom);
	byId("streamRefererTitle").textContent = byId("streamTopListMode").selectedOptions[0]?.textContent ?? kind.title;
	byId("streamRefererSubtitle").textContent = kind.subtitle(rangeLabel);
	byId("streamRefererTotal").textContent = kind.formatCount(total);
	byId("streamRefererList").innerHTML =
		items.length === 0
			? `<p class="muted">${kind.empty}</p>`
			: items
					.map((item) => {
						const label = String(item[kind.itemKey] ?? "");
						const percentage = total > 0 ? (Number(item.count) / total) * 100 : 0;
						return `<div class="geo-country-row"><div class="row between"><span title="${escapeHtml(label)}">${escapeHtml(truncate(label, 60))}</span><strong>${kind.formatCount(item.count)}</strong></div><div class="breakdown-track"><div style="width:${Math.max(1, percentage)}%"></div></div></div>`;
					})
					.join("");
}

function toDateTimeLocal(value) {
	const date = new Date(value);
	const pad = (part) => String(part).padStart(2, "0");
	return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function initializeRange() {
	const url = new URL(location.href);
	const now = Date.now();
	rangeTo = Number(url.searchParams.get("to")) || now;
	rangeFrom = Number(url.searchParams.get("from")) || rangeTo - 86_400_000;
	if (rangeFrom >= rangeTo) rangeFrom = rangeTo - 86_400_000;
	byId("dateFrom").value = toDateTimeLocal(rangeFrom);
	byId("dateTo").value = toDateTimeLocal(rangeTo);
	persistDateRange();
}

function persistDateRange() {
	const url = new URL(location.href);
	url.searchParams.set("from", String(rangeFrom));
	url.searchParams.set("to", String(rangeTo));
	history.replaceState(null, "", `${url.pathname}${url.search}${url.hash}`);
}

async function applyDateRangeValues(from, to, updateLabel = "Updated") {
	rangeFrom = Number(from);
	rangeTo = Number(to);
	byId("dateFrom").value = toDateTimeLocal(rangeFrom);
	byId("dateTo").value = toDateTimeLocal(rangeTo);
	persistDateRange();
	eventPage = 1;
	bandwidthPage = 1;
	await refreshDashboard(updateLabel);
}

function rangeQuery() {
	return { from: rangeFrom, to: rangeTo };
}

function queryString(values) {
	const query = new URLSearchParams();
	for (const [key, value] of Object.entries(values)) if (value !== "" && value !== null && value !== undefined) query.set(key, String(value));
	return query.toString();
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

function showToast(message, kind = "ok") {
	const toast = byId("toast");
	toast.textContent = message;
	toast.className = `toast ${kind}`;
	clearTimeout(showToast.timer);
	showToast.timer = setTimeout(() => toast.classList.add("hidden"), 3_500);
}

function statusFor(id) {
	return statuses.find((status) => status.id === id) ?? { tcp: "disabled", udp: "disabled", error: null, activeTcpConnections: 0, activeUdpPeers: 0 };
}

function statusBadge(value) {
	return `<span class="badge ${value === "active" ? "ok" : value === "error" ? "bad" : "info"}">${escapeHtml(value)}</span>`;
}

function renderStreamSelector() {
	const selector = byId("streamSelector");
	selector.innerHTML = `<option value="">All streams</option>${streams.map((stream) => `<option value="${escapeHtml(stream.id)}">${escapeHtml(stream.name)} (port ${stream.incomingPort})</option>`).join("")}`;
	if (streams.some((stream) => stream.id === selectedStreamId)) selector.value = selectedStreamId;
	else selectedStreamId = "";
}

function renderRulesStreamSelector() {
	const selector = byId("rulesStreamSelector");
	if (!streams.some((stream) => stream.id === rulesStreamId)) rulesStreamId = selectedStreamId || streams[0]?.id || "";
	selector.innerHTML = streams.length
		? streams.map((stream) => `<option value="${escapeHtml(stream.id)}">${escapeHtml(stream.name)} (port ${stream.incomingPort})</option>`).join("")
		: '<option value="">No streams configured</option>';
	selector.value = rulesStreamId;
	selector.disabled = streams.length === 0;
}

function renderProtectionStreamSelector() {
	const selector = byId("protectionStreamSelector");
	if (!streams.some((stream) => stream.id === protectionStreamId)) protectionStreamId = selectedStreamId || streams[0]?.id || "";
	selector.innerHTML = streams.length
		? streams.map((stream) => `<option value="${escapeHtml(stream.id)}">${escapeHtml(stream.name)} (port ${stream.incomingPort})</option>`).join("")
		: '<option value="">No streams configured</option>';
	selector.value = protectionStreamId;
	selector.disabled = streams.length === 0;
}

function renderHealthStreamSelector() {
	const selector = byId("healthStreamSelector");
	if (!streams.some((stream) => stream.id === healthStreamId)) healthStreamId = selectedStreamId || streams[0]?.id || "";
	selector.innerHTML = streams.length
		? streams.map((stream) => `<option value="${escapeHtml(stream.id)}">${escapeHtml(stream.name)} (port ${stream.incomingPort})</option>`).join("")
		: '<option value="">No streams configured</option>';
	selector.value = healthStreamId;
	selector.disabled = streams.length === 0;
}

function renderCertificateOptions() {
	const select = byId("streamCertificate");
	const selected = select.value;
	select.innerHTML = `<option value="">None / TLS passthrough</option>${certificates.map((certificate) => `<option value="${escapeHtml(certificate.id)}">${escapeHtml(certificate.primaryDomain)} | ${escapeHtml(certificate.siteName)} | expires ${escapeHtml(formatDate(certificate.expiresAt))}</option>`).join("")}`;
	if (certificates.some((certificate) => certificate.id === selected)) select.value = selected;
}

async function loadCurrentAdmin() {
	currentAdmin = await api("/me");
	applyCurrentAdminVisibility();
	return currentAdmin;
}

function applyCurrentAdminVisibility() {
	const isAdministrator = currentAdmin?.role === "administrator";
	byId("newStream").classList.toggle("hidden", !isAdministrator);
	byId("openUsers").classList.toggle("hidden", !isAdministrator);
	byId("openAudit").classList.toggle("hidden", !isAdministrator);
	byId("openSso").classList.toggle("hidden", !isAdministrator);
}

function openModal(name) {
	byId(`modal-${name}`).classList.remove("hidden");
	document.body.classList.add("modal-open");
	if (name === "users") void loadUsers();
	if (name === "audit") void loadAuditLog();
	if (name === "account") void loadAccount();
	if (name === "sso") void loadAdminSso();
}

async function loadAdminSso() {
	try {
		const settings = await api("/sso");
		byId("adminSsoEnabled").checked = Boolean(settings.enabled);
		byId("adminSsoEnforce").checked = Boolean(settings.enforceSso);
		byId("adminSsoIssuer").value = settings.issuerUrl ?? "";
		byId("adminSsoClientId").value = settings.clientId ?? "";
		byId("adminSsoClientSecret").value = "";
		byId("adminSsoScopes").value = settings.scopes || "openid email profile";
		byId("adminSsoButtonLabel").value = settings.buttonLabel || "Single sign-on";
		byId("adminSsoSecretStatus").textContent = settings.clientSecretConfigured ? "A client secret is configured." : "No client secret is configured.";
		byId("adminSsoRedirectUri").textContent = `${location.origin}/_burrowgate/admin/sso/callback`;
		byId("adminSsoBackchannelUri").textContent = `${location.origin}/_burrowgate/admin/sso/backchannel-logout`;
	} catch (error) {
		showToast(error.message, "bad");
	}
}

async function saveAdminSso() {
	const button = byId("saveAdminSso");
	button.disabled = true;
	try {
		const secret = byId("adminSsoClientSecret").value;
		await api("/sso", {
			method: "PUT",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				enabled: byId("adminSsoEnabled").checked,
				enforceSso: byId("adminSsoEnforce").checked,
				issuerUrl: byId("adminSsoIssuer").value,
				clientId: byId("adminSsoClientId").value,
				...(secret ? { clientSecret: secret } : {}),
				scopes: byId("adminSsoScopes").value,
				buttonLabel: byId("adminSsoButtonLabel").value,
			}),
		});
		await loadAdminSso();
		showToast("Single sign-on settings saved.");
	} catch (error) {
		showToast(error.message, "bad");
	} finally {
		button.disabled = false;
	}
}

function closeModal(name) {
	byId(`modal-${name}`).classList.add("hidden");
	if (!document.querySelector(".modal-overlay:not(.hidden)")) document.body.classList.remove("modal-open");
	if (name === "users") {
		editingPermissionsUserId = null;
		byId("userPermissionsCard").classList.add("hidden");
	}
}

function closeAllModals() {
	document.querySelectorAll(".modal-overlay:not(.hidden)").forEach((overlay) => closeModal(overlay.dataset.modal));
}

function userPermissionsSummary(user) {
	if (user.role === "administrator") return "All sites and streams";
	const parts = [];
	if (user.sitePermissions.length) parts.push(`${user.sitePermissions.length} site${user.sitePermissions.length === 1 ? "" : "s"}`);
	if (user.streamPermissions.length) parts.push(`${user.streamPermissions.length} stream${user.streamPermissions.length === 1 ? "" : "s"}`);
	return parts.length ? parts.join(", ") : "None";
}

function renderUsers() {
	const rows = usersData.items
		.map(
			(user) => `<tr>
        <td>${escapeHtml(user.username)}</td>
        <td><span class="badge ${user.role === "administrator" ? "info" : ""}">${user.role === "administrator" ? "Administrator" : "Member"}</span></td>
        <td>${user.totpEnrolled ? '<span class="badge ok">Enrolled</span>' : '<span class="badge warn">Pending</span>'}</td>
        <td>${user.enabled ? '<span class="badge ok">Enabled</span>' : '<span class="badge bad">Disabled</span>'}</td>
        <td>${escapeHtml(userPermissionsSummary(user))}</td>
        <td class="row-actions">
          ${user.role === "administrator" ? "" : `<button class="button secondary compact" data-user-permissions="${escapeHtml(user.id)}" type="button">Permissions</button>`}
          <button class="button secondary compact" data-user-reset-password="${escapeHtml(user.id)}" type="button">Reset password</button>
          <button class="button secondary compact" data-user-reset-totp="${escapeHtml(user.id)}" type="button">Reset 2FA</button>
          <button class="button danger compact" data-user-delete="${escapeHtml(user.id)}" type="button">Delete</button>
        </td>
      </tr>`,
		)
		.join("");
	byId("users").innerHTML = rows || '<tr><td colspan="6" class="empty-cell">No users yet.</td></tr>';
}

async function loadUsers() {
	setTableLoading("users", 6);
	try {
		usersData = await api("/users");
		renderUsers();
	} catch (error) {
		setTableError("users", 6, error);
	}
}

async function createUser(event) {
	event.preventDefault();
	const form = event.currentTarget;
	const payload = Object.fromEntries(new FormData(form));
	try {
		await api("/users", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
		form.reset();
		showToast("User created.");
		await loadUsers();
	} catch (error) {
		showToast(error.message, "bad");
	}
}

function permissionsGrid(id, resources, current, resourceKey) {
	const currentByResource = new Map(current.map((entry) => [entry[resourceKey], entry.level]));
	byId(id).innerHTML = resources.length
		? resources
				.map((resource) => {
					const level = currentByResource.get(resource.id) ?? "none";
					return `<label class="permission-row"><span>${escapeHtml(resource.label)}</span><select class="select" data-permission-resource="${escapeHtml(resource.id)}">
          <option value="none" ${level === "none" ? "selected" : ""}>None</option>
          <option value="viewer" ${level === "viewer" ? "selected" : ""}>Viewer</option>
          <option value="manager" ${level === "manager" ? "selected" : ""}>Manager</option>
        </select></label>`;
				})
				.join("")
		: '<p class="muted">None configured yet.</p>';
}

function openUserPermissions(userId) {
	const user = usersData.items.find((item) => item.id === userId);
	if (!user) return;
	editingPermissionsUserId = userId;
	byId("userPermissionsTitle").textContent = `Permissions for ${user.username}`;
	permissionsGrid(
		"userSitePermissions",
		usersData.sites.map((site) => ({ id: site.id, label: site.name })),
		user.sitePermissions,
		"siteId",
	);
	permissionsGrid(
		"userStreamPermissions",
		usersData.streams.map((stream) => ({ id: stream.id, label: `${stream.name} (port ${stream.incomingPort})` })),
		user.streamPermissions,
		"streamId",
	);
	byId("userPermissionsCard").classList.remove("hidden");
}

async function saveUserPermissions() {
	if (!editingPermissionsUserId) return;
	const sitePermissions = [...document.querySelectorAll("#userSitePermissions [data-permission-resource]")]
		.map((select) => ({ siteId: select.dataset.permissionResource, level: select.value }))
		.filter((entry) => entry.level !== "none");
	const streamPermissions = [...document.querySelectorAll("#userStreamPermissions [data-permission-resource]")]
		.map((select) => ({ streamId: select.dataset.permissionResource, level: select.value }))
		.filter((entry) => entry.level !== "none");
	try {
		await api(`/users/${encodeURIComponent(editingPermissionsUserId)}`, {
			method: "PATCH",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ sitePermissions, streamPermissions }),
		});
		showToast("Permissions updated.");
		byId("userPermissionsCard").classList.add("hidden");
		await loadUsers();
	} catch (error) {
		showToast(error.message, "bad");
	}
}

async function loadAccount() {
	const me = currentAdmin ?? (await loadCurrentAdmin());
	byId("accountSummary").textContent =
		`Signed in as ${me.username} (${me.role === "administrator" ? "Administrator" : "Member"}). Two-factor authentication: ${me.totpEnrolled ? "enrolled" : "not enrolled"}.`;
}

async function changePassword(event) {
	event.preventDefault();
	const form = event.currentTarget;
	const payload = Object.fromEntries(new FormData(form));
	try {
		await api("/me/password", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
		showToast("Password changed. Please log in again.");
		setTimeout(() => {
			location.href = "/_burrowgate/admin/login";
		}, 1_500);
	} catch (error) {
		showToast(error.message, "bad");
	}
}

async function regenerateRecoveryCodes(event) {
	event.preventDefault();
	const form = event.currentTarget;
	const payload = Object.fromEntries(new FormData(form));
	try {
		const result = await api("/me/recovery-codes/regenerate", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(payload),
		});
		form.reset();
		const list = byId("newRecoveryCodes");
		list.innerHTML = result.codes.map((code) => `<li><code>${escapeHtml(code)}</code></li>`).join("");
		list.classList.remove("hidden");
		showToast("Recovery codes regenerated.");
	} catch (error) {
		showToast(error.message, "bad");
	}
}

function renderAuditLog(items) {
	byId("auditLog").innerHTML = items.length
		? items
				.map((entry) => {
					const resource = entry.resource_type ? (entry.resource_id ? `${entry.resource_type} (${entry.resource_id})` : entry.resource_type) : "";
					return `<tr>
        <td>${escapeHtml(formatDate(entry.created_at))}</td>
        <td>${escapeHtml(entry.actor_username)}</td>
        <td>${escapeHtml(entry.action)}</td>
        <td class="truncate-cell" title="${escapeHtml(resource)}">${escapeHtml(resource)}</td>
        <td class="truncate-cell" title="${escapeHtml(entry.summary)}">${escapeHtml(entry.summary)}</td>
        <td>${escapeHtml(entry.ip)}</td>
      </tr>`;
				})
				.join("")
		: '<tr><td colspan="6" class="empty-cell">No audit log entries.</td></tr>';
}

async function loadAuditLog() {
	setTableLoading("auditLog", 6);
	try {
		const state = tableState.auditLog;
		const params = queryString({
			page: state.page,
			pageSize: state.pageSize,
			search: byId("auditSearch").value,
			sortBy: state.sortBy,
			sortDirection: state.sortDirection,
		});
		const result = await api(`/audit-log?${params}`);
		renderAuditLog(result.items);
		updatePagination("auditLog", result, loadAuditLog);
	} catch (error) {
		setTableError("auditLog", 6, error);
	}
}

async function purgeAuditLog() {
	const choice = prompt("Purge entries older than how many days? Enter 0 to purge all entries.", "90");
	if (choice === null) return;
	const days = Number(choice.trim());
	if (!Number.isFinite(days) || days < 0) {
		showToast("Enter a non-negative number of days.", "bad");
		return;
	}
	let confirmMessage = "Purge the entire audit log? This cannot be undone.";
	if (days > 0) {
		try {
			const cutoff = Date.now() - days * 86_400_000;
			const preview = await api(`/audit-log?until=${cutoff}&pageSize=1`);
			confirmMessage =
				preview.total > 0
					? `This will purge ${preview.total} entr${preview.total === 1 ? "y" : "ies"} older than ${days} day(s). Continue?`
					: `No entries are older than ${days} day(s) yet, so nothing will be purged. Continue anyway?`;
		} catch {
			confirmMessage = `Purge audit log entries older than ${days} day(s)?`;
		}
	}
	if (!confirm(confirmMessage)) return;
	try {
		const payload = days === 0 ? { all: true } : { olderThanDays: days };
		const result = await api("/audit-log/purge", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
		showToast(`Purged ${result.purged} entr${result.purged === 1 ? "y" : "ies"}.`);
		tableState.auditLog.page = 1;
		await loadAuditLog();
	} catch (error) {
		showToast(error.message, "bad");
	}
}

function renderStreams() {
	const list = byId("streamsList");
	if (!streams.length) {
		list.innerHTML = '<div class="empty-state-inline">No streams are configured.</div>';
		return;
	}
	const isAdministrator = currentAdmin?.role === "administrator";
	list.innerHTML = streams
		.map((stream) => {
			const status = statusFor(stream.id);
			const deleteButton = isAdministrator
				? `<button class="button danger compact" type="button" data-delete-stream="${escapeHtml(stream.id)}">Delete</button>`
				: "";
			return `<div class="site-list-item ${status.error ? "disabled" : ""}"><div class="site-list-title"><strong>${escapeHtml(stream.name)}</strong></div><div class="site-list-meta"><code>${escapeHtml(stream.forwardHost)}:${stream.forwardPort}</code><span>Retention ${stream.eventRetentionDays}d</span></div><div class="stream-status-row">${stream.tcpEnabled ? `TCP ${statusBadge(status.tcp)}` : ""}${stream.udpEnabled ? `UDP ${statusBadge(status.udp)}` : ""}<span class="muted">${status.activeTcpConnections} TCP / ${status.activeUdpPeers} UDP active</span></div>${status.error ? `<p class="badge bad">${escapeHtml(status.error)}</p>` : ""}<div class="site-list-actions"><button class="button secondary compact" type="button" data-edit-stream="${escapeHtml(stream.id)}">Edit</button>${deleteButton}</div></div>`;
		})
		.join("");
}

async function loadStreams() {
	const result = await api("/streams");
	streams = result.items;
	certificates = result.certificates;
	statuses = result.statuses;
	byId("udpPeerNotice").textContent = `UDP peers disconnect after ${result.defaults.udpPeerIdleTimeoutSeconds} seconds without a datagram.`;
	if (!byId("streamRetentionDays").value) byId("streamRetentionDays").value = String(result.defaults.retentionDays);
	renderStreamSelector();
	renderRulesStreamSelector();
	renderProtectionStreamSelector();
	renderHealthStreamSelector();
	renderCertificateOptions();
	renderStreams();
}

function filteredActive(items) {
	return selectedStreamId ? items.filter((item) => item.streamId === selectedStreamId) : items;
}

function compareValues(left, right, key) {
	const leftValue = left[key] ?? "";
	const rightValue = right[key] ?? "";
	if (typeof leftValue === "number" || typeof rightValue === "number") return Number(leftValue) - Number(rightValue);
	return String(leftValue).localeCompare(String(rightValue), undefined, { numeric: true, sensitivity: "base" });
}

function updateSortIndicators(panelId, state) {
	document.querySelectorAll(`#${panelId} .sort-button`).forEach((button) => {
		const selected = button.dataset.sort === state.sortBy;
		button.classList.toggle("selected", selected);
		button.querySelector("span").textContent = selected ? (state.sortDirection === "asc" ? "↑" : "↓") : "";
	});
}

function activeCountries(items) {
	const counts = new Map();
	for (const item of filteredActive(items)) {
		const code = String(item.countryCode || "ZZ").toUpperCase();
		counts.set(code, (counts.get(code) ?? 0) + 1);
	}
	return [...counts].map(([countryCode, count]) => ({ countryCode, count }));
}

function connectionsColumnCount() {
	return visibleColumnCount("connections", 3);
}

function renderActive(items) {
	activeConnections = items;
	const state = tableState.connections;
	const multiplier = state.sortDirection === "asc" ? 1 : -1;
	const filtered = [...filteredActive(items)].sort((left, right) => compareValues(left, right, state.sortBy) * multiplier);
	updateSortIndicators("panel-connections", state);
	byId("activeTcp").textContent = formatNumber(filtered.filter((item) => item.protocol === "tcp").length);
	byId("activeUdp").textContent = formatNumber(filtered.filter((item) => item.protocol === "udp").length);
	geoData.active = activeCountries(items);
	if (byId("geoMetricMode").value === "active") renderGeoMap();
	byId("activeConnections").innerHTML = filtered.length
		? filtered
				.map(
					(item) => `<tr>
          <td><span class="badge info">${item.protocol.toUpperCase()}</span></td>
          <td><code>${item.incomingPort}</code></td>
          <td class="ip-cell"><code title="${escapeHtml(`${item.clientIp} (${countryDisplayName(item.countryCode || "ZZ")})`)}">${escapeHtml(item.clientIp)}:${item.clientPort}</code></td>
          ${isColumnVisible("connections", "country") ? `<td>${countryBadge(item.countryCode)}</td>` : ""}
          ${isColumnVisible("connections", "connected") ? `<td title="${escapeHtml(formatDate(item.connectedAt))}">${formatDuration(item.connectedAt)}</td>` : ""}
          ${isColumnVisible("connections", "lastActivity") ? `<td>${escapeHtml(formatDate(item.lastActivityAt))}</td>` : ""}
          ${isColumnVisible("connections", "toOrigin") ? `<td>${formatBytes(item.clientToUpstreamBytes)}</td>` : ""}
          ${isColumnVisible("connections", "toClient") ? `<td>${formatBytes(item.upstreamToClientBytes)}</td>` : ""}
        </tr>`,
				)
				.join("")
		: `<tr><td colspan="${connectionsColumnCount()}" class="empty-cell">No active connections or UDP peers.</td></tr>`;
}

async function loadConnections() {
	const result = await api("/streams/active");
	statuses = result.statuses;
	renderActive(result.items);
	renderStreams();
}

async function loadOverview() {
	await loadGeoMapGeometry();
	const result = await api(`/streams/overview?${queryString({ streamId: selectedStreamId, ...rangeQuery() })}`);
	const rangeLabel = rangeDurationLabel(Number(result.rangeTo) - Number(result.rangeFrom));
	byId("rangeConnectionsLabel").textContent = `Connections (${rangeLabel})`;
	byId("uniqueIpsLabel").textContent = `Unique IPs (${rangeLabel})`;
	byId("clientToUpstreamLabel").textContent = `Client to origin (${rangeLabel})`;
	byId("upstreamToClientLabel").textContent = `Origin to client (${rangeLabel})`;
	byId("rangeErrorsLabel").textContent = `Errors (${rangeLabel})`;
	byId("rangeBlockedLabel").textContent = `Blocked (${rangeLabel})`;
	byId("rangeConnections").textContent = formatNumber(result.connections);
	byId("uniqueIps").textContent = formatNumber(result.uniqueIps);
	byId("rangeErrors").textContent = formatNumber(result.errors);
	byId("rangeBlocked").textContent = formatNumber(result.blocked);
	byId("clientToUpstream").textContent = formatBytes(result.clientToUpstreamBytes);
	byId("upstreamToClient").textContent = formatBytes(result.upstreamToClientBytes);
	geoStatus = result.geoip;
	geoData.events = result.countries.map((item) => ({ countryCode: item.countryCode, count: Number(item.connections) }));
	geoData.bandwidth = result.countries.map((item) => ({ countryCode: item.countryCode, count: Number(item.bytes) }));
	geoData.blocked = result.countries.map((item) => ({ countryCode: item.countryCode, count: Number(item.blocked) }));
	renderActive(result.active);
	renderGeoMap();
}

function countryDisplayName(code, fallback = "") {
	if (code === "ZZ") return "Unknown";
	if (code === "XX") return "Local / private network";
	try {
		return new Intl.DisplayNames(["en"], { type: "region" }).of(code) ?? (fallback || code);
	} catch {
		return fallback || code;
	}
}

function countryBadge(codeInput) {
	const code = String(codeInput || "ZZ").toUpperCase();
	const name = countryDisplayName(code);
	return `<span class="country-badge" title="${escapeHtml(name)}" aria-label="${escapeHtml(name)}">${escapeHtml(code)}</span>`;
}

function populateCountrySelects() {
	if (!geoMapGeometry) return;
	const countries = [...geoMapGeometry.paths.entries()]
		.map(([code, path]) => ({ code, name: path.dataset.name || countryDisplayName(code) }))
		.sort((left, right) => left.name.localeCompare(right.name));
	countries.push({ code: "ZZ", name: "Unknown / unmapped" }, { code: "XX", name: "Local / private network" });
	const configurations = [
		["eventCountry", "All countries"],
		["bandwidthCountry", "All countries"],
		["streamCountryRuleCountry", "Select country"],
	];
	for (const [id, emptyLabel] of configurations) {
		const select = byId(id);
		if (!select) continue;
		const current = select.value;
		select.innerHTML = `<option value="">${emptyLabel}</option>${countries.map((country) => `<option value="${country.code}">${escapeHtml(country.name)} (${country.code})</option>`).join("")}`;
		if ([...select.options].some((option) => option.value === current)) select.value = current;
	}
}

function geoLevel(value, maximum) {
	if (value <= 0 || maximum <= 0) return 0;
	return Math.max(1, Math.min(5, Math.ceil((Math.log1p(value) / Math.log1p(maximum)) * 5)));
}

function positionGeoTooltip(event, content) {
	const tooltip = byId("geoTooltip");
	const wrapper = tooltip.parentElement;
	const rect = wrapper.getBoundingClientRect();
	tooltip.innerHTML = content;
	tooltip.classList.remove("hidden");
	const x = event?.clientX ? event.clientX - rect.left + 12 : 16;
	const y = event?.clientY ? event.clientY - rect.top + 12 : 16;
	tooltip.style.left = `${Math.min(Math.max(8, x), Math.max(8, rect.width - 190))}px`;
	tooltip.style.top = `${Math.min(Math.max(8, y), Math.max(8, rect.height - 70))}px`;
}

function hideGeoTooltip() {
	byId("geoTooltip").classList.add("hidden");
}

function parseGeoViewBox(svg) {
	const [x, y, width, height] = (svg.getAttribute("viewBox") ?? "0 0 1010 666").split(/\s+/).map(Number);
	return { x, y, width, height };
}

function clampGeoZoom() {
	const { base, current } = geoZoom;
	current.width = Math.min(base.width, Math.max(base.width / GEO_ZOOM_MAX_SCALE, current.width));
	current.height = current.width * (base.height / base.width);
	current.x = Math.min(base.x + base.width - current.width, Math.max(base.x, current.x));
	current.y = Math.min(base.y + base.height - current.height, Math.max(base.y, current.y));
}

function applyGeoZoom() {
	const { base, current } = geoZoom;
	byId("geoMap").setAttribute("viewBox", `${current.x} ${current.y} ${current.width} ${current.height}`);
	const zoomed = current.width < base.width - 0.5;
	byId("geoMapWrap").classList.toggle("geo-zoomed", zoomed);
	byId("geoZoomOut").disabled = !zoomed;
	byId("geoZoomReset").disabled = !zoomed;
	byId("geoZoomIn").disabled = current.width <= base.width / GEO_ZOOM_MAX_SCALE + 0.5;
}

function zoomGeoMapAt(clientX, clientY, factor) {
	const svg = byId("geoMap");
	const rect = svg.getBoundingClientRect();
	if (!rect.width || !rect.height) return;
	const { current } = geoZoom;
	const pointX = current.x + ((clientX - rect.left) / rect.width) * current.width;
	const pointY = current.y + ((clientY - rect.top) / rect.height) * current.height;
	const newWidth = current.width * factor;
	const scaleChange = newWidth / current.width;
	current.width = newWidth;
	current.height = newWidth * (geoZoom.base.height / geoZoom.base.width);
	current.x = pointX - (pointX - current.x) * scaleChange;
	current.y = pointY - (pointY - current.y) * scaleChange;
	clampGeoZoom();
	applyGeoZoom();
}

function panGeoMap(deltaClientX, deltaClientY) {
	const svg = byId("geoMap");
	const rect = svg.getBoundingClientRect();
	if (!rect.width || !rect.height) return;
	const { current } = geoZoom;
	current.x -= (deltaClientX / rect.width) * current.width;
	current.y -= (deltaClientY / rect.height) * current.height;
	clampGeoZoom();
	applyGeoZoom();
}

function resetGeoZoom() {
	geoZoom.current = { ...geoZoom.base };
	applyGeoZoom();
}

function setupGeoMapZoom(svg) {
	geoZoom = { base: parseGeoViewBox(svg), current: parseGeoViewBox(svg) };
	applyGeoZoom();

	const wrap = byId("geoMapWrap");
	wrap.addEventListener(
		"wheel",
		(event) => {
			event.preventDefault();
			zoomGeoMapAt(event.clientX, event.clientY, event.deltaY < 0 ? 0.85 : 1 / 0.85);
		},
		{ passive: false },
	);

	let dragPointerId = null;
	let lastX = 0;
	let lastY = 0;
	svg.addEventListener("pointerdown", (event) => {
		if (event.button !== 0) return;
		dragPointerId = event.pointerId;
		lastX = event.clientX;
		lastY = event.clientY;
		svg.setPointerCapture(dragPointerId);
	});
	svg.addEventListener("pointermove", (event) => {
		if (event.pointerId !== dragPointerId) return;
		const deltaX = event.clientX - lastX;
		const deltaY = event.clientY - lastY;
		if (Math.abs(deltaX) < 1 && Math.abs(deltaY) < 1) return;
		hideGeoTooltip();
		panGeoMap(deltaX, deltaY);
		lastX = event.clientX;
		lastY = event.clientY;
	});
	const endGeoDrag = (event) => {
		if (event.pointerId !== dragPointerId) return;
		if (svg.hasPointerCapture(dragPointerId)) svg.releasePointerCapture(dragPointerId);
		dragPointerId = null;
	};
	svg.addEventListener("pointerup", endGeoDrag);
	svg.addEventListener("pointercancel", endGeoDrag);
	svg.addEventListener("dblclick", (event) => {
		event.preventDefault();
		zoomGeoMapAt(event.clientX, event.clientY, event.shiftKey ? 2 : 0.5);
	});

	byId("geoZoomIn").addEventListener("click", () => {
		const rect = svg.getBoundingClientRect();
		zoomGeoMapAt(rect.left + rect.width / 2, rect.top + rect.height / 2, 0.7);
	});
	byId("geoZoomOut").addEventListener("click", () => {
		const rect = svg.getBoundingClientRect();
		zoomGeoMapAt(rect.left + rect.width / 2, rect.top + rect.height / 2, 1 / 0.7);
	});
	byId("geoZoomReset").addEventListener("click", resetGeoZoom);
}

function renderGeoMap() {
	if (!geoMapGeometry) return;
	const mode = byId("geoMetricMode").value;
	const items = geoData[mode] ?? [];
	const values = new Map(items.map((item) => [String(item.countryCode).toUpperCase(), Number(item.count)]));
	const maximum = Math.max(0, ...items.filter((item) => item.countryCode !== "ZZ" && item.countryCode !== "XX").map((item) => Number(item.count)));
	const total = items.reduce((sum, item) => sum + Number(item.count), 0);
	const bandwidth = mode === "bandwidth";
	const title =
		mode === "active"
			? "Active connections"
			: mode === "events"
				? "Connections in traffic log"
				: mode === "blocked"
					? "Blocked connections"
					: "Proxied bandwidth";
	const unit = bandwidth ? "bytes" : mode === "active" ? "active connections" : mode === "blocked" ? "blocked connections" : "connections";
	const formatValue = bandwidth ? formatBytes : formatNumber;
	const rangeLabel = mode === "active" ? "live" : rangeDurationLabel(rangeTo - rangeFrom);
	byId("geoSubtitle").textContent = `${title} by country (${rangeLabel})`;
	byId("geoTotal").textContent = bandwidth ? formatBytes(total) : `${formatNumber(total)} ${unit}`;

	const svg = byId("geoMap");
	svg.setAttribute("aria-label", `World map showing ${unit} by country`);
	for (const [code, path] of geoMapGeometry.paths) {
		const value = values.get(code) ?? 0;
		const name = path.dataset.name ?? countryDisplayName(code);
		path.setAttribute("class", `geo-country geo-level-${geoLevel(value, maximum)}`);
		path.setAttribute("tabindex", value > 0 ? "0" : "-1");
		path.setAttribute("aria-label", `${name}: ${formatValue(value)}${bandwidth ? "" : ` ${unit}`}`);
		path.dataset.value = String(value);
		path.dataset.unit = unit;
		path.dataset.bandwidth = bandwidth ? "true" : "false";
	}

	const sorted = [...items].sort((left, right) => Number(right.count) - Number(left.count));
	byId("geoCountryList").innerHTML = sorted.length
		? sorted
				.slice(0, 10)
				.map((item) => {
					const code = String(item.countryCode).toUpperCase();
					const percentage = total > 0 ? (Number(item.count) / total) * 100 : 0;
					return `<div class="geo-country-row"><div class="row between"><span><code>${escapeHtml(code)}</code> ${escapeHtml(countryDisplayName(code))}</span><strong>${formatValue(item.count)}</strong></div><div class="breakdown-track"><div style="width:${Math.max(1, percentage)}%"></div></div></div>`;
				})
				.join("")
		: '<p class="muted">No geographic data is available for this view.</p>';

	if (!geoStatus?.enabled) {
		byId("geoMapStatus").textContent = "GeoIP is disabled.";
		byId("geoMapStatus").classList.remove("hidden");
	} else if (!geoStatus.available) {
		byId("geoMapStatus").textContent = geoStatus.error ?? "GeoIP database is unavailable.";
		byId("geoMapStatus").classList.remove("hidden");
	} else {
		byId("geoMapStatus").classList.add("hidden");
	}
}

async function loadGeoMapGeometry() {
	if (geoMapGeometry) return;
	const response = await fetch("/_burrowgate/static/world.svg?v=2.0.0", { cache: "force-cache" });
	if (!response.ok) throw new Error("Unable to load world map");
	const documentNode = new DOMParser().parseFromString(await response.text(), "image/svg+xml");
	const sourceRoot = documentNode.documentElement;
	if (sourceRoot.nodeName.toLowerCase() === "parsererror") throw new Error("Invalid world map SVG");

	const svg = byId("geoMap");
	svg.setAttribute("viewBox", sourceRoot.getAttribute("viewBox") ?? "0 0 1010 666");
	svg.setAttribute("preserveAspectRatio", "xMidYMid meet");
	const fragment = document.createDocumentFragment();
	const paths = new Map();
	for (const sourcePath of sourceRoot.querySelectorAll("path")) {
		const code = String(sourcePath.id ?? "").toUpperCase();
		const data = sourcePath.getAttribute("d") ?? "";
		if (!code || !data) continue;
		const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
		path.setAttribute("d", data);
		path.setAttribute("class", "geo-country geo-level-0");
		path.setAttribute("tabindex", "-1");
		path.dataset.code = code;
		path.dataset.name = countryDisplayName(code, sourcePath.getAttribute("aria-label") ?? code);
		path.dataset.value = "0";
		path.dataset.unit = "connections";
		path.dataset.bandwidth = "false";
		const show = (event) =>
			positionGeoTooltip(
				event,
				`<strong>${escapeHtml(path.dataset.name)}</strong><span>${path.dataset.bandwidth === "true" ? formatBytes(path.dataset.value) : `${formatNumber(path.dataset.value)} ${escapeHtml(path.dataset.unit)}`}</span>`,
			);
		path.addEventListener("pointerenter", show);
		path.addEventListener("pointermove", show);
		path.addEventListener("pointerleave", hideGeoTooltip);
		path.addEventListener("focus", show);
		path.addEventListener("blur", hideGeoTooltip);
		paths.set(code, path);
		fragment.append(path);
	}
	svg.replaceChildren(fragment);
	geoMapGeometry = { paths };
	populateCountrySelects();
	setupGeoMapZoom(svg);
}

function updatePagination(prefix, result, load) {
	byId(`${prefix}Summary`).textContent = result.total
		? `${(result.page - 1) * result.pageSize + 1}-${Math.min(result.page * result.pageSize, result.total)} of ${result.total}`
		: "No records";
	byId(`${prefix}Page`).textContent = `Page ${result.page} of ${result.totalPages}`;
	byId(`${prefix}Previous`).disabled = result.page <= 1;
	byId(`${prefix}Next`).disabled = result.page >= result.totalPages;
	byId(`${prefix}Previous`).onclick = () => {
		if (prefix === "events") eventPage -= 1;
		else if (prefix === "bandwidth") bandwidthPage -= 1;
		else tableState.rules.page -= 1;
		void load();
	};
	byId(`${prefix}Next`).onclick = () => {
		if (prefix === "events") eventPage += 1;
		else if (prefix === "bandwidth") bandwidthPage += 1;
		else tableState.rules.page += 1;
		void load();
	};
}

function eventsColumnCount() {
	return visibleColumnCount("events", 4);
}

async function loadEvents() {
	const state = tableState.events;
	byId("streamEvents").innerHTML = `<tr><td colspan="${eventsColumnCount()}" class="empty-cell"><span class="spinner"></span> Loading...</td></tr>`;
	const result = await api(
		`/streams/events?${queryString({ streamId: selectedStreamId, page: eventPage, pageSize, sortBy: state.sortBy, sortDirection: state.sortDirection, search: byId("eventSearch").value.trim(), protocol: byId("eventProtocol").value, eventType: byId("eventType").value, country: byId("eventCountry").value.trim().toUpperCase(), ...rangeQuery() })}`,
	);
	updateSortIndicators("panel-events", state);
	byId("streamEvents").innerHTML = result.items.length
		? result.items
				.map(
					(item) => `<tr>
          <td>${escapeHtml(formatDate(item.created_at))}</td>
          <td class="ip-cell"><code title="${item.client_ip ? escapeHtml(`${item.client_ip} (${countryDisplayName(item.country_code || "ZZ")})`) : ""}">${escapeHtml(item.client_ip || "-")}${item.client_port ? `:${item.client_port}` : ""}</code></td>
          ${isColumnVisible("events", "country") ? `<td>${countryBadge(item.country_code)}</td>` : ""}
          ${isColumnVisible("events", "event") ? `<td><span class="badge ${item.event_type.includes("error") || item.event_type === "blocked" ? "bad" : item.event_type === "throttled" || item.event_type === "monitored" ? "warn" : item.event_type === "connected" ? "ok" : "info"}">${escapeHtml(item.event_type)}</span></td>` : ""}
          <td class="protocol-column"><span class="protocol-badge">${item.protocol.toUpperCase()}</span></td>
          <td class="port-column"><code>${item.incoming_port}</code></td>
          ${isColumnVisible("events", "reason") ? `<td class="reason-cell" title="${escapeHtml(item.reason || item.error || "")}">${escapeHtml(item.reason || item.error || "-")}</td>` : ""}
          ${isColumnVisible("events", "rule") ? `<td>${item.protection_rule_id ? `<code>${escapeHtml(item.protection_rule_id)}</code>` : "-"}</td>` : ""}
          ${isColumnVisible("events", "toOrigin") ? `<td>${formatBytes(item.client_to_upstream_bytes)}</td>` : ""}
          ${isColumnVisible("events", "toClient") ? `<td>${formatBytes(item.upstream_to_client_bytes)}</td>` : ""}
          ${isColumnVisible("events", "connectionId") ? `<td>${item.connection_id ? `<code>${escapeHtml(item.connection_id)}</code>` : "-"}</td>` : ""}
        </tr>`,
				)
				.join("")
		: `<tr><td colspan="${eventsColumnCount()}" class="empty-cell">No stream events match these filters.</td></tr>`;
	updatePagination("events", result, loadEvents);
	updateEventsColumnVisibility();
}

function updateEventsColumnVisibility() {
	const stream = streams.find((item) => item.id === selectedStreamId);
	const singleStreamSelected = Boolean(selectedStreamId);
	const singleProtocol = singleStreamSelected && stream ? stream.tcpEnabled !== stream.udpEnabled : false;
	const wrap = byId("streamEvents").closest(".table-wrap");
	wrap.classList.toggle("hide-port-column", singleStreamSelected);
	wrap.classList.toggle("hide-protocol-column", singleProtocol);
	byId("eventProtocolFilter").classList.toggle("hidden", singleProtocol);
}

function streamsBandwidthColumnCount() {
	return visibleColumnCount("bandwidth", 2);
}

async function loadBandwidth() {
	const state = tableState.bandwidth;
	byId("streamBandwidth").innerHTML =
		`<tr><td colspan="${streamsBandwidthColumnCount()}" class="empty-cell"><span class="spinner"></span> Loading...</td></tr>`;
	const result = await api(
		`/streams/bandwidth?${queryString({ streamId: selectedStreamId, page: bandwidthPage, pageSize, sortBy: state.sortBy, sortDirection: state.sortDirection, search: byId("bandwidthSearch").value.trim(), protocol: byId("bandwidthProtocol").value, country: byId("bandwidthCountry").value.trim().toUpperCase(), ...rangeQuery() })}`,
	);
	updateSortIndicators("panel-bandwidth", state);
	byId("streamBandwidth").innerHTML = result.items.length
		? result.items
				.map(
					(item) => `<tr>
          <td class="ip-cell"><code title="${escapeHtml(`${item.ip} (${countryDisplayName(item.country_code || "ZZ")})`)}">${escapeHtml(item.ip)}</code></td>
          ${isColumnVisible("bandwidth", "country") ? `<td>${countryBadge(item.country_code)}</td>` : ""}
          <td class="port-column"><code>${item.incoming_port}</code></td>
          ${isColumnVisible("bandwidth", "toOrigin") ? `<td>${formatBytes(item.client_to_upstream_bytes)}</td>` : ""}
          ${isColumnVisible("bandwidth", "toClient") ? `<td>${formatBytes(item.upstream_to_client_bytes)}</td>` : ""}
          ${isColumnVisible("bandwidth", "total") ? `<td><strong>${formatBytes(item.total_bytes)}</strong></td>` : ""}
        </tr>`,
				)
				.join("")
		: `<tr><td colspan="${streamsBandwidthColumnCount()}" class="empty-cell">No stream bandwidth matches these filters.</td></tr>`;
	updatePagination("bandwidth", result, loadBandwidth);
	updateBandwidthColumnVisibility();
}

function updateBandwidthColumnVisibility() {
	const wrap = byId("streamBandwidth").closest(".table-wrap");
	wrap.classList.toggle("hide-port-column", Boolean(selectedStreamId));
}

function updateBulkDeleteStreamRulesButton() {
	const button = byId("bulkDeleteStreamRules");
	button.disabled = selectedStreamRuleIds.size === 0;
	button.textContent = `Delete selected (${selectedStreamRuleIds.size})`;
	const rowCheckboxes = [...document.querySelectorAll("#streamRules .rule-select")];
	const selectAll = byId("streamRulesSelectAll");
	const selectedOnPage = rowCheckboxes.filter((checkbox) => selectedStreamRuleIds.has(checkbox.dataset.ruleId));
	selectAll.checked = rowCheckboxes.length > 0 && selectedOnPage.length === rowCheckboxes.length;
	selectAll.indeterminate = selectedOnPage.length > 0 && selectedOnPage.length < rowCheckboxes.length;
}

function renderStreamCountryRulesTable() {
	const body = byId("streamCountryRules");
	if (!rulesStreamId) {
		body.innerHTML = '<tr><td colspan="7" class="empty-cell">Select a stream before adding country rules.</td></tr>';
		return;
	}
	if (streamCountryRules.length === 0) {
		body.innerHTML = '<tr><td colspan="7" class="empty-cell">No country rules are configured.</td></tr>';
		return;
	}
	body.innerHTML = streamCountryRules
		.map((rule) => {
			const currentState = ruleState(rule);
			const code = String(rule.country_code || "ZZ").toUpperCase();
			return `<tr class="rule-row ${currentState}">
      <td><span class="badge ${currentState === "active" ? "ok" : "warn"}">${currentState}</span></td>
      <td>${escapeHtml(code)} <span class="muted">${escapeHtml(countryDisplayName(code))}</span></td>
      <td><span class="badge action-${escapeHtml(rule.action)}">${escapeHtml(streamActionLabel(rule.action))}</span></td>
      <td title="${escapeHtml(rule.reason)}">${escapeHtml(truncate(rule.reason || "-", 56))}</td>
      <td>${escapeHtml(formatDate(rule.created_at))}</td>
      <td>${rule.expires_at === null ? "Never" : escapeHtml(formatDate(rule.expires_at))}</td>
      <td><button class="button danger compact" data-stream-country-rule-id="${escapeHtml(rule.id)}">Delete</button></td>
    </tr>`;
		})
		.join("");
}

function applyStreamNetworkPolicy(policy) {
	byId("streamDefaultIpAction").value = policy.defaultIpAction ?? "inherit";
	byId("streamDefaultCountryAction").value = policy.defaultCountryAction ?? "inherit";
	streamCountryRules = policy.countryRules ?? [];
	const warning = byId("streamGeoPolicyWarning");
	if (!policy.geoip?.enabled) {
		warning.textContent = "GeoIP is disabled. Country rules are stored but not enforced until GeoIP is enabled.";
		warning.classList.remove("hidden");
	} else if (!policy.geoip.available) {
		warning.textContent = policy.geoip.error || "The GeoIP database is unavailable. Country policy fails open until it becomes available.";
		warning.classList.remove("hidden");
	} else {
		warning.classList.add("hidden");
	}
	renderStreamCountryRulesTable();
}

function streamRulesColumnCount() {
	return visibleColumnCount("rules", 5);
}

async function loadStreamRules() {
	const state = tableState.rules;
	selectedStreamRuleIds.clear();
	updateBulkDeleteStreamRulesButton();
	const disabled = !rulesStreamId;
	byId("saveStreamNetworkDefaults").disabled = disabled;
	if (disabled) {
		byId("streamRules").innerHTML = `<tr><td colspan="${streamRulesColumnCount()}" class="empty-cell">Create a stream before adding network rules.</td></tr>`;
		byId("streamCountryRules").innerHTML = '<tr><td colspan="7" class="empty-cell">Create a stream before adding network rules.</td></tr>';
		return;
	}
	setTableLoading("streamRules", streamRulesColumnCount());
	setTableLoading("streamCountryRules", 7);
	updateSortIndicators("panel-rules", state);
	try {
		const [result, networkPolicy] = await Promise.all([
			api(
				`/streams/ip-rules?${queryString({
					streamId: rulesStreamId,
					page: state.page,
					pageSize: state.pageSize,
					sortBy: state.sortBy,
					sortDirection: state.sortDirection,
					search: byId("streamRuleSearch").value.trim(),
					action: byId("streamRuleAction").value,
					state: byId("streamRuleState").value,
				})}`,
			),
			api(`/streams/network-policy?${queryString({ streamId: rulesStreamId })}`),
		]);
		applyStreamNetworkPolicy(networkPolicy);
		if (result.page > result.totalPages) {
			state.page = result.totalPages;
			return await loadStreamRules();
		}
		byId("streamRules").innerHTML = result.items.length
			? result.items
					.map((rule) => {
						const currentState = ruleState(rule);
						return `<tr class="rule-row ${currentState}">
          <td><input type="checkbox" class="rule-select" data-rule-id="${escapeHtml(rule.id)}"></td>
          <td><span class="badge ${currentState === "active" ? "ok" : "warn"}">${currentState}</span></td>
          <td class="ip-cell"><code>${escapeHtml(rule.network_cidr)}</code></td>
          <td><span class="badge action-${escapeHtml(rule.action)}">${escapeHtml(streamActionLabel(rule.action))}</span></td>
          ${isColumnVisible("rules", "reason") ? `<td title="${escapeHtml(rule.reason)}">${escapeHtml(truncate(rule.reason || "-", 56))}</td>` : ""}
          ${isColumnVisible("rules", "created") ? `<td>${escapeHtml(formatDate(rule.created_at))}</td>` : ""}
          ${isColumnVisible("rules", "expires") ? `<td>${rule.expires_at === null ? "Never" : escapeHtml(formatDate(rule.expires_at))}</td>` : ""}
          <td><button class="button danger compact" data-stream-rule-id="${escapeHtml(rule.id)}">Delete</button></td>
        </tr>`;
					})
					.join("")
			: `<tr><td colspan="${streamRulesColumnCount()}" class="empty-cell">No IP rules match these filters.</td></tr>`;
		updatePagination("streamRules", result, loadStreamRules);
	} catch (error) {
		setTableError("streamRules", streamRulesColumnCount(), error);
		setTableError("streamCountryRules", 7, error);
	}
}

async function saveStreamNetworkDefaults() {
	const result = await api(`/streams/network-policy?${queryString({ streamId: rulesStreamId })}`, {
		method: "PUT",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({
			defaultIpAction: byId("streamDefaultIpAction").value,
			defaultCountryAction: byId("streamDefaultCountryAction").value,
		}),
	});
	const stream = streams.find((item) => item.id === rulesStreamId);
	if (stream) {
		stream.defaultIpAction = result.defaultIpAction;
		stream.defaultCountryAction = result.defaultCountryAction;
	}
	showToast("Default network actions saved.");
}

function renderProtectionCatalog(enabledIds) {
	const container = byId("protectionCatalogList");
	if (protectionCatalog.length === 0) {
		container.innerHTML = '<p class="muted">No stream-protection rulesets are loaded.</p>';
		return;
	}
	const enabled = new Set(enabledIds);
	container.innerHTML = protectionCatalog
		.map(
			(ruleset) =>
				`<label class="check-row compact-check"><input type="checkbox" class="protection-ruleset-checkbox" value="${escapeHtml(ruleset.id)}"${enabled.has(ruleset.id) ? " checked" : ""}><span><strong>${escapeHtml(ruleset.title)}</strong><small class="muted">${escapeHtml(ruleset.id)} | ${escapeHtml(ruleset.version)} | ${escapeHtml(ruleset.protocol)}${ruleset.description ? ` | ${escapeHtml(ruleset.description)}` : ""}</small></span></label>`,
		)
		.join("");
}

async function loadProtectionCatalog(enabledIds) {
	const result = await api("/streams/protection-catalog");
	protectionCatalog = result.items;
	renderProtectionCatalog(enabledIds);
}

function selectedProtectionRulesetIds() {
	return [...document.querySelectorAll(".protection-ruleset-checkbox:checked")].map((checkbox) => checkbox.value);
}

async function loadStreamProtection() {
	if (!protectionStreamId) {
		byId("saveStreamProtection").disabled = true;
		byId("protectionCatalogList").innerHTML = '<p class="muted">Create a stream before configuring protection.</p>';
		return;
	}
	byId("saveStreamProtection").disabled = false;
	const policy = await api(`/streams/protection-policy?${queryString({ streamId: protectionStreamId })}`);
	byId("streamProtectionMode").value = policy.mode;
	byId("streamProtectionExcludedRules").value = (policy.excludedRuleIds ?? []).join("\n");
	byId("streamProtectionBanLow").value = String(policy.banDurations?.low ?? 0);
	byId("streamProtectionBanMedium").value = String(policy.banDurations?.medium ?? 600);
	byId("streamProtectionBanHigh").value = String(policy.banDurations?.high ?? 3600);
	byId("streamProtectionBanCritical").value = String(policy.banDurations?.critical ?? 86400);
	await loadProtectionCatalog(policy.rulesetIds ?? []);
}

async function saveStreamProtection() {
	if (!protectionStreamId) return;
	try {
		await api(`/streams/protection-policy?${queryString({ streamId: protectionStreamId })}`, {
			method: "PUT",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				mode: byId("streamProtectionMode").value,
				rulesetIds: selectedProtectionRulesetIds(),
				excludedRuleIds: byId("streamProtectionExcludedRules").value.trim(),
				banDurations: {
					low: Number(byId("streamProtectionBanLow").value),
					medium: Number(byId("streamProtectionBanMedium").value),
					high: Number(byId("streamProtectionBanHigh").value),
					critical: Number(byId("streamProtectionBanCritical").value),
				},
			}),
		});
		showToast("Protection settings saved.");
	} catch (error) {
		showToast(error.message, "bad");
	}
}

function streamHealthOf(streamId) {
	return streams.find((stream) => stream.id === streamId) ?? null;
}

function loadStreamHealth() {
	const stream = streamHealthOf(healthStreamId);
	const canCheck = Boolean(stream?.tcpEnabled);
	byId("streamHealthTcpNotice").classList.toggle("hidden", !stream || canCheck);
	byId("streamHealthSettings").classList.toggle("hidden", !canCheck);
	byId("saveStreamHealth").disabled = !canCheck;
	if (!stream) return;
	byId("streamHealthEnabled").checked = Boolean(stream.originHealthCheck?.enabled);
	byId("streamHealthInterval").value = String(stream.originHealthCheck?.intervalSeconds ?? 30);
	byId("streamHealthTimeout").value = String(stream.originHealthCheck?.timeoutMs ?? 3_000);
	byId("streamHealthFailureThreshold").value = String(stream.originHealthCheck?.failureThreshold ?? 3);
	byId("streamHealthRecoveryThreshold").value = String(stream.originHealthCheck?.recoveryThreshold ?? 2);
	updateStreamHealthDetectionNotice();
}

const HEALTH_DETECTION_WARNING_SECONDS = 15;

function updateStreamHealthDetectionNotice() {
	const interval = Number(byId("streamHealthInterval").value);
	const threshold = Number(byId("streamHealthFailureThreshold").value);
	const notice = byId("streamHealthDetectionNotice");
	const detectionSeconds = interval * threshold;
	if (interval > 0 && threshold > 0 && detectionSeconds < HEALTH_DETECTION_WARNING_SECONDS) {
		notice.textContent = `With this interval and failure threshold, an incident opens after only ${detectionSeconds}s of continuous failures - a brief network blip could trigger a false alert. Consider a higher failure threshold.`;
		notice.classList.remove("hidden");
	} else {
		notice.classList.add("hidden");
	}
}

async function saveStreamHealth() {
	if (!healthStreamId) return;
	try {
		const updated = await api(`/streams/${encodeURIComponent(healthStreamId)}`, {
			method: "PUT",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				originHealthCheckEnabled: byId("streamHealthEnabled").checked,
				originHealthCheckIntervalSeconds: Number(byId("streamHealthInterval").value),
				originHealthCheckTimeoutMs: Number(byId("streamHealthTimeout").value),
				originHealthCheckFailureThreshold: Number(byId("streamHealthFailureThreshold").value),
				originHealthCheckRecoveryThreshold: Number(byId("streamHealthRecoveryThreshold").value),
			}),
		});
		const index = streams.findIndex((stream) => stream.id === healthStreamId);
		if (index >= 0) streams[index] = updated.stream;
		showToast("Health-check settings saved.");
	} catch (error) {
		showToast(error.message, "bad");
	}
}

function writeStreamBandwidthLimitProtocol(prefix, limit) {
	byId(`streamBandwidthLimit${prefix}Enabled`).checked = !!limit?.enabled;
	byId(`streamBandwidthLimit${prefix}MaxMiB`).value = String(bytesToMib(limit?.maxBytes ?? DEFAULT_BANDWIDTH_LIMIT.maxBytes));
	byId(`streamBandwidthLimit${prefix}WindowSeconds`).value = String(limit?.windowSeconds ?? DEFAULT_BANDWIDTH_LIMIT.windowSeconds);
	byId(`streamBandwidthLimit${prefix}BanSeconds`).value = String(limit?.banSeconds ?? DEFAULT_BANDWIDTH_LIMIT.banSeconds);
}

function readStreamBandwidthLimitProtocol(prefix) {
	return {
		enabled: byId(`streamBandwidthLimit${prefix}Enabled`).checked,
		maxBytes: mibToBytes(Number(byId(`streamBandwidthLimit${prefix}MaxMiB`).value)),
		windowSeconds: Number(byId(`streamBandwidthLimit${prefix}WindowSeconds`).value),
		banSeconds: Number(byId(`streamBandwidthLimit${prefix}BanSeconds`).value),
	};
}

async function loadStreamBandwidthLimit() {
	if (!protectionStreamId) {
		byId("saveStreamBandwidthLimit").disabled = true;
		return;
	}
	byId("saveStreamBandwidthLimit").disabled = false;
	const policy = await api(`/streams/bandwidth-limit-policy?${queryString({ streamId: protectionStreamId })}`);
	writeStreamBandwidthLimitProtocol("Tcp", policy.tcp);
	writeStreamBandwidthLimitProtocol("Udp", policy.udp);
}

async function saveStreamBandwidthLimit() {
	if (!protectionStreamId) return;
	try {
		await api(`/streams/bandwidth-limit-policy?${queryString({ streamId: protectionStreamId })}`, {
			method: "PUT",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				tcp: readStreamBandwidthLimitProtocol("Tcp"),
				udp: readStreamBandwidthLimitProtocol("Udp"),
			}),
		});
		showToast("Bandwidth limit settings saved.");
	} catch (error) {
		showToast(error.message, "bad");
	}
}

async function addStreamIpRule(event) {
	event.preventDefault();
	if (!rulesStreamId) return;
	const form = event.currentTarget;
	const data = new FormData(form);
	const expiresAtValue = data.get("expiresAt");
	try {
		await api(`/streams/ip-rules?${queryString({ streamId: rulesStreamId })}`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				networkCidr: data.get("networkCidr").trim(),
				action: data.get("action"),
				reason: data.get("reason").trim(),
				expiresAt: expiresAtValue ? new Date(expiresAtValue).getTime() : null,
			}),
		});
		form.reset();
		showToast("IP rule added.");
		tableState.rules.page = 1;
		await loadStreamRules();
	} catch (error) {
		showToast(error.message, "bad");
	}
}

async function addStreamCountryRuleFromForm(event) {
	event.preventDefault();
	if (!rulesStreamId) return;
	const form = event.currentTarget;
	const data = new FormData(form);
	const expiresAtValue = data.get("expiresAt");
	try {
		await api(`/streams/country-rules?${queryString({ streamId: rulesStreamId })}`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				countryCode: data.get("countryCode"),
				action: data.get("action"),
				reason: data.get("reason").trim(),
				expiresAt: expiresAtValue ? new Date(expiresAtValue).getTime() : null,
			}),
		});
		form.reset();
		showToast("Country rule added.");
		await loadStreamRules();
	} catch (error) {
		showToast(error.message, "bad");
	}
}

async function deleteStreamIpRule(id) {
	if (!rulesStreamId || !confirm("Delete this IP rule?")) return;
	try {
		await api(`/streams/ip-rules/${id}?${queryString({ streamId: rulesStreamId })}`, { method: "DELETE" });
		showToast("IP rule deleted.");
		await loadStreamRules();
	} catch (error) {
		showToast(error.message, "bad");
	}
}

async function deleteStreamCountryRule(id) {
	if (!rulesStreamId || !confirm("Delete this country rule?")) return;
	try {
		await api(`/streams/country-rules/${id}?${queryString({ streamId: rulesStreamId })}`, { method: "DELETE" });
		showToast("Country rule deleted.");
		await loadStreamRules();
	} catch (error) {
		showToast(error.message, "bad");
	}
}

async function bulkDeleteStreamIpRules() {
	if (!rulesStreamId || selectedStreamRuleIds.size === 0) return;
	if (!confirm(`Delete ${selectedStreamRuleIds.size} selected IP rule(s)?`)) return;
	try {
		await api(`/streams/ip-rules/bulk-delete?${queryString({ streamId: rulesStreamId })}`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ ids: [...selectedStreamRuleIds] }),
		});
		showToast("Selected IP rules deleted.");
		await loadStreamRules();
	} catch (error) {
		showToast(error.message, "bad");
	}
}

function updateProtocolControls() {
	const valid = byId("streamTcp").checked || byId("streamUdp").checked;
	byId("streamProtocolError").classList.toggle("hidden", valid);
	byId("saveStream").disabled = !valid;
	byId("streamCertificate").disabled = !byId("streamTcp").checked;
	if (!byId("streamTcp").checked) byId("streamCertificate").value = "";
	const proxyV1Option = byId("streamProxyProtocol").querySelector('option[value="v1"]');
	proxyV1Option.disabled = !byId("streamTcp").checked;
	if (!byId("streamTcp").checked && byId("streamProxyProtocol").value === "v1") byId("streamProxyProtocol").value = "disabled";
	const rateEnabled = byId("streamRateLimitEnabled").checked;
	byId("streamRateLimitSettings").classList.toggle("hidden", !rateEnabled);
	const algorithm = byId("streamRateLimitAlgorithm").value;
	document.querySelectorAll("#streamRateLimitSettings .token-setting").forEach((element) => element.classList.toggle("hidden", algorithm !== "token-bucket"));
	document.querySelectorAll("#streamRateLimitSettings .window-setting").forEach((element) => element.classList.toggle("hidden", algorithm === "token-bucket"));
	document
		.querySelectorAll("#streamRateLimitSettings .precision-setting")
		.forEach((element) => element.classList.toggle("hidden", algorithm !== "sliding-window"));
}

function resetForm() {
	byId("streamForm").reset();
	byId("streamId").value = "";
	byId("streamFormTitle").textContent = "Create stream";
	byId("saveStream").textContent = "Create";
	byId("cancelStreamEdit").classList.add("hidden");
	byId("streamTcp").checked = true;
	byId("streamUdp").checked = false;
	byId("streamProxyProtocol").value = "disabled";
	byId("streamRetentionDays").value = "7";
	byId("streamMaxConnectionsPerIp").value = "0";
	byId("streamRateLimitEnabled").checked = false;
	byId("streamRateLimitAlgorithm").value = "sliding-window";
	byId("streamRateLimitMax").value = "60";
	byId("streamRateLimitWindow").value = "60000";
	byId("streamRateLimitPrecision").value = "100";
	byId("streamRateLimitRefillRate").value = "10";
	byId("streamRateLimitRefillInterval").value = "1000";
	byId("streamUdpAmplificationMaxRatio").value = "0";
	updateProtocolControls();
}

function editStream(id) {
	const stream = streams.find((item) => item.id === id);
	if (!stream) return;
	byId("streamId").value = stream.id;
	byId("streamName").value = stream.name ?? "";
	byId("incomingPort").value = stream.incomingPort;
	byId("forwardHost").value = stream.forwardHost;
	byId("forwardPort").value = stream.forwardPort;
	byId("streamRetentionDays").value = stream.eventRetentionDays;
	byId("streamMaxConnectionsPerIp").value = stream.maxConnectionsPerIp ?? 0;
	const rateLimit = stream.connectionRateLimit ?? {};
	byId("streamRateLimitEnabled").checked = Boolean(rateLimit.enabled);
	byId("streamRateLimitAlgorithm").value = rateLimit.algorithm ?? "sliding-window";
	byId("streamRateLimitMax").value = String(rateLimit.max ?? 60);
	byId("streamRateLimitWindow").value = String(rateLimit.windowMs ?? 60000);
	byId("streamRateLimitPrecision").value = String(rateLimit.precisionMs ?? 100);
	byId("streamRateLimitRefillRate").value = String(rateLimit.refillRate ?? 10);
	byId("streamRateLimitRefillInterval").value = String(rateLimit.refillIntervalMs ?? 1000);
	byId("streamUdpAmplificationMaxRatio").value = String(stream.udpAmplificationMaxRatio ?? 0);
	byId("streamTcp").checked = stream.tcpEnabled;
	byId("streamUdp").checked = stream.udpEnabled;
	byId("streamProxyProtocol").value = stream.proxyProtocol ?? "disabled";
	byId("streamCertificate").value = stream.certificateId || "";
	byId("streamFormTitle").textContent = `Edit ${stream.name}`;
	byId("saveStream").textContent = "Save";
	byId("cancelStreamEdit").classList.remove("hidden");
	updateProtocolControls();
}

async function saveStream(event) {
	event.preventDefault();
	const id = byId("streamId").value;
	const payload = {
		name: byId("streamName").value.trim(),
		incomingPort: Number(byId("incomingPort").value),
		forwardHost: byId("forwardHost").value.trim(),
		forwardPort: Number(byId("forwardPort").value),
		tcpEnabled: byId("streamTcp").checked,
		udpEnabled: byId("streamUdp").checked,
		proxyProtocol: byId("streamProxyProtocol").value,
		certificateId: byId("streamCertificate").value || null,
		eventRetentionDays: Number(byId("streamRetentionDays").value),
		maxConnectionsPerIp: Number(byId("streamMaxConnectionsPerIp").value),
		connectionRateLimitEnabled: byId("streamRateLimitEnabled").checked,
		connectionRateLimitAlgorithm: byId("streamRateLimitAlgorithm").value,
		connectionRateLimitMax: Number(byId("streamRateLimitMax").value),
		connectionRateLimitWindowMs: Number(byId("streamRateLimitWindow").value),
		connectionRateLimitPrecisionMs: Number(byId("streamRateLimitPrecision").value),
		connectionRateLimitRefillRate: Number(byId("streamRateLimitRefillRate").value),
		connectionRateLimitRefillIntervalMs: Number(byId("streamRateLimitRefillInterval").value),
		udpAmplificationMaxRatio: Number(byId("streamUdpAmplificationMaxRatio").value),
	};
	try {
		await api(id ? `/streams/${id}` : "/streams", {
			method: id ? "PUT" : "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(payload),
		});
		showToast(id ? "Stream updated" : "Stream created");
		resetForm();
		await refreshDashboard();
		activeTab = "streams";
	} catch (error) {
		showToast(error.message, "bad");
	}
}

async function deleteStream(id) {
	const stream = streams.find((item) => item.id === id);
	if (
		!stream ||
		!confirm(
			`Delete the ${stream.tcpEnabled && stream.udpEnabled ? "TCP/UDP" : stream.tcpEnabled ? "TCP" : "UDP"} stream ${stream.name} (port ${stream.incomingPort})? Monitoring history for this stream will also be deleted.`,
		)
	)
		return;
	try {
		await api(`/streams/${id}`, { method: "DELETE" });
		if (selectedStreamId === id) selectedStreamId = "";
		showToast("Stream deleted");
		await refreshDashboard();
	} catch (error) {
		showToast(error.message, "bad");
	}
}

function setActiveTab(name) {
	activeTab = name;
	document.querySelectorAll(".tab").forEach((tab) => tab.classList.toggle("active", tab.dataset.tab === name));
	document.querySelectorAll(".tab-panel").forEach((panel) => panel.classList.add("hidden"));
	byId(`panel-${name}`).classList.remove("hidden");
	const geoMode = {
		connections: "active",
		events: "events",
		bandwidth: "bandwidth",
		rules: "blocked",
		protection: "blocked",
		health: "active",
		streams: "active",
	}[name];
	byId("geoMetricMode").value = geoMode;
	renderGeoMap();
	streamChartViewSelection = {
		connections: "connections:primary",
		events: "connections:primary",
		bandwidth: "bandwidth:primary",
		rules: "protection:primary",
		protection: "protection:primary",
		health: "health:primary",
		streams: "connections:primary",
	}[name];
	byId("streamChartView").value = streamChartViewSelection;
	renderStreamCharts();
	if (name === "events") void loadEvents();
	if (name === "bandwidth") void loadBandwidth();
	if (name === "connections") void loadConnections();
	if (name === "streams") void loadStreams();
	if (name === "rules") void loadStreamRules();
	if (name === "protection") {
		void loadStreamProtection();
		void loadStreamBandwidthLimit();
	}
	if (name === "health") loadStreamHealth();
}

async function refreshDashboard(updateLabel = "Updated") {
	try {
		if (!currentAdmin) await loadCurrentAdmin();
		await loadStreams();
		await Promise.all([loadOverview(), loadStreamMetrics(), loadStreamTopList()]);
		if (activeTab === "events") await loadEvents();
		if (activeTab === "bandwidth") await loadBandwidth();
		if (activeTab === "connections") await loadConnections();
		byId("lastUpdated").textContent = `${updateLabel} ${formatTime()}`;
	} catch (error) {
		showToast(error.message, "bad");
	}
}

function debounce(callback, delay = 300) {
	let timer;
	return (...args) => {
		clearTimeout(timer);
		timer = setTimeout(() => callback(...args), delay);
	};
}

initializeDateTimeFormat();
insertColumnsMenus({
	connections: "connectionsHeaderActions",
	events: "eventsHeaderActions",
	bandwidth: "bandwidthHeaderActions",
	rules: "rulesHeaderActions",
});
bindColumnsMenus();
initializeRange();
resetForm();

document.querySelectorAll(".tab").forEach((tab) => tab.addEventListener("click", () => setActiveTab(tab.dataset.tab)));
document.querySelectorAll(".sort-button").forEach((button) => {
	button.addEventListener("click", () => {
		const panel = button.closest(".tab-panel");
		const name = panel.id.replace("panel-", "");
		const state = tableState[name];
		if (!state) return;
		const sortBy = button.dataset.sort;
		if (state.sortBy === sortBy) state.sortDirection = state.sortDirection === "asc" ? "desc" : "asc";
		else {
			state.sortBy = sortBy;
			state.sortDirection = ["protocol", "clientIp", "client_ip", "ip", "countryCode", "country_code", "event_type", "reason"].includes(sortBy)
				? "asc"
				: "desc";
		}
		if (name === "connections") renderActive(activeConnections);
		if (name === "events") {
			eventPage = 1;
			void loadEvents();
		}
		if (name === "bandwidth") {
			bandwidthPage = 1;
			void loadBandwidth();
		}
		if (name === "rules") {
			state.page = 1;
			void loadStreamRules();
		}
	});
});
byId("geoMetricMode").addEventListener("change", renderGeoMap);
byId("streamChartView").addEventListener("change", (event) => {
	streamChartViewSelection = event.currentTarget.value;
	renderStreamCharts();
});
byId("streamTopListMode").addEventListener("change", (event) => {
	streamTopListScopeSelection = event.currentTarget.value;
	void loadStreamTopList();
});
byId("refreshDashboard").addEventListener("click", () => void refreshDashboard());
byId("refreshConnections").addEventListener("click", () => void loadConnections());
byId("refreshEvents").addEventListener("click", () => void loadEvents());
byId("refreshBandwidth").addEventListener("click", () => void loadBandwidth());
byId("streamSelector").addEventListener("change", () => {
	selectedStreamId = byId("streamSelector").value;
	eventPage = 1;
	bandwidthPage = 1;
	void refreshDashboard();
});
byId("dateTimeFormat").addEventListener("change", (event) => {
	saveDateTimeFormat(event.currentTarget.value);
	void refreshDashboard("Date format updated");
});
byId("applyDateRange").addEventListener("click", () => {
	const from = new Date(byId("dateFrom").value).getTime();
	const to = new Date(byId("dateTo").value).getTime();
	if (!Number.isFinite(from) || !Number.isFinite(to) || to - from < 60_000) return showToast("Select a valid range of at least one minute", "bad");
	void applyDateRangeValues(from, to);
});
byId("resetDateRange").addEventListener("click", () => {
	const to = Date.now();
	void applyDateRangeValues(to - 86_400_000, to, "Last 24 hours applied");
});
for (const id of ["streamTcp", "streamUdp", "incomingPort"]) byId(id).addEventListener("input", updateProtocolControls);
for (const id of ["streamRateLimitEnabled", "streamRateLimitAlgorithm"]) byId(id).addEventListener("change", updateProtocolControls);
byId("streamForm").addEventListener("submit", saveStream);
byId("newStream").addEventListener("click", resetForm);
byId("resetStreamForm").addEventListener("click", resetForm);
byId("cancelStreamEdit").addEventListener("click", resetForm);
byId("streamsList").addEventListener("click", (event) => {
	const edit = event.target.closest("[data-edit-stream]");
	const remove = event.target.closest("[data-delete-stream]");
	if (edit) editStream(edit.dataset.editStream);
	if (remove) void deleteStream(remove.dataset.deleteStream);
});
for (const [id, load] of [
	["eventSearch", loadEvents],
	["bandwidthSearch", loadBandwidth],
])
	byId(id).addEventListener(
		"input",
		debounce(() => {
			if (load === loadEvents) eventPage = 1;
			else bandwidthPage = 1;
			void load();
		}),
	);
for (const [id, load] of [
	["eventProtocol", loadEvents],
	["eventType", loadEvents],
	["eventCountry", loadEvents],
	["bandwidthProtocol", loadBandwidth],
	["bandwidthCountry", loadBandwidth],
])
	byId(id).addEventListener("change", () => {
		if (load === loadEvents) eventPage = 1;
		else bandwidthPage = 1;
		void load();
	});
byId("rulesStreamSelector").addEventListener("change", () => {
	rulesStreamId = byId("rulesStreamSelector").value;
	tableState.rules.page = 1;
	void loadStreamRules();
});
byId("saveStreamNetworkDefaults").addEventListener("click", () => void saveStreamNetworkDefaults());
byId("protectionStreamSelector").addEventListener("change", () => {
	protectionStreamId = byId("protectionStreamSelector").value;
	void loadStreamProtection();
	void loadStreamBandwidthLimit();
});
byId("refreshProtectionCatalog").addEventListener("click", () => void loadStreamProtection());
byId("saveStreamProtection").addEventListener("click", () => void saveStreamProtection());
byId("saveStreamBandwidthLimit").addEventListener("click", () => void saveStreamBandwidthLimit());
byId("healthStreamSelector").addEventListener("change", () => {
	healthStreamId = byId("healthStreamSelector").value;
	loadStreamHealth();
});
byId("saveStreamHealth").addEventListener("click", () => void saveStreamHealth());
byId("streamHealthInterval").addEventListener("input", updateStreamHealthDetectionNotice);
byId("streamHealthFailureThreshold").addEventListener("input", updateStreamHealthDetectionNotice);
byId("streamRuleForm").addEventListener("submit", addStreamIpRule);
byId("streamCountryRuleForm").addEventListener("submit", addStreamCountryRuleFromForm);
byId("refreshStreamRules").addEventListener("click", () => void loadStreamRules());
byId("bulkDeleteStreamRules").addEventListener("click", () => void bulkDeleteStreamIpRules());
byId("streamRulesSelectAll").addEventListener("change", (event) => {
	document.querySelectorAll("#streamRules .rule-select").forEach((checkbox) => {
		if (event.currentTarget.checked) selectedStreamRuleIds.add(checkbox.dataset.ruleId);
		else selectedStreamRuleIds.delete(checkbox.dataset.ruleId);
		checkbox.checked = event.currentTarget.checked;
	});
	updateBulkDeleteStreamRulesButton();
});
byId("streamRules").addEventListener("click", (event) => {
	const remove = event.target.closest("[data-stream-rule-id]");
	if (remove) void deleteStreamIpRule(remove.dataset.streamRuleId);
	const checkbox = event.target.closest(".rule-select");
	if (checkbox) {
		if (checkbox.checked) selectedStreamRuleIds.add(checkbox.dataset.ruleId);
		else selectedStreamRuleIds.delete(checkbox.dataset.ruleId);
		updateBulkDeleteStreamRulesButton();
	}
});
byId("streamCountryRules").addEventListener("click", (event) => {
	const remove = event.target.closest("[data-stream-country-rule-id]");
	if (remove) void deleteStreamCountryRule(remove.dataset.streamCountryRuleId);
});
byId("streamRuleSearch").addEventListener(
	"input",
	debounce(() => {
		tableState.rules.page = 1;
		void loadStreamRules();
	}),
);
for (const id of ["streamRuleAction", "streamRuleState", "streamRulePageSize"])
	byId(id).addEventListener("change", () => {
		if (id === "streamRulePageSize") tableState.rules.pageSize = Number(byId(id).value);
		tableState.rules.page = 1;
		void loadStreamRules();
	});
byId("logout").addEventListener("click", async () => {
	await api("/logout", { method: "POST" });
	location.href = "/_burrowgate/admin/login";
});

byId("openUsers").addEventListener("click", () => openModal("users"));
byId("openAudit").addEventListener("click", () => openModal("audit"));
byId("openAccount").addEventListener("click", () => openModal("account"));
byId("openSso").addEventListener("click", () => openModal("sso"));
byId("saveAdminSso").addEventListener("click", () => void saveAdminSso());
document.querySelectorAll(".modal-overlay").forEach((overlay) => {
	overlay.addEventListener("click", (event) => {
		if (event.target === overlay) closeModal(overlay.dataset.modal);
	});
	overlay.querySelector("[data-modal-close]").addEventListener("click", () => closeModal(overlay.dataset.modal));
});
document.addEventListener("keydown", (event) => {
	if (event.key === "Escape") closeAllModals();
});
byId("userForm").addEventListener("submit", createUser);
byId("refreshUsers").addEventListener("click", () => void loadUsers());
byId("closeUserPermissions").addEventListener("click", () => {
	editingPermissionsUserId = null;
	byId("userPermissionsCard").classList.add("hidden");
});
byId("saveUserPermissions").addEventListener("click", () => void saveUserPermissions());
byId("users").addEventListener("click", (event) => {
	const permissionsButton = event.target.closest("button[data-user-permissions]");
	if (permissionsButton) {
		openUserPermissions(permissionsButton.dataset.userPermissions);
		return;
	}
	const resetPasswordButton = event.target.closest("button[data-user-reset-password]");
	if (resetPasswordButton) {
		const password = prompt("New password for this user (minimum 8 characters):");
		if (!password) return;
		resetPasswordButton.disabled = true;
		api(`/users/${encodeURIComponent(resetPasswordButton.dataset.userResetPassword)}/reset-password`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ password }),
		})
			.then(() => showToast("Password reset. The user has been signed out everywhere."))
			.catch((error) => showToast(error.message, "bad"))
			.finally(() => {
				resetPasswordButton.disabled = false;
			});
		return;
	}
	const resetTotpButton = event.target.closest("button[data-user-reset-totp]");
	if (resetTotpButton) {
		if (!confirm("Reset two-factor authentication for this user? They will need to enroll again on next login.")) return;
		resetTotpButton.disabled = true;
		api(`/users/${encodeURIComponent(resetTotpButton.dataset.userResetTotp)}/totp/reset`, { method: "POST" })
			.then(() => {
				showToast("Two-factor authentication reset.");
				return loadUsers();
			})
			.catch((error) => {
				resetTotpButton.disabled = false;
				showToast(error.message, "bad");
			});
		return;
	}
	const deleteButton = event.target.closest("button[data-user-delete]");
	if (deleteButton) {
		if (!confirm("Delete this user? This cannot be undone.")) return;
		deleteButton.disabled = true;
		api(`/users/${encodeURIComponent(deleteButton.dataset.userDelete)}`, { method: "DELETE" })
			.then(() => {
				showToast("User deleted.");
				return loadUsers();
			})
			.catch((error) => {
				deleteButton.disabled = false;
				showToast(error.message, "bad");
			});
	}
});
byId("passwordForm").addEventListener("submit", changePassword);
byId("recoveryCodesForm").addEventListener("submit", regenerateRecoveryCodes);
byId("refreshAuditLog").addEventListener("click", () => void loadAuditLog());
byId("purgeAuditLog").addEventListener("click", () => void purgeAuditLog());
byId("auditSearch").addEventListener(
	"input",
	debounce(() => {
		tableState.auditLog.page = 1;
		void loadAuditLog();
	}),
);

window.addEventListener(
	"pagehide",
	() => {
		byId("streamTrafficChart").$dateRangeCleanup?.();
		streamTrafficChart?.destroy();
	},
	{ once: true },
);

void refreshDashboard();
setInterval(() => {
	if (document.visibilityState === "visible") void loadConnections();
}, 5_000);
