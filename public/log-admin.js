const ADMIN_API = "/_burrowgate/api/admin";
const mutationHeaders = { "x-burrowgate-admin": "1" };
const DATE_TIME_FORMAT_STORAGE_KEY = "burrowgate.admin.date-time-format";
const DATE_TIME_FORMATS = new Set(["iso-24", "dmy-24", "mdy-12", "browser"]);
const LEVELS = ["error", "warn", "audit", "info", "http", "debug", "verbose", "silly"];
const LEVEL_LABELS = { error: "Error", warn: "Warning", audit: "Audit", info: "Info", http: "HTTP", debug: "Debug", verbose: "Verbose", silly: "Silly" };
const LEVEL_COLORS = {
	error: "#f43f5e",
	warn: "#f59e0b",
	audit: "#a78bfa",
	info: "#22d3ee",
	http: "#22c55e",
	debug: "#64748b",
	verbose: "#94a3b8",
	silly: "#475569",
};

const byId = (id) => document.getElementById(id);
const escapeHtml = (value) =>
	String(value ?? "").replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);

function twoDigits(value) {
	return String(value).padStart(2, "0");
}

function formatNumber(value) {
	return Number(value ?? 0).toLocaleString();
}

function truncate(value, length = 120) {
	const text = String(value ?? "");
	return text.length > length ? `${text.slice(0, Math.max(0, length - 1))}…` : text;
}

function formatBytes(value) {
	const bytes = Math.max(0, Number(value ?? 0));
	if (!Number.isFinite(bytes) || bytes === 0) return "0 B";
	const units = ["B", "KiB", "MiB", "GiB", "TiB"];
	const index = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
	const scaled = bytes / 1024 ** index;
	return `${scaled >= 100 || index === 0 ? Math.round(scaled).toLocaleString() : scaled.toFixed(scaled >= 10 ? 1 : 2)} ${units[index]}`;
}

let dateTimeFormat = "iso-24";

function initializeDateTimeFormat() {
	try {
		const stored = localStorage.getItem(DATE_TIME_FORMAT_STORAGE_KEY);
		dateTimeFormat = stored && DATE_TIME_FORMATS.has(stored) ? stored : "iso-24";
	} catch {
		dateTimeFormat = "iso-24";
	}
	byId("dateTimeFormat").value = dateTimeFormat;
}

function saveDateTimeFormat(value) {
	dateTimeFormat = DATE_TIME_FORMATS.has(value) ? value : "iso-24";
	try {
		localStorage.setItem(DATE_TIME_FORMAT_STORAGE_KEY, dateTimeFormat);
	} catch {}
}

function formatDate(value) {
	const date = new Date(Number(value));
	if (Number.isNaN(date.getTime())) return "-";
	if (dateTimeFormat === "browser") return date.toLocaleString();
	const year = date.getFullYear();
	const month = twoDigits(date.getMonth() + 1);
	const day = twoDigits(date.getDate());
	const minutes = twoDigits(date.getMinutes());
	const seconds = twoDigits(date.getSeconds());
	if (dateTimeFormat === "mdy-12") {
		const hours = twoDigits(date.getHours() % 12 || 12);
		return `${month}/${day}/${year} ${hours}:${minutes}:${seconds} ${date.getHours() >= 12 ? "PM" : "AM"}`;
	}
	const time = `${twoDigits(date.getHours())}:${minutes}:${seconds}`;
	return dateTimeFormat === "dmy-24" ? `${day}/${month}/${year} ${time}` : `${year}-${month}-${day} ${time}`;
}

function formatTime(value = Date.now()) {
	const formatted = formatDate(value);
	return formatted.includes(" ") ? formatted.slice(formatted.indexOf(" ") + 1) : formatted;
}

function toDateTimeLocal(value) {
	const date = new Date(Number(value));
	return `${date.getFullYear()}-${twoDigits(date.getMonth() + 1)}-${twoDigits(date.getDate())}T${twoDigits(date.getHours())}:${twoDigits(date.getMinutes())}`;
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

let selectedRangeFrom = 0;
let selectedRangeTo = 0;
let dateRangeIsAutomatic = true;
let logPage = 1;
let currentResult = null;
let logChart = null;
let logRequestId = 0;
let canManage = false;

function setDateRangeInputs(from, to) {
	selectedRangeFrom = Number(from);
	selectedRangeTo = Number(to);
	byId("dateFrom").value = toDateTimeLocal(from);
	byId("dateTo").value = toDateTimeLocal(to);
	const maximum = toDateTimeLocal(Date.now() + 300_000);
	byId("dateFrom").max = maximum;
	byId("dateTo").max = maximum;
}

function persistDateRange() {
	const url = new URL(location.href);
	if (dateRangeIsAutomatic) {
		url.searchParams.delete("from");
		url.searchParams.delete("to");
	} else {
		url.searchParams.set("from", String(selectedRangeFrom));
		url.searchParams.set("to", String(selectedRangeTo));
	}
	history.replaceState(null, "", `${url.pathname}${url.search}${url.hash}`);
}

function initializeDateRange() {
	const url = new URL(location.href);
	const now = Date.now();
	const from = Number(url.searchParams.get("from"));
	const to = Number(url.searchParams.get("to"));
	const explicit = Number.isFinite(from) && from >= 0 && Number.isFinite(to) && to > from;
	dateRangeIsAutomatic = !explicit;
	setDateRangeInputs(explicit ? from : now - 86_400_000, explicit ? to : now);
	persistDateRange();
}

function readDateRange() {
	const from = new Date(byId("dateFrom").value).getTime();
	const to = new Date(byId("dateTo").value).getTime();
	if (!Number.isFinite(from) || !Number.isFinite(to) || to - from < 60_000) throw new Error("Select a valid range of at least one minute");
	if (to - from > 366 * 86_400_000) throw new Error("The log range cannot exceed 366 days");
	return { from, to };
}

function levelBadge(level) {
	const normalized = LEVELS.includes(level) ? level : "debug";
	return `<span class="badge log-level-badge log-level-${normalized}">${escapeHtml(LEVEL_LABELS[level] ?? level)}</span>`;
}

function metadataText(metadata) {
	if (metadata === undefined || metadata === null) return "";
	let text;
	try {
		text = JSON.stringify(metadata, null, 2);
	} catch {
		text = String(metadata);
	}
	return text.length > 4_000 ? `${text.slice(0, 3_999)}…` : text;
}

function renderRows(result) {
	byId("logRows").innerHTML = result.items.length
		? result.items
				.map((entry) => {
					const metadata = metadataText(entry.metadata);
					return `<tr><td class="log-time-cell">${escapeHtml(formatDate(entry.timestamp))}</td><td>${levelBadge(entry.level)}</td><td class="log-message-cell" title="${escapeHtml(entry.message)}">${escapeHtml(truncate(entry.message))}</td><td class="log-metadata-cell">${metadata ? `<pre title="${escapeHtml(metadata)}">${escapeHtml(metadata)}</pre>` : '<span class="muted">-</span>'}</td></tr>`;
				})
				.join("")
		: '<tr><td colspan="4" class="empty-cell">No searchable logs match this range and filter.</td></tr>';
	byId("logsSummary").textContent = result.total
		? `${(result.page - 1) * result.pageSize + 1}-${Math.min(result.page * result.pageSize, result.total)} of ${formatNumber(result.total)}`
		: "No records";
	byId("logsPage").textContent = `Page ${result.page} of ${result.totalPages}`;
	byId("logsPrevious").disabled = result.page <= 1;
	byId("logsNext").disabled = result.page >= result.totalPages;
	const dates = result.uncompressedDates ?? [];
	byId("searchableDates").textContent = dates.length
		? `Searchable uncompressed files: ${dates.join(", ")}`
		: "No uncompressed daily log files are available. Compressed archives are download-only.";
}

function metricLabel(bucket) {
	const date = new Date(Number(bucket));
	if (selectedRangeTo - selectedRangeFrom >= 86_400_000) {
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

const rangeSelectionPlugin = {
	id: "burrowgateLogRangeSelection",
	afterDatasetsDraw(chart) {
		const selection = chart.$rangeSelection;
		if (!selection?.dragging) return;
		const { ctx, chartArea } = chart;
		const left = Math.max(chartArea.left, Math.min(selection.startX, selection.currentX));
		const right = Math.min(chartArea.right, Math.max(selection.startX, selection.currentX));
		ctx.save();
		ctx.fillStyle = "rgba(139, 92, 246, 0.18)";
		ctx.strokeStyle = "rgba(167, 139, 250, 0.9)";
		ctx.fillRect(left, chartArea.top, Math.max(0, right - left), chartArea.bottom - chartArea.top);
		ctx.strokeRect(left + 0.5, chartArea.top + 0.5, Math.max(0, right - left - 1), chartArea.bottom - chartArea.top - 1);
		ctx.restore();
	},
};

function attachRangeSelection(chart, result) {
	const canvas = chart.canvas;
	canvas.$rangeCleanup?.();
	if (result.series.length < 2) return;
	const selection = { dragging: false, startX: 0, currentX: 0, pointerId: null };
	chart.$rangeSelection = selection;
	const canvasX = (event) => {
		const rect = canvas.getBoundingClientRect();
		return (event.clientX - rect.left) * (chart.width / rect.width);
	};
	const inside = (x, clientY) => {
		const rect = canvas.getBoundingClientRect();
		const y = (clientY - rect.top) * (chart.height / rect.height);
		return x >= chart.chartArea.left && x <= chart.chartArea.right && y >= chart.chartArea.top && y <= chart.chartArea.bottom;
	};
	const stop = () => {
		selection.dragging = false;
		selection.pointerId = null;
		chart.draw();
	};
	const down = (event) => {
		if (event.button !== 0) return;
		const x = canvasX(event);
		if (!inside(x, event.clientY)) return;
		selection.dragging = true;
		selection.startX = x;
		selection.currentX = x;
		selection.pointerId = event.pointerId;
		canvas.setPointerCapture?.(event.pointerId);
		event.preventDefault();
		chart.draw();
	};
	const move = (event) => {
		if (!selection.dragging || selection.pointerId !== event.pointerId) return;
		selection.currentX = canvasX(event);
		event.preventDefault();
		chart.draw();
	};
	const up = (event) => {
		if (!selection.dragging || selection.pointerId !== event.pointerId) return;
		selection.currentX = canvasX(event);
		if (Math.abs(selection.currentX - selection.startX) < 8) return stop();
		const scale = chart.scales.x;
		const left = Math.max(chart.chartArea.left, Math.min(selection.startX, selection.currentX));
		const right = Math.min(chart.chartArea.right, Math.max(selection.startX, selection.currentX));
		const startIndex = Math.max(0, Math.min(result.series.length - 1, Math.floor(Number(scale.getValueForPixel(left)))));
		const endIndex = Math.max(startIndex, Math.min(result.series.length - 1, Math.ceil(Number(scale.getValueForPixel(right)))));
		const from = Math.max(selectedRangeFrom, Number(result.series[startIndex]?.bucket ?? selectedRangeFrom));
		const to = Math.min(selectedRangeTo, Number(result.series[endIndex]?.bucket ?? selectedRangeTo) + Number(result.bucketMs));
		stop();
		if (to - from >= 60_000) void applyRange(from, to, "Graph selection applied");
	};
	canvas.addEventListener("pointerdown", down);
	canvas.addEventListener("pointermove", move);
	canvas.addEventListener("pointerup", up);
	canvas.addEventListener("pointercancel", stop);
	canvas.$rangeCleanup = () => {
		canvas.removeEventListener("pointerdown", down);
		canvas.removeEventListener("pointermove", move);
		canvas.removeEventListener("pointerup", up);
		canvas.removeEventListener("pointercancel", stop);
	};
}

function renderChart(result) {
	if (!window.Chart) return;
	const totals = Object.fromEntries(LEVELS.map((level) => [level, result.series.reduce((sum, point) => sum + Number(point[level] ?? 0), 0)]));
	const activeLevels = LEVELS.filter((level) => totals[level] > 0);
	const shownLevels = activeLevels.length ? activeLevels : ["info"];
	const styles = getComputedStyle(document.documentElement);
	const grid = styles.getPropertyValue("--chart-grid").trim() || "#273244";
	const text = styles.getPropertyValue("--chart-text").trim() || "#94a3b8";
	logChart?.destroy();
	logChart = new window.Chart(byId("logChart"), {
		type: "bar",
		data: {
			labels: result.series.map((point) => metricLabel(point.bucket)),
			datasets: shownLevels.map((level) => ({
				label: LEVEL_LABELS[level],
				data: result.series.map((point) => Number(point[level] ?? 0)),
				backgroundColor: LEVEL_COLORS[level],
				borderColor: LEVEL_COLORS[level],
				borderWidth: 1,
			})),
		},
		options: {
			responsive: true,
			maintainAspectRatio: false,
			resizeDelay: 150,
			animation: false,
			normalized: true,
			interaction: { mode: "index", intersect: false },
			plugins: { legend: { position: "bottom", labels: { color: text, usePointStyle: true, padding: 16 } }, tooltip: { mode: "index", intersect: false } },
			scales: {
				x: { stacked: true, grid: { display: false }, ticks: { color: text, maxRotation: 0, autoSkip: true, maxTicksLimit: 10 } },
				y: { stacked: true, beginAtZero: true, grid: { color: grid }, ticks: { color: text, precision: 0 } },
			},
		},
		plugins: [rangeSelectionPlugin],
	});
	attachRangeSelection(logChart, result);
	const total = LEVELS.reduce((sum, level) => sum + totals[level], 0);
	byId("logChartEmpty").classList.toggle("hidden", total > 0);
	byId("logChartSummary").innerHTML = total
		? LEVELS.filter((level) => totals[level] > 0)
				.map(
					(level) =>
						`<div class="breakdown-row"><div class="row between"><span><i class="log-level-dot" style="background:${LEVEL_COLORS[level]}"></i>${escapeHtml(LEVEL_LABELS[level])}</span><strong>${formatNumber(totals[level])}</strong></div><div class="breakdown-track"><div style="width:${Math.max(1, (totals[level] / Math.max(...Object.values(totals))) * 100)}%;background:${LEVEL_COLORS[level]}"></div></div></div>`,
				)
				.join("")
		: '<p class="muted">No searchable logs in this range.</p>';
}

async function loadLogs(advanceAutomaticRange = false) {
	const requestId = ++logRequestId;
	if (dateRangeIsAutomatic && advanceAutomaticRange) {
		const to = Date.now();
		setDateRangeInputs(to - 86_400_000, to);
	}
	byId("logRows").innerHTML = '<tr><td colspan="4" class="empty-cell"><span class="spinner"></span> Loading...</td></tr>';
	const result = await api(
		`/logs?${queryString({ from: selectedRangeFrom, to: selectedRangeTo, search: byId("logSearch").value.trim(), level: byId("logLevelFilter").value, page: logPage, pageSize: byId("logPageSize").value })}`,
	);
	if (requestId !== logRequestId) return;
	if (result.page > result.totalPages) {
		logPage = result.totalPages;
		return await loadLogs(false);
	}
	currentResult = result;
	renderRows(result);
	renderChart(result);
	markUpdated();
}

async function applyRange(from, to, label) {
	dateRangeIsAutomatic = false;
	logPage = 1;
	setDateRangeInputs(from, to);
	persistDateRange();
	await loadLogs(false);
	markUpdated(label);
}

async function loadSettings() {
	const settings = await api("/logs/settings");
	canManage = Boolean(settings.canManage);
	byId("fileLoggingEnabled").checked = Boolean(settings.fileEnabled);
	byId("loggingLevel").value = settings.level;
	byId("compressAfterDays").value = String(settings.compressAfterDays);
	byId("retentionDays").value = String(settings.retentionDays);
	byId("logDirectory").textContent = settings.directory;
	for (const element of [byId("fileLoggingEnabled"), byId("loggingLevel"), byId("compressAfterDays"), byId("retentionDays"), byId("saveLogSettings")]) {
		element.disabled = !canManage;
	}
	const notice = byId("logSettingsNotice");
	notice.classList.toggle("hidden", canManage);
	if (!canManage) notice.textContent = "Administrator access is required to change file logging settings or delete archives.";
}

async function saveSettings() {
	const compressAfterDays = Number(byId("compressAfterDays").value);
	const retentionDays = Number(byId("retentionDays").value);
	if (!Number.isInteger(compressAfterDays) || compressAfterDays < 1 || compressAfterDays > 3_649) {
		throw new Error("Compress-after days must be a whole number between 1 and 3649");
	}
	if (!Number.isInteger(retentionDays) || retentionDays < 2 || retentionDays > 3_650) {
		throw new Error("Delete-after days must be a whole number between 2 and 3650");
	}
	if (compressAfterDays >= retentionDays) {
		throw new Error("Compress-after days must be smaller than delete-after days");
	}
	await api("/logs/settings", {
		method: "PUT",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({ fileEnabled: byId("fileLoggingEnabled").checked, level: byId("loggingLevel").value, compressAfterDays, retentionDays }),
	});
	await Promise.all([loadSettings(), loadArchives(), loadLogs(false)]);
	showToast("Logging settings saved.");
}

async function loadArchives() {
	const result = await api("/logs/archives");
	canManage = Boolean(result.canManage);
	byId("archiveRows").innerHTML = result.items.length
		? result.items
				.map(
					(archive) =>
						`<tr><td>${escapeHtml(archive.date)}</td><td><code>${escapeHtml(archive.name)}</code></td><td>${formatBytes(archive.size)}</td><td>${escapeHtml(formatDate(archive.modifiedAt))}</td><td><div class="row"><a class="button secondary compact" href="${ADMIN_API}/logs/archives/${encodeURIComponent(archive.name)}">Download</a>${canManage ? `<button class="button secondary danger compact" type="button" data-delete-archive="${escapeHtml(archive.name)}">Delete</button>` : ""}</div></td></tr>`,
				)
				.join("")
		: '<tr><td colspan="5" class="empty-cell">No compressed log archives.</td></tr>';
}

async function deleteArchive(name) {
	if (!confirm(`Permanently delete ${name}? This cannot be undone.`)) return;
	await api(`/logs/archives/${encodeURIComponent(name)}`, { method: "DELETE" });
	await loadArchives();
	showToast("Log archive deleted.");
}

function debounce(callback, delay = 300) {
	let timer;
	return (...args) => {
		clearTimeout(timer);
		timer = setTimeout(() => callback(...args), delay);
	};
}

function bindActions() {
	byId("refreshDashboard").addEventListener(
		"click",
		() => void Promise.all([loadLogs(true), loadArchives(), loadSettings()]).catch((error) => showToast(error.message, "bad")),
	);
	byId("refreshArchives").addEventListener("click", () => void loadArchives().catch((error) => showToast(error.message, "bad")));
	byId("saveLogSettings").addEventListener("click", (event) => {
		const button = event.currentTarget;
		button.disabled = true;
		void saveSettings()
			.catch((error) => showToast(error.message, "bad"))
			.finally(() => {
				button.disabled = !canManage;
			});
	});
	byId("applyDateRange").addEventListener("click", () => {
		try {
			const range = readDateRange();
			void applyRange(range.from, range.to, "Range applied").catch((error) => showToast(error.message, "bad"));
		} catch (error) {
			showToast(error.message, "bad");
		}
	});
	byId("resetDateRange").addEventListener("click", () => {
		dateRangeIsAutomatic = true;
		logPage = 1;
		const to = Date.now();
		setDateRangeInputs(to - 86_400_000, to);
		persistDateRange();
		void loadLogs(false)
			.then(() => markUpdated("Last 24 hours applied"))
			.catch((error) => showToast(error.message, "bad"));
	});
	byId("dateTimeFormat").addEventListener("change", (event) => {
		saveDateTimeFormat(event.currentTarget.value);
		if (currentResult) {
			renderRows(currentResult);
			renderChart(currentResult);
		}
		void loadArchives().catch((error) => showToast(error.message, "bad"));
	});
	const reloadFromFirstPage = () => {
		logPage = 1;
		void loadLogs(false).catch((error) => showToast(error.message, "bad"));
	};
	byId("logSearch").addEventListener("input", debounce(reloadFromFirstPage));
	byId("logLevelFilter").addEventListener("change", reloadFromFirstPage);
	byId("logPageSize").addEventListener("change", reloadFromFirstPage);
	byId("logsPrevious").addEventListener("click", () => {
		if (logPage <= 1) return;
		logPage -= 1;
		void loadLogs(false).catch((error) => showToast(error.message, "bad"));
	});
	byId("logsNext").addEventListener("click", () => {
		logPage += 1;
		void loadLogs(false).catch((error) => showToast(error.message, "bad"));
	});
	byId("archiveRows").addEventListener("click", (event) => {
		const button = event.target.closest("[data-delete-archive]");
		if (button) void deleteArchive(button.dataset.deleteArchive).catch((error) => showToast(error.message, "bad"));
	});
	byId("logout").addEventListener("click", async () => {
		await fetch(`${ADMIN_API}/logout`, { method: "POST", headers: mutationHeaders });
		location.href = "/_burrowgate/admin/login";
	});
	window.addEventListener(
		"pagehide",
		() => {
			logChart?.destroy();
		},
		{ once: true },
	);
}

async function start() {
	initializeDateTimeFormat();
	initializeDateRange();
	bindActions();
	try {
		await Promise.all([loadSettings(), loadArchives(), loadLogs(false)]);
		markUpdated("Loaded");
	} catch (error) {
		showToast(error.message, "bad");
	}
}

void start();
