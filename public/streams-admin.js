const ADMIN_API = "/_burrowgate/api/admin";
const mutationHeaders = { "x-burrowgate-admin": "1" };
const byId = (id) => document.getElementById(id);

let streams = [];
let certificates = [];
let statuses = [];
let selectedStreamId = "";
let activeTab = "connections";
let eventPage = 1;
let bandwidthPage = 1;
let pageSize = 50;
let rangeFrom = 0;
let rangeTo = 0;
let geoMapGeometry = null;
let geoStatus = null;
let geoData = { active: [], events: [], bandwidth: [] };
let activeConnections = [];
let latestStreamMetrics = null;
let streamTrafficChart = null;
let streamBandwidthChart = null;

const tableState = {
	connections: { sortBy: "connectedAt", sortDirection: "desc" },
	events: { sortBy: "created_at", sortDirection: "desc" },
	bandwidth: { sortBy: "total_bytes", sortDirection: "desc" },
};

const escapeHtml = (value) =>
	String(value ?? "").replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);

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

function formatDate(value) {
	const date = new Date(Number(value));
	return Number.isNaN(date.getTime()) ? "-" : date.toLocaleString();
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
	if (Number(latestStreamMetrics?.rangeDurationMs ?? rangeTo - rangeFrom) >= 24 * 3_600_000 || detailed) {
		return date.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
	}
	return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
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
	canvas.parentElement?.classList.add("time-selectable");
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
	const formatter = definition.valueFormat === "bytes" ? formatBytes : (value) => formatNumber(Math.round(Number(value)));
	const labels = definition.data.map((point) => metricLabel(point.bucket));
	const datasets = definition.datasets.map((dataset, index) => {
		const color = theme.palette[index % theme.palette.length];
		return {
			label: dataset.label,
			data: definition.data.map((point) => Number(point[dataset.key] ?? 0)),
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
		type: "line",
		data: { labels, datasets },
		options: {
			responsive: true,
			resizeDelay: 150,
			animation: false,
			normalized: true,
			interaction: { mode: "index", intersect: false },
			plugins: {
				legend: {
					display: datasets.length > 1,
					position: "bottom",
					labels: { color: theme.text, usePointStyle: true, pointStyle: "line", boxWidth: 18, boxHeight: 3, padding: 18 },
				},
				tooltip: {
					enabled: true,
					mode: "index",
					intersect: false,
					callbacks: {
						title(items) {
							return metricLabel(definition.data[items[0].dataIndex]?.bucket, true);
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

function renderStreamCharts() {
	if (!latestStreamMetrics) return;
	const data = latestStreamMetrics.series ?? [];
	const bandwidthMode = activeTab === "bandwidth";
	const primary = bandwidthMode
		? {
				title: "Client to upstream bandwidth",
				subtitle: "Payload bytes received from stream clients and forwarded upstream",
				emptyMessage: "No client-to-upstream bandwidth in this range.",
				valueFormat: "bytes",
				datasets: [{ key: "clientToUpstreamBytes", label: "To upstream" }],
				data,
			}
		: {
				title: "Stream traffic volume",
				subtitle: "Connections, disconnections, and proxy errors",
				emptyMessage: "No stream lifecycle activity in this range.",
				valueFormat: "number",
				datasets: [
					{ key: "connected", label: "Connected" },
					{ key: "disconnected", label: "Disconnected" },
					{ key: "errors", label: "Errors" },
				],
				data,
			};
	const secondary = bandwidthMode
		? {
				title: "Upstream to client bandwidth",
				subtitle: "Payload bytes received upstream and returned to stream clients",
				emptyMessage: "No upstream-to-client bandwidth in this range.",
				valueFormat: "bytes",
				datasets: [{ key: "upstreamToClientBytes", label: "To clients" }],
				data,
			}
		: {
				title: "Stream data volume",
				subtitle: "Payload bytes transferred in both proxy directions",
				emptyMessage: "No stream bandwidth in this range.",
				valueFormat: "bytes",
				datasets: [
					{ key: "clientToUpstreamBytes", label: "To upstream" },
					{ key: "upstreamToClientBytes", label: "To clients" },
				],
				data,
			};
	byId("primaryChartTitle").textContent = primary.title;
	byId("primaryChartSubtitle").textContent = primary.subtitle;
	byId("secondaryChartTitle").textContent = secondary.title;
	byId("secondaryChartSubtitle").textContent = secondary.subtitle;
	byId("streamTrafficEmpty").textContent = primary.emptyMessage;
	byId("streamBandwidthEmpty").textContent = secondary.emptyMessage;
	const primaryHasData = primary.datasets.some((dataset) => data.some((point) => Number(point[dataset.key]) > 0));
	const secondaryHasData = secondary.datasets.some((dataset) => data.some((point) => Number(point[dataset.key]) > 0));
	byId("streamTrafficEmpty").classList.toggle("hidden", primaryHasData);
	byId("streamBandwidthEmpty").classList.toggle("hidden", secondaryHasData);
	streamTrafficChart?.destroy();
	streamBandwidthChart?.destroy();
	streamTrafficChart = createStreamChart("streamTrafficChart", primary);
	streamBandwidthChart = createStreamChart("streamBandwidthChart", secondary);
}

async function loadStreamMetrics() {
	latestStreamMetrics = await api(`/streams/metrics?${queryString({ streamId: selectedStreamId, ...rangeQuery() })}`);
	renderStreamCharts();
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
	selector.innerHTML = `<option value="">All streams</option>${streams.map((stream) => `<option value="${escapeHtml(stream.id)}">Port ${stream.incomingPort} → ${escapeHtml(stream.forwardHost)}:${stream.forwardPort}</option>`).join("")}`;
	if (streams.some((stream) => stream.id === selectedStreamId)) selector.value = selectedStreamId;
	else selectedStreamId = "";
}

function renderCertificateOptions() {
	const select = byId("streamCertificate");
	const selected = select.value;
	select.innerHTML = `<option value="">None / TLS passthrough</option>${certificates.map((certificate) => `<option value="${escapeHtml(certificate.id)}">${escapeHtml(certificate.primaryDomain)} · ${escapeHtml(certificate.siteName)} · expires ${escapeHtml(formatDate(certificate.expiresAt))}</option>`).join("")}`;
	if (certificates.some((certificate) => certificate.id === selected)) select.value = selected;
}

function mappingFor(stream) {
	const mappings = [];
	if (stream.tcpEnabled) mappings.push(`      - "${stream.incomingPort}:${stream.incomingPort}/tcp"`);
	if (stream.udpEnabled) mappings.push(`      - "${stream.incomingPort}:${stream.incomingPort}/udp"`);
	return `services:\n  burrowgate:\n    ports:\n${mappings.join("\n")}`;
}

function renderStreams() {
	const list = byId("streamsList");
	if (!streams.length) {
		list.innerHTML = '<div class="empty-state-inline">No streams are configured.</div>';
		return;
	}
	list.innerHTML = streams
		.map((stream) => {
			const status = statusFor(stream.id);
			const protocols = [stream.tcpEnabled ? "TCP" : "", stream.udpEnabled ? "UDP" : ""].filter(Boolean).join(" + ");
			return `<div class="site-list-item ${status.error ? "disabled" : ""}"><div class="site-list-title"><strong>${protocols} :${stream.incomingPort}</strong><span>${stream.certificateId ? "TLS" : "Raw"}</span></div><div class="site-list-meta"><code>${escapeHtml(stream.forwardHost)}:${stream.forwardPort}</code><span>Retention ${stream.eventRetentionDays}d</span></div><div class="stream-status-row">${stream.tcpEnabled ? `TCP ${statusBadge(status.tcp)}` : ""}${stream.udpEnabled ? `UDP ${statusBadge(status.udp)}` : ""}<span class="muted">${status.activeTcpConnections} TCP / ${status.activeUdpPeers} UDP active</span></div>${status.error ? `<p class="badge bad">${escapeHtml(status.error)}</p>` : ""}<div class="site-list-actions"><button class="button secondary compact" type="button" data-edit-stream="${escapeHtml(stream.id)}">Edit</button><button class="button danger compact" type="button" data-delete-stream="${escapeHtml(stream.id)}">Delete</button></div></div>`;
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
					(item) =>
						`<tr><td><span class="badge info">${item.protocol.toUpperCase()}</span></td><td><code>${item.incomingPort}</code></td><td><code>${escapeHtml(item.clientIp)}:${item.clientPort}</code></td><td>${escapeHtml(item.countryCode || "ZZ")}</td><td title="${escapeHtml(formatDate(item.connectedAt))}">${formatDuration(item.connectedAt)}</td><td>${escapeHtml(formatDate(item.lastActivityAt))}</td><td>${formatBytes(item.clientToUpstreamBytes)}</td><td>${formatBytes(item.upstreamToClientBytes)}</td></tr>`,
				)
				.join("")
		: '<tr><td colspan="8" class="empty-cell">No active connections or UDP peers.</td></tr>';
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
	byId("clientToUpstreamLabel").textContent = `Client to upstream (${rangeLabel})`;
	byId("upstreamToClientLabel").textContent = `Upstream to client (${rangeLabel})`;
	byId("rangeErrorsLabel").textContent = `Errors (${rangeLabel})`;
	byId("rangeConnections").textContent = formatNumber(result.connections);
	byId("uniqueIps").textContent = formatNumber(result.uniqueIps);
	byId("rangeErrors").textContent = formatNumber(result.errors);
	byId("clientToUpstream").textContent = formatBytes(result.clientToUpstreamBytes);
	byId("upstreamToClient").textContent = formatBytes(result.upstreamToClientBytes);
	geoStatus = result.geoip;
	geoData.events = result.countries.map((item) => ({ countryCode: item.countryCode, count: Number(item.connections) }));
	geoData.bandwidth = result.countries.map((item) => ({ countryCode: item.countryCode, count: Number(item.bytes) }));
	renderActive(result.active);
	renderGeoMap();
}

function countryDisplayName(code, fallback = "") {
	if (code === "ZZ") return "Unknown";
	try {
		return new Intl.DisplayNames(["en"], { type: "region" }).of(code) ?? (fallback || code);
	} catch {
		return fallback || code;
	}
}

function populateCountrySelects() {
	if (!geoMapGeometry) return;
	const countries = [...geoMapGeometry.paths.entries()]
		.map(([code, path]) => ({ code, name: path.dataset.name || countryDisplayName(code) }))
		.sort((left, right) => left.name.localeCompare(right.name));
	countries.push({ code: "ZZ", name: "Unknown / unmapped" });
	for (const id of ["eventCountry", "bandwidthCountry"]) {
		const select = byId(id);
		const current = select.value;
		select.innerHTML = `<option value="">All countries</option>${countries.map((country) => `<option value="${country.code}">${escapeHtml(country.name)} (${country.code})</option>`).join("")}`;
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

function renderGeoMap() {
	if (!geoMapGeometry) return;
	const mode = byId("geoMetricMode").value;
	const items = geoData[mode] ?? [];
	const values = new Map(items.map((item) => [String(item.countryCode).toUpperCase(), Number(item.count)]));
	const maximum = Math.max(0, ...items.filter((item) => item.countryCode !== "ZZ").map((item) => Number(item.count)));
	const total = items.reduce((sum, item) => sum + Number(item.count), 0);
	const bandwidth = mode === "bandwidth";
	const title = mode === "active" ? "Active connections" : mode === "events" ? "Connections in traffic log" : "Proxied bandwidth";
	const unit = bandwidth ? "bytes" : mode === "active" ? "active connections" : "connections";
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
		else bandwidthPage -= 1;
		void load();
	};
	byId(`${prefix}Next`).onclick = () => {
		if (prefix === "events") eventPage += 1;
		else bandwidthPage += 1;
		void load();
	};
}

async function loadEvents() {
	const state = tableState.events;
	byId("streamEvents").innerHTML = '<tr><td colspan="9" class="empty-cell"><span class="spinner"></span> Loading...</td></tr>';
	const result = await api(
		`/streams/events?${queryString({ streamId: selectedStreamId, page: eventPage, pageSize, sortBy: state.sortBy, sortDirection: state.sortDirection, search: byId("eventSearch").value.trim(), protocol: byId("eventProtocol").value, eventType: byId("eventType").value, country: byId("eventCountry").value.trim().toUpperCase(), ...rangeQuery() })}`,
	);
	updateSortIndicators("panel-events", state);
	byId("streamEvents").innerHTML = result.items.length
		? result.items
				.map(
					(item) =>
						`<tr><td>${escapeHtml(formatDate(item.created_at))}</td><td><span class="badge ${item.event_type.includes("error") ? "bad" : item.event_type === "connected" ? "ok" : "info"}">${escapeHtml(item.event_type)}</span></td><td>${item.protocol.toUpperCase()}</td><td><code>${item.incoming_port}</code></td><td><code>${escapeHtml(item.client_ip || "-")}${item.client_port ? `:${item.client_port}` : ""}</code></td><td>${escapeHtml(item.country_code || "ZZ")}</td><td title="${escapeHtml(item.error || "")}">${escapeHtml(item.reason || item.error || "-")}</td><td>${formatBytes(item.client_to_upstream_bytes)}</td><td>${formatBytes(item.upstream_to_client_bytes)}</td></tr>`,
				)
				.join("")
		: '<tr><td colspan="9" class="empty-cell">No stream events match these filters.</td></tr>';
	updatePagination("events", result, loadEvents);
}

async function loadBandwidth() {
	const state = tableState.bandwidth;
	byId("streamBandwidth").innerHTML = '<tr><td colspan="7" class="empty-cell"><span class="spinner"></span> Loading...</td></tr>';
	const result = await api(
		`/streams/bandwidth?${queryString({ streamId: selectedStreamId, page: bandwidthPage, pageSize, sortBy: state.sortBy, sortDirection: state.sortDirection, search: byId("bandwidthSearch").value.trim(), protocol: byId("bandwidthProtocol").value, country: byId("bandwidthCountry").value.trim().toUpperCase(), ...rangeQuery() })}`,
	);
	updateSortIndicators("panel-bandwidth", state);
	byId("streamBandwidth").innerHTML = result.items.length
		? result.items
				.map(
					(item) =>
						`<tr><td><span class="badge info">${item.protocol.toUpperCase()}</span></td><td><code>${item.incoming_port}</code></td><td><code>${escapeHtml(item.ip)}</code></td><td>${escapeHtml(item.country_code || "ZZ")}</td><td>${formatBytes(item.client_to_upstream_bytes)}</td><td>${formatBytes(item.upstream_to_client_bytes)}</td><td><strong>${formatBytes(item.total_bytes)}</strong></td></tr>`,
				)
				.join("")
		: '<tr><td colspan="7" class="empty-cell">No stream bandwidth matches these filters.</td></tr>';
	updatePagination("bandwidth", result, loadBandwidth);
}

function updateProtocolControls() {
	const valid = byId("streamTcp").checked || byId("streamUdp").checked;
	byId("streamProtocolError").classList.toggle("hidden", valid);
	byId("saveStream").disabled = !valid;
	byId("streamCertificate").disabled = !byId("streamTcp").checked;
	if (!byId("streamTcp").checked) byId("streamCertificate").value = "";
	const draft = { incomingPort: Number(byId("incomingPort").value), tcpEnabled: byId("streamTcp").checked, udpEnabled: byId("streamUdp").checked };
	if (draft.incomingPort && valid) {
		byId("composeMapping").textContent = mappingFor(draft);
		byId("composeMapping").classList.remove("hidden");
	} else byId("composeMapping").classList.add("hidden");
}

function resetForm() {
	byId("streamForm").reset();
	byId("streamId").value = "";
	byId("streamFormTitle").textContent = "Create stream";
	byId("saveStream").textContent = "Create";
	byId("cancelStreamEdit").classList.add("hidden");
	byId("streamTcp").checked = true;
	byId("streamUdp").checked = false;
	byId("streamRetentionDays").value = "7";
	updateProtocolControls();
}

function editStream(id) {
	const stream = streams.find((item) => item.id === id);
	if (!stream) return;
	byId("streamId").value = stream.id;
	byId("incomingPort").value = stream.incomingPort;
	byId("forwardHost").value = stream.forwardHost;
	byId("forwardPort").value = stream.forwardPort;
	byId("streamRetentionDays").value = stream.eventRetentionDays;
	byId("streamTcp").checked = stream.tcpEnabled;
	byId("streamUdp").checked = stream.udpEnabled;
	byId("streamCertificate").value = stream.certificateId || "";
	byId("streamFormTitle").textContent = `Edit stream :${stream.incomingPort}`;
	byId("saveStream").textContent = "Save";
	byId("cancelStreamEdit").classList.remove("hidden");
	updateProtocolControls();
}

async function saveStream(event) {
	event.preventDefault();
	const id = byId("streamId").value;
	const payload = {
		incomingPort: Number(byId("incomingPort").value),
		forwardHost: byId("forwardHost").value.trim(),
		forwardPort: Number(byId("forwardPort").value),
		tcpEnabled: byId("streamTcp").checked,
		udpEnabled: byId("streamUdp").checked,
		certificateId: byId("streamCertificate").value || null,
		eventRetentionDays: Number(byId("streamRetentionDays").value),
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
			`Delete the ${stream.tcpEnabled && stream.udpEnabled ? "TCP/UDP" : stream.tcpEnabled ? "TCP" : "UDP"} stream on port ${stream.incomingPort}? Monitoring history for this stream will also be deleted.`,
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
	const geoMode = { connections: "active", events: "events", bandwidth: "bandwidth" }[name];
	if (geoMode) {
		byId("geoMetricMode").value = geoMode;
		renderGeoMap();
		renderStreamCharts();
	}
	if (name === "events") void loadEvents();
	if (name === "bandwidth") void loadBandwidth();
	if (name === "connections") void loadConnections();
	if (name === "streams") void loadStreams();
}

async function refreshDashboard(updateLabel = "Updated") {
	try {
		await loadStreams();
		await Promise.all([loadOverview(), loadStreamMetrics()]);
		if (activeTab === "events") await loadEvents();
		if (activeTab === "bandwidth") await loadBandwidth();
		if (activeTab === "connections") await loadConnections();
		byId("lastUpdated").textContent = `${updateLabel} ${new Date().toLocaleTimeString()}`;
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
	});
});
byId("geoMetricMode").addEventListener("change", renderGeoMap);
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
byId("logout").addEventListener("click", async () => {
	await api("/logout", { method: "POST" });
	location.href = "/_burrowgate/admin/login";
});

window.addEventListener(
	"pagehide",
	() => {
		byId("streamTrafficChart").$dateRangeCleanup?.();
		byId("streamBandwidthChart").$dateRangeCleanup?.();
		streamTrafficChart?.destroy();
		streamBandwidthChart?.destroy();
	},
	{ once: true },
);

void refreshDashboard();
setInterval(() => {
	if (document.visibilityState === "visible") void loadConnections();
}, 5_000);
