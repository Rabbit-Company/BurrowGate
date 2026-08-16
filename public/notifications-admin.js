const ADMIN_API = "/_burrowgate/api/admin";
const mutationHeaders = { "x-burrowgate-admin": "1" };
const byId = (id) => document.getElementById(id);

const escapeHtml = (value) =>
	String(value ?? "").replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);

function truncate(value, length = 72) {
	const text = String(value ?? "");
	return text.length > length ? `${text.slice(0, length - 1)}...` : text;
}

function formatDate(value) {
	if (value === null || value === undefined) return "-";
	const date = new Date(Number(value));
	return Number.isNaN(date.getTime()) ? "-" : date.toLocaleString();
}

function formatNumber(value) {
	return new Intl.NumberFormat().format(Number(value ?? 0));
}

function formatEventType(type) {
	const text = String(type ?? "").replaceAll("_", " ");
	return text.charAt(0).toUpperCase() + text.slice(1);
}

function debounce(callback, delay = 300) {
	let timer;
	return (...args) => {
		clearTimeout(timer);
		timer = setTimeout(() => callback(...args), delay);
	};
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

let sites = [];
let streams = [];
let selectedSiteId = "";
let selectedStreamId = "";
const logState = {
	siteNotif: { page: 1, pageSize: 50, sortBy: "created_at", sortDirection: "desc" },
	streamNotif: { page: 1, pageSize: 50, sortBy: "created_at", sortDirection: "desc" },
};

function updateNotifControls(prefix) {
	const clearingWebhook = byId(`${prefix}ClearWebhook`).checked;
	if (clearingWebhook) byId(`${prefix}Enabled`).checked = false;
	const settingsVisible = byId(`${prefix}Enabled`).checked || clearingWebhook;
	byId(`${prefix}Settings`).classList.toggle("hidden", !settingsVisible);
}

function eventTypesFromForm(prefix) {
	const result = {};
	byId(`${prefix}Body`)
		.querySelectorAll('input[name="notificationEventType"]')
		.forEach((input) => {
			result[input.value] = input.checked;
		});
	return result;
}

function setEventTypes(prefix, eventTypes) {
	byId(`${prefix}Body`)
		.querySelectorAll('input[name="notificationEventType"]')
		.forEach((input) => {
			input.checked = eventTypes?.[input.value] !== false;
		});
}

function applyPolicy(prefix, policy) {
	byId(`${prefix}Enabled`).checked = Boolean(policy.enabled);
	byId(`${prefix}Provider`).value = policy.provider ?? "generic";
	byId(`${prefix}WebhookUrl`).value = "";
	byId(`${prefix}WebhookSecret`).value = "";
	byId(`${prefix}ClearWebhook`).checked = false;
	byId(`${prefix}ClearWebhookRow`).classList.toggle("hidden", !policy.webhookConfigured);
	byId(`${prefix}WebhookConfigured`).textContent = policy.webhookConfigured
		? "An encrypted webhook destination is configured. Leave the URL blank to keep it."
		: "No webhook is configured.";
	setEventTypes(prefix, policy.eventTypes);
	updateNotifControls(prefix);
}

function renderSiteSelector() {
	const selector = byId("siteNotifSelector");
	selector.innerHTML = sites.length
		? sites.map((site) => `<option value="${escapeHtml(site.id)}">${escapeHtml(site.name)} | ${escapeHtml(site.publicHost)}</option>`).join("")
		: '<option value="">No sites configured</option>';
	if (sites.some((site) => site.id === selectedSiteId)) selector.value = selectedSiteId;
	else selectedSiteId = selector.value;
}

function renderStreamSelector() {
	const selector = byId("streamNotifSelector");
	selector.innerHTML = streams.length
		? streams.map((stream) => `<option value="${escapeHtml(stream.id)}">${escapeHtml(stream.name)} (port ${stream.incomingPort})</option>`).join("")
		: '<option value="">No streams configured</option>';
	if (streams.some((stream) => stream.id === selectedStreamId)) selector.value = selectedStreamId;
	else selectedStreamId = selector.value;
}

function sortButtonsFor(prefix) {
	return byId(`${prefix}Log`).closest("article").querySelectorAll(".sort-button");
}

function updateSortIndicators(prefix) {
	const state = logState[prefix];
	sortButtonsFor(prefix).forEach((button) => {
		const selected = button.dataset.sort === state.sortBy;
		button.classList.toggle("selected", selected);
		button.querySelector("span").textContent = selected ? (state.sortDirection === "asc" ? "↑" : "↓") : "";
	});
}

function updateLogPagination(prefix, result, reload) {
	const id = `${prefix}Log`;
	byId(`${id}Summary`).textContent = result.total
		? `${(result.page - 1) * result.pageSize + 1}-${Math.min(result.page * result.pageSize, result.total)} of ${result.total}`
		: "No records";
	byId(`${id}Page`).textContent = `Page ${result.page} of ${result.totalPages}`;
	byId(`${id}Previous`).disabled = result.page <= 1;
	byId(`${id}Next`).disabled = result.page >= result.totalPages;
	byId(`${id}Previous`).onclick = () => {
		logState[prefix].page -= 1;
		void reload();
	};
	byId(`${id}Next`).onclick = () => {
		logState[prefix].page += 1;
		void reload();
	};
}

function statusBadgeClass(status) {
	return status === "delivered" ? "ok" : status === "failed" ? "bad" : "warn";
}

function renderLogRows(prefix, items) {
	byId(`${prefix}Log`).innerHTML = items.length
		? items
				.map(
					(item) => `<tr>
        <td>${escapeHtml(formatDate(item.occurredAt ?? item.createdAt))}</td>
        <td>${escapeHtml(formatEventType(item.type))}</td>
        <td><span class="badge ${statusBadgeClass(item.status)}">${escapeHtml(item.status)}</span></td>
        <td title="${escapeHtml(item.summary)}">${escapeHtml(truncate(item.summary, 90))}</td>
        <td>${item.attempts ? `${formatNumber(item.attempts)} attempt${item.attempts === 1 ? "" : "s"}` : "-"}${item.lastError ? `<br><small class="muted" title="${escapeHtml(item.lastError)}">${escapeHtml(truncate(item.lastError, 60))}</small>` : ""}</td>
      </tr>`,
				)
				.join("")
		: '<tr><td colspan="5" class="empty-cell">No notifications match these filters.</td></tr>';
}

async function loadSiteNotificationLog() {
	const state = logState.siteNotif;
	updateSortIndicators("siteNotif");
	if (!selectedSiteId) {
		byId("siteNotifLog").innerHTML = '<tr><td colspan="5" class="empty-cell">Select a site to load its notifications.</td></tr>';
		return;
	}
	byId("siteNotifLog").innerHTML = '<tr><td colspan="5" class="empty-cell"><span class="spinner"></span> Loading...</td></tr>';
	try {
		const result = await api(
			`/sites/${encodeURIComponent(selectedSiteId)}/notifications?${queryString({
				page: state.page,
				pageSize: state.pageSize,
				sortBy: state.sortBy,
				sortDirection: state.sortDirection,
				search: byId("siteNotifLogSearch").value.trim(),
				type: byId("siteNotifLogType").value,
				status: byId("siteNotifLogStatus").value,
			})}`,
		);
		if (result.page > result.totalPages && result.totalPages >= 1) {
			state.page = result.totalPages;
			await loadSiteNotificationLog();
			return;
		}
		renderLogRows("siteNotif", result.items);
		updateLogPagination("siteNotif", result, loadSiteNotificationLog);
	} catch (error) {
		byId("siteNotifLog").innerHTML = `<tr><td colspan="5" class="empty-cell error-text">${escapeHtml(error.message)}</td></tr>`;
	}
}

async function loadStreamNotificationLog() {
	const state = logState.streamNotif;
	updateSortIndicators("streamNotif");
	if (!selectedStreamId) {
		byId("streamNotifLog").innerHTML = '<tr><td colspan="5" class="empty-cell">Select a stream to load its notifications.</td></tr>';
		return;
	}
	byId("streamNotifLog").innerHTML = '<tr><td colspan="5" class="empty-cell"><span class="spinner"></span> Loading...</td></tr>';
	try {
		const result = await api(
			`/streams/notifications?${queryString({
				streamId: selectedStreamId,
				page: state.page,
				pageSize: state.pageSize,
				sortBy: state.sortBy,
				sortDirection: state.sortDirection,
				search: byId("streamNotifLogSearch").value.trim(),
				type: byId("streamNotifLogType").value,
				status: byId("streamNotifLogStatus").value,
			})}`,
		);
		if (result.page > result.totalPages && result.totalPages >= 1) {
			state.page = result.totalPages;
			await loadStreamNotificationLog();
			return;
		}
		renderLogRows("streamNotif", result.items);
		updateLogPagination("streamNotif", result, loadStreamNotificationLog);
	} catch (error) {
		byId("streamNotifLog").innerHTML = `<tr><td colspan="5" class="empty-cell error-text">${escapeHtml(error.message)}</td></tr>`;
	}
}

async function loadSiteNotifications() {
	byId("siteNotifEmpty").classList.toggle("hidden", Boolean(selectedSiteId));
	byId("siteNotifBody").classList.toggle("hidden", !selectedSiteId);
	logState.siteNotif.page = 1;
	if (selectedSiteId) {
		try {
			applyPolicy("siteNotif", await api(`/sites/${encodeURIComponent(selectedSiteId)}/notification-policy`));
		} catch (error) {
			showToast(error.message, "bad");
		}
	}
	await loadSiteNotificationLog();
}

async function loadStreamNotifications() {
	byId("streamNotifEmpty").classList.toggle("hidden", Boolean(selectedStreamId));
	byId("streamNotifBody").classList.toggle("hidden", !selectedStreamId);
	logState.streamNotif.page = 1;
	if (selectedStreamId) {
		try {
			applyPolicy("streamNotif", await api(`/streams/notification-policy?streamId=${encodeURIComponent(selectedStreamId)}`));
		} catch (error) {
			showToast(error.message, "bad");
		}
	}
	await loadStreamNotificationLog();
}

async function saveSiteNotifications() {
	if (!selectedSiteId) return;
	try {
		const policy = await api(`/sites/${encodeURIComponent(selectedSiteId)}/notification-policy`, {
			method: "PUT",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				enabled: byId("siteNotifEnabled").checked,
				provider: byId("siteNotifProvider").value,
				webhookUrl: byId("siteNotifWebhookUrl").value.trim(),
				webhookSecret: byId("siteNotifWebhookSecret").value.trim(),
				clearWebhook: byId("siteNotifClearWebhook").checked,
				eventTypes: eventTypesFromForm("siteNotif"),
			}),
		});
		applyPolicy("siteNotif", policy);
		showToast("Notification settings saved.");
	} catch (error) {
		showToast(error.message, "bad");
	}
}

async function saveStreamNotifications() {
	if (!selectedStreamId) return;
	try {
		const policy = await api(`/streams/notification-policy?streamId=${encodeURIComponent(selectedStreamId)}`, {
			method: "PUT",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				enabled: byId("streamNotifEnabled").checked,
				provider: byId("streamNotifProvider").value,
				webhookUrl: byId("streamNotifWebhookUrl").value.trim(),
				webhookSecret: byId("streamNotifWebhookSecret").value.trim(),
				clearWebhook: byId("streamNotifClearWebhook").checked,
				eventTypes: eventTypesFromForm("streamNotif"),
			}),
		});
		applyPolicy("streamNotif", policy);
		showToast("Notification settings saved.");
	} catch (error) {
		showToast(error.message, "bad");
	}
}

async function loadAll() {
	try {
		const [sitesResult, streamsResult] = await Promise.all([api("/sites"), api("/streams")]);
		sites = sitesResult.items ?? [];
		streams = streamsResult.items ?? [];
		renderSiteSelector();
		renderStreamSelector();
		await Promise.all([loadSiteNotifications(), loadStreamNotifications()]);
	} catch (error) {
		showToast(error.message, "bad");
	}
}

byId("siteNotifSelector").addEventListener("change", () => {
	selectedSiteId = byId("siteNotifSelector").value;
	void loadSiteNotifications();
});
byId("streamNotifSelector").addEventListener("change", () => {
	selectedStreamId = byId("streamNotifSelector").value;
	void loadStreamNotifications();
});
byId("siteNotifEnabled").addEventListener("change", () => updateNotifControls("siteNotif"));
byId("siteNotifClearWebhook").addEventListener("change", () => updateNotifControls("siteNotif"));
byId("streamNotifEnabled").addEventListener("change", () => updateNotifControls("streamNotif"));
byId("streamNotifClearWebhook").addEventListener("change", () => updateNotifControls("streamNotif"));
byId("siteNotifSave").addEventListener("click", () => void saveSiteNotifications());
byId("streamNotifSave").addEventListener("click", () => void saveStreamNotifications());

byId("siteNotifLogSearch").addEventListener(
	"input",
	debounce(() => {
		logState.siteNotif.page = 1;
		void loadSiteNotificationLog();
	}),
);
byId("streamNotifLogSearch").addEventListener(
	"input",
	debounce(() => {
		logState.streamNotif.page = 1;
		void loadStreamNotificationLog();
	}),
);
for (const id of ["siteNotifLogType", "siteNotifLogStatus", "siteNotifLogPageSize"])
	byId(id).addEventListener("change", () => {
		if (id === "siteNotifLogPageSize") logState.siteNotif.pageSize = Number(byId(id).value);
		logState.siteNotif.page = 1;
		void loadSiteNotificationLog();
	});
for (const id of ["streamNotifLogType", "streamNotifLogStatus", "streamNotifLogPageSize"])
	byId(id).addEventListener("change", () => {
		if (id === "streamNotifLogPageSize") logState.streamNotif.pageSize = Number(byId(id).value);
		logState.streamNotif.page = 1;
		void loadStreamNotificationLog();
	});

document.querySelectorAll(".sort-button").forEach((button) => {
	button.addEventListener("click", () => {
		const prefix = button.closest("article").querySelector("tbody[id$='Log']")?.id.replace(/Log$/, "");
		const state = logState[prefix];
		if (!state) return;
		const sortBy = button.dataset.sort;
		if (state.sortBy === sortBy) state.sortDirection = state.sortDirection === "asc" ? "desc" : "asc";
		else {
			state.sortBy = sortBy;
			state.sortDirection = "desc";
		}
		state.page = 1;
		if (prefix === "siteNotif") void loadSiteNotificationLog();
		else if (prefix === "streamNotif") void loadStreamNotificationLog();
	});
});

byId("refreshDashboard").addEventListener("click", () => void loadAll());
byId("logout").addEventListener("click", async () => {
	await api("/logout", { method: "POST" });
	location.href = "/_burrowgate/admin/login";
});

void loadAll();
