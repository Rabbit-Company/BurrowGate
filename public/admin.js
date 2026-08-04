const ADMIN_API = "/_burrowgate/api/admin";
const mutationHeaders = { "x-burrowgate-admin": "1" };

const tableState = {
	traffic: { page: 1, pageSize: 50, sortBy: "created_at", sortDirection: "desc" },
	sessions: { page: 1, pageSize: 50, sortBy: "last_seen_at", sortDirection: "desc" },
	rules: { page: 1, pageSize: 50, sortBy: "created_at", sortDirection: "desc" },
};

let activeTab = "traffic";
let latestMetrics = null;
let trafficChart = null;
let latencyChart = null;
let geoMapGeometry = null;
let geoMetrics = null;
let sites = [];
let challengeProviders = [];
let defaultEventRetentionDays = 7;
let errorResponseDefaults = { mode: "json", htmlTemplate: "", jsonFields: [], jsonFieldOptions: [], placeholders: [] };
let challengeDefaults = { htmlTemplate: "", placeholders: [] };
let errorResponseOptionsLoaded = false;
let selectedSiteId = null;
let editingSiteId = null;
let routePolicies = [];
let countryRules = [];
let editingRoutePolicyId = null;
let currentTls = null;
let overviewRequestId = 0;
let selectedRangeFrom = 0;
let selectedRangeTo = 0;
const loadedTabs = new Set(["traffic"]);

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

function formatNumber(value) {
	return Number(value ?? 0).toLocaleString();
}

function formatDate(value) {
	if (value === null || value === undefined) return "Never";
	const date = new Date(Number(value));
	return Number.isNaN(date.getTime()) ? "-" : date.toLocaleString();
}

function formatDuration(milliseconds) {
	const value = Number(milliseconds ?? 0);
	if (value < 1_000) return `${Math.round(value)} ms`;
	if (value < 60_000) return `${(value / 1_000).toFixed(1)} s`;
	return `${(value / 60_000).toFixed(1)} min`;
}

function toDateTimeLocal(value) {
	const date = new Date(Number(value));
	const pad = (part) => String(part).padStart(2, "0");
	return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function rangeDurationLabel(durationMs) {
	const totalMinutes = Math.max(1, Math.round(Number(durationMs) / 60_000));
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

function rangeQuery() {
	return { from: selectedRangeFrom, to: selectedRangeTo };
}

function persistDateRange() {
	const url = new URL(location.href);
	url.searchParams.set("from", String(selectedRangeFrom));
	url.searchParams.set("to", String(selectedRangeTo));
	history.replaceState(null, "", `${url.pathname}${url.search}${url.hash}`);
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

function initializeDateRange() {
	const url = new URL(location.href);
	const now = Date.now();
	const requestedTo = Number(url.searchParams.get("to"));
	const requestedFrom = Number(url.searchParams.get("from"));
	const to = Number.isFinite(requestedTo) && requestedTo > 0 ? requestedTo : now;
	const from = Number.isFinite(requestedFrom) && requestedFrom >= 0 && requestedFrom < to ? requestedFrom : to - 24 * 3_600_000;
	setDateRangeInputs(from, to);
	persistDateRange();
}

function readDateRangeInputs() {
	const from = new Date(byId("dateFrom").value).getTime();
	const to = new Date(byId("dateTo").value).getTime();
	if (!Number.isFinite(from) || !Number.isFinite(to)) throw new Error("Select both From and To date/time values.");
	if (to - from < 60_000) throw new Error("The selected range must be at least one minute.");
	if (to - from > 366 * 24 * 3_600_000) throw new Error("The selected range cannot exceed 366 days.");
	return { from, to };
}

function truncate(value, length = 72) {
	const text = String(value ?? "");
	return text.length > length ? `${text.slice(0, length - 1)}...` : text;
}

function debounce(callback, delay = 300) {
	let timer;
	return (...args) => {
		clearTimeout(timer);
		timer = setTimeout(() => callback(...args), delay);
	};
}

function showToast(message, kind = "ok") {
	const toast = byId("toast");
	toast.textContent = message;
	toast.className = `toast ${kind}`;
	clearTimeout(showToast.timer);
	showToast.timer = setTimeout(() => toast.classList.add("hidden"), 3_500);
}

async function api(path, options = {}, siteScoped = true) {
	const target = new URL(`${ADMIN_API}${path}`, location.origin);
	if (siteScoped && selectedSiteId) target.searchParams.set("siteId", selectedSiteId);
	const response = await fetch(`${target.pathname}${target.search}`, {
		...options,
		headers: { ...mutationHeaders, ...(options.headers ?? {}) },
	});
	if (response.status === 401) {
		location.href = "/_burrowgate/admin/login";
		throw new Error("Unauthorized");
	}
	const data = await response.json();
	if (!response.ok) throw new Error(data.error ?? "Request failed");
	return data;
}

function queryString(parameters) {
	const search = new URLSearchParams();
	for (const [key, value] of Object.entries(parameters)) {
		if (value !== "" && value !== undefined && value !== null) search.set(key, String(value));
	}
	return search.toString();
}

function setTableLoading(id, columns) {
	byId(id).innerHTML = `<tr><td colspan="${columns}" class="empty-cell"><span class="spinner"></span> Loading...</td></tr>`;
}

function setTableError(id, columns, error) {
	byId(id).innerHTML = `<tr><td colspan="${columns}" class="empty-cell error-text">${escapeHtml(error.message)}</td></tr>`;
}

function updatePagination(prefix, result, load) {
	byId(`${prefix}Summary`).textContent =
		result.total === 0
			? "No records"
			: `${formatNumber((result.page - 1) * result.pageSize + 1)}-${formatNumber(Math.min(result.page * result.pageSize, result.total))} of ${formatNumber(result.total)}`;
	byId(`${prefix}Page`).textContent = `Page ${formatNumber(result.page)} of ${formatNumber(result.totalPages)}`;
	const previous = byId(`${prefix}Previous`);
	const next = byId(`${prefix}Next`);
	previous.disabled = result.page <= 1;
	next.disabled = result.page >= result.totalPages;
	previous.onclick = () => {
		if (result.page <= 1) return;
		tableState[prefix === "events" ? "traffic" : prefix].page = result.page - 1;
		void load();
	};
	next.onclick = () => {
		if (result.page >= result.totalPages) return;
		tableState[prefix === "events" ? "traffic" : prefix].page = result.page + 1;
		void load();
	};
}

function updateSortIndicators(panelId, state) {
	document.querySelectorAll(`#${panelId} .sort-button`).forEach((button) => {
		const indicator = button.querySelector("span");
		button.classList.toggle("selected", button.dataset.sort === state.sortBy);
		indicator.textContent = button.dataset.sort === state.sortBy ? (state.sortDirection === "asc" ? "\u2191" : "\u2193") : "";
	});
}

async function loadOverview() {
	const requestId = ++overviewRequestId;
	const selectedDuration = selectedRangeTo - selectedRangeFrom;
	const rangeLabel = rangeDurationLabel(selectedDuration);
	byId("requestsStatLabel").textContent = `Requests (${rangeLabel})`;
	byId("uniqueIpsStatLabel").textContent = `Unique IPs (${rangeLabel})`;
	byId("blockedStatLabel").textContent = `Blocked (${rangeLabel})`;
	byId("errorsStatLabel").textContent = `5xx errors (${rangeLabel})`;
	byId("latencyStatLabel").textContent = `Average latency (${rangeLabel})`;
	byId("challengesStatLabel").textContent = `Challenges (${rangeLabel})`;

	const overview = await api(`/overview?${queryString(rangeQuery())}`);
	if (requestId !== overviewRequestId) return;

	const formatted = {
		requests24h: formatNumber(overview.requests24h),
		uniqueIps24h: formatNumber(overview.uniqueIps24h),
		blocked24h: formatNumber(overview.blocked24h),
		errors24h: formatNumber(overview.errors24h),
		averageLatency24h: formatDuration(overview.averageLatency24h),
		challenges24h: formatNumber(overview.challenges24h),
		activeSessions: formatNumber(overview.activeSessions),
		activeRules: formatNumber(overview.activeRules),
	};
	for (const [id, value] of Object.entries(formatted)) byId(id).textContent = value;

	const resolvedRangeLabel = rangeDurationLabel(overview.rangeDurationMs ?? selectedDuration);
	byId("requestsStatLabel").textContent = `Requests (${resolvedRangeLabel})`;
	byId("uniqueIpsStatLabel").textContent = `Unique IPs (${resolvedRangeLabel})`;
	byId("blockedStatLabel").textContent = `Blocked (${resolvedRangeLabel})`;
	byId("errorsStatLabel").textContent = `5xx errors (${resolvedRangeLabel})`;
	byId("latencyStatLabel").textContent = `Average latency (${resolvedRangeLabel})`;
	byId("challengesStatLabel").textContent = `Challenges (${resolvedRangeLabel})`;
	byId("errorRate24h").textContent = `${Number(overview.errorRate24h ?? 0).toFixed(2)}% error rate`;
	byId("retentionNote").textContent =
		`Only the selected page is loaded. Request events are retained for ${overview.retentionDays} day${overview.retentionDays === 1 ? "" : "s"}.`;
	if (overview.site) {
		byId("siteDescription").textContent = `${overview.site.name} | ${overview.site.publicHost} -> ${overview.site.originUrl}`;
	}
	const defaultSize = String(overview.defaultPageSize ?? 50);
	for (const id of ["eventPageSize", "sessionPageSize", "rulePageSize"]) {
		const select = byId(id);
		if ([...select.options].some((option) => option.value === defaultSize)) select.value = defaultSize;
	}
	tableState.traffic.pageSize = Number(byId("eventPageSize").value);
	tableState.sessions.pageSize = Number(byId("sessionPageSize").value);
	tableState.rules.pageSize = Number(byId("rulePageSize").value);
}

function statusClass(status) {
	if (status >= 500) return "bad";
	if (status >= 400) return "warn";
	if (status >= 300) return "info";
	return "ok";
}

function decisionClass(decision) {
	if (["blocked", "route-blocked", "origin-error", "websocket-origin-error", "websocket-upgrade-failed"].includes(decision)) return "bad";
	if (["challenge-required", "websocket-disabled", "rate-limited"].includes(decision)) return "warn";
	if (["allowlisted", "websocket-allowlisted", "proxied-unprotected", "websocket-unprotected"].includes(decision)) return "info";
	return "ok";
}

function networkActionLabel(action) {
	return (
		{
			pass: "allow / route policy",
			allow: "allow / bypass",
			block: "block",
			challenge: "challenge",
		}[action] ?? String(action ?? "-")
	);
}

function countryBadge(codeInput) {
	const code = String(codeInput || "ZZ").toUpperCase();
	const name = countryDisplayName(code);
	return `<span class="country-badge" title="${escapeHtml(name)}" aria-label="${escapeHtml(name)}">${escapeHtml(code)}</span>`;
}

async function loadTraffic() {
	const state = tableState.traffic;
	setTableLoading("events", 8);
	updateSortIndicators("panel-traffic", state);
	try {
		const result = await api(
			`/events?${queryString({
				page: state.page,
				pageSize: state.pageSize,
				sortBy: state.sortBy,
				sortDirection: state.sortDirection,
				search: byId("eventSearch").value.trim(),
				decision: byId("eventDecision").value,
				method: byId("eventMethod").value,
				status: byId("eventStatus").value,
				country: byId("eventCountry").value,
				...rangeQuery(),
			})}`,
		);
		if (result.page > result.totalPages) {
			state.page = result.totalPages;
			return await loadTraffic();
		}
		byId("events").innerHTML =
			result.items.length === 0
				? '<tr><td colspan="8" class="empty-cell">No traffic matches these filters.</td></tr>'
				: result.items
						.map(
							(event) => `<tr>
          <td>${formatDate(event.created_at)}</td>
          <td><code title="${escapeHtml(`${event.ip} (${countryDisplayName(event.country_code || "ZZ")})`)}">${escapeHtml(event.ip)}</code></td>
          <td>${countryBadge(event.country_code)}</td>
          <td><span class="method-badge">${escapeHtml(event.method)}</span></td>
          <td class="path-cell" title="${escapeHtml(event.path)}">${escapeHtml(truncate(event.path))}</td>
          <td><span class="badge ${statusClass(Number(event.status))}">${Number(event.status)}</span></td>
          <td><span class="badge ${decisionClass(event.decision)}">${escapeHtml(event.decision)}</span></td>
          <td>${formatDuration(event.latency_ms)}</td>
        </tr>`,
						)
						.join("");
		updatePagination("events", result, loadTraffic);
	} catch (error) {
		setTableError("events", 8, error);
	}
}

function sessionState(session) {
	if (session.revoked_at !== null) return "revoked";
	if (Number(session.expires_at) <= Date.now()) return "expired";
	return "active";
}

async function loadSessions() {
	const state = tableState.sessions;
	setTableLoading("sessions", 9);
	updateSortIndicators("panel-sessions", state);
	try {
		const result = await api(
			`/sessions?${queryString({
				page: state.page,
				pageSize: state.pageSize,
				sortBy: state.sortBy,
				sortDirection: state.sortDirection,
				search: byId("sessionSearch").value.trim(),
				state: byId("sessionState").value,
				country: byId("sessionCountry").value,
				...rangeQuery(),
			})}`,
		);
		if (result.page > result.totalPages) {
			state.page = result.totalPages;
			return await loadSessions();
		}
		byId("sessions").innerHTML =
			result.items.length === 0
				? '<tr><td colspan="9" class="empty-cell">No sessions match these filters.</td></tr>'
				: result.items
						.map((session) => {
							const currentState = sessionState(session);
							return `<tr class="session-row ${currentState}">
          <td><span class="badge ${currentState === "active" ? "ok" : currentState === "expired" ? "warn" : "bad"}">${currentState}</span></td>
          <td><code title="${escapeHtml(session.id)}">${escapeHtml(truncate(session.id, 24))}</code></td>
          <td><code title="${escapeHtml(`${session.last_ip} (${countryDisplayName(session.country_code || "ZZ")})`)}">${escapeHtml(session.last_ip)}</code></td>
          <td>${countryBadge(session.country_code)}</td>
          <td>${formatDate(session.created_at)}</td>
          <td>${formatDate(session.last_seen_at)}</td>
          <td>${formatDate(session.expires_at)}</td>
          <td>${formatNumber(session.request_count)}</td>
          <td>${currentState === "active" ? `<button class="button danger compact" data-session-id="${escapeHtml(session.id)}">Revoke</button>` : "-"}</td>
        </tr>`;
						})
						.join("");
		updatePagination("sessions", result, loadSessions);
	} catch (error) {
		setTableError("sessions", 9, error);
	}
}

function ruleState(rule) {
	return rule.expires_at !== null && Number(rule.expires_at) <= Date.now() ? "expired" : "active";
}

async function loadRules() {
	const state = tableState.rules;
	if (!selectedSiteId) {
		byId("rules").innerHTML = '<tr><td colspan="7" class="empty-cell">Create or select a site before adding IP rules.</td></tr>';
		byId("countryRules").innerHTML = '<tr><td colspan="7" class="empty-cell">Create or select a site before adding country rules.</td></tr>';
		byId("saveNetworkDefaults").disabled = true;
		return;
	}
	byId("saveNetworkDefaults").disabled = false;
	setTableLoading("rules", 7);
	setTableLoading("countryRules", 7);
	updateSortIndicators("panel-rules", state);
	try {
		const [result, networkPolicy] = await Promise.all([
			api(
				`/rules?${queryString({
					page: state.page,
					pageSize: state.pageSize,
					sortBy: state.sortBy,
					sortDirection: state.sortDirection,
					search: byId("ruleSearch").value.trim(),
					action: byId("ruleAction").value,
					state: byId("ruleState").value,
				})}`,
			),
			api("/network-policy"),
		]);
		applyNetworkPolicy(networkPolicy);
		if (result.page > result.totalPages) {
			state.page = result.totalPages;
			return await loadRules();
		}
		byId("rules").innerHTML =
			result.items.length === 0
				? '<tr><td colspan="7" class="empty-cell">No IP rules match these filters.</td></tr>'
				: result.items
						.map((rule) => {
							const currentState = ruleState(rule);
							return `<tr class="rule-row ${currentState}">
          <td><span class="badge ${currentState === "active" ? "ok" : "warn"}">${currentState}</span></td>
          <td><code>${escapeHtml(rule.network_cidr)}</code></td>
          <td><span class="badge action-${escapeHtml(rule.action)}">${escapeHtml(networkActionLabel(rule.action))}</span></td>
          <td title="${escapeHtml(rule.reason)}">${escapeHtml(truncate(rule.reason || "-", 56))}</td>
          <td>${formatDate(rule.created_at)}</td>
          <td>${rule.expires_at === null ? "Never" : formatDate(rule.expires_at)}</td>
          <td><button class="button danger compact" data-rule-id="${escapeHtml(rule.id)}">Delete</button></td>
        </tr>`;
						})
						.join("");
		updatePagination("rules", result, loadRules);
	} catch (error) {
		setTableError("rules", 7, error);
		setTableError("countryRules", 7, error);
	}
}

function applyNetworkPolicy(policy) {
	byId("defaultIpAction").value = policy.defaultIpAction ?? "inherit";
	byId("defaultCountryAction").value = policy.defaultCountryAction ?? "inherit";
	countryRules = policy.countryRules ?? [];
	const warning = byId("geoPolicyWarning");
	if (!policy.geoip?.enabled) {
		warning.textContent = "GeoIP is disabled. Country rules are stored but not enforced until GeoIP is enabled.";
		warning.classList.remove("hidden");
	} else if (!policy.geoip.available) {
		warning.textContent = policy.geoip.error || "The GeoIP database is unavailable. Country policy fails open until it becomes available.";
		warning.classList.remove("hidden");
	} else {
		warning.classList.add("hidden");
	}
	renderCountryRules();
}

function renderCountryRules() {
	const body = byId("countryRules");
	if (!selectedSiteId) {
		body.innerHTML = '<tr><td colspan="7" class="empty-cell">Select a site before adding country rules.</td></tr>';
		return;
	}
	if (countryRules.length === 0) {
		body.innerHTML = '<tr><td colspan="7" class="empty-cell">No country rules are configured.</td></tr>';
		return;
	}
	body.innerHTML = countryRules
		.map((rule) => {
			const currentState = ruleState(rule);
			const code = String(rule.country_code || "ZZ").toUpperCase();
			return `<tr class="rule-row ${currentState}">
      <td><span class="badge ${currentState === "active" ? "ok" : "warn"}">${currentState}</span></td>
      <td>${countryBadge(code)} <span>${escapeHtml(countryDisplayName(code))}</span></td>
      <td><span class="badge action-${escapeHtml(rule.action)}">${escapeHtml(networkActionLabel(rule.action))}</span></td>
      <td title="${escapeHtml(rule.reason)}">${escapeHtml(truncate(rule.reason || "-", 56))}</td>
      <td>${formatDate(rule.created_at)}</td>
      <td>${rule.expires_at === null ? "Never" : formatDate(rule.expires_at)}</td>
      <td><button class="button danger compact" data-country-rule-id="${escapeHtml(rule.id)}">Delete</button></td>
    </tr>`;
		})
		.join("");
}

async function saveNetworkDefaults() {
	const result = await api("/network-policy", {
		method: "PUT",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({
			defaultIpAction: byId("defaultIpAction").value,
			defaultCountryAction: byId("defaultCountryAction").value,
		}),
	});
	const site = selectedSite();
	if (site) {
		site.defaultIpAction = result.defaultIpAction;
		site.defaultCountryAction = result.defaultCountryAction;
		renderSites();
	}
	showToast("Default network actions saved.");
	await Promise.all([loadOverview(), loadMetrics()]);
}

function defaultChallengePolicy() {
	return [{ provider: "pow-sha256", config: { difficulty: 18 } }];
}

function selectedSite() {
	return sites.find((site) => site.id === selectedSiteId) ?? null;
}

function persistSiteSelection() {
	const url = new URL(location.href);
	if (selectedSiteId) url.searchParams.set("site", selectedSiteId);
	else url.searchParams.delete("site");
	history.replaceState(null, "", `${url.pathname}${url.search}${url.hash}`);
}

function renderSiteSelector() {
	const selector = byId("siteSelector");
	selector.disabled = sites.length === 0;
	selector.innerHTML =
		sites.length === 0
			? '<option value="">No sites configured</option>'
			: sites
					.map(
						(site) =>
							`<option value="${escapeHtml(site.id)}"${site.id === selectedSiteId ? " selected" : ""}>${escapeHtml(site.name)}${site.enabled ? "" : " (disabled)"} | ${escapeHtml(site.publicHost)}</option>`,
					)
					.join("");
}

function renderErrorResponseOptions() {
	byId("errorPlaceholderList").innerHTML = (errorResponseDefaults.placeholders ?? [])
		.map(
			(placeholder) =>
				`<div class="placeholder-item"><code>&#123;&#123;${escapeHtml(placeholder.name)}&#125;&#125;</code><small>${escapeHtml(placeholder.description)}</small></div>`,
		)
		.join("");
	byId("errorJsonFieldList").innerHTML = (errorResponseDefaults.jsonFieldOptions ?? [])
		.map(
			(field) =>
				`<label class="json-field-option"><input type="checkbox" name="errorJsonField" value="${escapeHtml(field.name)}"><span><strong>${escapeHtml(field.label)}</strong><small>${escapeHtml(field.description)}</small></span></label>`,
		)
		.join("");
}

function renderChallengePlaceholders() {
	byId("challengePlaceholderList").innerHTML = (challengeDefaults.placeholders ?? [])
		.map(
			(placeholder) =>
				`<div class="placeholder-item"><code>&#123;&#123;${escapeHtml(placeholder.name)}&#125;&#125;</code><small>${escapeHtml(placeholder.description)}</small></div>`,
		)
		.join("");
}

function selectedErrorJsonFields() {
	return [...document.querySelectorAll('input[name="errorJsonField"]:checked')].map((input) => input.value);
}

function setErrorJsonFields(fields) {
	const selected = new Set(fields ?? []);
	document.querySelectorAll('input[name="errorJsonField"]').forEach((input) => {
		input.checked = selected.has(input.value);
	});
}

function updateErrorResponseControls() {
	const htmlMode = byId("siteErrorResponseMode").value === "html";
	byId("siteErrorHtmlSettings").classList.toggle("hidden", !htmlMode);
	byId("siteErrorJsonSettings").classList.toggle("hidden", htmlMode);
}

function renderSites() {
	const container = byId("sitesList");
	if (sites.length === 0) {
		container.innerHTML = '<div class="empty-state-inline">No sites are configured. Create the first protected site.</div>';
		return;
	}
	container.innerHTML = sites
		.map(
			(site) => `<div class="site-list-item ${site.id === selectedSiteId ? "selected" : ""} ${site.enabled ? "" : "disabled"}">
    <div>
      <div class="site-list-title"><strong>${escapeHtml(site.name)}</strong><span class="badge ${site.enabled ? "ok" : "warn"}">${site.enabled ? "enabled" : "disabled"}</span></div>
      <div class="site-list-meta"><code>${escapeHtml(site.publicHost)}</code><span>Origin: ${escapeHtml(site.originUrl)}</span><span>Default: ${site.defaultAccessMode === "bypass" ? "unprotected" : "challenge"} | Session: ${formatDuration(Number(site.sessionTtlSeconds) * 1_000)} | Traffic: ${formatNumber(site.eventRetentionDays)} day${Number(site.eventRetentionDays) === 1 ? "" : "s"} | IP default: ${escapeHtml(site.defaultIpAction ?? "inherit")} | Country default: ${escapeHtml(site.defaultCountryAction ?? "inherit")} | Errors: ${escapeHtml(site.errorResponse?.mode ?? "json")} | ${formatNumber(site.challengePolicy.length)} challenge step${site.challengePolicy.length === 1 ? "" : "s"}</span></div>
    </div>
    <div class="site-list-actions"><button class="button secondary compact" type="button" data-site-select="${escapeHtml(site.id)}">Use</button><button class="button secondary compact" type="button" data-site-edit="${escapeHtml(site.id)}">Edit</button></div>
  </div>`,
		)
		.join("");
}

function resetSiteForm() {
	editingSiteId = null;
	byId("siteForm").reset();
	byId("siteId").value = "";
	byId("siteSessionTtl").value = "43200";
	byId("siteEventRetentionDays").value = String(defaultEventRetentionDays);
	byId("siteEnabled").checked = true;
	byId("siteDefaultAccessMode").value = "challenge";
	byId("siteChallengePolicy").value = JSON.stringify(defaultChallengePolicy(), null, 2);
	byId("siteErrorResponseMode").value = errorResponseDefaults.mode ?? "json";
	byId("siteErrorHtmlTemplate").value = errorResponseDefaults.htmlTemplate ?? "";
	setErrorJsonFields(errorResponseDefaults.jsonFields ?? []);
	updateErrorResponseControls();
	byId("siteChallengeHtmlTemplate").value = challengeDefaults.htmlTemplate ?? "";
	byId("siteSigningSecret").value = "";
	byId("siteSigningSecret").type = "password";
	byId("siteFormTitle").textContent = "Create site";
	byId("siteFormSubtitle").textContent = "Add another hostname and origin to BurrowGate.";
	byId("siteSecretHelp").textContent = "Leave blank to generate a secure secret. The generated value is shown once after creation.";
	byId("saveSite").textContent = "Create";
	byId("cancelSiteEdit").classList.add("hidden");
	byId("generatedSecretPanel").classList.add("hidden");
	byId("siteTlsPanel").classList.add("hidden");
	currentTls = null;
}

function editSite(id) {
	const site = sites.find((item) => item.id === id);
	if (!site) return;
	editingSiteId = site.id;
	byId("siteId").value = site.id;
	byId("siteName").value = site.name;
	byId("sitePublicHost").value = site.publicHost;
	byId("siteOriginUrl").value = site.originUrl;
	byId("siteSessionTtl").value = String(site.sessionTtlSeconds);
	byId("siteEventRetentionDays").value = String(site.eventRetentionDays ?? defaultEventRetentionDays);
	byId("siteEnabled").checked = Boolean(site.enabled);
	byId("siteDefaultAccessMode").value = site.defaultAccessMode ?? "challenge";
	byId("siteSigningSecret").value = "";
	byId("siteChallengePolicy").value = JSON.stringify(site.challengePolicy, null, 2);
	byId("siteErrorResponseMode").value = site.errorResponse?.mode ?? "json";
	byId("siteErrorHtmlTemplate").value = site.errorResponse?.htmlTemplate ?? errorResponseDefaults.htmlTemplate ?? "";
	setErrorJsonFields(site.errorResponse?.jsonFields ?? errorResponseDefaults.jsonFields ?? []);
	updateErrorResponseControls();
	byId("siteChallengeHtmlTemplate").value = site.challengePage?.htmlTemplate ?? challengeDefaults.htmlTemplate ?? "";
	byId("siteFormTitle").textContent = `Edit ${site.name}`;
	byId("siteFormSubtitle").textContent = "Changes apply to new requests immediately. Existing session expiration timestamps are unchanged.";
	byId("siteSecretHelp").textContent = "Leave blank to keep the current secret, or enter a new value to rotate it.";
	byId("saveSite").textContent = "Save changes";
	byId("cancelSiteEdit").classList.remove("hidden");
	byId("generatedSecretPanel").classList.add("hidden");
	byId("siteTlsPanel").classList.remove("hidden");
	byId("siteName").focus();
	void loadSiteTls(site.id);
}

function randomSecret(bytes = 48) {
	const data = new Uint8Array(bytes);
	crypto.getRandomValues(data);
	let binary = "";
	for (const value of data) binary += String.fromCharCode(value);
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

async function loadSites() {
	const response = await api("/sites", {}, false);
	sites = response.items ?? [];
	challengeProviders = response.challengeProviders ?? [];
	defaultEventRetentionDays = Number(response.defaultEventRetentionDays ?? 7);
	const firstErrorOptionsLoad = !errorResponseOptionsLoaded;
	const previousErrorJsonFields = errorResponseOptionsLoaded ? selectedErrorJsonFields() : null;
	errorResponseDefaults = response.errorResponseDefaults ?? errorResponseDefaults;
	renderErrorResponseOptions();
	challengeDefaults = response.challengeDefaults ?? challengeDefaults;
	renderChallengePlaceholders();
	errorResponseOptionsLoaded = true;
	if (firstErrorOptionsLoad && !editingSiteId) resetSiteForm();
	else if (previousErrorJsonFields) setErrorJsonFields(previousErrorJsonFields);
	const requestedId = new URL(location.href).searchParams.get("site");
	const currentExists = sites.some((site) => site.id === selectedSiteId);
	const requestedExists = sites.some((site) => site.id === requestedId);
	if (!currentExists) selectedSiteId = requestedExists ? requestedId : (sites.find((site) => site.enabled)?.id ?? sites[0]?.id ?? null);
	persistSiteSelection();
	renderSiteSelector();
	renderSites();
	const providerText = challengeProviders.length
		? challengeProviders.map((provider) => `${provider.name} (${provider.title})`).join(", ")
		: "No challenge providers are registered";
	byId("challengeProviderHelp").textContent = `Ordered JSON array. Available providers: ${providerText}.`;
	byId("routeChallengeHelp").textContent = `Leave blank to inherit the site chain. Available providers: ${providerText}.`;
	return response;
}

function resetSiteScopedPages() {
	tableState.traffic.page = 1;
	tableState.sessions.page = 1;
	tableState.rules.page = 1;
	latestMetrics = null;
	routePolicies = [];
	countryRules = [];
	resetRoutePolicyForm();
}

async function reloadSelectedSite() {
	resetSiteScopedPages();
	for (const name of ["sessions", "rules", "routes"]) loadedTabs.delete(name);
	const tasks = [loadOverview(), loadMetrics(), loadGeoMetrics(), loadTraffic()];
	if (activeTab === "sessions") {
		loadedTabs.add("sessions");
		tasks.push(loadSessions());
	}
	if (activeTab === "rules") {
		loadedTabs.add("rules");
		tasks.push(loadRules());
	}
	if (activeTab === "routes") {
		loadedTabs.add("routes");
		tasks.push(loadRoutePolicies());
	}
	await Promise.all(tasks);
	renderSites();
	markUpdated("Site changed");
}

async function chooseSite(id) {
	if (!sites.some((site) => site.id === id) || selectedSiteId === id) return;
	selectedSiteId = id;
	persistSiteSelection();
	renderSiteSelector();
	await reloadSelectedSite();
}

async function saveSite(event) {
	event.preventDefault();
	const submit = byId("saveSite");
	submit.disabled = true;
	byId("generatedSecretPanel").classList.add("hidden");
	let challengePolicy;
	try {
		challengePolicy = JSON.parse(byId("siteChallengePolicy").value);
	} catch {
		showToast("Challenge policy must be valid JSON.", "bad");
		submit.disabled = false;
		return;
	}
	const errorResponseMode = byId("siteErrorResponseMode").value;
	const errorJsonFields = selectedErrorJsonFields();
	if (errorResponseMode === "json" && errorJsonFields.length === 0) {
		showToast("Select at least one JSON error field.", "bad");
		submit.disabled = false;
		return;
	}
	if (errorResponseMode === "html" && !byId("siteErrorHtmlTemplate").value.trim()) {
		showToast("HTML error template cannot be empty.", "bad");
		submit.disabled = false;
		return;
	}
	const payload = {
		name: byId("siteName").value.trim(),
		publicHost: byId("sitePublicHost").value.trim(),
		originUrl: byId("siteOriginUrl").value.trim(),
		enabled: byId("siteEnabled").checked,
		defaultAccessMode: byId("siteDefaultAccessMode").value,
		sessionTtlSeconds: Number(byId("siteSessionTtl").value),
		eventRetentionDays: Number(byId("siteEventRetentionDays").value),
		challengePolicy,
		originSigningSecret: byId("siteSigningSecret").value.trim(),
		errorResponseMode,
		errorHtmlTemplate: byId("siteErrorHtmlTemplate").value,
		errorJsonFields,
		challengeHtmlTemplate: byId("siteChallengeHtmlTemplate").value,
	};
	try {
		const editing = Boolean(editingSiteId);
		const result = await api(
			editing ? `/sites/${encodeURIComponent(editingSiteId)}` : "/sites",
			{
				method: editing ? "PUT" : "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify(payload),
			},
			false,
		);
		const savedId = result.site.id;
		selectedSiteId = savedId;
		await loadSites();
		editSite(savedId);
		if (result.generatedSigningSecret) {
			byId("generatedSecretValue").textContent = result.generatedSigningSecret;
			byId("generatedSecretPanel").classList.remove("hidden");
		}
		await reloadSelectedSite();
		showToast(editing ? "Site updated." : "Site created.");
	} catch (error) {
		showToast(error.message, "bad");
	} finally {
		submit.disabled = false;
	}
}

function routeAccessLabel(mode) {
	return { inherit: "inherit", challenge: "challenge", bypass: "unprotected", block: "blocked" }[mode] ?? mode;
}

function formatRateLimit(policy) {
	if (!policy.rateLimit?.enabled) return "No rate limit";
	if (policy.rateLimit.algorithm === "token-bucket") {
		return `${formatNumber(policy.rateLimit.max)} burst | +${formatNumber(policy.rateLimit.refillRate)} every ${formatDuration(policy.rateLimit.refillIntervalMs)}`;
	}
	return `${formatNumber(policy.rateLimit.max)} / ${formatDuration(policy.rateLimit.windowMs)}`;
}

function renderRoutePolicies() {
	const container = byId("routePolicyList");
	if (!selectedSiteId) {
		container.innerHTML = '<div class="empty-state-inline">Create or select a site before adding route policies.</div>';
		return;
	}
	if (routePolicies.length === 0) {
		container.innerHTML = '<div class="empty-state-inline">No route policies. The site default applies to every request.</div>';
		return;
	}
	container.innerHTML = routePolicies
		.map(
			(policy) => `<div class="route-policy-item ${policy.enabled ? "" : "disabled"}">
    <div class="route-policy-main">
      <div class="site-list-title"><strong>${escapeHtml(policy.name)}</strong><span class="badge ${policy.enabled ? "ok" : "warn"}">${policy.enabled ? "enabled" : "disabled"}</span><span class="badge ${policy.accessMode === "block" ? "bad" : policy.accessMode === "challenge" ? "warn" : "info"}">${escapeHtml(routeAccessLabel(policy.accessMode))}</span></div>
      <div class="route-policy-pattern"><code>${escapeHtml(policy.pathPattern)}</code><span>${policy.methods.length ? escapeHtml(policy.methods.join(", ")) : "All methods"}</span><span>Priority ${formatNumber(policy.priority)}</span></div>
      <div class="site-list-meta"><span>${escapeHtml(formatRateLimit(policy))}</span><span>${escapeHtml(policy.rateLimit?.keyMode ?? "ip")} | ${escapeHtml(policy.rateLimit?.scope ?? "policy")}</span>${policy.challengePolicy ? `<span>${formatNumber(policy.challengePolicy.length)} custom challenge step${policy.challengePolicy.length === 1 ? "" : "s"}</span>` : ""}</div>
    </div>
    <div class="site-list-actions"><button class="button secondary compact" type="button" data-route-edit="${escapeHtml(policy.id)}">Edit</button><button class="button danger compact" type="button" data-route-delete="${escapeHtml(policy.id)}">Delete</button></div>
  </div>`,
		)
		.join("");
}

function updateRoutePolicyControls() {
	const rateEnabled = byId("routeRateEnabled").checked;
	byId("routeRateSettings").classList.toggle("hidden", !rateEnabled);
	const algorithm = byId("routeRateAlgorithm").value;
	document.querySelectorAll(".token-setting").forEach((element) => element.classList.toggle("hidden", algorithm !== "token-bucket"));
	document.querySelectorAll(".window-setting").forEach((element) => element.classList.toggle("hidden", algorithm === "token-bucket"));
	document.querySelectorAll(".precision-setting").forEach((element) => element.classList.toggle("hidden", algorithm !== "sliding-window"));
	byId("routeRateHeaderField").classList.toggle("hidden", byId("routeRateKeyMode").value !== "header-or-ip");
	byId("routeChallengeSettings").classList.toggle("hidden", byId("routePolicyAccessMode").value !== "challenge");
}

function resetRoutePolicyForm() {
	editingRoutePolicyId = null;
	byId("routePolicyForm").reset();
	byId("routePolicyId").value = "";
	byId("routePolicyPath").value = "/api/**";
	byId("routePolicyPriority").value = "0";
	byId("routePolicyAccessMode").value = "inherit";
	byId("routePolicyEnabled").checked = true;
	byId("routePolicyChallenge").value = "";
	byId("routeRateEnabled").checked = false;
	byId("routeRateAlgorithm").value = "sliding-window";
	byId("routeRateMax").value = "120";
	byId("routeRateWindow").value = "60000";
	byId("routeRatePrecision").value = "100";
	byId("routeRateRefillRate").value = "10";
	byId("routeRateRefillInterval").value = "1000";
	byId("routeRateKeyMode").value = "ip";
	byId("routeRateKeyHeader").value = "";
	byId("routeRateScope").value = "policy";
	byId("routePolicyFormTitle").textContent = "Create route policy";
	byId("routePolicyFormSubtitle").textContent = "Configure route-specific verification and API limits.";
	byId("saveRoutePolicy").textContent = "Create";
	byId("cancelRoutePolicyEdit").classList.add("hidden");
	updateRoutePolicyControls();
}

function editRoutePolicy(id) {
	const policy = routePolicies.find((item) => item.id === id);
	if (!policy) return;
	editingRoutePolicyId = policy.id;
	byId("routePolicyId").value = policy.id;
	byId("routePolicyName").value = policy.name;
	byId("routePolicyPath").value = policy.pathPattern;
	byId("routePolicyMethods").value = policy.methods.join(", ");
	byId("routePolicyPriority").value = String(policy.priority);
	byId("routePolicyAccessMode").value = policy.accessMode;
	byId("routePolicyEnabled").checked = Boolean(policy.enabled);
	byId("routePolicyChallenge").value = policy.challengePolicy ? JSON.stringify(policy.challengePolicy, null, 2) : "";
	byId("routeRateEnabled").checked = Boolean(policy.rateLimit.enabled);
	byId("routeRateAlgorithm").value = policy.rateLimit.algorithm;
	byId("routeRateMax").value = String(policy.rateLimit.max);
	byId("routeRateWindow").value = String(policy.rateLimit.windowMs);
	byId("routeRatePrecision").value = String(policy.rateLimit.precisionMs);
	byId("routeRateRefillRate").value = String(policy.rateLimit.refillRate);
	byId("routeRateRefillInterval").value = String(policy.rateLimit.refillIntervalMs);
	byId("routeRateKeyMode").value = policy.rateLimit.keyMode;
	byId("routeRateKeyHeader").value = policy.rateLimit.keyHeader ?? "";
	byId("routeRateScope").value = policy.rateLimit.scope;
	byId("routePolicyFormTitle").textContent = `Edit ${policy.name}`;
	byId("routePolicyFormSubtitle").textContent = "Changes affect new requests immediately; in-memory counters reset when the limiter configuration changes.";
	byId("saveRoutePolicy").textContent = "Save policy";
	byId("cancelRoutePolicyEdit").classList.remove("hidden");
	updateRoutePolicyControls();
	byId("routePolicyName").focus();
}

async function loadRoutePolicies() {
	if (!selectedSiteId) {
		routePolicies = [];
		renderRoutePolicies();
		return;
	}
	byId("routePolicyList").innerHTML = '<div class="empty-state-inline"><span class="spinner"></span> Loading route policies...</div>';
	try {
		const response = await api("/route-policies");
		routePolicies = response.items ?? [];
		renderRoutePolicies();
	} catch (error) {
		byId("routePolicyList").innerHTML = `<div class="empty-state-inline error-text">${escapeHtml(error.message)}</div>`;
	}
}

async function saveRoutePolicy(event) {
	event.preventDefault();
	const submit = byId("saveRoutePolicy");
	submit.disabled = true;
	let challengePolicy = null;
	const challengeText = byId("routePolicyChallenge").value.trim();
	if (challengeText) {
		try {
			challengePolicy = JSON.parse(challengeText);
		} catch {
			showToast("Route challenge policy must be valid JSON.", "bad");
			submit.disabled = false;
			return;
		}
	}
	const payload = {
		name: byId("routePolicyName").value.trim(),
		pathPattern: byId("routePolicyPath").value.trim(),
		methods: byId("routePolicyMethods").value,
		priority: Number(byId("routePolicyPriority").value),
		accessMode: byId("routePolicyAccessMode").value,
		enabled: byId("routePolicyEnabled").checked,
		challengePolicy,
		rateLimitEnabled: byId("routeRateEnabled").checked,
		rateLimitAlgorithm: byId("routeRateAlgorithm").value,
		rateLimitMax: Number(byId("routeRateMax").value),
		rateLimitWindowMs: Number(byId("routeRateWindow").value),
		rateLimitPrecisionMs: Number(byId("routeRatePrecision").value),
		rateLimitRefillRate: Number(byId("routeRateRefillRate").value),
		rateLimitRefillIntervalMs: Number(byId("routeRateRefillInterval").value),
		rateLimitKeyMode: byId("routeRateKeyMode").value,
		rateLimitKeyHeader: byId("routeRateKeyHeader").value.trim(),
		rateLimitScope: byId("routeRateScope").value,
	};
	try {
		const editing = Boolean(editingRoutePolicyId);
		const response = await api(editing ? `/route-policies/${encodeURIComponent(editingRoutePolicyId)}` : "/route-policies", {
			method: editing ? "PUT" : "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(payload),
		});
		await Promise.all([loadRoutePolicies(), loadMetrics()]);
		editRoutePolicy(response.policy.id);
		showToast(editing ? "Route policy updated." : "Route policy created.");
	} catch (error) {
		showToast(error.message, "bad");
	} finally {
		submit.disabled = false;
	}
}

function certificateStatusClass(certificate) {
	if (!certificate) return "";
	if (certificate.status === "active" && Number(certificate.expiresAt) > Date.now()) return "ok";
	if (certificate.status === "renewal-failed") return "warn";
	return "bad";
}

function renderTls(data) {
	currentTls = data;
	const settings = data.settings;
	const certificate = data.certificate;
	byId("tlsMode").value = settings.mode;
	byId("tlsForceHttps").checked = Boolean(settings.forceHttps);
	byId("acmeEmail").value = settings.acmeEmail ?? data.defaults.acmeEmail ?? "";
	byId("acmeDirectoryUrl").value = settings.acmeDirectoryUrl ?? data.defaults.acmeDirectoryUrl;
	byId("acmeForceHttps").checked = Boolean(settings.forceHttps || !certificate);
	byId("uploadedForceHttps").checked = Boolean(settings.forceHttps);

	byId("tlsSummaryMode").textContent = settings.mode === "letsencrypt" ? "Let's Encrypt" : settings.mode === "uploaded" ? "Uploaded" : "Disabled";
	byId("tlsSummaryCertificate").textContent = certificate ? `${certificate.source} | ${certificate.status}` : "None";
	byId("tlsSummaryExpires").textContent = certificate?.expiresAt ? formatDate(certificate.expiresAt) : "-";
	byId("tlsSummaryIssuer").textContent = certificate?.issuer || "-";
	const badge = byId("tlsStatusBadge");
	badge.className = `badge ${certificateStatusClass(certificate)}`;
	badge.textContent = certificate ? certificate.status : "Not configured";
	byId("tlsLastError").textContent = certificate?.lastError || "";
	byId("tlsLastError").classList.toggle("hidden", !certificate?.lastError);
	byId("renewAcmeCertificate").classList.toggle("hidden", certificate?.source !== "letsencrypt");
	byId("removeCertificate").classList.toggle("hidden", !certificate);

	const bootstrapState =
		data.listener.bootstrapTlsEnabled && !certificate
			? " A temporary self-signed bootstrap certificate is active until a managed certificate is installed."
			: "";
	const httpsState = data.listener.httpsEnabled
		? `HTTPS listener: internal port ${data.listener.httpsPort}, public port ${data.listener.publicHttpsPort}.${bootstrapState}`
		: "HTTPS listener is disabled. Set BG_HTTPS_ENABLED=true and restart BurrowGate before activating a certificate.";
	const httpState = data.listener.httpEnabled
		? ` HTTP listener: internal port ${data.listener.httpPort}, public port ${data.listener.publicHttpPort}.`
		: " HTTP is disabled; HTTP-01 issuance cannot work.";
	byId("tlsListenerNotice").textContent = `${httpsState}${httpState}`;

	const directory = byId("acmeDirectoryUrl").value;
	byId("acmeEnvironmentWarning").textContent = directory.includes("staging")
		? "Staging mode: the issued certificate will not be trusted by browsers. Use this while testing ACME integration."
		: "Production ACME directory selected. Failed or repeated orders can consume provider rate limits.";

	const events = data.events ?? [];
	byId("certificateEvents").innerHTML =
		events.length === 0
			? '<p class="muted">No certificate activity yet.</p>'
			: events
					.map(
						(event) =>
							`<div class="certificate-event"><span class="badge ${event.level === "error" ? "bad" : event.level === "warning" ? "warn" : "ok"}">${escapeHtml(event.level)}</span><div>${escapeHtml(event.message)}</div><time class="muted">${formatDate(event.createdAt)}</time></div>`,
					)
					.join("");
}

async function loadSiteTls(siteId = editingSiteId) {
	if (!siteId) return;
	byId("siteTlsPanel").classList.remove("hidden");
	const data = await api(`/sites/${encodeURIComponent(siteId)}/tls`, {}, false);
	if (editingSiteId === siteId) renderTls(data);
}

async function saveTlsSettings(event) {
	event.preventDefault();
	if (!editingSiteId) return;
	const button = byId("saveTlsSettings");
	await runWithButton(button, async () => {
		const data = await api(
			`/sites/${encodeURIComponent(editingSiteId)}/tls`,
			{
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ mode: byId("tlsMode").value, forceHttps: byId("tlsForceHttps").checked }),
			},
			false,
		);
		renderTls(data);
		showToast("HTTPS settings saved.");
	});
}

async function requestAcmeCertificate(event) {
	event.preventDefault();
	if (!editingSiteId) return;
	const button = byId("requestAcmeCertificate");
	await runWithButton(button, async () => {
		const data = await api(
			`/sites/${encodeURIComponent(editingSiteId)}/certificate/letsencrypt`,
			{
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					email: byId("acmeEmail").value.trim(),
					directoryUrl: byId("acmeDirectoryUrl").value.trim(),
					forceHttps: byId("acmeForceHttps").checked,
					termsAccepted: byId("acmeTermsAccepted").checked,
				}),
			},
			false,
		);
		renderTls(data);
		byId("acmeTermsAccepted").checked = false;
		showToast("Certificate issued and HTTPS listener reloaded.");
	});
}

async function uploadCertificate(event) {
	event.preventDefault();
	if (!editingSiteId) return;
	const button = byId("uploadCertificate");
	await runWithButton(button, async () => {
		const data = await api(
			`/sites/${encodeURIComponent(editingSiteId)}/certificate/upload`,
			{
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					certificatePem: byId("uploadedCertificatePem").value,
					privateKeyPem: byId("uploadedPrivateKeyPem").value,
					forceHttps: byId("uploadedForceHttps").checked,
				}),
			},
			false,
		);
		renderTls(data);
		byId("uploadedCertificatePem").value = "";
		byId("uploadedPrivateKeyPem").value = "";
		showToast("Certificate uploaded and activated.");
	});
}

async function renewAcmeCertificate() {
	if (!editingSiteId) return;
	const button = byId("renewAcmeCertificate");
	await runWithButton(button, async () => {
		const data = await api(`/sites/${encodeURIComponent(editingSiteId)}/certificate/renew`, { method: "POST" }, false);
		renderTls(data);
		showToast("Certificate renewed.");
	});
}

async function removeCertificate() {
	if (!editingSiteId || !confirm("Remove this site's certificate and disable HTTPS for it?")) return;
	const button = byId("removeCertificate");
	await runWithButton(button, async () => {
		const data = await api(`/sites/${encodeURIComponent(editingSiteId)}/certificate`, { method: "DELETE" }, false);
		renderTls(data);
		showToast("Certificate removed.");
	});
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
			value("--chart-series-5", "#22c55e"),
			value("--chart-series-6", "#eab308"),
			value("--chart-series-7", "#ec4899"),
			value("--chart-series-8", "#64748b"),
		],
	};
}

function metricLabel(bucket, rangeDurationMs, detailed = false) {
	const date = new Date(Number(bucket));
	if (Number(rangeDurationMs) >= 24 * 3_600_000 || detailed) {
		return date.toLocaleString([], {
			month: "short",
			day: "numeric",
			hour: "2-digit",
			minute: "2-digit",
		});
	}
	return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function metricValueFormatter(format) {
	if (format === "duration") return (value) => formatDuration(Number(value));
	return (value) => formatNumber(Math.round(Number(value)));
}

function chartColor(key, index, theme) {
	const semantic = {
		requests: 0,
		created: 0,
		verified: 0,
		allow: 4,
		active: 4,
		averageLatency: 3,
		bypassed: 3,
		challenge: 1,
		challenged: 1,
		expired: 1,
		blocked: 2,
		block: 2,
		revoked: 2,
		errors: 2,
		rateLimited: 5,
	};
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

function barDataset(definition, index, points, theme, datasetCount) {
	const color = chartColor(definition.key, index, theme);
	return {
		label: definition.label,
		data: points.map((point) => Number(point[definition.key] ?? 0)),
		backgroundColor: datasetCount === 1 ? points.map((_, pointIndex) => theme.palette[pointIndex % theme.palette.length]) : color,
		borderColor: datasetCount === 1 ? points.map((_, pointIndex) => theme.palette[pointIndex % theme.palette.length]) : color,
		borderWidth: 1,
		borderRadius: 5,
		maxBarThickness: 52,
	};
}

function chartOptions(definition, formatter) {
	const theme = chartTheme();
	const showLegend = definition.datasets.length > 1;
	return {
		responsive: true,
		resizeDelay: 150,
		animation: false,
		normalized: true,
		interaction: { mode: definition.timeSeries ? "index" : "nearest", intersect: false },
		plugins: {
			legend: {
				display: showLegend,
				position: "bottom",
				labels: {
					color: theme.text,
					usePointStyle: true,
					pointStyle: definition.type === "line" ? "line" : "rectRounded",
					boxWidth: 18,
					boxHeight: 3,
					padding: 18,
				},
			},
			tooltip: {
				enabled: true,
				mode: definition.timeSeries ? "index" : "nearest",
				intersect: false,
				callbacks: {
					title(items) {
						const item = items[0];
						const point = definition.data[item.dataIndex];
						if (definition.timeSeries && point?.bucket !== undefined) {
							return metricLabel(point.bucket, Number(latestMetrics?.rangeDurationMs ?? selectedRangeTo - selectedRangeFrom), true);
						}
						return String(point?.label ?? item.label ?? "");
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
					maxTicksLimit: definition.timeSeries && Number(latestMetrics?.rangeDurationMs ?? selectedRangeTo - selectedRangeFrom) <= 3_600_000 ? 6 : 8,
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
	const normalized = {
		...definition,
		datasets: [...(definition.datasets ?? [])],
		data: (definition.data ?? []).map((point) => ({ ...point })),
	};

	if (normalized.datasets.length === 0) {
		normalized.datasets.push({ key: "value", label: "No data" });
	}

	if (normalized.data.length === 0) {
		if (normalized.timeSeries) {
			const bucketMs = Number(latestMetrics?.bucketMs ?? 60_000);
			const bucketCount = Math.max(1, Number(latestMetrics?.bucketCount ?? 1));
			const endBucket = Math.floor(selectedRangeTo / bucketMs) * bucketMs;
			normalized.data = Array.from({ length: bucketCount }, (_, index) => ({
				bucket: endBucket - (bucketCount - index - 1) * bucketMs,
			}));
		} else {
			normalized.data = [{ label: "No data" }];
		}
	}

	for (const point of normalized.data) {
		for (const dataset of normalized.datasets) {
			if (!Number.isFinite(Number(point[dataset.key]))) point[dataset.key] = 0;
		}
	}

	return normalized;
}

const dateRangeSelectionPlugin = {
	id: "burrowgateDateRangeSelection",
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
		const bucketMs = Number(latestMetrics?.bucketMs ?? 60_000);
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
	const labels = definition.data.map((point) =>
		definition.timeSeries
			? metricLabel(point.bucket, Number(latestMetrics?.rangeDurationMs ?? selectedRangeTo - selectedRangeFrom))
			: String(point.label ?? ""),
	);
	const datasets = definition.datasets.map((dataset, index) =>
		definition.type === "bar"
			? barDataset(dataset, index, definition.data, theme, definition.datasets.length)
			: lineDataset(dataset, index, definition.data, theme),
	);
	const chart = new window.Chart(byId(canvasId), {
		type: definition.type,
		data: { labels, datasets },
		options: chartOptions(definition, formatter),
		plugins: [dateRangeSelectionPlugin],
	});
	attachDateRangeSelection(chart, definition);
	return chart;
}

function renderBreakdown(items) {
	const container = byId("decisionBreakdown");
	if (!items || items.length === 0) {
		container.innerHTML = "";
		container.classList.add("hidden");
		return;
	}
	container.classList.remove("hidden");
	const total = items.reduce((sum, item) => sum + Number(item.count), 0);
	if (total === 0) {
		container.innerHTML = '<p class="muted">No summary data is available.</p>';
		return;
	}
	container.innerHTML = items
		.slice(0, 6)
		.map((item) => {
			const percentage = Math.max(1, (Number(item.count) / total) * 100);
			return `<div class="breakdown-row"><div class="row between"><span>${escapeHtml(item.label)}</span><strong>${formatNumber(item.count)}</strong></div><div class="breakdown-track"><div style="width:${percentage}%"></div></div></div>`;
		})
		.join("");
}

function renderMetrics() {
	if (!latestMetrics?.primary || !latestMetrics?.secondary) return;
	const primary = normalizeChartDefinition(latestMetrics.primary);
	const secondary = normalizeChartDefinition(latestMetrics.secondary);

	byId("primaryChartTitle").textContent = primary.title;
	byId("primaryChartSubtitle").textContent = primary.subtitle;
	byId("secondaryChartTitle").textContent = secondary.title;
	byId("secondaryChartSubtitle").textContent = secondary.subtitle;
	byId("trafficEmpty").classList.add("hidden");
	byId("latencyEmpty").classList.add("hidden");
	byId("trafficChart").classList.remove("hidden");
	byId("latencyChart").classList.remove("hidden");

	trafficChart?.destroy();
	latencyChart?.destroy();
	trafficChart = createChart("trafficChart", primary);
	latencyChart = createChart("latencyChart", secondary);
	renderBreakdown(latestMetrics.breakdown ?? []);
}

async function loadMetrics() {
	const section = activeTab;
	try {
		const result = await api(
			`/metrics?${queryString({
				...rangeQuery(),
				section,
			})}`,
			{},
			section !== "sites",
		);
		if (activeTab !== section) return;
		latestMetrics = result;
		renderMetrics();
	} catch (error) {
		showToast(error.message, "bad");
	}
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
	const configurations = [
		["eventCountry", "All countries"],
		["sessionCountry", "All countries"],
		["countryRuleCountry", "Select country"],
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

function renderGeoMap() {
	if (!geoMapGeometry || !geoMetrics) return;
	const mode = byId("geoMetricMode").value;
	const items = geoMetrics[mode] ?? [];
	const values = new Map(items.map((item) => [String(item.countryCode).toUpperCase(), Number(item.count)]));
	const maximum = Math.max(0, ...items.filter((item) => item.countryCode !== "ZZ").map((item) => Number(item.count)));
	const total = items.reduce((sum, item) => sum + Number(item.count), 0);
	const rangeLabel = rangeDurationLabel(geoMetrics.rangeDurationMs ?? selectedRangeTo - selectedRangeFrom);
	const unit = mode === "sessions" ? "sessions" : "requests";
	byId("geoSubtitle").textContent = `${mode === "sessions" ? "Sessions created" : "Requests"} by country (${rangeLabel})`;
	byId("geoTotal").textContent = `${formatNumber(total)} ${unit}`;

	const svg = byId("geoMap");
	svg.setAttribute("aria-label", `World map showing ${unit} by country`);
	for (const [code, path] of geoMapGeometry.paths) {
		const value = values.get(code) ?? 0;
		const name = path.dataset.name ?? countryDisplayName(code);
		path.setAttribute("class", `geo-country geo-level-${geoLevel(value, maximum)}`);
		path.setAttribute("tabindex", value > 0 ? "0" : "-1");
		path.setAttribute("aria-label", `${name}: ${formatNumber(value)} ${unit}`);
		path.dataset.value = String(value);
		path.dataset.unit = unit;
	}

	const sorted = [...items].sort((a, b) => Number(b.count) - Number(a.count));
	byId("geoCountryList").innerHTML =
		sorted.length === 0
			? '<p class="muted">No geographic data is available for this range.</p>'
			: sorted
					.slice(0, 10)
					.map((item) => {
						const code = String(item.countryCode).toUpperCase();
						const name = countryDisplayName(code);
						const percentage = total > 0 ? (Number(item.count) / total) * 100 : 0;
						return `<div class="geo-country-row"><div class="row between"><span><code>${escapeHtml(code)}</code> ${escapeHtml(name)}</span><strong>${formatNumber(item.count)}</strong></div><div class="breakdown-track"><div style="width:${Math.max(1, percentage)}%"></div></div></div>`;
					})
					.join("");

	const status = geoMetrics.status;
	if (!status?.enabled) {
		byId("geoMapStatus").textContent = "GeoIP is disabled.";
		byId("geoMapStatus").classList.remove("hidden");
	} else if (!status.available) {
		byId("geoMapStatus").textContent = status.error ?? "GeoIP database is unavailable.";
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
		const name = countryDisplayName(code, sourcePath.getAttribute("aria-label") ?? code);
		path.setAttribute("d", data);
		path.setAttribute("class", "geo-country geo-level-0");
		path.setAttribute("tabindex", "-1");
		path.dataset.code = code;
		path.dataset.name = name;
		path.dataset.value = "0";
		path.dataset.unit = "requests";
		const show = (event) =>
			positionGeoTooltip(
				event,
				`<strong>${escapeHtml(path.dataset.name)}</strong><span>${formatNumber(path.dataset.value)} ${escapeHtml(path.dataset.unit)}</span>`,
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

async function loadGeoMetrics() {
	await loadGeoMapGeometry();
	geoMetrics = await api(`/geo-metrics?${queryString(rangeQuery())}`);
	renderGeoMap();
}

async function applyDateRangeValues(from, to, updateLabel = "Dashboard updated") {
	setDateRangeInputs(from, to);
	persistDateRange();
	tableState.traffic.page = 1;
	tableState.sessions.page = 1;
	const tasks = [loadOverview(), loadMetrics(), loadGeoMetrics()];
	if (loadedTabs.has("traffic")) tasks.push(loadTraffic());
	if (loadedTabs.has("sessions")) tasks.push(loadSessions());
	await Promise.all(tasks);
	markUpdated(updateLabel);
}

function markUpdated(prefix = "Updated") {
	byId("lastUpdated").textContent = `${prefix} ${new Date().toLocaleTimeString()}`;
}

async function runWithButton(button, task) {
	button.disabled = true;
	try {
		await task();
	} finally {
		button.disabled = false;
	}
}

async function refreshDashboard() {
	const tasks = [loadOverview(), loadMetrics(), loadGeoMetrics()];
	if (activeTab === "traffic") tasks.push(loadTraffic());
	if (activeTab === "sessions") tasks.push(loadSessions());
	if (activeTab === "rules") tasks.push(loadRules());
	if (activeTab === "routes") tasks.push(loadRoutePolicies());
	if (activeTab === "sites") tasks.push(loadSites());
	await Promise.all(tasks);
	markUpdated();
}

function setActiveTab(name) {
	activeTab = name;
	document.querySelectorAll(".tab").forEach((tab) => tab.classList.toggle("active", tab.dataset.tab === name));
	document.querySelectorAll(".tab-panel").forEach((panel) => panel.classList.add("hidden"));
	byId(`panel-${name}`).classList.remove("hidden");
	void loadMetrics();
	if (loadedTabs.has(name)) return;
	loadedTabs.add(name);
	if (name === "traffic") void loadTraffic();
	if (name === "sessions") void loadSessions();
	if (name === "rules") void loadRules();
	if (name === "routes") void loadRoutePolicies();
	if (name === "sites") void loadSites();
}

function bindSortButtons() {
	document.querySelectorAll(".sort-button").forEach((button) => {
		button.addEventListener("click", () => {
			const panel = button.closest(".tab-panel");
			const name = panel.id.replace("panel-", "");
			const state = tableState[name];
			const sortBy = button.dataset.sort;
			if (state.sortBy === sortBy) state.sortDirection = state.sortDirection === "asc" ? "desc" : "asc";
			else {
				state.sortBy = sortBy;
				state.sortDirection = sortBy === "network_cidr" || sortBy === "action" || sortBy === "last_ip" ? "asc" : "desc";
			}
			state.page = 1;
			if (name === "traffic") void loadTraffic();
			if (name === "sessions") void loadSessions();
			if (name === "rules") void loadRules();
		});
	});
}

function bindFilters() {
	const trafficSearch = debounce(() => {
		tableState.traffic.page = 1;
		void loadTraffic();
	});
	byId("eventSearch").addEventListener("input", trafficSearch);
	for (const id of ["eventDecision", "eventMethod", "eventStatus", "eventCountry"]) {
		byId(id).addEventListener("change", () => {
			tableState.traffic.page = 1;
			void loadTraffic();
		});
	}
	byId("eventPageSize").addEventListener("change", () => {
		tableState.traffic.page = 1;
		tableState.traffic.pageSize = Number(byId("eventPageSize").value);
		void loadTraffic();
	});

	const sessionSearch = debounce(() => {
		tableState.sessions.page = 1;
		void loadSessions();
	});
	byId("sessionSearch").addEventListener("input", sessionSearch);
	for (const id of ["sessionState", "sessionCountry"])
		byId(id).addEventListener("change", () => {
			tableState.sessions.page = 1;
			void loadSessions();
		});
	byId("sessionPageSize").addEventListener("change", () => {
		tableState.sessions.page = 1;
		tableState.sessions.pageSize = Number(byId("sessionPageSize").value);
		void loadSessions();
	});

	const ruleSearch = debounce(() => {
		tableState.rules.page = 1;
		void loadRules();
	});
	byId("ruleSearch").addEventListener("input", ruleSearch);
	for (const id of ["ruleAction", "ruleState"]) {
		byId(id).addEventListener("change", () => {
			tableState.rules.page = 1;
			void loadRules();
		});
	}
	byId("rulePageSize").addEventListener("change", () => {
		tableState.rules.page = 1;
		tableState.rules.pageSize = Number(byId("rulePageSize").value);
		void loadRules();
	});
}

async function handleBodyClick(event) {
	const selectSiteButton = event.target.closest("button[data-site-select]");
	if (selectSiteButton) {
		await chooseSite(selectSiteButton.dataset.siteSelect);
		return;
	}
	const editSiteButton = event.target.closest("button[data-site-edit]");
	if (editSiteButton) {
		editSite(editSiteButton.dataset.siteEdit);
		return;
	}

	const editRouteButton = event.target.closest("button[data-route-edit]");
	if (editRouteButton) {
		editRoutePolicy(editRouteButton.dataset.routeEdit);
		return;
	}
	const deleteRouteButton = event.target.closest("button[data-route-delete]");
	if (deleteRouteButton) {
		if (!confirm("Delete this route policy? Requests will immediately fall back to the next matching policy or the site default.")) return;
		deleteRouteButton.disabled = true;
		try {
			await api(`/route-policies/${encodeURIComponent(deleteRouteButton.dataset.routeDelete)}`, { method: "DELETE" });
			if (editingRoutePolicyId === deleteRouteButton.dataset.routeDelete) resetRoutePolicyForm();
			showToast("Route policy deleted.");
			await Promise.all([loadRoutePolicies(), loadMetrics()]);
		} catch (error) {
			deleteRouteButton.disabled = false;
			showToast(error.message, "bad");
		}
		return;
	}

	const sessionButton = event.target.closest("button[data-session-id]");
	if (sessionButton) {
		if (!confirm("Revoke this access session immediately?")) return;
		sessionButton.disabled = true;
		try {
			await api(`/sessions/${encodeURIComponent(sessionButton.dataset.sessionId)}/revoke`, { method: "POST" });
			showToast("Session revoked.");
			await Promise.all([loadSessions(), loadOverview(), loadMetrics()]);
		} catch (error) {
			sessionButton.disabled = false;
			showToast(error.message, "bad");
		}
		return;
	}

	const countryRuleButton = event.target.closest("button[data-country-rule-id]");
	if (countryRuleButton) {
		if (!confirm("Delete this country rule?")) return;
		countryRuleButton.disabled = true;
		try {
			await api(`/country-rules/${encodeURIComponent(countryRuleButton.dataset.countryRuleId)}`, { method: "DELETE" });
			showToast("Country rule deleted.");
			await Promise.all([loadRules(), loadOverview(), loadMetrics()]);
		} catch (error) {
			countryRuleButton.disabled = false;
			showToast(error.message, "bad");
		}
		return;
	}

	const ruleButton = event.target.closest("button[data-rule-id]");
	if (ruleButton) {
		if (!confirm("Delete this IP rule?")) return;
		ruleButton.disabled = true;
		try {
			await api(`/rules/${encodeURIComponent(ruleButton.dataset.ruleId)}`, { method: "DELETE" });
			showToast("IP rule deleted.");
			await Promise.all([loadRules(), loadOverview(), loadMetrics()]);
		} catch (error) {
			ruleButton.disabled = false;
			showToast(error.message, "bad");
		}
	}
}

function bindActions() {
	document.querySelectorAll(".tab").forEach((tab) => tab.addEventListener("click", () => setActiveTab(tab.dataset.tab)));
	byId("siteSelector").addEventListener("change", (event) => void chooseSite(event.currentTarget.value));
	byId("newRoutePolicy").addEventListener("click", () => {
		resetRoutePolicyForm();
		byId("routePolicyName").focus();
	});
	byId("cancelRoutePolicyEdit").addEventListener("click", resetRoutePolicyForm);
	byId("resetRoutePolicyForm").addEventListener("click", () => (editingRoutePolicyId ? editRoutePolicy(editingRoutePolicyId) : resetRoutePolicyForm()));
	byId("routePolicyForm").addEventListener("submit", saveRoutePolicy);
	byId("routeRateEnabled").addEventListener("change", updateRoutePolicyControls);
	byId("routeRateAlgorithm").addEventListener("change", updateRoutePolicyControls);
	byId("routeRateKeyMode").addEventListener("change", updateRoutePolicyControls);
	byId("routePolicyAccessMode").addEventListener("change", updateRoutePolicyControls);
	byId("refreshRoutePolicies").addEventListener(
		"click",
		(event) =>
			void runWithButton(event.currentTarget, async () => {
				await Promise.all([loadRoutePolicies(), loadMetrics()]);
				markUpdated("Route policies updated");
			}),
	);
	byId("newSite").addEventListener("click", () => {
		resetSiteForm();
		byId("siteName").focus();
	});
	byId("cancelSiteEdit").addEventListener("click", resetSiteForm);
	byId("resetSiteForm").addEventListener("click", () => (editingSiteId ? editSite(editingSiteId) : resetSiteForm()));
	byId("generateSiteSecret").addEventListener("click", () => {
		byId("siteSigningSecret").value = randomSecret();
		byId("siteSigningSecret").type = "text";
	});
	byId("copyGeneratedSecret").addEventListener("click", async () => {
		try {
			await navigator.clipboard.writeText(byId("generatedSecretValue").textContent);
			showToast("Signing secret copied.");
		} catch {
			showToast("Could not copy automatically. Select the secret and copy it manually.", "bad");
		}
	});
	byId("siteForm").addEventListener("submit", saveSite);
	byId("siteErrorResponseMode").addEventListener("change", updateErrorResponseControls);
	byId("resetErrorHtmlTemplate").addEventListener("click", () => {
		byId("siteErrorHtmlTemplate").value = errorResponseDefaults.htmlTemplate ?? "";
		showToast("Default HTML error template restored. Save the site to apply it.");
	});
	byId("resetChallengeHtmlTemplate").addEventListener("click", () => {
		byId("siteChallengeHtmlTemplate").value = challengeDefaults.htmlTemplate ?? "";
		showToast("Default challenge template restored. Save the site to apply it.");
	});
	byId("tlsSettingsForm").addEventListener("submit", (event) => void saveTlsSettings(event).catch((error) => showToast(error.message, "bad")));
	byId("acmeForm").addEventListener("submit", (event) => void requestAcmeCertificate(event).catch((error) => showToast(error.message, "bad")));
	byId("uploadCertificateForm").addEventListener("submit", (event) => void uploadCertificate(event).catch((error) => showToast(error.message, "bad")));
	byId("renewAcmeCertificate").addEventListener("click", () => void renewAcmeCertificate().catch((error) => showToast(error.message, "bad")));
	byId("removeCertificate").addEventListener("click", () => void removeCertificate().catch((error) => showToast(error.message, "bad")));
	byId("acmeDirectoryUrl").addEventListener("input", () => {
		byId("acmeEnvironmentWarning").textContent = byId("acmeDirectoryUrl").value.includes("staging")
			? "Staging mode: the issued certificate will not be trusted by browsers. Use this while testing ACME integration."
			: "Production ACME directory selected. Failed or repeated orders can consume provider rate limits.";
	});
	byId("refreshDashboard").addEventListener("click", (event) => void runWithButton(event.currentTarget, refreshDashboard));
	byId("refreshTraffic").addEventListener(
		"click",
		(event) =>
			void runWithButton(event.currentTarget, async () => {
				await Promise.all([loadTraffic(), loadOverview(), loadMetrics()]);
				markUpdated("Traffic updated");
			}),
	);
	byId("refreshSessions").addEventListener(
		"click",
		(event) =>
			void runWithButton(event.currentTarget, async () => {
				await Promise.all([loadSessions(), loadOverview(), loadMetrics()]);
				markUpdated("Sessions updated");
			}),
	);
	byId("refreshRules").addEventListener(
		"click",
		(event) =>
			void runWithButton(event.currentTarget, async () => {
				await Promise.all([loadRules(), loadOverview(), loadMetrics()]);
				markUpdated("Rules updated");
			}),
	);
	byId("saveNetworkDefaults").addEventListener("click", (event) => void runWithButton(event.currentTarget, saveNetworkDefaults));
	byId("countryRuleForm").addEventListener("submit", async (event) => {
		event.preventDefault();
		const form = event.currentTarget;
		const submit = form.querySelector('button[type="submit"]');
		submit.disabled = true;
		const data = Object.fromEntries(new FormData(form));
		const expiration = String(data.expiresAt ?? "").trim();
		data.expiresAt = expiration ? new Date(expiration).getTime() : null;
		try {
			await api("/country-rules", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify(data),
			});
			form.reset();
			showToast("Country rule added.");
			await Promise.all([loadRules(), loadOverview(), loadMetrics()]);
		} catch (error) {
			showToast(error.message, "bad");
		} finally {
			submit.disabled = false;
		}
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
	byId("geoMetricMode").addEventListener("change", renderGeoMap);
	byId("logout").addEventListener("click", async () => {
		await api("/logout", { method: "POST" }, false);
		location.href = "/_burrowgate/admin/login";
	});
	byId("ruleForm").addEventListener("submit", async (event) => {
		event.preventDefault();
		const form = event.currentTarget;
		const submit = form.querySelector('button[type="submit"]');
		submit.disabled = true;
		const data = Object.fromEntries(new FormData(form));
		const expiration = String(data.expiresAt ?? "").trim();
		data.expiresAt = expiration ? new Date(expiration).getTime() : null;
		try {
			await api("/rules", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify(data),
			});
			form.reset();
			tableState.rules.page = 1;
			showToast("IP rule added.");
			await Promise.all([loadRules(), loadOverview(), loadMetrics()]);
		} catch (error) {
			showToast(error.message, "bad");
		} finally {
			submit.disabled = false;
		}
	});
	document.body.addEventListener("click", handleBodyClick);
	window.addEventListener(
		"pagehide",
		() => {
			trafficChart?.destroy();
			latencyChart?.destroy();
		},
		{ once: true },
	);
}

async function start() {
	initializeDateRange();
	bindSortButtons();
	bindFilters();
	bindActions();
	resetSiteForm();
	resetRoutePolicyForm();
	try {
		await loadSites();
		await loadOverview();
		await Promise.all([loadTraffic(), loadMetrics(), loadGeoMetrics()]);
		markUpdated("Loaded");
	} catch (error) {
		showToast(error.message, "bad");
	}
}

void start();
