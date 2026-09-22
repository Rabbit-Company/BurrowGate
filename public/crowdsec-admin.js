const ADMIN_API = "/_burrowgate/api/admin/crowdsec";
const mutationHeaders = { "x-burrowgate-admin": "1" };
const byId = (id) => document.getElementById(id);

const escapeHtml = (value) =>
	String(value ?? "").replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);

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

/** Sets a test-result panel without dropping the classes that style and space it. */
function setConnectionResult(element, message, state) {
	element.textContent = message;
	element.className = `notice muted connection-result${state === "error" ? " error-text" : ""}`;
	element.classList.remove("hidden");
}

function formatTimestamp(value) {
	if (!value) return "Never";
	return new Date(value).toLocaleString();
}

function formatRelative(value) {
	if (!value) return "never";
	const seconds = Math.round((Date.now() - value) / 1_000);
	if (seconds < 60) return `${seconds}s ago`;
	if (seconds < 3_600) return `${Math.round(seconds / 60)}m ago`;
	if (seconds < 86_400) return `${Math.round(seconds / 3_600)}h ago`;
	return `${Math.round(seconds / 86_400)}d ago`;
}

const SCOPE_LABELS = { ip: "IP address", range: "Range", country: "Country", as: "AS" };
const REMEDIATION_LABELS = { ban: "Ban", captcha: "Captcha" };

function renderDecisions(status) {
	const { decisions } = status;
	byId("decisionTotal").textContent = decisions.total.toLocaleString();

	const scopeEntries = Object.entries(decisions.byScope);
	const remediationEntries = Object.entries(decisions.byRemediation);
	const rowCount = Math.max(scopeEntries.length, remediationEntries.length);
	if (!decisions.total) {
		byId("decisionBreakdown").innerHTML = '<tr><td colspan="4" class="empty-cell">Nothing loaded yet.</td></tr>';
	} else {
		const rows = [];
		for (let index = 0; index < rowCount; index++) {
			const scope = scopeEntries[index];
			const remediation = remediationEntries[index];
			rows.push(`<tr>
        <td>${scope ? escapeHtml(SCOPE_LABELS[scope[0]] ?? scope[0]) : ""}</td>
        <td>${scope ? scope[1].toLocaleString() : ""}</td>
        <td>${remediation ? escapeHtml(REMEDIATION_LABELS[remediation[0]] ?? remediation[0]) : ""}</td>
        <td>${remediation ? remediation[1].toLocaleString() : ""}</td>
      </tr>`);
		}
		byId("decisionBreakdown").innerHTML = rows.join("");
	}

	const origins = Object.entries(decisions.byOrigin).sort((left, right) => right[1] - left[1]);
	byId("decisionOrigins").textContent = origins.length
		? `By origin: ${origins.map(([origin, count]) => `${origin} (${count.toLocaleString()})`).join(", ")}`
		: "";

	const truncated = byId("decisionTruncated");
	truncated.classList.toggle("hidden", !status.truncated);
	if (status.truncated) {
		truncated.className = "muted error-text";
		truncated.textContent =
			"The Local API returned more decisions than this node's ceiling allows, so the set was truncated. Raise BG_CROWDSEC_MAX_DECISIONS or narrow your blocklist subscriptions.";
	}
}

function statusBadge(status) {
	if (!status.enabled) return '<span class="badge">Disabled</span>';
	if (status.lastPollStatus === "ok") return '<span class="badge ok">Healthy</span>';
	if (status.lastPollStatus === "error") return '<span class="badge bad">Failing</span>';
	return '<span class="badge warn">Starting</span>';
}

function renderStatus(status) {
	const rows = [
		["State", statusBadge(status)],
		["Local API", status.lapiUrl ? escapeHtml(status.lapiUrl) : "Not configured"],
		["Last poll", `${escapeHtml(formatTimestamp(status.lastPolledAt))} <span class="muted">(${escapeHtml(formatRelative(status.lastPolledAt))})</span>`],
		["Last success", `${escapeHtml(formatTimestamp(status.lastSuccessAt))} <span class="muted">(${escapeHtml(formatRelative(status.lastSuccessAt))})</span>`],
	];
	if (status.consecutiveFailures > 0) {
		rows.push(["Consecutive failures", `<span class="error-text">${status.consecutiveFailures}</span>`]);
	}
	if (status.lastPollError) {
		rows.push(["Last error", `<span class="error-text">${escapeHtml(status.lastPollError)}</span>`]);
	}
	if (status.nextPollIsFullSync && status.enabled) {
		rows.push(["Next poll", "Full resync"]);
	}
	rows.push(["Scopes", escapeHtml(status.scopes.map((scope) => SCOPE_LABELS[scope] ?? scope).join(", "))]);
	byId("statusRows").innerHTML = rows.map(([label, value]) => `<tr><td><strong>${escapeHtml(label)}</strong></td><td>${value}</td></tr>`).join("");
}

function applySettingsToForm(status) {
	byId("enabled").checked = status.enabled;
	byId("lapiUrl").value = status.lapiUrl ?? "";
	byId("apiKey").placeholder = status.apiKeyConfigured ? "Leave blank to keep the current key" : "Paste the key from cscli bouncers add";
	byId("verifyTls").checked = status.verifyTls;
	byId("pollIntervalSeconds").value = status.pollIntervalSeconds;
	byId("fullSyncIntervalSeconds").value = status.fullSyncIntervalSeconds;
	byId("requestTimeoutMs").value = status.requestTimeoutMs;
	byId("unknownRemediation").value = status.unknownRemediation;
	byId("alertAfterMinutes").value = status.alertAfterMinutes;
	byId("scopeIp").checked = status.scopes.includes("ip");
	byId("scopeRange").checked = status.scopes.includes("range");
	byId("scopeCountry").checked = status.scopes.includes("country");
	byId("scopeAs").checked = status.scopes.includes("as");
	byId("appsecUrl").value = status.appsecUrl ?? "";
	byId("appsecTimeoutMs").value = status.appsecTimeoutMs;
	byId("appsecMaxBodyBytes").value = status.appsecMaxBodyBytes;
	byId("appsecFailOpen").checked = status.appsecFailOpen;
}

function selectedScopes() {
	const scopes = [];
	if (byId("scopeIp").checked) scopes.push("ip");
	if (byId("scopeRange").checked) scopes.push("range");
	if (byId("scopeCountry").checked) scopes.push("country");
	if (byId("scopeAs").checked) scopes.push("as");
	return scopes;
}

let formDirty = false;

function render(status, { syncForm = true } = {}) {
	renderDecisions(status);
	renderStatus(status);
	if (syncForm && !formDirty) applySettingsToForm(status);
}

async function loadStatus(options = {}) {
	try {
		render(await api("/status"), options);
	} catch (error) {
		showToast(error.message, "bad");
	}
}

async function save() {
	const buttons = [byId("save"), byId("appsecSave")];
	for (const button of buttons) button.disabled = true;
	try {
		const status = await api("/settings", {
			method: "PUT",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				enabled: byId("enabled").checked,
				lapiUrl: byId("lapiUrl").value.trim(),
				apiKey: byId("apiKey").value.trim() || undefined,
				verifyTls: byId("verifyTls").checked,
				scopes: selectedScopes(),
				pollIntervalSeconds: Number(byId("pollIntervalSeconds").value),
				fullSyncIntervalSeconds: Number(byId("fullSyncIntervalSeconds").value),
				requestTimeoutMs: Number(byId("requestTimeoutMs").value),
				unknownRemediation: byId("unknownRemediation").value,
				alertAfterMinutes: Number(byId("alertAfterMinutes").value),
				appsecUrl: byId("appsecUrl").value.trim(),
				appsecTimeoutMs: Number(byId("appsecTimeoutMs").value),
				appsecMaxBodyBytes: Number(byId("appsecMaxBodyBytes").value),
				appsecFailOpen: byId("appsecFailOpen").checked,
			}),
		});
		byId("apiKey").value = "";
		formDirty = false;
		render(status);
		showToast("CrowdSec settings saved.");
		// The first poll runs right after saving, so show what it loaded a moment later.
		setTimeout(() => void loadStatus(), 1_500);
	} catch (error) {
		showToast(error.message, "bad");
	} finally {
		for (const button of buttons) button.disabled = false;
	}
}

async function testConnection() {
	const result = byId("testResult");
	const button = byId("testConnection");
	// Sent only when typed. An empty field means "use the key already stored on the server".
	const apiKey = byId("apiKey").value.trim();
	button.disabled = true;
	setConnectionResult(result, "Testing...", "pending");
	try {
		const outcome = await api("/test", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ lapiUrl: byId("lapiUrl").value.trim(), apiKey: apiKey || undefined, verifyTls: byId("verifyTls").checked }),
		});
		setConnectionResult(result, outcome.message, outcome.ok ? "ok" : "error");
	} catch (error) {
		setConnectionResult(result, error.message, "error");
	} finally {
		button.disabled = false;
	}
}

async function refreshNow() {
	const button = byId("refreshNow");
	button.disabled = true;
	try {
		render(await api("/refresh", { method: "POST" }));
		showToast("Resynced from the Local API.");
	} catch (error) {
		showToast(error.message, "bad");
	} finally {
		button.disabled = false;
	}
}

async function runLookup() {
	const ip = byId("lookupIp").value.trim();
	const result = byId("lookupResult");
	if (!ip) {
		result.textContent = "Enter an IP address.";
		result.className = "muted";
		return;
	}
	result.textContent = "Looking up...";
	result.className = "muted";
	try {
		const outcome = await api(`/lookup?ip=${encodeURIComponent(ip)}`);
		if (!outcome.decision) {
			result.innerHTML = `<span class="badge ok">No decision</span> ${escapeHtml(ip)} is not covered by any decision loaded on this node.`;
			return;
		}
		const decision = outcome.decision;
		const expiry = decision.expiresAt ? `${escapeHtml(formatTimestamp(decision.expiresAt))}` : "no expiry";
		result.innerHTML = `<span class="badge bad">${escapeHtml(REMEDIATION_LABELS[decision.remediation] ?? decision.remediation)}</span>
      Matched <strong>${escapeHtml(decision.value)}</strong> (${escapeHtml(SCOPE_LABELS[decision.scope] ?? decision.scope)})
      from <strong>${escapeHtml(decision.origin)}</strong>${decision.scenario ? ` for <strong>${escapeHtml(decision.scenario)}</strong>` : ""}, expires ${expiry}.`;
	} catch (error) {
		result.textContent = error.message;
		result.className = "muted error-text";
	}
}

async function testAppSec() {
	const result = byId("appsecTestResult");
	const button = byId("appsecTest");
	const apiKey = byId("apiKey").value.trim();
	button.disabled = true;
	setConnectionResult(result, "Testing...", "pending");
	try {
		const outcome = await api("/appsec/test", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ appsecUrl: byId("appsecUrl").value.trim(), apiKey: apiKey || undefined, verifyTls: byId("verifyTls").checked }),
		});
		setConnectionResult(result, outcome.message, outcome.ok ? "ok" : "error");
	} catch (error) {
		setConnectionResult(result, error.message, "error");
	} finally {
		button.disabled = false;
	}
}

byId("appsecTest").addEventListener("click", () => void testAppSec());
byId("appsecSave").addEventListener("click", () => void save());

for (const id of [
	"enabled",
	"lapiUrl",
	"apiKey",
	"verifyTls",
	"pollIntervalSeconds",
	"fullSyncIntervalSeconds",
	"requestTimeoutMs",
	"unknownRemediation",
	"alertAfterMinutes",
	"scopeIp",
	"scopeRange",
	"scopeCountry",
	"scopeAs",
	"appsecUrl",
	"appsecTimeoutMs",
	"appsecMaxBodyBytes",
	"appsecFailOpen",
]) {
	byId(id).addEventListener("input", () => {
		formDirty = true;
	});
}

byId("save").addEventListener("click", () => void save());
byId("testConnection").addEventListener("click", () => void testConnection());
byId("refreshNow").addEventListener("click", () => void refreshNow());
byId("lookupRun").addEventListener("click", () => void runLookup());
byId("lookupIp").addEventListener("keydown", (event) => {
	if (event.key === "Enter") void runLookup();
});

byId("refreshDashboard").addEventListener("click", () => void loadStatus());
byId("logout").addEventListener("click", async () => {
	await fetch("/_burrowgate/api/admin/logout", { method: "POST", headers: mutationHeaders });
	location.href = "/_burrowgate/admin/login";
});

void loadStatus();
// Counters move on their own as polls land, so refresh them without stomping on a form being edited.
setInterval(() => void loadStatus({ syncForm: false }), 15_000);
