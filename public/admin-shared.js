export const byId = (id) => document.getElementById(id);

export const escapeHtml = (value) =>
	String(value ?? "").replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);

export function setTableLoading(id, columns) {
	byId(id).innerHTML = `<tr><td colspan="${columns}" class="empty-cell"><span class="spinner"></span> Loading...</td></tr>`;
}

export function setTableError(id, columns, error) {
	byId(id).innerHTML = `<tr><td colspan="${columns}" class="empty-cell error-text">${escapeHtml(error.message)}</td></tr>`;
}

let pendingDurabilityWarning = false;

export function setPendingDurabilityWarning(value) {
	pendingDurabilityWarning = value;
}

export function showToast(message, kind = "ok") {
	const toast = byId("toast");
	if (kind === "ok" && pendingDurabilityWarning) {
		message = `${message} Not yet confirmed durable on a majority of cluster members - will retry.`;
		kind = "warn";
	}
	pendingDurabilityWarning = false;
	toast.textContent = message;
	toast.className = `toast ${kind}`;
	clearTimeout(showToast.timer);
	showToast.timer = setTimeout(() => toast.classList.add("hidden"), 3_500);
}

export async function runWithButton(button, task) {
	button.disabled = true;
	try {
		await task();
	} finally {
		button.disabled = false;
	}
}

export function createUsersController({ api }) {
	let usersData = { items: [], sites: [], streams: [] };
	let editingPermissionsUserId = null;

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
        <td>${user.totpEnrolled || user.webauthnCredentialCount > 0 ? '<span class="badge ok">Enrolled</span>' : '<span class="badge warn">Pending</span>'}</td>
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

	function closePermissionsEditor() {
		editingPermissionsUserId = null;
		byId("userPermissionsCard").classList.add("hidden");
	}

	return { loadUsers, createUser, openUserPermissions, saveUserPermissions, closePermissionsEditor };
}

export function createApiTokensController({ api }) {
	function clearApiTokenSecret() {
		byId("apiTokenSecret").value = "";
		byId("apiTokenCreated").classList.add("hidden");
	}

	async function loadApiTokens() {
		const list = byId("apiTokenList");
		try {
			const { tokens } = await api("/me/api-tokens");
			list.innerHTML =
				tokens
					.map(
						(token) => `<li class="site-list-item api-token-item">
			<div class="site-list-title"><strong>${escapeHtml(token.name)}</strong><span class="badge ${token.scope === "full" ? "warn" : ""}">${token.scope === "full" ? "Full access" : "Read only"}</span></div>
			<div class="site-list-meta"><span>${escapeHtml(token.prefix)}…</span><span>Created ${new Date(token.createdAt).toLocaleDateString()}</span><span>${token.expiresAt ? `${token.expiresAt <= Date.now() ? "Expired" : "Expires"} ${new Date(token.expiresAt).toLocaleDateString()}` : "Never expires"}</span></div>
			<div class="site-list-actions"><button class="button danger compact" type="button" data-api-token-revoke="${escapeHtml(token.id)}">Revoke</button></div>
		</li>`,
					)
					.join("") || '<li class="empty-state-inline">No API tokens.</li>';
		} catch (error) {
			list.innerHTML = `<li class="empty-state-inline error-text">${escapeHtml(error.message)}</li>`;
		}
	}

	async function createApiToken(event) {
		event.preventDefault();
		const form = event.currentTarget;
		const button = form.querySelector('button[type="submit"]');
		await runWithButton(button, async () => {
			clearApiTokenSecret();
			const fields = new FormData(form);
			const result = await api("/me/api-tokens", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					name: fields.get("name"),
					scope: fields.get("scope"),
					expiresInDays: fields.get("expiresInDays") === "never" ? null : Number(fields.get("expiresInDays")),
				}),
			});
			byId("apiTokenSecret").value = result.token;
			byId("apiTokenCreated").classList.remove("hidden");
			byId("apiTokenSecret").select();
			form.reset();
			await loadApiTokens();
		});
	}

	return { loadApiTokens, createApiToken, clearApiTokenSecret };
}

let searchCatalog = null;

function loadSearchCatalog() {
	searchCatalog ??= fetch("/_burrowgate/api/admin/search-fields", { headers: { accept: "application/json" } })
		.then((response) => (response.ok ? response.json() : { schemas: [] }))
		.then((data) => new Map((data.schemas ?? []).map((schema) => [schema.id, schema])))
		.catch(() => new Map());
	return searchCatalog;
}

const SEARCH_SYNTAX = [
	["health", "Free text, matched anywhere in the main columns"],
	["path:/api/login", "Field equals a value (ignores case)"],
	["path:/health*", "Wildcards: * any characters, ? one character"],
	["-path:/health*", "Exclude matches (same as NOT path:/health*)"],
	["user:*  /  -user:*", "Field has a value / field is empty"],
	["status:>=500  status:4xx", "Number comparisons and ranges such as 400..499"],
	["path:(/a OR /b)", "Several values for one field"],
	["a OR (b AND NOT c)", "Boolean logic; terms side by side are ANDed"],
	['path:"/a b"', "Quotes keep spaces and turn wildcards off"],
];

function searchHelpHtml(schema) {
	const syntax = SEARCH_SYNTAX.map(([example, meaning]) => `<tr><td><code>${escapeHtml(example)}</code></td><td>${escapeHtml(meaning)}</td></tr>`).join("");
	const fields = (schema?.fields ?? [])
		.map(
			(field) =>
				`<tr><td><code>${escapeHtml(field.name)}</code>${field.aliases.length ? `<span class="muted"> ${field.aliases.map(escapeHtml).join(", ")}</span>` : ""}</td><td>${escapeHtml(field.description)}${
					field.values ? `<span class="muted"> ${field.values.map(escapeHtml).join(", ")}</span>` : ""
				}</td></tr>`,
		)
		.join("");
	return `<div class="search-help-section"><h4>Syntax</h4><table class="search-help-table"><tbody>${syntax}</tbody></table></div>
		<div class="search-help-section"><h4>Fields</h4>${
			fields ? `<table class="search-help-table"><tbody>${fields}</tbody></table>` : '<p class="muted">Field list unavailable.</p>'
		}${schema?.dynamicFields ? '<p class="muted">Any other name is looked up in the entry\'s metadata, for example <code>siteId:abc</code> or <code>error.code:*</code>.</p>' : ""}</div>`;
}

export function enhanceSearchInput(inputId, schemaId) {
	const input = byId(inputId);
	if (!input || input.dataset.searchEnhanced) return;
	input.dataset.searchEnhanced = "1";
	input.dataset.searchSchema = schemaId;
	input.spellcheck = false;
	input.autocomplete = "off";
	const label = input.closest("label") ?? input.parentElement;
	label.classList.add("search-query-field");
	const caption = label.querySelector("span");
	const button = document.createElement("button");
	button.type = "button";
	button.className = "search-help-button";
	button.textContent = "?";
	button.title = "Search syntax and fields";
	button.setAttribute("aria-expanded", "false");
	const panel = document.createElement("div");
	panel.className = "search-help hidden";
	panel.setAttribute("role", "dialog");
	panel.setAttribute("aria-label", "Search syntax and fields");
	const feedback = document.createElement("small");
	feedback.className = "search-feedback hidden";
	feedback.id = `${inputId}Feedback`;
	(caption ?? label).append(button);
	label.after(panel);
	input.after(feedback);
	button.addEventListener("click", async (event) => {
		event.preventDefault();
		const open = panel.classList.toggle("hidden") === false;
		button.setAttribute("aria-expanded", String(open));
		if (open && !panel.dataset.loaded) {
			panel.innerHTML = '<p class="muted"><span class="spinner"></span> Loading...</p>';
			panel.innerHTML = searchHelpHtml((await loadSearchCatalog()).get(schemaId));
			panel.dataset.loaded = "1";
		}
	});
	document.addEventListener("click", (event) => {
		if (panel.classList.contains("hidden") || panel.contains(event.target) || button.contains(event.target)) return;
		panel.classList.add("hidden");
		button.setAttribute("aria-expanded", "false");
	});
}

export function reportSearch(inputId, result, error) {
	const input = byId(inputId);
	const feedback = byId(`${inputId}Feedback`);
	if (!input || !feedback) return;
	const invalid = Boolean(error?.message?.startsWith("Invalid search:"));
	const warnings = invalid ? [] : (result?.searchWarnings ?? []);
	input.classList.toggle("input-invalid", invalid);
	input.setAttribute("aria-invalid", String(invalid));
	feedback.textContent = invalid ? error.message.slice("Invalid search: ".length) : warnings.join(" ");
	feedback.className = `search-feedback${invalid ? " error-text" : warnings.length ? " warn-text" : " hidden"}`;
}

function quoteSearchValue(value) {
	return `"${String(value).replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

export function searchClause(field, value, exclude) {
	const empty = value === null || value === undefined || value === "";
	if (empty) return exclude ? `${field}:*` : `-${field}:*`;
	return `${exclude ? "-" : ""}${field}:${quoteSearchValue(value)}`;
}

export function addSearchClause(inputId, clause) {
	const input = byId(inputId);
	if (!input) return;
	const opposite = clause.startsWith("-") ? clause.slice(1) : `-${clause}`;
	const terms = input.value.trim() ? input.value.trim().split(/\s+(?=(?:[^"]*"[^"]*")*[^"]*$)/u) : [];
	const kept = terms.filter((term) => term !== clause && term !== opposite);
	input.value = [...kept, clause].join(" ");
	input.dispatchEvent(new Event("input", { bubbles: true }));
}

export function filterButtons(inputId, field, value) {
	const data = `data-search-target="${escapeHtml(inputId)}" data-search-field="${escapeHtml(field)}" data-search-value="${escapeHtml(value ?? "")}"`;
	const shown = value === null || value === undefined || value === "" ? "no value" : String(value);
	return `<span class="filter-buttons"><button type="button" class="filter-button" ${data} data-search-exclude="0" title="Show only ${escapeHtml(shown)}" aria-label="Filter for ${escapeHtml(shown)}">+</button><button type="button" class="filter-button" ${data} data-search-exclude="1" title="Hide ${escapeHtml(shown)}" aria-label="Filter out ${escapeHtml(shown)}">−</button></span>`;
}

document.addEventListener("click", (event) => {
	const button = event.target instanceof Element ? event.target.closest("[data-search-field]") : null;
	if (!button) return;
	event.preventDefault();
	event.stopPropagation();
	const clause = searchClause(button.dataset.searchField, button.dataset.searchValue, button.dataset.searchExclude === "1");
	addSearchClause(button.dataset.searchTarget, clause);
	button.dispatchEvent(new CustomEvent("search-clause-added", { bubbles: true, detail: { clause } }));
});
