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
