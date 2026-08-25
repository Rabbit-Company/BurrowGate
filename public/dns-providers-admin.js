const ADMIN_API = "/_burrowgate/api/admin/dns-providers";
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

function openModal(name) {
	byId(`modal-${name}`).classList.remove("hidden");
	document.body.classList.add("modal-open");
}

function closeModal(name) {
	byId(`modal-${name}`).classList.add("hidden");
	if (!document.querySelector(".modal-overlay:not(.hidden)")) document.body.classList.remove("modal-open");
}

let providers = [];

function renderProviders() {
	byId("providerRows").innerHTML = providers.length
		? providers
				.map(
					(provider) => `<tr>
        <td>${escapeHtml(provider.name)}</td>
        <td>${escapeHtml(provider.config.server ?? "-")}:${escapeHtml(provider.config.port ?? "53")}</td>
        <td>${escapeHtml(provider.config.zone ?? "-")}</td>
        <td class="row">
          <button class="button secondary compact" type="button" data-edit="${escapeHtml(provider.id)}">Edit</button>
          <button class="button secondary compact" type="button" data-delete="${escapeHtml(provider.id)}">Delete</button>
        </td>
      </tr>`,
				)
				.join("")
		: '<tr><td colspan="4" class="empty-cell">No DNS providers configured yet.</td></tr>';
	byId("providerRows")
		.querySelectorAll("[data-edit]")
		.forEach((button) => button.addEventListener("click", () => openProviderForm(providers.find((provider) => provider.id === button.dataset.edit))));
	byId("providerRows")
		.querySelectorAll("[data-delete]")
		.forEach((button) => button.addEventListener("click", () => void deleteProvider(button.dataset.delete)));
}

async function loadProviders() {
	try {
		providers = (await api("")).items ?? [];
		renderProviders();
	} catch (error) {
		showToast(error.message, "bad");
	}
}

async function deleteProvider(id) {
	if (!confirm("Delete this DNS provider? Sites still using it for DNS-01 must be switched off it first.")) return;
	try {
		await api(`/${encodeURIComponent(id)}`, { method: "DELETE" });
		await loadProviders();
		showToast("DNS provider deleted.");
	} catch (error) {
		showToast(error.message, "bad");
	}
}

function openProviderForm(provider) {
	byId("providerTestResult").classList.add("hidden");
	byId("providerId").value = provider?.id ?? "";
	byId("providerDialogTitle").textContent = provider ? "Edit DNS provider" : "Add DNS provider";
	byId("providerName").value = provider?.name ?? "";

	const config = provider?.config ?? {};
	byId("providerServer").value = config.server ?? "";
	byId("providerPort").value = config.port ?? 53;
	byId("providerZone").value = config.zone ?? "";
	byId("providerTsigKeyName").value = config.tsigKeyName ?? "";
	byId("providerTsigSecret").value = "";
	byId("providerTsigSecret").placeholder = config.tsigSecretConfigured ? "Leave blank to keep the current secret" : "Required";
	byId("providerPropagationSeconds").value = config.propagationSeconds ?? 30;

	openModal("provider");
}

function providerPayload() {
	const port = Number(byId("providerPort").value);
	const propagationSeconds = Number(byId("providerPropagationSeconds").value);
	return {
		name: byId("providerName").value.trim(),
		type: "rfc2136",
		config: {
			server: byId("providerServer").value.trim(),
			port: Number.isInteger(port) && port > 0 ? port : 53,
			zone: byId("providerZone").value.trim(),
			tsigKeyName: byId("providerTsigKeyName").value.trim(),
			tsigSecret: byId("providerTsigSecret").value.trim(),
			propagationSeconds: Number.isFinite(propagationSeconds) && propagationSeconds >= 0 ? propagationSeconds : 30,
		},
	};
}

async function saveProvider() {
	const id = byId("providerId").value;
	try {
		if (id)
			await api(`/${encodeURIComponent(id)}`, { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(providerPayload()) });
		else await api("", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(providerPayload()) });
		closeModal("provider");
		await loadProviders();
		showToast("DNS provider saved.");
	} catch (error) {
		showToast(error.message, "bad");
	}
}

async function testProviderConnection() {
	const id = byId("providerId").value;
	const result = byId("providerTestResult");
	if (!id) {
		result.textContent = "Save the provider first, then test the connection.";
		result.classList.remove("hidden");
		return;
	}
	result.textContent = "Testing...";
	result.classList.remove("hidden");
	try {
		const outcome = await api(`/${encodeURIComponent(id)}/test`, { method: "POST" });
		result.textContent = outcome.message;
		result.className = outcome.ok ? "muted" : "muted error-text";
	} catch (error) {
		result.textContent = error.message;
		result.className = "muted error-text";
	}
}

byId("providerAdd").addEventListener("click", () => openProviderForm(null));
byId("providerTest").addEventListener("click", () => void testProviderConnection());
byId("providerSave").addEventListener("click", () => void saveProvider());

document.querySelectorAll(".modal-overlay").forEach((overlay) => {
	overlay.addEventListener("click", (event) => {
		if (event.target === overlay) closeModal(overlay.dataset.modal);
	});
	overlay.querySelector("[data-modal-close]").addEventListener("click", () => closeModal(overlay.dataset.modal));
});

byId("refreshDashboard").addEventListener("click", () => void loadProviders());
byId("logout").addEventListener("click", async () => {
	await fetch("/_burrowgate/api/admin/logout", { method: "POST", headers: mutationHeaders });
	location.href = "/_burrowgate/admin/login";
});

void loadProviders();
