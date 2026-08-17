const ADMIN_API = "/_burrowgate/api/admin/firewall-sync";
const mutationHeaders = { "x-burrowgate-admin": "1" };
const byId = (id) => document.getElementById(id);

const escapeHtml = (value) =>
	String(value ?? "").replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);

function formatDate(value) {
	if (value === null || value === undefined) return "-";
	const date = new Date(Number(value));
	return Number.isNaN(date.getTime()) ? "-" : date.toLocaleString();
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

function openModal(name) {
	byId(`modal-${name}`).classList.remove("hidden");
	document.body.classList.add("modal-open");
}

function closeModal(name) {
	byId(`modal-${name}`).classList.add("hidden");
	if (!document.querySelector(".modal-overlay:not(.hidden)")) document.body.classList.remove("modal-open");
}

let providers = [];
let whitelist = [];

async function loadPreview() {
	try {
		const result = await api("/preview");
		byId("previewCount").textContent = String(result.totalCount);
		byId("previewSample").textContent = result.sample.length ? result.sample.join(", ") : "No active bans.";
		const excluded = (result.excludedPrivateCount ?? 0) + (result.excludedWhitelistedCount ?? 0);
		const exclusions = byId("previewExclusions");
		if (excluded > 0) {
			const parts = [];
			if (result.excludedPrivateCount)
				parts.push(`${result.excludedPrivateCount} private/LAN IP${result.excludedPrivateCount === 1 ? "" : "s"} (never pushed)`);
			if (result.excludedWhitelistedCount) parts.push(`${result.excludedWhitelistedCount} whitelisted`);
			exclusions.textContent = `${excluded} of ${result.totalActiveCount} active ban${result.totalActiveCount === 1 ? "" : "s"} excluded: ${parts.join(", ")}.`;
			exclusions.classList.remove("hidden");
		} else {
			exclusions.classList.add("hidden");
		}
	} catch (error) {
		byId("previewCount").textContent = "-";
		showToast(error.message, "bad");
	}
}

function renderWhitelist() {
	byId("whitelistRows").innerHTML = whitelist.length
		? whitelist
				.map(
					(entry) => `<tr>
        <td>${escapeHtml(entry.networkCidr)}</td>
        <td>${escapeHtml(entry.note ?? "-")}</td>
        <td>${escapeHtml(formatDate(entry.createdAt))}</td>
        <td><button class="button secondary compact" type="button" data-remove-whitelist="${escapeHtml(entry.id)}">Remove</button></td>
      </tr>`,
				)
				.join("")
		: '<tr><td colspan="4" class="empty-cell">No whitelist entries yet.</td></tr>';
	byId("whitelistRows")
		.querySelectorAll("[data-remove-whitelist]")
		.forEach((button) => button.addEventListener("click", () => void removeWhitelistEntry(button.dataset.removeWhitelist)));
}

async function loadWhitelist() {
	try {
		whitelist = (await api("/whitelist")).items ?? [];
		renderWhitelist();
	} catch (error) {
		showToast(error.message, "bad");
	}
}

async function addWhitelistEntry() {
	const networkCidr = byId("whitelistCidr").value.trim();
	if (!networkCidr) return;
	try {
		await api("/whitelist", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ networkCidr, note: byId("whitelistNote").value.trim() }),
		});
		byId("whitelistCidr").value = "";
		byId("whitelistNote").value = "";
		await loadWhitelist();
		showToast("Whitelist entry added.");
	} catch (error) {
		showToast(error.message, "bad");
	}
}

async function removeWhitelistEntry(id) {
	try {
		await api(`/whitelist/${encodeURIComponent(id)}`, { method: "DELETE" });
		await loadWhitelist();
		showToast("Whitelist entry removed.");
	} catch (error) {
		showToast(error.message, "bad");
	}
}

async function useMyCurrentIp() {
	try {
		const info = await api("/whoami");
		if (info?.ip) byId("whitelistCidr").value = info.ip;
		else showToast("Could not detect your current IP - enter it manually.", "bad");
	} catch {
		showToast("Could not detect your current IP - enter it manually.", "bad");
	}
}

function statusBadgeClass(status) {
	return status === "ok" ? "ok" : status === "error" ? "bad" : "warn";
}

function providerTypeLabel(type) {
	if (type === "unifi") return "UniFi Controller";
	if (type === "ovh") return "OVH Edge Firewall";
	return "Local nftables";
}

function renderProviders() {
	byId("providerRows").innerHTML = providers.length
		? providers
				.map(
					(provider) => `<tr>
        <td>${escapeHtml(provider.name)}</td>
        <td>${providerTypeLabel(provider.type)}</td>
        <td>${provider.enabled ? "Yes" : "No"}</td>
        <td>${escapeHtml(formatDate(provider.lastSyncedAt))}</td>
        <td>${provider.lastAppliedCount} / ${provider.maxEntries}</td>
        <td>${provider.lastSyncStatus ? `<span class="badge ${statusBadgeClass(provider.lastSyncStatus)}" title="${escapeHtml(provider.lastSyncError ?? "")}">${escapeHtml(provider.lastSyncStatus)}</span>` : "-"}</td>
        <td class="row">
          <button class="button secondary compact" type="button" data-edit="${escapeHtml(provider.id)}">Edit</button>
          <button class="button secondary compact" type="button" data-sync="${escapeHtml(provider.id)}">Sync now</button>
          <button class="button secondary compact" type="button" data-delete="${escapeHtml(provider.id)}">Delete</button>
        </td>
      </tr>`,
				)
				.join("")
		: '<tr><td colspan="7" class="empty-cell">No providers configured yet.</td></tr>';
	byId("providerRows")
		.querySelectorAll("[data-edit]")
		.forEach((button) => button.addEventListener("click", () => openProviderForm(providers.find((provider) => provider.id === button.dataset.edit))));
	byId("providerRows")
		.querySelectorAll("[data-sync]")
		.forEach((button) => button.addEventListener("click", () => void syncProviderNow(button.dataset.sync)));
	byId("providerRows")
		.querySelectorAll("[data-delete]")
		.forEach((button) => button.addEventListener("click", () => void deleteProvider(button.dataset.delete)));
}

async function loadProviders() {
	try {
		providers = (await api("/providers")).items ?? [];
		renderProviders();
	} catch (error) {
		showToast(error.message, "bad");
	}
}

async function syncProviderNow(id) {
	try {
		await api(`/providers/${encodeURIComponent(id)}/sync-now`, { method: "POST" });
		showToast("Sync triggered.");
		setTimeout(() => void loadProviders(), 1_000);
	} catch (error) {
		showToast(error.message, "bad");
	}
}

async function deleteProvider(id) {
	if (!confirm("Delete this provider? BurrowGate will try to remove its remote firewall entries too.")) return;
	try {
		const result = await api(`/providers/${encodeURIComponent(id)}`, { method: "DELETE" });
		await loadProviders();
		if (result.teardownError) showToast(`Provider deleted, but remote cleanup failed: ${result.teardownError}`, "bad");
		else showToast("Provider deleted and remote entries removed.");
	} catch (error) {
		showToast(error.message, "bad");
	}
}

function updateProviderTypeFields() {
	const type = byId("providerType").value;
	byId("unifiFields").classList.toggle("hidden", type !== "unifi");
	byId("nftablesFields").classList.toggle("hidden", type !== "nftables");
	byId("ovhFields").classList.toggle("hidden", type !== "ovh");
	byId("providerMaxEntries").max = type === "ovh" ? "20" : "";
}

function updateAckRow() {
	byId("providerAckRow").classList.toggle("hidden", !byId("providerEnabled").checked || whitelist.length > 0);
}

function openProviderForm(provider) {
	byId("providerTestResult").classList.add("hidden");
	byId("providerId").value = provider?.id ?? "";
	byId("providerDialogTitle").textContent = provider ? "Edit provider" : "Add provider";
	byId("providerName").value = provider?.name ?? "";
	byId("providerType").value = provider?.type ?? "unifi";
	byId("providerType").disabled = Boolean(provider);
	byId("providerMaxEntries").value = provider?.maxEntries ?? "";
	byId("providerEnabled").checked = provider?.enabled ?? false;
	byId("providerAcknowledge").checked = provider?.acknowledgedNoWhitelist ?? false;

	const config = provider?.config ?? {};
	byId("unifiControllerUrl").value = config.controllerUrl ?? "";
	byId("unifiApiBasePath").value = config.apiBasePath ?? "/proxy/network";
	byId("unifiSite").innerHTML = config.site
		? `<option value="${escapeHtml(config.site)}">${escapeHtml(config.site)}</option>`
		: `<option value="">Click "Load sites" first</option>`;
	byId("unifiSitesStatus").textContent = "";
	byId("unifiGroupName").value = config.listName ?? "BurrowGate-Banned-IPs";
	byId("unifiApiKey").value = "";
	byId("unifiApiKey").placeholder = config.apiKeyConfigured ? "Leave blank to keep the current key" : "Required";
	byId("unifiVerifyTls").checked = config.verifyTls ?? true;
	byId("nftBinaryPath").value = config.nftBinaryPath ?? "nft";
	byId("nftUseSudo").checked = config.useSudo ?? false;

	byId("ovhEndpoint").value = config.endpoint ?? "https://eu.api.ovh.com";
	byId("ovhApplicationKey").value = config.applicationKey ?? "";
	byId("ovhApplicationSecret").value = "";
	byId("ovhApplicationSecret").placeholder = config.applicationSecretConfigured ? "Leave blank to keep the current secret" : "Required";
	byId("ovhConsumerKey").value = "";
	byId("ovhConsumerKey").placeholder = config.consumerKeyConfigured ? "Leave blank to keep the current key" : "Required";
	byId("ovhCredentialStatus").textContent = "";
	byId("ovhIp").innerHTML = config.ipBlock
		? `<option value="${escapeHtml(config.ipBlock)}">${escapeHtml(config.ipBlock)}</option>`
		: `<option value="">Click "Load IPs" first</option>`;
	byId("ovhIpsStatus").textContent = "";

	updateProviderTypeFields();
	updateAckRow();
	openModal("provider");
}

async function loadUnifiSites() {
	const status = byId("unifiSitesStatus");
	status.textContent = "Loading...";
	status.className = "muted";
	try {
		const result = await api("/providers/unifi/sites", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				controllerUrl: byId("unifiControllerUrl").value.trim(),
				apiBasePath: byId("unifiApiBasePath").value.trim(),
				verifyTls: byId("unifiVerifyTls").checked,
				apiKey: byId("unifiApiKey").value.trim(),
				providerId: byId("providerId").value || undefined,
			}),
		});
		const currentValue = byId("unifiSite").value;
		byId("unifiSite").innerHTML = result.items.map((site) => `<option value="${escapeHtml(site.id)}">${escapeHtml(site.name)}</option>`).join("");
		if (result.items.some((site) => site.id === currentValue)) byId("unifiSite").value = currentValue;
		status.textContent = `Loaded ${result.items.length} site${result.items.length === 1 ? "" : "s"}.`;
	} catch (error) {
		status.textContent = error.message;
		status.className = "muted error-text";
	}
}

async function loadOvhIps() {
	const status = byId("ovhIpsStatus");
	status.textContent = "Loading...";
	status.className = "muted";
	try {
		const result = await api("/providers/ovh/ips", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				endpoint: byId("ovhEndpoint").value.trim(),
				applicationKey: byId("ovhApplicationKey").value.trim(),
				applicationSecret: byId("ovhApplicationSecret").value.trim(),
				consumerKey: byId("ovhConsumerKey").value.trim(),
				providerId: byId("providerId").value || undefined,
			}),
		});
		const currentValue = byId("ovhIp").value;
		byId("ovhIp").innerHTML = result.items
			.map((ip) => `<option value="${escapeHtml(ip.block)}">${escapeHtml(ip.block)}${ip.serviceName ? ` - ${escapeHtml(ip.serviceName)}` : ""}</option>`)
			.join("");
		if (result.items.some((ip) => ip.block === currentValue)) byId("ovhIp").value = currentValue;
		status.textContent = `Loaded ${result.items.length} IP${result.items.length === 1 ? "" : "s"}.`;
	} catch (error) {
		status.textContent = error.message;
		status.className = "muted error-text";
	}
}

async function requestOvhCredential() {
	const status = byId("ovhCredentialStatus");
	status.textContent = "Requesting...";
	status.className = "muted";
	try {
		const result = await api("/providers/ovh/credential", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ endpoint: byId("ovhEndpoint").value.trim(), applicationKey: byId("ovhApplicationKey").value.trim() }),
		});
		byId("ovhConsumerKey").value = result.consumerKey;
		status.innerHTML = `Requested. <a href="${escapeHtml(result.validationUrl)}" target="_blank" rel="noopener">Open this link to approve access</a>, then save the provider.`;
	} catch (error) {
		status.textContent = error.message;
		status.className = "muted error-text";
	}
}

function providerConfigFromForm() {
	const type = byId("providerType").value;
	if (type === "unifi") {
		return {
			controllerUrl: byId("unifiControllerUrl").value.trim(),
			apiBasePath: byId("unifiApiBasePath").value.trim(),
			site: byId("unifiSite").value.trim(),
			listName: byId("unifiGroupName").value.trim(),
			apiKey: byId("unifiApiKey").value.trim(),
			verifyTls: byId("unifiVerifyTls").checked,
		};
	}
	if (type === "ovh") {
		return {
			endpoint: byId("ovhEndpoint").value.trim(),
			applicationKey: byId("ovhApplicationKey").value.trim(),
			applicationSecret: byId("ovhApplicationSecret").value.trim(),
			consumerKey: byId("ovhConsumerKey").value.trim(),
			ipBlock: byId("ovhIp").value.trim(),
		};
	}
	return { nftBinaryPath: byId("nftBinaryPath").value.trim(), useSudo: byId("nftUseSudo").checked };
}

function providerPayload() {
	const maxEntries = Number(byId("providerMaxEntries").value);
	return {
		name: byId("providerName").value.trim(),
		type: byId("providerType").value,
		enabled: byId("providerEnabled").checked,
		acknowledgedNoWhitelist: byId("providerAcknowledge").checked,
		...(Number.isInteger(maxEntries) && maxEntries > 0 ? { maxEntries } : {}),
		config: providerConfigFromForm(),
	};
}

async function saveProvider() {
	const id = byId("providerId").value;
	try {
		if (id)
			await api(`/providers/${encodeURIComponent(id)}`, {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify(providerPayload()),
			});
		else await api("/providers", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(providerPayload()) });
		closeModal("provider");
		await loadProviders();
		showToast("Provider saved.");
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
		const outcome = await api(`/providers/${encodeURIComponent(id)}/test`, { method: "POST" });
		result.textContent = outcome.message;
		result.className = outcome.ok ? "muted" : "muted error-text";
	} catch (error) {
		result.textContent = error.message;
		result.className = "muted error-text";
	}
}

async function loadAll() {
	await Promise.all([loadPreview(), loadWhitelist(), loadProviders()]);
}

byId("whitelistAdd").addEventListener("click", () => void addWhitelistEntry());
byId("whitelistUseMine").addEventListener("click", () => void useMyCurrentIp());
byId("providerAdd").addEventListener("click", () => openProviderForm(null));
byId("providerType").addEventListener("change", updateProviderTypeFields);
byId("unifiLoadSites").addEventListener("click", () => void loadUnifiSites());
byId("ovhLoadIps").addEventListener("click", () => void loadOvhIps());
byId("ovhRequestCredential").addEventListener("click", () => void requestOvhCredential());
byId("providerEnabled").addEventListener("change", updateAckRow);
byId("providerTest").addEventListener("click", () => void testProviderConnection());
byId("providerSave").addEventListener("click", () => void saveProvider());

document.querySelectorAll(".modal-overlay").forEach((overlay) => {
	overlay.addEventListener("click", (event) => {
		if (event.target === overlay) closeModal(overlay.dataset.modal);
	});
	overlay.querySelector("[data-modal-close]").addEventListener("click", () => closeModal(overlay.dataset.modal));
});

byId("refreshDashboard").addEventListener("click", () => void loadAll());
byId("logout").addEventListener("click", async () => {
	await fetch("/_burrowgate/api/admin/logout", { method: "POST", headers: mutationHeaders });
	location.href = "/_burrowgate/admin/login";
});

void loadAll();
