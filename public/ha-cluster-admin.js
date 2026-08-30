const ADMIN_API = "/_burrowgate/api/admin/ha";
const mutationHeaders = { "x-burrowgate-admin": "1" };
const byId = (id) => document.getElementById(id);

const escapeHtml = (value) =>
	String(value ?? "").replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);

async function api(path, init = {}) {
	const headers = { ...mutationHeaders, ...(init.headers ?? {}) };
	const response = await fetch(`${ADMIN_API}${path}`, { ...init, headers });
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

function formatSince(timestamp) {
	if (!timestamp) return "-";
	return new Date(timestamp).toLocaleString();
}

function statusBadge(ok, label) {
	return `<span class="badge ${ok ? "ok" : "bad"}">${escapeHtml(label)}</span>`;
}

let identityFormPrefilled = false;

function renderSelf(status) {
	if (!status.enabled) {
		byId("selfRows").innerHTML = '<tr><td class="empty-cell">High Availability is not enabled on this instance.</td></tr>';
		byId("viewJoinCode").classList.add("hidden");
		return;
	}
	if (!identityFormPrefilled) {
		identityFormPrefilled = true;
		byId("identityNodeName").value = status.self.name ?? "";
		byId("identitySelfAdminUrl").value = status.self.selfAdminUrl ?? "";
	}
	const roleLabel = status.role === "primary" ? "Primary" : "Replica";
	const rows = [
		`<tr><td>Role</td><td>${escapeHtml(roleLabel)}</td></tr>`,
		`<tr><td>Name</td><td>${escapeHtml(status.self.name)}</td></tr>`,
		`<tr><td>Version</td><td>${escapeHtml(status.self.version)}</td></tr>`,
	];
	if (status.role === "replica") {
		const connected = status.connectionState === "connected";
		rows.push(`<tr><td>Connection to primary</td><td>${statusBadge(connected, connected ? "Connected" : status.connectionState)}</td></tr>`);
	}
	byId("selfRows").innerHTML = rows.join("");
	byId("viewJoinCode").classList.toggle("hidden", status.role !== "primary" || Boolean(status.authorityFence));
	byId("leaveCluster").classList.toggle("hidden", status.role !== "replica");
}

function nameCell(name, adminUrl) {
	const address = adminUrl ? `<br><small class="muted">${escapeHtml(adminUrl)}</small>` : "";
	return `${escapeHtml(name)}${address}`;
}

function syncCell(node, latestSeq) {
	if (node.lastAckedSeq == null) return '<span class="badge bad">Unknown</span>';
	if (typeof latestSeq !== "number") return '<span class="badge bad">Unknown</span>';
	const lag = Math.max(0, latestSeq - node.lastAckedSeq);
	return lag === 0 ? '<span class="badge ok">Up to date</span>' : `<span class="badge bad">${lag} change${lag === 1 ? "" : "s"} behind</span>`;
}

function renderNodes(status) {
	const notice = byId("clusterNotice");
	if (!status.enabled) {
		notice.classList.add("hidden");
		byId("nodeRows").innerHTML = '<tr><td colspan="6" class="empty-cell">-</td></tr>';
		return;
	}
	if (status.role === "replica" && status.primaryReachable === false) {
		notice.textContent = "The primary is unreachable from this node right now, so the full cluster list isn't available - showing this node's own status only.";
		notice.classList.remove("hidden");
		byId("nodeRows").innerHTML = '<tr><td colspan="6" class="empty-cell">Primary unreachable.</td></tr>';
		return;
	}
	const notices = [];
	if (status.authorityFence) {
		notices.push(
			`This primary observed cluster epoch ${status.authorityFence.observedEpoch} from node "${status.authorityFence.sourceNodeId}", newer than its own epoch, and has durably removed itself from service. ` +
				"It may be a stale former primary. Confirm the current primary, reconfigure this node as its replica, and restart it; do not clear the fence while its authority is uncertain.",
		);
	} else if (status.stuckPromotionIntent) {
		notices.push(
			`This node is durably write-fenced after an interrupted promotion of "${status.stuckPromotionIntent.targetNodeId}" that hasn't resolved itself. ` +
				"If that node is now running as primary elsewhere, this node needs manual recovery - see the Failover section of docs/HIGH_AVAILABILITY.md. " +
				"If it's just slow to reconnect, this will clear on its own once it does.",
		);
	} else if (status.fencedForPromotion) {
		notices.push("A promotion is currently in progress - configuration writes are temporarily paused.");
	}
	if (status.versionCompatible === false) {
		const mismatches = (status.versionMismatches ?? []).map((node) => `${node.name} (${node.version})`).join(", ");
		notices.push(
			`Cluster configuration is read-only because these nodes do not match this primary's version: ${mismatches}. Upgrade them, or forget an offline node that has been permanently removed.`,
		);
	}
	if (notices.length > 0) {
		notice.textContent = notices.join(" ");
		notice.classList.remove("hidden");
	} else {
		notice.classList.add("hidden");
	}
	if (status.role === "primary") {
		const rows = [
			`<tr><td>${nameCell(status.self.name, status.self.selfAdminUrl)}</td><td>Primary (you)</td><td>${escapeHtml(status.self.version)}</td><td>-</td><td>-</td><td></td></tr>`,
			...status.nodes.map((node) => {
				const sameVersion = node.version === status.self.version;
				const promoteButton =
					!status.authorityFence && node.connected && sameVersion && node.adminUrl
						? `<button class="button secondary promote-node-button" type="button" data-node-id="${escapeHtml(node.nodeId)}" data-node-name="${escapeHtml(node.name)}">Promote</button>`
						: "";
				const forgetButton =
					!status.authorityFence && !node.connected
						? `<button class="button secondary danger forget-node-button" type="button" data-node-id="${escapeHtml(node.nodeId)}" data-node-name="${escapeHtml(node.name)}">Forget</button>`
						: "";
				const seen = node.connected ? formatSince(node.connectedAt) : `Offline; last seen ${formatSince(node.lastSeenAt)}`;
				return `<tr><td>${nameCell(node.name, node.adminUrl)}</td><td>Replica${node.connected ? "" : " (offline)"}</td><td>${escapeHtml(node.version)}${sameVersion ? "" : ' <span class="badge bad">Mismatch</span>'}</td><td>${escapeHtml(seen)}</td><td>${node.connected ? syncCell(node, status.latestSeq) : '<span class="badge bad">Offline</span>'}</td><td>${promoteButton}${forgetButton}</td></tr>`;
			}),
		];
		byId("nodeRows").innerHTML = rows.join("");
		return;
	}
	const rows = [
		`<tr><td>${nameCell(status.primary.name, status.primary.selfAdminUrl ?? status.primary.adminUrl)}</td><td>Primary</td><td>${escapeHtml(status.primary.version)}</td><td>-</td><td>-</td><td></td></tr>`,
		...status.nodes.map((node) => {
			const isSelf = node.name === status.self.name;
			return `<tr><td>${nameCell(node.name, node.adminUrl)}</td><td>Replica${isSelf ? " (you)" : ""}</td><td>${escapeHtml(node.version)}</td><td>${escapeHtml(formatSince(node.connectedAt))}</td><td>${syncCell(node, status.latestSeq)}</td><td></td></tr>`;
		}),
	];
	byId("nodeRows").innerHTML = rows.join("");
}

function renderDeadLetters(data) {
	const rows = data.deadLetters ?? [];
	if (!data.enabled || rows.length === 0) {
		byId("deadLetterRows").innerHTML = '<tr><td colspan="5" class="empty-cell">No dropped events.</td></tr>';
		return;
	}
	byId("deadLetterRows").innerHTML = rows
		.map(
			(row) =>
				`<tr><td>${escapeHtml(row.node_id)}</td><td>${escapeHtml(row.entity_type)}:${escapeHtml(row.entity_id)}</td><td>${escapeHtml(row.op)}</td><td>${escapeHtml(row.reason)}</td><td>${escapeHtml(formatSince(row.occurred_at))}</td></tr>`,
		)
		.join("");
}

async function loadStatus() {
	try {
		const status = await api("/status");
		renderSelf(status);
		renderNodes(status);
	} catch (error) {
		showToast(error.message, "bad");
	}
	try {
		renderDeadLetters(await api("/dead-letters"));
	} catch (error) {
		showToast(error.message, "bad");
	}
}

byId("refreshDashboard").addEventListener("click", () => void loadStatus());
byId("logout").addEventListener("click", async () => {
	await fetch("/_burrowgate/api/admin/logout", { method: "POST", headers: mutationHeaders });
	location.href = "/_burrowgate/admin/login";
});

async function waitForRestartThenReload(maxAttempts = 30) {
	byId("restartOverlay").classList.remove("hidden");
	byId("restartOverlayError").classList.add("hidden");
	await new Promise((resolve) => setTimeout(resolve, 800));
	for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
		try {
			const response = await fetch("/_burrowgate/health", { cache: "no-store" });
			if (response.ok || response.status === 503) {
				location.reload();
				return;
			}
		} catch {}
		await new Promise((resolve) => setTimeout(resolve, 1_000));
	}
	byId("restartOverlayMessage").textContent = "This instance hasn't come back up yet.";
	byId("restartOverlayError").textContent =
		"If it's not running under a process supervisor that restarts it automatically (e.g. Docker's restart: unless-stopped, or systemd), it may need to be started manually.";
	byId("restartOverlayError").classList.remove("hidden");
}

async function handleRestartingFormSubmit(form, method, path, buildBody) {
	form.addEventListener("submit", async (event) => {
		event.preventDefault();
		const submit = form.querySelector('button[type="submit"]');
		submit.disabled = true;
		try {
			const data = Object.fromEntries(new FormData(form));
			await api(path, { method, headers: { "content-type": "application/json" }, body: JSON.stringify(buildBody(data)) });
			await waitForRestartThenReload();
		} catch (error) {
			showToast(error.message, "bad");
			submit.disabled = false;
		}
	});
}

byId("identityForm").addEventListener("submit", async (event) => {
	event.preventDefault();
	const form = event.currentTarget;
	const submit = form.querySelector('button[type="submit"]');
	submit.disabled = true;
	try {
		const data = Object.fromEntries(new FormData(form));
		await api("/identity", {
			method: "PUT",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ nodeName: data.nodeName || undefined, selfAdminUrl: data.selfAdminUrl }),
		});
		showToast("Saved.");
		await loadStatus();
	} catch (error) {
		showToast(error.message, "bad");
	} finally {
		submit.disabled = false;
	}
});

void handleRestartingFormSubmit(byId("joinClusterForm"), "POST", "/join", (data) => ({
	joinCode: data.joinCode,
	selfAdminUrl: data.selfAdminUrl,
	nodeName: data.nodeName || undefined,
}));

byId("viewJoinCode").addEventListener("click", async () => {
	try {
		const { joinCode } = await api("/join-code", { method: "POST" });
		byId("joinCodeValue").textContent = joinCode;
		byId("joinCodePanel").classList.remove("hidden");
	} catch (error) {
		showToast(error.message, "bad");
	}
});
byId("copyJoinCode").addEventListener("click", async () => {
	try {
		await navigator.clipboard.writeText(byId("joinCodeValue").textContent);
		showToast("Join code copied.");
	} catch {
		showToast("Could not copy automatically. Select the code and copy it manually.", "bad");
	}
});

byId("leaveCluster").addEventListener("click", async () => {
	const confirmed = confirm(
		"Leave this cluster?\n\nThis node will become a standalone primary of a new cluster of one, with a freshly generated join code. It will restart to apply the change.",
	);
	if (!confirmed) return;
	const button = byId("leaveCluster");
	button.disabled = true;
	try {
		await api("/leave", { method: "POST" });
		await waitForRestartThenReload();
	} catch (error) {
		showToast(error.message, "bad");
		button.disabled = false;
	}
});

byId("nodeRows").addEventListener("click", async (event) => {
	const forgetButton = event.target.closest(".forget-node-button");
	if (forgetButton) {
		const nodeId = forgetButton.dataset.nodeId;
		const nodeName = forgetButton.dataset.nodeName;
		if (
			!confirm(
				`Forget offline node "${nodeName}"?\n\nOnly do this after it has left the cluster or been permanently decommissioned. If it reconnects, it will register again.`,
			)
		)
			return;
		forgetButton.disabled = true;
		try {
			await api(`/nodes/${encodeURIComponent(nodeId)}`, { method: "DELETE" });
			showToast("Node forgotten.");
			await loadStatus();
		} catch (error) {
			showToast(error.message, "bad");
			forgetButton.disabled = false;
		}
		return;
	}
	const button = event.target.closest(".promote-node-button");
	if (!button) return;
	const nodeId = button.dataset.nodeId;
	const nodeName = button.dataset.nodeName;
	const confirmed = confirm(
		`Promote "${nodeName}" to primary?\n\nThis restarts every currently-connected node in the cluster, including this one. ` +
			"Only promote the node that's most recently connected/caught-up - there is no automatic protection against promoting a stale one.",
	);
	if (!confirmed) return;
	button.disabled = true;
	try {
		await api(`/promote/${encodeURIComponent(nodeId)}`, { method: "POST" });
		await waitForRestartThenReload();
	} catch (error) {
		showToast(error.message, "bad");
		button.disabled = false;
	}
});

void loadStatus();
