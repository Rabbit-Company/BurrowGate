(function () {
	function escapeHtml(value) {
		return String(value ?? "")
			.replaceAll("&", "&amp;")
			.replaceAll("<", "&lt;")
			.replaceAll(">", "&gt;")
			.replaceAll('"', "&quot;")
			.replaceAll("'", "&#039;");
	}

	// Lightweight, safe rendering for GitHub release-note markdown: escape everything first, then
	// convert a handful of common constructs (headings, bold, inline code, links, bullet lists).
	function renderReleaseNotes(markdown) {
		const escaped = escapeHtml((markdown || "").replace(/\r\n?/g, "\n")).trim();
		if (!escaped) return '<p class="muted">No release notes provided.</p>';
		const withInline = escaped
			.replace(/^### (.*)$/gm, "<h4>$1</h4>")
			.replace(/^## (.*)$/gm, "<h3>$1</h3>")
			.replace(/^# (.*)$/gm, "<h3>$1</h3>")
			.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
			.replace(/`([^`]+)`/g, "<code>$1</code>")
			.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
		const lines = withInline.split("\n");
		const blocks = [];
		let list = null;
		for (const line of lines) {
			const bullet = line.match(/^\s*[-*]\s+(.*)$/);
			if (bullet) {
				if (!list) {
					list = [];
					blocks.push(list);
				}
				list.push(bullet[1]);
				continue;
			}
			list = null;
			blocks.push(line);
		}
		return blocks
			.map((block) => {
				if (Array.isArray(block)) return `<ul>${block.map((item) => `<li>${item}</li>`).join("")}</ul>`;
				if (!block.trim()) return "";
				if (/^<h[34]>/.test(block)) return block;
				return `<p>${block}</p>`;
			})
			.filter(Boolean)
			.join("");
	}

	function closeModal() {
		const overlay = document.getElementById("updateCheckModalOverlay");
		if (overlay) overlay.classList.add("hidden");
		if (!document.querySelector(".modal-overlay:not(.hidden)")) document.body.classList.remove("modal-open");
	}

	function ensureModal() {
		let overlay = document.getElementById("updateCheckModalOverlay");
		if (overlay) return overlay;
		overlay = document.createElement("div");
		overlay.id = "updateCheckModalOverlay";
		overlay.className = "modal-overlay hidden";
		overlay.innerHTML =
			'<div class="modal modal-large"><div class="modal-header"><h2 id="updateCheckModalTitle">Update available</h2>' +
			'<button type="button" class="button secondary icon-button modal-close" id="updateCheckModalClose" aria-label="Close">&times;</button></div>' +
			'<div class="modal-body">' +
			'<div id="updateCheckModalNotes"></div>' +
			'<p class="updateCheckModalFooter"><a id="updateCheckModalLink" target="_blank" rel="noopener noreferrer">View this release on GitHub</a></p></div></div>';
		document.body.appendChild(overlay);
		overlay.addEventListener("click", (event) => {
			if (event.target === overlay) closeModal();
		});
		document.getElementById("updateCheckModalClose").addEventListener("click", closeModal);
		document.addEventListener("keydown", (event) => {
			if (event.key === "Escape") closeModal();
		});
		return overlay;
	}

	function showModal(status) {
		const overlay = ensureModal();
		document.getElementById("updateCheckModalTitle").textContent = status.releaseName || `v${status.latestVersion}`;
		document.getElementById("updateCheckModalNotes").innerHTML = renderReleaseNotes(status.releaseNotes);
		const link = document.getElementById("updateCheckModalLink");
		link.href = status.releaseUrl || "#";
		overlay.classList.remove("hidden");
		document.body.classList.add("modal-open");
	}

	async function init() {
		const anchor = document.querySelector(".version-tag");
		if (!anchor || anchor.dataset.updateCheckAttached) return;
		anchor.dataset.updateCheckAttached = "1";
		let status;
		try {
			const response = await fetch("/_burrowgate/api/admin/update-status");
			if (!response.ok) return;
			status = await response.json();
		} catch {
			return;
		}
		if (!status || !status.updateAvailable || !status.latestVersion) return;
		const badge = document.createElement("button");
		badge.type = "button";
		badge.className = "badge info update-check-badge";
		badge.textContent = `Update available: v${status.latestVersion}`;
		badge.addEventListener("click", () => showModal(status));
		anchor.insertAdjacentElement("afterend", badge);
	}

	if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", () => void init());
	else void init();
})();
