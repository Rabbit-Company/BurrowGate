(() => {
	"use strict";

	// Mobile nav toggle
	const navToggle = document.querySelector(".nav-toggle");
	const navPanel = document.querySelector(".nav-primary-links");
	if (navToggle && navPanel) {
		navToggle.addEventListener("click", () => {
			const open = navPanel.classList.toggle("open");
			navToggle.setAttribute("aria-expanded", open ? "true" : "false");
		});
		navPanel.querySelectorAll("a").forEach((link) => {
			link.addEventListener("click", () => {
				navPanel.classList.remove("open");
				navToggle.setAttribute("aria-expanded", "false");
			});
		});
	}

	// Copy-to-clipboard for code blocks
	document.querySelectorAll(".code-copy").forEach((button) => {
		const targetId = button.getAttribute("data-copy-target");
		const target = targetId ? document.getElementById(targetId) : null;
		if (!target) return;
		const defaultLabel = button.innerHTML;
		button.addEventListener("click", async () => {
			try {
				await navigator.clipboard.writeText(target.textContent.trim());
				button.textContent = "Copied";
				setTimeout(() => {
					button.innerHTML = defaultLabel;
				}, 1800);
			} catch (err) {
				button.textContent = "Press Ctrl+C";
			}
		});
	});

	// Screenshot lightbox
	const lightbox = document.querySelector(".lightbox");
	if (lightbox) {
		const img = lightbox.querySelector("img");
		const titleEl = lightbox.querySelector(".lightbox-head h3");
		const descEl = lightbox.querySelector(".lightbox-head p");
		const closeBtn = lightbox.querySelector(".lightbox-close");

		const openLightbox = (trigger) => {
			const src = trigger.getAttribute("data-full");
			const alt = trigger.getAttribute("data-alt") || "";
			const title = trigger.getAttribute("data-title") || "";
			const desc = trigger.getAttribute("data-desc") || "";
			if (!src) return;
			img.src = src;
			img.alt = alt;
			if (titleEl) titleEl.textContent = title;
			if (descEl) descEl.textContent = desc;
			lightbox.classList.add("open");
			document.body.style.overflow = "hidden";
			closeBtn.focus();
		};

		const closeLightbox = () => {
			lightbox.classList.remove("open");
			document.body.style.overflow = "";
			img.src = "";
		};

		document.querySelectorAll("[data-lightbox-trigger]").forEach((trigger) => {
			trigger.addEventListener("click", (e) => {
				e.preventDefault();
				openLightbox(trigger);
			});
		});

		closeBtn.addEventListener("click", closeLightbox);
		lightbox.addEventListener("click", (e) => {
			if (e.target === lightbox) closeLightbox();
		});
		document.addEventListener("keydown", (e) => {
			if (e.key === "Escape" && lightbox.classList.contains("open")) closeLightbox();
		});
	}

	// Screenshot filter chips
	const filterBar = document.querySelector(".filter-bar");
	if (filterBar) {
		const chips = filterBar.querySelectorAll(".filter-chip");
		const cards = document.querySelectorAll("[data-category]");
		chips.forEach((chip) => {
			chip.addEventListener("click", () => {
				chips.forEach((c) => c.classList.remove("active"));
				chip.classList.add("active");
				const category = chip.getAttribute("data-filter");
				cards.forEach((card) => {
					const match = category === "all" || card.getAttribute("data-category") === category;
					card.style.display = match ? "" : "none";
				});
			});
		});
	}

	// Footer year
	const yearEl = document.getElementById("year");
	if (yearEl) yearEl.textContent = new Date().getFullYear();
})();
