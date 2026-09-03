(() => {
	const challenge = window.__BURROWGATE_CHALLENGE__;
	const status = document.getElementById("status");
	const T = challenge.text || {};
	function t(key, fallback) {
		return T[key] ?? fallback;
	}
	function substitute(str, vars) {
		return str.replace(/\{\{(\w+)\}\}/g, (_, name) => (name in vars ? String(vars[name]) : `{{${name}}}`));
	}

	let input = document.querySelector('[data-bg-password="input"]');
	let submitButton = document.querySelector('[data-bg-password="submit"]');

	if (!input) {
		const form = document.createElement("form");
		form.className = "bg-password-form";
		form.autocomplete = "off";

		input = document.createElement("input");
		input.type = "password";
		input.name = "password";
		input.autocomplete = "off";
		input.placeholder = t("inputPlaceholder", "Password");
		input.className = "bg-password-input";
		form.appendChild(input);

		submitButton = document.createElement("button");
		submitButton.type = "submit";
		submitButton.textContent = t("submitLabel", "Continue");
		submitButton.className = "bg-password-submit";
		form.appendChild(submitButton);

		(status ? status.parentNode : document.body).insertBefore(form, status ? status.nextSibling : null);
	}

	const style = document.createElement("style");
	style.textContent =
		".bg-password-form{display:flex;gap:8px;justify-content:center;margin:18px 0;flex-wrap:wrap}" +
		".bg-password-input{min-width:220px;padding:10px 12px;border-radius:8px;border:1px solid rgba(148,163,184,.35);background:rgba(15,23,42,.9);color:#e5e7eb;font-size:14px;outline:none}" +
		".bg-password-input:focus{border-color:#8b5cf6;box-shadow:0 0 0 2px rgba(139,92,246,.35)}" +
		".bg-password-submit{padding:10px 16px;border-radius:8px;border:1px solid rgba(148,163,184,.35);background:rgba(139,92,246,.35);color:#e5e7eb;font-size:14px;cursor:pointer;outline:none}" +
		".bg-password-submit:hover{background:rgba(139,92,246,.5)}" +
		".bg-password-submit:focus-visible{border-color:#8b5cf6;box-shadow:0 0 0 2px rgba(139,92,246,.35)}" +
		".bg-password-submit:disabled{opacity:.6;cursor:default}";
	document.head.appendChild(style);

	let finished = false;

	async function trySubmit(event) {
		if (event) event.preventDefault();
		if (finished) return;
		const value = input.value;
		if (!value) return;
		finished = true;
		if (submitButton) submitButton.disabled = true;
		if (status) status.textContent = t("verifying", "Verifying with BurrowGate...");

		const response = await fetch("/_burrowgate/api/challenge/verify", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ flowId: challenge.flowId, answer: { password: value } }),
		});
		const result = await response.json();
		if (result.done) {
			const minimumDisplayMs = Math.max(0, Number(challenge.minimumDisplayMs) || 0);
			const startedAt = Date.now();
			if (minimumDisplayMs > 0) {
				if (status)
					status.textContent = substitute(t("redirectingIn", "Verification successful. Redirecting in {{seconds}} seconds..."), {
						seconds: Math.ceil(minimumDisplayMs / 1000),
					});
				const countdown = setInterval(() => {
					const left = Math.max(0, minimumDisplayMs - (Date.now() - startedAt));
					if (status)
						status.textContent =
							left > 0
								? substitute(t("redirectingIn", "Verification successful. Redirecting in {{seconds}} seconds..."), { seconds: Math.ceil(left / 1000) })
								: t("redirecting", "Verification successful. Redirecting...");
					if (left <= 0) clearInterval(countdown);
				}, 250);
				setTimeout(() => location.replace(result.redirect || "/"), minimumDisplayMs);
			} else {
				location.replace(result.redirect || "/");
			}
			return;
		}
		if (result.next) {
			location.reload();
			return;
		}
		finished = false;
		if (submitButton) submitButton.disabled = false;
		input.value = "";
		input.focus();
		if (status) status.textContent = result.reason || t("incorrectPassword", "Incorrect password");
	}

	const ownForm = input.closest("form");
	if (ownForm) ownForm.addEventListener("submit", trySubmit);
	if (submitButton) submitButton.addEventListener("click", trySubmit);
	if (!ownForm) {
		input.addEventListener("keydown", (event) => {
			if (event.key === "Enter") trySubmit(event);
		});
	}

	if (status) status.textContent = t("statusReady", "Enter the password to continue.");
	input.focus();
})();
