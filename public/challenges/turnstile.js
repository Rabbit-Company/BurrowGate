(() => {
	const challenge = window.__BURROWGATE_CHALLENGE__;
	const status = document.getElementById("status");
	const startedAt = Date.now();
	let finished = false;
	const T = challenge.text || {};
	function t(key, fallback) {
		return T[key] ?? fallback;
	}
	function substitute(str, vars) {
		return str.replace(/\{\{(\w+)\}\}/g, (_, name) => (name in vars ? String(vars[name]) : `{{${name}}}`));
	}

	let container = document.querySelector('[data-bg-turnstile="widget"]');
	if (!container) {
		container = document.createElement("div");
		container.id = "bg-turnstile";
		container.style.margin = "18px 0";
		(status ? status.parentNode : document.body).insertBefore(container, status ? status.nextSibling : null);
	}

	async function submit(token) {
		if (finished) return;
		finished = true;
		if (status) status.textContent = t("verifying", "Verifying with BurrowGate...");

		const response = await fetch("/_burrowgate/api/challenge/verify", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ flowId: challenge.flowId, answer: { token } }),
		});
		const result = await response.json();
		if (result.done) {
			const minimumDisplayMs = Math.max(0, Number(challenge.minimumDisplayMs) || 0);
			const remainingMs = Math.max(0, minimumDisplayMs - (Date.now() - startedAt));
			if (remainingMs > 0) {
				if (status)
					status.textContent = substitute(t("redirectingIn", "Verification successful. Redirecting in {{seconds}} seconds..."), {
						seconds: Math.ceil(remainingMs / 1000),
					});
				const timer = setInterval(() => {
					const left = Math.max(0, minimumDisplayMs - (Date.now() - startedAt));
					if (status)
						status.textContent =
							left > 0
								? substitute(t("redirectingIn", "Verification successful. Redirecting in {{seconds}} seconds..."), { seconds: Math.ceil(left / 1000) })
								: t("redirecting", "Verification successful. Redirecting...");
					if (left <= 0) clearInterval(timer);
				}, 250);
				setTimeout(() => location.replace(result.redirect || "/"), remainingMs);
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
		if (status) status.textContent = result.reason || t("verificationFailed", "Verification failed. Try again.");
		if (window.turnstile && widgetId !== undefined) window.turnstile.reset(widgetId);
	}

	let widgetId;

	window.__bgTurnstileOnload = () => {
		widgetId = window.turnstile.render(container, {
			sitekey: challenge.publicData.siteKey,
			theme: challenge.publicData.theme,
			size: challenge.publicData.size,
			callback: submit,
			"error-callback": () => {
				if (status) status.textContent = t("loadFailed", "Turnstile failed to load. Reloading...");
				setTimeout(() => location.reload(), 1200);
			},
			"expired-callback": () => {
				if (window.turnstile && widgetId !== undefined) window.turnstile.reset(widgetId);
			},
		});
		if (status) status.textContent = t("completePrompt", "Complete the challenge to continue.");
	};

	const script = document.createElement("script");
	script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=__bgTurnstileOnload";
	script.async = true;
	script.defer = true;
	document.head.appendChild(script);

	if (status) status.textContent = t("widgetLoading", "Loading Turnstile...");
})();
