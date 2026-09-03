(() => {
	const challenge = window.__BURROWGATE_CHALLENGE__;
	const status = document.getElementById("status");
	const startedAt = Date.now();
	let finished = false;

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
		if (status) status.textContent = "Verifying with BurrowGate...";

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
				if (status) status.textContent = `Verification successful. Redirecting in ${Math.ceil(remainingMs / 1000)} seconds...`;
				const timer = setInterval(() => {
					const left = Math.max(0, minimumDisplayMs - (Date.now() - startedAt));
					if (status)
						status.textContent =
							left > 0 ? `Verification successful. Redirecting in ${Math.ceil(left / 1000)} seconds...` : "Verification successful. Redirecting...";
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
		if (status) status.textContent = result.reason || "Verification failed. Try again.";
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
				if (status) status.textContent = "Turnstile failed to load. Reloading...";
				setTimeout(() => location.reload(), 1200);
			},
			"expired-callback": () => {
				if (window.turnstile && widgetId !== undefined) window.turnstile.reset(widgetId);
			},
		});
		if (status) status.textContent = "Complete the challenge to continue.";
	};

	const script = document.createElement("script");
	script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=__bgTurnstileOnload";
	script.async = true;
	script.defer = true;
	document.head.appendChild(script);

	if (status) status.textContent = "Loading Turnstile...";
})();
