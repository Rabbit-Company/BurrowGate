(() => {
	const challenge = window.__BURROWGATE_CHALLENGE__;
	const status = document.getElementById("status");
	const startedAt = Date.now();
	let finished = false;

	const container = document.createElement("div");
	container.id = "bg-recaptcha-v2";
	container.style.margin = "18px 0";
	(status ? status.parentNode : document.body).insertBefore(container, status ? status.nextSibling : null);

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
		if (window.grecaptcha && widgetId !== undefined) {
			window.grecaptcha.reset(widgetId);
			retryIfInvisible();
		}
	}

	let widgetId;
	const isInvisible = challenge.publicData.size === "invisible";

	function retryIfInvisible() {
		if (isInvisible && window.grecaptcha && widgetId !== undefined) window.grecaptcha.execute(widgetId);
	}

	window.__bgRecaptchaV2Onload = () => {
		widgetId = window.grecaptcha.render(container, {
			sitekey: challenge.publicData.siteKey,
			theme: challenge.publicData.theme,
			size: challenge.publicData.size,
			callback: submit,
			"error-callback": () => {
				if (status) status.textContent = "reCAPTCHA failed to load. Reloading...";
				setTimeout(() => location.reload(), 1200);
			},
			"expired-callback": () => {
				if (window.grecaptcha && widgetId !== undefined) window.grecaptcha.reset(widgetId);
				retryIfInvisible();
			},
		});
		if (status) status.textContent = "Complete the challenge to continue.";
		retryIfInvisible();
	};

	const script = document.createElement("script");
	script.src = "https://www.google.com/recaptcha/api.js?render=explicit&onload=__bgRecaptchaV2Onload";
	script.async = true;
	script.defer = true;
	document.head.appendChild(script);

	if (status) status.textContent = "Loading reCAPTCHA...";
})();
