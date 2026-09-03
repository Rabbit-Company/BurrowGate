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
		if (status) status.textContent = result.reason || t("verificationFailed", "Verification failed. Reloading...");
		setTimeout(() => location.reload(), 1200);
	}

	function fail(message) {
		if (status) status.textContent = message;
		setTimeout(() => location.reload(), 1200);
	}

	const script = document.createElement("script");
	script.src = `https://www.google.com/recaptcha/api.js?render=${encodeURIComponent(challenge.publicData.siteKey)}`;
	script.async = true;
	script.defer = true;
	script.onload = () => {
		if (!window.grecaptcha) {
			fail(t("loadFailed", "reCAPTCHA failed to load. Reloading..."));
			return;
		}
		window.grecaptcha.ready(() => {
			window.grecaptcha
				.execute(challenge.publicData.siteKey, { action: challenge.publicData.action })
				.then(submit)
				.catch(() => fail(t("executionFailed", "reCAPTCHA verification failed. Reloading...")));
		});
	};
	script.onerror = () => fail(t("loadFailed", "reCAPTCHA failed to load. Reloading..."));
	document.head.appendChild(script);

	if (status) status.textContent = t("verifyingBrowser", "Verifying your browser...");
})();
