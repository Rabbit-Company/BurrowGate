(() => {
	const challenge = window.__BURROWGATE_CHALLENGE__;
	const status = document.getElementById("status");
	const attempts = document.getElementById("attempts");
	const T = challenge.text || {};
	function t(key, fallback) {
		return T[key] ?? fallback;
	}
	function substitute(str, vars) {
		return str.replace(/\{\{(\w+)\}\}/g, (_, name) => (name in vars ? String(vars[name]) : `{{${name}}}`));
	}
	const workerCount = Math.max(1, Math.min(8, navigator.hardwareConcurrency || 2));
	const workers = [];
	let total = 0;
	let finished = false;
	const startedAt = Date.now();

	async function submit(nonce) {
		if (finished) return;
		finished = true;
		if (status) status.textContent = t("proofFound", "Proof found. Verifying with BurrowGate...");
		workers.forEach((worker) => worker.terminate());

		const response = await fetch("/_burrowgate/api/challenge/verify", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ flowId: challenge.flowId, answer: { nonce } }),
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
		if (status) status.textContent = result.reason || t("verificationFailed", "Verification failed. Reloading...");
		setTimeout(() => location.reload(), 1200);
	}

	for (let index = 0; index < workerCount; index += 1) {
		const worker = new Worker("/_burrowgate/static/pow-worker.js");
		workers.push(worker);
		worker.onmessage = (event) => {
			total += event.data.iterations || 0;
			if (attempts) attempts.textContent = total.toLocaleString();
			if (event.data.type === "solved") submit(event.data.nonce);
		};
		worker.postMessage({ seed: challenge.publicData.seed, difficulty: challenge.publicData.difficulty, start: index, step: workerCount });
	}

	if (status) status.textContent = substitute(t("provingWork", "Using {{workerCount}} browser worker(s)..."), { workerCount });
})();
