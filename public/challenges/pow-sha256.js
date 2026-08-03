(() => {
	const challenge = window.__BURROWGATE_CHALLENGE__;
	const status = document.getElementById("status");
	const attempts = document.getElementById("attempts");
	const workerCount = Math.max(1, Math.min(8, navigator.hardwareConcurrency || 2));
	const workers = [];
	let total = 0;
	let finished = false;
	const startedAt = Date.now();

	async function submit(nonce) {
		if (finished) return;
		finished = true;
		status.textContent = "Proof found. Verifying with BurrowGate...";
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
				status.textContent = `Verification successful. Redirecting in ${Math.ceil(remainingMs / 1000)} seconds...`;
				const timer = setInterval(() => {
					const left = Math.max(0, minimumDisplayMs - (Date.now() - startedAt));
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
		status.textContent = result.reason || "Verification failed. Reloading...";
		setTimeout(() => location.reload(), 1200);
	}

	for (let index = 0; index < workerCount; index += 1) {
		const worker = new Worker("/_burrowgate/static/pow-worker.js");
		workers.push(worker);
		worker.onmessage = (event) => {
			total += event.data.iterations || 0;
			attempts.textContent = total.toLocaleString();
			if (event.data.type === "solved") submit(event.data.nonce);
		};
		worker.postMessage({ seed: challenge.publicData.seed, difficulty: challenge.publicData.difficulty, start: index, step: workerCount });
	}

	status.textContent = `Using ${workerCount} browser worker${workerCount === 1 ? "" : "s"}...`;
})();
