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

	const { rounds } = challenge.publicData;
	const optionColor = challenge.publicData.optionColor || "#0f172a";
	const optionBorderColor = challenge.publicData.optionBorderColor || "#202d4b";
	const optionTextColor = challenge.publicData.optionTextColor || "#e5e7eb";
	const accentColor = challenge.publicData.accentColor || "#7c3aed";
	const MAX_OPTIONS = 4;

	// Element contract: [data-bg-quiz="progress"] and/or ["options"] are reused as-is if present;
	// a default wrapper is only created for whichever piece is missing.
	let progressEl = document.querySelector('[data-bg-quiz="progress"]');
	let optionsEl = document.querySelector('[data-bg-quiz="options"]');
	if (!progressEl || !optionsEl) {
		const wrapper = document.createElement("div");
		wrapper.className = "bg-quiz-wrapper";

		if (!progressEl) {
			progressEl = document.createElement("div");
			progressEl.className = "bg-quiz-progress";
			wrapper.appendChild(progressEl);
		}

		if (!optionsEl) {
			optionsEl = document.createElement("div");
			optionsEl.className = "bg-quiz-options";
			wrapper.appendChild(optionsEl);
		}

		(status ? status.parentNode : document.body).insertBefore(wrapper, status ? status.nextSibling : null);
	}

	// [data-bg-quiz-option="0".."3"] - up to 4 fixed answer-button slots, all-or-nothing like
	// Snake's move hooks: if all four are present anywhere in the page, they're reused directly
	// (text + a click listener set on the real element, unused slots hidden per round) instead of
	// creating buttons at runtime - this is what makes each option fully positionable/restylable in
	// a custom template. Providing fewer than four falls back to the default per-round creation below.
	const fixedButtons = [];
	for (let i = 0; i < MAX_OPTIONS; i += 1) {
		const el = document.querySelector(`[data-bg-quiz-option="${i}"]`);
		if (el) fixedButtons.push(el);
	}
	const useFixedButtons = fixedButtons.length === MAX_OPTIONS;

	const style = document.createElement("style");
	style.textContent =
		".bg-quiz-wrapper{display:grid;gap:10px;margin:18px 0}" +
		".bg-quiz-progress{font-size:13px;color:#94a3b8;text-align:center}" +
		".bg-quiz-options{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}" +
		`.bg-quiz-option{padding:12px 14px;border-radius:8px;border:1px solid ${optionBorderColor};background:${optionColor};color:${optionTextColor};font-size:14px;cursor:pointer;outline:none;text-align:center}` +
		`.bg-quiz-option:hover{background:color-mix(in srgb, ${accentColor} 25%, ${optionColor})}` +
		`.bg-quiz-option:focus-visible{border-color:${accentColor};box-shadow:0 0 0 2px color-mix(in srgb, ${accentColor} 35%, transparent)}` +
		".bg-quiz-option:disabled{opacity:.6;cursor:default}";
	document.head.appendChild(style);

	let index = 0;
	let choices = [];
	let finished = false;
	let dynamicButtons = [];

	function setButtonsDisabled(disabled) {
		for (const button of useFixedButtons ? fixedButtons : dynamicButtons) button.disabled = disabled;
	}

	function renderRound() {
		const round = rounds[index];
		if (progressEl) progressEl.textContent = rounds.length > 1 ? `Question ${index + 1} of ${rounds.length}` : "";
		if (status) status.textContent = round.question;

		if (useFixedButtons) {
			fixedButtons.forEach((button, i) => {
				const option = round.options[i];
				button.hidden = option === undefined;
				button.disabled = option === undefined;
				if (option !== undefined) {
					button.textContent = option;
					button.dataset.quizOptionValue = option;
				}
			});
			return;
		}

		optionsEl.innerHTML = "";
		dynamicButtons = round.options.map((option) => {
			const button = document.createElement("button");
			button.type = "button";
			button.className = "bg-quiz-option";
			button.textContent = option;
			button.addEventListener("click", () => choose(option));
			optionsEl.appendChild(button);
			return button;
		});
	}

	if (useFixedButtons) {
		for (const button of fixedButtons) {
			button.addEventListener("click", () => {
				if (button.hidden || button.disabled) return;
				choose(button.dataset.quizOptionValue);
			});
		}
	}

	function choose(option) {
		if (finished) return;
		choices.push(option);
		index += 1;
		if (index < rounds.length) {
			renderRound();
		} else {
			void submit();
		}
	}

	function resetRound() {
		index = 0;
		choices = [];
		renderRound();
	}

	async function submit() {
		if (finished) return;
		finished = true;
		setButtonsDisabled(true);
		if (progressEl) progressEl.textContent = "";
		if (status) status.textContent = t("verifying", "Verifying with BurrowGate...");

		const response = await fetch("/_burrowgate/api/challenge/verify", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ flowId: challenge.flowId, answer: { choices } }),
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
		if (status) status.textContent = result.reason || t("wrongAnswer", "That's not quite right - try again.");
		setTimeout(() => {
			finished = false;
			resetRound();
		}, 1200);
	}

	renderRound();
})();
