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

	const { trackWidth, pieceSize, targetX, tolerancePx } = challenge.publicData;
	const pieceShape = challenge.publicData.pieceShape || "circle";
	const pieceColor = challenge.publicData.pieceColor || "#7c3aed";
	const targetColor = challenge.publicData.targetColor || "#22d3ee";
	const trackColor = challenge.publicData.trackColor || "#94a3b8";
	const backgroundColor = challenge.publicData.backgroundColor || "#0b1220";
	const TRACK_WIDTH_PX = 6;
	const MAX_SAMPLES = 500;
	const CANVAS_HEIGHT = pieceSize + 24;
	const CENTER_Y = CANVAS_HEIGHT / 2;
	const EDGE_PADDING = 10;

	let canvas = document.querySelector('[data-bg-slider="canvas"]');
	if (!canvas) {
		const wrapper = document.createElement("div");
		wrapper.className = "bg-slider-wrapper";

		canvas = document.createElement("canvas");
		canvas.className = "bg-slider-canvas";
		wrapper.appendChild(canvas);

		const hint = document.createElement("div");
		hint.className = "bg-slider-hint";
		hint.textContent = t("hint", "Drag the circle into the outlined target");
		wrapper.appendChild(hint);

		(status ? status.parentNode : document.body).insertBefore(wrapper, status ? status.nextSibling : null);
	}
	canvas.width = trackWidth + EDGE_PADDING * 2;
	canvas.height = CANVAS_HEIGHT;

	const style = document.createElement("style");
	style.textContent =
		".bg-slider-wrapper{display:grid;gap:10px;justify-items:center;margin:18px 0}" +
		".bg-slider-canvas{display:block;max-width:100%;border:1px solid rgba(148,163,184,.35);border-radius:10px;touch-action:none;cursor:grab}" +
		".bg-slider-canvas.is-dragging{cursor:grabbing}" +
		".bg-slider-hint{font-size:13px;color:#94a3b8}";
	document.head.appendChild(style);
	canvas.style.background = backgroundColor;

	const context = canvas.getContext("2d");

	let pieceX = 0;
	let dragging = false;
	let grabOffsetX = 0;
	let dragStartedAt = 0;
	let path = [];
	let finished = false;

	function clamp(value, min, max) {
		return Math.max(min, Math.min(max, value));
	}

	function render() {
		context.fillStyle = backgroundColor;
		context.fillRect(0, 0, canvas.width, canvas.height);

		context.strokeStyle = trackColor;
		context.lineWidth = TRACK_WIDTH_PX;
		context.lineCap = "round";
		context.beginPath();
		context.moveTo(EDGE_PADDING + pieceSize / 2, CENTER_Y);
		context.lineTo(EDGE_PADDING + trackWidth - pieceSize / 2, CENTER_Y);
		context.stroke();

		context.strokeStyle = targetColor;
		context.lineWidth = 2;
		context.beginPath();
		if (pieceShape === "square") {
			const half = pieceSize / 2;
			context.strokeRect(EDGE_PADDING + targetX, CENTER_Y - half, pieceSize, pieceSize);
		} else {
			context.arc(EDGE_PADDING + targetX + pieceSize / 2, CENTER_Y, pieceSize / 2, 0, Math.PI * 2);
			context.stroke();
		}

		context.fillStyle = pieceColor;
		context.beginPath();
		if (pieceShape === "square") {
			const half = pieceSize / 2;
			context.fillRect(EDGE_PADDING + pieceX, CENTER_Y - half, pieceSize, pieceSize);
		} else {
			context.arc(EDGE_PADDING + pieceX + pieceSize / 2, CENTER_Y, pieceSize / 2, 0, Math.PI * 2);
			context.fill();
		}
	}

	function pointerPos(event) {
		const rect = canvas.getBoundingClientRect();
		const scaleX = canvas.width / rect.width;
		const scaleY = canvas.height / rect.height;
		return { x: (event.clientX - rect.left) * scaleX - EDGE_PADDING, y: (event.clientY - rect.top) * scaleY };
	}

	function pushSample(x, y) {
		if (path.length >= MAX_SAMPLES) return;
		path.push({ x, y, t: Date.now() - dragStartedAt });
	}

	async function submit(finalX) {
		if (finished) return;
		finished = true;
		if (status) status.textContent = t("verifying", "Verifying with BurrowGate...");

		const response = await fetch("/_burrowgate/api/challenge/verify", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ flowId: challenge.flowId, answer: { finalX, path } }),
		});
		const result = await response.json();
		if (result.done) {
			const minimumDisplayMs = Math.max(0, Number(challenge.minimumDisplayMs) || 0);
			const startedAt = Date.now();
			const remainingMs = minimumDisplayMs;
			if (remainingMs > 0) {
				if (status)
					status.textContent = substitute(t("redirectingIn", "Verification successful. Redirecting in {{seconds}} seconds..."), {
						seconds: Math.ceil(remainingMs / 1000),
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

	function resetPiece() {
		pieceX = 0;
		path = [];
		render();
	}

	canvas.addEventListener("pointerdown", (event) => {
		if (finished) return;
		const point = pointerPos(event);
		const centerX = pieceX + pieceSize / 2;
		const centerY = CENTER_Y;
		const distance = Math.hypot(point.x - centerX, point.y - centerY);
		if (distance > pieceSize / 2 + 6) return;
		event.preventDefault();
		dragging = true;
		canvas.classList.add("is-dragging");
		canvas.setPointerCapture(event.pointerId);
		grabOffsetX = point.x - pieceX;
		dragStartedAt = Date.now();
		path = [{ x: pieceX, y: point.y, t: 0 }];
	});

	canvas.addEventListener("pointermove", (event) => {
		if (!dragging || finished) return;
		const point = pointerPos(event);
		pieceX = clamp(point.x - grabOffsetX, 0, trackWidth - pieceSize);
		pushSample(pieceX, clamp(point.y, 0, CANVAS_HEIGHT));
		render();
	});

	function endDrag(event) {
		if (!dragging) return;
		dragging = false;
		canvas.classList.remove("is-dragging");
		try {
			canvas.releasePointerCapture(event.pointerId);
		} catch {}
		if (Math.abs(pieceX - targetX) <= tolerancePx) {
			void submit(pieceX);
		} else {
			if (status) status.textContent = t("retry", "Not quite - try again.");
			resetPiece();
		}
	}

	canvas.addEventListener("pointerup", endDrag);
	canvas.addEventListener("pointercancel", endDrag);

	if (status) status.textContent = t("statusReady", "Drag the circle into the outlined target to continue.");
	render();
})();
