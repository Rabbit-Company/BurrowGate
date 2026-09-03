(() => {
	const challenge = window.__BURROWGATE_CHALLENGE__;
	const status = document.getElementById("status");

	const { trackWidth, pieceSize, targetX, tolerancePx } = challenge.publicData;
	const MAX_SAMPLES = 500;
	const CANVAS_HEIGHT = pieceSize + 24;
	const CENTER_Y = CANVAS_HEIGHT / 2;

	const wrapper = document.createElement("div");
	wrapper.className = "bg-slider-wrapper";

	const canvas = document.createElement("canvas");
	canvas.width = trackWidth;
	canvas.height = CANVAS_HEIGHT;
	canvas.className = "bg-slider-canvas";
	wrapper.appendChild(canvas);

	const hint = document.createElement("div");
	hint.className = "bg-slider-hint";
	hint.textContent = "Drag the circle into the outlined target";
	wrapper.appendChild(hint);

	(status ? status.parentNode : document.body).insertBefore(wrapper, status ? status.nextSibling : null);

	const style = document.createElement("style");
	style.textContent =
		".bg-slider-wrapper{display:grid;gap:10px;justify-items:center;margin:18px 0}" +
		".bg-slider-canvas{display:block;background:#0b1220;border:1px solid rgba(148,163,184,.35);border-radius:10px;touch-action:none;cursor:grab}" +
		".bg-slider-canvas.is-dragging{cursor:grabbing}" +
		".bg-slider-hint{font-size:13px;color:#94a3b8}";
	document.head.appendChild(style);

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
		context.fillStyle = "#0b1220";
		context.fillRect(0, 0, canvas.width, canvas.height);

		context.strokeStyle = "rgba(148,163,184,.35)";
		context.lineWidth = 2;
		context.beginPath();
		context.moveTo(pieceSize / 2, CENTER_Y);
		context.lineTo(trackWidth - pieceSize / 2, CENTER_Y);
		context.stroke();

		context.strokeStyle = "#22d3ee";
		context.lineWidth = 2;
		context.beginPath();
		context.arc(targetX + pieceSize / 2, CENTER_Y, pieceSize / 2, 0, Math.PI * 2);
		context.stroke();

		context.fillStyle = "#7c3aed";
		context.beginPath();
		context.arc(pieceX + pieceSize / 2, CENTER_Y, pieceSize / 2, 0, Math.PI * 2);
		context.fill();
	}

	function pointerPos(event) {
		const rect = canvas.getBoundingClientRect();
		return { x: event.clientX - rect.left, y: event.clientY - rect.top };
	}

	function pushSample(x, y) {
		if (path.length >= MAX_SAMPLES) return;
		path.push({ x, y, t: Date.now() - dragStartedAt });
	}

	async function submit(finalX) {
		if (finished) return;
		finished = true;
		if (status) status.textContent = "Verifying with BurrowGate...";

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
				if (status) status.textContent = `Verification successful. Redirecting in ${Math.ceil(remainingMs / 1000)} seconds...`;
				const countdown = setInterval(() => {
					const left = Math.max(0, minimumDisplayMs - (Date.now() - startedAt));
					if (status)
						status.textContent =
							left > 0 ? `Verification successful. Redirecting in ${Math.ceil(left / 1000)} seconds...` : "Verification successful. Redirecting...";
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
		if (status) status.textContent = result.reason || "Verification failed. Reloading...";
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
			if (status) status.textContent = "Not quite - try again.";
			resetPiece();
		}
	}

	canvas.addEventListener("pointerup", endDrag);
	canvas.addEventListener("pointercancel", endDrag);

	if (status) status.textContent = "Drag the circle into the outlined target to continue.";
	render();
})();
