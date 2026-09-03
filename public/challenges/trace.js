(() => {
	const challenge = window.__BURROWGATE_CHALLENGE__;
	const status = document.getElementById("status");

	// Shared engine: MUST match src/challenges/providers/trace-engine.ts exactly. Same PRNG, same
	// track-shape generators, same point-to-segment distance/wall-metrics math. If you change one,
	// change the other and update both algorithm comments together.
	const CANVAS_WIDTH = 460;
	const CANVAS_HEIGHT = 300;
	const CANVAS_MARGIN = 40;
	const BALL_RADIUS = 10;
	const MIN_EFFECTIVE_WIDTH = BALL_RADIUS * 2 + 28;

	function seededRandom(seed) {
		let state = seed % 2147483647;
		if (state <= 0) state += 2147483646;
		return function () {
			state = (state * 16807) % 2147483647;
			return (state - 1) / 2147483646;
		};
	}

	function generatePathPoints(shape, seed, pathWidth) {
		const rng = seededRandom(seed);
		const w = CANVAS_WIDTH;
		const h = CANVAS_HEIGHT;
		const points = [];

		const startY = CANVAS_MARGIN + rng() * (h - 2 * CANVAS_MARGIN);
		const endY = CANVAS_MARGIN + rng() * (h - 2 * CANVAS_MARGIN);
		const start = { x: CANVAS_MARGIN, y: startY };
		const end = { x: w - CANVAS_MARGIN, y: endY };
		const straightWidth = Math.max(pathWidth, MIN_EFFECTIVE_WIDTH);

		if (shape === "chokepoint") {
			const maxWidth = Math.max(pathWidth * 1.25, MIN_EFFECTIVE_WIDTH + 16);
			const minWidth = MIN_EFFECTIVE_WIDTH;
			const endpointWidth = MIN_EFFECTIVE_WIDTH + 8;
			const freq1 = 2 + rng() * 2;
			const freq2 = 4 + rng() * 3;
			const phaseOffset = rng() * Math.PI * 2;

			for (let i = 0; i <= 150; i += 1) {
				const t = i / 150;
				const x = start.x + t * (end.x - start.x);
				const baseY = start.y + t * (end.y - start.y);
				const widthScale = 0.5 + 0.5 * Math.cos(t * Math.PI * freq2 + phaseOffset);
				const width = i === 0 || i === 150 ? endpointWidth : minWidth + widthScale * (maxWidth - minWidth);
				const y = baseY + Math.sin(t * Math.PI * freq1 + phaseOffset) * 50;
				points.push({ x, y, width });
			}
		} else if (shape === "bezier") {
			const cp1 = { x: w * 0.25, y: CANVAS_MARGIN + rng() * (h - 2 * CANVAS_MARGIN) };
			const cp2 = { x: w * 0.75, y: CANVAS_MARGIN + rng() * (h - 2 * CANVAS_MARGIN) };

			for (let i = 0; i <= 120; i += 1) {
				const t = i / 120;
				const x = (1 - t) ** 3 * start.x + 3 * (1 - t) ** 2 * t * cp1.x + 3 * (1 - t) * t ** 2 * cp2.x + t ** 3 * end.x;
				const y = (1 - t) ** 3 * start.y + 3 * (1 - t) ** 2 * t * cp1.y + 3 * (1 - t) * t ** 2 * cp2.y + t ** 3 * end.y;
				points.push({ x, y, width: straightWidth });
			}
		} else if (shape === "zigzag") {
			const waypoints = [start, { x: w * 0.33, y: h - CANVAS_MARGIN }, { x: w * 0.66, y: CANVAS_MARGIN }, end];
			for (let i = 0; i < waypoints.length - 1; i += 1) {
				const p1 = waypoints[i];
				const p2 = waypoints[i + 1];
				const segmentSteps = 30;
				for (let j = 0; j < segmentSteps; j += 1) {
					const t = j / segmentSteps;
					points.push({ x: p1.x + (p2.x - p1.x) * t, y: p1.y + (p2.y - p1.y) * t, width: straightWidth });
				}
			}
			points.push({ x: end.x, y: end.y, width: straightWidth });
		} else {
			const amp = h / 2 - CANVAS_MARGIN;
			for (let i = 0; i <= 150; i += 1) {
				const t = i / 150;
				const x = start.x + t * (end.x - start.x);
				const y = h / 2 + Math.sin(t * Math.PI * 3) * amp;
				points.push({ x, y, width: straightWidth });
			}
		}

		points[0] = { x: start.x, y: start.y, width: points[0].width };
		points[points.length - 1] = { x: end.x, y: end.y, width: points[points.length - 1].width };

		return { points, start, end };
	}

	function distToSegment(pt, p1, p2) {
		const l2 = Math.hypot(p2.x - p1.x, p2.y - p1.y) ** 2;
		if (l2 === 0) return { dist: Math.hypot(pt.x - p1.x, pt.y - p1.y), width: p1.width };
		const t = Math.max(0, Math.min(1, ((pt.x - p1.x) * (p2.x - p1.x) + (pt.y - p1.y) * (p2.y - p1.y)) / l2));
		const projX = p1.x + t * (p2.x - p1.x);
		const projY = p1.y + t * (p2.y - p1.y);
		const width = p1.width + t * (p2.width - p1.width);
		return { dist: Math.hypot(pt.x - projX, pt.y - projY), width };
	}

	function trackMetrics(pt, points) {
		let minDistance = Infinity;
		let width = 36;
		for (let i = 0; i < points.length - 1; i += 1) {
			const res = distToSegment(pt, points[i], points[i + 1]);
			if (res.dist < minDistance) {
				minDistance = res.dist;
				width = res.width;
			}
		}
		const allowedRadius = width / 2 - BALL_RADIUS;
		const oobDepth = Math.max(0, minDistance - allowedRadius);
		return { minDistance, allowedRadius, oobDepth, isWallHit: oobDepth > 0 };
	}
	// End shared engine

	// Gameplay thresholds a genuine player can legitimately trip and needs live feedback for - duplicated
	// from src/challenges/providers/trace.ts. The timing/jitter/"too perfect" anti-bot checks stay
	// server-only, same as snake.js/slider.js: a real human dragging a mouse can't accidentally trip them.
	const MAX_HIT_RATIO = 0.35;
	const MAX_OOB_DEPTH_PX = 25;
	const MAX_SAMPLES = 1200;

	const { shape, pathWidth, seed, ballRadius, endRadius } = challenge.publicData;
	const track = generatePathPoints(shape, seed, pathWidth);

	// Element contract: a template may supply [data-bg-trace="canvas"] and/or ["metrics"] - each is
	// reused as-is independently if found; a default wrapper/hint is only created for whichever piece
	// is missing (see trace.js's default template for the usual layout, which supplies both).
	let canvas = document.querySelector('[data-bg-trace="canvas"]');
	let metricsEl = document.querySelector('[data-bg-trace="metrics"]');
	if (!canvas || !metricsEl) {
		const wrapper = document.createElement("div");
		wrapper.className = "bg-trace-wrapper";

		if (!canvas) {
			canvas = document.createElement("canvas");
			canvas.className = "bg-trace-canvas";
			wrapper.appendChild(canvas);
		}

		if (!metricsEl) {
			metricsEl = document.createElement("div");
			metricsEl.className = "bg-trace-metrics";
			wrapper.appendChild(metricsEl);
		}

		const hint = document.createElement("div");
		hint.className = "bg-trace-hint";
		hint.textContent = "Drag the ball along the path to the target without touching the walls";
		wrapper.appendChild(hint);

		(status ? status.parentNode : document.body).insertBefore(wrapper, status ? status.nextSibling : null);
	}
	canvas.width = CANVAS_WIDTH;
	canvas.height = CANVAS_HEIGHT;

	const style = document.createElement("style");
	style.textContent =
		".bg-trace-wrapper{display:grid;gap:10px;justify-items:center;margin:18px 0}" +
		".bg-trace-canvas{display:block;max-width:100%;background:#0b1220;border:1px solid rgba(148,163,184,.35);border-radius:10px;touch-action:none;cursor:grab}" +
		".bg-trace-canvas.is-dragging{cursor:grabbing}" +
		".bg-trace-metrics{font-size:12px;color:#94a3b8;display:flex;gap:14px}" +
		".bg-trace-hint{font-size:13px;color:#94a3b8}";
	document.head.appendChild(style);

	const context = canvas.getContext("2d");

	let ballPos = { x: track.start.x, y: track.start.y };
	let dragging = false;
	let dragStartedAt = 0;
	let path = [];
	let hitCount = 0;
	let maxExcursion = 0;
	let finished = false;

	function updateMetrics() {
		if (metricsEl) metricsEl.textContent = `Wall touches: ${hitCount} | Max excursion: ${maxExcursion.toFixed(1)}px`;
	}

	function draw() {
		context.clearRect(0, 0, canvas.width, canvas.height);

		for (let i = 0; i < track.points.length - 1; i += 1) {
			const p1 = track.points[i];
			const p2 = track.points[i + 1];
			context.beginPath();
			context.moveTo(p1.x, p1.y);
			context.lineTo(p2.x, p2.y);
			context.strokeStyle = "#1e293b";
			context.lineWidth = p1.width;
			context.lineCap = "round";
			context.lineJoin = "round";
			context.stroke();
		}

		context.beginPath();
		context.arc(track.end.x, track.end.y, endRadius, 0, Math.PI * 2);
		context.fillStyle = "#ff4d4d";
		context.fill();

		if (path.length > 1) {
			context.beginPath();
			context.moveTo(path[0].x, path[0].y);
			for (let i = 1; i < path.length; i += 1) context.lineTo(path[i].x, path[i].y);
			context.strokeStyle = "#22d3ee";
			context.lineWidth = 2;
			context.stroke();
		}

		context.beginPath();
		context.arc(ballPos.x, ballPos.y, ballRadius, 0, Math.PI * 2);
		context.fillStyle = "#7c3aed";
		context.fill();
		context.strokeStyle = "#fff";
		context.lineWidth = 2;
		context.stroke();
	}

	function pointerPos(event) {
		const rect = canvas.getBoundingClientRect();
		const scaleX = canvas.width / rect.width;
		const scaleY = canvas.height / rect.height;
		return { x: (event.clientX - rect.left) * scaleX, y: (event.clientY - rect.top) * scaleY };
	}

	function pushSample(point) {
		if (path.length >= MAX_SAMPLES) return;
		path.push({ x: point.x, y: point.y, t: Date.now() - dragStartedAt });
		const metrics = trackMetrics(point, track.points);
		if (metrics.isWallHit) {
			hitCount += 1;
			maxExcursion = Math.max(maxExcursion, metrics.oobDepth);
		}
		updateMetrics();
	}

	async function submit() {
		if (finished) return;
		finished = true;
		if (status) status.textContent = "Verifying with BurrowGate...";

		const response = await fetch("/_burrowgate/api/challenge/verify", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ flowId: challenge.flowId, answer: { path } }),
		});
		const result = await response.json();
		if (result.done) {
			const minimumDisplayMs = Math.max(0, Number(challenge.minimumDisplayMs) || 0);
			const startedAt = Date.now();
			if (minimumDisplayMs > 0) {
				if (status) status.textContent = `Verification successful. Redirecting in ${Math.ceil(minimumDisplayMs / 1000)} seconds...`;
				const countdown = setInterval(() => {
					const left = Math.max(0, minimumDisplayMs - (Date.now() - startedAt));
					if (status)
						status.textContent =
							left > 0 ? `Verification successful. Redirecting in ${Math.ceil(left / 1000)} seconds...` : "Verification successful. Redirecting...";
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
		if (status) status.textContent = result.reason || "Verification failed. Reloading...";
		setTimeout(() => location.reload(), 1200);
	}

	function resetBall() {
		ballPos = { x: track.start.x, y: track.start.y };
		path = [];
		hitCount = 0;
		maxExcursion = 0;
		updateMetrics();
		draw();
	}

	canvas.addEventListener("pointerdown", (event) => {
		if (finished) return;
		const point = pointerPos(event);
		if (Math.hypot(point.x - ballPos.x, point.y - ballPos.y) > ballRadius * 2) return;
		event.preventDefault();
		dragging = true;
		canvas.classList.add("is-dragging");
		canvas.setPointerCapture(event.pointerId);
		dragStartedAt = Date.now();
		hitCount = 0;
		maxExcursion = 0;
		ballPos = point;
		path = [{ x: point.x, y: point.y, t: 0 }];
		updateMetrics();
		draw();
	});

	canvas.addEventListener("pointermove", (event) => {
		if (!dragging || finished) return;
		const point = pointerPos(event);
		ballPos = point;
		pushSample(point);
		draw();
	});

	function endDrag(event) {
		if (!dragging) return;
		dragging = false;
		canvas.classList.remove("is-dragging");
		try {
			canvas.releasePointerCapture(event.pointerId);
		} catch {}

		const reachedEnd = Math.hypot(ballPos.x - track.end.x, ballPos.y - track.end.y) <= endRadius;
		const hitRatio = path.length > 0 ? hitCount / path.length : 1;
		if (reachedEnd && hitRatio <= MAX_HIT_RATIO && maxExcursion <= MAX_OOB_DEPTH_PX) {
			void submit();
		} else {
			if (status) status.textContent = "Not quite - try again.";
			resetBall();
		}
	}

	canvas.addEventListener("pointerup", endDrag);
	canvas.addEventListener("pointercancel", endDrag);

	if (status) status.textContent = "Drag the ball along the path to the target without touching the walls.";
	updateMetrics();
	draw();
})();
