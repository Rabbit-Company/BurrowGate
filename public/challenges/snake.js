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

	// Shared deterministic engine: MUST match src/challenges/providers/snake-engine.ts exactly.
	// Same PRNG, same apple shuffle, same fixed start state, same step/collision rules. If you change
	// one, change the other and update both algorithm comments together.
	function mulberry32(seed) {
		let t = seed >>> 0;
		return function () {
			t = (t + 0x6d2b79f5) >>> 0;
			let r = Math.imul(t ^ (t >>> 15), 1 | t);
			r = (r + Math.imul(r ^ (r >>> 7), 61 | r)) ^ r;
			return ((r ^ (r >>> 14)) >>> 0) / 4294967296;
		};
	}

	function shuffledCells(gridSize, rng) {
		const cells = [];
		for (let index = 0; index < gridSize * gridSize; index += 1) cells.push(index);
		for (let index = cells.length - 1; index > 0; index -= 1) {
			const swapIndex = Math.floor(rng() * (index + 1));
			const temp = cells[index];
			cells[index] = cells[swapIndex];
			cells[swapIndex] = temp;
		}
		return cells;
	}

	const DIRECTION_DELTA = { U: { dx: 0, dy: -1 }, D: { dx: 0, dy: 1 }, L: { dx: -1, dy: 0 }, R: { dx: 1, dy: 0 } };
	const OPPOSITE = { U: "D", D: "U", L: "R", R: "L" };

	function cellIndex(x, y, gridSize) {
		return x + y * gridSize;
	}

	function initialBody(gridSize) {
		const headX = gridSize >> 1;
		const headY = gridSize >> 1;
		return [cellIndex(headX, headY, gridSize), cellIndex(headX - 1, headY, gridSize), cellIndex(headX - 2, headY, gridSize)];
	}

	function nextApplePosition(cells, pointer, occupied) {
		let index = pointer;
		while (occupied.has(cells[index])) index += 1;
		return { position: cells[index], pointer: index + 1 };
	}

	// Applies one move to the current state, mirroring snake-engine.ts's simulateSnake loop body.
	function stepOnce(state, move, gridSize, cells) {
		const effectiveDirection = state.body.length > 1 && move === OPPOSITE[state.direction] ? state.direction : move;
		const delta = DIRECTION_DELTA[effectiveDirection];
		const headIndex = state.body[0];
		const headX = headIndex % gridSize;
		const headY = (headIndex / gridSize) | 0;
		const newX = headX + delta.dx;
		const newY = headY + delta.dy;
		if (newX < 0 || newX >= gridSize || newY < 0 || newY >= gridSize) return { ...state, collided: "wall" };
		const newHead = cellIndex(newX, newY, gridSize);
		const willGrow = newHead === state.applePos;
		const bodyWithoutTail = willGrow ? state.body : state.body.slice(0, -1);
		if (bodyWithoutTail.includes(newHead)) return { ...state, collided: "self" };

		const body = [newHead, ...bodyWithoutTail];
		let applesEaten = state.applesEaten;
		let applePos = state.applePos;
		let pointer = state.pointer;
		if (willGrow) {
			applesEaten += 1;
			if (applesEaten < state.applesRequired) {
				const next = nextApplePosition(cells, pointer, new Set(body));
				applePos = next.position;
				pointer = next.pointer;
			}
		}
		return { body, direction: effectiveDirection, applesEaten, applePos, pointer, applesRequired: state.applesRequired, collided: null };
	}
	// End shared engine

	const { seed, gridSize, applesRequired } = challenge.publicData;
	const TICK_MS = Number(challenge.publicData.tickMs) || 150;
	const backgroundColor = challenge.publicData.backgroundColor || "#0b1220";
	const appleColor = challenge.publicData.appleColor || "#22d3ee";
	const snakeColor = challenge.publicData.snakeColor || "#7c3aed";
	const snakeHeadColor = challenge.publicData.snakeHeadColor || "#a78bfa";
	const rng = mulberry32(seed);
	const cells = shuffledCells(gridSize, rng);
	const firstApple = nextApplePosition(cells, 0, new Set(initialBody(gridSize)));

	function freshState() {
		return {
			body: initialBody(gridSize),
			direction: "R",
			applesEaten: 0,
			applePos: firstApple.position,
			pointer: firstApple.pointer,
			applesRequired,
			collided: null,
		};
	}

	let state = freshState();
	let desiredDirection = "R";
	let moves = "";
	let moveTimings = [];
	let lastTickAt = Date.now();
	let finished = false;
	let gameOver = false;
	let timer = null;
	const startedAt = Date.now();

	// Element contract: a template may supply any of [data-bg-snake="canvas"], ["score"], ["restart"],
	// ["overlay"], and [data-bg-snake-move="up"|"down"|"left"|"right"] on any element (a button, an
	// image, a div - whatever). Each hook is used independently if present; anything missing falls back
	// to the same programmatically-created default as before, so a template with no hooks at all (every
	// existing custom template included) behaves exactly as it always has.
	let canvas = document.querySelector('[data-bg-snake="canvas"]');
	let scoreEl = document.querySelector('[data-bg-snake="score"]');
	let restartButton = document.querySelector('[data-bg-snake="restart"]');
	let overlay = document.querySelector('[data-bg-snake="overlay"]');
	const moveButtons = {
		U: document.querySelector('[data-bg-snake-move="up"]'),
		D: document.querySelector('[data-bg-snake-move="down"]'),
		L: document.querySelector('[data-bg-snake-move="left"]'),
		R: document.querySelector('[data-bg-snake-move="right"]'),
	};

	const availableWidth = Math.min(360, Math.max(200, (window.innerWidth || 360) - 48));
	const CELL_PX = Math.max(8, Math.min(22, Math.floor(availableWidth / gridSize)));

	const wrapper = document.createElement("div");
	wrapper.className = "bg-snake-wrapper";

	if (!scoreEl) {
		scoreEl = document.createElement("div");
		scoreEl.className = "bg-snake-score";
		wrapper.appendChild(scoreEl);
	}

	let canvasWrap = null;
	if (!canvas) {
		canvasWrap = document.createElement("div");
		canvasWrap.className = "bg-snake-canvas-wrap";
		canvas = document.createElement("canvas");
		canvas.className = "bg-snake-canvas";
		canvasWrap.appendChild(canvas);
	}
	canvas.width = gridSize * CELL_PX;
	canvas.height = gridSize * CELL_PX;

	if (!restartButton) {
		overlay = overlay || document.createElement("div");
		overlay.className = overlay.className || "bg-snake-overlay";
		restartButton = document.createElement("button");
		restartButton.type = "button";
		restartButton.textContent = t("start", "Start");
		restartButton.className = "bg-snake-restart";
		overlay.appendChild(restartButton);
		if (canvasWrap) canvasWrap.appendChild(overlay);
		else wrapper.appendChild(overlay);
	} else if (!overlay) {
		overlay = document.createElement("div");
	}
	if (canvasWrap) wrapper.appendChild(canvasWrap);

	const needsDefaultDpad = Object.values(moveButtons).every((button) => !button);
	if (needsDefaultDpad) {
		const controls = document.createElement("div");
		controls.className = "bg-snake-controls";
		controls.innerHTML =
			'<div class="bg-snake-dpad">' +
			'<button type="button" data-bg-snake-move="up" aria-label="Up">▲</button>' +
			'<div class="bg-snake-dpad-row">' +
			'<button type="button" data-bg-snake-move="left" aria-label="Left">◀</button>' +
			'<button type="button" data-bg-snake-move="down" aria-label="Down">▼</button>' +
			'<button type="button" data-bg-snake-move="right" aria-label="Right">▶</button>' +
			"</div></div>";
		wrapper.appendChild(controls);
		moveButtons.U = controls.querySelector('[data-bg-snake-move="up"]');
		moveButtons.D = controls.querySelector('[data-bg-snake-move="down"]');
		moveButtons.L = controls.querySelector('[data-bg-snake-move="left"]');
		moveButtons.R = controls.querySelector('[data-bg-snake-move="right"]');
	}

	if (wrapper.childElementCount > 0) {
		(status ? status.parentNode : document.body).insertBefore(wrapper, status ? status.nextSibling : null);
	}

	const style = document.createElement("style");
	style.textContent =
		".bg-snake-wrapper{display:grid;gap:12px;justify-items:center;margin:18px 0}" +
		".bg-snake-score{font-size:13px;color:#94a3b8}" +
		".bg-snake-canvas-wrap{position:relative}" +
		".bg-snake-canvas{display:block;background:#0b1220;border:1px solid rgba(148,163,184,.35);border-radius:10px}" +
		".bg-snake-overlay{position:absolute;inset:0;display:grid;place-items:center;border-radius:10px;background:rgba(11,18,32,.85);opacity:0;pointer-events:none;transition:opacity 120ms ease}" +
		".bg-snake-overlay.is-visible{opacity:1;pointer-events:auto}" +
		".bg-snake-dpad{display:grid;justify-items:center;gap:6px}" +
		".bg-snake-dpad-row{display:flex;gap:6px}" +
		".bg-snake-dpad button,.bg-snake-restart{min-height:44px;border-radius:8px;border:1px solid rgba(148,163,184,.35);background:rgba(15,23,42,.9);color:#e5e7eb;font-size:18px;cursor:pointer}" +
		".bg-snake-dpad button{min-width:44px}" +
		".bg-snake-restart{padding:10px 28px}" +
		".bg-snake-dpad button:active,.bg-snake-restart:active{background:rgba(139,92,246,.35)}" +
		"@media (max-width:520px){.bg-snake-dpad button,.bg-snake-restart{min-height:64px;font-size:26px}.bg-snake-dpad button{min-width:64px}.bg-snake-restart{padding:14px 36px}.bg-snake-dpad,.bg-snake-dpad-row{gap:10px}}";
	document.head.appendChild(style);

	const context = canvas.getContext("2d");

	function render() {
		if (scoreEl) scoreEl.textContent = `${state.applesEaten} / ${applesRequired}`;
		context.fillStyle = backgroundColor;
		context.fillRect(0, 0, canvas.width, canvas.height);
		const appleX = state.applePos % gridSize;
		const appleY = (state.applePos / gridSize) | 0;
		context.fillStyle = appleColor;
		context.fillRect(appleX * CELL_PX + 2, appleY * CELL_PX + 2, CELL_PX - 4, CELL_PX - 4);
		state.body.forEach((segment, index) => {
			const x = segment % gridSize;
			const y = (segment / gridSize) | 0;
			context.fillStyle = index === 0 ? snakeHeadColor : snakeColor;
			context.fillRect(x * CELL_PX + 1, y * CELL_PX + 1, CELL_PX - 2, CELL_PX - 2);
		});
	}

	function setDirection(direction) {
		desiredDirection = direction;
	}

	for (const [direction, button] of Object.entries(moveButtons)) {
		if (button) button.addEventListener("click", () => setDirection(direction));
	}

	const ARROW_KEYS = { ArrowUp: "U", ArrowDown: "D", ArrowLeft: "L", ArrowRight: "R" };
	const LETTER_KEYS = { w: "U", s: "D", a: "L", d: "R" };
	document.addEventListener("keydown", (event) => {
		const direction = ARROW_KEYS[event.key] || LETTER_KEYS[event.key.toLowerCase()];
		if (!direction) return;
		event.preventDefault();
		setDirection(direction);
	});

	function statusMessage() {
		return substitute(t("goal", "Eat {{applesRequired}} apple(s) to continue. Avoid the wall and yourself."), { applesRequired });
	}

	async function submit() {
		if (finished) return;
		finished = true;
		if (status) status.textContent = t("verifying", "Verifying with BurrowGate...");

		const response = await fetch("/_burrowgate/api/challenge/verify", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ flowId: challenge.flowId, answer: { moves, timings: moveTimings } }),
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

	function endGame(message) {
		gameOver = true;
		clearInterval(timer);
		if (status) status.textContent = message;
		overlay.classList.add("is-visible");
	}

	function resetGame() {
		state = freshState();
		desiredDirection = "R";
		moves = "";
		moveTimings = [];
		lastTickAt = Date.now();
		gameOver = false;
		overlay.classList.remove("is-visible");
		if (status) status.textContent = statusMessage();
		render();
		timer = setInterval(tick, TICK_MS);
	}

	restartButton.addEventListener("click", resetGame);

	function tick() {
		if (gameOver || finished) return;
		const next = stepOnce(state, desiredDirection, gridSize, cells);
		const now = Date.now();
		moves += desiredDirection;
		moveTimings.push(now - lastTickAt);
		lastTickAt = now;
		if (next.collided === "wall") {
			endGame(t("wallHit", "The snake hit a wall. Try again."));
			return;
		}
		if (next.collided === "self") {
			endGame(t("selfHit", "The snake collided with itself. Try again."));
			return;
		}
		state = next;
		render();
		if (state.applesEaten >= applesRequired) {
			clearInterval(timer);
			void submit();
		}
	}

	render();
	if (status) status.textContent = statusMessage();
	overlay.classList.add("is-visible");
})();
