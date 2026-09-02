(() => {
	const challenge = window.__BURROWGATE_CHALLENGE__;
	const status = document.getElementById("status");

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
	let finished = false;
	let gameOver = false;
	let timer = null;
	const startedAt = Date.now();

	const availableWidth = Math.min(360, Math.max(200, (window.innerWidth || 360) - 48));
	const CELL_PX = Math.max(8, Math.min(22, Math.floor(availableWidth / gridSize)));
	const wrapper = document.createElement("div");
	wrapper.className = "bg-snake-wrapper";

	const scoreEl = document.createElement("div");
	scoreEl.className = "bg-snake-score";
	wrapper.appendChild(scoreEl);

	const canvasWrap = document.createElement("div");
	canvasWrap.className = "bg-snake-canvas-wrap";

	const canvas = document.createElement("canvas");
	canvas.width = gridSize * CELL_PX;
	canvas.height = gridSize * CELL_PX;
	canvas.className = "bg-snake-canvas";
	canvasWrap.appendChild(canvas);

	const overlay = document.createElement("div");
	overlay.className = "bg-snake-overlay";
	const restartButton = document.createElement("button");
	restartButton.type = "button";
	restartButton.textContent = "Restart";
	restartButton.className = "bg-snake-restart";
	overlay.appendChild(restartButton);
	canvasWrap.appendChild(overlay);
	wrapper.appendChild(canvasWrap);

	const controls = document.createElement("div");
	controls.className = "bg-snake-controls";
	controls.innerHTML =
		'<div class="bg-snake-dpad">' +
		'<button type="button" data-dir="U" aria-label="Up">▲</button>' +
		'<div class="bg-snake-dpad-row">' +
		'<button type="button" data-dir="L" aria-label="Left">◀</button>' +
		'<button type="button" data-dir="D" aria-label="Down">▼</button>' +
		'<button type="button" data-dir="R" aria-label="Right">▶</button>' +
		"</div></div>";
	wrapper.appendChild(controls);

	(status ? status.parentNode : document.body).insertBefore(wrapper, status ? status.nextSibling : null);

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
		".bg-snake-dpad button,.bg-snake-restart{min-width:44px;min-height:44px;border-radius:8px;border:1px solid rgba(148,163,184,.35);background:rgba(15,23,42,.9);color:#e5e7eb;font-size:18px;cursor:pointer}" +
		".bg-snake-dpad button:active,.bg-snake-restart:active{background:rgba(139,92,246,.35)}" +
		"@media (max-width:520px){.bg-snake-dpad button,.bg-snake-restart{min-width:64px;min-height:64px;font-size:26px}.bg-snake-dpad,.bg-snake-dpad-row{gap:10px}}";
	document.head.appendChild(style);

	const context = canvas.getContext("2d");

	function render() {
		scoreEl.textContent = `${state.applesEaten} / ${applesRequired}`;
		context.fillStyle = "#0b1220";
		context.fillRect(0, 0, canvas.width, canvas.height);
		const appleX = state.applePos % gridSize;
		const appleY = (state.applePos / gridSize) | 0;
		context.fillStyle = "#22d3ee";
		context.fillRect(appleX * CELL_PX + 2, appleY * CELL_PX + 2, CELL_PX - 4, CELL_PX - 4);
		state.body.forEach((segment, index) => {
			const x = segment % gridSize;
			const y = (segment / gridSize) | 0;
			context.fillStyle = index === 0 ? "#a78bfa" : "#7c3aed";
			context.fillRect(x * CELL_PX + 1, y * CELL_PX + 1, CELL_PX - 2, CELL_PX - 2);
		});
	}

	function setDirection(direction) {
		desiredDirection = direction;
	}

	controls.querySelectorAll("button[data-dir]").forEach((button) => {
		button.addEventListener("click", () => setDirection(button.dataset.dir));
	});

	const ARROW_KEYS = { ArrowUp: "U", ArrowDown: "D", ArrowLeft: "L", ArrowRight: "R" };
	const LETTER_KEYS = { w: "U", s: "D", a: "L", d: "R" };
	document.addEventListener("keydown", (event) => {
		const direction = ARROW_KEYS[event.key] || LETTER_KEYS[event.key.toLowerCase()];
		if (!direction) return;
		event.preventDefault();
		setDirection(direction);
	});

	function statusMessage() {
		return `Eat ${applesRequired} apple${applesRequired === 1 ? "" : "s"} to continue. Avoid the wall and yourself.`;
	}

	async function submit() {
		if (finished) return;
		finished = true;
		if (status) status.textContent = "Verifying with BurrowGate...";

		const response = await fetch("/_burrowgate/api/challenge/verify", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ flowId: challenge.flowId, answer: { moves } }),
		});
		const result = await response.json();
		if (result.done) {
			const minimumDisplayMs = Math.max(0, Number(challenge.minimumDisplayMs) || 0);
			const remainingMs = Math.max(0, minimumDisplayMs - (Date.now() - startedAt));
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
		moves += desiredDirection;
		if (next.collided === "wall") {
			endGame("The snake hit a wall. Try again.");
			return;
		}
		if (next.collided === "self") {
			endGame("The snake collided with itself. Try again.");
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
	timer = setInterval(tick, TICK_MS);
})();
