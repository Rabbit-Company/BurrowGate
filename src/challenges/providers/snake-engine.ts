/**
 * Deterministic Snake game engine with the client copy in public/challenges/snake.js. The two
 * MUST stay byte-for-byte identical in behavior: same PRNG, same apple shuffle, same start state,
 * same step/collision rules. If you change one, change the other and update both algorithm
 * comments together.
 */

export type Direction = "U" | "D" | "L" | "R";

const DIRECTION_DELTA: Record<Direction, { dx: number; dy: number }> = {
	U: { dx: 0, dy: -1 },
	D: { dx: 0, dy: 1 },
	L: { dx: -1, dy: 0 },
	R: { dx: 1, dy: 0 },
};

const OPPOSITE: Record<Direction, Direction> = { U: "D", D: "U", L: "R", R: "L" };

/** mulberry32: tiny, purely-integer PRNG. Deterministic across engines - only Math.imul/>>> are used, both exactly spec'd. */
export function mulberry32(seed: number): () => number {
	let t = seed >>> 0;
	return () => {
		t = (t + 0x6d2b79f5) >>> 0;
		let r = Math.imul(t ^ (t >>> 15), 1 | t);
		r = (r + Math.imul(r ^ (r >>> 7), 61 | r)) ^ r;
		return ((r ^ (r >>> 14)) >>> 0) / 4294967296;
	};
}

/** Fisher-Yates shuffle of every grid cell index (x + y*gridSize), driven by the seeded RNG. */
export function shuffledCells(gridSize: number, rng: () => number): number[] {
	const cells: number[] = [];
	for (let index = 0; index < gridSize * gridSize; index += 1) cells.push(index);
	for (let index = cells.length - 1; index > 0; index -= 1) {
		const swapIndex = Math.floor(rng() * (index + 1));
		const temporary = cells[index]!;
		cells[index] = cells[swapIndex]!;
		cells[swapIndex] = temporary;
	}
	return cells;
}

function cellIndex(x: number, y: number, gridSize: number): number {
	return x + y * gridSize;
}

/** Fixed, seed-independent starting position: head at grid center, body trailing 2 cells left, facing right. */
function initialBody(gridSize: number): number[] {
	const headX = gridSize >> 1;
	const headY = gridSize >> 1;
	return [cellIndex(headX, headY, gridSize), cellIndex(headX - 1, headY, gridSize), cellIndex(headX - 2, headY, gridSize)];
}

function nextApplePosition(cells: number[], pointer: number, occupied: Set<number>): { position: number; pointer: number } {
	let index = pointer;
	while (occupied.has(cells[index]!)) index += 1;
	return { position: cells[index]!, pointer: index + 1 };
}

export interface SimulateSnakeParams {
	seed: number;
	gridSize: number;
	applesRequired: number;
	moves: string;
}

export interface SimulateSnakeResult {
	success: boolean;
	reason?: string;
	applesEaten?: number;
}

/**
 * Replays a submitted move string from the fixed start state against the seed's apple sequence.
 * Pure and side-effect free - safe to call directly from tests to check a hand-built transcript.
 * `moves` must already be validated by the caller to contain only U/D/L/R characters.
 */
export function simulateSnake({ seed, gridSize, applesRequired, moves }: SimulateSnakeParams): SimulateSnakeResult {
	const rng = mulberry32(seed);
	const cells = shuffledCells(gridSize, rng);

	let body = initialBody(gridSize);
	let direction: Direction = "R";
	let applesEaten = 0;
	let occupied = new Set(body);
	let apple = nextApplePosition(cells, 0, occupied);

	for (const character of moves) {
		const move = character as Direction;
		const effectiveDirection: Direction = body.length > 1 && move === OPPOSITE[direction] ? direction : move;
		const delta = DIRECTION_DELTA[effectiveDirection];
		const headIndex = body[0]!;
		const headX = headIndex % gridSize;
		const headY = (headIndex / gridSize) | 0;
		const newX = headX + delta.dx;
		const newY = headY + delta.dy;
		if (newX < 0 || newX >= gridSize || newY < 0 || newY >= gridSize) return { success: false, reason: "The snake hit a wall.", applesEaten };
		const newHead = cellIndex(newX, newY, gridSize);
		const willGrow = newHead === apple.position;
		const bodyWithoutTail = willGrow ? body : body.slice(0, -1);
		if (bodyWithoutTail.includes(newHead)) return { success: false, reason: "The snake collided with itself.", applesEaten };

		body = [newHead, ...bodyWithoutTail];
		direction = effectiveDirection;
		occupied = new Set(body);

		if (willGrow) {
			applesEaten += 1;
			if (applesEaten >= applesRequired) return { success: true, applesEaten };
			apple = nextApplePosition(cells, apple.pointer, occupied);
		}
	}

	return { success: false, reason: "Not enough apples were eaten.", applesEaten };
}
