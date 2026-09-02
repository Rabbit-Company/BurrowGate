import type { ChallengeProvider } from "../types.ts";
import { simulateSnake } from "./snake-engine.ts";

const MIN_GRID_SIZE = 10;
const MAX_GRID_SIZE = 40;
const MIN_APPLES = 1;
const MAX_APPLES = 30;
const MIN_TICK_MS = 60;
const MAX_TICK_MS = 500;
const DEFAULT_TICK_MS = 150;
const MOVE_PATTERN = /^[UDLR]+$/u;

function gridSize(config: Record<string, unknown>): number {
	const value = Number(config.gridSize);
	if (!Number.isInteger(value) || value < MIN_GRID_SIZE || value > MAX_GRID_SIZE) {
		throw new Error(`Snake grid size must be an integer from ${MIN_GRID_SIZE} to ${MAX_GRID_SIZE}`);
	}
	return value;
}

function applesRequired(config: Record<string, unknown>): number {
	const value = Number(config.applesRequired);
	if (!Number.isInteger(value) || value < MIN_APPLES || value > MAX_APPLES) {
		throw new Error(`Snake apples required must be an integer from ${MIN_APPLES} to ${MAX_APPLES}`);
	}
	return value;
}

/** Client-only rendering speed - the server never validates timing, only the final move sequence. */
function tickMs(config: Record<string, unknown>): number {
	if (config.tickMs === undefined) return DEFAULT_TICK_MS;
	const value = Number(config.tickMs);
	if (!Number.isInteger(value) || value < MIN_TICK_MS || value > MAX_TICK_MS) {
		throw new Error(`Snake speed must be an integer from ${MIN_TICK_MS} to ${MAX_TICK_MS} milliseconds`);
	}
	return value;
}

function maxMoves(size: number): number {
	return Math.min(6000, size * size * 6);
}

export const snakeProvider: ChallengeProvider = {
	name: "snake",
	clientScript: "/_burrowgate/static/challenges/snake.js",
	title: "Eat some apples",
	description: "This website asks visitors to play a short game of Snake before continuing.",

	validateConfig(config) {
		gridSize(config);
		applesRequired(config);
		tickMs(config);
	},

	async create(_context, config) {
		const size = gridSize(config);
		const apples = applesRequired(config);
		const speed = tickMs(config);
		const seed = crypto.getRandomValues(new Uint32Array(1))[0]!;
		return {
			publicData: { kind: "snake", seed, gridSize: size, applesRequired: apples, tickMs: speed },
			privateData: { seed, gridSize: size, applesRequired: apples },
		};
	},

	async verify(_context, _config, privateData, answer) {
		const moves = answer && typeof answer === "object" ? String((answer as Record<string, unknown>).moves ?? "") : "";
		const size = Number(privateData.gridSize);
		if (!moves || !MOVE_PATTERN.test(moves) || moves.length > maxMoves(size)) {
			return { success: false, reason: "Invalid move sequence" };
		}
		const result = simulateSnake({
			seed: Number(privateData.seed),
			gridSize: size,
			applesRequired: Number(privateData.applesRequired),
			moves,
		});
		return result.success
			? { success: true, metadata: { provider: "snake", applesEaten: result.applesEaten } }
			: { success: false, reason: result.reason ?? "Snake challenge failed" };
	},
};
