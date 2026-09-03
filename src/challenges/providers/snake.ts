import { buildChallengeTemplate } from "../../services/challenge-page-service.ts";
import type { ChallengeProvider } from "../types.ts";
import { simulateSnake } from "./snake-engine.ts";

// Element contract (see docs/CHALLENGE_PAGES.md): [data-bg-snake="canvas"|"score"|"restart"|"overlay"] and
// [data-bg-snake-move="up"|"down"|"left"|"right"] on any element. These carry the same bg-snake-* classes
// snake.js would create by default, so this default template renders identically to the old
// programmatically-built UI - an owner can freely rearrange, restyle, or drop any piece.
const DEFAULT_TEMPLATE = buildChallengeTemplate({
	showTitle: false,
	extraStyle: ".status{min-height:3.3em}",
	bodyExtra:
		'<div class="bg-snake-wrapper">' +
		'<div class="bg-snake-score" data-bg-snake="score"></div>' +
		'<div class="bg-snake-canvas-wrap">' +
		'<canvas class="bg-snake-canvas" data-bg-snake="canvas"></canvas>' +
		'<div class="bg-snake-overlay" data-bg-snake="overlay">' +
		'<button type="button" class="bg-snake-restart" data-bg-snake="restart">Start</button>' +
		"</div>" +
		"</div>" +
		'<div class="bg-snake-controls">' +
		'<div class="bg-snake-dpad">' +
		'<button type="button" data-bg-snake-move="up" aria-label="Up">▲</button>' +
		'<div class="bg-snake-dpad-row">' +
		'<button type="button" data-bg-snake-move="left" aria-label="Left">◀</button>' +
		'<button type="button" data-bg-snake-move="down" aria-label="Down">▼</button>' +
		'<button type="button" data-bg-snake-move="right" aria-label="Right">▶</button>' +
		"</div></div>" +
		"</div>",
});

const MIN_GRID_SIZE = 10;
const MAX_GRID_SIZE = 40;
const MIN_APPLES = 1;
const MAX_APPLES = 30;
const MIN_TICK_MS = 60;
const MAX_TICK_MS = 500;
const DEFAULT_TICK_MS = 150;
const MOVE_PATTERN = /^[UDLR]+$/u;
const GENERIC_FAILURE_REASON = "Snake challenge failed";
const MIN_ELAPSED_RATIO = 0.85;
const MIN_TICK_RATIO = 0.5;

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

/** Client rendering speed, also used server-side as the per-move pace for the minimum-elapsed-time check in verify(). */
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
	defaultHtmlTemplate: DEFAULT_TEMPLATE,
	extraPlaceholders: [
		{ name: "applesRequired", description: "Apples required to complete this Snake challenge." },
		{ name: "gridSize", description: "Snake grid size (cells per side)." },
	],
	extraTemplateContext(publicData) {
		return { applesRequired: String(publicData.applesRequired ?? ""), gridSize: String(publicData.gridSize ?? "") };
	},

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

	async verify(context, config, privateData, answer) {
		const answerObject = answer && typeof answer === "object" ? (answer as Record<string, unknown>) : {};
		const moves = String(answerObject.moves ?? "");
		const size = Number(privateData.gridSize);
		if (!moves || !MOVE_PATTERN.test(moves) || moves.length > maxMoves(size)) {
			return { success: false, reason: GENERIC_FAILURE_REASON };
		}
		const speed = tickMs(config);
		const minElapsedMs = moves.length * speed * MIN_ELAPSED_RATIO;
		if (Date.now() - context.createdAt < minElapsedMs) {
			return { success: false, reason: GENERIC_FAILURE_REASON };
		}
		const timings = answerObject.timings;
		const tickFloorMs = speed * MIN_TICK_RATIO;
		const hasPlausiblePacing =
			Array.isArray(timings) &&
			timings.length === moves.length &&
			timings.every((gap) => typeof gap === "number" && Number.isFinite(gap) && gap >= tickFloorMs);
		if (!hasPlausiblePacing) {
			return { success: false, reason: GENERIC_FAILURE_REASON };
		}
		const result = simulateSnake({
			seed: Number(privateData.seed),
			gridSize: size,
			applesRequired: Number(privateData.applesRequired),
			moves,
		});
		return result.success
			? { success: true, metadata: { provider: "snake", applesEaten: result.applesEaten } }
			: { success: false, reason: GENERIC_FAILURE_REASON };
	},
};
