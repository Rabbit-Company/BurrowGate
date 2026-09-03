import { buildChallengeTemplate } from "../../services/challenge-page-service.ts";
import { hexColorConfig } from "../color-config.ts";
import type { ChallengeProvider } from "../types.ts";

// [data-bg-slider="canvas"] - an owner-supplied canvas is reused as-is (see slider.js).
const DEFAULT_TEMPLATE = buildChallengeTemplate({
	bodyExtra:
		'<div class="bg-slider-wrapper">' +
		'<canvas class="bg-slider-canvas" data-bg-slider="canvas"></canvas>' +
		'<div class="bg-slider-hint">Drag the circle into the outlined target</div>' +
		"</div>",
});

const MIN_TRACK_WIDTH = 220;
const MAX_TRACK_WIDTH = 400;
const MIN_PIECE_SIZE = 28;
const MAX_PIECE_SIZE = 56;
const TOLERANCE_PX = 6;
const DEFAULT_PIECE_COLOR = "#7c3aed";
const DEFAULT_TARGET_COLOR = "#22d3ee";
const DEFAULT_TRACK_COLOR = "#94a3b8";
const DEFAULT_BACKGROUND_COLOR = "#0b1220";
const PIECE_SHAPES = ["circle", "square"];
const MIN_SAMPLES = 6;
const MAX_SAMPLES = 500;
const MIN_DURATION_BASE_MS = 80;
const MIN_MS_PER_PX = 0.6;
const MIN_TIME_JITTER_VARIANCE = 1;
const MIN_SPATIAL_JITTER_VARIANCE = 1;
const GENERIC_FAILURE_REASON = "sliderChallengeFailed";

function trackWidth(config: Record<string, unknown>): number {
	const value = Number(config.trackWidth);
	if (!Number.isInteger(value) || value < MIN_TRACK_WIDTH || value > MAX_TRACK_WIDTH) {
		throw new Error(`Slider track width must be an integer from ${MIN_TRACK_WIDTH} to ${MAX_TRACK_WIDTH}`);
	}
	return value;
}

function pieceSize(config: Record<string, unknown>): number {
	const value = Number(config.pieceSize);
	if (!Number.isInteger(value) || value < MIN_PIECE_SIZE || value > MAX_PIECE_SIZE) {
		throw new Error(`Slider piece size must be an integer from ${MIN_PIECE_SIZE} to ${MAX_PIECE_SIZE}`);
	}
	return value;
}

function pieceShape(config: Record<string, unknown>): string {
	if (config.pieceShape === undefined) return "circle";
	const value = String(config.pieceShape);
	if (!PIECE_SHAPES.includes(value)) {
		throw new Error(`Slider piece shape must be one of ${PIECE_SHAPES.join(", ")}`);
	}
	return value;
}

interface PathSample {
	x: number;
	y: number;
	t: number;
}

function parsePath(raw: unknown): PathSample[] | null {
	if (!Array.isArray(raw) || raw.length < MIN_SAMPLES || raw.length > MAX_SAMPLES) return null;
	const path: PathSample[] = [];
	for (const entry of raw) {
		const sample = entry as Record<string, unknown>;
		const x = Number(sample?.x);
		const y = Number(sample?.y);
		const t = Number(sample?.t);
		if (!Number.isFinite(x) || !Number.isFinite(y) || !Number.isFinite(t) || t < 0) return null;
		path.push({ x, y, t });
	}
	for (let index = 1; index < path.length; index += 1) {
		if (path[index]!.t < path[index - 1]!.t) return null;
	}
	return path;
}

function variance(values: number[]): number {
	if (values.length === 0) return 0;
	const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
	return values.reduce((sum, value) => sum + (value - mean) ** 2, 0) / values.length;
}

export const sliderProvider: ChallengeProvider = {
	name: "slider",
	clientScript: "/_burrowgate/static/challenges/slider.js",
	title: "Drag to verify",
	description: "This website asks visitors to drag a slider into place before continuing.",
	defaultHtmlTemplate: DEFAULT_TEMPLATE,
	defaultTexts: [
		{ key: "hint", label: "Hint text under the canvas", default: "Drag the circle into the outlined target" },
		{ key: "statusReady", label: "Initial status message", default: "Drag the circle into the outlined target to continue." },
		{ key: "retry", label: "Missed-target retry message", default: "Not quite - try again." },
		{ key: "sliderChallengeFailed", label: "Generic failure message", default: "Slider challenge failed" },
	],

	validateConfig(config) {
		trackWidth(config);
		pieceSize(config);
		pieceShape(config);
		hexColorConfig(config, "pieceColor", DEFAULT_PIECE_COLOR);
		hexColorConfig(config, "targetColor", DEFAULT_TARGET_COLOR);
		hexColorConfig(config, "trackColor", DEFAULT_TRACK_COLOR);
		hexColorConfig(config, "backgroundColor", DEFAULT_BACKGROUND_COLOR);
	},

	async create(_context, config) {
		const width = trackWidth(config);
		const size = pieceSize(config);
		const minDrag = Math.min(80, Math.floor(width * 0.4));
		const range = width - size - minDrag;
		const offset = Math.floor((crypto.getRandomValues(new Uint32Array(1))[0]! / 4294967296) * (range + 1));
		const targetX = minDrag + offset;
		const data = {
			kind: "slider",
			trackWidth: width,
			pieceSize: size,
			targetX,
			tolerancePx: TOLERANCE_PX,
			pieceShape: pieceShape(config),
			pieceColor: hexColorConfig(config, "pieceColor", DEFAULT_PIECE_COLOR),
			targetColor: hexColorConfig(config, "targetColor", DEFAULT_TARGET_COLOR),
			trackColor: hexColorConfig(config, "trackColor", DEFAULT_TRACK_COLOR),
			backgroundColor: hexColorConfig(config, "backgroundColor", DEFAULT_BACKGROUND_COLOR),
		};
		return { publicData: data, privateData: data };
	},

	async verify(_context, _config, privateData, answer) {
		const answerObject = answer && typeof answer === "object" ? (answer as Record<string, unknown>) : {};
		const width = Number(privateData.trackWidth);
		const size = Number(privateData.pieceSize);
		const targetX = Number(privateData.targetX);
		const finalX = Number(answerObject.finalX);

		if (!Number.isFinite(finalX) || finalX < 0 || finalX > width - size) {
			return { success: false, reason: GENERIC_FAILURE_REASON };
		}
		if (Math.abs(finalX - targetX) > TOLERANCE_PX) {
			return { success: false, reason: GENERIC_FAILURE_REASON };
		}
		const path = parsePath(answerObject.path);
		if (!path) {
			return { success: false, reason: GENERIC_FAILURE_REASON };
		}
		const lastSample = path[path.length - 1]!;
		if (Math.abs(lastSample.x - finalX) > TOLERANCE_PX) {
			return { success: false, reason: GENERIC_FAILURE_REASON };
		}
		const distance = Math.abs(finalX - path[0]!.x);
		const totalDurationMs = lastSample.t - path[0]!.t;
		if (totalDurationMs < MIN_DURATION_BASE_MS + distance * MIN_MS_PER_PX) {
			return { success: false, reason: GENERIC_FAILURE_REASON };
		}
		const dts: number[] = [];
		const dxs: number[] = [];
		for (let index = 1; index < path.length; index += 1) {
			dts.push(path[index]!.t - path[index - 1]!.t);
			dxs.push(path[index]!.x - path[index - 1]!.x);
		}
		if (variance(dts) < MIN_TIME_JITTER_VARIANCE || variance(dxs) < MIN_SPATIAL_JITTER_VARIANCE) {
			return { success: false, reason: GENERIC_FAILURE_REASON };
		}

		return { success: true, metadata: { provider: "slider" } };
	},
};
