import { buildChallengeTemplate } from "../../services/challenge-page-service.ts";
import { hexColorConfig } from "../color-config.ts";
import type { ChallengeProvider } from "../types.ts";
import { BALL_RADIUS, TARGET_RADIUS, generatePathPoints, pathLength, trackMetrics, type TraceShape } from "./trace-engine.ts";

// [data-bg-trace="canvas"] - an owner-supplied canvas is reused as-is (see trace.js). The 460px-wide
// canvas already fits the shared template's default ~488px desktop content width with no CSS
// downscaling, so no custom mainMaxWidth is needed here (unlike before the engine's canvas was shrunk).
const DEFAULT_TEMPLATE = buildChallengeTemplate({
	bodyExtra:
		'<div class="bg-trace-wrapper">' +
		'<canvas class="bg-trace-canvas" data-bg-trace="canvas"></canvas>' +
		'<div class="bg-trace-metrics" data-bg-trace="metrics"></div>' +
		'<div class="bg-trace-hint">Drag the ball along the path to the target without touching the walls</div>' +
		"</div>",
});

const SHAPES: TraceShape[] = ["chokepoint", "bezier", "zigzag", "loop"];
// Floor matches trace-engine.ts's MIN_EFFECTIVE_WIDTH (BALL_RADIUS*2 + 28, sized for touch precision).
const MIN_PATH_WIDTH = 48;
const MAX_PATH_WIDTH = 96;
const MIN_SAMPLES = 40;
const MAX_SAMPLES = 1200;
const MIN_DURATION_BASE_MS = 200;
const MIN_MS_PER_PATH_PX = 2.5;
const MAX_HIT_RATIO = 0.35;
const MAX_OOB_DEPTH_PX = 25;
const MIN_TIME_JITTER_VARIANCE = 1;
const PERFECT_CENTER_EPSILON_PX = 0.6;
const GENERIC_FAILURE_REASON = "traceChallengeFailed";
const DEFAULT_TRACK_COLOR = "#1e293b";
const DEFAULT_TARGET_COLOR = "#ff4d4d";
const DEFAULT_TRAIL_COLOR = "#22d3ee";
const DEFAULT_BALL_COLOR = "#7c3aed";
const DEFAULT_BACKGROUND_COLOR = "#0b1220";

function shapeConfig(config: Record<string, unknown>): TraceShape {
	const value = String(config.shape) as TraceShape;
	if (!SHAPES.includes(value)) {
		throw new Error(`Trace shape must be one of ${SHAPES.join(", ")}`);
	}
	return value;
}

function pathWidthConfig(config: Record<string, unknown>): number {
	const value = Number(config.pathWidth);
	if (!Number.isInteger(value) || value < MIN_PATH_WIDTH || value > MAX_PATH_WIDTH) {
		throw new Error(`Trace path width must be an integer from ${MIN_PATH_WIDTH} to ${MAX_PATH_WIDTH}`);
	}
	return value;
}

function variance(values: number[]): number {
	if (values.length === 0) return 0;
	const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
	return values.reduce((sum, value) => sum + (value - mean) ** 2, 0) / values.length;
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

export const traceProvider: ChallengeProvider = {
	name: "trace",
	clientScript: "/_burrowgate/static/challenges/trace.js",
	title: "Trace the path",
	description: "This website asks visitors to trace a path without straying off it before continuing.",
	defaultHtmlTemplate: DEFAULT_TEMPLATE,
	extraPlaceholders: [{ name: "shape", description: 'Track shape for this Trace challenge (e.g. "chokepoint").' }],
	extraTemplateContext(publicData) {
		return { shape: String(publicData.shape ?? "") };
	},
	defaultTexts: [
		{ key: "hint", label: "Hint text under the canvas", default: "Drag the ball along the path to the target without touching the walls" },
		{
			key: "statusReady",
			label: "Initial status message",
			default: "Drag the ball along the path to the target without touching the walls.",
		},
		{
			key: "metrics",
			label: "Live metrics line (use {{hitCount}}, {{maxExcursion}})",
			default: "Wall touches: {{hitCount}} | Max excursion: {{maxExcursion}}px",
		},
		{ key: "retry", label: "Off-track retry message", default: "Not quite - try again." },
		{ key: "traceChallengeFailed", label: "Generic failure message", default: "Trace challenge failed" },
	],

	validateConfig(config) {
		shapeConfig(config);
		pathWidthConfig(config);
		hexColorConfig(config, "trackColor", DEFAULT_TRACK_COLOR);
		hexColorConfig(config, "targetColor", DEFAULT_TARGET_COLOR);
		hexColorConfig(config, "trailColor", DEFAULT_TRAIL_COLOR);
		hexColorConfig(config, "ballColor", DEFAULT_BALL_COLOR);
		hexColorConfig(config, "backgroundColor", DEFAULT_BACKGROUND_COLOR);
	},

	async create(_context, config) {
		const shape = shapeConfig(config);
		const width = pathWidthConfig(config);
		const seed = crypto.getRandomValues(new Uint32Array(1))[0]!;
		const data = {
			kind: "trace",
			shape,
			pathWidth: width,
			seed,
			ballRadius: BALL_RADIUS,
			endRadius: TARGET_RADIUS,
			trackColor: hexColorConfig(config, "trackColor", DEFAULT_TRACK_COLOR),
			targetColor: hexColorConfig(config, "targetColor", DEFAULT_TARGET_COLOR),
			trailColor: hexColorConfig(config, "trailColor", DEFAULT_TRAIL_COLOR),
			ballColor: hexColorConfig(config, "ballColor", DEFAULT_BALL_COLOR),
			backgroundColor: hexColorConfig(config, "backgroundColor", DEFAULT_BACKGROUND_COLOR),
		};
		return { publicData: data, privateData: data };
	},

	async verify(_context, _config, privateData, answer) {
		const answerObject = answer && typeof answer === "object" ? (answer as Record<string, unknown>) : {};
		const shape = String(privateData.shape) as TraceShape;
		const width = Number(privateData.pathWidth);
		const seed = Number(privateData.seed);

		const path = parsePath(answerObject.path);
		if (!path) {
			return { success: false, reason: GENERIC_FAILURE_REASON };
		}

		const track = generatePathPoints(shape, seed, width);
		const lastSample = path[path.length - 1]!;
		const reachedEnd = Math.hypot(lastSample.x - track.end.x, lastSample.y - track.end.y) <= TARGET_RADIUS;
		if (!reachedEnd) {
			return { success: false, reason: GENERIC_FAILURE_REASON };
		}

		const totalDurationMs = lastSample.t - path[0]!.t;
		const minDurationMs = MIN_DURATION_BASE_MS + pathLength(track.points) * MIN_MS_PER_PATH_PX;
		if (totalDurationMs < minDurationMs) {
			return { success: false, reason: GENERIC_FAILURE_REASON };
		}

		let hitCount = 0;
		let maxExcursion = 0;
		let centerOffsetSum = 0;
		for (const sample of path) {
			const metrics = trackMetrics(sample, track.points);
			centerOffsetSum += metrics.minDistance;
			if (metrics.isWallHit) {
				hitCount += 1;
				maxExcursion = Math.max(maxExcursion, metrics.oobDepth);
			}
		}
		const hitRatio = hitCount / path.length;
		const avgCenterOffset = centerOffsetSum / path.length;
		if (hitRatio > MAX_HIT_RATIO || maxExcursion > MAX_OOB_DEPTH_PX) {
			return { success: false, reason: GENERIC_FAILURE_REASON };
		}
		if (hitCount === 0 && avgCenterOffset < PERFECT_CENTER_EPSILON_PX) {
			return { success: false, reason: GENERIC_FAILURE_REASON };
		}

		const dts: number[] = [];
		for (let index = 1; index < path.length; index += 1) {
			dts.push(path[index]!.t - path[index - 1]!.t);
		}
		if (variance(dts) < MIN_TIME_JITTER_VARIANCE) {
			return { success: false, reason: GENERIC_FAILURE_REASON };
		}

		return { success: true, metadata: { provider: "trace", hitRatio, maxExcursion } };
	},
};
