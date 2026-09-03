import type { ChallengeProvider } from "../types.ts";
import { BALL_RADIUS, TARGET_RADIUS, generatePathPoints, pathLength, trackMetrics, type TraceShape } from "./trace-engine.ts";

const SHAPES: TraceShape[] = ["chokepoint", "bezier", "zigzag", "loop"];
const MIN_PATH_WIDTH = 28;
const MAX_PATH_WIDTH = 56;
const MIN_SAMPLES = 40;
const MAX_SAMPLES = 1200;
const MIN_DURATION_BASE_MS = 200;
const MIN_MS_PER_PATH_PX = 2.5;
const MAX_HIT_RATIO = 0.35;
const MAX_OOB_DEPTH_PX = 25;
const MIN_TIME_JITTER_VARIANCE = 1;
const PERFECT_CENTER_EPSILON_PX = 0.6;
const GENERIC_FAILURE_REASON = "Trace challenge failed";

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

	validateConfig(config) {
		shapeConfig(config);
		pathWidthConfig(config);
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
