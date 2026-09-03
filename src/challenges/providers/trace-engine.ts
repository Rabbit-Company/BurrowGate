/**
 * Deterministic path-tracer engine with the client copy in public/challenges/trace.js. The two
 * MUST stay byte-for-byte identical in behavior: same PRNG, same track-shape generators, same
 * point-to-segment distance/wall-metrics math. If you change one, change the other and update
 * both algorithm comments together.
 */

export type TraceShape = "chokepoint" | "bezier" | "zigzag" | "loop";

// Sized to fit its own default template's ~488px desktop content width with no CSS downscaling at all,
// and to minimize the physical-to-logical amplification factor on a small phone viewport (~339px
// available there regardless of template) - see docs/CHALLENGE_PAGES.md's Trace section for the math.
export const CANVAS_WIDTH = 460;
export const CANVAS_HEIGHT = 300;
const CANVAS_MARGIN = 40;
export const BALL_RADIUS = 10;
export const TARGET_RADIUS = 16;
const MIN_EFFECTIVE_WIDTH = BALL_RADIUS * 2 + 28;

export interface Point {
	x: number;
	y: number;
}

export interface TrackPoint extends Point {
	width: number;
}

export interface Track {
	points: TrackPoint[];
	start: Point;
	end: Point;
}

/** Park-Miller minimal-standard LCG - simple enough to hand-duplicate exactly on both sides. */
export function seededRandom(seed: number): () => number {
	let state = seed % 2147483647;
	if (state <= 0) state += 2147483646;
	return () => {
		state = (state * 16807) % 2147483647;
		return (state - 1) / 2147483646;
	};
}

/**
 * Generates a winding track from `seed`. `pathWidth` sets the constant width for bezier/zigzag/loop, and
 * the wide end of chokepoint's taper (1.25x); chokepoint's narrow end is always exactly `MIN_EFFECTIVE_WIDTH`
 * (not further scaled down by `pathWidth`) so its pinch points stay passable regardless of configuration.
 */
export function generatePathPoints(shape: TraceShape, seed: number, pathWidth: number): Track {
	const rng = seededRandom(seed);
	const w = CANVAS_WIDTH;
	const h = CANVAS_HEIGHT;
	const points: TrackPoint[] = [];

	const startY = CANVAS_MARGIN + rng() * (h - 2 * CANVAS_MARGIN);
	const endY = CANVAS_MARGIN + rng() * (h - 2 * CANVAS_MARGIN);
	const start: Point = { x: CANVAS_MARGIN, y: startY };
	const end: Point = { x: w - CANVAS_MARGIN, y: endY };
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
		const cp1: Point = { x: w * 0.25, y: CANVAS_MARGIN + rng() * (h - 2 * CANVAS_MARGIN) };
		const cp2: Point = { x: w * 0.75, y: CANVAS_MARGIN + rng() * (h - 2 * CANVAS_MARGIN) };

		for (let i = 0; i <= 120; i += 1) {
			const t = i / 120;
			const x = (1 - t) ** 3 * start.x + 3 * (1 - t) ** 2 * t * cp1.x + 3 * (1 - t) * t ** 2 * cp2.x + t ** 3 * end.x;
			const y = (1 - t) ** 3 * start.y + 3 * (1 - t) ** 2 * t * cp1.y + 3 * (1 - t) * t ** 2 * cp2.y + t ** 3 * end.y;
			points.push({ x, y, width: straightWidth });
		}
	} else if (shape === "zigzag") {
		const waypoints: Point[] = [start, { x: w * 0.33, y: h - CANVAS_MARGIN }, { x: w * 0.66, y: CANVAS_MARGIN }, end];
		for (let i = 0; i < waypoints.length - 1; i += 1) {
			const p1 = waypoints[i]!;
			const p2 = waypoints[i + 1]!;
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

	points[0] = { x: start.x, y: start.y, width: points[0]!.width };
	points[points.length - 1] = { x: end.x, y: end.y, width: points[points.length - 1]!.width };

	return { points, start, end };
}

export function distToSegment(pt: Point, p1: TrackPoint, p2: TrackPoint): { dist: number; width: number } {
	const l2 = Math.hypot(p2.x - p1.x, p2.y - p1.y) ** 2;
	if (l2 === 0) return { dist: Math.hypot(pt.x - p1.x, pt.y - p1.y), width: p1.width };
	const t = Math.max(0, Math.min(1, ((pt.x - p1.x) * (p2.x - p1.x) + (pt.y - p1.y) * (p2.y - p1.y)) / l2));
	const projX = p1.x + t * (p2.x - p1.x);
	const projY = p1.y + t * (p2.y - p1.y);
	const width = p1.width + t * (p2.width - p1.width);
	return { dist: Math.hypot(pt.x - projX, pt.y - projY), width };
}

export interface TrackMetrics {
	minDistance: number;
	allowedRadius: number;
	oobDepth: number;
	isWallHit: boolean;
}

export function trackMetrics(pt: Point, points: TrackPoint[]): TrackMetrics {
	let minDistance = Infinity;
	let width = 36;
	for (let i = 0; i < points.length - 1; i += 1) {
		const res = distToSegment(pt, points[i]!, points[i + 1]!);
		if (res.dist < minDistance) {
			minDistance = res.dist;
			width = res.width;
		}
	}
	const allowedRadius = width / 2 - BALL_RADIUS;
	const oobDepth = Math.max(0, minDistance - allowedRadius);
	return { minDistance, allowedRadius, oobDepth, isWallHit: oobDepth > 0 };
}

export function pathLength(points: Point[]): number {
	let total = 0;
	for (let i = 1; i < points.length; i += 1) {
		total += Math.hypot(points[i]!.x - points[i - 1]!.x, points[i]!.y - points[i - 1]!.y);
	}
	return total;
}
