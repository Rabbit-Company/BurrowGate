import { describe, expect, test } from "bun:test";
import { generatePathPoints, pathLength, seededRandom, trackMetrics, type Track } from "../src/challenges/providers/trace-engine.ts";
import { traceProvider } from "../src/challenges/providers/trace.ts";
import type { ChallengeVerifyContext } from "../src/challenges/types.ts";

const verifyContext: ChallengeVerifyContext = {
	flowId: "flow_1",
	siteId: "site_1",
	clientIp: "203.0.113.10",
	userAgentHash: "ua",
	expiresAt: Date.now() + 60_000,
	attempts: 0,
	createdAt: Date.now() - 60_000,
};

const SEED = 1337;
const SHAPE = "chokepoint";
const PATH_WIDTH = 60;
const privateData = { shape: SHAPE, pathWidth: PATH_WIDTH, seed: SEED };

function buildRun(track: Track, options: { sampleCount?: number; offsetPx?: number; jitter?: boolean } = {}) {
	const { sampleCount = 80, offsetPx = 1.5, jitter = true } = options;
	const total = pathLength(track.points);
	const durationMs = 400 + total * 4;
	const path: { x: number; y: number; t: number }[] = [];
	for (let i = 0; i < sampleCount; i += 1) {
		const idx = Math.round((i / (sampleCount - 1)) * (track.points.length - 1));
		const base = track.points[idx]!;
		const neighbor = track.points[Math.min(idx + 1, track.points.length - 1)]!;
		let tx = neighbor.x - base.x;
		let ty = neighbor.y - base.y;
		const len = Math.hypot(tx, ty) || 1;
		tx /= len;
		ty /= len;
		const mag = i === 0 || i === sampleCount - 1 ? 0 : offsetPx * (i % 2 === 0 ? 1 : -1);
		let x = base.x + -ty * mag;
		let y = base.y + tx * mag;
		if (i === 0) {
			x = track.start.x;
			y = track.start.y;
		}
		if (i === sampleCount - 1) {
			x = track.end.x;
			y = track.end.y;
		}
		const wobble = !jitter || i === 0 ? 0 : i % 3 === 0 ? 3 : i % 3 === 1 ? -2 : 1;
		let t = Math.round((i / (sampleCount - 1)) * durationMs) + wobble;
		if (i === sampleCount - 1) t = durationMs;
		path.push({ x, y, t });
	}
	for (let i = 1; i < path.length; i += 1) {
		if (path[i]!.t < path[i - 1]!.t) path[i]!.t = path[i - 1]!.t + 1;
	}
	return path;
}

describe("seededRandom / generatePathPoints", () => {
	test("produces a pinned, deterministic sequence for a given seed", () => {
		const rng = seededRandom(1337);
		expect(rng()).toBeCloseTo(0.010463855239063367, 12);
		expect(rng()).toBeCloseTo(0.8660227473508778, 12);
		expect(rng()).toBeCloseTo(0.24431577440753185, 12);
	});

	test("chokepoint track is pinned for seed 1337 / pathWidth 60", () => {
		const track = generatePathPoints("chokepoint", 1337, 60);
		expect(track.points.length).toBe(151);
		expect(track.start).toEqual({ x: 40, y: 42.30204815259394 });
		expect(track.end).toEqual({ x: 420, y: 230.52500441719312 });
		expect(track.points[75]).toEqual({ x: 230, y: 115.68168361436423, width: 48.22017881199078 });
		expect(track.points[0]!.width).toBe(56);
		expect(track.points[150]!.width).toBe(56);
	});

	test("bezier track is pinned for seed 42 / pathWidth 60", () => {
		const track = generatePathPoints("bezier", 42, 60);
		expect(track.start).toEqual({ x: 40, y: 40.07231554954529 });
		expect(track.end).toEqual({ x: 420, y: 155.4091623941522 });
		expect(pathLength(track.points)).toBeCloseTo(420.37650646609796, 6);
	});

	test("no track point is ever narrower than the ball's diameter plus touch slack, across every shape", () => {
		for (const shape of ["chokepoint", "bezier", "zigzag", "loop"] as const) {
			for (const pathWidth of [48, 60, 96]) {
				const track = generatePathPoints(shape, 7, pathWidth);
				for (const point of track.points) {
					expect(point.width).toBeGreaterThanOrEqual(48);
				}
			}
		}
	});

	test("trackMetrics reports no wall hit exactly on the centerline, and a hit far off it", () => {
		const track = generatePathPoints("chokepoint", 1337, 60);
		expect(trackMetrics(track.start, track.points).isWallHit).toBe(false);
		expect(trackMetrics({ x: 0, y: 0 }, track.points).isWallHit).toBe(true);
	});
});

describe("traceProvider", () => {
	test("validateConfig accepts a valid config", () => {
		expect(() => traceProvider.validateConfig?.({ shape: "chokepoint", pathWidth: 60 })).not.toThrow();
	});

	test("validateConfig rejects an invalid or missing shape", () => {
		expect(() => traceProvider.validateConfig?.({ shape: "spiral", pathWidth: 60 })).toThrow();
		expect(() => traceProvider.validateConfig?.({ pathWidth: 60 })).toThrow();
	});

	test("validateConfig rejects an out-of-range or missing pathWidth", () => {
		expect(() => traceProvider.validateConfig?.({ shape: "bezier", pathWidth: 47 })).toThrow();
		expect(() => traceProvider.validateConfig?.({ shape: "bezier", pathWidth: 97 })).toThrow();
		expect(() => traceProvider.validateConfig?.({ shape: "bezier" })).toThrow();
	});

	test("create returns matching public/private data with a numeric seed", async () => {
		const material = await traceProvider.create(
			{ flowId: "flow_1", siteId: "site_1", clientIp: "203.0.113.10", userAgentHash: "ua", expiresAt: Date.now() + 60_000 },
			{ shape: "zigzag", pathWidth: 70 },
		);
		expect(material.publicData).toEqual(material.privateData);
		expect(material.publicData.kind).toBe("trace");
		expect(material.publicData.shape).toBe("zigzag");
		expect(material.publicData.pathWidth).toBe(70);
		expect(material.publicData.ballRadius).toBe(10);
		expect(material.publicData.endRadius).toBe(16);
		expect(typeof material.publicData.seed).toBe("number");
		expect(material.publicData.trackColor).toBe("#1e293b");
		expect(material.publicData.targetColor).toBe("#ff4d4d");
		expect(material.publicData.trailColor).toBe("#22d3ee");
		expect(material.publicData.ballColor).toBe("#7c3aed");
		expect(material.publicData.backgroundColor).toBe("#0b1220");
	});

	test("create carries through custom colors", async () => {
		const material = await traceProvider.create(
			{ flowId: "flow_1", siteId: "site_1", clientIp: "203.0.113.10", userAgentHash: "ua", expiresAt: Date.now() + 60_000 },
			{
				shape: "zigzag",
				pathWidth: 70,
				trackColor: "#111111",
				targetColor: "#222222",
				trailColor: "#333333",
				ballColor: "#444444",
				backgroundColor: "#555555",
			},
		);
		expect(material.publicData.trackColor).toBe("#111111");
		expect(material.publicData.targetColor).toBe("#222222");
		expect(material.publicData.trailColor).toBe("#333333");
		expect(material.publicData.ballColor).toBe("#444444");
		expect(material.publicData.backgroundColor).toBe("#555555");
	});

	test("validateConfig rejects a malformed hex color", () => {
		expect(() => traceProvider.validateConfig?.({ shape: "bezier", pathWidth: 60, ballColor: "purple" })).toThrow();
	});

	test("verify accepts a plausible, jittered run along the real track", async () => {
		const track = generatePathPoints(SHAPE, SEED, PATH_WIDTH);
		const result = await traceProvider.verify(verifyContext, {}, privateData, { path: buildRun(track) });
		expect(result.success).toBe(true);
	});

	test("verify rejects a run shorter than the minimum sample count", async () => {
		const track = generatePathPoints(SHAPE, SEED, PATH_WIDTH);
		const result = await traceProvider.verify(verifyContext, {}, privateData, { path: buildRun(track, { sampleCount: 10 }) });
		expect(result.success).toBe(false);
		expect(result.reason).toBe("traceChallengeFailed");
	});

	test("verify rejects a run that never reaches the end", async () => {
		const track = generatePathPoints(SHAPE, SEED, PATH_WIDTH);
		const result = await traceProvider.verify(verifyContext, {}, privateData, { path: buildRun(track).slice(0, -20) });
		expect(result.success).toBe(false);
	});

	test("verify rejects a run with too many wall hits", async () => {
		const track = generatePathPoints(SHAPE, SEED, PATH_WIDTH);
		const result = await traceProvider.verify(verifyContext, {}, privateData, { path: buildRun(track, { offsetPx: 20 }) });
		expect(result.success).toBe(false);
	});

	test("verify rejects a single large excursion even with a low overall hit ratio", async () => {
		const track = generatePathPoints(SHAPE, SEED, PATH_WIDTH);
		const path = buildRun(track);
		path[40] = { ...path[40]!, x: 0, y: 0 };
		const result = await traceProvider.verify(verifyContext, {}, privateData, { path });
		expect(result.success).toBe(false);
	});

	test("verify rejects a suspiciously perfect, laser-centered run with zero wall hits", async () => {
		const track = generatePathPoints(SHAPE, SEED, PATH_WIDTH);
		const result = await traceProvider.verify(verifyContext, {}, privateData, { path: buildRun(track, { offsetPx: 0 }) });
		expect(result.success).toBe(false);
	});

	test("verify rejects perfectly uniform (zero-variance) timestamps", async () => {
		const track = generatePathPoints(SHAPE, SEED, PATH_WIDTH);
		const result = await traceProvider.verify(verifyContext, {}, privateData, { path: buildRun(track, { jitter: false }) });
		expect(result.success).toBe(false);
	});

	test("verify rejects a missing or malformed answer", async () => {
		expect((await traceProvider.verify(verifyContext, {}, privateData, {})).success).toBe(false);
		expect((await traceProvider.verify(verifyContext, {}, privateData, { path: "not-an-array" })).success).toBe(false);
		expect((await traceProvider.verify(verifyContext, {}, privateData, { path: [{ x: 1 }] })).success).toBe(false);
	});
});
