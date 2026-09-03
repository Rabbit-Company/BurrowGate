import { describe, expect, test } from "bun:test";
import { sliderProvider } from "../src/challenges/providers/slider.ts";
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

const privateData = { trackWidth: 300, pieceSize: 40, targetX: 150 };

const PLAUSIBLE_PATH = [
	{ x: 0, y: 20, t: 0 },
	{ x: 20, y: 22, t: 30 },
	{ x: 55, y: 19, t: 65 },
	{ x: 85, y: 23, t: 95 },
	{ x: 110, y: 20, t: 130 },
	{ x: 130, y: 21, t: 160 },
	{ x: 145, y: 19, t: 195 },
	{ x: 150, y: 20, t: 225 },
];

const ALMOST_UNIFORM_PATH = [
	{ x: 0, y: 20, t: 0 },
	{ x: 21, y: 20, t: 30 },
	{ x: 43, y: 20, t: 61 },
	{ x: 64, y: 20, t: 91 },
	{ x: 86, y: 20, t: 122 },
	{ x: 107, y: 20, t: 152 },
	{ x: 129, y: 20, t: 183 },
	{ x: 150, y: 20, t: 213 },
];

const UNIFORM_PATH = [
	{ x: 0, y: 20, t: 0 },
	{ x: 20, y: 20, t: 32 },
	{ x: 40, y: 20, t: 64 },
	{ x: 60, y: 20, t: 96 },
	{ x: 80, y: 20, t: 128 },
	{ x: 100, y: 20, t: 160 },
	{ x: 120, y: 20, t: 192 },
	{ x: 140, y: 20, t: 224 },
];

describe("sliderProvider", () => {
	test("validateConfig accepts a valid config", () => {
		expect(() => sliderProvider.validateConfig?.({ trackWidth: 300, pieceSize: 40 })).not.toThrow();
	});

	test("validateConfig rejects an out-of-range or missing trackWidth", () => {
		expect(() => sliderProvider.validateConfig?.({ trackWidth: 219, pieceSize: 40 })).toThrow();
		expect(() => sliderProvider.validateConfig?.({ trackWidth: 401, pieceSize: 40 })).toThrow();
		expect(() => sliderProvider.validateConfig?.({ pieceSize: 40 })).toThrow();
	});

	test("validateConfig rejects an out-of-range or missing pieceSize", () => {
		expect(() => sliderProvider.validateConfig?.({ trackWidth: 300, pieceSize: 27 })).toThrow();
		expect(() => sliderProvider.validateConfig?.({ trackWidth: 300, pieceSize: 57 })).toThrow();
		expect(() => sliderProvider.validateConfig?.({ trackWidth: 300 })).toThrow();
	});

	test("validateConfig rejects an invalid piece shape or a malformed hex color", () => {
		expect(() => sliderProvider.validateConfig?.({ trackWidth: 300, pieceSize: 40, pieceShape: "triangle" })).toThrow();
		expect(() => sliderProvider.validateConfig?.({ trackWidth: 300, pieceSize: 40, pieceColor: "not-a-color" })).toThrow();
		expect(() => sliderProvider.validateConfig?.({ trackWidth: 300, pieceSize: 40, pieceColor: "#7c3aed" })).not.toThrow();
		expect(() => sliderProvider.validateConfig?.({ trackWidth: 300, pieceSize: 40, pieceShape: "square" })).not.toThrow();
	});

	test("create returns matching public/private data with targetX inside the draggable range", async () => {
		const material = await sliderProvider.create(
			{ flowId: "flow_1", siteId: "site_1", clientIp: "203.0.113.10", userAgentHash: "ua", expiresAt: Date.now() + 60_000 },
			{ trackWidth: 300, pieceSize: 40 },
		);
		expect(material.publicData).toEqual(material.privateData);
		expect(material.publicData.kind).toBe("slider");
		expect(material.publicData.trackWidth).toBe(300);
		expect(material.publicData.pieceSize).toBe(40);
		expect(material.publicData.tolerancePx).toBe(6);
		expect(material.publicData.pieceShape).toBe("circle");
		expect(material.publicData.pieceColor).toBe("#7c3aed");
		expect(material.publicData.targetColor).toBe("#22d3ee");
		expect(material.publicData.trackColor).toBe("#94a3b8");
		expect(material.publicData.backgroundColor).toBe("#0b1220");
		const targetX = Number(material.publicData.targetX);
		expect(targetX).toBeGreaterThanOrEqual(80);
		expect(targetX).toBeLessThanOrEqual(260);
	});

	test("create carries through a custom piece shape and colors", async () => {
		const material = await sliderProvider.create(
			{ flowId: "flow_1", siteId: "site_1", clientIp: "203.0.113.10", userAgentHash: "ua", expiresAt: Date.now() + 60_000 },
			{
				trackWidth: 300,
				pieceSize: 40,
				pieceShape: "square",
				pieceColor: "#ff0000",
				targetColor: "#00ff00",
				trackColor: "#0000ff",
				backgroundColor: "#111111",
			},
		);
		expect(material.publicData.pieceShape).toBe("square");
		expect(material.publicData.pieceColor).toBe("#ff0000");
		expect(material.publicData.targetColor).toBe("#00ff00");
		expect(material.publicData.trackColor).toBe("#0000ff");
		expect(material.publicData.backgroundColor).toBe("#111111");
	});

	test("verify accepts a plausible, jittered winning drag", async () => {
		const result = await sliderProvider.verify(verifyContext, {}, privateData, { finalX: 150, path: PLAUSIBLE_PATH });
		expect(result.success).toBe(true);
	});

	test("verify rejects landing outside the tolerance", async () => {
		const result = await sliderProvider.verify(verifyContext, {}, privateData, { finalX: 130, path: PLAUSIBLE_PATH });
		expect(result.success).toBe(false);
		expect(result.reason).toBe("sliderChallengeFailed");
	});

	test("verify rejects a path shorter than the minimum sample count", async () => {
		const result = await sliderProvider.verify(verifyContext, {}, privateData, { finalX: 150, path: PLAUSIBLE_PATH.slice(0, 3) });
		expect(result.success).toBe(false);
	});

	test("verify rejects a drag completed faster than physically plausible", async () => {
		const instantPath = PLAUSIBLE_PATH.map((sample, index) => ({ ...sample, t: index }));
		const result = await sliderProvider.verify(verifyContext, {}, privateData, { finalX: 150, path: instantPath });
		expect(result.success).toBe(false);
	});

	test("verify rejects a perfectly uniform (linearly-interpolated) fake path", async () => {
		const result = await sliderProvider.verify(verifyContext, {}, privateData, { finalX: 140, path: UNIFORM_PATH });
		expect(result.success).toBe(false);
	});

	test("verify rejects a low-but-nonzero-variance path a distinct-value-count check would have missed", async () => {
		const result = await sliderProvider.verify(verifyContext, {}, privateData, { finalX: 150, path: ALMOST_UNIFORM_PATH });
		expect(result.success).toBe(false);
	});

	test("verify rejects a finalX that doesn't match the path's last sample", async () => {
		const mismatchedPath = PLAUSIBLE_PATH.slice(0, -1).concat([{ x: 100, y: 20, t: 225 }]);
		const result = await sliderProvider.verify(verifyContext, {}, privateData, { finalX: 150, path: mismatchedPath });
		expect(result.success).toBe(false);
	});

	test("verify rejects timestamps that go backwards", async () => {
		const brokenPath = PLAUSIBLE_PATH.map((sample, index) => (index === 4 ? { ...sample, t: 10 } : sample));
		const result = await sliderProvider.verify(verifyContext, {}, privateData, { finalX: 150, path: brokenPath });
		expect(result.success).toBe(false);
	});

	test("verify rejects a missing or malformed answer", async () => {
		expect((await sliderProvider.verify(verifyContext, {}, privateData, {})).success).toBe(false);
		expect((await sliderProvider.verify(verifyContext, {}, privateData, { finalX: 150 })).success).toBe(false);
		expect((await sliderProvider.verify(verifyContext, {}, privateData, { finalX: 150, path: "not-an-array" })).success).toBe(false);
	});
});
