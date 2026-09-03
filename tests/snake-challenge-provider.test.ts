import { describe, expect, test } from "bun:test";
import { mulberry32, shuffledCells, simulateSnake } from "../src/challenges/providers/snake-engine.ts";
import { snakeProvider } from "../src/challenges/providers/snake.ts";
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

function plausibleTimings(moves: string, tickMs = 150): number[] {
	return Array.from({ length: moves.length }, () => tickMs);
}

describe("mulberry32 / shuffledCells", () => {
	test("produces a pinned, deterministic sequence for a given seed", () => {
		expect(mulberry32(7)()).toBe(0.011704753153026104);
		expect(shuffledCells(4, mulberry32(7)).slice(0, 6)).toEqual([8, 7, 11, 3, 14, 1]);
	});
});

describe("simulateSnake", () => {
	test("fails when the snake runs straight into a wall (seed-independent)", () => {
		// Head starts at grid center facing right; 7 "U" moves walks it off the top edge for a 12x12 grid.
		const result = simulateSnake({ seed: 1, gridSize: 12, applesRequired: 999, moves: "U".repeat(7) });
		expect(result.success).toBe(false);
		expect(result.reason).toBe("The snake hit a wall.");
	});

	test("fails when the snake collides with itself", () => {
		// Grows the snake by eating 3 apples (verified transcript for seed=1/gridSize=12), then loops
		// tightly enough that a length-6 snake catches its own tail. applesRequired is set far out of
		// reach (999) so an apple eaten along the loop can never accidentally satisfy a "win" instead.
		const growthPrefix = "DLLLUURRRRRRRUUUUULLLDD";
		const tightLoop = "ULDR".repeat(3);
		const result = simulateSnake({ seed: 1, gridSize: 12, applesRequired: 999, moves: growthPrefix + tightLoop });
		expect(result.success).toBe(false);
		expect(result.reason).toBe("The snake collided with itself.");
		expect(result.applesEaten).toBe(3);
	});

	test("succeeds once the required number of apples is eaten without a collision", () => {
		const result = simulateSnake({ seed: 42, gridSize: 12, applesRequired: 3, moves: "RUUULLLLLLDDDDDD" });
		expect(result.success).toBe(true);
		expect(result.applesEaten).toBe(3);
	});

	test("ignores trailing moves once the win condition is already reached", () => {
		const result = simulateSnake({ seed: 42, gridSize: 12, applesRequired: 3, moves: "RUUULLLLLLDDDDDDUUUUUUUUUUUUUUUU" });
		expect(result.success).toBe(true);
	});
});

describe("snakeProvider", () => {
	test("validateConfig accepts a valid config", () => {
		expect(() => snakeProvider.validateConfig?.({ gridSize: 16, applesRequired: 5 })).not.toThrow();
	});

	test("validateConfig rejects an out-of-range or missing gridSize", () => {
		expect(() => snakeProvider.validateConfig?.({ gridSize: 9, applesRequired: 5 })).toThrow();
		expect(() => snakeProvider.validateConfig?.({ gridSize: 41, applesRequired: 5 })).toThrow();
		expect(() => snakeProvider.validateConfig?.({ applesRequired: 5 })).toThrow();
	});

	test("validateConfig rejects an out-of-range or missing applesRequired", () => {
		expect(() => snakeProvider.validateConfig?.({ gridSize: 16, applesRequired: 0 })).toThrow();
		expect(() => snakeProvider.validateConfig?.({ gridSize: 16, applesRequired: 31 })).toThrow();
		expect(() => snakeProvider.validateConfig?.({ gridSize: 16 })).toThrow();
	});

	test("validateConfig accepts a missing tickMs (defaults client-side) but rejects an out-of-range one", () => {
		expect(() => snakeProvider.validateConfig?.({ gridSize: 16, applesRequired: 5 })).not.toThrow();
		expect(() => snakeProvider.validateConfig?.({ gridSize: 16, applesRequired: 5, tickMs: 59 })).toThrow();
		expect(() => snakeProvider.validateConfig?.({ gridSize: 16, applesRequired: 5, tickMs: 501 })).toThrow();
	});

	test("create returns a public seed/gridSize/applesRequired/tickMs and mirrors seed/gridSize/applesRequired in privateData", async () => {
		const material = await snakeProvider.create(
			{ flowId: "flow_1", siteId: "site_1", clientIp: "203.0.113.10", userAgentHash: "ua", expiresAt: Date.now() + 60_000 },
			{ gridSize: 20, applesRequired: 4, tickMs: 200 },
		);
		expect(material.publicData.kind).toBe("snake");
		expect(material.publicData.gridSize).toBe(20);
		expect(material.publicData.applesRequired).toBe(4);
		expect(material.publicData.tickMs).toBe(200);
		expect(typeof material.publicData.seed).toBe("number");
		expect(material.privateData.seed).toBe(material.publicData.seed);
	});

	test("create defaults tickMs to 150 when the config doesn't specify one", async () => {
		const material = await snakeProvider.create(
			{ flowId: "flow_1", siteId: "site_1", clientIp: "203.0.113.10", userAgentHash: "ua", expiresAt: Date.now() + 60_000 },
			{ gridSize: 20, applesRequired: 4 },
		);
		expect(material.publicData.tickMs).toBe(150);
	});

	test("create defaults colors and carries through custom ones", async () => {
		const context = { flowId: "flow_1", siteId: "site_1", clientIp: "203.0.113.10", userAgentHash: "ua", expiresAt: Date.now() + 60_000 };
		const defaults = await snakeProvider.create(context, { gridSize: 20, applesRequired: 4 });
		expect(defaults.publicData.backgroundColor).toBe("#0b1220");
		expect(defaults.publicData.appleColor).toBe("#22d3ee");
		expect(defaults.publicData.snakeColor).toBe("#7c3aed");
		expect(defaults.publicData.snakeHeadColor).toBe("#a78bfa");

		const custom = await snakeProvider.create(context, {
			gridSize: 20,
			applesRequired: 4,
			backgroundColor: "#111111",
			appleColor: "#222222",
			snakeColor: "#333333",
			snakeHeadColor: "#444444",
		});
		expect(custom.publicData.backgroundColor).toBe("#111111");
		expect(custom.publicData.appleColor).toBe("#222222");
		expect(custom.publicData.snakeColor).toBe("#333333");
		expect(custom.publicData.snakeHeadColor).toBe("#444444");
	});

	test("validateConfig rejects a malformed hex color", () => {
		expect(() => snakeProvider.validateConfig?.({ gridSize: 16, applesRequired: 5, appleColor: "red" })).toThrow();
	});

	test("verify accepts a winning transcript end-to-end", async () => {
		const privateData = { seed: 42, gridSize: 12, applesRequired: 3 };
		const moves = "RUUULLLLLLDDDDDD";
		const result = await snakeProvider.verify(verifyContext, {}, privateData, { moves, timings: plausibleTimings(moves) });
		expect(result.success).toBe(true);
	});

	test("verify rejects a losing transcript", async () => {
		const privateData = { seed: 1, gridSize: 12, applesRequired: 3 };
		const moves = "U".repeat(7);
		const result = await snakeProvider.verify(verifyContext, {}, privateData, { moves, timings: plausibleTimings(moves) });
		expect(result.success).toBe(false);
	});

	test("verify rejects a missing, empty, or malformed move string", async () => {
		const privateData = { seed: 42, gridSize: 12, applesRequired: 3 };
		expect((await snakeProvider.verify(verifyContext, {}, privateData, {})).success).toBe(false);
		expect((await snakeProvider.verify(verifyContext, {}, privateData, { moves: "" })).success).toBe(false);
		expect((await snakeProvider.verify(verifyContext, {}, privateData, { moves: "UDXR" })).success).toBe(false);
	});

	test("verify rejects a move string longer than the cap without throwing", async () => {
		const privateData = { seed: 42, gridSize: 12, applesRequired: 3 };
		const result = await snakeProvider.verify(verifyContext, {}, privateData, { moves: "U".repeat(20_000) });
		expect(result.success).toBe(false);
	});

	test("verify rejects a winning transcript submitted faster than the tick rate allows", async () => {
		const privateData = { seed: 42, gridSize: 12, applesRequired: 3 };
		const moves = "RUUULLLLLLDDDDDD";
		const instantContext = { ...verifyContext, createdAt: Date.now() };
		const result = await snakeProvider.verify(instantContext, { tickMs: 150 }, privateData, { moves, timings: plausibleTimings(moves) });
		expect(result.success).toBe(false);
		expect(result.reason).toBe("snakeChallengeFailed");
	});

	test("verify accepts the same transcript once enough real time has passed", async () => {
		const privateData = { seed: 42, gridSize: 12, applesRequired: 3 };
		const moves = "RUUULLLLLLDDDDDD";
		const plausibleContext = { ...verifyContext, createdAt: Date.now() - moves.length * 150 };
		const result = await snakeProvider.verify(plausibleContext, { tickMs: 150 }, privateData, { moves, timings: plausibleTimings(moves) });
		expect(result.success).toBe(true);
	});

	test("verify rejects a winning transcript with no per-move timings (the pre-telemetry solver shape)", async () => {
		const privateData = { seed: 42, gridSize: 12, applesRequired: 3 };
		const moves = "RUUULLLLLLDDDDDD";
		const plausibleContext = { ...verifyContext, createdAt: Date.now() - moves.length * 150 };
		const result = await snakeProvider.verify(plausibleContext, { tickMs: 150 }, privateData, { moves });
		expect(result.success).toBe(false);
		expect(result.reason).toBe("snakeChallengeFailed");
	});

	test("verify rejects timings whose length doesn't match the move string", async () => {
		const privateData = { seed: 42, gridSize: 12, applesRequired: 3 };
		const moves = "RUUULLLLLLDDDDDD";
		const plausibleContext = { ...verifyContext, createdAt: Date.now() - moves.length * 150 };
		const result = await snakeProvider.verify(plausibleContext, { tickMs: 150 }, privateData, {
			moves,
			timings: plausibleTimings(moves).slice(0, -1),
		});
		expect(result.success).toBe(false);
		expect(result.reason).toBe("snakeChallengeFailed");
	});

	test("verify rejects a winning transcript where the total wait was padded but individual moves are near-instant", async () => {
		const privateData = { seed: 42, gridSize: 12, applesRequired: 3 };
		const moves = "RUUULLLLLLDDDDDD";
		const plausibleContext = { ...verifyContext, createdAt: Date.now() - moves.length * 150 };
		const result = await snakeProvider.verify(plausibleContext, { tickMs: 150 }, privateData, {
			moves,
			timings: moves.split("").map(() => 1),
		});
		expect(result.success).toBe(false);
		expect(result.reason).toBe("snakeChallengeFailed");
	});

	test("verify accepts naturally jittery per-move timings as long as every gap clears the floor", async () => {
		const privateData = { seed: 42, gridSize: 12, applesRequired: 3 };
		const moves = "RUUULLLLLLDDDDDD";
		const timings = moves.split("").map((_, index) => (index % 2 === 0 ? 130 : 220));
		const plausibleContext = { ...verifyContext, createdAt: Date.now() - timings.reduce((a, b) => a + b, 0) };
		const result = await snakeProvider.verify(plausibleContext, { tickMs: 150 }, privateData, { moves, timings });
		expect(result.success).toBe(true);
	});
});
