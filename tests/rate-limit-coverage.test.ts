import { describe, expect, test } from "bun:test";
import { Web } from "@rabbit-company/web";
import { registerChallengeRoutes } from "../src/routes/challenge-routes.ts";
import { registerMonitoringRoutes } from "../src/routes/monitoring-routes.ts";
import { registerAccessRoutes } from "../src/routes/access-routes.ts";

const source = await Bun.file(new URL("../src/index.ts", import.meta.url)).text();

const limitedPaths = [...source.matchAll(/app\.use\("(\/_burrowgate\/[^"]*)",\s*rateLimit\(/g)].map((match) => match[1]!);

function registeredPaths(): string[] {
	const app = new Web();
	registerChallengeRoutes(app);
	registerMonitoringRoutes(app);
	registerAccessRoutes(app);
	return (app as unknown as { getRoutes(): Array<{ method: string; path: string }> }).getRoutes().map((route) => route.path);
}

function covers(pattern: string, path: string): boolean {
	if (pattern.endsWith("/*")) {
		const base = pattern.slice(0, -2);
		return path === base || path.startsWith(`${base}/`);
	}
	return path === pattern;
}

describe("rate limit coverage", () => {
	test("every rate-limited path actually has routes behind it", () => {
		const paths = registeredPaths();
		const checkable = limitedPaths.filter((pattern) => /\/(challenge|v1|access)\b/.test(pattern));
		expect(checkable.length).toBeGreaterThan(0);

		const dead = checkable.filter((pattern) => !paths.some((path) => covers(pattern, path)));
		expect(dead, "Rate limits registered on paths no route serves - they protect nothing").toEqual([]);
	});

	test("every challenge endpoint is covered by a challenge rate limit", () => {
		const challengeRoutes = registeredPaths().filter((path) => path.startsWith("/_burrowgate/api/challenge"));
		expect(challengeRoutes.length).toBeGreaterThan(0);

		const challengeLimits = limitedPaths.filter((pattern) => pattern.includes("/challenge"));
		const uncovered = challengeRoutes.filter((path) => !challengeLimits.some((pattern) => covers(pattern, path)));
		expect(uncovered, "Challenge endpoints with no challenge-specific rate limit").toEqual([]);
	});

	test("the backstop covers every API route, including the ones with their own limit", () => {
		const backstop = limitedPaths.find((pattern) => pattern === "/_burrowgate/api/*");
		expect(backstop, "The /_burrowgate/api/* backstop is gone - every API route below now depends on its own limit alone").toBeDefined();

		const apiRoutes = registeredPaths().filter((path) => path.startsWith("/_burrowgate/api/"));
		expect(apiRoutes.filter((path) => !covers(backstop!, path))).toEqual([]);
	});
});
