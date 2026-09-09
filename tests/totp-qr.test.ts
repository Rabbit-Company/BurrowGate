import { describe, expect, test } from "bun:test";
import { enrollmentUri, generateSecret, qrSvg } from "../src/services/totp-service.ts";

function parseModules(svg: string): { size: number; dark: Set<string> } {
	const viewBox = svg.match(/viewBox="0 0 (\d+) (\d+)"/u);
	if (!viewBox) throw new Error("QR SVG has no viewBox");
	const points = [...svg.matchAll(/M(\d+) (\d+)h1v1h-1z/gu)].map((match) => [Number(match[1]), Number(match[2])] as const);
	if (points.length === 0) throw new Error("QR SVG has no dark modules");
	const margin = Math.min(...points.map(([x]) => x), ...points.map(([, y]) => y));
	const dark = new Set(points.map(([x, y]) => `${x - margin},${y - margin}`));
	return { size: Number(viewBox[1]) - margin * 2, dark };
}

function isFinderPatternAt(modules: { dark: Set<string> }, originX: number, originY: number): boolean {
	for (let y = 0; y < 7; y++) {
		for (let x = 0; x < 7; x++) {
			const ring = x === 0 || x === 6 || y === 0 || y === 6;
			const centre = x >= 2 && x <= 4 && y >= 2 && y <= 4;
			if (modules.dark.has(`${originX + x},${originY + y}`) !== (ring || centre)) return false;
		}
	}
	return true;
}

describe("TOTP enrollment QR code", () => {
	const uri = enrollmentUri("alice", "JBSWY3DPEHPK3PXP");

	test("renders an SVG the enrollment page can inline", () => {
		const svg = qrSvg(uri);

		expect(svg.startsWith("<svg")).toBe(true);
		expect(svg.trimEnd().endsWith("</svg>")).toBe(true);
		expect(svg).toContain('xmlns="http://www.w3.org/2000/svg"');
		expect(svg).toContain("viewBox=");
		expect(svg).not.toContain("<?xml");
	});

	test("is a structurally valid QR symbol with all three finder patterns", () => {
		const modules = parseModules(qrSvg(uri));

		expect(modules.size).toBeGreaterThanOrEqual(21);
		expect((modules.size - 17) % 4).toBe(0);
		expect(modules.dark.size).toBeGreaterThan(0);

		expect(isFinderPatternAt(modules, 0, 0)).toBe(true);
		expect(isFinderPatternAt(modules, modules.size - 7, 0)).toBe(true);
		expect(isFinderPatternAt(modules, 0, modules.size - 7)).toBe(true);
	});

	test("encodes the account it was given rather than a fixed image", () => {
		const first = qrSvg(enrollmentUri("alice", generateSecret()));
		const second = qrSvg(enrollmentUri("bob", generateSecret()));

		expect(first).not.toBe(second);
		expect(qrSvg(uri)).toBe(qrSvg(uri));
	});

	test("survives a unicode account name, which byte mode has to cover", () => {
		const unicode = enrollmentUri("иван@example.com", "NBSWY3DPEB3W64TMMQ");
		const modules = parseModules(qrSvg(unicode));

		expect(isFinderPatternAt(modules, 0, 0)).toBe(true);
		expect(isFinderPatternAt(modules, modules.size - 7, 0)).toBe(true);
	});
});
