import { afterEach, describe, expect, test } from "bun:test";
import { Levels } from "@rabbit-company/web-middleware/logger";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { DailyFileLogService, type FileLogSettings } from "../src/services/daily-file-log-service.ts";

const directories: string[] = [];
const defaults: FileLogSettings = { fileEnabled: false, level: "info", compressAfterDays: 1, retentionDays: 30 };

async function temporaryDirectory(): Promise<string> {
	const directory = await mkdtemp(join(tmpdir(), "burrowgate-logs-"));
	directories.push(directory);
	return directory;
}

afterEach(async () => {
	await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("daily file logging", () => {
	test("stores structured entries by local day and searches only plain-text files", async () => {
		const directory = await temporaryDirectory();
		const timestamp = new Date(2026, 7, 31, 12, 30, 0).getTime();
		const service = new DailyFileLogService({ directory, defaults, now: () => timestamp });
		await service.initialize();
		service.log({ timestamp, level: Levels.INFO, message: "ignored while disabled" });
		await service.flush();
		expect(await service.query({ from: timestamp - 1_000, to: timestamp + 1_000 })).toMatchObject({ total: 0, items: [] });

		await service.updateSettings({ fileEnabled: true });
		service.log({ timestamp, level: Levels.INFO, message: "Application ready", metadata: { port: 443 } });
		service.log({ timestamp: timestamp + 100, level: Levels.ERROR, message: "Origin failed", metadata: { origin: "api" } });
		await service.flush();

		const text = await readFile(join(directory, "2026-08-31.txt"), "utf8");
		expect(text).toContain('"msg":"Application ready"');
		expect(text).toContain('"level":0');
		const result = await service.query({ from: timestamp - 1_000, to: timestamp + 1_000, search: "origin", pageSize: 50 });
		expect(result.total).toBe(1);
		expect(result.items[0]).toMatchObject({ level: "error", message: "Origin failed" });
		expect(result.series.reduce((sum, point) => sum + point.info, 0)).toBe(1);
		expect(result.series.reduce((sum, point) => sum + point.error, 0)).toBe(1);
		service.stop();
	});

	test("keeps an NDJSON batch in memory until its file append succeeds", async () => {
		const directory = await temporaryDirectory();
		const timestamp = new Date(2026, 7, 31, 12, 30, 0).getTime();
		const service = new DailyFileLogService({ directory, defaults: { ...defaults, fileEnabled: true }, now: () => timestamp });
		await service.initialize();
		const logPath = join(directory, "2026-08-31.txt");
		await mkdir(logPath);
		service.log({ timestamp, level: Levels.INFO, message: "Retained until retry" });
		await expect(service.flush()).rejects.toThrow();
		await rm(logPath, { recursive: true });
		await service.flush();
		const text = await readFile(logPath, "utf8");
		expect(text).toContain('"msg":"Retained until retry"');
		expect(text.match(/"msg":"Retained until retry"/g)).toHaveLength(1);
		expect(text).toContain('"msg":"File logging failed; queued batches will be retried"');
		expect(text).toContain('"msg":"File logging recovered"');
		service.stop();
	});

	test("splits one NDJSON batch across local calendar-day files", async () => {
		const directory = await temporaryDirectory();
		const beforeMidnight = new Date(2026, 7, 31, 23, 59, 0).getTime();
		const afterMidnight = new Date(2026, 8, 1, 0, 1, 0).getTime();
		const service = new DailyFileLogService({ directory, defaults: { ...defaults, fileEnabled: true }, now: () => afterMidnight });
		await service.initialize();
		service.log({ timestamp: beforeMidnight, level: Levels.INFO, message: "Before midnight" });
		service.log({ timestamp: afterMidnight, level: Levels.INFO, message: "After midnight" });
		await service.flush();
		expect(await readFile(join(directory, "2026-08-31.txt"), "utf8")).toContain('"msg":"Before midnight"');
		expect(await readFile(join(directory, "2026-09-01.txt"), "utf8")).toContain('"msg":"After midnight"');
		service.stop();
	});

	test("compresses eligible previous days and removes files past retention", async () => {
		const directory = await temporaryDirectory();
		await mkdir(directory, { recursive: true });
		await writeFile(join(directory, "2026-08-30.txt"), '{"timestamp":1788100000000,"level":"info","message":"yesterday"}\n');
		await writeFile(join(directory, "2026-08-30.txt.gz.tmp"), "interrupted archive");
		await writeFile(join(directory, "2026-08-28.txt"), '{"timestamp":1787900000000,"level":"info","message":"expired"}\n');
		const now = new Date(2026, 7, 31, 12, 0, 0).getTime();
		const service = new DailyFileLogService({
			directory,
			defaults: { fileEnabled: true, level: "info", compressAfterDays: 1, retentionDays: 3 },
			now: () => now,
		});
		await service.initialize();

		const archives = await service.archives();
		expect(archives.map((archive) => archive.name)).toEqual(["2026-08-30.txt.gz"]);
		expect(gunzipSync(await readFile(join(directory, "2026-08-30.txt.gz"))).toString()).toContain("yesterday");
		expect(await Bun.file(join(directory, "2026-08-28.txt")).exists()).toBe(false);
		expect(await Bun.file(join(directory, "2026-08-30.txt")).exists()).toBe(false);
		service.stop();
	});

	test("persists validated settings and safely limits archive access", async () => {
		const directory = await temporaryDirectory();
		const service = new DailyFileLogService({ directory, defaults });
		await service.initialize();
		let changedLevel = -1;
		service.setLevelHandler((level) => {
			changedLevel = level;
		});
		await service.updateSettings({ fileEnabled: true, level: "debug", compressAfterDays: 2, retentionDays: 14 });
		expect(changedLevel).toBe(Levels.DEBUG);
		expect(JSON.parse(await readFile(join(directory, "settings.json"), "utf8"))).toMatchObject({ level: "debug", retentionDays: 14 });
		await expect(service.updateSettings({ compressAfterDays: 14, retentionDays: 14 })).rejects.toThrow("less than retention days");
		expect(await service.archivePath("../settings.json")).toBeNull();
		service.stop();
	});
});
