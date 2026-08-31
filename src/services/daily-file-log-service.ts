import { Levels, NDJsonTransport, type LogEntry, type Transport } from "@rabbit-company/web-middleware/logger";
import { createReadStream, createWriteStream, existsSync, readFileSync } from "node:fs";
import { appendFile, mkdir, readdir, rename, stat, unlink, writeFile } from "node:fs/promises";
import { createInterface } from "node:readline";
import { pipeline } from "node:stream/promises";
import { createGzip } from "node:zlib";
import { config } from "../config.ts";

export const LOG_LEVEL_NAMES = ["error", "warn", "audit", "info", "http", "debug", "verbose", "silly"] as const;
export type LogLevelName = (typeof LOG_LEVEL_NAMES)[number];

export interface FileLogSettings {
	fileEnabled: boolean;
	level: LogLevelName;
	compressAfterDays: number;
	retentionDays: number;
}

export interface StoredLogEntry {
	timestamp: number;
	level: LogLevelName;
	message: string;
	metadata?: unknown;
}

export interface LogArchive {
	name: string;
	date: string;
	size: number;
	modifiedAt: number;
}

export interface LogQuery {
	from: number;
	to: number;
	search?: string;
	level?: LogLevelName | "";
	page?: number;
	pageSize?: number;
}

export interface LogQueryResult {
	items: StoredLogEntry[];
	total: number;
	page: number;
	pageSize: number;
	totalPages: number;
	bucketMs: number;
	rangeFrom: number;
	rangeTo: number;
	series: Array<{ bucket: number } & Record<LogLevelName, number>>;
	uncompressedDates: string[];
}

interface DailyFileLogServiceOptions {
	directory?: string;
	defaults?: FileLogSettings;
	now?: () => number;
}

interface PendingFileBatch {
	path: string;
	data: string;
}

const LOG_BATCH_FLUSH_INTERVAL_MS = 1_000;
const LOG_BATCH_MAX_BYTES = 64 * 1_024;

const LEVEL_BY_NAME: Record<LogLevelName, Levels> = {
	error: Levels.ERROR,
	warn: Levels.WARN,
	audit: Levels.AUDIT,
	info: Levels.INFO,
	http: Levels.HTTP,
	debug: Levels.DEBUG,
	verbose: Levels.VERBOSE,
	silly: Levels.SILLY,
};

function validLevel(value: unknown): value is LogLevelName {
	return typeof value === "string" && (LOG_LEVEL_NAMES as readonly string[]).includes(value);
}

function validatedSettings(value: Partial<FileLogSettings>, fallback: FileLogSettings): FileLogSettings {
	const fileEnabled = typeof value.fileEnabled === "boolean" ? value.fileEnabled : fallback.fileEnabled;
	const level = validLevel(value.level) ? value.level : fallback.level;
	const compressAfterDays = Number(value.compressAfterDays ?? fallback.compressAfterDays);
	const retentionDays = Number(value.retentionDays ?? fallback.retentionDays);
	if (!Number.isInteger(compressAfterDays) || compressAfterDays < 1 || compressAfterDays > 3_649) {
		throw new Error("Compress-after days must be a whole number between 1 and 3649");
	}
	if (!Number.isInteger(retentionDays) || retentionDays < 2 || retentionDays > 3_650) {
		throw new Error("Retention days must be a whole number between 2 and 3650");
	}
	if (compressAfterDays >= retentionDays) throw new Error("Compress-after days must be less than retention days");
	return { fileEnabled, level, compressAfterDays, retentionDays };
}

function localDateKey(timestamp: number): string {
	const date = new Date(timestamp);
	return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
}

function dateOrdinal(dateKey: string): number | null {
	const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(dateKey);
	if (!match) return null;
	return Math.floor(Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3])) / 86_400_000);
}

function levelName(level: Levels): LogLevelName | null {
	const name = String(Levels[level] ?? "").toLowerCase();
	return validLevel(name) ? name : null;
}

function safeJson(value: unknown): string | undefined {
	const seen = new WeakSet<object>();
	return JSON.stringify(value, (_key, item) => {
		if (typeof item === "bigint") return item.toString();
		if (item instanceof Error) return { name: item.name, message: item.message, stack: item.stack };
		if (item && typeof item === "object") {
			if (seen.has(item)) return "[Circular]";
			seen.add(item);
		}
		return item;
	});
}

function jsonSafeValue(value: unknown): unknown {
	try {
		const serialized = safeJson(value);
		return serialized === undefined ? String(value) : JSON.parse(serialized);
	} catch {
		return "[Unserializable metadata]";
	}
}

function parseStoredEntry(line: string): StoredLogEntry | null {
	try {
		const parsed = JSON.parse(line) as Partial<StoredLogEntry> & { time?: unknown; msg?: unknown };
		if (Number.isFinite(parsed.timestamp) && validLevel(parsed.level) && typeof parsed.message === "string") {
			return {
				timestamp: Number(parsed.timestamp),
				level: parsed.level,
				message: parsed.message,
				...(parsed.metadata === undefined ? {} : { metadata: parsed.metadata }),
			};
		}
		const timestamp = typeof parsed.time === "string" ? Date.parse(parsed.time) : Number.NaN;
		const level = typeof parsed.level === "number" ? levelName(parsed.level) : validLevel(parsed.level) ? parsed.level : null;
		if (!Number.isFinite(timestamp) || !level || typeof parsed.msg !== "string") return null;
		return { timestamp, level, message: parsed.msg, ...(parsed.metadata === undefined ? {} : { metadata: parsed.metadata }) };
	} catch {
		return null;
	}
}

function bucketSize(duration: number): number {
	if (duration <= 6 * 3_600_000) return 5 * 60_000;
	if (duration <= 24 * 3_600_000) return 15 * 60_000;
	if (duration <= 7 * 86_400_000) return 3_600_000;
	if (duration <= 31 * 86_400_000) return 6 * 3_600_000;
	return 86_400_000;
}

function emptyPoint(bucket: number): { bucket: number } & Record<LogLevelName, number> {
	return { bucket, error: 0, warn: 0, audit: 0, info: 0, http: 0, debug: 0, verbose: 0, silly: 0 };
}

export class DailyFileLogService implements Transport {
	readonly directory: string;
	private readonly settingsPath: string;
	private readonly now: () => number;
	private settingsValue: FileLogSettings;
	private readonly ndjson = new NDJsonTransport();
	private readonly pendingBatches: PendingFileBatch[] = [];
	private queue: Promise<void> = Promise.resolve();
	private maintenanceTimer: ReturnType<typeof setInterval> | null = null;
	private batchFlushTimer: ReturnType<typeof setInterval> | null = null;
	private levelHandler: ((level: Levels) => void) | null = null;
	private writeFailureStartedAt: number | null = null;

	constructor(options: DailyFileLogServiceOptions = {}) {
		this.directory = options.directory ?? config.logging.directory;
		this.settingsPath = `${this.directory}/settings.json`;
		this.now = options.now ?? Date.now;
		const configuredDefaults =
			options.defaults ??
			({
				fileEnabled: config.logging.fileEnabled,
				level: config.logging.level,
				compressAfterDays: config.logging.compressAfterDays,
				retentionDays: config.logging.retentionDays,
			} satisfies FileLogSettings);
		const safeDefaults: FileLogSettings = { fileEnabled: false, level: "info", compressAfterDays: 1, retentionDays: 30 };
		const defaults = validatedSettings(configuredDefaults, safeDefaults);
		this.settingsValue = defaults;
		if (existsSync(this.settingsPath)) {
			try {
				this.settingsValue = validatedSettings(JSON.parse(readFileSync(this.settingsPath, "utf8")), defaults);
			} catch {
				this.settingsValue = defaults;
			}
		}
	}

	settings(): FileLogSettings {
		return { ...this.settingsValue };
	}

	loggerLevel(): Levels {
		return LEVEL_BY_NAME[this.settingsValue.level];
	}

	setLevelHandler(handler: (level: Levels) => void): void {
		this.levelHandler = handler;
		handler(this.loggerLevel());
	}

	async initialize(): Promise<void> {
		await mkdir(this.directory, { recursive: true });
		await this.runMaintenance();
		if (!this.maintenanceTimer) {
			this.maintenanceTimer = setInterval(() => void this.runMaintenance().catch(() => {}), 60 * 60_000);
			this.maintenanceTimer.unref?.();
		}
		if (!this.batchFlushTimer) {
			this.batchFlushTimer = setInterval(() => void this.persistBufferedLogs().catch(() => {}), LOG_BATCH_FLUSH_INTERVAL_MS);
			this.batchFlushTimer.unref?.();
		}
	}

	stop(): void {
		if (this.maintenanceTimer) clearInterval(this.maintenanceTimer);
		if (this.batchFlushTimer) clearInterval(this.batchFlushTimer);
		this.maintenanceTimer = null;
		this.batchFlushTimer = null;
	}

	log(entry: LogEntry): void {
		if (!this.settingsValue.fileEnabled) return;
		this.ndjson.log({ ...entry, ...(entry.metadata === undefined ? {} : { metadata: { metadata: jsonSafeValue(entry.metadata) } }) });
		if (Buffer.byteLength(this.ndjson.getData(), "utf8") >= LOG_BATCH_MAX_BYTES) void this.persistBufferedLogs().catch(() => {});
	}

	async flush(): Promise<void> {
		await this.persistBufferedLogs();
	}

	async updateSettings(value: Partial<FileLogSettings>): Promise<FileLogSettings> {
		const next = validatedSettings(value, this.settingsValue);
		if (this.settingsValue.fileEnabled && !next.fileEnabled) await this.flush();
		await mkdir(this.directory, { recursive: true });
		const temporaryPath = `${this.settingsPath}.tmp`;
		await writeFile(temporaryPath, `${JSON.stringify(next, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
		await rename(temporaryPath, this.settingsPath);
		this.settingsValue = next;
		this.levelHandler?.(LEVEL_BY_NAME[next.level]);
		await this.runMaintenance();
		return this.settings();
	}

	async query(input: LogQuery): Promise<LogQueryResult> {
		await this.flush();
		const from = Number(input.from);
		const to = Number(input.to);
		if (!Number.isFinite(from) || !Number.isFinite(to) || from < 0 || to <= from) throw new Error("Select a valid log date range");
		if (to - from > 366 * 86_400_000) throw new Error("The log date range cannot exceed 366 days");
		const page = Math.max(1, Math.min(200, Math.floor(Number(input.page ?? 1)) || 1));
		const pageSize = Math.max(10, Math.min(200, Math.floor(Number(input.pageSize ?? 50)) || 50));
		const search = input.search?.trim().toLowerCase() ?? "";
		const filterLevel = input.level && validLevel(input.level) ? input.level : "";
		const bucketMs = bucketSize(to - from);
		const firstBucket = Math.floor(from / bucketMs) * bucketMs;
		const points = new Map<number, ReturnType<typeof emptyPoint>>();
		for (let bucket = firstBucket; bucket <= to; bucket += bucketMs) points.set(bucket, emptyPoint(bucket));
		const keep = page * pageSize;
		const matched: StoredLogEntry[] = [];
		let total = 0;
		const files = await this.uncompressedFiles();
		for (const file of files) {
			const reader = createInterface({ input: createReadStream(`${this.directory}/${file}`), crlfDelay: Infinity });
			for await (const line of reader) {
				const entry = parseStoredEntry(line);
				if (!entry || entry.timestamp < from || entry.timestamp > to) continue;
				const point = points.get(Math.floor(entry.timestamp / bucketMs) * bucketMs);
				if (point) point[entry.level] += 1;
				if (filterLevel && entry.level !== filterLevel) continue;
				if (search && !(safeJson(entry) ?? "").toLowerCase().includes(search)) continue;
				total += 1;
				matched.push(entry);
				if (matched.length > keep) matched.shift();
			}
		}
		const newest = matched.reverse();
		const offset = (page - 1) * pageSize;
		return {
			items: newest.slice(offset, offset + pageSize),
			total,
			page,
			pageSize,
			totalPages: Math.max(1, Math.ceil(total / pageSize)),
			bucketMs,
			rangeFrom: from,
			rangeTo: to,
			series: [...points.values()],
			uncompressedDates: files.map((file) => file.slice(0, 10)),
		};
	}

	async archives(): Promise<LogArchive[]> {
		await this.flush();
		await mkdir(this.directory, { recursive: true });
		const files = (await readdir(this.directory))
			.filter((name) => /^\d{4}-\d{2}-\d{2}\.txt\.gz$/.test(name))
			.sort()
			.reverse();
		return await Promise.all(
			files.map(async (name) => {
				const details = await stat(`${this.directory}/${name}`);
				return { name, date: name.slice(0, 10), size: details.size, modifiedAt: details.mtimeMs };
			}),
		);
	}

	async archivePath(name: string): Promise<string | null> {
		if (!/^\d{4}-\d{2}-\d{2}\.txt\.gz$/.test(name)) return null;
		const path = `${this.directory}/${name}`;
		return existsSync(path) ? path : null;
	}

	async deleteArchive(name: string): Promise<boolean> {
		const path = await this.archivePath(name);
		if (!path) return false;
		await unlink(path);
		return true;
	}

	async runMaintenance(): Promise<void> {
		await this.schedule(async () => {
			await mkdir(this.directory, { recursive: true });
			const todayOrdinal = dateOrdinal(localDateKey(this.now()))!;
			const files = await readdir(this.directory);
			let deleted = 0;
			let compressed = 0;
			for (const name of files) {
				const match = /^(\d{4}-\d{2}-\d{2})\.txt(\.gz)?$/.exec(name);
				if (!match) continue;
				const ordinal = dateOrdinal(match[1] ?? "");
				if (ordinal === null) continue;
				const ageDays = todayOrdinal - ordinal;
				const path = `${this.directory}/${name}`;
				if (ageDays >= this.settingsValue.retentionDays) {
					await unlink(path);
					deleted += 1;
					continue;
				}
				if (!match[2] && ageDays >= this.settingsValue.compressAfterDays) {
					await this.compress(path);
					compressed += 1;
				}
			}
			if (deleted > 0 || compressed > 0) {
				this.bufferInternalLog(Levels.INFO, "Log file maintenance completed", { directory: this.directory, compressed, deletedForRetention: deleted });
			}
		});
	}

	private async uncompressedFiles(): Promise<string[]> {
		await mkdir(this.directory, { recursive: true });
		return (await readdir(this.directory)).filter((name) => /^\d{4}-\d{2}-\d{2}\.txt$/.test(name)).sort();
	}

	private async compress(path: string): Promise<void> {
		const target = `${path}.gz`;
		if (existsSync(target)) {
			await unlink(path);
			return;
		}
		const temporary = `${target}.tmp`;
		try {
			if (existsSync(temporary)) await unlink(temporary);
			await pipeline(createReadStream(path), createGzip({ level: 9 }), createWriteStream(temporary, { flags: "wx", mode: 0o600 }));
			await rename(temporary, target);
			await unlink(path);
		} catch (error) {
			if (existsSync(temporary)) await unlink(temporary).catch(() => {});
			throw error;
		}
	}

	private queueCurrentBatch(): void {
		const data = this.ndjson.getData();
		if (!data) return;
		this.ndjson.reset();
		const byPath = new Map<string, string[]>();
		for (const line of data.split("\n")) {
			if (!line) continue;
			try {
				const parsed = JSON.parse(line) as { time?: unknown };
				const timestamp = typeof parsed.time === "string" ? Date.parse(parsed.time) : Number.NaN;
				if (!Number.isFinite(timestamp)) continue;
				const path = `${this.directory}/${localDateKey(timestamp)}.txt`;
				const lines = byPath.get(path) ?? [];
				lines.push(line);
				byPath.set(path, lines);
			} catch {}
		}
		for (const [path, lines] of byPath) this.pendingBatches.push({ path, data: `${lines.join("\n")}\n` });
	}

	private async persistBufferedLogs(): Promise<void> {
		this.queueCurrentBatch();
		if (this.pendingBatches.length === 0) {
			await this.queue;
			return;
		}
		await this.schedule(async () => {
			try {
				await mkdir(this.directory, { recursive: true });
				while (this.pendingBatches.length > 0) {
					const batch = this.pendingBatches[0]!;
					await appendFile(batch.path, batch.data, { encoding: "utf8", mode: 0o600 });
					this.pendingBatches.shift();
				}
				if (this.writeFailureStartedAt !== null) {
					const failedAt = this.writeFailureStartedAt;
					this.writeFailureStartedAt = null;
					console.info("File logging recovered", { directory: this.directory, outageDurationMs: this.now() - failedAt });
					this.bufferInternalLog(Levels.INFO, "File logging recovered", { directory: this.directory, outageDurationMs: this.now() - failedAt });
					while (this.pendingBatches.length > 0) {
						const batch = this.pendingBatches[0]!;
						await appendFile(batch.path, batch.data, { encoding: "utf8", mode: 0o600 });
						this.pendingBatches.shift();
					}
				}
			} catch (error) {
				if (this.writeFailureStartedAt === null) {
					this.writeFailureStartedAt = this.now();
					console.error("File logging failed; retaining queued batches for retry", error);
					this.bufferInternalLog(Levels.ERROR, "File logging failed; queued batches will be retried", {
						directory: this.directory,
						pendingBatches: this.pendingBatches.length,
						error,
					});
				}
				throw error;
			}
		}, false);
	}

	private bufferInternalLog(level: Levels, message: string, metadata: Record<string, unknown>): void {
		if (!this.settingsValue.fileEnabled || this.loggerLevel() < level) return;
		this.ndjson.log({ timestamp: this.now(), level, message, metadata: { metadata: jsonSafeValue(metadata) } });
		this.queueCurrentBatch();
	}

	private schedule(task: () => Promise<void>, reportFailure = true): Promise<void> {
		const run = this.queue.then(task);
		this.queue = run.catch((error) => {
			if (reportFailure) console.error("File logging operation failed", error);
		});
		return run;
	}
}

export const dailyFileLogs = new DailyFileLogService();
