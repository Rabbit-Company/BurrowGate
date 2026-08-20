/**
 * Bun's built-in SQL client (`import { SQL } from "bun"`), the exact driver
 * src/db/client.ts uses against sqlite://. Every proxied request logs a row
 * to request_events (src/db/repository.ts logRequestEvent) and the
 * dashboard reads them back with filtered/aggregated SELECTs, so both
 * directions are benchmarked against a schema subset of the real table.
 */
import { rm } from "node:fs/promises";
import { SQL } from "bun";
import { measureLatency, measureRate, printResults, saveSuiteRun, type BenchResult } from "./lib/harness.ts";

const SUITE = "sqlite";
const DIR = `${import.meta.dir}/tmp/sqlite`;

function randomId(): string {
	return crypto.randomUUID().replace(/-/gu, "");
}

async function seed(db: SQL, rows: number): Promise<void> {
	const decisions = ["allow", "blocked", "route-blocked", "challenged"];
	await db.begin(async (transaction) => {
		for (let i = 0; i < rows; i++) {
			await transaction`INSERT INTO request_events (id,site_id,ip,method,path,status,decision,latency_ms,country_code,created_at)
				VALUES (${randomId()},${"site-bench"},${"203.0.113.1"},${"GET"},${"/bench"},${200},${decisions[i % decisions.length]},${12},${"US"},${Date.now() - i * 1000})`;
		}
	});
}

export async function run(): Promise<BenchResult[]> {
	await Bun.$`mkdir -p ${DIR}`.quiet();
	const dbPath = `${DIR}/bench.db`;
	await rm(dbPath, { force: true });

	const db = new SQL(`sqlite://${dbPath}`);
	await db`CREATE TABLE request_events (
		id VARCHAR(64) PRIMARY KEY,
		site_id VARCHAR(64) NOT NULL,
		ip VARCHAR(128) NOT NULL,
		method VARCHAR(16) NOT NULL,
		path TEXT NOT NULL,
		status INTEGER NOT NULL,
		decision VARCHAR(64) NOT NULL,
		latency_ms INTEGER NOT NULL,
		country_code VARCHAR(2) NULL,
		created_at BIGINT NOT NULL
	)`;

	const results: BenchResult[] = [];

	results.push(
		await measureRate(SUITE, "insert request_events row", "ops/sec", async () => {
			await db`INSERT INTO request_events (id,site_id,ip,method,path,status,decision,latency_ms,country_code,created_at)
				VALUES (${randomId()},${"site-bench"},${"203.0.113.1"},${"GET"},${"/bench"},${200},${"allow"},${12},${"US"},${Date.now()})`;
			return 1;
		}),
	);

	await seed(db, 20_000);

	results.push(
		await measureLatency(SUITE, "select recent 100 rows for a site", async () => {
			await db`SELECT * FROM request_events WHERE site_id=${"site-bench"} ORDER BY created_at DESC LIMIT 100`;
		}),
	);

	results.push(
		await measureLatency(SUITE, "count+group by decision", async () => {
			await db`SELECT decision, COUNT(*) AS count FROM request_events WHERE site_id=${"site-bench"} GROUP BY decision`;
		}),
	);

	await db.close();
	await rm(DIR, { recursive: true, force: true });
	return results;
}

if (import.meta.main) {
	const results = await run();
	if (process.env.BENCH_JSON_STDOUT) {
		console.log(JSON.stringify(results));
	} else {
		printResults(results);
		console.log(await saveSuiteRun(results, `${import.meta.dir}/results`, "09-sqlite"));
	}
}
