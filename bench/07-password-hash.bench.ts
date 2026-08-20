/**
 * Bun.password with argon2id, exactly as used by
 * src/services/admin-auth-service.ts and admin-user-service.ts for admin
 * login and credential storage. Argon2id cost dominates login latency, so a
 * runtime regression here directly slows down every admin/access login.
 */
import { measureLatency, printResults, saveSuiteRun, type BenchResult } from "./lib/harness.ts";

const SUITE = "password-hash";
const PASSWORD = "correct horse battery staple";

export async function run(): Promise<BenchResult[]> {
	const results: BenchResult[] = [];

	results.push(
		await measureLatency(SUITE, "argon2id hash", async () => {
			await Bun.password.hash(PASSWORD, { algorithm: "argon2id" });
		}),
	);

	const hash = await Bun.password.hash(PASSWORD, { algorithm: "argon2id" });
	results.push(
		await measureLatency(SUITE, "argon2id verify", async () => {
			await Bun.password.verify(PASSWORD, hash);
		}),
	);

	return results;
}

if (import.meta.main) {
	const results = await run();
	if (process.env.BENCH_JSON_STDOUT) {
		console.log(JSON.stringify(results));
	} else {
		printResults(results);
		console.log(await saveSuiteRun(results, `${import.meta.dir}/results`, "07-password-hash"));
	}
}
