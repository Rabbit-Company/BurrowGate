process.env.DATABASE_URL = ":memory:";
process.env.BG_MASTER_KEY ??= "test-suite-master-key-at-least-32-characters-long";

for (const key of Object.keys(process.env)) {
	if (key.startsWith("BG_HA_")) delete process.env[key];
}

const { migrate } = await import("../src/db/migrate.ts");
await migrate();
