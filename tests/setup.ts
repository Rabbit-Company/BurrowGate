process.env.DATABASE_URL = ":memory:";
process.env.BG_MASTER_KEY ??= "test-suite-master-key-at-least-32-characters-long";

const { migrate } = await import("../src/db/migrate.ts");
await migrate();
