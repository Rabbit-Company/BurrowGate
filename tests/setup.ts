process.env.DATABASE_URL = ":memory:";

const { migrate } = await import("../src/db/migrate.ts");
await migrate();
