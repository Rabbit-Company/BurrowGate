import { SQL } from "bun";
import { mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { config } from "../config.ts";

async function ensureSqliteDirectory(url: string): Promise<void> {
	if (!url.startsWith("sqlite://./") && !url.startsWith("file://./")) return;
	const path = url.replace(/^(sqlite|file):\/\//u, "").split("?")[0];
	if (path) await mkdir(dirname(path), { recursive: true });
}

await ensureSqliteDirectory(config.databaseUrl);
export const db = new SQL(config.databaseUrl);
