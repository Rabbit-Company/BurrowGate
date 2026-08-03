import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { config } from "../config.ts";
import { randomToken } from "../utils/crypto.ts";

async function readNonEmpty(path: string): Promise<string | null> {
	try {
		const value = (await readFile(path, "utf8")).trim();
		return value || null;
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
		throw error;
	}
}

async function writePrivateFile(path: string, value: string): Promise<void> {
	await writeFile(path, `${value}\n`, { encoding: "utf8", mode: 0o600 });
	await chmod(path, 0o600);
}

export async function initializeRuntimeSecrets(): Promise<void> {
	await mkdir(config.dataDirectory, { recursive: true, mode: 0o700 });

	if (!config.masterKey && !config.masterKeyFile) {
		const path = join(config.dataDirectory, "master.key");
		let value = await readNonEmpty(path);
		if (!value) {
			value = randomToken(48);
			await writePrivateFile(path, value);
			console.log(`[BurrowGate] Generated persistent master key at ${path}`);
		}
		config.masterKeyFile = path;
	}

	if (!config.admin.password) {
		const path = join(config.dataDirectory, "bootstrap-admin-password.txt");
		let password = await readNonEmpty(path);
		const generated = !password;
		if (!password) {
			password = randomToken(24);
			await writePrivateFile(path, password);
		}
		config.admin.password = password;
		if (generated) {
			console.log("[BurrowGate] Generated bootstrap dashboard credentials:");
			console.log(`[BurrowGate]   Username: ${config.admin.username}`);
			console.log(`[BurrowGate]   Password: ${password}`);
			console.log(`[BurrowGate] Credentials were saved to ${path}; protect or remove this file after setting BG_ADMIN_PASSWORD.`);
		} else {
			console.log(`[BurrowGate] Using bootstrap dashboard password stored at ${path}`);
		}
	}
}
