import { config } from "../config.ts";
import { sha256Bytes, toBase64Url } from "../utils/crypto.ts";

let keyPromise: Promise<CryptoKey> | null = null;

function fromBase64Url(value: string): Uint8Array {
	const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
	const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
	const binary = atob(padded);
	return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function masterSecret(): Promise<string> {
	const inline = config.masterKey;
	if (inline) return inline;
	if (config.masterKeyFile) {
		const value = (await Bun.file(config.masterKeyFile).text()).trim();
		if (value) return value;
	}
	throw new Error("TLS private-key storage requires BG_MASTER_KEY or BG_MASTER_KEY_FILE");
}

async function encryptionKey(): Promise<CryptoKey> {
	keyPromise ??= (async () => {
		const secret = await masterSecret();
		if (secret.length < 32) throw new Error("BG_MASTER_KEY must contain at least 32 characters");
		return await crypto.subtle.importKey("raw", await sha256Bytes(secret), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
	})();
	return await keyPromise;
}

export async function encryptSecret(value: string): Promise<string> {
	const nonce = crypto.getRandomValues(new Uint8Array(12));
	const plaintext = new TextEncoder().encode(value);
	const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, await encryptionKey(), plaintext));
	return `v1.${toBase64Url(nonce)}.${toBase64Url(ciphertext)}`;
}

export async function decryptSecret(value: string): Promise<string> {
	const [version, nonceValue, ciphertextValue] = value.split(".");
	if (version !== "v1" || !nonceValue || !ciphertextValue) throw new Error("Unsupported encrypted secret format");
	const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromBase64Url(nonceValue) }, await encryptionKey(), fromBase64Url(ciphertextValue));
	return new TextDecoder().decode(plaintext);
}

export async function assertSecretEncryptionConfigured(): Promise<void> {
	await encryptionKey();
}
