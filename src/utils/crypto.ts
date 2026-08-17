const encoder = new TextEncoder();

export function randomToken(bytes = 32): string {
	const data = crypto.getRandomValues(new Uint8Array(bytes));
	return toBase64Url(data);
}

export function randomId(prefix = "bg"): string {
	return `${prefix}_${crypto.randomUUID().replaceAll("-", "")}`;
}

export async function sha256Bytes(value: string | Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
	const input = typeof value === "string" ? encoder.encode(value) : value;
	return new Uint8Array(await crypto.subtle.digest("SHA-256", input));
}

export async function sha256Hex(value: string | Uint8Array<ArrayBuffer>): Promise<string> {
	return toHex(await sha256Bytes(value));
}

/** SHA-1 is mandated by OVH's legacy API request-signing protocol (not a security choice we are making). */
export async function sha1Hex(value: string): Promise<string> {
	return toHex(new Uint8Array(await crypto.subtle.digest("SHA-1", encoder.encode(value))));
}

export async function hmacSha256Hex(secret: string, value: string): Promise<string> {
	const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
	const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(value));
	return toHex(new Uint8Array(signature));
}

export function toHex(bytes: Uint8Array): string {
	let value = "";
	for (const byte of bytes) value += byte.toString(16).padStart(2, "0");
	return value;
}

export function toBase64Url(bytes: Uint8Array): string {
	let binary = "";
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export function fromBase64Url(value: string): Uint8Array<ArrayBuffer> {
	const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
	const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
	const binary = atob(padded);
	return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export async function timingSafeEqualText(left: string, right: string): Promise<boolean> {
	const leftDigest = await sha256Bytes(left);
	const rightDigest = await sha256Bytes(right);

	return crypto.timingSafeEqual(leftDigest, rightDigest);
}

export function countLeadingZeroBits(bytes: Uint8Array): number {
	let total = 0;
	for (const byte of bytes) {
		if (byte === 0) {
			total += 8;
			continue;
		}
		total += Math.clz32(byte) - 24;
		break;
	}
	return total;
}
