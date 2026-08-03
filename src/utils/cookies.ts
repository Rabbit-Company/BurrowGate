export interface CookieOptions {
	httpOnly?: boolean;
	secure?: boolean;
	sameSite?: "Strict" | "Lax" | "None";
	path?: string;
	maxAge?: number;
}

export function parseCookies(header: string | null): Map<string, string> {
	const cookies = new Map<string, string>();
	if (!header) return cookies;

	for (const part of header.split(";")) {
		const separator = part.indexOf("=");
		if (separator <= 0) continue;
		const name = part.slice(0, separator).trim();
		const value = part.slice(separator + 1).trim();
		try {
			cookies.set(name, decodeURIComponent(value));
		} catch {
			cookies.set(name, value);
		}
	}
	return cookies;
}

export function serializeCookie(name: string, value: string, options: CookieOptions = {}): string {
	const parts = [`${name}=${encodeURIComponent(value)}`];
	parts.push(`Path=${options.path ?? "/"}`);
	if (options.maxAge !== undefined) parts.push(`Max-Age=${Math.max(0, Math.floor(options.maxAge))}`);
	if (options.httpOnly ?? true) parts.push("HttpOnly");
	if (options.secure) parts.push("Secure");
	parts.push(`SameSite=${options.sameSite ?? "Lax"}`);
	return parts.join("; ");
}

export function removeCookieFromHeader(header: string | null, name: string): string | null {
	if (!header) return null;
	const kept = header
		.split(";")
		.map((part) => part.trim())
		.filter((part) => !part.startsWith(`${name}=`));
	return kept.length > 0 ? kept.join("; ") : null;
}
