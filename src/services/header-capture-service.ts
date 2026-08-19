const DEFAULT_REDACTED_HEADERS = new Set(["authorization", "cookie", "set-cookie"]);
const REDACTED_PLACEHOLDER = "[redacted]";
const CAPTURE_BYTE_CEILING = 8_192;

export interface CapturedHeaders {
	json: string;
	truncated: boolean;
}

export const REDACTED_HEADER_PLACEHOLDER = REDACTED_PLACEHOLDER;

export function parseCapturedHeaders(json: string | null | undefined): [string, string][] {
	if (!json) return [];
	try {
		const parsed = JSON.parse(json) as unknown;
		if (!Array.isArray(parsed)) return [];
		return parsed.filter(
			(entry): entry is [string, string] => Array.isArray(entry) && entry.length === 2 && typeof entry[0] === "string" && typeof entry[1] === "string",
		);
	} catch {
		return [];
	}
}

export function captureHeaders(headers: Headers, policy: { redactAuthHeaders: boolean; redactedHeaders: readonly string[] }): CapturedHeaders | null {
	const redacted = new Set(policy.redactedHeaders.map((name) => name.toLowerCase()));
	const entries: [string, string][] = [];
	for (const [name, value] of headers) {
		const lower = name.toLowerCase();
		const strip = (policy.redactAuthHeaders && DEFAULT_REDACTED_HEADERS.has(lower)) || redacted.has(lower);
		entries.push([name, strip ? REDACTED_PLACEHOLDER : value]);
	}
	if (entries.length === 0) return null;

	let json = JSON.stringify(entries);
	let truncated = false;
	if (new TextEncoder().encode(json).byteLength > CAPTURE_BYTE_CEILING) {
		truncated = true;
		while (entries.length > 0 && new TextEncoder().encode(JSON.stringify(entries)).byteLength > CAPTURE_BYTE_CEILING) entries.pop();
		json = JSON.stringify(entries);
	}
	return { json, truncated };
}
