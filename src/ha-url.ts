export function isSecureHaUrl(value: string): boolean {
	try {
		const url = new URL(value);
		return url.protocol === "https:" && !!url.hostname && !url.username && !url.password;
	} catch {
		return false;
	}
}

export function requireSecureHaUrl(value: string, label: string): string {
	const trimmed = value.trim();
	if (!isSecureHaUrl(trimmed)) throw new Error(`${label} must be a valid absolute HTTPS URL without embedded credentials`);
	return trimmed.replace(/\/+$/u, "");
}
