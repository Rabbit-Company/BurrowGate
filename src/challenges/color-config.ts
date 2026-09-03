const HEX_COLOR_PATTERN = /^#[0-9a-fA-F]{6}$/;

/** Validates an optional 6-digit hex color config field (matches what <input type="color"> submits). */
export function hexColorConfig(config: Record<string, unknown>, key: string, fallback: string): string {
	const value = config[key];
	if (value === undefined) return fallback;
	if (typeof value !== "string" || !HEX_COLOR_PATTERN.test(value)) {
		throw new Error(`${key} must be a 6-digit hex color (e.g. #7c3aed)`);
	}
	return value;
}
