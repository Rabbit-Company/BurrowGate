function environment(name: string, fallback?: string): string {
	const value = process.env[name]?.trim() || fallback;
	if (!value) throw new Error(`${name} is required; copy example.env to .env and replace its placeholders`);
	return value;
}

function port(name: string, fallback: number): number {
	const value = Number(process.env[name] ?? fallback);
	if (!Number.isInteger(value) || value < 1 || value > 65_535) throw new Error(`${name} must be a valid TCP port`);
	return value;
}

function url(name: string, fallback?: string): string {
	const value = environment(name, fallback);
	const parsed = new URL(value);
	if (!["http:", "https:"].includes(parsed.protocol)) throw new Error(`${name} must use HTTP or HTTPS`);
	return parsed.origin;
}

function originList(value: string | undefined): string[] {
	if (!value?.trim()) return [];
	return value
		.split(",")
		.map((entry) => entry.trim())
		.filter(Boolean)
		.map((entry) => {
			const parsed = new URL(entry);
			if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("DEMO_ALLOWED_FRONTEND_ORIGINS entries must use HTTP or HTTPS");
			return parsed.origin;
		});
}

const frontendPort = port("DEMO_FRONTEND_PORT", 3100);
const backendPort = port("DEMO_BACKEND_PORT", 3200);
const frontendPublicOrigin = url("DEMO_FRONTEND_PUBLIC_ORIGIN", "https://app.example.test");

export const demoConfig = {
	frontendPort,
	backendPort,
	frontendPublicOrigin,
	backendPublicOrigin: url("DEMO_BACKEND_PUBLIC_ORIGIN", "https://api.example.test"),
	allowedFrontendOrigins: [
		...new Set([
			frontendPublicOrigin,
			`http://localhost:${frontendPort}`,
			`http://127.0.0.1:${frontendPort}`,
			...originList(process.env.DEMO_ALLOWED_FRONTEND_ORIGINS),
		]),
	],
	burrowGateUrl: url("BURROWGATE_URL"),
	frontendSiteId: environment("BURROWGATE_FRONTEND_SITE_ID"),
	verificationToken: environment("BURROWGATE_SESSION_VERIFICATION_TOKEN"),
	cacheTtlMs: Number(process.env.BURROWGATE_AUTH_CACHE_TTL_MS ?? 5_000),
};

if (!Number.isFinite(demoConfig.cacheTtlMs) || demoConfig.cacheTtlMs < 0) {
	throw new Error("BURROWGATE_AUTH_CACHE_TTL_MS must be zero or a positive number");
}
