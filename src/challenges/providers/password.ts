import type { ChallengeProvider } from "../types.ts";

const ARGON2ID_PREFIX = /^\$argon2id\$/;

const DEFAULT_TEMPLATE = `<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<meta name="theme-color" content="#111827">
	<title>{{title}} - {{siteName}}</title>
	<link rel="icon" type="image/svg+xml" href="/_burrowgate/static/favicon.svg">
	<link rel="stylesheet" href="/_burrowgate/static/burrowgate.css">
</head>
<body>
	<main class="shell challenge">
		<section class="card pad auth-card">
			<div class="brand"><span class="mark"></span> BurrowGate</div>
			<h1 class="auth-title">{{title}}</h1>
			<p id="status" class="muted">Starting challenge...</p>
			<form class="grid" data-bg-password="form" autocomplete="off">
				<label>Password<input class="input" data-bg-password="input" type="password" name="password" autocomplete="off" placeholder="Password"></label>
				<button class="button" data-bg-password="submit" type="submit">Continue</button>
			</form>
			<noscript><p class="muted">JavaScript is required to complete this challenge. Enable it and reload to continue.</p></noscript>
		</section>
	</main>
	{{challengeScript}}
</body>
</html>`;

function password(config: Record<string, unknown>): string {
	const value = config.password;
	if (typeof value !== "string" || !value.trim() || value.length > 256) throw new Error("A password is required");
	return value;
}

export const passwordProvider: ChallengeProvider = {
	name: "password",
	clientScript: "/_burrowgate/static/challenges/password.js",
	title: "Enter the password",
	description: "This website asks visitors to enter a password before continuing.",
	defaultHtmlTemplate: DEFAULT_TEMPLATE,
	defaultTexts: [
		{ key: "inputPlaceholder", label: "Password field placeholder", default: "Password" },
		{ key: "submitLabel", label: "Submit button label", default: "Continue" },
		{ key: "statusReady", label: "Initial status message", default: "Enter the password to continue." },
		{ key: "incorrectPassword", label: "Wrong-password message", default: "Incorrect password" },
	],

	validateConfig(config) {
		password(config);
	},

	async normalizeConfigForStorage(config) {
		const value = password(config);
		if (ARGON2ID_PREFIX.test(value)) return config;
		return { ...config, password: await Bun.password.hash(value, { algorithm: "argon2id" }) };
	},

	async create(_context, config) {
		return { publicData: { kind: "password" }, privateData: { passwordHash: password(config) } };
	},

	async verify(_context, _config, privateData, answer) {
		const submitted = answer && typeof answer === "object" ? String((answer as Record<string, unknown>).password ?? "") : "";
		if (!submitted) return { success: false, reason: "incorrectPassword" };
		const hash = String(privateData.passwordHash ?? "");
		if (!hash) return { success: false, reason: "incorrectPassword" };
		const ok = await Bun.password.verify(submitted, hash);
		return ok ? { success: true, metadata: { provider: "password" } } : { success: false, reason: "incorrectPassword" };
	},
};
