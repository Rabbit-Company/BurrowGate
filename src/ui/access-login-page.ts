import type { SiteRecord } from "../types.ts";
import { escapeHtml, page } from "./layout.ts";

export function accessLoginPage(site: SiteRecord, returnPath: string, error = ""): string {
	return page(
		"Sign in",
		`<main class="shell challenge"><section class="card pad auth-card"><div class="brand"><span class="mark"></span> BurrowGate</div><h1 class="auth-title">Sign in to ${escapeHtml(site.name)}</h1><p class="muted">Your identity is verified by BurrowGate before the request reaches the protected application.</p>${error ? `<p class="badge bad auth-error">${escapeHtml(error)}</p>` : ""}<form method="post" action="/_burrowgate/access/login" class="grid"><input type="hidden" name="return" value="${escapeHtml(returnPath)}"><label>Username<input class="input" name="username" autocomplete="username" maxlength="255" required autofocus></label><label>Password<input class="input" type="password" name="password" autocomplete="current-password" maxlength="1024" required></label><button class="button" type="submit">Sign in</button></form></section></main>`,
	);
}

export function accessTotpEnrollPage(site: SiteRecord, uri: string, secret: string, qrSvgMarkup: string, returnPath: string, error = ""): string {
	return page(
		"Two-factor setup",
		`<main class="shell challenge"><section class="card pad auth-card"><div class="brand"><span class="mark"></span> BurrowGate</div><h1 class="auth-title">Set up two-factor authentication</h1><p class="muted">${escapeHtml(site.name)} requires a second factor for this account. Scan this code with an authenticator app, or enter the secret manually.</p>${error ? `<p class="badge bad auth-error">${escapeHtml(error)}</p>` : ""}<div class="totp-qr">${qrSvgMarkup}</div><p class="muted totp-secret">Secret: <code>${escapeHtml(secret)}</code></p><form method="post" action="/_burrowgate/access/login/enroll" class="grid"><input type="hidden" name="return" value="${escapeHtml(returnPath)}"><label>6-digit code<input class="input" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" autofocus></label><button class="button" type="submit">Verify and continue</button></form></section></main>`,
	);
}

export function accessTotpVerifyPage(site: SiteRecord, returnPath: string, error = ""): string {
	return page(
		"Two-factor verification",
		`<main class="shell challenge"><section class="card pad auth-card"><div class="brand"><span class="mark"></span> BurrowGate</div><h1 class="auth-title">Enter your verification code</h1><p class="muted">Signing in to ${escapeHtml(site.name)}.</p>${error ? `<p class="badge bad auth-error">${escapeHtml(error)}</p>` : ""}<form method="post" action="/_burrowgate/access/login/totp" class="grid"><input type="hidden" name="return" value="${escapeHtml(returnPath)}"><label>6-digit code<input class="input" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" autofocus></label><button class="button" type="submit">Verify</button></form></section></main>`,
	);
}
