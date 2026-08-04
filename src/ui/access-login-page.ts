import type { SiteRecord } from "../types.ts";
import { escapeHtml, page } from "./layout.ts";

export function accessLoginPage(site: SiteRecord, returnPath: string, error = ""): string {
	return page(
		"Sign in",
		`<main class="shell challenge"><section class="card pad auth-card"><div class="brand"><span class="mark"></span> BurrowGate</div><h1 class="auth-title">Sign in to ${escapeHtml(site.name)}</h1><p class="muted">Your identity is verified by BurrowGate before the request reaches the protected application.</p>${error ? `<p class="badge bad auth-error">${escapeHtml(error)}</p>` : ""}<form method="post" action="/_burrowgate/access/login" class="grid"><input type="hidden" name="return" value="${escapeHtml(returnPath)}"><label>Username<input class="input" name="username" autocomplete="username" maxlength="255" required autofocus></label><label>Password<input class="input" type="password" name="password" autocomplete="current-password" maxlength="1024" required></label><button class="button" type="submit">Sign in</button></form></section></main>`,
	);
}
