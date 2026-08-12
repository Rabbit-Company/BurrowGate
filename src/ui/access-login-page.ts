import type { SiteRecord } from "../types.ts";
import { authErrorToast, escapeHtml, page } from "./layout.ts";

export function accessLoginPage(
	site: SiteRecord,
	returnPath: string,
	error = "",
	sso?: { enabled: boolean; enforceSso: boolean; buttonLabel: string },
): string {
	const passwordForm = `<form method="post" action="/_burrowgate/access/login" class="grid"><input type="hidden" name="return" value="${escapeHtml(returnPath)}"><label>Username<input class="input" name="username" autocomplete="username" maxlength="255" required autofocus></label><label>Password<input class="input" type="password" name="password" autocomplete="current-password" maxlength="1024" required></label><button class="button" type="submit">Sign in</button></form>`;
	const ssoButton = sso?.enabled
		? `<a class="button" href="/_burrowgate/access/login/sso?return=${encodeURIComponent(returnPath)}">${escapeHtml(sso.buttonLabel)}</a>`
		: "";
	const body =
		sso?.enabled && sso.enforceSso
			? `${ssoButton}<details class="totp-recovery"><summary>Use a local account instead</summary>${passwordForm}</details>`
			: sso?.enabled
				? `${ssoButton}<div class="auth-divider"><span>or</span></div>${passwordForm}`
				: passwordForm;
	return page(
		"Sign in",
		`<main class="shell challenge"><section class="card pad auth-card"><div class="brand"><span class="mark"></span> BurrowGate</div><h1 class="auth-title">Sign in to ${escapeHtml(site.name)}</h1><p class="muted">Your identity is verified by BurrowGate before the request reaches the protected application.</p>${authErrorToast(error)}${body}</section></main>`,
	);
}

export function accessTwoFactorEnrollPage(site: SiteRecord, uri: string, secret: string, qrSvgMarkup: string, returnPath: string, error = ""): string {
	const webauthnSection = `<div id="webauthnStatus" class="muted" hidden></div><button class="button" type="button" id="webauthnRegisterButton">Register a security key</button><div class="auth-divider"><span>or use an authenticator app</span></div>`;
	const totpSection = `<p class="muted">${escapeHtml(site.name)} requires a second factor for this account. Scan this code with an authenticator app, or enter the secret manually.</p><div class="totp-qr">${qrSvgMarkup}</div><p class="muted totp-secret">Secret: <code>${escapeHtml(secret)}</code></p><form method="post" action="/_burrowgate/access/login/enroll" class="grid"><input type="hidden" name="return" value="${escapeHtml(returnPath)}"><label>6-digit code<input class="input" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" autofocus></label><button class="button" type="submit">Verify and continue</button></form><p class="muted totp-url"><a href="${escapeHtml(uri)}">Open in authenticator app</a></p>`;
	const script = `<script type="module">
import { isWebauthnSupported, registerCredential } from "/_burrowgate/static/webauthn-client.js";
const button = document.getElementById("webauthnRegisterButton");
const status = document.getElementById("webauthnStatus");
const returnPath = document.getElementById("authCard").dataset.return;
if (!isWebauthnSupported()) button.disabled = true;
button?.addEventListener("click", async () => {
	button.disabled = true;
	status.hidden = false;
	status.textContent = "Waiting for your security key...";
	try {
		const optionsResponse = await fetch("/_burrowgate/api/access/login/webauthn/register/options", { method: "POST" });
		if (!optionsResponse.ok) throw new Error("Could not start registration");
		const options = await optionsResponse.json();
		const credential = await registerCredential(options);
		const verifyResponse = await fetch("/_burrowgate/api/access/login/webauthn/register/verify", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ response: credential }),
		});
		const result = await verifyResponse.json();
		if (!verifyResponse.ok) throw new Error(result.error || "Registration failed");
		window.location.href = returnPath;
	} catch (error) {
		status.textContent = error instanceof Error ? error.message : "Registration failed";
		button.disabled = false;
	}
});
</script>`;
	return page(
		"Two-factor setup",
		`<main class="shell challenge"><section class="card pad auth-card" id="authCard" data-return="${escapeHtml(returnPath)}"><div class="brand"><span class="mark"></span> BurrowGate</div><h1 class="auth-title">Set up two-factor authentication</h1>${authErrorToast(error)}${webauthnSection}${totpSection}</section>${script}</main>`,
	);
}

export function accessTwoFactorVerifyPage(site: SiteRecord, returnPath: string, methods: { hasWebauthn: boolean; hasTotp: boolean }, error = ""): string {
	const webauthnSection = methods.hasWebauthn
		? `<div id="webauthnStatus" class="muted" hidden></div><button class="button" type="button" id="webauthnAuthenticateButton">Use your security key</button>${methods.hasTotp ? `<div class="auth-divider"><span>or</span></div>` : ""}`
		: "";
	const totpSection = methods.hasTotp
		? `<form method="post" action="/_burrowgate/access/login/verify" class="grid"><input type="hidden" name="return" value="${escapeHtml(returnPath)}"><label>6-digit code<input class="input" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" autofocus></label><button class="button" type="submit">Verify</button></form>`
		: "";
	const script = methods.hasWebauthn
		? `<script type="module">
import { isWebauthnSupported, authenticateWithCredential } from "/_burrowgate/static/webauthn-client.js";
const button = document.getElementById("webauthnAuthenticateButton");
const status = document.getElementById("webauthnStatus");
const returnPath = document.getElementById("authCard").dataset.return;
if (!isWebauthnSupported()) button.disabled = true;
button?.addEventListener("click", async () => {
	button.disabled = true;
	status.hidden = false;
	status.textContent = "Waiting for your security key...";
	try {
		const optionsResponse = await fetch("/_burrowgate/api/access/login/webauthn/authenticate/options", { method: "POST" });
		if (!optionsResponse.ok) throw new Error("Could not start verification");
		const options = await optionsResponse.json();
		const credential = await authenticateWithCredential(options);
		const verifyResponse = await fetch("/_burrowgate/api/access/login/webauthn/authenticate/verify", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ response: credential }),
		});
		const result = await verifyResponse.json();
		if (!verifyResponse.ok) throw new Error(result.error || "Verification failed");
		window.location.href = returnPath;
	} catch (error) {
		status.textContent = error instanceof Error ? error.message : "Verification failed";
		button.disabled = false;
	}
});
</script>`
		: "";
	return page(
		"Two-factor verification",
		`<main class="shell challenge"><section class="card pad auth-card" id="authCard" data-return="${escapeHtml(returnPath)}"><div class="brand"><span class="mark"></span> BurrowGate</div><h1 class="auth-title">Enter your verification code</h1><p class="muted">Signing in to ${escapeHtml(site.name)}.</p>${authErrorToast(error)}${webauthnSection}${totpSection}</section>${script}</main>`,
	);
}
