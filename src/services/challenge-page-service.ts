import type { ChallengeProvider, ChallengeProviderCspSources } from "../challenges/types.ts";
import type { ChallengeFlowRecord, ChallengeStepRecord, SiteRecord } from "../types.ts";
import { config } from "../config.ts";
import { requestHost } from "../utils/http.ts";

export const CSP_SOURCE_FIELDS = ["scriptSrc", "frameSrc", "connectSrc", "styleSrc", "imgSrc"] as const;

// A single CSP source-expression token: a keyword, data:/blob:, a bare scheme, or scheme://host[:port]
// (host optionally a "*." wildcard subdomain). Rejects a bare "*" and anything containing ";"/","/
// whitespace, since these values are joined directly into a Content-Security-Policy header value.
const CSP_SOURCE_PATTERN = /^(?:'self'|'none'|'unsafe-inline'|'unsafe-eval'|data:|blob:|[a-z][a-z0-9+.-]*:(?:\/\/(?:\*\.)?[a-z0-9.-]+(?::\d+)?\/?)?)$/iu;

/** Parses a space/newline-separated list of extra CSP source expressions, validating each token. Throws on an invalid token. */
export function parseCspSourceList(value: string): string[] {
	const tokens = value.split(/\s+/u).filter(Boolean);
	for (const token of tokens) {
		if (!CSP_SOURCE_PATTERN.test(token)) throw new Error(`Invalid CSP source "${token}"`);
	}
	return tokens;
}

/** Parses `sites.challenge_csp_overrides_json` - only well-formed { provider: { field: string[] } } entries survive; malformed data is silently dropped rather than thrown, since stored data is trusted (validated at write time via parseCspSourceList) but must never crash a read. */
export function parseStoredChallengeCsp(json: string | null | undefined): Record<string, ChallengeProviderCspSources> {
	if (!json) return {};
	try {
		const parsed: unknown = JSON.parse(json);
		if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
		const result: Record<string, ChallengeProviderCspSources> = {};
		for (const [provider, entry] of Object.entries(parsed as Record<string, unknown>)) {
			if (!entry || typeof entry !== "object" || Array.isArray(entry)) continue;
			const fields: ChallengeProviderCspSources = {};
			for (const field of CSP_SOURCE_FIELDS) {
				const value = (entry as Record<string, unknown>)[field];
				if (Array.isArray(value) && value.every((item) => typeof item === "string")) {
					const list = value.filter(Boolean);
					if (list.length > 0) fields[field] = list;
				}
			}
			if (Object.keys(fields).length > 0) result[provider] = fields;
		}
		return result;
	} catch {
		return {};
	}
}

/** Merges a provider's own built-in CSP widening with the site's per-provider extra sources, field by field (union, no dedup needed - a repeated source is harmless in a CSP header). */
export function resolveProviderCspSources(site: SiteRecord, provider: ChallengeProvider): ChallengeProviderCspSources {
	const overrides = parseStoredChallengeCsp(site.challenge_csp_overrides_json)[provider.name];
	if (!overrides) return provider.cspSources ?? {};
	const merged: ChallengeProviderCspSources = { ...provider.cspSources };
	for (const field of CSP_SOURCE_FIELDS) {
		const extra = overrides[field];
		if (!extra?.length) continue;
		merged[field] = [...(merged[field] ?? []), ...extra];
	}
	return merged;
}

export function challengePageCsp(site: SiteRecord, provider: ChallengeProvider): string {
	const extra = resolveProviderCspSources(site, provider);
	const hasAny = CSP_SOURCE_FIELDS.some((field) => extra[field]?.length);
	if (!hasAny) {
		return "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
	}
	const directives = [
		"default-src 'self'",
		`style-src 'self' 'unsafe-inline'${extra.styleSrc?.length ? ` ${extra.styleSrc.join(" ")}` : ""}`,
		`script-src 'self' 'unsafe-inline'${extra.scriptSrc?.length ? ` ${extra.scriptSrc.join(" ")}` : ""}`,
		`img-src 'self' data:${extra.imgSrc?.length ? ` ${extra.imgSrc.join(" ")}` : ""}`,
		`connect-src 'self'${extra.connectSrc?.length ? ` ${extra.connectSrc.join(" ")}` : ""}`,
	];
	if (extra.frameSrc?.length) directives.push(`frame-src 'self' ${extra.frameSrc.join(" ")}`);
	directives.push("frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'");
	return directives.join("; ");
}

export const CHALLENGE_TEMPLATE_PLACEHOLDERS = [
	{ name: "title", description: 'Challenge provider title (e.g. "Verifying your browser").' },
	{ name: "description", description: "Challenge provider description shown above the title." },
	{ name: "siteName", description: "Configured site name." },
	{ name: "host", description: "Public request host." },
	{ name: "homeUrl", description: "Root URL of the protected site." },
	{ name: "provider", description: 'Active challenge provider name (e.g. "pow-sha256").' },
	{
		name: "challengeScript",
		description: "Required. BurrowGate injects the challenge bootstrap and client script here. The page cannot verify without it.",
	},
] as const;

/**
 * Base visitor-facing text strings duplicated across every challenge provider's client script
 * (the "Verifying...", redirect-countdown, and generic-failure lines). A provider overrides any of
 * these by listing the same key in its own `defaultTexts` with a different `default` - same
 * override-by-key-match rule `extraTemplateContext` uses for placeholders. `{{name}}` markers are
 * substituted client-side (not HTML-escaped, since this travels as JSON, not markup).
 */
export const BASE_CHALLENGE_TEXTS: ReadonlyArray<{ key: string; label: string; default: string }> = [
	{ key: "verifying", label: "Verifying status message", default: "Verifying with BurrowGate..." },
	{
		key: "redirectingIn",
		label: "Redirect countdown message (use {{seconds}})",
		default: "Verification successful. Redirecting in {{seconds}} seconds...",
	},
	{ key: "redirecting", label: "Redirect message (no countdown left)", default: "Verification successful. Redirecting..." },
	{ key: "verificationFailed", label: "Generic failure message", default: "Verification failed. Reloading..." },
];

const LOGO_DATA_URI =
	"data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20viewBox%3D%220%200%2064%2064%22%20role%3D%22img%22%20aria-label%3D%22BurrowGate%22%3E%3Cdefs%3E%3ClinearGradient%20id%3D%22bg%22%20x1%3D%2210%22%20y1%3D%228%22%20x2%3D%2254%22%20y2%3D%2256%22%20gradientUnits%3D%22userSpaceOnUse%22%3E%3Cstop%20stop-color%3D%22%238b5cf6%22%2F%3E%3Cstop%20offset%3D%221%22%20stop-color%3D%22%2322d3ee%22%2F%3E%3C%2FlinearGradient%3E%3C%2Fdefs%3E%3Crect%20width%3D%2264%22%20height%3D%2264%22%20rx%3D%2216%22%20fill%3D%22url%28%23bg%29%22%2F%3E%3Cg%20transform%3D%22translate%2814%2014%29%20scale%281.5%29%22%20fill%3D%22none%22%20stroke%3D%22%230b1020%22%20stroke-width%3D%222%22%20stroke-linecap%3D%22round%22%20stroke-linejoin%3D%22round%22%3E%3Cpath%20d%3D%22M5%2021h14a2%202%200%200%200%202%20-2v-7a9%209%200%200%200%20-18%200v7a2%202%200%200%200%202%202%22%2F%3E%3Cpath%20d%3D%22M8%2021v-9a4%204%200%201%201%208%200v9%22%2F%3E%3Cpath%20d%3D%22M3%2017h4%22%2F%3E%3Cpath%20d%3D%22M17%2017h4%22%2F%3E%3C%2Fg%3E%3C%2Fsvg%3E";

export const DEFAULT_CHALLENGE_HTML_TEMPLATE = `<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<meta name="color-scheme" content="dark">
	<meta name="theme-color" content="#111827">
	<title>{{title}} - {{siteName}}</title>
	<link rel="icon" type="image/svg+xml" href="/_burrowgate/static/favicon.svg">
	<style>
		:root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
		* { box-sizing: border-box; }
		body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px; color: #e5e7eb; background: radial-gradient(circle at top, #312e81 0, #111827 42%, #030712 100%); }
		main { width: min(560px, 100%); padding: 36px; border: 1px solid rgba(148, 163, 184, .22); border-radius: 20px; background: rgba(15, 23, 42, .9); box-shadow: 0 24px 80px rgba(0, 0, 0, .4); }
		.brand { display: flex; align-items: center; gap: 12px; margin-bottom: 30px; font-weight: 700; }
		.logo { width: 42px; height: 42px; flex: none; background: url("${LOGO_DATA_URI}") center / contain no-repeat; }
		.eyebrow { margin: 0 0 10px; color: #94a3b8; font-size: 14px; line-height: 1.6; }
		h1 { margin: 0 0 22px; font-size: clamp(24px, 5vw, 34px); }
		.status { margin: 0; color: #cbd5e1; line-height: 1.65; min-height: 1.65em; }
		.progress { position: relative; margin: 26px 0 22px; height: 6px; border-radius: 999px; overflow: hidden; background: rgba(148, 163, 184, .16); }
		.progress::after { content: ""; position: absolute; inset: 0; width: 40%; border-radius: inherit; background: linear-gradient(90deg, #8b5cf6, #22d3ee); animation: slide 1.15s ease-in-out infinite; }
		@keyframes slide { 0% { transform: translateX(-110%); } 100% { transform: translateX(310%); } }
		@media (prefers-reduced-motion: reduce) { .progress::after { animation: none; width: 100%; } }
		.footnote { margin: 0; padding-top: 22px; border-top: 1px solid rgba(148, 163, 184, .18); font-size: 13px; color: #64748b; line-height: 1.6; }
		.footnote strong { color: #a78bfa; font-weight: 600; font-variant-numeric: tabular-nums; font-feature-settings: "tnum" 1; }
		noscript { display: block; margin-top: 20px; padding: 12px 14px; border-radius: 10px; background: rgba(190, 18, 60, .16); color: #fda4af; font-size: 13px; }
		@media (max-width: 520px) {
			body { padding: 0; }
			main { width: 100%; min-height: 100vh; display: flex; flex-direction: column; justify-content: center; border: 0; border-radius: 0; box-shadow: none; padding: 24px 18px; }
		}
	</style>
</head>
<body>
	<main>
		<div class="brand"><span class="logo"></span><span>BurrowGate</span></div>
		<p class="eyebrow">{{description}}</p>
		<h1>{{title}}</h1>
		<p id="status" class="status">Starting challenge...</p>
		<div class="progress" role="progressbar" aria-label="Verification in progress"></div>
		<p class="footnote"><strong id="attempts">0</strong> work units attempted. You will be redirected automatically once verification completes.</p>
		<noscript>JavaScript is required to complete this challenge. Enable it and reload to continue.</noscript>
	</main>
	{{challengeScript}}
</body>
</html>`;

export interface ChallengeTemplateOptions {
	/** CSS width for <main> (before the min(...,100%) wrapper) - e.g. "560px" (default) or wider for a canvas game. */
	mainMaxWidth?: string;
	/** Markup inserted directly after <p id="status">, before the closing </main> - a provider's widget/canvas/form container, optionally carrying documented data-bg-<provider>-* hooks a site owner can restyle or remap. */
	bodyExtra?: string;
	/** Extra CSS rules appended inside the shared <style> block. */
	extraStyle?: string;
	/** Set false to omit the <h1>{{title}}</h1> heading entirely - for a provider whose eyebrow description already says the same thing, and where the vertical space matters more (a canvas game on a short mobile viewport). Default true. */
	showTitle?: boolean;
}

/**
 * Shared shell for a provider's own default template - the same head/brand/eyebrow/status/noscript
 * boilerplate DEFAULT_CHALLENGE_HTML_TEMPLATE has, minus the progress bar and attempts footnote (only
 * pow-sha256 uses those, and it keeps using DEFAULT_CHALLENGE_HTML_TEMPLATE directly via the resolution
 * chain's fallback rather than needing its own copy). A provider supplies its own bodyExtra/mainMaxWidth
 * instead of a client script reaching back into a shared template to add or remove elements at runtime.
 */
export function buildChallengeTemplate(options: ChallengeTemplateOptions = {}): string {
	const mainMaxWidth = options.mainMaxWidth ?? "560px";
	const bodyExtra = options.bodyExtra ?? "";
	const extraStyle = options.extraStyle ?? "";
	const titleMarkup = options.showTitle === false ? "" : "<h1>{{title}}</h1>";
	return `<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<meta name="color-scheme" content="dark">
	<meta name="theme-color" content="#111827">
	<title>{{title}} - {{siteName}}</title>
	<link rel="icon" type="image/svg+xml" href="/_burrowgate/static/favicon.svg">
	<style>
		:root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
		* { box-sizing: border-box; }
		body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px; color: #e5e7eb; background: radial-gradient(circle at top, #312e81 0, #111827 42%, #030712 100%); }
		main { width: min(${mainMaxWidth}, 100%); padding: 36px; border: 1px solid rgba(148, 163, 184, .22); border-radius: 20px; background: rgba(15, 23, 42, .9); box-shadow: 0 24px 80px rgba(0, 0, 0, .4); }
		.brand { display: flex; align-items: center; gap: 12px; margin-bottom: 30px; font-weight: 700; }
		.logo { width: 42px; height: 42px; flex: none; background: url("${LOGO_DATA_URI}") center / contain no-repeat; }
		.eyebrow { margin: 0 0 10px; color: #94a3b8; font-size: 14px; line-height: 1.6; }
		h1 { margin: 0 0 22px; font-size: clamp(24px, 5vw, 34px); }
		.status { margin: 0; color: #cbd5e1; line-height: 1.65; min-height: 1.65em; }
		noscript { display: block; margin-top: 20px; padding: 12px 14px; border-radius: 10px; background: rgba(190, 18, 60, .16); color: #fda4af; font-size: 13px; }
		@media (max-width: 520px) {
			body { padding: 0; }
			main { width: 100%; min-height: 100vh; display: flex; flex-direction: column; justify-content: center; border: 0; border-radius: 0; box-shadow: none; padding: 24px 18px; }
		}
		${extraStyle}
	</style>
</head>
<body>
	<main>
		<div class="brand"><span class="logo"></span><span>BurrowGate</span></div>
		<p class="eyebrow">{{description}}</p>
		${titleMarkup}
		<p id="status" class="status">Starting challenge...</p>
		${bodyExtra}
		<noscript>JavaScript is required to complete this challenge. Enable it and reload to continue.</noscript>
	</main>
	{{challengeScript}}
</body>
</html>`;
}

interface ChallengeContext {
	title: string;
	description: string;
	siteName: string;
	host: string;
	homeUrl: string;
	provider: string;
}

function escapeHtml(value: unknown): string {
	return String(value ?? "")
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;")
		.replaceAll("'", "&#39;");
}

function contextFor(site: SiteRecord, request: Request, provider: ChallengeProvider): ChallengeContext {
	const url = new URL(request.url);
	const host = requestHost(request);
	const protocol = url.protocol === "https:" ? "https:" : "http:";
	return {
		title: provider.title,
		description: provider.description,
		siteName: site.name,
		host,
		homeUrl: `${protocol}//${host}/`,
		provider: provider.name,
	};
}

function challengeScript(flow: ChallengeFlowRecord, provider: ChallengeProvider, publicData: unknown, text: Record<string, string>): string {
	// Server-generated markup: never HTML-escaped. The bootstrap JSON is neutralized against
	// "</script>" breakout the same way the previous hard-coded page did.
	const bootstrap = JSON.stringify({
		flowId: flow.id,
		provider: provider.name,
		publicData,
		minimumDisplayMs: config.challengeMinDisplayMs,
		text,
	}).replaceAll("<", "\\u003c");
	return `<script>window.__BURROWGATE_CHALLENGE__=${bootstrap};</script><script src="${escapeHtml(provider.clientScript)}"></script>`;
}

export function validateChallengeHtmlTemplate(value: unknown, fallback = DEFAULT_CHALLENGE_HTML_TEMPLATE): string {
	if (value === undefined) return fallback;
	const template = String(value);
	if (!template.trim()) throw new Error("Challenge HTML template cannot be empty");
	if (template.length > 131_072) throw new Error("Challenge HTML template must be at most 131072 characters");
	if (!template.includes("{{challengeScript}}")) throw new Error("Challenge HTML template must include the {{challengeScript}} placeholder");
	return template;
}

/** Parses `sites.challenge_html_templates_json` - only non-empty string entries survive, everything else (malformed JSON, wrong shape, blank values) is silently dropped so a resolution never throws over stored template data. */
export function parseStoredChallengeTemplates(json: string | null | undefined): Record<string, string> {
	if (!json) return {};
	try {
		const parsed: unknown = JSON.parse(json);
		if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
		const result: Record<string, string> = {};
		for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
			if (typeof value === "string" && value) result[key] = value;
		}
		return result;
	} catch {
		return {};
	}
}

/** Parses `sites.challenge_text_overrides_json` - one level deeper than templates: only a well-formed { provider: { key: string } } shape survives, everything else is silently dropped. */
export function parseStoredChallengeTexts(json: string | null | undefined): Record<string, Record<string, string>> {
	if (!json) return {};
	try {
		const parsed: unknown = JSON.parse(json);
		if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
		const result: Record<string, Record<string, string>> = {};
		for (const [provider, entry] of Object.entries(parsed as Record<string, unknown>)) {
			if (!entry || typeof entry !== "object" || Array.isArray(entry)) continue;
			const keys: Record<string, string> = {};
			for (const [key, value] of Object.entries(entry as Record<string, unknown>)) {
				if (typeof value === "string" && value) keys[key] = value;
			}
			if (Object.keys(keys).length > 0) result[provider] = keys;
		}
		return result;
	} catch {
		return {};
	}
}

/** Merges BASE_CHALLENGE_TEXTS -> provider.defaultTexts -> the site's stored per-provider text overrides, by key. */
export function resolveProviderTexts(site: SiteRecord, provider: ChallengeProvider): Record<string, string> {
	const merged: Record<string, string> = {};
	for (const text of BASE_CHALLENGE_TEXTS) merged[text.key] = text.default;
	for (const text of provider.defaultTexts ?? []) merged[text.key] = text.default;
	const overrides = parseStoredChallengeTexts(site.challenge_text_overrides_json)[provider.name] ?? {};
	for (const [key, value] of Object.entries(overrides)) merged[key] = value;
	return merged;
}

/**
 * Resolves a provider's verify() reason (a stable key like "sliderChallengeFailed", not display
 * text) through the same merge resolveProviderTexts uses. A reason that isn't a registered text key
 * passes through unchanged - this is how pow-sha256/CAPTCHA providers' diagnostic reason strings
 * (never registered as text keys) stay untranslated English, unaffected by this mechanism.
 */
export function resolveChallengeReasonText(site: SiteRecord, provider: ChallengeProvider, reason: string): string {
	return resolveProviderTexts(site, provider)[reason] ?? reason;
}

/**
 * Most-specific first: an explicit per-provider override, then the site's own legacy general
 * template (but only if it was actually edited - createSite persists the literal
 * DEFAULT_CHALLENGE_HTML_TEMPLATE text for a site that never touched the field, so an untouched
 * site must fall through to the provider's own default rather than getting stuck on that copy),
 * then the provider's own default, then the generic default for a provider that doesn't have one.
 */
function resolveChallengeTemplate(site: SiteRecord, provider: ChallengeProvider): string {
	const overrides = parseStoredChallengeTemplates(site.challenge_html_templates_json);
	const perProviderOverride = overrides[provider.name];
	if (perProviderOverride) return perProviderOverride;
	if (site.challenge_html_template && site.challenge_html_template !== DEFAULT_CHALLENGE_HTML_TEMPLATE) {
		return site.challenge_html_template;
	}
	return provider.defaultHtmlTemplate ?? DEFAULT_CHALLENGE_HTML_TEMPLATE;
}

export function renderChallengePage(
	site: SiteRecord,
	request: Request,
	flow: ChallengeFlowRecord,
	step: ChallengeStepRecord,
	provider: ChallengeProvider,
): string {
	const context = contextFor(site, request, provider);
	const publicData = JSON.parse(step.public_data_json) as Record<string, unknown>;
	const extraContext = provider.extraTemplateContext?.(publicData) ?? {};
	const template = resolveChallengeTemplate(site, provider);
	let result = template;
	for (const placeholder of CHALLENGE_TEMPLATE_PLACEHOLDERS) {
		if (placeholder.name === "challengeScript") continue;
		result = result.replaceAll(`{{${placeholder.name}}}`, escapeHtml(context[placeholder.name as keyof ChallengeContext]));
	}
	for (const [name, value] of Object.entries(extraContext)) {
		result = result.replaceAll(`{{${name}}}`, escapeHtml(value));
	}
	// Injected last, unescaped, so template values can never smuggle markup into the script region.
	return result.replaceAll("{{challengeScript}}", challengeScript(flow, provider, publicData, resolveProviderTexts(site, provider)));
}
