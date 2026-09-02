import type { ChallengeProvider } from "../challenges/types.ts";
import type { ChallengeFlowRecord, ChallengeStepRecord, SiteRecord } from "../types.ts";
import { config } from "../config.ts";
import { requestHost } from "../utils/http.ts";

export function challengePageCsp(provider: ChallengeProvider): string {
	const extra = provider.cspSources;
	if (!extra) {
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

function challengeScript(flow: ChallengeFlowRecord, step: ChallengeStepRecord, provider: ChallengeProvider): string {
	// Server-generated markup: never HTML-escaped. The bootstrap JSON is neutralized against
	// "</script>" breakout the same way the previous hard-coded page did.
	const bootstrap = JSON.stringify({
		flowId: flow.id,
		provider: provider.name,
		publicData: JSON.parse(step.public_data_json),
		minimumDisplayMs: config.challengeMinDisplayMs,
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

export function renderChallengePage(
	site: SiteRecord,
	request: Request,
	flow: ChallengeFlowRecord,
	step: ChallengeStepRecord,
	provider: ChallengeProvider,
): string {
	const context = contextFor(site, request, provider);
	const template = site.challenge_html_template || DEFAULT_CHALLENGE_HTML_TEMPLATE;
	let result = template;
	for (const placeholder of CHALLENGE_TEMPLATE_PLACEHOLDERS) {
		if (placeholder.name === "challengeScript") continue;
		result = result.replaceAll(`{{${placeholder.name}}}`, escapeHtml(context[placeholder.name as keyof ChallengeContext]));
	}
	// Injected last, unescaped, so template values can never smuggle markup into the script region.
	return result.replaceAll("{{challengeScript}}", challengeScript(flow, step, provider));
}
