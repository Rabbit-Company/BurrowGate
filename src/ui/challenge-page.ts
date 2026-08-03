import type { ChallengeProvider } from "../challenges/types.ts";
import type { ChallengeFlowRecord, ChallengeStepRecord } from "../types.ts";
import { config } from "../config.ts";
import { escapeHtml } from "./layout.ts";

export function challengePage(flow: ChallengeFlowRecord, step: ChallengeStepRecord, provider: ChallengeProvider): string {
	const bootstrap = JSON.stringify({
		flowId: flow.id,
		provider: provider.name,
		publicData: JSON.parse(step.public_data_json),
		minimumDisplayMs: config.challengeMinDisplayMs,
	}).replaceAll("<", "\\u003c");
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#111827"><title>Verification | BurrowGate</title><link rel="icon" type="image/svg+xml" href="/_burrowgate/static/favicon.svg"><link rel="stylesheet" href="/_burrowgate/static/burrowgate.css"></head><body><main class="shell challenge"><section class="card pad auth-card"><div class="brand"><span class="mark">BG</span> BurrowGate</div><p class="muted challenge-description">${escapeHtml(provider.description)}</p><h1 class="challenge-title">${escapeHtml(provider.title)}</h1><p id="status" class="muted">Starting challenge...</p><div class="progress"><div></div></div><p class="muted challenge-footnote"><span id="attempts">0</span> work units attempted. You will be redirected automatically.</p><noscript>JavaScript is required to complete this challenge.</noscript></section></main><script>window.__BURROWGATE_CHALLENGE__=${bootstrap};</script><script src="${escapeHtml(provider.clientScript)}"></script></body></html>`;
}
