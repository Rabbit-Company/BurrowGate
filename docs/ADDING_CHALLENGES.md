# Adding a challenge provider

A provider has two pieces:

1. A server implementation registered in `src/challenges/index.ts`.
2. A browser client script served from `/_burrowgate/static/challenges/...`.

## Server contract

```ts
import type { ChallengeProvider } from "../types.ts";

export const captchaExampleProvider: ChallengeProvider = {
	name: "captcha-example",
	clientScript: "/_burrowgate/static/challenges/captcha-example.js",
	title: "Confirm you are human",
	description: "Complete the visual verification to continue.",

	async create(context, config) {
		return {
			publicData: {
				kind: "captcha-example",
				siteKey: String(config.siteKey),
			},
			privateData: {
				// Store only server-side data needed during verification.
			},
		};
	},

	async verify(context, config, privateData, answer) {
		// Send the browser response token to the CAPTCHA verification API.
		// Bind verification to the expected hostname/site and optionally client IP.
		return { success: true, metadata: { provider: "captcha-example" } };
	},
};
```

A provider can optionally supply its own default verification-page template (`defaultHtmlTemplate`) instead of falling back to the generic one, plus extra static `{{name}}` placeholders resolved from its own `publicData` (`extraPlaceholders`/`extraTemplateContext`) - see [Custom Challenge Pages](CHALLENGE_PAGES.md) for the full resolution order and the DOM-hook convention (`data-bg-<provider>="..."`) that lets a site's own template override specific elements without forking the whole page. `buildChallengeTemplate()` in `src/services/challenge-page-service.ts` builds the shared shell (head, brand, status text, noscript) so a new provider's default only needs to supply its own body content and, if it needs more room than the default 560px card, a wider `mainMaxWidth`.

A provider also declares `defaultTexts: [{ key, label, default }]` for every visitor-facing string its client script shows - the admin UI lists these (plus the shared base keys every provider gets for free: `verifying`, `redirectingIn`, `redirecting`, `verificationFailed`) as editable fields under that provider's Text section, so a site owner can translate or reword them without touching the template. The client script reads them off the challenge bootstrap at runtime (`challenge.text.<key>`, with a hardcoded fallback matching `default` - see any existing `public/challenges/*.js` for the small `t()`/`substitute()` helpers each one duplicates), not off the template placeholders, since these are read live in the browser rather than substituted into the page HTML once. If `verify()` needs a translatable failure reason too (a single generic message, or a small closed set of real outcomes - not a probe-revealing gradient), return a stable key as `reason` and register that same key in `defaultTexts`; `challenge-service.ts`'s `verifyFlow()` resolves it to display text the same way right before the response reaches the browser, so an untranslated/unregistered key (a raw diagnostic string) just passes through unchanged.

Register it:

```ts
export const challengeRegistry = new ChallengeRegistry().register(powSha256Provider).register(captchaExampleProvider);
```

Add a static route for its browser module, or replace the current explicit static routes with a static-file allowlist.

## Browser contract

The generic verification page defines:

```js
window.__BURROWGATE_CHALLENGE__ = {
	flowId: "flow_...",
	provider: "captcha-example",
	publicData: {},
};
```

The browser module completes its work and submits:

```js
await fetch("/_burrowgate/api/challenge/verify", {
	method: "POST",
	headers: { "content-type": "application/json" },
	body: JSON.stringify({
		flowId: window.__BURROWGATE_CHALLENGE__.flowId,
		answer: { token: "provider-response-token" },
	}),
});
```

The response is one of:

```json
{ "done": true, "redirect": "/original/path" }
```

```json
{ "done": false, "next": true }
```

```json
{ "done": false, "reason": "Verification failed" }
```

## Challenge-chain guarantees

BurrowGate, rather than the provider, handles:

- Flow and step expiration
- Maximum attempts
- Ordered multi-provider policies
- Atomic one-time step consumption
- Session creation
- Safe local return paths
- Secure cookies
- Redirecting to the original GET/HEAD URL

Providers should remain stateless except for data persisted in their challenge step.

## Real examples

`src/challenges/providers/hcaptcha.ts`, `src/challenges/providers/turnstile.ts`, and `src/challenges/providers/recaptcha-v2.ts` implement this contract against actual CAPTCHA services and cover two things the example above glosses over:

- **Verification-page CSP.** hCaptcha and Turnstile both load a script and an iframe from their own domain. A provider that needs this declares `cspSources` (`scriptSrc`, `frameSrc`, `connectSrc`, `styleSrc`, `imgSrc`) on the `ChallengeProvider` object. BurrowGate widens the Content-Security-Policy of `/_burrowgate/verify` to include those hosts only when that provider is the active step. See [Custom Challenge Pages](CHALLENGE_PAGES.md).
- **Secret storage.** A provider whose config includes a server-side secret (here, the CAPTCHA secret key used to call the provider's verification API) should implement the optional `normalizeConfigForStorage(config)` hook to encrypt it before it's written to the database, the same way every other secret in BurrowGate is stored. All three providers use `encryptSecret`/`decryptSecret`/`isEncryptedSecret` from `src/services/secret-encryption-service.ts`, encrypting only when the value isn't already in encrypted form so a re-save of an unrelated field doesn't touch it.

`src/challenges/providers/recaptcha-v3.ts` calls the same verification API as `recaptcha-v2.ts` but makes a graduated decision instead of a strict pass/fail: Google returns a `0.0`-`1.0` risk score rather than a boolean, so `verify()` only succeeds when `success` is `true`, the returned `action` matches the configured one (a light replay/binding guard), **and** the score meets a configurable `scoreThreshold`. It also has no visible widget - the client calls `grecaptcha.execute()` automatically on page load instead of waiting for a click, closer to `pow-sha256`'s "just show status text and complete automatically" flow than to a CAPTCHA widget. A provider making this kind of graduated decision should keep the threshold itself in `config` (not hardcoded) so it stays adjustable from the dashboard.

`src/challenges/providers/snake.ts` implements an interactive challenge with no third party at all - the visitor plays a short game of Snake in the browser, and the server independently verifies the outcome. It covers a third concern the two CAPTCHA providers don't have:

- **A deterministic game engine duplicated on both sides.** The server generates a random seed at `create()` time (public, not secret - like `pow-sha256`'s `seed`/`difficulty`) and puts it in `publicData`. The client needs to run the _exact same_ seeded PRNG, apple-placement, and movement/collision rules live, in the browser, so it can render the game and know where apples appear as it plays. The server then replays the client's final submitted move sequence through its own copy of that same algorithm to verify it's a legitimate win. Since this codebase has no build step for client scripts, the algorithm is a small, precisely specified piece of code hand-duplicated into `src/challenges/providers/snake-engine.ts` (server) and a clearly delimited block inside `public/challenges/snake.js` (client) - the two comments each point at the other, and `tests/snake-challenge-provider.test.ts` pins exact PRNG output and known win/wall/self-collision transcripts to catch any drift.

`src/challenges/providers/slider.ts` is the other end of the interactive-challenge spectrum from `snake`: a discrete move string is trivial for a script to compute and replay perfectly, so `snake` can only lean on submission timing to tell a bot from a human. A drag challenge instead has a continuous `(x, y, t)` pointer trajectory as its answer - tens to hundreds of samples carrying real device jitter and human motor-control variance, which is a meaningfully bigger engineering lift for an attacker to fake convincingly than padding a `sleep()` call. Unlike `snake`, there's no shared engine to duplicate: the "answer" is one number (`targetX`), generated with `crypto.getRandomValues` and shipped through both `publicData` and `privateData` exactly like `snake`'s `seed`, with no algorithm the client needs to replay. `verify()` checks landing accuracy against `targetX`, a distance-scaled minimum duration, and that the _variance_ of the recorded `dt`/`dx` gaps clears a floor (not merely "more than one distinct value" - that would still pass a fake alternating between two near-identical gaps). As with `snake`, the client only submits once it judges the drop close enough to succeed, so a real player never sees a server-side rejection - every `verify()` failure therefore collapses into one generic reason rather than leaking which check tripped.

`src/challenges/providers/trace.ts` (+ `trace-engine.ts`) combines both ideas: like `slider`, the answer is a full pointer trajectory; like `snake`, that trajectory is checked against a procedurally generated environment - here, a winding track the visitor must drag a ball along, seeded and shaped (`chokepoint`/`bezier`/`zigzag`/`loop`) the same way `snake`'s seed drives its apple layout, so `trace-engine.ts` is hand-duplicated into `public/challenges/trace.js` exactly like `snake-engine.ts` is into `snake.js`. `verify()` checks track-relative deviation (point-to-segment distance against the tapering track width, tallying a wall-hit ratio and max excursion), a distance-scaled minimum duration, and timestamp-jitter variance, with every threshold (`MAX_HIT_RATIO`, `MAX_OOB_DEPTH_PX`, `MIN_TIME_JITTER_VARIANCE`, `PERFECT_CENTER_EPSILON_PX`) an internal constant the client never sees. The one check with no `slider`/`snake` analogue is the "too perfect" rejection: zero wall hits _and_ a suspiciously laser-centered average track offset is itself a tell, since real hands wobble even on an easy track.

`src/challenges/providers/password.ts` is the odd one out: every other provider's `publicData` carries something about the answer - a seed, a target, at minimum enough for the client to render and locally pre-check its own attempt. A shared password can't work that way, since the whole point is that the secret never reaches the browser: `publicData` here is just `{ kind: "password" }`, and `privateData` holds only the Argon2id hash (`Bun.password.hash(value, { algorithm: "argon2id" })`, the same call `access-list-service.ts` and `admin-user-service.ts` already use for account passwords - there's no shared hashing utility in this codebase, so the provider calls it directly rather than inventing a wrapper). `normalizeConfigForStorage` mirrors `hcaptcha.ts`'s encrypt-on-write shape, but one-way: an `/^\$argon2id\$/` prefix check stands in for `isEncryptedSecret`, so re-saving a site without changing the password doesn't hash an already-hashed value. `verify()` also breaks from `snake`/`slider`/`trace`'s "one generic reason" convention on purpose: a wrong password is a normal, common outcome for a genuine visitor (a typo), not a probe-only path, so it's fine - and more helpful - to say `"Incorrect password"` outright rather than obscure it. Because a shared password is guessable in a way none of the other providers' answers are, sites using it should also enable the per-site challenge-failure auto-ban (Sites settings in the dashboard) - see `src/services/challenge-failure-ban-service.ts`.

Its `defaultHtmlTemplate` is also the one exception to `buildChallengeTemplate()`: a password prompt reads like a sign-in form, not a game/CAPTCHA card, so instead of the dark gradient shell every other provider gets, it's a hand-written template that links the real `/_burrowgate/static/burrowgate.css` (same-origin, already covered by the default strict CSP) and reuses `accessLoginPage()`'s exact classes (`.shell.challenge`, `.card.pad.auth-card`, `.input`, `.button`, `form.grid label`) rather than duplicating that look into a copy that would drift out of sync. A provider is free to do this instead of `buildChallengeTemplate()` whenever its content is closer to a dashboard form than a challenge widget - the only real requirement is keeping `{{challengeScript}}` in the template, same as any other.
