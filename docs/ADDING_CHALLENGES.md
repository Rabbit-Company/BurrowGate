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

`src/challenges/providers/hcaptcha.ts` and `src/challenges/providers/turnstile.ts` implement this contract against actual CAPTCHA services and cover two things the example above glosses over:

- **Verification-page CSP.** hCaptcha and Turnstile both load a script and an iframe from their own domain. A provider that needs this declares `cspSources` (`scriptSrc`, `frameSrc`, `connectSrc`, `styleSrc`, `imgSrc`) on the `ChallengeProvider` object. BurrowGate widens the Content-Security-Policy of `/_burrowgate/verify` to include those hosts only when that provider is the active step. See [Custom Challenge Pages](CHALLENGE_PAGES.md).
- **Secret storage.** A provider whose config includes a server-side secret (here, the CAPTCHA secret key used to call the provider's verification API) should implement the optional `normalizeConfigForStorage(config)` hook to encrypt it before it's written to the database, the same way every other secret in BurrowGate is stored. Both providers use `encryptSecret`/`decryptSecret`/`isEncryptedSecret` from `src/services/secret-encryption-service.ts`, encrypting only when the value isn't already in encrypted form so a re-save of an unrelated field doesn't touch it.

`src/challenges/providers/snake.ts` implements an interactive challenge with no third party at all - the visitor plays a short game of Snake in the browser, and the server independently verifies the outcome. It covers a third concern the two CAPTCHA providers don't have:

- **A deterministic game engine duplicated on both sides.** The server generates a random seed at `create()` time (public, not secret - like `pow-sha256`'s `seed`/`difficulty`) and puts it in `publicData`. The client needs to run the _exact same_ seeded PRNG, apple-placement, and movement/collision rules live, in the browser, so it can render the game and know where apples appear as it plays. The server then replays the client's final submitted move sequence through its own copy of that same algorithm to verify it's a legitimate win. Since this codebase has no build step for client scripts, the algorithm is a small, precisely specified piece of code hand-duplicated into `src/challenges/providers/snake-engine.ts` (server) and a clearly delimited block inside `public/challenges/snake.js` (client) - the two comments each point at the other, and `tests/snake-challenge-provider.test.ts` pins exact PRNG output and known win/wall/self-collision transcripts to catch any drift.
