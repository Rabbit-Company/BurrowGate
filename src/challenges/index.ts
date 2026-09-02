import { ChallengeRegistry } from "./registry.ts";
import { powSha256Provider } from "./providers/pow-sha256.ts";
import { hcaptchaProvider } from "./providers/hcaptcha.ts";
import { turnstileProvider } from "./providers/turnstile.ts";
export const challengeRegistry = new ChallengeRegistry().register(powSha256Provider).register(hcaptchaProvider).register(turnstileProvider);
