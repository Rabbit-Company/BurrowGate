import { ChallengeRegistry } from "./registry.ts";
import { powSha256Provider } from "./providers/pow-sha256.ts";
import { hcaptchaProvider } from "./providers/hcaptcha.ts";
import { turnstileProvider } from "./providers/turnstile.ts";
import { snakeProvider } from "./providers/snake.ts";
import { sliderProvider } from "./providers/slider.ts";
import { traceProvider } from "./providers/trace.ts";
import { recaptchaV2Provider } from "./providers/recaptcha-v2.ts";
import { recaptchaV3Provider } from "./providers/recaptcha-v3.ts";
export const challengeRegistry = new ChallengeRegistry()
	.register(powSha256Provider)
	.register(hcaptchaProvider)
	.register(turnstileProvider)
	.register(snakeProvider)
	.register(sliderProvider)
	.register(traceProvider)
	.register(recaptchaV2Provider)
	.register(recaptchaV3Provider);
