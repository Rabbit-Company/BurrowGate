import { ChallengeRegistry } from "./registry.ts";
import { powSha256Provider } from "./providers/pow-sha256.ts";
export const challengeRegistry = new ChallengeRegistry().register(powSha256Provider);
