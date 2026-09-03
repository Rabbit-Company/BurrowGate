export interface ChallengeCreateContext {
	flowId: string;
	siteId: string;
	clientIp: string;
	userAgentHash: string;
	expiresAt: number;
}
export interface ChallengeVerifyContext extends ChallengeCreateContext {
	attempts: number;
	createdAt: number;
}
export interface ChallengeMaterial {
	publicData: Record<string, unknown>;
	privateData: Record<string, unknown>;
}
export interface ChallengeResult {
	success: boolean;
	reason?: string;
	metadata?: Record<string, unknown>;
}
export interface ChallengeProviderCspSources {
	scriptSrc?: string[];
	frameSrc?: string[];
	connectSrc?: string[];
	styleSrc?: string[];
	imgSrc?: string[];
}
export interface ChallengeProvider {
	readonly name: string;
	readonly clientScript: string;
	readonly title: string;
	readonly description: string;
	/** Extra Content-Security-Policy sources the verification page needs to load this provider's widget. Omit when the default same-origin policy is sufficient. */
	readonly cspSources?: ChallengeProviderCspSources;
	validateConfig?(config: Record<string, unknown>): void;
	/** Transforms step config before it is persisted (encrypting a secret). Called only on write, not on every read. */
	normalizeConfigForStorage?(config: Record<string, unknown>): Promise<Record<string, unknown>>;
	create(context: ChallengeCreateContext, config: Record<string, unknown>): Promise<ChallengeMaterial>;
	verify(context: ChallengeVerifyContext, config: Record<string, unknown>, privateData: Record<string, unknown>, answer: unknown): Promise<ChallengeResult>;
}
