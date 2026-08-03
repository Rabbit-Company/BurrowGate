export interface ChallengeCreateContext {
	flowId: string;
	siteId: string;
	clientIp: string;
	userAgentHash: string;
	expiresAt: number;
}
export interface ChallengeVerifyContext extends ChallengeCreateContext {
	attempts: number;
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
export interface ChallengeProvider {
	readonly name: string;
	readonly clientScript: string;
	readonly title: string;
	readonly description: string;
	validateConfig?(config: Record<string, unknown>): void;
	create(context: ChallengeCreateContext, config: Record<string, unknown>): Promise<ChallengeMaterial>;
	verify(context: ChallengeVerifyContext, config: Record<string, unknown>, privateData: Record<string, unknown>, answer: unknown): Promise<ChallengeResult>;
}
