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
	/** This provider's own default verification-page HTML template. Falls back to the generic DEFAULT_CHALLENGE_HTML_TEMPLATE when unset. */
	readonly defaultHtmlTemplate?: string;
	/** Extra {{name}} placeholders this provider's template can use, beyond the generic set - descriptive metadata for the admin UI's placeholder reference list. Resolved at render time by extraTemplateContext. */
	readonly extraPlaceholders?: ReadonlyArray<{ name: string; description: string }>;
	/** Exposes this provider's own static, known-at-render-time publicData fields as extra {{name}} template placeholders. Only for values fixed at create() time - a value that changes live during play (e.g. apples eaten so far) can't be server-substituted and must stay a DOM hook the client script updates instead. */
	extraTemplateContext?(publicData: Record<string, unknown>): Record<string, string>;
	validateConfig?(config: Record<string, unknown>): void;
	/** Transforms step config before it is persisted (encrypting a secret). Called only on write, not on every read. */
	normalizeConfigForStorage?(config: Record<string, unknown>): Promise<Record<string, unknown>>;
	create(context: ChallengeCreateContext, config: Record<string, unknown>): Promise<ChallengeMaterial>;
	verify(context: ChallengeVerifyContext, config: Record<string, unknown>, privateData: Record<string, unknown>, answer: unknown): Promise<ChallengeResult>;
}
