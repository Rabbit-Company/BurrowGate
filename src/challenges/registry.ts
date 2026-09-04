import type { ChallengeProvider } from "./types.ts";
export class ChallengeRegistry {
	private providers = new Map<string, ChallengeProvider>();
	register(provider: ChallengeProvider): this {
		if (this.providers.has(provider.name)) throw new Error(`Challenge provider already registered: ${provider.name}`);
		this.providers.set(provider.name, provider);
		return this;
	}
	get(name: string): ChallengeProvider {
		const p = this.providers.get(name);
		if (!p) throw new Error(`Unknown challenge provider: ${name}`);
		return p;
	}
	tryGet(name: string): ChallengeProvider | undefined {
		return this.providers.get(name);
	}
	names(): string[] {
		return [...this.providers.keys()];
	}
}
