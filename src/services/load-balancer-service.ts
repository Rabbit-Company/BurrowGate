import { repository } from "../db/repository.ts";
import type { AccessSessionRecord, LoadBalancingAlgorithm, SiteOriginRecord, SiteRecord } from "../types.ts";
import { originHealthManager } from "./origin-health-service.ts";

const PASSIVE_FAILURE_QUARANTINE_MS = 15_000;

function stableHash(value: string): number {
	let hash = 2_166_136_261;
	for (let index = 0; index < value.length; index += 1) {
		hash ^= value.charCodeAt(index);
		hash = Math.imul(hash, 16_777_619);
	}
	return hash >>> 0;
}

function byPriority(origins: SiteOriginRecord[]): SiteOriginRecord[] {
	if (origins.length < 2) return origins;
	const priority = Math.min(...origins.map((origin) => Number(origin.priority)));
	return origins.filter((origin) => Number(origin.priority) === priority);
}

export function ipAffinityOrigin(origins: SiteOriginRecord[], ip: string, weighted: boolean): SiteOriginRecord | null {
	if (origins.length === 0) return null;
	const ordered = [...origins].sort((left, right) => left.id.localeCompare(right.id));
	if (!weighted) return ordered[stableHash(ip) % ordered.length]!;
	const total = ordered.reduce((sum, origin) => sum + Math.max(1, Number(origin.weight)), 0);
	let bucket = stableHash(ip) % total;
	for (const origin of ordered) {
		bucket -= Math.max(1, Number(origin.weight));
		if (bucket < 0) return origin;
	}
	return ordered[ordered.length - 1]!;
}

interface SelectionOptions {
	excludeOriginIds?: Set<string>;
}

export class LoadBalancer {
	private readonly originsBySite = new Map<string, SiteOriginRecord[]>();
	private readonly roundRobinCursor = new Map<string, number>();
	private readonly smoothWeights = new Map<string, number>();
	private readonly passiveQuarantine = new Map<string, number>();

	async initialize(): Promise<void> {
		this.originsBySite.clear();
		for (const origin of await repository.allOrigins()) {
			const origins = this.originsBySite.get(origin.site_id) ?? [];
			origins.push(origin);
			this.originsBySite.set(origin.site_id, origins);
		}
	}

	async refreshSite(siteId: string): Promise<void> {
		const previous = this.originsBySite.get(siteId) ?? [];
		const origins = await repository.originsForSite(siteId);
		if (origins.length > 0) this.originsBySite.set(siteId, origins);
		else this.originsBySite.delete(siteId);
		for (const origin of previous) if (!origins.some((candidate) => candidate.id === origin.id)) this.passiveQuarantine.delete(origin.id);
		this.roundRobinCursor.delete(siteId);
		for (const key of this.smoothWeights.keys()) if (key.startsWith(`${siteId}:`)) this.smoothWeights.delete(key);
	}

	removeSite(siteId: string): void {
		for (const origin of this.originsBySite.get(siteId) ?? []) this.passiveQuarantine.delete(origin.id);
		this.originsBySite.delete(siteId);
		this.roundRobinCursor.delete(siteId);
		for (const key of this.smoothWeights.keys()) if (key.startsWith(`${siteId}:`)) this.smoothWeights.delete(key);
	}

	origins(siteId: string): SiteOriginRecord[] {
		return [...(this.originsBySite.get(siteId) ?? [])];
	}

	reportPassiveFailure(originId: string): void {
		this.passiveQuarantine.set(originId, Date.now() + PASSIVE_FAILURE_QUARANTINE_MS);
	}

	clearPassiveFailure(originId: string): void {
		this.passiveQuarantine.delete(originId);
	}

	private originAvailable(origin: SiteOriginRecord, existingAffinity: boolean, excluded: Set<string>, allowUnhealthy = false): boolean {
		if (origin.enabled !== 1 || excluded.has(origin.id)) return false;
		if (!existingAffinity && origin.draining === 1) return false;
		if (!allowUnhealthy && originHealthManager.originState(origin.id) === "unhealthy") return false;
		const quarantinedUntil = this.passiveQuarantine.get(origin.id) ?? 0;
		if (quarantinedUntil > Date.now()) return false;
		if (quarantinedUntil > 0) this.passiveQuarantine.delete(origin.id);
		return true;
	}

	private candidates(site: SiteRecord, excluded: Set<string>): SiteOriginRecord[] {
		const eligible = this.origins(site.id).filter((origin) => this.originAvailable(origin, false, excluded, true));
		const healthy = eligible.filter((origin) => originHealthManager.originState(origin.id) === "healthy");
		const notUnhealthy = eligible.filter((origin) => originHealthManager.originState(origin.id) !== "unhealthy");
		const preferred = healthy.length > 0 ? healthy : notUnhealthy.length > 0 ? notUnhealthy : site.health_check_failure_mode === "monitor" ? eligible : [];
		return (site.load_balancing_algorithm ?? "failover") === "failover" ? byPriority(preferred) : preferred;
	}

	private nextByAlgorithm(site: SiteRecord, origins: SiteOriginRecord[]): SiteOriginRecord | null {
		if (origins.length === 0) return null;
		const algorithm: LoadBalancingAlgorithm = site.load_balancing_algorithm ?? "failover";
		if (algorithm === "failover")
			return [...origins].sort(
				(left, right) => Number(left.priority) - Number(right.priority) || right.is_primary - left.is_primary || left.created_at - right.created_at,
			)[0]!;
		if (algorithm === "round-robin") {
			const cursor = this.roundRobinCursor.get(site.id) ?? 0;
			this.roundRobinCursor.set(site.id, cursor + 1);
			return origins[cursor % origins.length]!;
		}
		let selected = origins[0]!;
		let selectedWeight = Number.NEGATIVE_INFINITY;
		let total = 0;
		for (const origin of origins) {
			const weight = Math.max(1, Number(origin.weight));
			total += weight;
			const key = `${site.id}:${origin.id}`;
			const current = (this.smoothWeights.get(key) ?? 0) + weight;
			this.smoothWeights.set(key, current);
			if (current > selectedWeight) {
				selected = origin;
				selectedWeight = current;
			}
		}
		const selectedKey = `${site.id}:${selected.id}`;
		this.smoothWeights.set(selectedKey, (this.smoothWeights.get(selectedKey) ?? 0) - total);
		return selected;
	}

	async selectOrigin(site: SiteRecord, session: AccessSessionRecord | null, ip: string, options: SelectionOptions = {}): Promise<SiteOriginRecord | null> {
		const excluded = options.excludeOriginIds ?? new Set<string>();
		const affinity = site.load_balancing_affinity !== 0;
		if (affinity && session?.origin_id) {
			const assigned = this.origins(site.id).find((origin) => origin.id === session.origin_id);
			if (assigned && this.originAvailable(assigned, true, excluded)) return assigned;
		}

		const candidates = this.candidates(site, excluded);
		const algorithm = site.load_balancing_algorithm ?? "failover";
		const selected = affinity && !session ? ipAffinityOrigin(candidates, ip, algorithm === "weighted-round-robin") : this.nextByAlgorithm(site, candidates);
		if (affinity && session && selected && session.origin_id !== selected.id) {
			await repository.assignSessionOrigin(session.id, site.id, selected.id);
			session.origin_id = selected.id;
		}
		return selected;
	}
}

export const loadBalancer = new LoadBalancer();
