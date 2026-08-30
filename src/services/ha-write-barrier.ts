import { AsyncLocalStorage } from "node:async_hooks";
import { config } from "../config.ts";

const PROMOTION_WRITE_DRAIN_TIMEOUT_MS = 30_000;

interface WriteLeaseContext {
	active: boolean;
}

export class HaPromotionWriteFenceError extends Error {
	constructor(message = "This node is promoting a replica and is temporarily not accepting configuration writes") {
		super(message);
		this.name = "HaPromotionWriteFenceError";
	}
}

export class HaPrimaryAuthorityFenceError extends Error {
	constructor(message = "This primary has observed a newer cluster epoch and is durably fenced until it is reconfigured") {
		super(message);
		this.name = "HaPrimaryAuthorityFenceError";
	}
}

export class HaQuorumLossFenceError extends Error {
	constructor(message = "This primary has lost contact with a majority of the cluster and is temporarily not accepting configuration writes") {
		super(message);
		this.name = "HaQuorumLossFenceError";
	}
}

function isQuorumProofStale(): boolean {
	return config.ha.quorumTrackingActive && Date.now() - config.ha.lastMajorityConfirmedAt >= config.ha.quorumLossFenceSeconds * 1000;
}

class HaPrimaryWriteBarrier {
	private readonly leaseStorage = new AsyncLocalStorage<WriteLeaseContext>();
	private activeWrites = 0;
	private readonly drainWaiters = new Set<() => void>();

	async runPrimaryWrite<T>(operation: () => Promise<T>): Promise<T> {
		const inherited = this.leaseStorage.getStore();
		if (inherited?.active) return await operation();
		if (config.ha.authorityFence) throw new HaPrimaryAuthorityFenceError();
		if (config.ha.quorumFenced || isQuorumProofStale()) throw new HaQuorumLossFenceError();
		if (config.ha.fencedForPromotion) throw new HaPromotionWriteFenceError();

		const context: WriteLeaseContext = { active: true };
		this.activeWrites += 1;
		try {
			return await this.leaseStorage.run(context, operation);
		} finally {
			context.active = false;
			this.activeWrites -= 1;
			if (this.activeWrites === 0) {
				for (const resolve of this.drainWaiters) resolve();
				this.drainWaiters.clear();
			}
		}
	}

	async beginPromotion(timeoutMs = PROMOTION_WRITE_DRAIN_TIMEOUT_MS): Promise<void> {
		if (config.ha.authorityFence)
			throw new HaPrimaryAuthorityFenceError("This node cannot promote a replica because it has evidence that it is no longer the authoritative primary");
		if (config.ha.quorumFenced || isQuorumProofStale())
			throw new HaQuorumLossFenceError("This node cannot promote a replica while it has lost contact with a majority of the cluster");
		if (config.ha.fencedForPromotion) throw new HaPromotionWriteFenceError("A promotion is already in progress on this node");
		if (config.ha.electionInProgress) throw new HaPromotionWriteFenceError("An automatic failover election is already in progress on this node");

		config.ha.fencedForPromotion = true;
		if (this.activeWrites === 0) return;

		let drain: (() => void) | null = null;
		let timeout: ReturnType<typeof setTimeout> | null = null;
		try {
			await new Promise<void>((resolve, reject) => {
				drain = resolve;
				this.drainWaiters.add(resolve);
				timeout = setTimeout(() => reject(new Error("Timed out waiting for active configuration writes to finish before promotion")), timeoutMs);
				(timeout as unknown as { unref?: () => void }).unref?.();
			});
		} catch (error) {
			config.ha.fencedForPromotion = false;
			throw error;
		} finally {
			if (timeout) clearTimeout(timeout);
			if (drain) this.drainWaiters.delete(drain);
		}
	}

	endPromotion(): void {
		config.ha.fencedForPromotion = false;
	}

	activeWriteCount(): number {
		return this.activeWrites;
	}

	hasActiveLease(): boolean {
		return this.leaseStorage.getStore()?.active === true;
	}
}

export const haPrimaryWriteBarrier = new HaPrimaryWriteBarrier();

const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export function isPrimaryAdminWriteRequest(request: Request): boolean {
	if (!MUTATING_METHODS.has(request.method)) return false;
	const pathname = new URL(request.url).pathname;
	if (!pathname.startsWith("/_burrowgate/api/admin/")) return false;
	return (
		pathname !== "/_burrowgate/api/admin/logout" &&
		pathname !== "/_burrowgate/api/admin/ha/consume-recovery-code" &&
		pathname !== "/_burrowgate/api/admin/ha/resolve-admin-session" &&
		!pathname.startsWith("/_burrowgate/api/admin/ha/promote/")
	);
}
