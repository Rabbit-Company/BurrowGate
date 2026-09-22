import { parseCidr, parseIp } from "../utils/ip.ts";

/**
 * In-memory index of the decisions pulled from a CrowdSec Local API.
 *
 * A community blocklist carries tens of thousands of entries, so `ip-rule-service`'s linear CIDR
 * scan is not usable here. Exact addresses go in numeric-keyed maps, ranges in maps bucketed by
 * prefix length (a lookup masks once per distinct prefix, not once per rule), country and AS in
 * plain maps keyed by values the request already resolved.
 *
 * Decisions never touch the database. Writing them to a table would push a six-figure row count
 * through the HA replication changelog on every resync, and a replica could not write them anyway,
 * so every node polls the LAPI itself and keeps its own copy.
 */

export type CrowdSecRemediation = "ban" | "captcha";
export type CrowdSecScope = "ip" | "range" | "country" | "as";

export interface CrowdSecDecision {
	/** The LAPI's own id, used to match `deleted` entries against what we hold. */
	id: number;
	remediation: CrowdSecRemediation;
	/** `CAPI` for the community blocklist, `cscli` for a manual ban, or a subscribed list's name. */
	origin: string;
	scenario: string;
	scope: CrowdSecScope;
	/** As the LAPI expressed it, kept for the dashboard and the traffic log. */
	value: string;
	/** Absolute expiry in epoch milliseconds, or null when the decision carries no usable duration. */
	expiresAt: number | null;
}

export interface CrowdSecStoreStats {
	total: number;
	byScope: Record<CrowdSecScope, number>;
	byRemediation: Record<CrowdSecRemediation, number>;
	byOrigin: Record<string, number>;
}

/** A decision as the LAPI serialises it. Every field is treated as untrusted input. */
export interface RawCrowdSecDecision {
	id?: unknown;
	type?: unknown;
	scope?: unknown;
	value?: unknown;
	duration?: unknown;
	until?: unknown;
	origin?: unknown;
	scenario?: unknown;
}

const GO_DURATION_PATTERN = /(\d+(?:\.\d+)?)(ns|us|µs|μs|ms|s|m|h)/gu;

const DURATION_UNIT_MS: Record<string, number> = {
	ns: 1e-6,
	us: 1e-3,
	µs: 1e-3,
	μs: 1e-3,
	ms: 1,
	s: 1_000,
	m: 60_000,
	h: 3_600_000,
};

/**
 * Parses a Go duration string (`"3h59m51.7s"`, `"-1h"`, `"168h0m0s"`) into milliseconds.
 *
 * The LAPI sends durations, not deadlines, so this is where expiry comes from. Null means "no
 * usable duration", never "never expires", so a malformed value cannot produce an immortal ban.
 */
export function parseGoDurationMs(input: string): number | null {
	const trimmed = input.trim();
	if (!trimmed) return null;
	const negative = trimmed.startsWith("-");
	const body = negative || trimmed.startsWith("+") ? trimmed.slice(1) : trimmed;
	if (!body) return null;

	GO_DURATION_PATTERN.lastIndex = 0;
	let total = 0;
	let matched = 0;
	let consumed = 0;
	for (const match of body.matchAll(GO_DURATION_PATTERN)) {
		const amount = Number(match[1]);
		const unit = DURATION_UNIT_MS[match[2]!];
		if (!Number.isFinite(amount) || unit === undefined) return null;
		total += amount * unit;
		matched += 1;
		consumed += match[0]!.length;
	}
	// Partial parses ("3h junk") are rejected rather than silently truncated to something plausible.
	if (!matched || consumed !== body.length) return null;
	return negative ? -total : total;
}

export function decisionExpiry(raw: RawCrowdSecDecision, now: number): number | null {
	if (typeof raw.duration === "string") {
		const milliseconds = parseGoDurationMs(raw.duration);
		if (milliseconds !== null) return now + milliseconds;
	}
	if (typeof raw.until === "string") {
		const parsed = Date.parse(raw.until);
		if (Number.isFinite(parsed)) return parsed;
	}
	return null;
}

function normalizeScope(value: unknown): CrowdSecScope | null {
	const scope = String(value ?? "")
		.trim()
		.toLowerCase();
	if (scope === "ip") return "ip";
	if (scope === "range") return "range";
	if (scope === "country") return "country";
	if (scope === "as" || scope === "asn") return "as";
	return null;
}

/**
 * Maps a LAPI remediation onto something BurrowGate can enforce.
 *
 * `ban` and `captcha` are what the ecosystem ships. Anything else follows the operator's
 * configured fallback rather than being silently ignored or silently escalated.
 */
export function normalizeRemediation(value: unknown, unknownFallback: CrowdSecRemediation | "ignore"): CrowdSecRemediation | null {
	const type = String(value ?? "")
		.trim()
		.toLowerCase();
	if (type === "ban") return "ban";
	if (type === "captcha") return "captcha";
	return unknownFallback === "ignore" ? null : unknownFallback;
}

/** Ban outranks captcha, and at equal remediation the longer-lasting decision wins. */
function priority(decision: CrowdSecDecision): number {
	return decision.remediation === "ban" ? 2 : 1;
}

function outranks(candidate: CrowdSecDecision, incumbent: CrowdSecDecision): boolean {
	const difference = priority(candidate) - priority(incumbent);
	if (difference !== 0) return difference > 0;
	if (candidate.expiresAt === null) return true;
	if (incumbent.expiresAt === null) return false;
	return candidate.expiresAt > incumbent.expiresAt;
}

function maskIpv4(value: number, prefix: number): number {
	if (prefix <= 0) return 0;
	if (prefix >= 32) return value >>> 0;
	const shift = 32 - prefix;
	return ((value >>> shift) << shift) >>> 0;
}

function maskIpv6(value: bigint, prefix: number): bigint {
	if (prefix <= 0) return 0n;
	if (prefix >= 128) return value;
	const shift = BigInt(128 - prefix);
	return (value >> shift) << shift;
}

const IPV4_MAPPED_MARKER = 0xffffn;

export interface NumericAddress {
	version: 4 | 6;
	v4: number;
	v6: bigint;
}

/**
 * Parses a client address into the numeric form the maps are keyed by.
 *
 * IPv4-mapped IPv6 (`::ffff:1.2.3.4`) folds down to plain IPv4: a dual-stack listener hands
 * addresses over in that form, while CrowdSec issued the decision against the v4 address.
 */
export function numericAddress(ip: string): NumericAddress | null {
	const parsed = parseIp(ip);
	if (!parsed) return null;
	if (parsed.version === 4) return { version: 4, v4: Number(parsed.value), v6: 0n };
	if (parsed.value >> 32n === IPV4_MAPPED_MARKER) {
		return { version: 4, v4: Number(parsed.value & 0xffffffffn), v6: 0n };
	}
	return { version: 6, v4: 0, v6: parsed.value };
}

type BucketKind = "ipv4" | "ipv6" | "rangeV4" | "rangeV6" | "country" | "as";

interface Location {
	kind: BucketKind;
	numeric: number;
	big: bigint;
	text: string;
	prefix: number;
}

export class CrowdSecDecisionStore {
	private ipv4 = new Map<number, CrowdSecDecision>();
	private ipv6 = new Map<bigint, CrowdSecDecision>();
	private rangesV4 = new Map<number, Map<number, CrowdSecDecision>>();
	private rangesV6 = new Map<number, Map<bigint, CrowdSecDecision>>();
	/** Prefix lengths present in `rangesV4`/`rangesV6`, longest first so the most specific range wins. */
	private prefixesV4: number[] = [];
	private prefixesV6: number[] = [];
	private countries = new Map<string, CrowdSecDecision>();
	private asns = new Map<number, CrowdSecDecision>();

	/**
	 * Decisions outranked by another on the same value, for instance two sources banning one
	 * address. Kept so deleting the winner promotes the runner-up instead of unblocking an address
	 * something else still covers. Almost always empty, and never read on the lookup path.
	 */
	private shadowed = new Map<string, CrowdSecDecision[]>();

	/** Interning pool: 100k decisions share a few dozen distinct origin and scenario strings. */
	private interned = new Map<string, string>();

	private intern(value: string): string {
		const existing = this.interned.get(value);
		if (existing !== undefined) return existing;
		this.interned.set(value, value);
		return value;
	}

	private locate(scope: CrowdSecScope, value: string): Location | null {
		if (scope === "ip") {
			const address = numericAddress(value.trim());
			if (!address) return null;
			return address.version === 4
				? { kind: "ipv4", numeric: address.v4, big: 0n, text: "", prefix: 32 }
				: { kind: "ipv6", numeric: 0, big: address.v6, text: "", prefix: 128 };
		}
		if (scope === "range") {
			const cidr = parseCidr(value.trim());
			if (!cidr) return null;
			// A /32 or /128 "range" is an exact address. Routing it to the exact maps keeps the
			// prefix buckets small and the common lookup a single map hit.
			if (cidr.version === 4) {
				const network = Number(cidr.network);
				if (cidr.prefix === 32) return { kind: "ipv4", numeric: network, big: 0n, text: "", prefix: 32 };
				return { kind: "rangeV4", numeric: maskIpv4(network, cidr.prefix), big: 0n, text: "", prefix: cidr.prefix };
			}
			if (cidr.prefix === 128) return { kind: "ipv6", numeric: 0, big: cidr.network, text: "", prefix: 128 };
			return { kind: "rangeV6", numeric: 0, big: maskIpv6(cidr.network, cidr.prefix), text: "", prefix: cidr.prefix };
		}
		if (scope === "country") {
			const code = value.trim().toUpperCase();
			if (!/^[A-Z]{2}$/u.test(code)) return null;
			return { kind: "country", numeric: 0, big: 0n, text: code, prefix: 0 };
		}
		const asn = Number(value.trim().replace(/^as/iu, ""));
		if (!Number.isSafeInteger(asn) || asn <= 0) return null;
		return { kind: "as", numeric: asn, big: 0n, text: "", prefix: 0 };
	}

	private shadowKey(location: Location): string {
		switch (location.kind) {
			case "ipv4":
				return `4:${location.numeric}`;
			case "ipv6":
				return `6:${location.big.toString(16)}`;
			case "rangeV4":
				return `r4:${location.prefix}:${location.numeric}`;
			case "rangeV6":
				return `r6:${location.prefix}:${location.big.toString(16)}`;
			case "country":
				return `c:${location.text}`;
			default:
				return `a:${location.numeric}`;
		}
	}

	private read(location: Location): CrowdSecDecision | undefined {
		switch (location.kind) {
			case "ipv4":
				return this.ipv4.get(location.numeric);
			case "ipv6":
				return this.ipv6.get(location.big);
			case "rangeV4":
				return this.rangesV4.get(location.prefix)?.get(location.numeric);
			case "rangeV6":
				return this.rangesV6.get(location.prefix)?.get(location.big);
			case "country":
				return this.countries.get(location.text);
			default:
				return this.asns.get(location.numeric);
		}
	}

	private write(location: Location, decision: CrowdSecDecision): void {
		switch (location.kind) {
			case "ipv4":
				this.ipv4.set(location.numeric, decision);
				return;
			case "ipv6":
				this.ipv6.set(location.big, decision);
				return;
			case "rangeV4": {
				let bucket = this.rangesV4.get(location.prefix);
				if (!bucket) {
					bucket = new Map();
					this.rangesV4.set(location.prefix, bucket);
					this.prefixesV4 = [...this.rangesV4.keys()].sort((left, right) => right - left);
				}
				bucket.set(location.numeric, decision);
				return;
			}
			case "rangeV6": {
				let bucket = this.rangesV6.get(location.prefix);
				if (!bucket) {
					bucket = new Map();
					this.rangesV6.set(location.prefix, bucket);
					this.prefixesV6 = [...this.rangesV6.keys()].sort((left, right) => right - left);
				}
				bucket.set(location.big, decision);
				return;
			}
			case "country":
				this.countries.set(location.text, decision);
				return;
			default:
				this.asns.set(location.numeric, decision);
		}
	}

	private erase(location: Location): void {
		switch (location.kind) {
			case "ipv4":
				this.ipv4.delete(location.numeric);
				return;
			case "ipv6":
				this.ipv6.delete(location.big);
				return;
			case "rangeV4": {
				const bucket = this.rangesV4.get(location.prefix);
				if (!bucket) return;
				bucket.delete(location.numeric);
				if (bucket.size === 0) {
					this.rangesV4.delete(location.prefix);
					this.prefixesV4 = [...this.rangesV4.keys()].sort((left, right) => right - left);
				}
				return;
			}
			case "rangeV6": {
				const bucket = this.rangesV6.get(location.prefix);
				if (!bucket) return;
				bucket.delete(location.big);
				if (bucket.size === 0) {
					this.rangesV6.delete(location.prefix);
					this.prefixesV6 = [...this.rangesV6.keys()].sort((left, right) => right - left);
				}
				return;
			}
			case "country":
				this.countries.delete(location.text);
				return;
			default:
				this.asns.delete(location.numeric);
		}
	}

	/** Lets the request path bail before it parses anything. */
	get empty(): boolean {
		return (
			this.ipv4.size === 0 &&
			this.ipv6.size === 0 &&
			this.prefixesV4.length === 0 &&
			this.prefixesV6.length === 0 &&
			this.countries.size === 0 &&
			this.asns.size === 0
		);
	}

	/**
	 * Null when the decision is unusable: an unparseable value, an unindexed scope, a remediation
	 * the operator ignores, or a duration already run out (the LAPI does send expired entries).
	 */
	private materialize(raw: RawCrowdSecDecision, now: number, unknownFallback: CrowdSecRemediation | "ignore"): CrowdSecDecision | null {
		const scope = normalizeScope(raw.scope);
		if (!scope) return null;
		const remediation = normalizeRemediation(raw.type, unknownFallback);
		if (!remediation) return null;
		const value = typeof raw.value === "string" ? raw.value.trim() : "";
		if (!value) return null;
		const id = Number(raw.id);
		const expiresAt = decisionExpiry(raw, now);
		if (expiresAt !== null && expiresAt <= now) return null;
		return {
			id: Number.isSafeInteger(id) ? id : -1,
			remediation,
			origin: this.intern(typeof raw.origin === "string" && raw.origin ? raw.origin : "unknown"),
			scenario: this.intern(typeof raw.scenario === "string" && raw.scenario ? raw.scenario : ""),
			scope,
			value,
			expiresAt,
		};
	}

	private insert(decision: CrowdSecDecision): boolean {
		const location = this.locate(decision.scope, decision.value);
		if (!location) return false;
		const existing = this.read(location);
		if (!existing || existing.id === decision.id) {
			this.write(location, decision);
			return true;
		}

		// Two live decisions on the same value. Keep the stronger one visible and park the other.
		const key = this.shadowKey(location);
		const parked = (this.shadowed.get(key) ?? []).filter((entry) => entry.id !== decision.id);
		if (outranks(decision, existing)) {
			this.write(location, decision);
			parked.push(existing);
		} else {
			parked.push(decision);
		}
		this.shadowed.set(key, parked);
		return true;
	}

	private remove(scope: CrowdSecScope, value: string, id: number): void {
		const location = this.locate(scope, value);
		if (!location) return;
		const key = this.shadowKey(location);
		const parked = this.shadowed.get(key);
		const existing = this.read(location);

		if (existing && existing.id === id) {
			if (parked?.length) {
				// Promote the strongest decision still covering this value rather than unblocking it.
				let best = parked[0]!;
				for (const candidate of parked) if (outranks(candidate, best)) best = candidate;
				const remaining = parked.filter((entry) => entry.id !== best.id);
				this.write(location, best);
				if (remaining.length) this.shadowed.set(key, remaining);
				else this.shadowed.delete(key);
			} else {
				this.erase(location);
			}
			return;
		}

		if (!parked) return;
		const remaining = parked.filter((entry) => entry.id !== id);
		if (remaining.length) this.shadowed.set(key, remaining);
		else this.shadowed.delete(key);
	}

	private adopt(replacement: CrowdSecDecisionStore): void {
		this.ipv4 = replacement.ipv4;
		this.ipv6 = replacement.ipv6;
		this.rangesV4 = replacement.rangesV4;
		this.rangesV6 = replacement.rangesV6;
		this.prefixesV4 = replacement.prefixesV4;
		this.prefixesV6 = replacement.prefixesV6;
		this.countries = replacement.countries;
		this.asns = replacement.asns;
		this.shadowed = replacement.shadowed;
		this.interned = replacement.interned;
	}

	/** Replaces everything with a full snapshot, built into new maps and swapped in at the end. */
	applySnapshot(decisions: readonly RawCrowdSecDecision[], now = Date.now(), unknownFallback: CrowdSecRemediation | "ignore" = "ban"): number {
		const replacement = new CrowdSecDecisionStore();
		let accepted = 0;
		for (const raw of decisions) {
			const decision = replacement.materialize(raw, now, unknownFallback);
			if (decision && replacement.insert(decision)) accepted += 1;
		}
		this.adopt(replacement);
		return accepted;
	}

	/**
	 * The same rebuild, yielding to the event loop every `chunkSize` decisions.
	 *
	 * Half a million decisions take the better part of a second to build, which a reverse proxy
	 * cannot stall for. Yielding is safe because the swap is atomic: requests arriving mid-rebuild
	 * keep matching the previous snapshot.
	 */
	async applySnapshotYielding(
		decisions: readonly RawCrowdSecDecision[],
		now = Date.now(),
		unknownFallback: CrowdSecRemediation | "ignore" = "ban",
		chunkSize = 4_000,
	): Promise<number> {
		const replacement = new CrowdSecDecisionStore();
		let accepted = 0;
		for (let index = 0; index < decisions.length; index++) {
			const decision = replacement.materialize(decisions[index]!, now, unknownFallback);
			if (decision && replacement.insert(decision)) accepted += 1;
			if ((index + 1) % chunkSize === 0) await new Promise<void>((resolve) => setImmediate(resolve));
		}
		this.adopt(replacement);
		return accepted;
	}

	applyDelta(
		added: readonly RawCrowdSecDecision[],
		deleted: readonly RawCrowdSecDecision[],
		now = Date.now(),
		unknownFallback: CrowdSecRemediation | "ignore" = "ban",
	): { added: number; removed: number } {
		let removed = 0;
		for (const raw of deleted) {
			const scope = normalizeScope(raw.scope);
			const value = typeof raw.value === "string" ? raw.value.trim() : "";
			if (!scope || !value) continue;
			const id = Number(raw.id);
			this.remove(scope, value, Number.isSafeInteger(id) ? id : -1);
			removed += 1;
		}
		let inserted = 0;
		for (const raw of added) {
			const decision = this.materialize(raw, now, unknownFallback);
			if (decision && this.insert(decision)) inserted += 1;
		}
		return { added: inserted, removed };
	}

	/**
	 * The request-path lookup, ordered by specificity: an exact address beats a range, which beats
	 * an ASN, which beats a country. The caller passes the country and ASN it already resolved, so
	 * those scopes cost one map lookup each and no extra GeoIP work.
	 */
	lookup(ip: string, countryCode: string | null, asn: number | null, now = Date.now()): CrowdSecDecision | null {
		if (this.empty) return null;

		const address = ip === "unknown" ? null : numericAddress(ip);
		if (address) {
			if (address.version === 4) {
				const exact = this.ipv4.get(address.v4);
				if (exact) {
					const live = this.live(exact, { kind: "ipv4", numeric: address.v4, big: 0n, text: "", prefix: 32 }, now);
					if (live) return live;
				}
				for (const prefix of this.prefixesV4) {
					const hit = this.rangesV4.get(prefix)?.get(maskIpv4(address.v4, prefix));
					if (!hit) continue;
					const live = this.live(hit, { kind: "rangeV4", numeric: maskIpv4(address.v4, prefix), big: 0n, text: "", prefix }, now);
					if (live) return live;
				}
			} else {
				const exact = this.ipv6.get(address.v6);
				if (exact) {
					const live = this.live(exact, { kind: "ipv6", numeric: 0, big: address.v6, text: "", prefix: 128 }, now);
					if (live) return live;
				}
				for (const prefix of this.prefixesV6) {
					const masked = maskIpv6(address.v6, prefix);
					const hit = this.rangesV6.get(prefix)?.get(masked);
					if (!hit) continue;
					const live = this.live(hit, { kind: "rangeV6", numeric: 0, big: masked, text: "", prefix }, now);
					if (live) return live;
				}
			}
		}

		if (asn !== null && this.asns.size) {
			const hit = this.asns.get(asn);
			if (hit) {
				const live = this.live(hit, { kind: "as", numeric: asn, big: 0n, text: "", prefix: 0 }, now);
				if (live) return live;
			}
		}

		if (countryCode && this.countries.size) {
			const code = countryCode.toUpperCase();
			const hit = this.countries.get(code);
			if (hit) {
				const live = this.live(hit, { kind: "country", numeric: 0, big: 0n, text: code, prefix: 0 }, now);
				if (live) return live;
			}
		}

		return null;
	}

	/**
	 * The decision if still in force, evicting it (and promoting anything behind it) once lapsed.
	 * Checking here rather than on a timer means a stalled poll degrades safely, with bans ageing
	 * out on their own instead of sticking forever.
	 */
	private live(decision: CrowdSecDecision, location: Location, now: number): CrowdSecDecision | null {
		if (decision.expiresAt === null || decision.expiresAt > now) return decision;
		this.remove(decision.scope, decision.value, decision.id);
		const promoted = this.read(location);
		return promoted && (promoted.expiresAt === null || promoted.expiresAt > now) ? promoted : null;
	}

	/** Run periodically so lapsed decisions do not hold memory forever. */
	sweepExpired(now = Date.now()): number {
		const expired: CrowdSecDecision[] = [];
		const collect = (decision: CrowdSecDecision) => {
			if (decision.expiresAt !== null && decision.expiresAt <= now) expired.push(decision);
		};
		for (const decision of this.ipv4.values()) collect(decision);
		for (const decision of this.ipv6.values()) collect(decision);
		for (const bucket of this.rangesV4.values()) for (const decision of bucket.values()) collect(decision);
		for (const bucket of this.rangesV6.values()) for (const decision of bucket.values()) collect(decision);
		for (const decision of this.countries.values()) collect(decision);
		for (const decision of this.asns.values()) collect(decision);
		for (const list of this.shadowed.values()) for (const decision of list) collect(decision);
		for (const decision of expired) this.remove(decision.scope, decision.value, decision.id);
		return expired.length;
	}

	stats(): CrowdSecStoreStats {
		const byScope: Record<CrowdSecScope, number> = { ip: 0, range: 0, country: 0, as: 0 };
		const byRemediation: Record<CrowdSecRemediation, number> = { ban: 0, captcha: 0 };
		const byOrigin: Record<string, number> = {};
		let total = 0;
		const count = (decision: CrowdSecDecision) => {
			total += 1;
			byScope[decision.scope] += 1;
			byRemediation[decision.remediation] += 1;
			byOrigin[decision.origin] = (byOrigin[decision.origin] ?? 0) + 1;
		};
		for (const decision of this.ipv4.values()) count(decision);
		for (const decision of this.ipv6.values()) count(decision);
		for (const bucket of this.rangesV4.values()) for (const decision of bucket.values()) count(decision);
		for (const bucket of this.rangesV6.values()) for (const decision of bucket.values()) count(decision);
		for (const decision of this.countries.values()) count(decision);
		for (const decision of this.asns.values()) count(decision);
		return { total, byScope, byRemediation, byOrigin };
	}

	/** Used to persist a snapshot across restarts. */
	export(): CrowdSecDecision[] {
		const all: CrowdSecDecision[] = [];
		for (const decision of this.ipv4.values()) all.push(decision);
		for (const decision of this.ipv6.values()) all.push(decision);
		for (const bucket of this.rangesV4.values()) for (const decision of bucket.values()) all.push(decision);
		for (const bucket of this.rangesV6.values()) for (const decision of bucket.values()) all.push(decision);
		for (const decision of this.countries.values()) all.push(decision);
		for (const decision of this.asns.values()) all.push(decision);
		for (const list of this.shadowed.values()) for (const decision of list) all.push(decision);
		return all;
	}

	clear(): void {
		this.ipv4 = new Map();
		this.ipv6 = new Map();
		this.rangesV4 = new Map();
		this.rangesV6 = new Map();
		this.prefixesV4 = [];
		this.prefixesV6 = [];
		this.countries = new Map();
		this.asns = new Map();
		this.shadowed = new Map();
		this.interned = new Map();
	}
}

/** The process-wide store the request path reads from. */
export const crowdSecDecisions = new CrowdSecDecisionStore();
