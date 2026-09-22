/**
 * CrowdSec decision lookups, the one piece of the integration that runs on every
 * request (src/services/crowdsec-decision-store.ts, called from the gateway in
 * src/index.ts). A CrowdSec deployment subscribed to the community blocklist
 * routinely holds 10k-500k decisions, so the question this suite answers is
 * whether that number affects per-request cost at all.
 *
 * The comparison row is the linear CIDR scan src/services/ip-rule-service.ts
 * performs for admin-authored rules - the approach a naive CrowdSec integration
 * would have reused - measured over a deliberately small 500-rule list.
 */
import { CrowdSecDecisionStore, type RawCrowdSecDecision } from "../src/services/crowdsec-decision-store.ts";
import { cidrContains, parseCidr, type ParsedCidr } from "../src/utils/ip.ts";
import { measureRate, printResults, saveSuiteRun, type BenchResult } from "./lib/harness.ts";

const SUITE = "crowdsec";

/** Deterministic pseudo-random source, so every run indexes the same address set. */
function makeRandom(seed: number): () => number {
	let state = seed >>> 0;
	return () => {
		state = (state * 1_664_525 + 1_013_904_223) >>> 0;
		return state / 0x100000000;
	};
}

function ipv4(random: () => number): string {
	return `${1 + Math.floor(random() * 223)}.${Math.floor(random() * 256)}.${Math.floor(random() * 256)}.${Math.floor(random() * 256)}`;
}

/**
 * Builds a decision set shaped like a real one: overwhelmingly exact IPv4 addresses from the
 * community blocklist, a few percent of ranges spread across the prefix lengths operators
 * actually use, and a sprinkling of IPv6, country, and ASN decisions.
 */
function decisionSet(count: number, seed = 7): RawCrowdSecDecision[] {
	const random = makeRandom(seed);
	const rangePrefixes = [16, 20, 22, 23, 24, 25, 26, 28];
	const decisions: RawCrowdSecDecision[] = [];
	for (let index = 0; index < count; index++) {
		const roll = random();
		if (roll < 0.94) {
			decisions.push({ id: index, type: "ban", scope: "Ip", value: ipv4(random), duration: "4h", origin: "CAPI", scenario: "crowdsecurity/http-probing" });
		} else if (roll < 0.985) {
			const prefix = rangePrefixes[Math.floor(random() * rangePrefixes.length)]!;
			decisions.push({
				id: index,
				type: "ban",
				scope: "Range",
				value: `${Math.floor(random() * 223) + 1}.${Math.floor(random() * 256)}.${Math.floor(random() * 256)}.0/${prefix}`,
				duration: "8h",
				origin: "lists:firehol_cruzit_web_attacks",
				scenario: "blocklist",
			});
		} else if (roll < 0.995) {
			decisions.push({
				id: index,
				type: "ban",
				scope: "Range",
				value: `2001:db8:${Math.floor(random() * 65536).toString(16)}::/48`,
				duration: "8h",
				origin: "CAPI",
				scenario: "crowdsecurity/http-probing",
			});
		} else {
			decisions.push({
				id: index,
				type: "captcha",
				scope: "AS",
				value: String(1 + Math.floor(random() * 60000)),
				duration: "12h",
				origin: "cscli",
				scenario: "manual",
			});
		}
	}
	return decisions;
}

/** A mixed probe set: some addresses that hit, most that miss, which is the real request mix. */
function probeAddresses(decisions: RawCrowdSecDecision[], count: number): string[] {
	const random = makeRandom(99);
	const exact = decisions.filter((entry) => entry.scope === "Ip").map((entry) => entry.value as string);
	const probes: string[] = [];
	for (let index = 0; index < count; index++) {
		probes.push(random() < 0.1 && exact.length ? exact[Math.floor(random() * exact.length)]! : ipv4(random));
	}
	return probes;
}

function benchmarkStore(size: number, results: BenchResult[]): Promise<BenchResult> {
	const store = new CrowdSecDecisionStore();
	const accepted = store.applySnapshot(decisionSet(size));
	const probes = probeAddresses(decisionSet(size), 4_096);
	const mask = probes.length - 1;
	let cursor = 0;
	return measureRate(
		SUITE,
		`lookup against ${size.toLocaleString("en-US")} decisions`,
		"ops/sec",
		() => {
			// Batched per sample so timer overhead does not dominate a sub-microsecond operation.
			for (let index = 0; index < 1_000; index++) {
				store.lookup(probes[cursor++ & mask]!, "US", 64496);
			}
			return 1_000;
		},
		{ meta: { decisions: accepted, stats: store.stats().byScope } },
	);
}

export async function run(): Promise<BenchResult[]> {
	const results: BenchResult[] = [];

	for (const size of [10_000, 100_000, 500_000]) {
		results.push(await benchmarkStore(size, results));
	}

	// What a `startup=true` resync spends before it can swap the new set in.
	for (const size of [100_000, 500_000]) {
		const raw = decisionSet(size);
		const store = new CrowdSecDecisionStore();
		results.push(
			await measureRate(SUITE, `build snapshot of ${size.toLocaleString("en-US")} decisions`, "ops/sec", () => {
				store.applySnapshot(raw);
				return 1;
			}),
		);
	}

	// The rejected alternative: ip-rule-service's linear CIDR scan, over only 500 rules.
	const random = makeRandom(11);
	const linear: ParsedCidr[] = [];
	for (let index = 0; index < 500; index++) {
		const parsed = parseCidr(`${Math.floor(random() * 223) + 1}.${Math.floor(random() * 256)}.${Math.floor(random() * 256)}.0/24`);
		if (parsed) linear.push(parsed);
	}
	const linearProbes = probeAddresses(decisionSet(1_000), 4_096);
	const linearMask = linearProbes.length - 1;
	let linearCursor = 0;
	results.push(
		await measureRate(SUITE, "linear CIDR scan over 500 rules (rejected approach)", "ops/sec", () => {
			for (let index = 0; index < 100; index++) {
				const ip = linearProbes[linearCursor++ & linearMask]!;
				linear.find((cidr) => cidrContains(cidr, ip));
			}
			return 100;
		}),
	);

	return results;
}

if (import.meta.main) {
	const results = await run();
	if (process.env.BENCH_JSON_STDOUT) {
		console.log(JSON.stringify(results));
	} else {
		printResults(results);
		console.log(await saveSuiteRun(results, `${import.meta.dir}/results`, "11-crowdsec-lookup"));
	}
}
