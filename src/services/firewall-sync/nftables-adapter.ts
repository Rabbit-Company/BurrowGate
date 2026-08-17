import { config } from "../../config.ts";
import { splitCidrsByFamily } from "../../utils/ip.ts";

export { splitCidrsByFamily };

export const NFT_TABLE = "burrowgate";
export const NFT_CHAIN = "input";
export const NFT_SET_V4 = "banned_ips";
export const NFT_SET_V6 = "banned_ips_v6";
export const NFT_RULE_COMMENT = "burrowgate-managed";

export interface NftablesProviderConfig {
	nftBinaryPath: string;
	useSudo: boolean;
}

export function parseNftablesProviderConfig(value: unknown): NftablesProviderConfig {
	const raw = (value ?? {}) as Record<string, unknown>;
	return {
		nftBinaryPath: typeof raw.nftBinaryPath === "string" && raw.nftBinaryPath.trim() ? raw.nftBinaryPath.trim() : "nft",
		useSudo: raw.useSudo === true,
	};
}

/** Idempotent bootstrap of BurrowGate's isolated table/sets/chain. Safe to run every tick. */
export function buildNftTableSetChainScript(): string {
	return (
		[
			`add table inet ${NFT_TABLE}`,
			`add set inet ${NFT_TABLE} ${NFT_SET_V4} { type ipv4_addr; flags interval; auto-merge; }`,
			`add set inet ${NFT_TABLE} ${NFT_SET_V6} { type ipv6_addr; flags interval; auto-merge; }`,
			`add chain inet ${NFT_TABLE} ${NFT_CHAIN} { type filter hook input priority -10; policy accept; }`,
		].join("\n") + "\n"
	);
}

/** `add rule` is not idempotent (it always appends), so callers must only request the families that are actually missing the marker rule. */
export function buildNftAddRuleScript(needV4: boolean, needV6: boolean): string {
	const lines: string[] = [];
	if (needV4) lines.push(`add rule inet ${NFT_TABLE} ${NFT_CHAIN} ip saddr @${NFT_SET_V4} counter drop comment "${NFT_RULE_COMMENT}"`);
	if (needV6) lines.push(`add rule inet ${NFT_TABLE} ${NFT_CHAIN} ip6 saddr @${NFT_SET_V6} counter drop comment "${NFT_RULE_COMMENT}"`);
	return lines.length ? lines.join("\n") + "\n" : "";
}

/** Atomic full replace: `flush` + `add element` inside one `nft -f` file commits as a single kernel transaction. */
export function buildNftReplaceScript(cidrsV4: string[], cidrsV6: string[]): string {
	const lines: string[] = [`flush set inet ${NFT_TABLE} ${NFT_SET_V4}`];
	if (cidrsV4.length > 0) lines.push(`add element inet ${NFT_TABLE} ${NFT_SET_V4} { ${cidrsV4.join(", ")} }`);
	lines.push(`flush set inet ${NFT_TABLE} ${NFT_SET_V6}`);
	if (cidrsV6.length > 0) lines.push(`add element inet ${NFT_TABLE} ${NFT_SET_V6} { ${cidrsV6.join(", ")} }`);
	return lines.join("\n") + "\n";
}

/** Removing the whole table also drops its chain, sets, and rule in one atomic step - nothing BurrowGate-managed is left behind. */
export function buildNftDeleteTableScript(): string {
	return `delete table inet ${NFT_TABLE}\n`;
}

interface NftChainListing {
	nftables?: Array<{ rule?: { comment?: string; expr?: Array<{ match?: { left?: { payload?: { protocol?: string; field?: string } } } }> } }>;
}

/**
 * `nft -j list chain` reports the address family via `payload.protocol` ("ip" | "ip6"), not `field`
 * (both v4 and v6 "source address" matches use `field: "saddr"`) - protocol is the real discriminator.
 */
export function parseNftChainRulesJson(jsonText: string): { hasV4Rule: boolean; hasV6Rule: boolean } {
	let parsed: NftChainListing;
	try {
		parsed = JSON.parse(jsonText) as NftChainListing;
	} catch {
		return { hasV4Rule: false, hasV6Rule: false };
	}
	let hasV4Rule = false;
	let hasV6Rule = false;
	for (const entry of parsed.nftables ?? []) {
		const rule = entry.rule;
		if (!rule || rule.comment !== NFT_RULE_COMMENT) continue;
		const protocol = rule.expr?.find((expr) => expr.match?.left?.payload?.field === "saddr")?.match?.left?.payload?.protocol;
		if (protocol === "ip") hasV4Rule = true;
		if (protocol === "ip6") hasV6Rule = true;
	}
	return { hasV4Rule, hasV6Rule };
}

export interface NftRunResult {
	stdout: string;
	exitCode: number;
}

function spawnNft(command: string[]) {
	return Bun.spawn(command, { stdin: "pipe", stdout: "pipe", stderr: "pipe" });
}

async function runNft(cfg: NftablesProviderConfig, args: string[], stdin: string): Promise<string> {
	const command = cfg.useSudo ? ["sudo", "-n", cfg.nftBinaryPath, ...args] : [cfg.nftBinaryPath, ...args];
	let proc: ReturnType<typeof spawnNft>;
	try {
		proc = spawnNft(command);
	} catch (error) {
		throw new Error(`Unable to launch '${cfg.nftBinaryPath}': ${error instanceof Error ? error.message : String(error)}. Is nftables installed and on PATH?`);
	}
	proc.stdin.write(stdin);
	await proc.stdin.end();
	const timeout = setTimeout(() => proc.kill(), config.firewallSync.nftTimeoutMs);
	let stdout: string;
	let stderr: string;
	let exitCode: number;
	try {
		[stdout, stderr, exitCode] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);
	} finally {
		clearTimeout(timeout);
	}
	if (exitCode !== 0) {
		const detail = (stderr || stdout).trim();
		if (/operation not permitted/iu.test(detail)) {
			throw new Error(
				`nft lacks permission to modify the ruleset (${detail}). Grant it via: sudo setcap cap_net_admin+ep $(which ${cfg.nftBinaryPath}) - or enable "Use sudo" with a narrow sudoers rule.`,
			);
		}
		throw new Error(`nft exited ${exitCode}: ${detail || "no output"}`);
	}
	return stdout;
}

export async function nftablesReconcile(configJson: string, cidrs: string[]): Promise<void> {
	const cfg = parseNftablesProviderConfig(JSON.parse(configJson));
	await runNft(cfg, ["-f", "-"], buildNftTableSetChainScript());
	const chainJson = await runNft(cfg, ["-j", "list", "chain", "inet", NFT_TABLE, NFT_CHAIN], "");
	const { hasV4Rule, hasV6Rule } = parseNftChainRulesJson(chainJson);
	const addRuleScript = buildNftAddRuleScript(!hasV4Rule, !hasV6Rule);
	if (addRuleScript) await runNft(cfg, ["-f", "-"], addRuleScript);
	const { v4, v6 } = splitCidrsByFamily(cidrs);
	await runNft(cfg, ["-f", "-"], buildNftReplaceScript(v4, v6));
}

/** Best-effort: if the table was never created (or was already removed out-of-band), there's nothing to clean up. */
export async function nftablesTeardown(configJson: string): Promise<void> {
	const cfg = parseNftablesProviderConfig(JSON.parse(configJson));
	try {
		await runNft(cfg, ["-f", "-"], buildNftDeleteTableScript());
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		if (/no such file or directory|does not exist/iu.test(message)) return;
		throw error;
	}
}

export async function nftablesTestConnection(configJson: string): Promise<{ ok: boolean; message: string }> {
	const cfg = parseNftablesProviderConfig(JSON.parse(configJson));
	try {
		await runNft(cfg, ["--check", "-f", "-"], buildNftTableSetChainScript());
		return { ok: true, message: `'${cfg.nftBinaryPath}' is reachable and permitted to manage the inet ${NFT_TABLE} table.` };
	} catch (error) {
		return { ok: false, message: error instanceof Error ? error.message : String(error) };
	}
}
