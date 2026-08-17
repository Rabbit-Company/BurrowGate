import { config } from "../../config.ts";
import { sha1Hex } from "../../utils/crypto.ts";
import { splitCidrsByFamily } from "../../utils/ip.ts";
import { decryptSecret } from "../secret-encryption-service.ts";

/** Hard protocol limit: OVH's per-IP edge firewall has exactly 20 fixed rule slots (sequence 0-19). */
export const OVH_MAX_RULES = 20;

export interface OvhProviderConfig {
	endpoint: string;
	applicationKey: string;
	applicationSecretEncrypted: string;
	consumerKeyEncrypted: string;
	ipBlock: string;
}

export function normalizeOvhEndpoint(value: unknown): string {
	return typeof value === "string" && value.trim() ? value.trim().replace(/\/+$/u, "") : "https://eu.api.ovh.com";
}

/**
 * All OVH v1 API paths are versioned (e.g. eu.api.ovh.com/1.0/ip).
 */
export function ovhApiRoot(endpoint: string): string {
	const root = normalizeOvhEndpoint(endpoint);
	return root.endsWith("/1.0") ? root : `${root}/1.0`;
}

export function parseOvhProviderConfig(value: unknown): OvhProviderConfig {
	const raw = (value ?? {}) as Record<string, unknown>;
	return {
		endpoint: normalizeOvhEndpoint(raw.endpoint),
		applicationKey: typeof raw.applicationKey === "string" ? raw.applicationKey.trim() : "",
		applicationSecretEncrypted: typeof raw.applicationSecretEncrypted === "string" ? raw.applicationSecretEncrypted : "",
		consumerKeyEncrypted: typeof raw.consumerKeyEncrypted === "string" ? raw.consumerKeyEncrypted : "",
		ipBlock: typeof raw.ipBlock === "string" ? raw.ipBlock.trim() : "",
	};
}

/** `{ip}` (an ipBlock, e.g. "51.75.1.2/32") and `{ipOnFirewall}` (a bare ipv4 address) are the same address for a single-IP VPS. */
export function ovhFirewallIpAddress(ipBlock: string): string {
	return ipBlock.split("/")[0] ?? ipBlock;
}

/**
 * The rule `source` field is typed `ipv4Block` - OVH rejects a bare address ("Given data (x.x.x.x) is not valid
 * for type ipv4Block"). BurrowGate's own ban rules are frequently stored without a prefix (a single-IP auto-ban
 * has no "/32" suffix), so every source needs one appended before it's sent.
 */
export function normalizeOvhIpv4Source(cidr: string): string {
	return cidr.includes("/") ? cidr : `${cidr}/32`;
}

function ipDetailPath(ipBlock: string): string {
	return `/ip/${encodeURIComponent(ipBlock)}`;
}
function firewallPath(ipBlock: string): string {
	return `/ip/${encodeURIComponent(ipBlock)}/firewall`;
}
function firewallIpPath(ipBlock: string, firewallIp: string): string {
	return `${firewallPath(ipBlock)}/${encodeURIComponent(firewallIp)}`;
}
function ruleListPath(ipBlock: string, firewallIp: string): string {
	return `${firewallIpPath(ipBlock, firewallIp)}/rule`;
}
function rulePath(ipBlock: string, firewallIp: string, sequence: number): string {
	return `${ruleListPath(ipBlock, firewallIp)}/${sequence}`;
}

interface OvhRequestSpec {
	url: string;
	init: RequestInit;
}

/** OVH's legacy request-signing scheme: `$1$` + sha1(appSecret+consumerKey+method+url+body+timestamp). Pure and testable given a fixed timestamp. */
export async function ovhSignature(appSecret: string, consumerKey: string, method: string, url: string, body: string, timestamp: number): Promise<string> {
	return `$1$${await sha1Hex(`${appSecret}+${consumerKey}+${method}+${url}+${body}+${timestamp}`)}`;
}

export async function buildOvhRequest(
	cfg: Pick<OvhProviderConfig, "endpoint" | "applicationKey">,
	appSecret: string,
	consumerKey: string,
	method: string,
	path: string,
	timestamp: number,
	body?: unknown,
): Promise<OvhRequestSpec> {
	const url = `${ovhApiRoot(cfg.endpoint)}${path}`;
	const bodyText = body === undefined ? "" : JSON.stringify(body);
	const signature = await ovhSignature(appSecret, consumerKey, method, url, bodyText, timestamp);
	const headers: Record<string, string> = {
		"X-Ovh-Application": cfg.applicationKey,
		"X-Ovh-Consumer": consumerKey,
		"X-Ovh-Timestamp": String(timestamp),
		"X-Ovh-Signature": signature,
		accept: "application/json",
	};
	if (bodyText) headers["content-type"] = "application/json";
	return { url, init: { method, headers, body: bodyText || undefined, signal: AbortSignal.timeout(config.firewallSync.requestTimeoutMs) } };
}

async function fetchOvhJson(spec: OvhRequestSpec): Promise<unknown> {
	const response = await fetch(spec.url, spec.init);
	const text = await response.text();
	if (!response.ok) throw new Error(`HTTP ${response.status}: ${text.slice(0, 300)}`);
	try {
		return text ? JSON.parse(text) : null;
	} catch {
		throw new Error(`Unexpected non-JSON response: ${text.slice(0, 300)}`);
	}
}

function isOvhNotFound(error: unknown): boolean {
	return error instanceof Error && /HTTP 404/u.test(error.message);
}

async function ovhServerTimestamp(endpoint: string): Promise<number> {
	const response = await fetch(`${ovhApiRoot(endpoint)}/auth/time`, { signal: AbortSignal.timeout(config.firewallSync.requestTimeoutMs) });
	if (!response.ok) throw new Error(`Unable to fetch OVH server time: HTTP ${response.status}`);
	const value = Number((await response.text()).trim());
	if (!Number.isFinite(value)) throw new Error("Unable to parse OVH server time");
	return value;
}

export interface OvhExistingRule {
	sequence: number;
	source: string | null;
	action: string;
	protocol: string;
	sourcePort: string | null;
	destinationPort: string | null;
}

export interface OvhRuleDiff {
	toDelete: number[];
	toCreate: Array<{ sequence: number; source: string }>;
}

/**
 * OVH's rule API has no comment/label field, so there's no way to ask the API which of the 20 slots are
 * BurrowGate's. The admin may have their own rules on the same IP for other reasons (a manual allow rule, a
 * port-scoped block, etc.). Only a rule with exactly BurrowGate's own shape - a plain ipv4 deny with no port
 * restriction - is treated as "ours"; anything else is left completely alone (never deleted, never reused),
 * since an automated sync has no business touching a rule it didn't create.
 */
export function isOvhManagedRule(rule: OvhExistingRule): boolean {
	return rule.action === "deny" && rule.protocol === "ipv4" && !rule.sourcePort && !rule.destinationPort;
}

/**
 * Keeps unchanged managed rules in place instead of flush+recreate (zero API calls when the ban list hasn't
 * changed), never touches a rule that isn't BurrowGate's own, and reduces the effective capacity by however many
 * slots those foreign rules occupy.
 */
export function computeOvhRuleDiff(desiredCidrs: string[], existingRules: OvhExistingRule[]): OvhRuleDiff {
	const reservedSequences = new Set(existingRules.filter((rule) => !isOvhManagedRule(rule)).map((rule) => rule.sequence));
	const availableSlots = Math.max(0, OVH_MAX_RULES - reservedSequences.size);
	const capped = desiredCidrs.slice(0, availableSlots);
	const desiredSet = new Set(capped);
	const keptSources = new Set<string>();
	const occupiedSequences = new Set<number>(reservedSequences);
	const toDelete: number[] = [];
	for (const rule of existingRules) {
		if (!isOvhManagedRule(rule)) continue;
		if (rule.source && desiredSet.has(rule.source) && !keptSources.has(rule.source)) {
			keptSources.add(rule.source);
			occupiedSequences.add(rule.sequence);
		} else {
			toDelete.push(rule.sequence);
		}
	}
	const missing = capped.filter((cidr) => !keptSources.has(cidr));
	const freeSequences: number[] = [];
	for (let sequence = 0; sequence < OVH_MAX_RULES; sequence++) if (!occupiedSequences.has(sequence)) freeSequences.push(sequence);
	const toCreate = missing.map((source, index) => ({ sequence: freeSequences[index]!, source }));
	return { toDelete, toCreate };
}

/** POST /ip/{ip}/firewall's body parameter is named `ipOnFirewall` (its OVH *type* happens to also be called `ipv4`, which is an easy mix-up). */
export function ovhEnableFirewallRequestBody(firewallIp: string): { ipOnFirewall: string } {
	return { ipOnFirewall: firewallIp };
}

async function ovhEnsureFirewallEnabled(
	cfg: Pick<OvhProviderConfig, "endpoint" | "applicationKey" | "ipBlock">,
	appSecret: string,
	consumerKey: string,
	firewallIp: string,
	timestamp: number,
): Promise<void> {
	const getSpec = await buildOvhRequest(cfg, appSecret, consumerKey, "GET", firewallIpPath(cfg.ipBlock, firewallIp), timestamp);
	try {
		await fetchOvhJson(getSpec);
		return;
	} catch (error) {
		if (!isOvhNotFound(error)) throw error;
	}
	const createSpec = await buildOvhRequest(cfg, appSecret, consumerKey, "POST", firewallPath(cfg.ipBlock), timestamp, ovhEnableFirewallRequestBody(firewallIp));
	await fetchOvhJson(createSpec);
}

async function ovhFetchExistingRules(
	cfg: Pick<OvhProviderConfig, "endpoint" | "applicationKey" | "ipBlock">,
	appSecret: string,
	consumerKey: string,
	firewallIp: string,
	timestamp: number,
): Promise<OvhExistingRule[]> {
	const listSpec = await buildOvhRequest(cfg, appSecret, consumerKey, "GET", ruleListPath(cfg.ipBlock, firewallIp), timestamp);
	const sequences = (await fetchOvhJson(listSpec)) as number[];
	return await Promise.all(
		sequences.map(async (sequence) => {
			const spec = await buildOvhRequest(cfg, appSecret, consumerKey, "GET", rulePath(cfg.ipBlock, firewallIp, sequence), timestamp);
			return (await fetchOvhJson(spec)) as OvhExistingRule;
		}),
	);
}

export async function ovhReconcile(configJson: string, cidrs: string[]): Promise<void> {
	const cfg = parseOvhProviderConfig(JSON.parse(configJson));
	if (!cfg.applicationKey || !cfg.applicationSecretEncrypted || !cfg.consumerKeyEncrypted) {
		throw new Error("OVH application key, application secret, and consumer key are all required");
	}
	if (!cfg.ipBlock) throw new Error("No OVH IP selected - use “Load IPs” and pick one");
	const appSecret = await decryptSecret(cfg.applicationSecretEncrypted);
	const consumerKey = await decryptSecret(cfg.consumerKeyEncrypted);
	const firewallIp = ovhFirewallIpAddress(cfg.ipBlock);
	const timestamp = await ovhServerTimestamp(cfg.endpoint);
	await ovhEnsureFirewallEnabled(cfg, appSecret, consumerKey, firewallIp, timestamp);
	const existing = await ovhFetchExistingRules(cfg, appSecret, consumerKey, firewallIp, timestamp);
	// The edge firewall's `source` field is typed ipv4Block specifically - no IPv6 support.
	const { v4 } = splitCidrsByFamily(cidrs);
	const diff = computeOvhRuleDiff(v4.map(normalizeOvhIpv4Source), existing);
	await Promise.all(
		diff.toDelete.map(async (sequence) => {
			const spec = await buildOvhRequest(cfg, appSecret, consumerKey, "DELETE", rulePath(cfg.ipBlock, firewallIp, sequence), timestamp);
			try {
				await fetchOvhJson(spec);
			} catch (error) {
				if (!isOvhNotFound(error)) throw error;
			}
		}),
	);
	await Promise.all(
		diff.toCreate.map(async ({ sequence, source }) => {
			const spec = await buildOvhRequest(cfg, appSecret, consumerKey, "POST", ruleListPath(cfg.ipBlock, firewallIp), timestamp, {
				action: "deny",
				protocol: "ipv4",
				sequence,
				source,
			});
			await fetchOvhJson(spec);
		}),
	);
}

export async function ovhTestConnection(configJson: string): Promise<{ ok: boolean; message: string }> {
	const cfg = parseOvhProviderConfig(JSON.parse(configJson));
	if (!cfg.applicationKey) return { ok: false, message: "Application key is required" };
	if (!cfg.applicationSecretEncrypted) return { ok: false, message: "Application secret is required" };
	if (!cfg.consumerKeyEncrypted) return { ok: false, message: "Consumer key is required - use “Request access”" };
	if (!cfg.ipBlock) return { ok: false, message: "No OVH IP selected - use “Load IPs” and pick one" };
	try {
		const appSecret = await decryptSecret(cfg.applicationSecretEncrypted);
		const consumerKey = await decryptSecret(cfg.consumerKeyEncrypted);
		const timestamp = await ovhServerTimestamp(cfg.endpoint);
		const firewallIp = ovhFirewallIpAddress(cfg.ipBlock);
		const spec = await buildOvhRequest(cfg, appSecret, consumerKey, "GET", firewallIpPath(cfg.ipBlock, firewallIp), timestamp);
		let enabled = true;
		try {
			await fetchOvhJson(spec);
		} catch (error) {
			if (isOvhNotFound(error)) enabled = false;
			else throw error;
		}
		return {
			ok: true,
			message: enabled
				? `Connected. Edge firewall already enabled for ${firewallIp}.`
				: `Connected. Edge firewall for ${firewallIp} will be enabled on first sync.`,
		};
	} catch (error) {
		return { ok: false, message: error instanceof Error ? error.message : String(error) };
	}
}

export async function ovhTeardown(configJson: string): Promise<void> {
	const cfg = parseOvhProviderConfig(JSON.parse(configJson));
	if (!cfg.applicationKey || !cfg.applicationSecretEncrypted || !cfg.consumerKeyEncrypted || !cfg.ipBlock) return;
	const appSecret = await decryptSecret(cfg.applicationSecretEncrypted);
	const consumerKey = await decryptSecret(cfg.consumerKeyEncrypted);
	const firewallIp = ovhFirewallIpAddress(cfg.ipBlock);
	const timestamp = await ovhServerTimestamp(cfg.endpoint);
	const spec = await buildOvhRequest(cfg, appSecret, consumerKey, "DELETE", firewallIpPath(cfg.ipBlock, firewallIp), timestamp);
	try {
		await fetchOvhJson(spec);
	} catch (error) {
		if (!isOvhNotFound(error)) throw error;
	}
}

export interface OvhIpOption {
	block: string;
	serviceName: string | null;
}

export interface OvhListIpsInput {
	endpoint: string;
	applicationKey: string;
	applicationSecret?: string;
	consumerKey?: string;
	existingConfigJson?: string | null;
}

/** Used by the admin UI's "Load IPs" button - works against unsaved form values, falling back to stored secrets when a field was left blank while editing. */
export async function ovhListIps(input: OvhListIpsInput): Promise<OvhIpOption[]> {
	const endpoint = normalizeOvhEndpoint(input.endpoint);
	const applicationKey = input.applicationKey.trim();
	if (!applicationKey) throw new Error("Application key is required");
	let appSecret = input.applicationSecret?.trim() ?? "";
	let consumerKey = input.consumerKey?.trim() ?? "";
	if (!appSecret || !consumerKey) {
		const existing = input.existingConfigJson ? parseOvhProviderConfig(JSON.parse(input.existingConfigJson)) : null;
		if (!appSecret) {
			if (!existing?.applicationSecretEncrypted) throw new Error("Application secret is required");
			appSecret = await decryptSecret(existing.applicationSecretEncrypted);
		}
		if (!consumerKey) {
			if (!existing?.consumerKeyEncrypted) throw new Error("Consumer key is required");
			consumerKey = await decryptSecret(existing.consumerKeyEncrypted);
		}
	}
	const cfg = { endpoint, applicationKey };
	const timestamp = await ovhServerTimestamp(endpoint);
	const listSpec = await buildOvhRequest(cfg, appSecret, consumerKey, "GET", "/ip", timestamp);
	const blocks = (await fetchOvhJson(listSpec)) as string[];
	const details = await Promise.all(
		blocks.map(async (block) => {
			const spec = await buildOvhRequest(cfg, appSecret, consumerKey, "GET", ipDetailPath(block), timestamp);
			const detail = (await fetchOvhJson(spec)) as { routedTo?: { serviceName?: string | null } };
			return { block, serviceName: detail.routedTo?.serviceName ?? null };
		}),
	);
	if (details.length === 0) throw new Error("Connected, but no IPs were returned");
	return details;
}

export interface OvhCredentialRequestResult {
	consumerKey: string;
	validationUrl: string;
	state: string;
}

/**
 * Access is scoped to just the /ip/* resource tree BurrowGate actually needs - not the whole OVH account.
 * OVH's wildcard rights don't cover the bare path they're rooted at (a documented quirk - the same one affects
 * `/domain/zone/*` not covering `/domain/zone/<domain>` on its own), so `GET /ip` (listing IPs) needs its own
 * explicit rule alongside the `/ip/*` wildcard that covers everything with a path segment after the slash.
 */
export function ovhCredentialRequestBody(redirection: string | null): { accessRules: Array<{ method: string; path: string }>; redirection: string | null } {
	return {
		accessRules: [
			{ method: "GET", path: "/ip" },
			{ method: "GET", path: "/ip/*" },
			{ method: "POST", path: "/ip/*" },
			{ method: "PUT", path: "/ip/*" },
			{ method: "DELETE", path: "/ip/*" },
		],
		redirection,
	};
}

/** Consumer-key acquisition needs no prior consumer key (that's what's being requested) - only the application key identifies the caller. */
export async function ovhRequestCredential(endpointInput: string, applicationKey: string): Promise<OvhCredentialRequestResult> {
	if (!applicationKey.trim()) throw new Error("Application key is required");
	const response = await fetch(`${ovhApiRoot(endpointInput)}/auth/credential`, {
		method: "POST",
		headers: { "X-Ovh-Application": applicationKey.trim(), "content-type": "application/json", accept: "application/json" },
		body: JSON.stringify(ovhCredentialRequestBody(null)),
		signal: AbortSignal.timeout(config.firewallSync.requestTimeoutMs),
	});
	const text = await response.text();
	if (!response.ok) throw new Error(`HTTP ${response.status}: ${text.slice(0, 300)}`);
	return JSON.parse(text) as OvhCredentialRequestResult;
}
