import { config } from "../../config.ts";
import { hmacSha256, sha256Hex, toHex } from "../../utils/crypto.ts";
import { splitCidrsByFamily } from "../../utils/ip.ts";
import { decryptSecret } from "../secret-encryption-service.ts";

/** BurrowGate reserves a block of 20 rule numbers on the Network ACL. */
export const AWS_NACL_MAX_RULES = 20;
export const AWS_NACL_DEFAULT_RULE_NUMBER_START = 1;
const EC2_API_VERSION = "2016-11-15";

export interface AwsNaclProviderConfig {
	region: string;
	accessKeyId: string;
	secretAccessKeyEncrypted: string;
	sessionTokenEncrypted: string;
	networkAclId: string;
	ruleNumberStart: number;
}

export function normalizeAwsRegion(value: unknown): string {
	return typeof value === "string" && value.trim() ? value.trim() : "us-east-1";
}

/** Rule numbers run 1-32766; capping the start keeps the reserved 20-slot block from spilling past the valid range. */
export function normalizeAwsRuleNumberStart(value: unknown): number {
	const number = Number(value);
	if (!Number.isInteger(number) || number < 1) return AWS_NACL_DEFAULT_RULE_NUMBER_START;
	return Math.min(number, 32_766 - AWS_NACL_MAX_RULES + 1);
}

export function parseAwsNaclProviderConfig(value: unknown): AwsNaclProviderConfig {
	const raw = (value ?? {}) as Record<string, unknown>;
	return {
		region: normalizeAwsRegion(raw.region),
		accessKeyId: typeof raw.accessKeyId === "string" ? raw.accessKeyId.trim() : "",
		secretAccessKeyEncrypted: typeof raw.secretAccessKeyEncrypted === "string" ? raw.secretAccessKeyEncrypted : "",
		sessionTokenEncrypted: typeof raw.sessionTokenEncrypted === "string" ? raw.sessionTokenEncrypted : "",
		networkAclId: typeof raw.networkAclId === "string" ? raw.networkAclId.trim() : "",
		ruleNumberStart: normalizeAwsRuleNumberStart(raw.ruleNumberStart),
	};
}

/**
 * `cidrBlock` is typed as an actual CIDR block - AWS rejects a bare address ("Value (x.x.x.x) for parameter
 * cidrBlock is invalid. This is not a valid CIDR block."). BurrowGate's own ban rules are frequently stored
 * without a prefix (a single-IP auto-ban has no "/32" suffix), so every source needs one appended before it's sent.
 */
export function normalizeAwsIpv4Cidr(cidr: string): string {
	return cidr.includes("/") ? cidr : `${cidr}/32`;
}

function awsEc2Host(region: string): string {
	return `ec2.${region}.amazonaws.com`;
}

/** SigV4's URI-encoding is RFC 3986 with uppercase hex - encodeURIComponent leaves `!'()*` unescaped, which AWS requires escaped. */
export function awsUriEncode(value: string): string {
	return encodeURIComponent(value).replace(/[!'()*]/gu, (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`);
}

/** Query-protocol (EC2) requests sign their form-encoded body as the "canonical query string" - params sorted by key, both key and value URI-encoded. */
export function awsCanonicalParams(params: Record<string, string>): string {
	return Object.keys(params)
		.sort()
		.map((key) => `${awsUriEncode(key)}=${awsUriEncode(params[key]!)}`)
		.join("&");
}

export function awsAmzDate(date: Date): string {
	return `${date.toISOString().replace(/[-:]/gu, "").slice(0, 15)}Z`;
}

export function awsDateStamp(date: Date): string {
	return awsAmzDate(date).slice(0, 8);
}

/**
 * SigV4's derived signing key: a chain of four HMACs (date -> region -> service -> "aws4_request"), each keyed by
 * the previous step's raw output rather than a hex re-encoding of it. Verified against AWS's own published example
 * (docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html "Examples of derived signing keys").
 */
export async function awsSigningKey(secretAccessKey: string, dateStamp: string, region: string, service: string): Promise<Uint8Array> {
	const encoder = new TextEncoder();
	const kDate = await hmacSha256(encoder.encode(`AWS4${secretAccessKey}`), dateStamp);
	const kRegion = await hmacSha256(kDate, region);
	const kService = await hmacSha256(kRegion, service);
	return await hmacSha256(kService, "aws4_request");
}

export interface AwsRequestSpec {
	url: string;
	init: RequestInit;
}

export async function buildAwsEc2Request(
	cfg: Pick<AwsNaclProviderConfig, "region" | "accessKeyId">,
	secretAccessKey: string,
	sessionToken: string,
	action: string,
	params: Record<string, string>,
	date: Date,
): Promise<AwsRequestSpec> {
	const host = awsEc2Host(cfg.region);
	const amzDate = awsAmzDate(date);
	const dateStamp = awsDateStamp(date);
	const body = awsCanonicalParams({ Action: action, Version: EC2_API_VERSION, ...params });
	const payloadHash = await sha256Hex(body);
	const headerEntries: Array<[string, string]> = [
		["content-type", "application/x-www-form-urlencoded; charset=utf-8"],
		["host", host],
		["x-amz-date", amzDate],
	];
	if (sessionToken) headerEntries.push(["x-amz-security-token", sessionToken]);
	headerEntries.sort(([a], [b]) => (a < b ? -1 : 1));
	const canonicalHeaders = headerEntries.map(([name, value]) => `${name}:${value}\n`).join("");
	const signedHeaders = headerEntries.map(([name]) => name).join(";");
	const canonicalRequest = `POST\n/\n\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;
	const credentialScope = `${dateStamp}/${cfg.region}/ec2/aws4_request`;
	const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${credentialScope}\n${await sha256Hex(canonicalRequest)}`;
	const signingKey = await awsSigningKey(secretAccessKey, dateStamp, cfg.region, "ec2");
	const signature = toHex(await hmacSha256(signingKey, stringToSign));
	const authorization = `AWS4-HMAC-SHA256 Credential=${cfg.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
	const headers: Record<string, string> = { ...Object.fromEntries(headerEntries), authorization };
	return { url: `https://${host}/`, init: { method: "POST", headers, body, signal: AbortSignal.timeout(config.firewallSync.requestTimeoutMs) } };
}

function extractTag(xml: string, tag: string): string | null {
	const match = xml.match(new RegExp(`<${tag}>([^<]*)</${tag}>`, "u"));
	return match ? match[1]! : null;
}

/**
 * AWS's `<item>` wrapper is reused at every nesting level (a networkAclSet item contains its own entrySet items),
 * so a naive non-greedy regex would stop at the first nested closing tag instead of the outer one. This tracks
 * open/close depth to return only the top-level blocks of `tag` within `xml`, exactly like a real element boundary.
 */
function extractTopLevelBlocks(xml: string, tag: string): string[] {
	const openTag = `<${tag}>`;
	const closeTag = `</${tag}>`;
	const blocks: string[] = [];
	let searchFrom = 0;
	while (true) {
		const start = xml.indexOf(openTag, searchFrom);
		if (start === -1) break;
		let depth = 1;
		let cursor = start + openTag.length;
		while (depth > 0) {
			const nextOpen = xml.indexOf(openTag, cursor);
			const nextClose = xml.indexOf(closeTag, cursor);
			if (nextClose === -1) {
				cursor = xml.length;
				break;
			}
			if (nextOpen !== -1 && nextOpen < nextClose) {
				depth += 1;
				cursor = nextOpen + openTag.length;
			} else {
				depth -= 1;
				cursor = nextClose + closeTag.length;
			}
		}
		blocks.push(xml.slice(start + openTag.length, Math.max(start + openTag.length, cursor - closeTag.length)));
		searchFrom = cursor;
	}
	return blocks;
}

/** EC2's Query API is XML-only (unlike JSON-protocol services, it ignores an Accept: application/json header), so error responses need their own tiny parser. */
export function parseAwsErrorXml(xml: string): { code: string; message: string } | null {
	const errorBlock = extractTopLevelBlocks(xml, "Error")[0];
	if (!errorBlock) return null;
	return { code: extractTag(errorBlock, "Code") ?? "Unknown", message: extractTag(errorBlock, "Message") ?? xml.slice(0, 300) };
}

async function fetchAwsXml(spec: AwsRequestSpec): Promise<string> {
	const response = await fetch(spec.url, spec.init);
	const text = await response.text();
	if (!response.ok) {
		const parsedError = parseAwsErrorXml(text);
		throw new Error(parsedError ? `${parsedError.code}: ${parsedError.message}` : `HTTP ${response.status}: ${text.slice(0, 300)}`);
	}
	return text;
}

export interface AwsNaclExistingEntry {
	ruleNumber: number;
	ruleAction: "allow" | "deny";
	protocol: string;
	cidrBlock: string | null;
	portRangeFrom: number | null;
	portRangeTo: number | null;
}

/** Parses the <entrySet> of a single <item> from a DescribeNetworkAcls response - ingress entries only (Egress == false). */
export function parseAwsNaclEntriesXml(xml: string): AwsNaclExistingEntry[] {
	const naclBlock = extractTopLevelBlocks(xml, "item").find((block) => block.includes("<entrySet>"));
	if (!naclBlock) return [];
	const entrySetMatch = naclBlock.match(/<entrySet>([\s\S]*?)<\/entrySet>/u);
	if (!entrySetMatch) return [];
	return extractTopLevelBlocks(entrySetMatch[1]!, "item")
		.filter((item) => extractTag(item, "egress") !== "true")
		.map((item) => {
			const portRangeMatch = item.match(/<portRange>([\s\S]*?)<\/portRange>/u);
			const from = portRangeMatch ? Number(extractTag(portRangeMatch[1]!, "from")) : null;
			const to = portRangeMatch ? Number(extractTag(portRangeMatch[1]!, "to")) : null;
			return {
				ruleNumber: Number(extractTag(item, "ruleNumber")),
				ruleAction: extractTag(item, "ruleAction") === "allow" ? "allow" : "deny",
				protocol: extractTag(item, "protocol") ?? "",
				cidrBlock: extractTag(item, "cidrBlock"),
				portRangeFrom: from !== null && Number.isFinite(from) ? from : null,
				portRangeTo: to !== null && Number.isFinite(to) ? to : null,
			};
		});
}

export interface AwsNaclOption {
	networkAclId: string;
	vpcId: string;
	isDefault: boolean;
}

/** Parses the top-level <networkAclSet> of a DescribeNetworkAcls response (used for the admin UI's "Load Network ACLs" picker). */
export function parseAwsNaclListXml(xml: string): AwsNaclOption[] {
	return extractTopLevelBlocks(xml, "item")
		.filter((block) => block.includes("<networkAclId>"))
		.map((item) => ({
			networkAclId: extractTag(item, "networkAclId") ?? "",
			vpcId: extractTag(item, "vpcId") ?? "",
			isDefault: extractTag(item, "default") === "true",
		}))
		.filter((option) => option.networkAclId);
}

/**
 * There's no comment/label field on a Network ACL entry, so - same reasoning as OVH's `isOvhManagedRule` - only a
 * rule matching BurrowGate's exact shape (ingress, deny, all-protocols, no port restriction) is ever touched.
 * Anything else in the reserved rule-number range (a rule the admin added themselves) is left alone and its slot
 * excluded from the free-slot pool.
 */
export function isAwsNaclManagedRule(entry: AwsNaclExistingEntry): boolean {
	return entry.ruleAction === "deny" && entry.protocol === "-1" && entry.portRangeFrom === null && entry.portRangeTo === null;
}

export interface AwsNaclRuleDiff {
	toDelete: number[];
	toCreate: Array<{ ruleNumber: number; cidrBlock: string }>;
}

function reservedRuleNumbers(ruleNumberStart: number): number[] {
	return Array.from({ length: AWS_NACL_MAX_RULES }, (_, index) => ruleNumberStart + index);
}

/** Keeps unchanged managed entries in place instead of flush+recreate, and never reuses a slot occupied by a rule that isn't BurrowGate's own. */
export function computeAwsNaclRuleDiff(desiredCidrs: string[], existingEntries: AwsNaclExistingEntry[], ruleNumberStart: number): AwsNaclRuleDiff {
	const candidates = reservedRuleNumbers(ruleNumberStart);
	const candidateSet = new Set(candidates);
	const inRange = existingEntries.filter((entry) => candidateSet.has(entry.ruleNumber));
	const reserved = new Set(inRange.filter((entry) => !isAwsNaclManagedRule(entry)).map((entry) => entry.ruleNumber));
	const availableSlots = Math.max(0, AWS_NACL_MAX_RULES - reserved.size);
	const capped = desiredCidrs.slice(0, availableSlots);
	const desiredSet = new Set(capped);
	const keptCidrs = new Set<string>();
	const occupied = new Set<number>(reserved);
	const toDelete: number[] = [];
	for (const entry of inRange) {
		if (!isAwsNaclManagedRule(entry)) continue;
		if (entry.cidrBlock && desiredSet.has(entry.cidrBlock) && !keptCidrs.has(entry.cidrBlock)) {
			keptCidrs.add(entry.cidrBlock);
			occupied.add(entry.ruleNumber);
		} else {
			toDelete.push(entry.ruleNumber);
		}
	}
	const missing = capped.filter((cidr) => !keptCidrs.has(cidr));
	const free = candidates.filter((ruleNumber) => !occupied.has(ruleNumber));
	const toCreate = missing.map((cidrBlock, index) => ({ ruleNumber: free[index]!, cidrBlock }));
	return { toDelete, toCreate };
}

async function awsDescribeEntries(
	cfg: Pick<AwsNaclProviderConfig, "region" | "accessKeyId" | "networkAclId">,
	secretAccessKey: string,
	sessionToken: string,
	date: Date,
): Promise<AwsNaclExistingEntry[]> {
	const spec = await buildAwsEc2Request(cfg, secretAccessKey, sessionToken, "DescribeNetworkAcls", { "NetworkAclId.1": cfg.networkAclId }, date);
	return parseAwsNaclEntriesXml(await fetchAwsXml(spec));
}

async function awsCredentials(cfg: AwsNaclProviderConfig): Promise<{ secretAccessKey: string; sessionToken: string }> {
	return {
		secretAccessKey: await decryptSecret(cfg.secretAccessKeyEncrypted),
		sessionToken: cfg.sessionTokenEncrypted ? await decryptSecret(cfg.sessionTokenEncrypted) : "",
	};
}

export async function awsNaclReconcile(configJson: string, cidrs: string[]): Promise<void> {
	const cfg = parseAwsNaclProviderConfig(JSON.parse(configJson));
	if (!cfg.accessKeyId || !cfg.secretAccessKeyEncrypted) throw new Error("AWS access key ID and secret access key are both required");
	if (!cfg.networkAclId) throw new Error("No Network ACL selected - use “Load Network ACLs” and pick one");
	const { secretAccessKey, sessionToken } = await awsCredentials(cfg);
	const date = new Date();
	const existing = await awsDescribeEntries(cfg, secretAccessKey, sessionToken, date);
	// Network ACL entries take either CidrBlock (IPv4) or Ipv6CidrBlock, never both - IPv6 support would need its own parallel entry set.
	const { v4 } = splitCidrsByFamily(cidrs);
	const diff = computeAwsNaclRuleDiff(v4.map(normalizeAwsIpv4Cidr), existing, cfg.ruleNumberStart);
	for (const ruleNumber of diff.toDelete) {
		const spec = await buildAwsEc2Request(
			cfg,
			secretAccessKey,
			sessionToken,
			"DeleteNetworkAclEntry",
			{
				NetworkAclId: cfg.networkAclId,
				RuleNumber: String(ruleNumber),
				Egress: "false",
			},
			date,
		);
		await fetchAwsXml(spec);
	}
	for (const { ruleNumber, cidrBlock } of diff.toCreate) {
		const spec = await buildAwsEc2Request(
			cfg,
			secretAccessKey,
			sessionToken,
			"CreateNetworkAclEntry",
			{
				NetworkAclId: cfg.networkAclId,
				RuleNumber: String(ruleNumber),
				Protocol: "-1",
				RuleAction: "deny",
				Egress: "false",
				CidrBlock: cidrBlock,
			},
			date,
		);
		await fetchAwsXml(spec);
	}
}

export async function awsNaclTestConnection(configJson: string): Promise<{ ok: boolean; message: string }> {
	const cfg = parseAwsNaclProviderConfig(JSON.parse(configJson));
	if (!cfg.accessKeyId) return { ok: false, message: "Access key ID is required" };
	if (!cfg.secretAccessKeyEncrypted) return { ok: false, message: "Secret access key is required" };
	if (!cfg.networkAclId) return { ok: false, message: "No Network ACL selected - use “Load Network ACLs” and pick one" };
	try {
		const { secretAccessKey, sessionToken } = await awsCredentials(cfg);
		const entries = await awsDescribeEntries(cfg, secretAccessKey, sessionToken, new Date());
		const managed = entries.filter((entry) => isAwsNaclManagedRule(entry) && reservedRuleNumbers(cfg.ruleNumberStart).includes(entry.ruleNumber));
		return {
			ok: true,
			message: `Connected to ${cfg.networkAclId}. ${managed.length} of ${AWS_NACL_MAX_RULES} reserved rule slots (${cfg.ruleNumberStart}-${cfg.ruleNumberStart + AWS_NACL_MAX_RULES - 1}) currently in use.`,
		};
	} catch (error) {
		return { ok: false, message: error instanceof Error ? error.message : String(error) };
	}
}

/** Best-effort: deletes only entries matching BurrowGate's own managed shape within its reserved rule-number range - never touches anything else on the ACL. */
export async function awsNaclTeardown(configJson: string): Promise<void> {
	const cfg = parseAwsNaclProviderConfig(JSON.parse(configJson));
	if (!cfg.accessKeyId || !cfg.secretAccessKeyEncrypted || !cfg.networkAclId) return;
	const { secretAccessKey, sessionToken } = await awsCredentials(cfg);
	const date = new Date();
	const existing = await awsDescribeEntries(cfg, secretAccessKey, sessionToken, date);
	const candidateSet = new Set(reservedRuleNumbers(cfg.ruleNumberStart));
	const managed = existing.filter((entry) => candidateSet.has(entry.ruleNumber) && isAwsNaclManagedRule(entry));
	for (const entry of managed) {
		const spec = await buildAwsEc2Request(
			cfg,
			secretAccessKey,
			sessionToken,
			"DeleteNetworkAclEntry",
			{
				NetworkAclId: cfg.networkAclId,
				RuleNumber: String(entry.ruleNumber),
				Egress: "false",
			},
			date,
		);
		await fetchAwsXml(spec);
	}
}

export interface AwsNaclListInput {
	region: string;
	accessKeyId: string;
	secretAccessKey?: string;
	sessionToken?: string;
	existingConfigJson?: string | null;
}

/** Used by the admin UI's "Load Network ACLs" button - works against unsaved form values, falling back to stored secrets when a field was left blank while editing. */
export async function awsListNacls(input: AwsNaclListInput): Promise<AwsNaclOption[]> {
	const region = normalizeAwsRegion(input.region);
	const accessKeyId = input.accessKeyId.trim();
	if (!accessKeyId) throw new Error("Access key ID is required");
	let secretAccessKey = input.secretAccessKey?.trim() ?? "";
	let sessionToken = input.sessionToken?.trim() ?? "";
	if (!secretAccessKey || !sessionToken) {
		const existing = input.existingConfigJson ? parseAwsNaclProviderConfig(JSON.parse(input.existingConfigJson)) : null;
		if (!secretAccessKey) {
			if (!existing?.secretAccessKeyEncrypted) throw new Error("Secret access key is required");
			secretAccessKey = await decryptSecret(existing.secretAccessKeyEncrypted);
		}
		if (!sessionToken && existing?.sessionTokenEncrypted) sessionToken = await decryptSecret(existing.sessionTokenEncrypted);
	}
	const spec = await buildAwsEc2Request({ region, accessKeyId }, secretAccessKey, sessionToken, "DescribeNetworkAcls", {}, new Date());
	const items = parseAwsNaclListXml(await fetchAwsXml(spec));
	if (items.length === 0) throw new Error("Connected, but no Network ACLs were returned");
	return items;
}
