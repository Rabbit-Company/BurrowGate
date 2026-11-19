import { config } from "../../config.ts";
import { formatIp, parseCidr } from "../../utils/ip.ts";
import { decryptSecret } from "../secret-encryption-service.ts";

export const CLOUDFLARE_DEFAULT_MAX_ENTRIES = 10_000;
export const CLOUDFLARE_DEFAULT_LIST_NAME = "burrowgate_banned_ips";
export const CLOUDFLARE_API_ROOT = "https://api.cloudflare.com/client/v4";
const ITEM_COMMENT_PREFIX = "Managed by BurrowGate";
const LIST_DESCRIPTION = "IPs banned by BurrowGate. Kept in sync automatically, manual edits are overwritten.";
const ITEMS_PAGE_SIZE = 500;
const ITEMS_MAX_PAGES = 2_000;
const ACCOUNTS_PAGE_SIZE = 50;
const OPERATION_POLL_INTERVAL_MS = 500;
const OPERATION_TIMEOUT_MS = 60_000;
const SUBMIT_ATTEMPTS = 5;
const SUBMIT_RETRY_BASE_MS = 1_000;
const FULL_RECHECK_MS = 5 * 60_000;

export interface CloudflareProviderConfig {
	accountId: string;
	listName: string;
	apiTokenEncrypted: string;
	ownerId: string;
}

export function newCloudflareOwnerId(): string {
	return crypto.randomUUID().replaceAll("-", "").slice(0, 16);
}

export function isValidCloudflareOwnerId(ownerId: string): boolean {
	return /^[a-z0-9]{1,32}$/u.test(ownerId);
}

export function cloudflareOwnerComment(ownerId: string): string {
	return `${ITEM_COMMENT_PREFIX} (${ownerId})`;
}

export function isValidCloudflareListName(name: string): boolean {
	return /^[a-z0-9_]{1,50}$/u.test(name);
}

export function isValidCloudflareAccountId(accountId: string): boolean {
	return /^[0-9a-f]{32}$/u.test(accountId);
}

export function parseCloudflareProviderConfig(value: unknown): CloudflareProviderConfig {
	const raw = (value ?? {}) as Record<string, unknown>;
	return {
		accountId: typeof raw.accountId === "string" ? raw.accountId.trim().toLowerCase() : "",
		listName: typeof raw.listName === "string" && raw.listName.trim() ? raw.listName.trim() : CLOUDFLARE_DEFAULT_LIST_NAME,
		apiTokenEncrypted: typeof raw.apiTokenEncrypted === "string" ? raw.apiTokenEncrypted : "",
		ownerId: typeof raw.ownerId === "string" ? raw.ownerId.trim().toLowerCase() : "",
	};
}

export function canonicalCloudflareIp(value: string): string | null {
	const parsed = parseCidr(value);
	if (!parsed) return null;
	const address = formatIp(parsed.version, parsed.network);
	return parsed.prefix === parsed.bits ? address : `${address}/${parsed.prefix}`;
}

export function cloudflareListItemValue(cidr: string): string | null {
	const parsed = parseCidr(cidr);
	if (!parsed) return null;
	if (parsed.version === 4 && parsed.prefix < 8) return null;
	if (parsed.version === 6 && parsed.prefix < 12) return null;
	return canonicalCloudflareIp(cidr);
}

export interface CloudflareExistingItem {
	id: string;
	ip: string;
	comment?: string;
}

export interface CloudflareListDiff {
	toDelete: string[];
	toCreate: string[];
}

export function cloudflareDesiredValues(desiredCidrs: string[]): string[] {
	const desired: string[] = [];
	const seen = new Set<string>();
	for (const cidr of desiredCidrs) {
		const value = cloudflareListItemValue(cidr);
		if (value === null || seen.has(value)) continue;
		seen.add(value);
		desired.push(value);
	}
	return desired;
}

export function computeCloudflareListDiff(desiredCidrs: string[], existingItems: CloudflareExistingItem[], ownerId: string): CloudflareListDiff {
	const desired = cloudflareDesiredValues(desiredCidrs);
	const desiredSet = new Set(desired);
	const ownComment = cloudflareOwnerComment(ownerId);
	const present = new Set<string>();
	const keptOwn = new Set<string>();
	const toDelete: string[] = [];
	for (const item of existingItems) {
		const key = canonicalCloudflareIp(item.ip) ?? item.ip;
		if (item.comment !== ownComment) {
			present.add(key);
			continue;
		}
		if (desiredSet.has(key) && !keptOwn.has(key)) {
			keptOwn.add(key);
			present.add(key);
		} else toDelete.push(item.id);
	}
	return { toDelete, toCreate: desired.filter((value) => !present.has(value)) };
}

export interface CloudflareRequestSpec {
	url: string;
	init: RequestInit;
}

export function buildCloudflareRequest(apiToken: string, method: string, path: string, body?: unknown): CloudflareRequestSpec {
	const headers: Record<string, string> = { authorization: `Bearer ${apiToken}`, accept: "application/json" };
	if (body !== undefined) headers["content-type"] = "application/json";
	return {
		url: `${CLOUDFLARE_API_ROOT}${path}`,
		init: {
			method,
			headers,
			body: body === undefined ? undefined : JSON.stringify(body),
			signal: AbortSignal.timeout(config.firewallSync.requestTimeoutMs),
		},
	};
}

interface CloudflareEnvelope {
	success?: boolean;
	errors?: Array<{ code?: number; message?: string }>;
	result?: unknown;
	result_info?: Record<string, unknown>;
}

export function cloudflareErrorMessage(status: number, envelope: CloudflareEnvelope | null, text: string): string {
	const details = (envelope?.errors ?? [])
		.map((error) => (error.code ? `${error.message ?? "Unknown error"} (${error.code})` : (error.message ?? "")))
		.filter(Boolean)
		.join("; ");
	return `HTTP ${status}: ${details || text.slice(0, 300)}`;
}

export class CloudflareApiError extends Error {
	constructor(
		message: string,
		readonly status: number,
	) {
		super(message);
	}
}

async function cloudflareFetch(spec: CloudflareRequestSpec): Promise<CloudflareEnvelope> {
	const response = await fetch(spec.url, spec.init);
	const text = await response.text();
	let envelope: CloudflareEnvelope | null = null;
	try {
		envelope = text ? (JSON.parse(text) as CloudflareEnvelope) : null;
	} catch {
		envelope = null;
	}
	if (!response.ok || envelope?.success === false) throw new CloudflareApiError(cloudflareErrorMessage(response.status, envelope, text), response.status);
	if (!envelope) throw new Error(`Unexpected non-JSON response: ${text.slice(0, 300)}`);
	return envelope;
}

function listsPath(accountId: string): string {
	return `/accounts/${encodeURIComponent(accountId)}/rules/lists`;
}

function listPath(accountId: string, listId: string): string {
	return `${listsPath(accountId)}/${encodeURIComponent(listId)}`;
}

function itemsPath(accountId: string, listId: string): string {
	return `${listPath(accountId, listId)}/items`;
}

function operationPath(accountId: string, operationId: string): string {
	return `${listsPath(accountId)}/bulk_operations/${encodeURIComponent(operationId)}`;
}

interface CloudflareList {
	id: string;
	name: string;
	kind: string;
	numItems: number;
	modifiedOn: string;
}

async function findManagedList(cfg: CloudflareProviderConfig, apiToken: string): Promise<CloudflareList | null> {
	const envelope = await cloudflareFetch(buildCloudflareRequest(apiToken, "GET", listsPath(cfg.accountId)));
	const lists = Array.isArray(envelope.result) ? (envelope.result as Array<Record<string, unknown>>) : [];
	const match = lists.find((list) => list.name === cfg.listName);
	if (!match) return null;
	return {
		id: String(match.id ?? ""),
		name: String(match.name ?? ""),
		kind: String(match.kind ?? ""),
		numItems: Number(match.num_items ?? 0),
		modifiedOn: String(match.modified_on ?? ""),
	};
}

function assertIpList(list: CloudflareList): void {
	if (list.kind !== "ip") throw new Error(`Cloudflare list '${list.name}' already exists but holds ${list.kind} items, not IPs. Pick another list name.`);
}

async function createManagedList(cfg: CloudflareProviderConfig, apiToken: string): Promise<string> {
	const envelope = await cloudflareFetch(
		buildCloudflareRequest(apiToken, "POST", listsPath(cfg.accountId), { name: cfg.listName, kind: "ip", description: LIST_DESCRIPTION }),
	);
	const id = (envelope.result as { id?: unknown } | undefined)?.id;
	if (typeof id !== "string" || !id) throw new Error("Cloudflare created the list but returned no list ID");
	return id;
}

async function fetchListItems(cfg: CloudflareProviderConfig, apiToken: string, listId: string): Promise<CloudflareExistingItem[]> {
	const items: CloudflareExistingItem[] = [];
	let cursor: string | null = null;
	for (let page = 0; page < ITEMS_MAX_PAGES; page++) {
		const query = new URLSearchParams({ per_page: String(ITEMS_PAGE_SIZE) });
		if (cursor) query.set("cursor", cursor);
		const envelope = await cloudflareFetch(buildCloudflareRequest(apiToken, "GET", `${itemsPath(cfg.accountId, listId)}?${query}`));
		const rows = Array.isArray(envelope.result) ? (envelope.result as Array<Record<string, unknown>>) : [];
		for (const row of rows) {
			if (typeof row.id !== "string" || typeof row.ip !== "string") continue;
			items.push({ id: row.id, ip: row.ip, comment: typeof row.comment === "string" ? row.comment : undefined });
		}
		const after = (envelope.result_info?.cursors as { after?: unknown } | undefined)?.after;
		if (typeof after !== "string" || !after || rows.length === 0) return items;
		cursor = after;
	}
	throw new Error(`Cloudflare list has more than ${ITEMS_MAX_PAGES * ITEMS_PAGE_SIZE} items`);
}

export type CloudflareOperationState = { done: false } | { done: true; error: string | null };

export function parseCloudflareOperationStatus(result: unknown): CloudflareOperationState {
	const status = (result as { status?: unknown } | undefined)?.status;
	if (status === "completed") return { done: true, error: null };
	if (status === "failed") {
		const error = (result as { error?: unknown }).error;
		return { done: true, error: typeof error === "string" && error ? error : "unknown error" };
	}
	return { done: false };
}

async function waitForOperation(cfg: CloudflareProviderConfig, apiToken: string, operationId: string): Promise<void> {
	const deadline = Date.now() + OPERATION_TIMEOUT_MS;
	while (Date.now() < deadline) {
		const envelope = await cloudflareFetch(buildCloudflareRequest(apiToken, "GET", operationPath(cfg.accountId, operationId)));
		const state = parseCloudflareOperationStatus(envelope.result);
		if (state.done) {
			if (state.error) throw new Error(`Cloudflare bulk list operation failed: ${state.error}`);
			return;
		}
		await Bun.sleep(OPERATION_POLL_INTERVAL_MS);
	}
	throw new Error(`Cloudflare bulk list operation ${operationId} did not finish within ${OPERATION_TIMEOUT_MS / 1000} seconds`);
}

export function isRetryableSubmitError(error: unknown): boolean {
	if (!(error instanceof CloudflareApiError)) return true;
	return error.status !== 400 && error.status !== 401 && error.status !== 403 && error.status !== 404;
}

async function submitBulkOperation(apiToken: string, method: string, path: string, body: unknown): Promise<CloudflareEnvelope> {
	for (let attempt = 1; ; attempt++) {
		try {
			return await cloudflareFetch(buildCloudflareRequest(apiToken, method, path, body));
		} catch (error) {
			if (attempt >= SUBMIT_ATTEMPTS || !isRetryableSubmitError(error)) throw error;
			await Bun.sleep(SUBMIT_RETRY_BASE_MS * attempt + Math.floor(Math.random() * SUBMIT_RETRY_BASE_MS));
		}
	}
}

async function runBulkOperation(cfg: CloudflareProviderConfig, apiToken: string, method: string, path: string, body: unknown): Promise<void> {
	const envelope = await submitBulkOperation(apiToken, method, path, body);
	const operationId = (envelope.result as { operation_id?: unknown } | undefined)?.operation_id;
	if (typeof operationId !== "string" || !operationId) throw new Error("Cloudflare accepted the list change but returned no operation ID");
	await waitForOperation(cfg, apiToken, operationId);
}

export function cloudflareDeleteItemsBody(itemIds: string[]): { items: Array<{ id: string }> } {
	return { items: itemIds.map((id) => ({ id })) };
}

export function cloudflareCreateItemsBody(values: string[], ownerId: string): Array<{ ip: string; comment: string }> {
	const comment = cloudflareOwnerComment(ownerId);
	return values.map((ip) => ({ ip, comment }));
}

function requireUsableConfig(cfg: CloudflareProviderConfig): void {
	if (!cfg.apiTokenEncrypted) throw new Error("Cloudflare API token is not configured");
	if (!isValidCloudflareAccountId(cfg.accountId)) throw new Error("No Cloudflare account selected. Use “Load accounts” or paste the 32-character account ID");
	if (!isValidCloudflareListName(cfg.listName)) throw new Error("Cloudflare list name may only contain lowercase letters, digits and underscores (max 50)");
	if (!isValidCloudflareOwnerId(cfg.ownerId)) throw new Error("Cloudflare provider has no owner ID. Open the provider and save it again");
}

interface VerifiedListState {
	fingerprint: string;
	desiredKey: string;
	verifiedAt: number;
}

const verifiedLists = new Map<string, VerifiedListState>();

export function resetCloudflareVerifiedLists(): void {
	verifiedLists.clear();
}

function listFingerprint(list: CloudflareList): string {
	return `${list.id}|${list.modifiedOn}|${list.numItems}`;
}

export async function cloudflareReconcile(configJson: string, cidrs: string[], options: { force?: boolean } = {}): Promise<void> {
	const cfg = parseCloudflareProviderConfig(JSON.parse(configJson));
	requireUsableConfig(cfg);
	const apiToken = await decryptSecret(cfg.apiTokenEncrypted);
	const cacheKey = `${cfg.accountId}:${cfg.listName}:${cfg.ownerId}`;
	const desiredKey = cloudflareDesiredValues(cidrs).join(",");
	const existingList = await findManagedList(cfg, apiToken);
	if (existingList) assertIpList(existingList);
	const verified = verifiedLists.get(cacheKey);
	if (
		!options.force &&
		existingList &&
		verified &&
		verified.fingerprint === listFingerprint(existingList) &&
		verified.desiredKey === desiredKey &&
		Date.now() - verified.verifiedAt < FULL_RECHECK_MS
	)
		return;
	verifiedLists.delete(cacheKey);
	const listId = existingList ? existingList.id : await createManagedList(cfg, apiToken);
	const existingItems = existingList && existingList.numItems > 0 ? await fetchListItems(cfg, apiToken, listId) : [];
	const diff = computeCloudflareListDiff(cidrs, existingItems, cfg.ownerId);
	if (diff.toDelete.length > 0) await runBulkOperation(cfg, apiToken, "DELETE", itemsPath(cfg.accountId, listId), cloudflareDeleteItemsBody(diff.toDelete));
	if (diff.toCreate.length > 0)
		await runBulkOperation(cfg, apiToken, "POST", itemsPath(cfg.accountId, listId), cloudflareCreateItemsBody(diff.toCreate, cfg.ownerId));
	if (existingList && diff.toDelete.length === 0 && diff.toCreate.length === 0)
		verifiedLists.set(cacheKey, { fingerprint: listFingerprint(existingList), desiredKey, verifiedAt: Date.now() });
}

export function cloudflareRuleExpression(listName: string): string {
	return `(ip.src in $${listName})`;
}

export async function cloudflareTestConnection(configJson: string): Promise<{ ok: boolean; message: string }> {
	const cfg = parseCloudflareProviderConfig(JSON.parse(configJson));
	try {
		requireUsableConfig(cfg);
	} catch (error) {
		return { ok: false, message: error instanceof Error ? error.message : String(error) };
	}
	try {
		const apiToken = await decryptSecret(cfg.apiTokenEncrypted);
		const list = await findManagedList(cfg, apiToken);
		if (list) assertIpList(list);
		const expression = cloudflareRuleExpression(cfg.listName);
		const ownership = `This instance tags its items '${cloudflareOwnerComment(cfg.ownerId)}' and leaves all other items alone.`;
		return {
			ok: true,
			message: list
				? `Connected. List '${cfg.listName}' found with ${list.numItems} item${list.numItems === 1 ? "" : "s"}. ${ownership} Each zone needs a WAF custom rule with the expression ${expression} and action Block.`
				: `Connected. List '${cfg.listName}' will be created on first sync. ${ownership} Then add a WAF custom rule with the expression ${expression} and action Block to each zone.`,
		};
	} catch (error) {
		return { ok: false, message: error instanceof Error ? error.message : String(error) };
	}
}

export async function cloudflareTeardown(configJson: string): Promise<void> {
	const cfg = parseCloudflareProviderConfig(JSON.parse(configJson));
	if (!cfg.apiTokenEncrypted || !isValidCloudflareAccountId(cfg.accountId) || !isValidCloudflareListName(cfg.listName)) return;
	if (!isValidCloudflareOwnerId(cfg.ownerId)) return;
	verifiedLists.delete(`${cfg.accountId}:${cfg.listName}:${cfg.ownerId}`);
	const apiToken = await decryptSecret(cfg.apiTokenEncrypted);
	const list = await findManagedList(cfg, apiToken);
	if (!list || list.kind !== "ip") return;
	if (list.numItems > 0) {
		const ownComment = cloudflareOwnerComment(cfg.ownerId);
		const ownItemIds = (await fetchListItems(cfg, apiToken, list.id)).filter((item) => item.comment === ownComment).map((item) => item.id);
		if (ownItemIds.length > 0) await runBulkOperation(cfg, apiToken, "DELETE", itemsPath(cfg.accountId, list.id), cloudflareDeleteItemsBody(ownItemIds));
		const remaining = await findManagedList(cfg, apiToken);
		if (!remaining || remaining.numItems > 0) return;
	}
	try {
		await cloudflareFetch(buildCloudflareRequest(apiToken, "DELETE", listPath(cfg.accountId, list.id)));
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		throw new Error(`${message}. Remove the WAF custom rules that reference $${cfg.listName}, then delete the list in the Cloudflare dashboard.`);
	}
}

export interface CloudflareAccountOption {
	id: string;
	name: string;
}

export function parseCloudflareAccounts(result: unknown): CloudflareAccountOption[] {
	if (!Array.isArray(result)) return [];
	return (result as Array<Record<string, unknown>>)
		.filter((row) => typeof row.id === "string" && row.id)
		.map((row) => ({ id: String(row.id), name: typeof row.name === "string" && row.name ? row.name : String(row.id) }));
}

export interface CloudflareListAccountsInput {
	apiToken?: string;
	existingConfigJson?: string | null;
}

export async function cloudflareListAccounts(input: CloudflareListAccountsInput): Promise<CloudflareAccountOption[]> {
	let apiToken = input.apiToken?.trim() ?? "";
	if (!apiToken) {
		const existing = input.existingConfigJson ? parseCloudflareProviderConfig(JSON.parse(input.existingConfigJson)) : null;
		if (!existing?.apiTokenEncrypted) throw new Error("API token is required");
		apiToken = await decryptSecret(existing.apiTokenEncrypted);
	}
	const accounts: CloudflareAccountOption[] = [];
	for (let page = 1; page <= 20; page++) {
		const query = new URLSearchParams({ page: String(page), per_page: String(ACCOUNTS_PAGE_SIZE) });
		const envelope = await cloudflareFetch(buildCloudflareRequest(apiToken, "GET", `/accounts?${query}`));
		const batch = parseCloudflareAccounts(envelope.result);
		accounts.push(...batch);
		const totalCount = Number(envelope.result_info?.total_count ?? 0);
		if (batch.length < ACCOUNTS_PAGE_SIZE || accounts.length >= totalCount) break;
	}
	if (accounts.length === 0) throw new Error("Connected, but this token can't list accounts. Paste the account ID from the Cloudflare dashboard instead.");
	return accounts;
}
