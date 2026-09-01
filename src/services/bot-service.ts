import type { ParsedCidr } from "../utils/ip.ts";
import { cidrContains, parseCidr } from "../utils/ip.ts";
import type { RoutePolicyRecord, SiteRecord } from "../types.ts";
import { Logger } from "../logger.ts";

export type BotCategory = "search-engine" | "ai-search" | "ai-assistant" | "ai-crawler" | "archiver" | "page-preview" | "advertising" | "seo-tool" | "other";

export const BOT_CATEGORY_ORDER: readonly BotCategory[] = [
	"ai-crawler",
	"ai-search",
	"ai-assistant",
	"search-engine",
	"archiver",
	"page-preview",
	"advertising",
	"seo-tool",
	"other",
];

export interface BotCatalogEntry {
	id: string;
	name: string;
	category: BotCategory;
	verification: "ip-range" | "user-agent";
}

export interface BotIdentity {
	id: string;
	name: string;
	category: BotCategory;
	verified: boolean;
	source: "user-agent";
}

export interface BotPolicy {
	blockedBots: string[];
}

const FEEDS = {
	google: "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
	bing: "https://www.bing.com/toolbox/bingbot.json",
	duckduckbot: "https://duckduckgo.com/duckduckbot.json",
	applebot: "https://search.developer.apple.com/applebot.json",
	gptbot: "https://openai.com/gptbot.json",
	"oai-searchbot": "https://openai.com/searchbot.json",
	"chatgpt-user": "https://openai.com/chatgpt-user.json",
	perplexitybot: "https://www.perplexity.com/perplexitybot.json",
	"perplexity-user": "https://www.perplexity.com/perplexity-user.json",
	ccbot: "https://index.commoncrawl.org/ccbot.json",
	shapbot: "https://docs.parallel.ai/resources/shapbot.json",
	duckassistbot: "https://duckduckgo.com/duckassistbot.json",
} as const;

interface BotDefinition extends BotCatalogEntry {
	userAgents: RegExp[];
	ipProvider?: keyof typeof FEEDS;
}

const DEFINITIONS = (
	[
		{
			id: "googlebot",
			name: "Google crawler",
			category: "search-engine",
			verification: "ip-range",
			ipProvider: "google",
			userAgents: [/googlebot/i, /google-inspectiontool/i, /googleother/i, /storebot-google/i],
		},
		{
			id: "bingbot",
			name: "Bingbot",
			category: "search-engine",
			verification: "ip-range",
			ipProvider: "bing",
			userAgents: [/bingbot/i, /adidxbot/i, /microsoftpreview/i],
		},
		{ id: "duckduckbot", name: "DuckDuckBot", category: "search-engine", verification: "ip-range", ipProvider: "duckduckbot", userAgents: [/duckduckbot/i] },
		{ id: "applebot", name: "Applebot", category: "search-engine", verification: "ip-range", ipProvider: "applebot", userAgents: [/applebot/i] },
		{ id: "yandexbot", name: "YandexBot", category: "search-engine", verification: "user-agent", userAgents: [/yandex(?:bot|images|accessibilitybot)/i] },
		{ id: "baiduspider", name: "Baidu", category: "search-engine", verification: "user-agent", userAgents: [/baiduspider/i] },
		{ id: "petalbot", name: "PetalBot", category: "search-engine", verification: "user-agent", userAgents: [/petalbot/i] },
		{ id: "archive-org-bot", name: "archive.org_bot", category: "archiver", verification: "user-agent", userAgents: [/archive\.org_bot/i] },
		{ id: "arquivo-web-crawler", name: "Arquivo Web Crawler", category: "archiver", verification: "user-agent", userAgents: [/arquivo-web-crawler/i] },
		{ id: "terracotta", name: "Terracotta Bot", category: "search-engine", verification: "user-agent", userAgents: [/terracotta(?:-news)?/i] },
		{ id: "timpibot", name: "Timpibot", category: "search-engine", verification: "user-agent", userAgents: [/timpibot/i] },
		{ id: "gptbot", name: "GPTBot", category: "ai-crawler", verification: "ip-range", ipProvider: "gptbot", userAgents: [/gptbot/i] },
		{
			id: "oai-searchbot",
			name: "OAI-SearchBot",
			category: "ai-search",
			verification: "ip-range",
			ipProvider: "oai-searchbot",
			userAgents: [/oai-searchbot/i],
		},
		{ id: "chatgpt-user", name: "ChatGPT-User", category: "ai-assistant", verification: "ip-range", ipProvider: "chatgpt-user", userAgents: [/chatgpt-user/i] },
		{ id: "claudebot", name: "ClaudeBot", category: "ai-crawler", verification: "user-agent", userAgents: [/claudebot/i, /anthropic-ai/i] },
		{ id: "claude-searchbot", name: "Claude-SearchBot", category: "ai-search", verification: "user-agent", userAgents: [/claude-searchbot/i] },
		{ id: "claude-user", name: "Claude-User", category: "ai-assistant", verification: "user-agent", userAgents: [/claude-user/i] },
		{
			id: "perplexitybot",
			name: "PerplexityBot",
			category: "ai-search",
			verification: "ip-range",
			ipProvider: "perplexitybot",
			userAgents: [/perplexitybot/i],
		},
		{
			id: "perplexity-user",
			name: "Perplexity-User",
			category: "ai-assistant",
			verification: "ip-range",
			ipProvider: "perplexity-user",
			userAgents: [/perplexity-user/i],
		},
		{ id: "ccbot", name: "CCBot", category: "ai-crawler", verification: "ip-range", ipProvider: "ccbot", userAgents: [/(?:^|[^a-z])ccbot(?:[^a-z]|$)/i] },
		{ id: "shapbot", name: "ShapBot", category: "ai-crawler", verification: "ip-range", ipProvider: "shapbot", userAgents: [/shapbot/i] },
		{ id: "bytespider", name: "Bytespider", category: "ai-crawler", verification: "user-agent", userAgents: [/bytespider/i] },
		{ id: "tiktokspider", name: "TikTok Spider", category: "ai-crawler", verification: "user-agent", userAgents: [/tiktokspider/i] },
		{ id: "cohere-ai", name: "cohere-ai", category: "ai-crawler", verification: "user-agent", userAgents: [/cohere-ai/i] },
		{ id: "anchor-browser", name: "Anchor Browser", category: "ai-crawler", verification: "user-agent", userAgents: [/anchor browser/i] },
		{
			id: "cloudflare-crawler",
			name: "Cloudflare Crawler",
			category: "ai-crawler",
			verification: "user-agent",
			userAgents: [/cloudflarebrowserrenderingcrawler/i],
		},
		{
			id: "duckassistbot",
			name: "DuckAssistBot",
			category: "ai-assistant",
			verification: "ip-range",
			ipProvider: "duckassistbot",
			userAgents: [/duckassistbot/i],
		},
		{ id: "google-cloudvertexbot", name: "Google-CloudVertexBot", category: "ai-crawler", verification: "user-agent", userAgents: [/google-cloudvertexbot/i] },
		{ id: "manus-bot", name: "Manus Bot", category: "ai-assistant", verification: "user-agent", userAgents: [/(?:^|[^a-z])manus(?:bot)?(?:[^a-z]|$)/i] },
		{ id: "mistralai-user", name: "MistralAI-User", category: "ai-assistant", verification: "user-agent", userAgents: [/mistralai-user/i] },
		{ id: "novellum", name: "Novellum AI Crawl", category: "ai-crawler", verification: "user-agent", userAgents: [/(?:^|[^a-z])novellum(?:[^a-z]|$)/i] },
		{ id: "proratainc", name: "ProRataInc", category: "ai-crawler", verification: "user-agent", userAgents: [/proratainc/i] },
		{ id: "meta-webindexer", name: "Meta-WebIndexer", category: "ai-search", verification: "user-agent", userAgents: [/meta-webindexer/i] },
		{ id: "meta-externalads", name: "Meta-ExternalAds", category: "advertising", verification: "user-agent", userAgents: [/meta-externalads/i] },
		{ id: "meta-externalagent", name: "Meta-ExternalAgent", category: "ai-crawler", verification: "user-agent", userAgents: [/meta-externalagent/i] },
		{ id: "meta-externalfetcher", name: "Meta-ExternalFetcher", category: "ai-assistant", verification: "user-agent", userAgents: [/meta-externalfetcher/i] },
		{ id: "amazonbot", name: "Amazonbot", category: "ai-crawler", verification: "user-agent", userAgents: [/amazonbot/i] },
		{
			id: "facebookexternalhit",
			name: "FacebookExternalHit",
			category: "page-preview",
			verification: "user-agent",
			userAgents: [/facebookexternalhit/i, /facebot/i],
		},
		{ id: "linkedinbot", name: "LinkedInBot", category: "page-preview", verification: "user-agent", userAgents: [/linkedinbot/i] },
		{ id: "google-extended", name: "Google-Extended", category: "ai-crawler", verification: "user-agent", userAgents: [/google-extended/i] },
		{ id: "applebot-extended", name: "Applebot-Extended", category: "ai-crawler", verification: "user-agent", userAgents: [/applebot-extended/i] },
		{ id: "sogou", name: "Sogou Spider", category: "search-engine", verification: "user-agent", userAgents: [/sogou(?: web spider)?/i] },
		{ id: "naver", name: "Naver (Yeti)", category: "search-engine", verification: "user-agent", userAgents: [/yeti/i, /naverbot/i] },
		{ id: "seznambot", name: "SeznamBot", category: "search-engine", verification: "user-agent", userAgents: [/seznambot/i] },
		{ id: "ahrefsbot", name: "AhrefsBot", category: "seo-tool", verification: "user-agent", userAgents: [/ahrefsbot/i] },
		{ id: "semrushbot", name: "SemrushBot", category: "seo-tool", verification: "user-agent", userAgents: [/semrushbot/i] },
		{ id: "mj12bot", name: "MJ12bot", category: "seo-tool", verification: "user-agent", userAgents: [/mj12bot/i] },
		{ id: "rogerbot", name: "Rogerbot", category: "seo-tool", verification: "user-agent", userAgents: [/rogerbot/i] },
		{ id: "dotbot", name: "DotBot", category: "seo-tool", verification: "user-agent", userAgents: [/dotbot/i] },

		{ id: "facebookbot", name: "FacebookBot", category: "page-preview", verification: "user-agent", userAgents: [/facebookbot/i] },
		{ id: "twitterbot", name: "Twitterbot", category: "page-preview", verification: "user-agent", userAgents: [/twitterbot/i] },
		{ id: "pinterestbot", name: "Pinterestbot", category: "page-preview", verification: "user-agent", userAgents: [/pinterestbot/i] },
		{ id: "slackbot", name: "Slackbot", category: "page-preview", verification: "user-agent", userAgents: [/slackbot/i] },
		{ id: "discordbot", name: "Discordbot", category: "page-preview", verification: "user-agent", userAgents: [/discordbot/i] },
		{ id: "whatsapp", name: "WhatsApp", category: "page-preview", verification: "user-agent", userAgents: [/whatsapp/i] },
	] satisfies BotDefinition[]
).sort((left, right) => {
	const categoryDifference = BOT_CATEGORY_ORDER.indexOf(left.category) - BOT_CATEGORY_ORDER.indexOf(right.category);
	return categoryDifference || left.name.localeCompare(right.name, undefined, { sensitivity: "base" });
});

const DEFINITION_BY_ID = new Map(DEFINITIONS.map((definition) => [definition.id, definition]));

export const BOT_CATALOG: BotCatalogEntry[] = DEFINITIONS.map(({ id, name, category, verification }) => ({ id, name, category, verification }));

const ranges: Record<keyof typeof FEEDS, ParsedCidr[]> = {
	google: [],
	bing: [],
	duckduckbot: [],
	applebot: [],
	gptbot: [],
	"oai-searchbot": [],
	"chatgpt-user": [],
	perplexitybot: [],
	"perplexity-user": [],
	ccbot: [],
	shapbot: [],
	duckassistbot: [],
};
const REFRESH_INTERVAL_MS = 24 * 60 * 60 * 1_000;
let refreshTimer: ReturnType<typeof setInterval> | null = null;

function parseFeed(body: unknown): ParsedCidr[] {
	if (!body || typeof body !== "object" || !Array.isArray((body as { prefixes?: unknown }).prefixes)) throw new Error("IP feed has no prefixes array");
	const parsed: ParsedCidr[] = [];
	for (const item of (body as { prefixes: unknown[] }).prefixes) {
		if (!item || typeof item !== "object") continue;
		const entry = item as { ipv4Prefix?: unknown; ipv6Prefix?: unknown };
		const text = typeof entry.ipv4Prefix === "string" ? entry.ipv4Prefix : typeof entry.ipv6Prefix === "string" ? entry.ipv6Prefix : null;
		const cidr = text ? parseCidr(text) : null;
		if (cidr) parsed.push(cidr);
	}
	if (parsed.length === 0) throw new Error("IP feed contained no valid prefixes");
	return parsed;
}

async function refreshProvider(provider: keyof typeof FEEDS): Promise<void> {
	const response = await fetch(FEEDS[provider], { headers: { accept: "application/json" }, signal: AbortSignal.timeout(15_000) });
	if (!response.ok) throw new Error(`HTTP ${response.status}`);
	const parsed = parseFeed(await response.json());
	ranges[provider] = parsed;
	Logger.info(`Bot detection: loaded ${parsed.length} ${provider} crawler IP ranges`);
}

export async function refreshBotIpRanges(): Promise<void> {
	await Promise.all(
		(Object.keys(FEEDS) as Array<keyof typeof FEEDS>).map(async (provider) => {
			try {
				await refreshProvider(provider);
			} catch (error) {
				Logger.warn(`Bot detection: failed to refresh ${provider} crawler ranges; keeping the previous ranges`, { error });
			}
		}),
	);
}

export function startBotIpRangeRefresh(): void {
	void refreshBotIpRanges();
	if (refreshTimer) return;
	refreshTimer = setInterval(() => void refreshBotIpRanges(), REFRESH_INTERVAL_MS);
	refreshTimer.unref?.();
}

export function identifyBot(request: Request, ip: string): BotIdentity | null {
	const userAgent = request.headers.get("user-agent") ?? "";
	const definition = DEFINITIONS.find((item) => item.userAgents.some((pattern) => pattern.test(userAgent)));
	if (!definition) return null;
	const verified = definition.ipProvider ? ranges[definition.ipProvider].some((range) => cidrContains(range, ip)) : false;
	return { id: definition.id, name: definition.name, category: definition.category, verified, source: "user-agent" };
}

function blockedBots(value: unknown, fallback: string[]): string[] {
	if (value === undefined) return fallback;
	if (!Array.isArray(value)) throw new Error("Blocked bots must be an array");
	const result = [...new Set(value.map((item) => String(item).trim().toLowerCase()).filter(Boolean))];
	for (const id of result) if (!DEFINITION_BY_ID.has(id)) throw new Error(`Unknown bot: ${id}`);
	return result;
}

export function parseBotPolicy(value: unknown, fallback: BotPolicy = { blockedBots: [] }): BotPolicy {
	if (value === undefined) return { blockedBots: [...fallback.blockedBots] };
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Bot policy must be an object");
	return { blockedBots: blockedBots((value as { blockedBots?: unknown }).blockedBots, fallback.blockedBots) };
}

export function storedBotPolicy(json: string | null | undefined, fallback: BotPolicy = { blockedBots: [] }): BotPolicy {
	if (!json) return { blockedBots: [...fallback.blockedBots] };
	try {
		return parseBotPolicy(JSON.parse(json), fallback);
	} catch {
		return { blockedBots: [...fallback.blockedBots] };
	}
}

export function serializeBotPolicy(value: unknown, fallback?: string | null): string {
	const existing = storedBotPolicy(fallback);
	return JSON.stringify(parseBotPolicy(value, existing));
}

export function serializeRouteBotPolicy(value: unknown, fallback?: string | null): string | null {
	if (value === undefined) return fallback ?? null;
	if (value === null || value === "") return null;
	return JSON.stringify(parseBotPolicy(value));
}

export function resolvedBotPolicy(site: SiteRecord, route: RoutePolicyRecord | null): BotPolicy {
	return route?.bot_policy_json ? storedBotPolicy(route.bot_policy_json) : storedBotPolicy(site.bot_policy_json);
}

export function botIsBlocked(bot: BotIdentity | null, site: SiteRecord, route: RoutePolicyRecord | null): boolean {
	return Boolean(bot && resolvedBotPolicy(site, route).blockedBots.includes(bot.id));
}

export function setBotIpRangesForTests(provider: keyof typeof FEEDS, cidrs: string[]): void {
	ranges[provider] = cidrs.map((cidr) => parseCidr(cidr)).filter((cidr): cidr is ParsedCidr => cidr !== null);
}
