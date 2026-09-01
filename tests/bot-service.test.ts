import { describe, expect, test } from "bun:test";
import { repository } from "../src/db/repository.ts";
import { BOT_CATALOG, BOT_CATEGORY_ORDER, botIsBlocked, identifyBot, setBotIpRangesForTests, storedBotPolicy } from "../src/services/bot-service.ts";
import { recordEvent } from "../src/services/event-service.ts";
import { createRoutePolicy, routePolicyView } from "../src/services/route-policy-service.ts";
import { createSite, siteView, updateSite } from "../src/services/site-service.ts";

describe("bot identification", () => {
	test("sorts the catalog by category and then bot name", () => {
		for (let index = 1; index < BOT_CATALOG.length; index += 1) {
			const previous = BOT_CATALOG[index - 1]!;
			const current = BOT_CATALOG[index]!;
			const previousCategory = BOT_CATEGORY_ORDER.indexOf(previous.category);
			const currentCategory = BOT_CATEGORY_ORDER.indexOf(current.category);
			expect(currentCategory).toBeGreaterThanOrEqual(previousCategory);
			if (currentCategory === previousCategory) {
				expect(current.name.localeCompare(previous.name, undefined, { sensitivity: "base" })).toBeGreaterThanOrEqual(0);
			}
		}
	});

	test("recognizes AI bots from their User-Agent", () => {
		const bot = identifyBot(new Request("https://example.test/", { headers: { "user-agent": "Mozilla/5.0; compatible; GPTBot/1.2" } }), "203.0.113.4");
		expect(bot).toEqual({ id: "gptbot", name: "GPTBot", category: "ai-crawler", verified: false, source: "user-agent" });
	});

	test("recognizes PetalBot and ShapBot from their User-Agent", () => {
		expect(
			identifyBot(
				new Request("https://example.test/", {
					headers: { "user-agent": "Mozilla/5.0 (compatible; PetalBot;+https://webmaster.petalsearch.com/site/petalbot)" },
				}),
				"203.0.113.5",
			),
		).toMatchObject({
			id: "petalbot",
			category: "search-engine",
			verified: false,
			source: "user-agent",
		});
		expect(
			identifyBot(new Request("https://example.test/", { headers: { "user-agent": "Mozilla/5.0 (compatible; ShapBot/1.0)" } }), "203.0.113.6"),
		).toMatchObject({
			id: "shapbot",
			category: "ai-crawler",
			verified: false,
			source: "user-agent",
		});
	});

	test("recognizes each Meta crawler as an independent bot", () => {
		const cases = [
			["facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", "facebookexternalhit", "page-preview"],
			["meta-webindexer/1.1 (+/documentation/sharing/webmasters/web-crawlers)", "meta-webindexer", "ai-search"],
			["meta-externalads/1.1 (+/documentation/sharing/webmasters/web-crawlers)", "meta-externalads", "advertising"],
			["meta-externalagent/1.1 (+/documentation/sharing/webmasters/web-crawlers)", "meta-externalagent", "ai-crawler"],
			["meta-externalfetcher/1.1 (+/documentation/sharing/webmasters/web-crawlers)", "meta-externalfetcher", "ai-assistant"],
		] as const;

		for (const [userAgent, id, category] of cases) {
			expect(identifyBot(new Request("https://example.test/", { headers: { "user-agent": userAgent } }), "203.0.113.7")).toMatchObject({
				id,
				category,
				verified: false,
				source: "user-agent",
			});
		}
	});

	test("recognizes the additional crawlers listed by Cloudflare", () => {
		const cases = [
			["Anchor Browser", "anchor-browser", "ai-crawler"],
			["archive.org_bot", "archive-org-bot", "archiver"],
			["Arquivo-web-crawler (compatible; heritrix/3.4.0)", "arquivo-web-crawler", "archiver"],
			["CloudflareBrowserRenderingCrawler/1.0", "cloudflare-crawler", "ai-crawler"],
			["DuckAssistBot/1.2", "duckassistbot", "ai-assistant"],
			["FacebookBot/1.0", "facebookbot", "page-preview"],
			["Google-CloudVertexBot/1.0", "google-cloudvertexbot", "ai-crawler"],
			["ManusBot/1.0", "manus-bot", "ai-assistant"],
			["MistralAI-User/1.0", "mistralai-user", "ai-assistant"],
			["Novellum", "novellum", "ai-crawler"],
			["ProRataInc/1.0", "proratainc", "ai-crawler"],
			["Terracotta-News", "terracotta", "search-engine"],
			["TikTokSpider/1.0", "tiktokspider", "ai-crawler"],
			["Timpibot/1.0 (+http://timpi.io/crawler)", "timpibot", "search-engine"],
		] as const;

		for (const [userAgent, id, category] of cases) {
			expect(identifyBot(new Request("https://example.test/", { headers: { "user-agent": userAgent } }), "203.0.113.8")).toMatchObject({
				id,
				category,
				verified: false,
				source: "user-agent",
			});
		}
	});

	test("verifies Google and Bing crawlers against published-range data", () => {
		setBotIpRangesForTests("google", ["66.249.64.0/24", "2001:db8:1::/48"]);
		setBotIpRangesForTests("bing", ["157.55.39.0/24"]);
		expect(identifyBot(new Request("https://example.test/", { headers: { "user-agent": "Googlebot/2.1" } }), "66.249.64.10")).toMatchObject({
			id: "googlebot",
			verified: true,
			source: "user-agent",
		});
		expect(identifyBot(new Request("https://example.test/", { headers: { "user-agent": "bingbot/2.0" } }), "157.55.39.42")).toMatchObject({
			id: "bingbot",
			verified: true,
			source: "user-agent",
		});
		expect(identifyBot(new Request("https://example.test/", { headers: { "user-agent": "bingbot/2.0" } }), "66.249.64.10")).toMatchObject({
			id: "bingbot",
			verified: false,
		});
	});

	test("verifies ShapBot against its published IP ranges", () => {
		setBotIpRangesForTests("shapbot", ["34.122.173.216/32"]);
		expect(identifyBot(new Request("https://example.test/", { headers: { "user-agent": "ShapBot/1.0" } }), "34.122.173.216")).toMatchObject({
			id: "shapbot",
			verified: true,
			source: "user-agent",
		});
	});

	test("does not identify ordinary requests from crawler IP ranges alone", () => {
		setBotIpRangesForTests("google", ["66.249.64.0/24"]);
		expect(identifyBot(new Request("https://example.test/", { headers: { "user-agent": "Mozilla/5.0" } }), "66.249.64.10")).toBeNull();
	});
});

describe("bot policies", () => {
	test("site policies persist and route policies can override them", async () => {
		const { site } = await createSite({
			name: "Bot policy site",
			publicHost: `bots-${crypto.randomUUID()}.test`,
			originUrl: "https://origin.test",
			botPolicy: { blockedBots: ["gptbot"] },
		});
		expect(siteView(site).botPolicy.blockedBots).toEqual(["gptbot"]);

		const gptbot = identifyBot(new Request("https://example.test/", { headers: { "user-agent": "GPTBot/1.0" } }), "203.0.113.10")!;
		expect(botIsBlocked(gptbot, site, null)).toBe(true);

		const route = await createRoutePolicy(site.id, {
			name: "Public docs",
			pathPattern: "/docs/**",
			botPolicy: { blockedBots: ["bingbot"] },
		});
		expect(routePolicyView(route).botPolicy?.blockedBots).toEqual(["bingbot"]);
		expect(botIsBlocked(gptbot, site, route)).toBe(false);

		const { site: updated } = await updateSite(site.id, {
			name: site.name,
			publicHost: site.public_host,
			originUrl: site.origin_url,
			botPolicy: { blockedBots: ["claudebot", "gptbot"] },
		});
		expect(storedBotPolicy(updated.bot_policy_json).blockedBots).toEqual(["claudebot", "gptbot"]);
	});

	test("rejects unknown bot identifiers", async () => {
		await expect(
			createSite({
				name: "Invalid bot policy",
				publicHost: `invalid-bot-${crypto.randomUUID()}.test`,
				originUrl: "https://origin.test",
				botPolicy: { blockedBots: ["made-up-bot"] },
			}),
		).rejects.toThrow("Unknown bot");
	});
});

describe("bot metrics", () => {
	test("aggregates request counts per bot and blocked totals", async () => {
		const { site } = await createSite({ name: "Bot metrics", publicHost: `bot-metrics-${crypto.randomUUID()}.test`, originUrl: "https://origin.test" });
		const now = Date.now();
		await recordEvent({
			siteId: site.id,
			sessionId: null,
			ip: "203.0.113.20",
			method: "GET",
			path: "/",
			status: 200,
			decision: "proxied",
			latencyMs: 10,
			botId: "gptbot",
			botName: "GPTBot",
			botCategory: "ai-crawler",
			botVerified: false,
		});
		await recordEvent({
			siteId: site.id,
			sessionId: null,
			ip: "203.0.113.21",
			method: "GET",
			path: "/private",
			status: 403,
			decision: "bot-blocked",
			latencyMs: 2,
			botId: "gptbot",
			botName: "GPTBot",
			botCategory: "ai-crawler",
			botVerified: false,
		});

		const metrics = await repository.botMetrics(site.id, now - 60_000, now + 60_000, 60_000);
		expect(metrics.bots[0]).toMatchObject({ id: "gptbot", name: "GPTBot", category: "ai-crawler", count: 2, blocked: 1 });
		expect(metrics.series.reduce((total, point) => total + Number(point.bot0 ?? 0), 0)).toBe(2);

		const topBots = await repository.tabBotMetrics(site.id, now - 60_000, now + 60_000);
		expect(topBots[0]).toMatchObject({ botId: "gptbot", name: "GPTBot", category: "ai-crawler", count: 2 });
	});
});
