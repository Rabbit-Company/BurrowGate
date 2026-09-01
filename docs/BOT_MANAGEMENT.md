# Bot identification and blocking

BurrowGate classifies known search crawlers, social preview agents, and AI crawlers before applying access policy. The resolved identity is stored with the request event, shown in Recent traffic, and available in the dashboard chart selector as **Bot requests over time** or **Requests by bot**.

## Identification confidence

Published crawler source-address feeds are refreshed in memory at startup and every 24 hours. These currently cover Google crawler, Bingbot, DuckDuckBot, DuckAssistBot, Applebot, GPTBot, OAI-SearchBot, ChatGPT-User, PerplexityBot, Perplexity-User, CCBot, and ShapBot.

Bot identification always starts with the User-Agent. Requests without a recognized bot User-Agent skip IP-range lookup entirely. When the identified bot publishes an address feed, BurrowGate checks only that bot's ranges and marks the identity **verified** when its address matches. A request from a published crawler address without the corresponding User-Agent is not classified as a bot.

User-Agent-only identities remain available for visibility and policy enforcement but are marked unverified. User agents can be spoofed, so bot identity must not be used to grant additional access.

Feed refresh failures do not interrupt proxy startup or discard the last successfully loaded ranges. Until the first successful refresh, requests can still be classified from User-Agent but will not be marked verified.

## Categories

The catalog separates **AI Crawler**, **AI Search**, **AI Assistant**, **Search Engine**, **Archiver**, **Page Preview and Social**, **Advertising**, and **SEO Tool** traffic. This lets policies block training crawlers without also blocking user-requested assistants, search bots, link-preview agents, or SEO tools.

## Policy behavior

Open **Sites**, edit a site, and use its **Bots** tab to select bots that should receive HTTP 403. Categories can be blocked as a group or expanded to choose individual bots. Identification and metrics are always active; the checkboxes control blocking only.

A route policy can inherit the site's blocked-bot list or replace it with a route-specific list. Replacement makes both narrow exceptions and stricter paths possible. For example, a site can block GPTBot generally while `/public-docs/**` uses an empty route override to allow it.

Bot policy runs after explicit IP/ASN/country network rules and before route access mode, browser challenges, rate limits, and origin proxying. A bot rejected by bot policy is stored with decision `bot-blocked`.

## Visibility and analytics

Bot identification is recorded on every matching request, whether that bot is allowed or blocked. In **Recent traffic**, enable the hidden **Bot** column for a compact identity badge, or open a request row to see its bot name, category, and verification state.

The dashboard also provides:

- **Top bots (identified requests)** in the same panel as Top referrers
- **Bot requests over time** in the main chart selector
- **Requests by bot** for comparing individual agents

## Recognized bots

The built-in catalog contains 55 bot definitions. Bots are shown below in the same category and alphabetical order used by the dashboard.

### AI Crawler

- Amazonbot
- Anchor Browser
- Applebot-Extended
- Bytespider
- CCBot
- ClaudeBot
- Cloudflare Crawler
- cohere-ai
- Google-CloudVertexBot
- Google-Extended
- GPTBot
- Meta-ExternalAgent
- Novellum AI Crawl
- ProRataInc
- ShapBot
- TikTok Spider

### AI Search

- Claude-SearchBot
- Meta-WebIndexer
- OAI-SearchBot
- PerplexityBot

### AI Assistant

- ChatGPT-User
- Claude-User
- DuckAssistBot
- Manus Bot
- Meta-ExternalFetcher
- MistralAI-User
- Perplexity-User

### Search Engine

- Applebot
- Baidu
- Bingbot
- DuckDuckBot
- Google crawler
- Naver (Yeti)
- PetalBot
- SeznamBot
- Sogou Spider
- Terracotta Bot
- Timpibot
- YandexBot

### Archiver

- archive.org_bot
- Arquivo Web Crawler

### Page Preview and Social

- Discordbot
- FacebookBot
- FacebookExternalHit
- LinkedInBot
- Pinterestbot
- Slackbot
- Twitterbot
- WhatsApp

### Advertising

- Meta-ExternalAds

### SEO Tool

- AhrefsBot
- DotBot
- MJ12bot
- Rogerbot
- SemrushBot
