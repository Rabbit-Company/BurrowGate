import type { Web } from "@rabbit-company/web";
import { challengeRegistry } from "../challenges/index.ts";
import {
	adminCookieName,
	adminCookieNames,
	config,
	cookieCanBeIssuedForRequest,
	insecureCookieConfigurationMessage,
	secureCookieForRequest,
} from "../config.ts";
import { repository, type SortDirection } from "../db/repository.ts";
import { addCountryRule, addIpRule, invalidateNetworkPolicy } from "../services/ip-rule-service.ts";
import { adminSessionTokens, createAdminSession, getAdminSession } from "../services/session-service.ts";
import { createSite, parseDefaultNetworkAction, siteView, updateSite, type SiteInput } from "../services/site-service.ts";
import { createRoutePolicy, deleteRoutePolicy, routePolicyView, updateRoutePolicy, type RoutePolicyInput } from "../services/route-policy-service.ts";
import { invalidateRouteRateLimiter } from "../services/rate-limit-service.ts";
import { issueLetsEncryptCertificate } from "../services/acme-service.ts";
import { recordCertificateEvent, saveCertificate, tlsView, updateTlsSettings } from "../services/certificate-service.ts";
import { geoIpStatus } from "../services/geoip-service.ts";
import {
	DEFAULT_ERROR_HTML_TEMPLATE,
	DEFAULT_ERROR_JSON_FIELDS,
	ERROR_JSON_FIELD_OPTIONS,
	ERROR_TEMPLATE_PLACEHOLDERS,
} from "../services/error-response-service.ts";
import { DEFAULT_CHALLENGE_HTML_TEMPLATE, CHALLENGE_TEMPLATE_PLACEHOLDERS } from "../services/challenge-page-service.ts";
import { requestTlsReload } from "../services/tls-listener-service.ts";
import {
	accessListView,
	createAccessUser,
	importAccessUsers,
	removeAccessUser,
	updateAccessSettings,
	updateAccessUser,
} from "../services/access-list-service.ts";
import type { DefaultNetworkAction, IpRuleAction, SiteRecord } from "../types.ts";
import { adminPage, loginPage } from "../ui/admin-page.ts";
import { serializeCookie } from "../utils/cookies.ts";
import { sha256Hex, timingSafeEqualText } from "../utils/crypto.ts";
import { htmlResponse, jsonResponse, sameOriginRequest } from "../utils/http.ts";
import { flushBandwidthMetrics } from "../services/bandwidth-service.ts";
import { originHealthManager } from "../services/origin-health-service.ts";

async function guard(request: Request): Promise<Response | null> {
	return (await getAdminSession(request)) ? null : jsonResponse({ error: "Unauthorized" }, 401);
}

function mutationGuard(request: Request): Response | null {
	if (!sameOriginRequest(request) || request.headers.get("x-burrowgate-admin") !== "1") {
		return jsonResponse({ error: "CSRF validation failed" }, 403);
	}
	return null;
}

function integerParam(url: URL, name: string, fallback: number, minimum: number, maximum: number): number {
	const value = Number(url.searchParams.get(name));
	if (!Number.isInteger(value)) return fallback;
	return Math.min(maximum, Math.max(minimum, value));
}

function stringParam(url: URL, name: string): string | undefined {
	const value = url.searchParams.get(name)?.trim();
	return value || undefined;
}

function enumParam<T extends string>(url: URL, name: string, allowed: readonly T[], fallback?: T): T | undefined {
	const value = url.searchParams.get(name) as T | null;
	return value && allowed.includes(value) ? value : fallback;
}

function sortDirection(url: URL): SortDirection {
	return url.searchParams.get("sortDirection") === "asc" ? "asc" : "desc";
}

const DEFAULT_DATE_RANGE_MS = 24 * 3_600_000;
const MIN_DATE_RANGE_MS = 60_000;
const MAX_DATE_RANGE_MS = 366 * 24 * 3_600_000;
const METRIC_BUCKETS_MS = [
	60_000, 300_000, 900_000, 1_800_000, 3_600_000, 7_200_000, 10_800_000, 21_600_000, 43_200_000, 86_400_000, 172_800_000, 345_600_000, 604_800_000,
] as const;

function requestedDateRange(url: URL): { since: number; until: number; durationMs: number } {
	const now = Date.now();
	const rawUntil = Number(url.searchParams.get("to"));
	const rawSince = Number(url.searchParams.get("from"));
	let until = Number.isFinite(rawUntil) && rawUntil > 0 ? Math.min(rawUntil, now + 300_000) : now;
	let since = Number.isFinite(rawSince) && rawSince >= 0 ? rawSince : until - DEFAULT_DATE_RANGE_MS;
	if (until - since < MIN_DATE_RANGE_MS) since = until - MIN_DATE_RANGE_MS;
	if (until - since > MAX_DATE_RANGE_MS) since = until - MAX_DATE_RANGE_MS;
	if (since < 0) since = 0;
	return { since, until, durationMs: until - since };
}

function metricBucketSize(durationMs: number): number {
	const minimum = Math.max(60_000, Math.ceil(durationMs / 120));
	return METRIC_BUCKETS_MS.find((candidate) => candidate >= minimum) ?? 604_800_000;
}

async function firstSite(): Promise<SiteRecord | null> {
	return (await repository.allSites())[0] ?? null;
}

async function selectedSite(url: URL): Promise<{ site: SiteRecord | null; error: Response | null }> {
	const requestedId = stringParam(url, "siteId");
	if (!requestedId) return { site: await firstSite(), error: null };
	const site = await repository.siteById(requestedId);
	return site ? { site, error: null } : { site: null, error: jsonResponse({ error: "Selected site was not found" }, 404) };
}

function providerViews() {
	return challengeRegistry.names().map((name) => {
		const provider = challengeRegistry.get(name);
		return { name: provider.name, title: provider.title, description: provider.description };
	});
}

async function parseSiteInput(request: Request): Promise<SiteInput> {
	const body = await request.json();
	if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("Site payload must be an object");
	return body as SiteInput;
}

async function parseRoutePolicyInput(request: Request): Promise<RoutePolicyInput> {
	const body = await request.json();
	if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("Route policy payload must be an object");
	return body as RoutePolicyInput;
}

export function registerAdminRoutes(app: Web<any>): void {
	app.get("/_burrowgate/admin/login", async (ctx) =>
		(await getAdminSession(ctx.req))
			? Response.redirect(new URL("/_burrowgate/admin", ctx.req.url).href, 302)
			: htmlResponse(loginPage(cookieCanBeIssuedForRequest(ctx.req) ? undefined : insecureCookieConfigurationMessage())),
	);

	app.post("/_burrowgate/admin/login", async (ctx) => {
		const form = await ctx.req.formData();
		const username = String(form.get("username") ?? "");
		const password = String(form.get("password") ?? "");
		if (!(await timingSafeEqualText(username, config.admin.username)) || !(await timingSafeEqualText(password, config.admin.password))) {
			return htmlResponse(loginPage("Invalid username or password"), 401);
		}
		if (!cookieCanBeIssuedForRequest(ctx.req)) {
			return htmlResponse(loginPage(insecureCookieConfigurationMessage()), 409);
		}
		const session = await createAdminSession(ctx.req, username);
		return new Response(null, { status: 302, headers: { location: "/_burrowgate/admin", "set-cookie": session.cookie } });
	});

	app.get("/_burrowgate/admin", async (ctx) =>
		(await getAdminSession(ctx.req)) ? htmlResponse(adminPage()) : Response.redirect(new URL("/_burrowgate/admin/login", ctx.req.url).href, 302),
	);

	app.get(
		"/_burrowgate/static/chart.umd.js",
		() =>
			new Response(Bun.file("node_modules/chart.js/dist/chart.umd.js"), {
				headers: { "content-type": "text/javascript; charset=utf-8", "cache-control": "public, max-age=86400" },
			}),
	);

	app.get(
		"/_burrowgate/static/admin.js",
		() =>
			new Response(Bun.file("public/admin.js"), {
				headers: { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-store" },
			}),
	);

	app.get("/_burrowgate/static/world.svg", (ctx) => {
		const accepted = ctx.req.headers.get("accept-encoding") ?? "";
		const encoding = accepted.includes("br") ? "br" : accepted.includes("gzip") ? "gzip" : null;
		const file = encoding === "br" ? "public/world.svg.br" : encoding === "gzip" ? "public/world.svg.gz" : "public/world.svg";
		const headers: Record<string, string> = {
			"content-type": "image/svg+xml; charset=utf-8",
			"cache-control": "public, max-age=2592000, immutable",
			vary: "Accept-Encoding",
		};
		if (encoding) headers["content-encoding"] = encoding;
		return new Response(Bun.file(file), { headers });
	});

	app.get("/_burrowgate/api/admin/sites", async (ctx) => {
		const denied = await guard(ctx.req);
		if (denied) return denied;
		return jsonResponse({
			items: (await repository.allSites()).map((site) => ({ ...siteView(site), originHealth: originHealthManager.summary(site.id) })),
			challengeProviders: providerViews(),
			defaultEventRetentionDays: config.eventRetentionDays,
			errorResponseDefaults: {
				mode: "json",
				htmlTemplate: DEFAULT_ERROR_HTML_TEMPLATE,
				jsonFields: DEFAULT_ERROR_JSON_FIELDS,
				jsonFieldOptions: ERROR_JSON_FIELD_OPTIONS,
				placeholders: ERROR_TEMPLATE_PLACEHOLDERS,
			},
			challengeDefaults: {
				htmlTemplate: DEFAULT_CHALLENGE_HTML_TEMPLATE,
				placeholders: CHALLENGE_TEMPLATE_PLACEHOLDERS,
			},
		});
	});

	app.post("/_burrowgate/api/admin/sites", async (ctx) => {
		const denied = (await guard(ctx.req)) ?? mutationGuard(ctx.req);
		if (denied) return denied;
		try {
			const created = await createSite(await parseSiteInput(ctx.req));
			await originHealthManager.refreshSite(created.site.id);
			return jsonResponse(
				{
					site: siteView(created.site),
					generatedSigningSecret: created.generatedSigningSecret,
				},
				201,
			);
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to create site" }, 400);
		}
	});

	app.addRoute("PUT", "/_burrowgate/api/admin/sites/:id", async (ctx: any) => {
		const denied = (await guard(ctx.req)) ?? mutationGuard(ctx.req);
		if (denied) return denied;
		try {
			const site = await updateSite(ctx.params.id, await parseSiteInput(ctx.req));
			await originHealthManager.refreshSite(site.id);
			await requestTlsReload();
			return jsonResponse({ site: siteView(site) });
		} catch (error) {
			const message = error instanceof Error ? error.message : "Unable to update site";
			return jsonResponse({ error: message }, message === "Site not found" ? 404 : 400);
		}
	});

	app.get("/_burrowgate/api/admin/sites/:id/health", async (ctx: any) => {
		const denied = await guard(ctx.req);
		if (denied) return denied;
		const site = await repository.siteById(ctx.params.id);
		if (!site) return jsonResponse({ error: "Site not found" }, 404);
		return jsonResponse({
			status: originHealthManager.summary(site.id),
			events: await originHealthManager.events(site.id, integerParam(new URL(ctx.req.url), "limit", 50, 1, 200)),
			alerts: (await repository.healthAlerts(site.id, 25)).map((alert) => ({
				id: alert.id,
				type: alert.event_type,
				status: alert.status,
				attempts: Number(alert.attempts),
				lastError: alert.last_error,
				createdAt: Number(alert.created_at),
				deliveredAt: alert.delivered_at === null ? null : Number(alert.delivered_at),
			})),
		});
	});

	app.post("/_burrowgate/api/admin/sites/:id/health/check", async (ctx: any) => {
		const denied = (await guard(ctx.req)) ?? mutationGuard(ctx.req);
		if (denied) return denied;
		try {
			return jsonResponse({ status: await originHealthManager.checkNow(ctx.params.id) });
		} catch (error) {
			const message = error instanceof Error ? error.message : "Unable to run origin health check";
			return jsonResponse({ error: message }, message === "Site not found" ? 404 : 409);
		}
	});

	app.get("/_burrowgate/api/admin/route-policies", async (ctx) => {
		const denied = await guard(ctx.req);
		if (denied) return denied;
		const selection = await selectedSite(new URL(ctx.req.url));
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ items: [] });
		return jsonResponse({
			items: (await repository.routePolicies(selection.site.id)).map(routePolicyView),
			site: siteView(selection.site),
		});
	});

	app.post("/_burrowgate/api/admin/route-policies", async (ctx) => {
		const denied = (await guard(ctx.req)) ?? mutationGuard(ctx.req);
		if (denied) return denied;
		const selection = await selectedSite(new URL(ctx.req.url));
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "Create a site before adding route policies" }, 400);
		try {
			const policy = await createRoutePolicy(selection.site.id, await parseRoutePolicyInput(ctx.req));
			return jsonResponse({ policy: routePolicyView(policy) }, 201);
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to create route policy" }, 400);
		}
	});

	app.addRoute("PUT", "/_burrowgate/api/admin/route-policies/:id", async (ctx: any) => {
		const denied = (await guard(ctx.req)) ?? mutationGuard(ctx.req);
		if (denied) return denied;
		const selection = await selectedSite(new URL(ctx.req.url));
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "Selected site was not found" }, 404);
		try {
			const policy = await updateRoutePolicy(selection.site.id, ctx.params.id, await parseRoutePolicyInput(ctx.req));
			invalidateRouteRateLimiter(policy.id);
			return jsonResponse({ policy: routePolicyView(policy) });
		} catch (error) {
			const message = error instanceof Error ? error.message : "Unable to update route policy";
			return jsonResponse({ error: message }, message === "Route policy not found" ? 404 : 400);
		}
	});

	app.addRoute("DELETE", "/_burrowgate/api/admin/route-policies/:id", async (ctx: any) => {
		const denied = (await guard(ctx.req)) ?? mutationGuard(ctx.req);
		if (denied) return denied;
		const selection = await selectedSite(new URL(ctx.req.url));
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "Selected site was not found" }, 404);
		try {
			await deleteRoutePolicy(selection.site.id, ctx.params.id);
			invalidateRouteRateLimiter(ctx.params.id);
			return jsonResponse({ ok: true });
		} catch (error) {
			const message = error instanceof Error ? error.message : "Unable to delete route policy";
			return jsonResponse({ error: message }, message === "Route policy not found" ? 404 : 400);
		}
	});

	app.get("/_burrowgate/api/admin/access-list", async (ctx) => {
		const denied = await guard(ctx.req);
		if (denied) return denied;
		const selection = await selectedSite(new URL(ctx.req.url));
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "Create a site before configuring access authentication" }, 400);
		return jsonResponse(await accessListView(selection.site.id));
	});

	app.addRoute("PUT", "/_burrowgate/api/admin/access-list", async (ctx) => {
		const denied = (await guard(ctx.req)) ?? mutationGuard(ctx.req);
		if (denied) return denied;
		const selection = await selectedSite(new URL(ctx.req.url));
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "Create a site before configuring access authentication" }, 400);
		try {
			const body = (await ctx.req.json()) as any;
			await updateAccessSettings(selection.site.id, body ?? {});
			return jsonResponse(await accessListView(selection.site.id));
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to update access-list settings" }, 400);
		}
	});

	app.post("/_burrowgate/api/admin/access-list/users", async (ctx) => {
		const denied = (await guard(ctx.req)) ?? mutationGuard(ctx.req);
		if (denied) return denied;
		const selection = await selectedSite(new URL(ctx.req.url));
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "Create a site before adding users" }, 400);
		try {
			const user = await createAccessUser(selection.site.id, (await ctx.req.json()) as any);
			return jsonResponse({ user }, 201);
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to create access user" }, 400);
		}
	});

	app.addRoute("PUT", "/_burrowgate/api/admin/access-list/users/:id", async (ctx: any) => {
		const denied = (await guard(ctx.req)) ?? mutationGuard(ctx.req);
		if (denied) return denied;
		const selection = await selectedSite(new URL(ctx.req.url));
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "Selected site was not found" }, 404);
		try {
			const user = await updateAccessUser(selection.site.id, ctx.params.id, (await ctx.req.json()) as any);
			return jsonResponse({ user });
		} catch (error) {
			const message = error instanceof Error ? error.message : "Unable to update access user";
			return jsonResponse({ error: message }, message === "Access user not found" ? 404 : 400);
		}
	});

	app.addRoute("DELETE", "/_burrowgate/api/admin/access-list/users/:id", async (ctx: any) => {
		const denied = (await guard(ctx.req)) ?? mutationGuard(ctx.req);
		if (denied) return denied;
		const selection = await selectedSite(new URL(ctx.req.url));
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "Selected site was not found" }, 404);
		try {
			await removeAccessUser(selection.site.id, ctx.params.id);
			return jsonResponse({ ok: true });
		} catch (error) {
			const message = error instanceof Error ? error.message : "Unable to remove access user";
			return jsonResponse({ error: message }, message === "Access user not found" ? 404 : 400);
		}
	});

	app.post("/_burrowgate/api/admin/access-list/import", async (ctx) => {
		const denied = (await guard(ctx.req)) ?? mutationGuard(ctx.req);
		if (denied) return denied;
		const selection = await selectedSite(new URL(ctx.req.url));
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "Selected site was not found" }, 404);
		try {
			const body = (await ctx.req.json()) as { userIds?: unknown };
			const imported = await importAccessUsers(selection.site.id, body?.userIds);
			return jsonResponse({ imported }, 201);
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to import access users" }, 400);
		}
	});

	app.get("/_burrowgate/api/admin/geo-metrics", async (ctx) => {
		const denied = await guard(ctx.req);
		if (denied) return denied;
		const url = new URL(ctx.req.url);
		const selection = await selectedSite(url);
		if (selection.error) return selection.error;
		const range = requestedDateRange(url);
		await flushBandwidthMetrics();
		const metrics = await repository.geoMetrics(selection.site?.id, range.since, range.until);
		return jsonResponse({
			rangeFrom: range.since,
			rangeTo: range.until,
			rangeDurationMs: range.durationMs,
			site: selection.site ? siteView(selection.site) : null,
			status: geoIpStatus(),
			requests: metrics.requests,
			sessions: metrics.sessions,
			bandwidth: metrics.bandwidth,
		});
	});

	app.get("/_burrowgate/api/admin/overview", async (ctx) => {
		const denied = await guard(ctx.req);
		if (denied) return denied;
		const url = new URL(ctx.req.url);
		const selection = await selectedSite(url);
		if (selection.error) return selection.error;
		const range = requestedDateRange(url);
		return jsonResponse({
			...(await repository.overview(selection.site?.id, range.since, range.until)),
			retentionDays: selection.site?.event_retention_days ?? config.eventRetentionDays,
			defaultPageSize: config.adminPageSize,
			site: selection.site ? siteView(selection.site) : null,
			originHealth: selection.site ? originHealthManager.summary(selection.site.id) : null,
		});
	});

	app.get("/_burrowgate/api/admin/metrics", async (ctx) => {
		const denied = await guard(ctx.req);
		if (denied) return denied;
		const url = new URL(ctx.req.url);
		const section = enumParam(url, "section", ["traffic", "bandwidth", "sessions", "rules", "routes", "access", "sites"] as const, "traffic") ?? "traffic";
		const selection = section === "sites" ? { site: null, error: null } : await selectedSite(url);
		if (selection.error) return selection.error;
		const range = requestedDateRange(url);
		const bucketMs = metricBucketSize(range.durationMs);
		const since = range.since;
		const until = range.until;
		const firstBucket = Math.floor(since / bucketMs) * bucketMs;
		const finalBucket = Math.floor(until / bucketMs) * bucketMs;
		const bucketCount = Math.floor((finalBucket - firstBucket) / bucketMs) + 1;
		const base = {
			section,
			rangeFrom: range.since,
			rangeTo: range.until,
			rangeDurationMs: range.durationMs,
			bucketMs,
			bucketCount,
		};

		if (section === "bandwidth") {
			await flushBandwidthMetrics();
			const metrics = await repository.bandwidthMetrics(selection.site?.id, since, until, bucketMs);
			return jsonResponse({
				...base,
				primary: {
					title: "Client-side bandwidth",
					subtitle: "Payload bytes crossing between users and BurrowGate",
					type: "line",
					timeSeries: true,
					valueFormat: "bytes",
					emptyMessage: "No client bandwidth in this range.",
					datasets: [
						{ key: "clientDownload", label: "Sent to clients" },
						{ key: "clientUpload", label: "Received from clients" },
					],
					data: metrics.series,
				},
				secondary: {
					title: "Upstream bandwidth",
					subtitle: "Payload bytes crossing between BurrowGate and origin servers",
					type: "line",
					timeSeries: true,
					valueFormat: "bytes",
					emptyMessage: "No upstream bandwidth in this range.",
					datasets: [
						{ key: "upstreamDownload", label: "Received from origins" },
						{ key: "upstreamUpload", label: "Sent to origins" },
					],
					data: metrics.series,
				},
				breakdown: [],
				protocols: metrics.protocols,
			});
		}

		if (section === "sessions") {
			const metrics = await repository.sessionMetrics(selection.site?.id, since, until, bucketMs);
			return jsonResponse({
				...base,
				primary: {
					title: "Session lifecycle",
					subtitle: "New, expired, and revoked visitor sessions per interval",
					type: "line",
					timeSeries: true,
					valueFormat: "number",
					emptyMessage: "No session changes in this range.",
					datasets: [
						{ key: "created", label: "Created" },
						{ key: "expired", label: "Expired" },
						{ key: "revoked", label: "Revoked" },
					],
					data: metrics.series,
				},
				secondary: {
					title: "Active sessions",
					subtitle: "Sessions that remained valid at the end of each interval",
					type: "line",
					timeSeries: true,
					valueFormat: "number",
					emptyMessage: "No active sessions in this range.",
					datasets: [{ key: "active", label: "Active sessions" }],
					data: metrics.series,
				},
				breakdown: metrics.states,
			});
		}

		if (section === "rules") {
			const metrics = await repository.ruleMetrics(selection.site?.id ?? "", since, until, bucketMs);
			return jsonResponse({
				...base,
				primary: {
					title: "Network rules created",
					subtitle: "IP and country rules added per interval",
					type: "line",
					timeSeries: true,
					valueFormat: "number",
					emptyMessage: "No network rules were created in this range.",
					datasets: [
						{ key: "pass", label: "Allow and follow route" },
						{ key: "allow", label: "Allow and bypass" },
						{ key: "block", label: "Block" },
						{ key: "challenge", label: "Challenge" },
					],
					data: metrics.series,
				},
				secondary: {
					title: "Current rule state",
					subtitle: "Active and expired rules grouped by action",
					type: "bar",
					timeSeries: false,
					valueFormat: "number",
					emptyMessage: "No network rules are configured.",
					datasets: [
						{ key: "active", label: "Active" },
						{ key: "expired", label: "Expired" },
					],
					data: metrics.states,
				},
				breakdown: [],
			});
		}

		if (section === "routes") {
			const metrics = await repository.routeMetrics(selection.site?.id ?? "", since, until, bucketMs);
			return jsonResponse({
				...base,
				primary: {
					title: "Route outcomes",
					subtitle: "How route policies handled HTTP and WebSocket requests",
					type: "line",
					timeSeries: true,
					valueFormat: "number",
					emptyMessage: "No route activity in this range.",
					datasets: [
						{ key: "verified", label: "Verified" },
						{ key: "bypassed", label: "Bypassed" },
						{ key: "challenged", label: "Challenged" },
						{ key: "rateLimited", label: "Rate limited" },
						{ key: "blocked", label: "Blocked" },
					],
					data: metrics.series,
				},
				secondary: {
					title: "Route policy configuration",
					subtitle: "Current policies by access mode and rate-limit usage",
					type: "bar",
					timeSeries: false,
					valueFormat: "number",
					emptyMessage: "No route policies are configured.",
					datasets: [{ key: "count", label: "Policies" }],
					data: metrics.policies,
				},
				breakdown: [
					{ label: "Enabled policies", count: metrics.enabledPolicies },
					{ label: "Disabled policies", count: metrics.disabledPolicies },
				],
			});
		}

		if (section === "access") {
			const metrics = await repository.accessListMetrics(selection.site?.id ?? "", since, until, bucketMs);
			return jsonResponse({
				...base,
				primary: {
					title: "Access authentication",
					subtitle: "Authenticated requests and login outcomes",
					type: "line",
					timeSeries: true,
					valueFormat: "number",
					emptyMessage: "No access authentication activity in this range.",
					datasets: [
						{ key: "authenticated", label: "Authenticated" },
						{ key: "loginRequired", label: "Login required" },
						{ key: "failed", label: "Failed" },
						{ key: "rateLimited", label: "Rate limited" },
					],
					data: metrics.series,
				},
				secondary: {
					title: "Assigned users",
					subtitle: "Current users by state",
					type: "bar",
					timeSeries: false,
					valueFormat: "number",
					emptyMessage: "No users are assigned to this site.",
					datasets: [{ key: "count", label: "Users" }],
					data: [
						{ label: "Active", count: metrics.activeUsers },
						{ label: "Disabled", count: metrics.disabledUsers },
					],
				},
				breakdown: [
					{ label: "Active users", count: metrics.activeUsers },
					{ label: "Disabled users", count: metrics.disabledUsers },
				],
			});
		}

		if (section === "sites") {
			const metrics = await repository.siteMetrics(since, until, bucketMs);
			return jsonResponse({
				...base,
				primary: {
					title: "Traffic by site",
					subtitle: "Request volume across the busiest configured sites",
					type: "line",
					timeSeries: true,
					valueFormat: "number",
					emptyMessage: "No site traffic in this range.",
					datasets: metrics.sites.map((site) => ({ key: site.key, label: site.label })),
					data: metrics.series.map((point) => ({ bucket: point.bucket, ...point.values })),
				},
				secondary: {
					title: "Origin latency by site",
					subtitle: "Average origin response time over the selected range",
					type: "bar",
					timeSeries: false,
					valueFormat: "duration",
					emptyMessage: "No site latency data in this range.",
					datasets: [{ key: "averageLatency", label: "Average latency" }],
					data: metrics.sites,
				},
				breakdown: [
					{ label: "Enabled sites", count: metrics.enabledSites },
					{ label: "Disabled sites", count: metrics.disabledSites },
				],
			});
		}

		const metrics = await repository.trafficMetrics(selection.site?.id, since, until, bucketMs);
		return jsonResponse({
			...base,
			primary: {
				title: "Traffic volume",
				subtitle: "Requests, blocked requests, and origin errors",
				type: "line",
				timeSeries: true,
				valueFormat: "number",
				emptyMessage: "No traffic in this range.",
				datasets: [
					{ key: "requests", label: "Requests" },
					{ key: "blocked", label: "Blocked" },
					{ key: "errors", label: "5xx errors" },
				],
				data: metrics.series,
			},
			secondary: {
				title: "Origin latency",
				subtitle: "Average proxy response time per interval",
				type: "line",
				timeSeries: true,
				valueFormat: "duration",
				emptyMessage: "No latency data in this range.",
				datasets: [{ key: "averageLatency", label: "Average latency" }],
				data: metrics.series,
			},
			breakdown: metrics.decisions.map((item) => ({ label: item.decision, count: item.count })),
		});
	});

	app.get("/_burrowgate/api/admin/events", async (ctx) => {
		const denied = await guard(ctx.req);
		if (denied) return denied;
		const url = new URL(ctx.req.url);
		const selection = await selectedSite(url);
		if (selection.error) return selection.error;
		const range = requestedDateRange(url);
		const search = stringParam(url, "search");
		const decision = stringParam(url, "decision");
		const method = stringParam(url, "method");
		const statusGroup = enumParam(url, "status", ["1xx", "2xx", "3xx", "4xx", "5xx"] as const);
		const countryCode = stringParam(url, "country")?.toUpperCase();
		return jsonResponse(
			await repository.pagedEvents({
				...(selection.site ? { siteId: selection.site.id } : {}),
				page: integerParam(url, "page", 1, 1, 1_000_000),
				pageSize: integerParam(url, "pageSize", config.adminPageSize, 10, 200),
				...(search ? { search } : {}),
				...(decision ? { decision } : {}),
				...(method ? { method } : {}),
				...(statusGroup ? { statusGroup } : {}),
				...(countryCode && /^[A-Z]{2}$/u.test(countryCode) ? { countryCode } : {}),
				since: range.since,
				until: range.until,
				sortBy: enumParam(url, "sortBy", ["created_at", "ip", "country_code", "method", "path", "status", "decision", "latency_ms"] as const, "created_at")!,
				sortDirection: sortDirection(url),
			}),
		);
	});

	app.get("/_burrowgate/api/admin/bandwidth", async (ctx) => {
		const denied = await guard(ctx.req);
		if (denied) return denied;
		const url = new URL(ctx.req.url);
		const selection = await selectedSite(url);
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "No site configured" }, 400);
		const range = requestedDateRange(url);
		const search = stringParam(url, "search");
		const countryCode = stringParam(url, "country")?.toUpperCase();
		const protocol = enumParam(url, "protocol", ["http", "websocket"] as const);
		await flushBandwidthMetrics();
		return jsonResponse(
			await repository.pagedBandwidthIps({
				siteId: selection.site.id,
				page: integerParam(url, "page", 1, 1, 1_000_000),
				pageSize: integerParam(url, "pageSize", config.adminPageSize, 10, 200),
				...(search ? { search } : {}),
				...(countryCode && /^[A-Z]{2}$/u.test(countryCode) ? { countryCode } : {}),
				...(protocol ? { protocol } : {}),
				since: range.since,
				until: range.until,
				sortBy: enumParam(
					url,
					"sortBy",
					[
						"ip",
						"country_code",
						"client_received_bytes",
						"client_sent_bytes",
						"upstream_sent_bytes",
						"upstream_received_bytes",
						"client_total_bytes",
						"upstream_total_bytes",
					] as const,
					"client_total_bytes",
				)!,
				sortDirection: sortDirection(url),
			}),
		);
	});

	app.get("/_burrowgate/api/admin/sessions", async (ctx) => {
		const denied = await guard(ctx.req);
		if (denied) return denied;
		const url = new URL(ctx.req.url);
		const selection = await selectedSite(url);
		if (selection.error) return selection.error;
		const range = requestedDateRange(url);
		const search = stringParam(url, "search");
		const state = enumParam(url, "state", ["active", "expired", "revoked"] as const);
		const countryCode = stringParam(url, "country")?.toUpperCase();
		return jsonResponse(
			await repository.pagedSessions({
				...(selection.site ? { siteId: selection.site.id } : {}),
				page: integerParam(url, "page", 1, 1, 1_000_000),
				pageSize: integerParam(url, "pageSize", config.adminPageSize, 10, 200),
				...(search ? { search } : {}),
				...(state ? { state } : {}),
				...(countryCode && /^[A-Z]{2}$/u.test(countryCode) ? { countryCode } : {}),
				since: range.since,
				until: range.until,
				sortBy: enumParam(url, "sortBy", ["last_seen_at", "created_at", "expires_at", "request_count", "last_ip", "country_code"] as const, "last_seen_at")!,
				sortDirection: sortDirection(url),
			}),
		);
	});

	app.get("/_burrowgate/api/admin/network-policy", async (ctx) => {
		const denied = await guard(ctx.req);
		if (denied) return denied;
		const selection = await selectedSite(new URL(ctx.req.url));
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "No site configured" }, 400);
		return jsonResponse({
			defaultIpAction: selection.site.default_ip_action ?? "inherit",
			defaultCountryAction: selection.site.default_country_action ?? "inherit",
			countryRules: await repository.countryRules(selection.site.id),
			geoip: geoIpStatus(),
		});
	});

	app.addRoute("PUT", "/_burrowgate/api/admin/network-policy", async (ctx) => {
		const denied = (await guard(ctx.req)) ?? mutationGuard(ctx.req);
		if (denied) return denied;
		const selection = await selectedSite(new URL(ctx.req.url));
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "No site configured" }, 400);
		try {
			const body = (await ctx.req.json()) as { defaultIpAction?: DefaultNetworkAction; defaultCountryAction?: DefaultNetworkAction };
			const defaultIpAction = parseDefaultNetworkAction(body.defaultIpAction, selection.site.default_ip_action ?? "inherit");
			const defaultCountryAction = parseDefaultNetworkAction(body.defaultCountryAction, selection.site.default_country_action ?? "inherit");
			await repository.updateSiteNetworkDefaults(selection.site.id, defaultIpAction, defaultCountryAction, Date.now());
			invalidateNetworkPolicy(selection.site.id);
			return jsonResponse({ defaultIpAction, defaultCountryAction });
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to update network policy" }, 400);
		}
	});

	app.post("/_burrowgate/api/admin/country-rules", async (ctx) => {
		const denied = (await guard(ctx.req)) ?? mutationGuard(ctx.req);
		if (denied) return denied;
		const selection = await selectedSite(new URL(ctx.req.url));
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "No site configured" }, 400);
		const body = (await ctx.req.json()) as { countryCode?: string; action?: IpRuleAction; reason?: string; expiresAt?: number | string | null };
		if (!body.countryCode || !["allow", "pass", "block", "challenge"].includes(body.action ?? "")) {
			return jsonResponse({ error: "Invalid country rule" }, 400);
		}
		const expiresAt = body.expiresAt === null || body.expiresAt === undefined || body.expiresAt === "" ? null : Number(body.expiresAt);
		if (expiresAt !== null && (!Number.isFinite(expiresAt) || expiresAt <= Date.now())) {
			return jsonResponse({ error: "Expiration must be in the future" }, 400);
		}
		try {
			return jsonResponse(await addCountryRule(selection.site.id, body.countryCode, body.action!, body.reason ?? "", expiresAt), 201);
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Invalid country rule" }, 400);
		}
	});

	app.delete("/_burrowgate/api/admin/country-rules/:id", async (ctx) => {
		const denied = (await guard(ctx.req)) ?? mutationGuard(ctx.req);
		if (denied) return denied;
		const selection = await selectedSite(new URL(ctx.req.url));
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "No site configured" }, 400);
		await repository.deleteCountryRuleForSite(ctx.params.id!, selection.site.id);
		invalidateNetworkPolicy(selection.site.id);
		return jsonResponse({ deleted: true });
	});

	app.get("/_burrowgate/api/admin/rules", async (ctx) => {
		const denied = await guard(ctx.req);
		if (denied) return denied;
		const url = new URL(ctx.req.url);
		const selection = await selectedSite(url);
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ items: [], page: 1, pageSize: config.adminPageSize, total: 0, totalPages: 1 });
		const search = stringParam(url, "search");
		const action = enumParam(url, "action", ["allow", "pass", "block", "challenge"] as const);
		const state = enumParam(url, "state", ["active", "expired"] as const);
		return jsonResponse(
			await repository.pagedRules({
				siteId: selection.site.id,
				page: integerParam(url, "page", 1, 1, 1_000_000),
				pageSize: integerParam(url, "pageSize", config.adminPageSize, 10, 200),
				...(search ? { search } : {}),
				...(action ? { action } : {}),
				...(state ? { state } : {}),
				sortBy: enumParam(url, "sortBy", ["created_at", "expires_at", "network_cidr", "action"] as const, "created_at")!,
				sortDirection: sortDirection(url),
			}),
		);
	});

	app.post("/_burrowgate/api/admin/rules", async (ctx) => {
		const denied = (await guard(ctx.req)) ?? mutationGuard(ctx.req);
		if (denied) return denied;
		const selection = await selectedSite(new URL(ctx.req.url));
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "No site configured" }, 400);
		const body = (await ctx.req.json()) as { networkCidr?: string; action?: IpRuleAction; reason?: string; expiresAt?: number | string | null };
		if (!body.networkCidr || !["allow", "pass", "block", "challenge"].includes(body.action ?? "")) {
			return jsonResponse({ error: "Invalid rule" }, 400);
		}
		const parsedExpiresAt = body.expiresAt === null || body.expiresAt === undefined || body.expiresAt === "" ? null : Number(body.expiresAt);
		if (parsedExpiresAt !== null && (!Number.isFinite(parsedExpiresAt) || parsedExpiresAt <= Date.now())) {
			return jsonResponse({ error: "Expiration must be in the future" }, 400);
		}
		try {
			return jsonResponse(await addIpRule(selection.site.id, body.networkCidr, body.action!, body.reason ?? "", parsedExpiresAt), 201);
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Invalid rule" }, 400);
		}
	});

	app.delete("/_burrowgate/api/admin/rules/:id", async (ctx) => {
		const denied = (await guard(ctx.req)) ?? mutationGuard(ctx.req);
		if (denied) return denied;
		const selection = await selectedSite(new URL(ctx.req.url));
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "No site configured" }, 400);
		await repository.deleteRuleForSite(ctx.params.id!, selection.site.id);
		invalidateNetworkPolicy(selection.site.id);
		return jsonResponse({ deleted: true });
	});

	app.post("/_burrowgate/api/admin/sessions/:id/revoke", async (ctx) => {
		const denied = (await guard(ctx.req)) ?? mutationGuard(ctx.req);
		if (denied) return denied;
		const selection = await selectedSite(new URL(ctx.req.url));
		if (selection.error) return selection.error;
		if (!selection.site) return jsonResponse({ error: "No site configured" }, 400);
		await repository.revokeSessionForSite(ctx.params.id!, selection.site.id, Date.now());
		return jsonResponse({ revoked: true });
	});

	app.get("/_burrowgate/api/admin/sites/:id/tls", async (ctx: any) => {
		const denied = await guard(ctx.req);
		if (denied) return denied;
		const site = await repository.siteById(ctx.params.id);
		if (!site) return jsonResponse({ error: "Site not found" }, 404);
		return jsonResponse(await tlsView(site));
	});

	app.addRoute("PUT", "/_burrowgate/api/admin/sites/:id/tls", async (ctx: any) => {
		const denied = (await guard(ctx.req)) ?? mutationGuard(ctx.req);
		if (denied) return denied;
		const site = await repository.siteById(ctx.params.id);
		if (!site) return jsonResponse({ error: "Site not found" }, 404);
		try {
			const body = (await ctx.req.json()) as Record<string, unknown>;
			const current = await repository.ensureTlsSettings(site.id);
			const requestedMode = body.mode === undefined ? current.mode : String(body.mode);
			if (requestedMode === "uploaded" || requestedMode === "letsencrypt") {
				const certificate = await repository.certificateBySite(site.id);
				const certificateUsable = certificate?.status === "active" && Number(certificate.expires_at ?? 0) > Date.now();
				const sourceMatches = certificate?.source === requestedMode;
				if (!certificateUsable || !sourceMatches) {
					return jsonResponse({ error: "The selected TLS mode requires a matching active certificate" }, 400);
				}
			}
			await updateTlsSettings(site, body);
			await requestTlsReload();
			return jsonResponse(await tlsView(site));
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to update TLS settings" }, 400);
		}
	});

	app.post("/_burrowgate/api/admin/sites/:id/certificate/upload", async (ctx: any) => {
		const denied = (await guard(ctx.req)) ?? mutationGuard(ctx.req);
		if (denied) return denied;
		const site = await repository.siteById(ctx.params.id);
		if (!site) return jsonResponse({ error: "Site not found" }, 404);
		try {
			const body = (await ctx.req.json()) as { certificatePem?: string; privateKeyPem?: string; forceHttps?: boolean };
			if (!body.certificatePem || !body.privateKeyPem) throw new Error("Certificate and private-key PEM are required");
			const certificate = await saveCertificate({ site, source: "uploaded", certificatePem: body.certificatePem, privateKeyPem: body.privateKeyPem });
			await updateTlsSettings(site, { mode: "uploaded", forceHttps: Boolean(body.forceHttps) });
			await recordCertificateEvent(site.id, certificate.id, "info", "Uploaded certificate activated", { expiresAt: certificate.expires_at });
			await requestTlsReload();
			return jsonResponse(await tlsView(site), 201);
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Unable to upload certificate" }, 400);
		}
	});

	app.post("/_burrowgate/api/admin/sites/:id/certificate/letsencrypt", async (ctx: any) => {
		const denied = (await guard(ctx.req)) ?? mutationGuard(ctx.req);
		if (denied) return denied;
		const site = await repository.siteById(ctx.params.id);
		if (!site) return jsonResponse({ error: "Site not found" }, 404);
		try {
			const body = (await ctx.req.json()) as { email?: string; directoryUrl?: string; forceHttps?: boolean; termsAccepted?: boolean };
			await issueLetsEncryptCertificate(site, {
				...(body.email ? { email: body.email } : {}),
				...(body.directoryUrl ? { directoryUrl: body.directoryUrl } : {}),
				forceHttps: Boolean(body.forceHttps),
				termsAccepted: body.termsAccepted === true,
			});
			return jsonResponse(await tlsView(site), 201);
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Certificate issuance failed" }, 400);
		}
	});

	app.post("/_burrowgate/api/admin/sites/:id/certificate/renew", async (ctx: any) => {
		const denied = (await guard(ctx.req)) ?? mutationGuard(ctx.req);
		if (denied) return denied;
		const site = await repository.siteById(ctx.params.id);
		if (!site) return jsonResponse({ error: "Site not found" }, 404);
		const certificate = await repository.certificateBySite(site.id);
		if (!certificate || certificate.source !== "letsencrypt") return jsonResponse({ error: "This site does not have a Let's Encrypt certificate" }, 400);
		const settings = await repository.ensureTlsSettings(site.id);
		try {
			await issueLetsEncryptCertificate(site, {
				email: settings.acme_email,
				directoryUrl: settings.acme_directory_url,
				forceHttps: settings.force_https === 1,
				termsAccepted: true,
				renewal: true,
			});
			return jsonResponse(await tlsView(site));
		} catch (error) {
			return jsonResponse({ error: error instanceof Error ? error.message : "Certificate renewal failed" }, 400);
		}
	});

	app.delete("/_burrowgate/api/admin/sites/:id/certificate", async (ctx: any) => {
		const denied = (await guard(ctx.req)) ?? mutationGuard(ctx.req);
		if (denied) return denied;
		const site = await repository.siteById(ctx.params.id);
		if (!site) return jsonResponse({ error: "Site not found" }, 404);
		const certificate = await repository.certificateBySite(site.id);
		if (certificate) {
			const streams = await repository.streamsUsingCertificate(certificate.id);
			if (streams.length) {
				return jsonResponse(
					{ error: `This certificate is used by stream port${streams.length === 1 ? "" : "s"} ${streams.map((stream) => stream.incoming_port).join(", ")}` },
					409,
				);
			}
		}
		await repository.deleteCertificate(site.id);
		await updateTlsSettings(site, { mode: "disabled", forceHttps: false });
		await recordCertificateEvent(site.id, certificate?.id ?? null, "warning", "Certificate removed");
		await requestTlsReload();
		return jsonResponse(await tlsView(site));
	});

	app.post("/_burrowgate/api/admin/logout", async (ctx) => {
		const denied = (await guard(ctx.req)) ?? mutationGuard(ctx.req);
		if (denied) return denied;
		for (const token of adminSessionTokens(ctx.req)) {
			await repository.deleteAdmin(await sha256Hex(token));
		}
		const response = jsonResponse({ loggedOut: true });
		const secure = secureCookieForRequest(ctx.req);
		for (const name of adminCookieNames) {
			response.headers.append(
				"set-cookie",
				serializeCookie(name, "", {
					secure: name === adminCookieName(true) ? true : secure && name === adminCookieName(secure),
					maxAge: 0,
					sameSite: "Strict",
				}),
			);
		}
		return response;
	});
}
