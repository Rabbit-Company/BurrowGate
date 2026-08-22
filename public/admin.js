import { isWebauthnSupported, registerCredential } from "/_burrowgate/static/webauthn-client.js";

const ADMIN_API = "/_burrowgate/api/admin";
const mutationHeaders = { "x-burrowgate-admin": "1" };
const DATE_TIME_FORMAT_STORAGE_KEY = "burrowgate.admin.date-time-format";
const DATE_TIME_FORMATS = new Set(["iso-24", "dmy-24", "mdy-12", "browser"]);
const DEFAULT_BAN_DURATIONS = { low: 0, medium: 600, high: 3600, critical: 86400 };
const DEFAULT_BANDWIDTH_LIMIT = { enabled: false, maxBytes: 50 * 1024 * 1024, windowSeconds: 60, banSeconds: 3600 };
const DEFAULT_CORS = {
	mode: "disabled",
	allowedOrigins: [],
	allowedMethods: ["GET", "HEAD", "POST"],
	allowedHeaders: ["content-type", "authorization"],
	exposedHeaders: [],
	allowCredentials: false,
	maxAgeSeconds: 86400,
};
const DEFAULT_HSTS = { mode: "disabled", maxAgeSeconds: 15552000, includeSubDomains: false, preload: false };

const tableState = {
	traffic: { page: 1, pageSize: 50, sortBy: "created_at", sortDirection: "desc" },
	bandwidth: { page: 1, pageSize: 50, sortBy: "client_total_bytes", sortDirection: "desc" },
	sessions: { page: 1, pageSize: 50, sortBy: "last_seen_at", sortDirection: "desc" },
	rules: { page: 1, pageSize: 50, sortBy: "created_at", sortDirection: "desc" },
	auditLog: { page: 1, pageSize: 50, sortBy: "created_at", sortDirection: "desc" },
};

const COLUMN_VISIBILITY_STORAGE_KEY = "burrowgate.admin.column-visibility";

const COLUMN_REGISTRY = {
	traffic: [
		{ key: "country", label: "Country" },
		{ key: "asn", label: "ASN" },
		{ key: "method", label: "Method" },
		{ key: "path", label: "Path" },
		{ key: "referer", label: "Referrer" },
		{ key: "origin", label: "Origin", apply: () => setTrafficOriginVisibility(trafficOrigins) },
		{ key: "status", label: "Status" },
		{ key: "decision", label: "Decision" },
		{ key: "cache", label: "Cache" },
		{ key: "protection", label: "Protection" },
		{ key: "latency", label: "Latency" },
	],
	bandwidth: [
		{ key: "country", label: "Country" },
		{ key: "toClient", label: "To client" },
		{ key: "fromClient", label: "From client" },
		{ key: "fromOrigin", label: "From origin" },
		{ key: "toOrigin", label: "To origin" },
		{ key: "clientTotal", label: "Client total" },
		{ key: "upstreamTotal", label: "Upstream total" },
	],
	sessions: [
		{ key: "country", label: "Country" },
		{ key: "asn", label: "ASN" },
		{ key: "created", label: "Created" },
		{ key: "lastSeen", label: "Last seen" },
		{ key: "expires", label: "Expires" },
		{ key: "requests", label: "Requests" },
	],
	rules: [
		{ key: "reason", label: "Reason" },
		{ key: "ruleId", label: "Rule ID" },
		{ key: "created", label: "Created" },
		{ key: "expires", label: "Expires" },
	],
};

function readColumnVisibility() {
	try {
		const stored = JSON.parse(localStorage.getItem(COLUMN_VISIBILITY_STORAGE_KEY) ?? "{}");
		return stored && typeof stored === "object" ? stored : {};
	} catch {
		return {};
	}
}

let columnVisibility = readColumnVisibility();

function saveColumnVisibility() {
	try {
		localStorage.setItem(COLUMN_VISIBILITY_STORAGE_KEY, JSON.stringify(columnVisibility));
	} catch {}
}

function isColumnVisible(tableKey, columnKey) {
	return columnVisibility[tableKey]?.[columnKey] !== false;
}

const TABLE_RELOADERS = {
	traffic: () => loadTraffic(),
	bandwidth: () => loadBandwidth(),
	sessions: () => loadSessions(),
	rules: () => loadRules(),
};

function setColumnVisible(tableKey, columnKey, visible) {
	columnVisibility[tableKey] ??= {};
	columnVisibility[tableKey][columnKey] = visible;
	saveColumnVisibility();
	applyColumnVisibility(tableKey);
	TABLE_RELOADERS[tableKey]?.();
}

function applyColumnVisibility(tableKey) {
	for (const column of COLUMN_REGISTRY[tableKey] ?? []) {
		if (column.apply) {
			column.apply();
			continue;
		}
		const visible = isColumnVisible(tableKey, column.key);
		document.querySelectorAll(`[data-column="${tableKey}:${column.key}"]`).forEach((element) => element.classList.toggle("hidden", !visible));
	}
}

function visibleColumnCount(tableKey, fixedCount, eligible = () => true) {
	const columns = COLUMN_REGISTRY[tableKey] ?? [];
	return fixedCount + columns.filter((column) => eligible(column.key) && isColumnVisible(tableKey, column.key)).length;
}

function columnsMenuMarkup(tableKey) {
	const columns = COLUMN_REGISTRY[tableKey] ?? [];
	if (columns.length === 0) return "";
	const items = columns
		.map(
			(column) =>
				`<label class="columns-menu-item"><input type="checkbox" data-column-toggle="${tableKey}:${column.key}"${isColumnVisible(tableKey, column.key) ? " checked" : ""}> ${escapeHtml(column.label)}</label>`,
		)
		.join("");
	return `<details class="columns-menu-details"><summary class="button secondary compact">Columns</summary><div class="columns-menu">${items}</div></details>`;
}

function insertColumnsMenus(anchors) {
	for (const [tableKey, containerId] of Object.entries(anchors)) {
		const markup = columnsMenuMarkup(tableKey);
		if (!markup) continue;
		byId(containerId)?.insertAdjacentHTML("afterbegin", markup);
	}
	for (const tableKey of Object.keys(anchors)) applyColumnVisibility(tableKey);
}

function bindColumnsMenus() {
	document.addEventListener("change", (event) => {
		const target = event.target;
		if (!(target instanceof HTMLInputElement) || !target.dataset.columnToggle) return;
		const [tableKey, columnKey] = target.dataset.columnToggle.split(":");
		setColumnVisible(tableKey, columnKey, target.checked);
	});
	document.addEventListener("click", (event) => {
		for (const details of document.querySelectorAll("details.columns-menu-details[open]")) {
			if (!details.contains(event.target)) details.removeAttribute("open");
		}
	});
}

const selectedRuleIds = new Set();

let activeTab = "traffic";
let latestMetrics = null;
let trafficChart = null;
let chartViewSelection = "traffic:primary";
let geoScopeSelection = "requests";
let topListScopeSelection = "requests";
let geoMapGeometry = null;
let geoMetrics = null;
let topListData = null;
let geoZoom = null;
const GEO_ZOOM_MAX_SCALE = 8;

const GEO_TAB_CONFIG = {
	traffic: { geoScope: "requests", label: "Requests", unit: "requests", topList: "referrers", refererScope: "requests" },
	bandwidth: { geoScope: "bandwidth", label: "Client bandwidth", unit: "bytes", topList: "none" },
	sessions: { geoScope: "sessions", label: "Sessions created", unit: "sessions", topList: "usernames", usernameSource: "sessions" },
	rules: { geoScope: "blocked", label: "Blocked requests", unit: "blocked requests", topList: "ips", ipScope: "blocked" },
	protection: { geoScope: "protection", label: "Matched requests", unit: "matched requests", topList: "paths", pathScope: "protection" },
	cache: { geoScope: "cache", label: "Cache hits", unit: "cache hits", topList: "referrers", refererScope: "cache" },
	access: { geoScope: "access", label: "Authentication events", unit: "auth events", topList: "usernames", usernameSource: "access" },
	routes: { geoScope: "routes", label: "Route enforcement actions", unit: "enforcement actions", topList: "ips", ipScope: "routes" },
	sites: { geoScope: "sites", label: "Requests (all sites)", unit: "requests", topList: "referrers", refererScope: "sites" },
};

const SUPPLEMENTAL_TOP_LIST_CONFIG = {
	topPathsAll: { geoScope: "paths-requests", topList: "paths", pathScope: "requests" },
	topIpsBandwidth: { geoScope: "bandwidth-ips", topList: "ipsBandwidth" },
};

function geoConfigForScope(scope) {
	const allEntries = [...Object.values(GEO_TAB_CONFIG), ...Object.values(SUPPLEMENTAL_TOP_LIST_CONFIG)];
	return allEntries.find((entry) => entry.geoScope === scope) ?? GEO_TAB_CONFIG.traffic;
}
let sites = [];
let sitePendingChanges = [];
let currentAdmin = null;
let usersData = { items: [], sites: [], streams: [] };
let accessSso = {
	enabled: false,
	enforceSso: false,
	issuerUrl: "",
	clientId: "",
	clientSecretConfigured: false,
	scopes: "openid email profile",
	buttonLabel: "Single sign-on",
};
let editingPermissionsUserId = null;
let challengeProviders = [];
let defaultEventRetentionDays = 7;
let errorResponseDefaults = { mode: "json", htmlTemplate: "", jsonFields: [], jsonFieldOptions: [], placeholders: [] };
let challengeDefaults = { htmlTemplate: "", placeholders: [] };
let websocketDefaults = {
	available: true,
	mode: "allow",
	connectTimeoutMs: 15000,
	idleTimeoutSeconds: 120,
	maxPayloadBytes: 16777216,
	preOpenQueueBytes: 1048576,
	upstreamBufferBytes: 16777216,
};
let httpCacheDefaults = {
	mode: "disabled",
	ttlSeconds: 3600,
	maxObjectBytes: 5242880,
	extensions: [
		".css",
		".js",
		".mjs",
		".png",
		".jpg",
		".jpeg",
		".gif",
		".webp",
		".avif",
		".svg",
		".ico",
		".woff",
		".woff2",
		".ttf",
		".otf",
		".eot",
		".wasm",
		".txt",
		".xml",
	],
	instanceMaxObjectBytes: 33554432,
};
let bodyCaptureDefaults = {
	mode: "disabled",
	maxRequestBytes: 4096,
	maxResponseBytes: 4096,
	expiresAt: null,
	contentTypes: [
		"text/plain",
		"text/html",
		"text/css",
		"text/javascript",
		"application/javascript",
		"application/json",
		"application/xml",
		"application/x-www-form-urlencoded",
	],
	instanceMaxBytesCeiling: 1048576,
};
let headerCaptureDefaults = { mode: "disabled", redactAuthHeaders: true, redactedHeaders: [], expiresAt: null };
let managedProtection = { defaultRuleSetId: "burrowgate-core", items: [] };
let errorResponseOptionsLoaded = false;
let selectedSiteId = "";
let editingSiteId = null;
let activeSiteEditorTab = "general";
let activeRouteEditorTab = "general";
let siteOrigins = [];
let trafficHasMultipleOrigins = false;
let trafficOrigins = [];
let editingOriginId = null;
let routePolicies = [];
let accessList = {
	settings: { enabled: false, sendUsernameToUpstream: false, sessionVerificationTokenEnabled: false, sessionVerificationTokenCreatedAt: null },
	users: [],
	availableUsers: [],
};
let countryRules = [];
let asnRules = [];
let editingRoutePolicyId = null;
let routeIpRules = [];
let routeCountryRules = [];
let routeAsnRules = [];
let currentTls = null;
let overviewRequestId = 0;
let trafficRequestId = 0;
let geoRequestId = 0;
let topListRequestId = 0;
let asnRequestId = 0;
let asnScopeSelection = "requests";
let asnMetrics = null;
let selectedRangeFrom = 0;
let selectedRangeTo = 0;
let dateRangeIsAutomatic = true;
let dateTimeFormat = "iso-24";
const loadedTabs = new Set(["traffic"]);

const byId = (id) => document.getElementById(id);
const escapeHtml = (value) =>
	String(value ?? "").replace(
		/[&<>"']/g,
		(character) =>
			({
				"&": "&amp;",
				"<": "&lt;",
				">": "&gt;",
				'"': "&quot;",
				"'": "&#39;",
			})[character],
	);

function formatNumber(value) {
	return Number(value ?? 0).toLocaleString();
}

function formatBytes(value) {
	const bytes = Math.max(0, Number(value ?? 0));
	if (!Number.isFinite(bytes) || bytes === 0) return "0 B";
	const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
	const index = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
	const scaled = bytes / 1024 ** index;
	return `${scaled >= 100 || index === 0 ? Math.round(scaled).toLocaleString() : scaled.toFixed(scaled >= 10 ? 1 : 2)} ${units[index]}`;
}

function formatBitrate(value) {
	const bits = Math.max(0, Number(value ?? 0));
	if (!Number.isFinite(bits) || bits === 0) return "0 bps";
	const units = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"];
	const index = Math.min(units.length - 1, Math.floor(Math.log(bits) / Math.log(1000)));
	const scaled = bits / 1000 ** index;
	return `${scaled >= 100 || index === 0 ? Math.round(scaled).toLocaleString() : scaled.toFixed(scaled >= 10 ? 1 : 2)} ${units[index]}`;
}

function bytesDefinitionToBitrate(definition, bucketMs) {
	if (definition.valueFormat !== "bytes" || !bucketMs) return definition;
	const bucketSeconds = bucketMs / 1000;
	return {
		...definition,
		valueFormat: "bitrate",
		data: definition.data.map((point) => {
			const converted = { ...point };
			for (const dataset of definition.datasets) converted[dataset.key] = (Number(point[dataset.key] ?? 0) * 8) / bucketSeconds;
			return converted;
		}),
	};
}

function optionalNumberInput(id) {
	const value = byId(id).value.trim();
	return value ? Number(value) : null;
}

function mibToBytes(mib) {
	return mib === null || mib === undefined ? null : Math.round(mib * 1024 * 1024);
}

function bytesToMib(bytes) {
	return bytes === null || bytes === undefined ? null : bytes / (1024 * 1024);
}

function parseHeaderAssignments(id, label) {
	return byId(id)
		.value.split(/\r?\n/u)
		.map((line) => line.trim())
		.filter(Boolean)
		.map((line, index) => {
			const separator = line.indexOf(":");
			if (separator < 1) throw new Error(`${label} line ${index + 1} must use Name: value`);
			return { name: line.slice(0, separator).trim(), value: line.slice(separator + 1).trim() };
		});
}

function parseHeaderNames(id) {
	return byId(id)
		.value.split(/[\r\n,]+/u)
		.map((name) => name.trim())
		.filter(Boolean);
}

function formatHeaderAssignments(assignments) {
	return (assignments ?? []).map((assignment) => `${assignment.name}: ${assignment.value}`).join("\n");
}

function formatHeaderNames(names) {
	return (names ?? []).join("\n");
}

function parseCacheExtensions(id, nullable) {
	const extensions = [
		...new Set(
			byId(id)
				.value.split(/[\s,]+/u)
				.map((value) => value.trim().toLowerCase())
				.filter(Boolean),
		),
	];
	if (extensions.length > 0) return extensions;
	return nullable ? null : [...httpCacheDefaults.extensions];
}

function parseBodyCaptureContentTypes(id, nullable) {
	const contentTypes = [
		...new Set(
			byId(id)
				.value.split(/[\s,]+/u)
				.map((value) => value.trim().toLowerCase())
				.filter(Boolean),
		),
	];
	if (contentTypes.length > 0) return contentTypes;
	return nullable ? null : [...bodyCaptureDefaults.contentTypes];
}

function parseHeaderCaptureRedactedHeaders(id, nullable) {
	const names = [
		...new Set(
			byId(id)
				.value.split(/[\s,]+/u)
				.map((value) => value.trim().toLowerCase())
				.filter(Boolean),
		),
	];
	if (names.length > 0) return names;
	return nullable ? null : [];
}

function parseRuleIds(id) {
	return [
		...new Set(
			byId(id)
				.value.split(/[\s,]+/u)
				.map((value) => value.trim().toUpperCase())
				.filter(Boolean),
		),
	];
}

function parseCorsOrigins(id, nullable) {
	const origins = [
		...new Set(
			byId(id)
				.value.split(/[\s,]+/u)
				.map((value) => value.trim())
				.filter(Boolean),
		),
	];
	if (origins.length > 0) return origins;
	return nullable ? null : [];
}

function parseCorsMethods(id, nullable) {
	const methods = [
		...new Set(
			byId(id)
				.value.split(/[\s,]+/u)
				.map((value) => value.trim().toUpperCase())
				.filter(Boolean),
		),
	];
	if (methods.length > 0) return methods;
	return nullable ? null : [...DEFAULT_CORS.allowedMethods];
}

function parseCorsHeaderNames(id, nullable) {
	const names = [
		...new Set(
			byId(id)
				.value.split(/[\s,]+/u)
				.map((value) => value.trim().toLowerCase())
				.filter(Boolean),
		),
	];
	if (names.length > 0) return names;
	return nullable ? null : [];
}

function readHttpPolicy(prefix, routeOverrides) {
	return {
		requestHeaders: {
			set: parseHeaderAssignments(`${prefix}RequestHeadersSet`, "Request header policy"),
			remove: parseHeaderNames(`${prefix}RequestHeadersRemove`),
		},
		responseHeaders: {
			set: parseHeaderAssignments(`${prefix}ResponseHeadersSet`, "Response header policy"),
			remove: parseHeaderNames(`${prefix}ResponseHeadersRemove`),
		},
		limits: {
			maxBodyBytes: routeOverrides ? optionalNumberInput(`${prefix}MaxBodyBytes`) : Number(byId(`${prefix}MaxBodyBytes`).value),
			maxRequestTargetBytes: routeOverrides ? optionalNumberInput(`${prefix}MaxRequestTargetBytes`) : Number(byId(`${prefix}MaxRequestTargetBytes`).value),
			maxHeaderBytes: routeOverrides ? optionalNumberInput(`${prefix}MaxHeaderBytes`) : Number(byId(`${prefix}MaxHeaderBytes`).value),
		},
		cache: routeOverrides
			? {
					mode: byId(`${prefix}CacheMode`).value,
					ttlSeconds: optionalNumberInput(`${prefix}CacheTtl`),
					maxObjectBytes: optionalNumberInput(`${prefix}CacheMaxObject`),
					extensions: parseCacheExtensions(`${prefix}CacheExtensions`, true),
				}
			: {
					mode: byId(`${prefix}CacheEnabled`).checked ? "enabled" : "disabled",
					ttlSeconds: Number(byId(`${prefix}CacheTtl`).value),
					maxObjectBytes: Number(byId(`${prefix}CacheMaxObject`).value),
					extensions: parseCacheExtensions(`${prefix}CacheExtensions`, false),
				},
		protection: routeOverrides
			? { mode: byId(`${prefix}ProtectionMode`).value, excludedRuleIds: parseRuleIds(`${prefix}ProtectionExcludedRules`) }
			: {
					mode: byId(`${prefix}ProtectionMode`).value,
					rulesetId: byId(`${prefix}ProtectionRuleset`).value,
					excludedRuleIds: parseRuleIds(`${prefix}ProtectionExcludedRules`),
				},
		banDurations: {
			low: routeOverrides ? optionalNumberInput(`${prefix}BanDurationLow`) : Number(byId(`${prefix}BanDurationLow`).value),
			medium: routeOverrides ? optionalNumberInput(`${prefix}BanDurationMedium`) : Number(byId(`${prefix}BanDurationMedium`).value),
			high: routeOverrides ? optionalNumberInput(`${prefix}BanDurationHigh`) : Number(byId(`${prefix}BanDurationHigh`).value),
			critical: routeOverrides ? optionalNumberInput(`${prefix}BanDurationCritical`) : Number(byId(`${prefix}BanDurationCritical`).value),
		},
		bandwidthLimit: routeOverrides
			? {
					enabled: byId(`${prefix}BandwidthLimitEnabled`).value === "" ? null : byId(`${prefix}BandwidthLimitEnabled`).value === "true",
					maxBytes: mibToBytes(optionalNumberInput(`${prefix}BandwidthLimitMaxMiB`)),
					windowSeconds: optionalNumberInput(`${prefix}BandwidthLimitWindowSeconds`),
					banSeconds: optionalNumberInput(`${prefix}BandwidthLimitBanSeconds`),
				}
			: {
					enabled: byId(`${prefix}BandwidthLimitEnabled`).checked,
					maxBytes: mibToBytes(Number(byId(`${prefix}BandwidthLimitMaxMiB`).value)),
					windowSeconds: Number(byId(`${prefix}BandwidthLimitWindowSeconds`).value),
					banSeconds: Number(byId(`${prefix}BandwidthLimitBanSeconds`).value),
				},
		bodyCapture: {
			mode: routeOverrides ? byId(`${prefix}BodyCaptureMode`).value : byId(`${prefix}BodyCaptureEnabled`).checked ? "enabled" : "disabled",
			maxRequestBytes: routeOverrides ? optionalNumberInput(`${prefix}BodyCaptureMaxRequest`) : Number(byId(`${prefix}BodyCaptureMaxRequest`).value),
			maxResponseBytes: routeOverrides ? optionalNumberInput(`${prefix}BodyCaptureMaxResponse`) : Number(byId(`${prefix}BodyCaptureMaxResponse`).value),
			expiresAt: parseDateTimeLocal(`${prefix}BodyCaptureExpiresAt`),
			contentTypes: parseBodyCaptureContentTypes(`${prefix}BodyCaptureContentTypes`, routeOverrides),
		},
		headerCapture: {
			mode: routeOverrides ? byId(`${prefix}HeaderCaptureMode`).value : byId(`${prefix}HeaderCaptureEnabled`).checked ? "enabled" : "disabled",
			redactAuthHeaders: routeOverrides
				? byId(`${prefix}HeaderCaptureRedactAuth`).value === ""
					? null
					: byId(`${prefix}HeaderCaptureRedactAuth`).value === "true"
				: byId(`${prefix}HeaderCaptureRedactAuth`).checked,
			redactedHeaders: parseHeaderCaptureRedactedHeaders(`${prefix}HeaderCaptureRedactedHeaders`, routeOverrides),
			expiresAt: parseDateTimeLocal(`${prefix}HeaderCaptureExpiresAt`),
		},
		cors: routeOverrides
			? {
					mode: byId(`${prefix}CorsMode`).value,
					allowedOrigins: parseCorsOrigins(`${prefix}CorsOrigins`, true),
					allowedMethods: parseCorsMethods(`${prefix}CorsMethods`, true),
					allowedHeaders: parseCorsHeaderNames(`${prefix}CorsHeaders`, true),
					exposedHeaders: parseCorsHeaderNames(`${prefix}CorsExposedHeaders`, true),
					allowCredentials: byId(`${prefix}CorsCredentials`).value === "" ? null : byId(`${prefix}CorsCredentials`).value === "true",
					maxAgeSeconds: optionalNumberInput(`${prefix}CorsMaxAge`),
				}
			: {
					mode: byId(`${prefix}CorsEnabled`).checked ? "enabled" : "disabled",
					allowedOrigins: parseCorsOrigins(`${prefix}CorsOrigins`, false),
					allowedMethods: parseCorsMethods(`${prefix}CorsMethods`, false),
					allowedHeaders: parseCorsHeaderNames(`${prefix}CorsHeaders`, false),
					exposedHeaders: parseCorsHeaderNames(`${prefix}CorsExposedHeaders`, false),
					allowCredentials: byId(`${prefix}CorsCredentials`).checked,
					maxAgeSeconds: Number(byId(`${prefix}CorsMaxAge`).value),
				},
		...(routeOverrides
			? {}
			: {
					hsts: {
						mode: byId(`${prefix}HstsEnabled`).checked ? "enabled" : "disabled",
						maxAgeSeconds: Number(byId(`${prefix}HstsMaxAge`).value),
						includeSubDomains: byId(`${prefix}HstsIncludeSubDomains`).checked,
						preload: byId(`${prefix}HstsPreload`).checked,
					},
				}),
	};
}

function writeHttpPolicy(prefix, policy, routeOverrides) {
	const http = policy ?? {};
	byId(`${prefix}RequestHeadersSet`).value = formatHeaderAssignments(http.requestHeaders?.set);
	byId(`${prefix}RequestHeadersRemove`).value = formatHeaderNames(http.requestHeaders?.remove);
	byId(`${prefix}ResponseHeadersSet`).value = formatHeaderAssignments(http.responseHeaders?.set);
	byId(`${prefix}ResponseHeadersRemove`).value = formatHeaderNames(http.responseHeaders?.remove);
	for (const [suffix, key] of [
		["MaxBodyBytes", "maxBodyBytes"],
		["MaxRequestTargetBytes", "maxRequestTargetBytes"],
		["MaxHeaderBytes", "maxHeaderBytes"],
	]) {
		const value = http.limits?.[key];
		byId(`${prefix}${suffix}`).value = routeOverrides && (value === null || value === undefined) ? "" : String(value ?? 0);
	}
	const cache = http.cache ?? (routeOverrides ? { mode: "inherit", ttlSeconds: null, maxObjectBytes: null, extensions: null } : httpCacheDefaults);
	if (routeOverrides) byId(`${prefix}CacheMode`).value = cache.mode ?? "inherit";
	else byId(`${prefix}CacheEnabled`).checked = cache.mode === "enabled";
	byId(`${prefix}CacheTtl`).value = routeOverrides && cache.ttlSeconds == null ? "" : String(cache.ttlSeconds ?? httpCacheDefaults.ttlSeconds);
	byId(`${prefix}CacheMaxObject`).value =
		routeOverrides && cache.maxObjectBytes == null ? "" : String(cache.maxObjectBytes ?? httpCacheDefaults.maxObjectBytes);
	byId(`${prefix}CacheExtensions`).value = cache.extensions?.join(", ") ?? "";
	const protection =
		http.protection ?? (routeOverrides ? { mode: "inherit", excludedRuleIds: [] } : { mode: "monitor", rulesetId: "default", excludedRuleIds: [] });
	byId(`${prefix}ProtectionMode`).value = protection.mode ?? (routeOverrides ? "inherit" : "monitor");
	if (!routeOverrides) byId(`${prefix}ProtectionRuleset`).value = protection.rulesetId ?? "default";
	byId(`${prefix}ProtectionExcludedRules`).value = protection.excludedRuleIds?.join("\n") ?? "";
	const banDurations = http.banDurations ?? {};
	for (const [suffix, key] of [
		["BanDurationLow", "low"],
		["BanDurationMedium", "medium"],
		["BanDurationHigh", "high"],
		["BanDurationCritical", "critical"],
	]) {
		const value = banDurations[key];
		byId(`${prefix}${suffix}`).value = routeOverrides && (value === null || value === undefined) ? "" : String(value ?? DEFAULT_BAN_DURATIONS[key]);
	}
	const bandwidthLimit =
		http.bandwidthLimit ?? (routeOverrides ? { enabled: null, maxBytes: null, windowSeconds: null, banSeconds: null } : DEFAULT_BANDWIDTH_LIMIT);
	if (routeOverrides) {
		byId(`${prefix}BandwidthLimitEnabled`).value =
			bandwidthLimit.enabled === null || bandwidthLimit.enabled === undefined ? "" : String(bandwidthLimit.enabled);
	} else {
		byId(`${prefix}BandwidthLimitEnabled`).checked = !!bandwidthLimit.enabled;
	}
	byId(`${prefix}BandwidthLimitMaxMiB`).value =
		routeOverrides && bandwidthLimit.maxBytes == null ? "" : String(bytesToMib(bandwidthLimit.maxBytes ?? DEFAULT_BANDWIDTH_LIMIT.maxBytes));
	byId(`${prefix}BandwidthLimitWindowSeconds`).value =
		routeOverrides && bandwidthLimit.windowSeconds == null ? "" : String(bandwidthLimit.windowSeconds ?? DEFAULT_BANDWIDTH_LIMIT.windowSeconds);
	byId(`${prefix}BandwidthLimitBanSeconds`).value =
		routeOverrides && bandwidthLimit.banSeconds == null ? "" : String(bandwidthLimit.banSeconds ?? DEFAULT_BANDWIDTH_LIMIT.banSeconds);
	const bodyCapture =
		http.bodyCapture ??
		(routeOverrides ? { mode: "inherit", maxRequestBytes: null, maxResponseBytes: null, expiresAt: null, contentTypes: null } : bodyCaptureDefaults);
	if (routeOverrides) byId(`${prefix}BodyCaptureMode`).value = bodyCapture.mode ?? "inherit";
	else byId(`${prefix}BodyCaptureEnabled`).checked = bodyCapture.mode === "enabled";
	byId(`${prefix}BodyCaptureMaxRequest`).value =
		routeOverrides && bodyCapture.maxRequestBytes == null ? "" : String(bodyCapture.maxRequestBytes ?? bodyCaptureDefaults.maxRequestBytes);
	byId(`${prefix}BodyCaptureMaxResponse`).value =
		routeOverrides && bodyCapture.maxResponseBytes == null ? "" : String(bodyCapture.maxResponseBytes ?? bodyCaptureDefaults.maxResponseBytes);
	byId(`${prefix}BodyCaptureExpiresAt`).value = bodyCapture.expiresAt == null ? "" : toDateTimeLocal(bodyCapture.expiresAt);
	byId(`${prefix}BodyCaptureContentTypes`).value =
		routeOverrides && bodyCapture.contentTypes == null ? "" : (bodyCapture.contentTypes ?? bodyCaptureDefaults.contentTypes).join(", ");
	const headerCapture =
		http.headerCapture ?? (routeOverrides ? { mode: "inherit", redactAuthHeaders: null, redactedHeaders: null, expiresAt: null } : headerCaptureDefaults);
	if (routeOverrides) byId(`${prefix}HeaderCaptureMode`).value = headerCapture.mode ?? "inherit";
	else byId(`${prefix}HeaderCaptureEnabled`).checked = headerCapture.mode === "enabled";
	if (routeOverrides) {
		byId(`${prefix}HeaderCaptureRedactAuth`).value =
			headerCapture.redactAuthHeaders === null || headerCapture.redactAuthHeaders === undefined ? "" : String(headerCapture.redactAuthHeaders);
	} else {
		byId(`${prefix}HeaderCaptureRedactAuth`).checked = headerCapture.redactAuthHeaders ?? headerCaptureDefaults.redactAuthHeaders;
	}
	byId(`${prefix}HeaderCaptureExpiresAt`).value = headerCapture.expiresAt == null ? "" : toDateTimeLocal(headerCapture.expiresAt);
	byId(`${prefix}HeaderCaptureRedactedHeaders`).value = (headerCapture.redactedHeaders ?? []).join(", ");
	const cors =
		http.cors ??
		(routeOverrides
			? { mode: "inherit", allowedOrigins: null, allowedMethods: null, allowedHeaders: null, exposedHeaders: null, allowCredentials: null, maxAgeSeconds: null }
			: DEFAULT_CORS);
	if (routeOverrides) byId(`${prefix}CorsMode`).value = cors.mode ?? "inherit";
	else byId(`${prefix}CorsEnabled`).checked = cors.mode === "enabled";
	byId(`${prefix}CorsOrigins`).value = (cors.allowedOrigins ?? (routeOverrides ? [] : DEFAULT_CORS.allowedOrigins)).join(", ");
	byId(`${prefix}CorsMethods`).value = (cors.allowedMethods ?? (routeOverrides ? [] : DEFAULT_CORS.allowedMethods)).join(", ");
	byId(`${prefix}CorsHeaders`).value = (cors.allowedHeaders ?? (routeOverrides ? [] : DEFAULT_CORS.allowedHeaders)).join(", ");
	byId(`${prefix}CorsExposedHeaders`).value = (cors.exposedHeaders ?? (routeOverrides ? [] : DEFAULT_CORS.exposedHeaders)).join(", ");
	if (routeOverrides) {
		byId(`${prefix}CorsCredentials`).value = cors.allowCredentials === null || cors.allowCredentials === undefined ? "" : String(cors.allowCredentials);
	} else {
		byId(`${prefix}CorsCredentials`).checked = cors.allowCredentials ?? DEFAULT_CORS.allowCredentials;
	}
	byId(`${prefix}CorsMaxAge`).value = routeOverrides && cors.maxAgeSeconds == null ? "" : String(cors.maxAgeSeconds ?? DEFAULT_CORS.maxAgeSeconds);
	if (!routeOverrides) {
		const hsts = http.hsts ?? DEFAULT_HSTS;
		byId(`${prefix}HstsEnabled`).checked = hsts.mode === "enabled";
		byId(`${prefix}HstsMaxAge`).value = String(hsts.maxAgeSeconds ?? DEFAULT_HSTS.maxAgeSeconds);
		byId(`${prefix}HstsIncludeSubDomains`).checked = hsts.includeSubDomains ?? DEFAULT_HSTS.includeSubDomains;
		byId(`${prefix}HstsPreload`).checked = hsts.preload ?? DEFAULT_HSTS.preload;
	}
	if (!routeOverrides) updateSiteHttpCacheControls();
	if (!routeOverrides) updateSiteHttpBodyCaptureControls();
	if (!routeOverrides) updateSiteHttpHeaderCaptureControls();
	if (!routeOverrides) updateSiteHttpCorsControls();
	if (!routeOverrides) updateSiteHttpHstsControls();
	if (!routeOverrides) updateSiteProtectionControls();
}

function twoDigits(value) {
	return String(value).padStart(2, "0");
}

function readDateTimeFormat() {
	try {
		const stored = localStorage.getItem(DATE_TIME_FORMAT_STORAGE_KEY);
		return stored && DATE_TIME_FORMATS.has(stored) ? stored : "iso-24";
	} catch {
		return "iso-24";
	}
}

function initializeDateTimeFormat() {
	dateTimeFormat = readDateTimeFormat();
	byId("dateTimeFormat").value = dateTimeFormat;
}

function saveDateTimeFormat(value) {
	dateTimeFormat = DATE_TIME_FORMATS.has(value) ? value : "iso-24";
	try {
		localStorage.setItem(DATE_TIME_FORMAT_STORAGE_KEY, dateTimeFormat);
	} catch {
		// The preference still applies for this page when browser storage is unavailable.
	}
}

function formatDate(value) {
	if (value === null || value === undefined) return "Never";
	const date = value instanceof Date ? value : new Date(Number(value));
	if (Number.isNaN(date.getTime())) return "-";
	if (dateTimeFormat === "browser") return date.toLocaleString();
	const year = date.getFullYear();
	const month = twoDigits(date.getMonth() + 1);
	const day = twoDigits(date.getDate());
	const minutes = twoDigits(date.getMinutes());
	const seconds = twoDigits(date.getSeconds());
	if (dateTimeFormat === "mdy-12") {
		const suffix = date.getHours() >= 12 ? "PM" : "AM";
		const hours = twoDigits(date.getHours() % 12 || 12);
		return `${month}/${day}/${year} ${hours}:${minutes}:${seconds} ${suffix}`;
	}
	const time = `${twoDigits(date.getHours())}:${minutes}:${seconds}`;
	return dateTimeFormat === "dmy-24" ? `${day}/${month}/${year} ${time}` : `${year}-${month}-${day} ${time}`;
}

function formatTime(value = Date.now()) {
	const date = value instanceof Date ? value : new Date(Number(value));
	if (Number.isNaN(date.getTime())) return "-";
	if (dateTimeFormat === "browser") return date.toLocaleTimeString();
	const minutes = twoDigits(date.getMinutes());
	const seconds = twoDigits(date.getSeconds());
	if (dateTimeFormat === "mdy-12") {
		return `${twoDigits(date.getHours() % 12 || 12)}:${minutes}:${seconds} ${date.getHours() >= 12 ? "PM" : "AM"}`;
	}
	return `${twoDigits(date.getHours())}:${minutes}:${seconds}`;
}

function formatDuration(milliseconds) {
	const value = Number(milliseconds ?? 0);
	if (value < 1_000) return `${Math.round(value)} ms`;
	if (value < 60_000) return `${(value / 1_000).toFixed(1)} s`;
	return `${(value / 60_000).toFixed(1)} min`;
}

function toDateTimeLocal(value) {
	const date = new Date(Number(value));
	const pad = (part) => String(part).padStart(2, "0");
	return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function parseDateTimeLocal(id) {
	const value = byId(id).value.trim();
	return value ? new Date(value).getTime() : null;
}

function rangeDurationLabel(durationMs) {
	const totalMinutes = Math.max(1, Math.round(Number(durationMs) / 60_000));
	if (totalMinutes < 60) return `${totalMinutes}m`;
	const totalHours = totalMinutes / 60;
	if (totalHours < 48) {
		const hours = Math.floor(totalHours);
		const minutes = totalMinutes % 60;
		return minutes === 0 ? `${hours}h` : `${hours}h ${minutes}m`;
	}
	const days = Math.floor(totalHours / 24);
	const hours = Math.floor(totalHours % 24);
	return hours === 0 ? `${days}d` : `${days}d ${hours}h`;
}

function rangeQuery() {
	return { from: selectedRangeFrom, to: selectedRangeTo };
}

function persistDateRange() {
	const url = new URL(location.href);
	url.searchParams.set("from", String(selectedRangeFrom));
	url.searchParams.set("to", String(selectedRangeTo));
	history.replaceState(null, "", `${url.pathname}${url.search}${url.hash}`);
}

function setDateRangeInputs(from, to) {
	selectedRangeFrom = Number(from);
	selectedRangeTo = Number(to);
	byId("dateFrom").value = toDateTimeLocal(selectedRangeFrom);
	byId("dateTo").value = toDateTimeLocal(selectedRangeTo);
	const maximum = toDateTimeLocal(Date.now() + 300_000);
	byId("dateFrom").max = maximum;
	byId("dateTo").max = maximum;
}

function initializeDateRange() {
	const url = new URL(location.href);
	const now = Date.now();
	const requestedTo = Number(url.searchParams.get("to"));
	const requestedFrom = Number(url.searchParams.get("from"));
	const explicitRange = Number.isFinite(requestedTo) && requestedTo > 0 && Number.isFinite(requestedFrom) && requestedFrom >= 0 && requestedFrom < requestedTo;
	dateRangeIsAutomatic = !explicitRange;
	const to = explicitRange ? requestedTo : now;
	const from = explicitRange ? requestedFrom : to - 24 * 3_600_000;
	setDateRangeInputs(from, to);
	if (explicitRange) persistDateRange();
	else {
		url.searchParams.delete("from");
		url.searchParams.delete("to");
		history.replaceState(null, "", `${url.pathname}${url.search}${url.hash}`);
	}
}

function applyAutomaticDateRange() {
	if (!dateRangeIsAutomatic) return;
	const to = Date.now();
	setDateRangeInputs(to - 24 * 3_600_000, to);
}

function readDateRangeInputs() {
	const from = new Date(byId("dateFrom").value).getTime();
	const to = new Date(byId("dateTo").value).getTime();
	if (!Number.isFinite(from) || !Number.isFinite(to)) throw new Error("Select both From and To date/time values.");
	if (to - from < 60_000) throw new Error("The selected range must be at least one minute.");
	if (to - from > 366 * 24 * 3_600_000) throw new Error("The selected range cannot exceed 366 days.");
	return { from, to };
}

function truncate(value, length = 72) {
	const text = String(value ?? "");
	return text.length > length ? `${text.slice(0, length - 1)}...` : text;
}

function debounce(callback, delay = 300) {
	let timer;
	return (...args) => {
		clearTimeout(timer);
		timer = setTimeout(() => callback(...args), delay);
	};
}

function showToast(message, kind = "ok") {
	const toast = byId("toast");
	toast.textContent = message;
	toast.className = `toast ${kind}`;
	clearTimeout(showToast.timer);
	showToast.timer = setTimeout(() => toast.classList.add("hidden"), 3_500);
}

async function api(path, options = {}, siteScoped = true) {
	const target = new URL(`${ADMIN_API}${path}`, location.origin);
	if (siteScoped && selectedSiteId) target.searchParams.set("siteId", selectedSiteId);
	const response = await fetch(`${target.pathname}${target.search}`, {
		...options,
		headers: { ...mutationHeaders, ...(options.headers ?? {}) },
	});
	if (response.status === 401) {
		location.href = "/_burrowgate/admin/login";
		throw new Error("Unauthorized");
	}
	const data = await response.json();
	if (!response.ok) throw new Error(data.error ?? "Request failed");
	return data;
}

function queryString(parameters) {
	const search = new URLSearchParams();
	for (const [key, value] of Object.entries(parameters)) {
		if (value !== "" && value !== undefined && value !== null) search.set(key, String(value));
	}
	return search.toString();
}

function setTableLoading(id, columns) {
	byId(id).innerHTML = `<tr><td colspan="${columns}" class="empty-cell"><span class="spinner"></span> Loading...</td></tr>`;
}

function setTableError(id, columns, error) {
	byId(id).innerHTML = `<tr><td colspan="${columns}" class="empty-cell error-text">${escapeHtml(error.message)}</td></tr>`;
}

function updatePagination(prefix, result, load) {
	byId(`${prefix}Summary`).textContent =
		result.total === 0
			? "No records"
			: `${formatNumber((result.page - 1) * result.pageSize + 1)}-${formatNumber(Math.min(result.page * result.pageSize, result.total))} of ${formatNumber(result.total)}`;
	byId(`${prefix}Page`).textContent = `Page ${formatNumber(result.page)} of ${formatNumber(result.totalPages)}`;
	const previous = byId(`${prefix}Previous`);
	const next = byId(`${prefix}Next`);
	previous.disabled = result.page <= 1;
	next.disabled = result.page >= result.totalPages;
	previous.onclick = () => {
		if (result.page <= 1) return;
		tableState[prefix === "events" ? "traffic" : prefix].page = result.page - 1;
		void load();
	};
	next.onclick = () => {
		if (result.page >= result.totalPages) return;
		tableState[prefix === "events" ? "traffic" : prefix].page = result.page + 1;
		void load();
	};
}

function updateSortIndicators(panelId, state) {
	document.querySelectorAll(`#${panelId} .sort-button`).forEach((button) => {
		const indicator = button.querySelector("span");
		button.classList.toggle("selected", button.dataset.sort === state.sortBy);
		indicator.textContent = button.dataset.sort === state.sortBy ? (state.sortDirection === "asc" ? "\u2191" : "\u2193") : "";
	});
}

async function loadOverview() {
	const requestId = ++overviewRequestId;
	const selectedDuration = selectedRangeTo - selectedRangeFrom;
	const rangeLabel = rangeDurationLabel(selectedDuration);
	byId("requestsStatLabel").textContent = `Requests (${rangeLabel})`;
	byId("uniqueIpsStatLabel").textContent = `Unique IPs (${rangeLabel})`;
	byId("blockedStatLabel").textContent = `Blocked (${rangeLabel})`;
	byId("errorsStatLabel").textContent = `5xx errors (${rangeLabel})`;
	byId("latencyStatLabel").textContent = `Average latency (${rangeLabel})`;
	byId("challengesStatLabel").textContent = `Challenges (${rangeLabel})`;
	byId("cacheHitRatioStatLabel").textContent = `Cache hit ratio (${rangeLabel})`;

	const overview = await api(`/overview?${queryString(rangeQuery())}`);
	if (requestId !== overviewRequestId) return;

	const formatted = {
		requests24h: formatNumber(overview.requests24h),
		uniqueIps24h: formatNumber(overview.uniqueIps24h),
		blocked24h: formatNumber(overview.blocked24h),
		errors24h: formatNumber(overview.errors24h),
		averageLatency24h: formatDuration(overview.averageLatency24h),
		challenges24h: formatNumber(overview.challenges24h),
		activeSessions: formatNumber(overview.activeSessions),
		cacheHitRatioStat: `${(Number(overview.cacheHitRatio ?? 0) * 100).toFixed(2)}%`,
	};
	for (const [id, value] of Object.entries(formatted)) byId(id).textContent = value;

	const resolvedRangeLabel = rangeDurationLabel(overview.rangeDurationMs ?? selectedDuration);
	byId("requestsStatLabel").textContent = `Requests (${resolvedRangeLabel})`;
	byId("uniqueIpsStatLabel").textContent = `Unique IPs (${resolvedRangeLabel})`;
	byId("blockedStatLabel").textContent = `Blocked (${resolvedRangeLabel})`;
	byId("errorsStatLabel").textContent = `5xx errors (${resolvedRangeLabel})`;
	byId("latencyStatLabel").textContent = `Average latency (${resolvedRangeLabel})`;
	byId("challengesStatLabel").textContent = `Challenges (${resolvedRangeLabel})`;
	byId("cacheHitRatioStatLabel").textContent = `Cache hit ratio (${resolvedRangeLabel})`;
	byId("errorRate24h").textContent = `${Number(overview.errorRate24h ?? 0).toFixed(2)}% error rate`;
	byId("retentionNote").textContent =
		`Only the selected page is loaded. Request events are retained for ${overview.retentionDays} day${overview.retentionDays === 1 ? "" : "s"}.`;
	if (overview.site) {
		byId("siteDescription").textContent = `${overview.site.name} | ${overview.site.publicHost} → ${overview.site.originUrl}`;
	}
	renderOriginHealthBanner(overview.originHealth);
	const defaultSize = String(overview.defaultPageSize ?? 50);
	for (const id of ["eventPageSize", "bandwidthPageSize", "sessionPageSize", "rulePageSize"]) {
		const select = byId(id);
		if ([...select.options].some((option) => option.value === defaultSize)) select.value = defaultSize;
	}
	tableState.traffic.pageSize = Number(byId("eventPageSize").value);
	tableState.bandwidth.pageSize = Number(byId("bandwidthPageSize").value);
	tableState.sessions.pageSize = Number(byId("sessionPageSize").value);
	tableState.rules.pageSize = Number(byId("rulePageSize").value);
}

function statusClass(status) {
	if (status >= 500) return "bad";
	if (status >= 400) return "warn";
	if (status >= 300) return "info";
	return "ok";
}

function decisionClass(decision) {
	if (
		[
			"blocked",
			"route-blocked",
			"managed-protection-blocked",
			"websocket-policy-denied",
			"origin-error",
			"websocket-origin-error",
			"websocket-upgrade-failed",
			"access-login-failed",
		].includes(decision)
	)
		return "bad";
	if (["challenge-required", "websocket-disabled", "rate-limited", "request-limited", "access-login-required", "access-login-rate-limited"].includes(decision))
		return "warn";
	if (["allowlisted", "websocket-allowlisted", "proxied-unprotected", "websocket-unprotected"].includes(decision)) return "info";
	return "ok";
}

function networkActionLabel(action) {
	return (
		{
			pass: "allow / route policy",
			allow: "allow / bypass",
			block: "block",
			challenge: "challenge",
		}[action] ?? String(action ?? "-")
	);
}

function countryBadge(codeInput) {
	const code = String(codeInput || "ZZ").toUpperCase();
	const name = countryDisplayName(code);
	return `<span class="country-badge" title="${escapeHtml(name)}" aria-label="${escapeHtml(name)}">${escapeHtml(code)}</span>`;
}

function asnBadge(asn, org) {
	if (!asn) {
		const title = org || "Unknown";
		return `<span class="country-badge" title="${escapeHtml(title)}" aria-label="${escapeHtml(title)}">-</span>`;
	}
	const label = `AS${asn}`;
	const title = org ? `${label} - ${org}` : label;
	return `<span class="country-badge" title="${escapeHtml(title)}" aria-label="${escapeHtml(title)}">${escapeHtml(label)}</span>`;
}

function refererLabel(host) {
	if (!host) return '<span class="muted">Direct</span>';
	if (host === "(same site)") return '<span class="muted">Same site</span>';
	return escapeHtml(host);
}

function setTrafficOriginVisibility(origins = []) {
	trafficOrigins = origins;
	trafficHasMultipleOrigins = origins.length > 1;
	byId("eventOriginFilter").classList.toggle("hidden", !trafficHasMultipleOrigins);
	byId("eventOriginColumnHeader").classList.toggle("hidden", !trafficHasMultipleOrigins || !isColumnVisible("traffic", "origin"));
	if (!trafficHasMultipleOrigins) byId("eventOrigin").value = "";
}

function trafficColumnCount() {
	return visibleColumnCount("traffic", 2, (key) => key !== "origin" || trafficHasMultipleOrigins);
}

async function loadTraffic() {
	const requestId = ++trafficRequestId;
	const state = tableState.traffic;
	setTableLoading("events", trafficColumnCount());
	updateSortIndicators("panel-traffic", state);
	try {
		const result = await api(
			`/events?${queryString({
				page: state.page,
				pageSize: state.pageSize,
				sortBy: state.sortBy,
				sortDirection: state.sortDirection,
				search: byId("eventSearch").value.trim(),
				decision: byId("eventDecision").value,
				cache: byId("eventCacheStatus").value,
				protection: byId("eventProtectionStatus").value,
				method: byId("eventMethod").value,
				status: byId("eventStatus").value,
				origin: byId("eventOrigin").value,
				country: byId("eventCountry").value,
				asn: byId("eventAsn").value,
				...rangeQuery(),
			})}`,
		);
		if (requestId !== trafficRequestId) return;
		if (result.page > result.totalPages) {
			state.page = result.totalPages;
			return await loadTraffic();
		}
		const originSelect = byId("eventOrigin");
		const selectedOriginId = originSelect.value;
		const origins = result.origins ?? [];
		originSelect.innerHTML = `<option value="">All origins</option>${origins
			.map((origin) => `<option value="${escapeHtml(origin.id)}">${escapeHtml(origin.name)}</option>`)
			.join("")}`;
		setTrafficOriginVisibility(origins);
		if (trafficHasMultipleOrigins && [...originSelect.options].some((option) => option.value === selectedOriginId)) originSelect.value = selectedOriginId;
		if (!trafficHasMultipleOrigins && selectedOriginId) {
			state.page = 1;
			return await loadTraffic();
		}
		byId("events").innerHTML =
			result.items.length === 0
				? `<tr><td colspan="${trafficColumnCount()}" class="empty-cell">No traffic matches these filters.</td></tr>`
				: result.items
						.map(
							(event) => `<tr class="clickable-row" data-event-id="${escapeHtml(event.id)}">
          <td>${formatDate(event.created_at)}</td>
          <td class="ip-cell"><code title="${escapeHtml(`${event.ip} (${countryDisplayName(event.country_code || "ZZ")})`)}">${escapeHtml(event.ip)}</code>${event.access_username ? `<span class="cell-subtext">${escapeHtml(event.access_username)}</span>` : ""}</td>
          ${isColumnVisible("traffic", "country") ? `<td>${countryBadge(event.country_code)}</td>` : ""}
          ${isColumnVisible("traffic", "asn") ? `<td>${asnBadge(event.asn, event.asn_org)}</td>` : ""}
          ${isColumnVisible("traffic", "method") ? `<td><span class="method-badge">${escapeHtml(event.method)}</span></td>` : ""}
          ${isColumnVisible("traffic", "path") ? `<td class="path-cell" title="${escapeHtml(event.path)}">${escapeHtml(truncate(event.path))}</td>` : ""}
          ${isColumnVisible("traffic", "referer") ? `<td class="referrer-cell" title="${escapeHtml(event.referer || "No referrer")}">${refererLabel(event.referer_host)}</td>` : ""}
          ${trafficHasMultipleOrigins && isColumnVisible("traffic", "origin") ? `<td title="${escapeHtml(event.origin_id ?? "No origin selected")}">${event.origin_name ? escapeHtml(event.origin_name) : event.origin_id ? `<span class="muted">${escapeHtml(truncate(event.origin_id, 18))}</span>` : "-"}</td>` : ""}
          ${isColumnVisible("traffic", "status") ? `<td><span class="badge ${statusClass(Number(event.status))}">${Number(event.status)}</span></td>` : ""}
          ${isColumnVisible("traffic", "decision") ? `<td><span class="badge ${decisionClass(event.decision)}">${escapeHtml(event.decision)}</span></td>` : ""}
			${isColumnVisible("traffic", "cache") ? `<td>${event.cache_status ? `<span class="badge ${event.cache_status === "hit" ? "ok" : event.cache_status === "miss" ? "warn" : "info"}">${escapeHtml(event.cache_status)}</span>` : '<span class="muted">-</span>'}</td>` : ""}
			${isColumnVisible("traffic", "protection") ? `<td title="${escapeHtml(event.protection_rule_id ?? "No managed rule matched")}">${event.protection_status ? `<span class="badge ${event.protection_status === "blocked" ? "bad" : event.protection_status === "monitored" ? "warn" : "ok"}">${event.protection_status === "monitored" ? "would block" : escapeHtml(event.protection_status)}</span>` : '<span class="muted">-</span>'}</td>` : ""}
          ${isColumnVisible("traffic", "latency") ? `<td>${formatDuration(event.latency_ms)}</td>` : ""}
        </tr>`,
						)
						.join("");
		updatePagination("events", result, loadTraffic);
	} catch (error) {
		if (requestId !== trafficRequestId) return;
		setTableError("events", trafficColumnCount(), error);
	}
}

function bodySection(label, body, truncated, contentType) {
	if (body === null || body === undefined) {
		return `<div class="event-detail-body"><h3>${label}</h3><p class="muted">No ${label.toLowerCase()} was captured for this request. Body capture may be disabled, expired, or the content type isn't text-based.</p></div>`;
	}
	return `<div class="event-detail-body"><h3>${label}${truncated ? ' <span class="badge warn">truncated</span>' : ""}</h3>${
		contentType ? `<p class="muted">${escapeHtml(contentType)}</p>` : ""
	}<pre class="event-detail-pre">${escapeHtml(body)}</pre></div>`;
}

function parseCapturedHeadersJson(json) {
	if (!json) return [];
	try {
		const parsed = JSON.parse(json);
		return Array.isArray(parsed) ? parsed.filter((entry) => Array.isArray(entry) && entry.length === 2) : [];
	} catch {
		return [];
	}
}

function headersSection(label, headersJson, truncated) {
	const entries = parseCapturedHeadersJson(headersJson);
	if (entries.length === 0) {
		return `<div class="event-detail-body"><h3>${label}</h3><p class="muted">No ${label.toLowerCase()} were captured for this request. Header capture may be disabled or expired.</p></div>`;
	}
	const rows = entries
		.map(
			([name, value]) =>
				`<tr><td>${escapeHtml(name)}</td><td>${value === "[redacted]" ? '<span class="badge warn">redacted</span>' : escapeHtml(value)}</td></tr>`,
		)
		.join("");
	return `<div class="event-detail-body"><h3>${label}${truncated ? ' <span class="badge warn">truncated</span>' : ""}</h3><table class="event-detail-headers"><tbody>${rows}</tbody></table></div>`;
}

function resendPanel(event) {
	const method = event.method.toUpperCase();
	const requestHeaders = parseCapturedHeadersJson(event.request_headers);
	const headerFields = requestHeaders
		.map(([name, value]) => {
			const redacted = value === "[redacted]";
			return `<label class="resend-header-row"><span>${escapeHtml(name)}</span><input class="input" data-header-name="${escapeHtml(name)}" value="${
				redacted ? "" : escapeHtml(value)
			}" placeholder="${redacted ? "Redacted - enter a value to send" : ""}"></label>`;
		})
		.join("");
	return `<div class="event-detail-body">
    <h3>Resend</h3>
    <p class="muted">Replays this request back through BurrowGate with the headers and body below. Redacted headers are left blank and must be filled in.</p>
    ${requestHeaders.length ? `<div class="site-form-grid">${headerFields}</div>` : '<p class="muted">No request headers were captured to resend.</p>'}
    <div class="small-top-margin"><label><span>Additional / override headers</span><textarea id="resendExtraHeaders" class="input code-input compact-code-input" rows="3" spellcheck="false" placeholder="Content-Type: application/json"></textarea><small class="muted">One <code>Name: value</code> rule per line. Not needed if the header is already listed above.</small></label></div>
    <div class="small-top-margin"><label><span>Body</span><textarea id="resendBody" class="input code-input compact-code-input" rows="4">${escapeHtml(event.request_body ?? "")}</textarea></label></div>
    <button class="small-top-margin button${["GET", "HEAD"].includes(method) ? "" : " danger"}" type="button" data-resend-event="${escapeHtml(event.id)}" data-method="${escapeHtml(method)}">Resend ${escapeHtml(method)} request</button>
    <div id="resendResult"></div>
  </div>`;
}

const HOP_NOT_FOLLOWED_LABELS = {
	"redirect-limit": "redirect limit reached, not followed",
	"off-site": "points to a different host, not followed",
	"unparseable-location": "invalid location, not followed",
	"no-location": "redirect had no location header",
};

function hopChainSection(hops) {
	if (!hops || hops.length <= 1) return "";
	const rows = hops
		.map((hop, index) => {
			const note = !hop.followed && hop.notFollowedReason ? HOP_NOT_FOLLOWED_LABELS[hop.notFollowedReason] : "";
			return `<tr><td>Hop ${index + 1}${index === hops.length - 1 ? " (final)" : ""}<br><span class="muted">${escapeHtml(hop.method)} ${escapeHtml(hop.path)}</span></td><td><span class="badge ${statusClass(hop.status)}">${hop.status}</span>${
				hop.location ? `<br><span class="muted">${escapeHtml(hop.location)}</span>` : ""
			}${note ? `<br><span class="badge warn">${escapeHtml(note)}</span>` : ""}</td></tr>`;
		})
		.join("");
	return `<div class="event-detail-body"><h3>Redirect chain</h3><table class="event-detail-headers"><tbody>${rows}</tbody></table></div>`;
}

function renderResendResult(result) {
	const headerRows = result.headers.map(([name, value]) => `<tr><td>${escapeHtml(name)}</td><td>${escapeHtml(value)}</td></tr>`).join("");
	return `${hopChainSection(result.hops)}
  <div class="event-detail-body">
    <h3>Response <span class="badge ${statusClass(result.status)}">${result.status}</span></h3>
    <table class="event-detail-headers"><tbody>${headerRows}</tbody></table>
    <pre class="event-detail-pre">${escapeHtml(result.body)}${result.bodyTruncated ? "\n…truncated" : ""}</pre>
  </div>`;
}

function severityBadgeClass(severity) {
	return severity === "critical" || severity === "high" ? "bad" : severity === "medium" ? "warn" : "info";
}

function protectionMatchesSection(matches) {
	if (!matches || matches.length === 0) return "";
	const rows = matches
		.map(
			(match) =>
				`<tr><td>${escapeHtml(match.ruleId ?? "-")}<br><span class="muted">${escapeHtml(match.title ?? "")}</span></td><td>${escapeHtml(match.category ?? "-")}</td><td><span class="badge ${severityBadgeClass(match.severity)}">${escapeHtml(match.severity ?? "-")}</span></td><td>${escapeHtml(match.location ?? "-")}</td></tr>`,
		)
		.join("");
	return `<div class="event-detail-body"><h3>Managed protection matches</h3><table class="event-detail-headers"><tbody>${rows}</tbody></table></div>`;
}

function renderEventDetail(event) {
	const rows = [
		["Request ID", escapeHtml(event.id)],
		["Time", escapeHtml(formatDate(event.created_at))],
		["Method", escapeHtml(event.method)],
		["Path", escapeHtml(event.path)],
		["Status", String(event.status)],
		["Decision", escapeHtml(event.decision)],
		["IP", escapeHtml(`${event.ip} (${countryDisplayName(event.country_code || "ZZ")})`)],
		["ASN", asnBadge(event.asn, event.asn_org)],
		["Session", event.session_id ? escapeHtml(event.session_id) : "-"],
		["User", event.access_username ? escapeHtml(event.access_username) : "-"],
		["Origin", event.origin_name ? escapeHtml(event.origin_name) : event.origin_id ? escapeHtml(event.origin_id) : "-"],
		["Cache", event.cache_status ? escapeHtml(event.cache_status) : "-"],
		["Protection", event.protection_status ? escapeHtml(event.protection_status) : "-"],
		["Protection rule", event.protection_rule_id ? escapeHtml(event.protection_rule_id) : "-"],
		["Protection category", event.protection_category ? escapeHtml(event.protection_category) : "-"],
		["Protection severity", event.protection_severity ? escapeHtml(event.protection_severity) : "-"],
		["Protection ruleset", event.protection_ruleset_id ? escapeHtml(`${event.protection_ruleset_id} ${event.protection_ruleset_version ?? ""}`.trim()) : "-"],
		["Referrer", event.referer ? escapeHtml(event.referer) : "-"],
		["Latency", escapeHtml(formatDuration(event.latency_ms))],
	];
	return `
    <div class="event-detail-grid">${rows.map(([label, value]) => `<div><span class="muted">${label}</span><div>${value}</div></div>`).join("")}</div>
    ${protectionMatchesSection(event.protection_matches)}
    ${bodySection("Request body", event.request_body, event.request_body_truncated === 1, event.request_content_type)}
    ${bodySection("Response body", event.response_body, event.response_body_truncated === 1, event.response_content_type)}
    ${headersSection("Request headers", event.request_headers, event.request_headers_truncated === 1)}
    ${headersSection("Response headers", event.response_headers, event.response_headers_truncated === 1)}
    ${resendPanel(event)}
  `;
}

async function openEventDetail(id) {
	openModal("event");
	const container = byId("eventDetailBody");
	container.innerHTML = '<p class="muted"><span class="spinner"></span> Loading...</p>';
	try {
		const event = await api(`/events/${encodeURIComponent(id)}`, {}, false);
		container.innerHTML = renderEventDetail(event);
	} catch (error) {
		container.innerHTML = `<p class="error-text">${escapeHtml(error.message)}</p>`;
	}
}

async function handleResendClick(button) {
	const method = button.dataset.method;
	if (!["GET", "HEAD"].includes(method)) {
		if (!confirm(`Resend this ${method} request? If the endpoint has side effects (creating or modifying data), this may repeat them.`)) return;
	}
	const panel = button.closest(".event-detail-body");
	const headers = {};
	for (const input of panel.querySelectorAll("[data-header-name]")) {
		if (input.value.trim() !== "") headers[input.dataset.headerName] = input.value;
	}
	const bodyField = panel.querySelector("#resendBody");
	const resultContainer = panel.querySelector("#resendResult");
	try {
		for (const { name, value } of parseHeaderAssignments("resendExtraHeaders", "Additional headers")) headers[name] = value;
	} catch (error) {
		resultContainer.innerHTML = `<p class="error-text">${escapeHtml(error.message)}</p>`;
		return;
	}
	button.disabled = true;
	resultContainer.innerHTML = '<p class="muted"><span class="spinner"></span> Sending...</p>';
	try {
		const result = await api(
			`/events/${encodeURIComponent(button.dataset.resendEvent)}/resend`,
			{ method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ headers, body: bodyField ? bodyField.value : undefined }) },
			false,
		);
		resultContainer.innerHTML = renderResendResult(result);
	} catch (error) {
		resultContainer.innerHTML = `<p class="error-text">${escapeHtml(error.message)}</p>`;
	} finally {
		button.disabled = false;
	}
}

function bandwidthColumnCount() {
	return visibleColumnCount("bandwidth", 2);
}

async function loadBandwidth() {
	const state = tableState.bandwidth;
	setTableLoading("bandwidthIps", bandwidthColumnCount());
	updateSortIndicators("panel-bandwidth", state);
	try {
		const result = await api(
			`/bandwidth?${queryString({
				page: state.page,
				pageSize: state.pageSize,
				sortBy: state.sortBy,
				sortDirection: state.sortDirection,
				search: byId("bandwidthSearch").value.trim(),
				protocol: byId("bandwidthProtocol").value,
				country: byId("bandwidthCountry").value,
				...rangeQuery(),
			})}`,
		);
		if (result.page > result.totalPages) {
			state.page = result.totalPages;
			return await loadBandwidth();
		}
		byId("bandwidthIps").innerHTML =
			result.items.length === 0
				? `<tr><td colspan="${bandwidthColumnCount()}" class="empty-cell">No client bandwidth matches these filters.</td></tr>`
				: result.items
						.map(
							(item) => `<tr>
          <td class="ip-cell"><code title="${escapeHtml(`${item.ip} (${countryDisplayName(item.country_code || "ZZ")})`)}">${escapeHtml(item.ip)}</code></td>
          ${isColumnVisible("bandwidth", "country") ? `<td>${countryBadge(item.country_code)}</td>` : ""}
          ${isColumnVisible("bandwidth", "toClient") ? `<td>${formatBytes(item.client_sent_bytes)}</td>` : ""}
          ${isColumnVisible("bandwidth", "fromClient") ? `<td>${formatBytes(item.client_received_bytes)}</td>` : ""}
          ${isColumnVisible("bandwidth", "fromOrigin") ? `<td>${formatBytes(item.upstream_received_bytes)}</td>` : ""}
          ${isColumnVisible("bandwidth", "toOrigin") ? `<td>${formatBytes(item.upstream_sent_bytes)}</td>` : ""}
          ${isColumnVisible("bandwidth", "clientTotal") ? `<td><strong>${formatBytes(item.client_total_bytes)}</strong></td>` : ""}
          ${isColumnVisible("bandwidth", "upstreamTotal") ? `<td>${formatBytes(item.upstream_total_bytes)}</td>` : ""}
          <td><button class="button danger compact" type="button" data-bandwidth-block="${escapeHtml(item.ip)}">Block IP</button></td>
        </tr>`,
						)
						.join("");
		updatePagination("bandwidth", result, loadBandwidth);
	} catch (error) {
		setTableError("bandwidthIps", bandwidthColumnCount(), error);
	}
}

function sessionState(session) {
	if (session.revoked_at !== null) return "revoked";
	if (Number(session.expires_at) <= Date.now()) return "expired";
	return "active";
}

function sessionsColumnCount() {
	return visibleColumnCount("sessions", 4);
}

async function loadSessions() {
	const state = tableState.sessions;
	setTableLoading("sessions", sessionsColumnCount());
	updateSortIndicators("panel-sessions", state);
	try {
		const result = await api(
			`/sessions?${queryString({
				page: state.page,
				pageSize: state.pageSize,
				sortBy: state.sortBy,
				sortDirection: state.sortDirection,
				search: byId("sessionSearch").value.trim(),
				state: byId("sessionState").value,
				country: byId("sessionCountry").value,
				asn: byId("sessionAsn").value,
				...rangeQuery(),
			})}`,
		);
		if (result.page > result.totalPages) {
			state.page = result.totalPages;
			return await loadSessions();
		}
		byId("sessions").innerHTML =
			result.items.length === 0
				? `<tr><td colspan="${sessionsColumnCount()}" class="empty-cell">No sessions match these filters.</td></tr>`
				: result.items
						.map((session) => {
							const currentState = sessionState(session);
							return `<tr class="session-row ${currentState}">
          <td><span class="badge ${currentState === "active" ? "ok" : currentState === "expired" ? "warn" : "bad"}">${currentState}</span></td>
          <td><code title="${escapeHtml(session.id)}">${escapeHtml(truncate(session.id, 24))}</code>${session.access_username ? `<span class="cell-subtext">${escapeHtml(session.access_username)}</span>` : ""}</td>
          <td class="ip-cell"><code title="${escapeHtml(`${session.last_ip} (${countryDisplayName(session.country_code || "ZZ")})`)}">${escapeHtml(session.last_ip)}</code></td>
          ${isColumnVisible("sessions", "country") ? `<td>${countryBadge(session.country_code)}</td>` : ""}
          ${isColumnVisible("sessions", "asn") ? `<td>${asnBadge(session.asn, session.asn_org)}</td>` : ""}
          ${isColumnVisible("sessions", "created") ? `<td>${formatDate(session.created_at)}</td>` : ""}
          ${isColumnVisible("sessions", "lastSeen") ? `<td>${formatDate(session.last_seen_at)}</td>` : ""}
          ${isColumnVisible("sessions", "expires") ? `<td>${formatDate(session.expires_at)}</td>` : ""}
          ${isColumnVisible("sessions", "requests") ? `<td>${formatNumber(session.request_count)}</td>` : ""}
          <td>${currentState === "active" ? `<button class="button danger compact" data-session-id="${escapeHtml(session.id)}">Revoke</button>` : "-"}</td>
        </tr>`;
						})
						.join("");
		updatePagination("sessions", result, loadSessions);
	} catch (error) {
		setTableError("sessions", sessionsColumnCount(), error);
	}
}

function ruleState(rule) {
	return rule.expires_at !== null && Number(rule.expires_at) <= Date.now() ? "expired" : "active";
}

function updateBulkUnbanRulesButton() {
	const button = byId("bulkUnbanRules");
	button.disabled = selectedRuleIds.size === 0;
	button.textContent = `Unban selected (${selectedRuleIds.size})`;
	const rowCheckboxes = [...document.querySelectorAll("#rules .rule-select")];
	const selectAll = byId("rulesSelectAll");
	const selectedOnPage = rowCheckboxes.filter((checkbox) => selectedRuleIds.has(checkbox.dataset.ruleId));
	selectAll.checked = rowCheckboxes.length > 0 && selectedOnPage.length === rowCheckboxes.length;
	selectAll.indeterminate = selectedOnPage.length > 0 && selectedOnPage.length < rowCheckboxes.length;
}

function rulesColumnCount() {
	return visibleColumnCount("rules", 5);
}

async function loadRules() {
	const state = tableState.rules;
	selectedRuleIds.clear();
	updateBulkUnbanRulesButton();
	if (!selectedSiteId) {
		byId("rules").innerHTML = `<tr><td colspan="${rulesColumnCount()}" class="empty-cell">Create or select a site before adding IP rules.</td></tr>`;
		byId("countryRules").innerHTML = '<tr><td colspan="7" class="empty-cell">Create or select a site before adding country rules.</td></tr>';
		byId("asnRules").innerHTML = '<tr><td colspan="7" class="empty-cell">Create or select a site before adding ASN rules.</td></tr>';
		byId("saveNetworkDefaults").disabled = true;
		return;
	}
	byId("saveNetworkDefaults").disabled = false;
	setTableLoading("rules", rulesColumnCount());
	setTableLoading("countryRules", 7);
	setTableLoading("asnRules", 7);
	updateSortIndicators("panel-rules", state);
	try {
		const [result, networkPolicy] = await Promise.all([
			api(
				`/rules?${queryString({
					page: state.page,
					pageSize: state.pageSize,
					sortBy: state.sortBy,
					sortDirection: state.sortDirection,
					search: byId("ruleSearch").value.trim(),
					action: byId("ruleAction").value,
					state: byId("ruleState").value,
				})}`,
			),
			api("/network-policy"),
		]);
		applyNetworkPolicy(networkPolicy);
		if (result.page > result.totalPages) {
			state.page = result.totalPages;
			return await loadRules();
		}
		byId("rules").innerHTML =
			result.items.length === 0
				? `<tr><td colspan="${rulesColumnCount()}" class="empty-cell">No IP rules match these filters.</td></tr>`
				: result.items
						.map((rule) => {
							const currentState = ruleState(rule);
							return `<tr class="rule-row ${currentState}">
          <td><input type="checkbox" class="rule-select" data-rule-id="${escapeHtml(rule.id)}"></td>
          <td><span class="badge ${currentState === "active" ? "ok" : "warn"}">${currentState}</span></td>
          <td class="ip-cell"><code>${escapeHtml(rule.network_cidr)}</code></td>
          <td><span class="badge action-${escapeHtml(rule.action)}">${escapeHtml(networkActionLabel(rule.action))}</span></td>
          ${isColumnVisible("rules", "reason") ? `<td title="${escapeHtml(rule.reason)}">${escapeHtml(truncate(rule.reason || "-", 56))}</td>` : ""}
          ${isColumnVisible("rules", "ruleId") ? `<td>${rule.rule_id ? `<code>${escapeHtml(rule.rule_id)}</code>` : '<span class="badge">Manual</span>'}</td>` : ""}
          ${isColumnVisible("rules", "created") ? `<td>${formatDate(rule.created_at)}</td>` : ""}
          ${isColumnVisible("rules", "expires") ? `<td>${rule.expires_at === null ? "Never" : formatDate(rule.expires_at)}</td>` : ""}
          <td><button class="button danger compact" data-rule-id="${escapeHtml(rule.id)}">Delete</button></td>
        </tr>`;
						})
						.join("");
		updatePagination("rules", result, loadRules);
	} catch (error) {
		setTableError("rules", rulesColumnCount(), error);
		setTableError("countryRules", 7, error);
		setTableError("asnRules", 7, error);
	}
}

function applyNetworkPolicy(policy) {
	byId("defaultIpAction").value = policy.defaultIpAction ?? "inherit";
	byId("defaultCountryAction").value = policy.defaultCountryAction ?? "inherit";
	countryRules = policy.countryRules ?? [];
	asnRules = policy.asnRules ?? [];
	const warning = byId("geoPolicyWarning");
	if (!policy.geoip?.enabled) {
		warning.textContent = "GeoIP is disabled. Country rules are stored but not enforced until GeoIP is enabled.";
		warning.classList.remove("hidden");
	} else if (!policy.geoip.available) {
		warning.textContent = policy.geoip.error || "The GeoIP database is unavailable. Country policy fails open until it becomes available.";
		warning.classList.remove("hidden");
	} else {
		warning.classList.add("hidden");
	}
	const asnWarning = byId("asnPolicyWarning");
	if (asnWarning) {
		if (!policy.geoip?.asn?.enabled) {
			asnWarning.textContent = "The ASN database is disabled. ASN rules are stored but not enforced until it is enabled.";
			asnWarning.classList.remove("hidden");
		} else if (!policy.geoip.asn.available) {
			asnWarning.textContent = policy.geoip.asn.error || "The ASN database is unavailable. ASN policy fails open until it becomes available.";
			asnWarning.classList.remove("hidden");
		} else {
			asnWarning.classList.add("hidden");
		}
	}
	renderCountryRules();
	renderAsnRules();
}

function renderCountryRules() {
	const body = byId("countryRules");
	if (!selectedSiteId) {
		body.innerHTML = '<tr><td colspan="7" class="empty-cell">Select a site before adding country rules.</td></tr>';
		return;
	}
	if (countryRules.length === 0) {
		body.innerHTML = '<tr><td colspan="7" class="empty-cell">No country rules are configured.</td></tr>';
		return;
	}
	body.innerHTML = countryRules
		.map((rule) => {
			const currentState = ruleState(rule);
			const code = String(rule.country_code || "ZZ").toUpperCase();
			return `<tr class="rule-row ${currentState}">
      <td><span class="badge ${currentState === "active" ? "ok" : "warn"}">${currentState}</span></td>
      <td>${countryBadge(code)} <span>${escapeHtml(countryDisplayName(code))}</span></td>
      <td><span class="badge action-${escapeHtml(rule.action)}">${escapeHtml(networkActionLabel(rule.action))}</span></td>
      <td title="${escapeHtml(rule.reason)}">${escapeHtml(truncate(rule.reason || "-", 56))}</td>
      <td>${formatDate(rule.created_at)}</td>
      <td>${rule.expires_at === null ? "Never" : formatDate(rule.expires_at)}</td>
      <td><button class="button danger compact" data-country-rule-id="${escapeHtml(rule.id)}">Delete</button></td>
    </tr>`;
		})
		.join("");
}

function renderAsnRules() {
	const body = byId("asnRules");
	if (!selectedSiteId) {
		body.innerHTML = '<tr><td colspan="7" class="empty-cell">Select a site before adding ASN rules.</td></tr>';
		return;
	}
	if (asnRules.length === 0) {
		body.innerHTML = '<tr><td colspan="7" class="empty-cell">No ASN rules are configured.</td></tr>';
		return;
	}
	body.innerHTML = asnRules
		.map((rule) => {
			const currentState = ruleState(rule);
			return `<tr class="rule-row ${currentState}">
      <td><span class="badge ${currentState === "active" ? "ok" : "warn"}">${currentState}</span></td>
      <td><code>AS${rule.asn}</code></td>
      <td><span class="badge action-${escapeHtml(rule.action)}">${escapeHtml(networkActionLabel(rule.action))}</span></td>
      <td title="${escapeHtml(rule.reason)}">${escapeHtml(truncate(rule.reason || "-", 56))}</td>
      <td>${formatDate(rule.created_at)}</td>
      <td>${rule.expires_at === null ? "Never" : formatDate(rule.expires_at)}</td>
      <td><button class="button danger compact" data-asn-rule-id="${escapeHtml(rule.id)}">Delete</button></td>
    </tr>`;
		})
		.join("");
}

async function saveNetworkDefaults() {
	const result = await api("/network-policy", {
		method: "PUT",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({
			defaultIpAction: byId("defaultIpAction").value,
			defaultCountryAction: byId("defaultCountryAction").value,
		}),
	});
	const site = selectedSite();
	if (site) {
		site.defaultIpAction = result.defaultIpAction;
		site.defaultCountryAction = result.defaultCountryAction;
		renderSites();
	}
	showToast("Default network actions saved.");
	await Promise.all([loadOverview(), loadMetrics()]);
}

function defaultChallengePolicy() {
	return [{ provider: "pow-sha256", config: { difficulty: 18 } }];
}

function selectedSite() {
	return sites.find((site) => site.id === selectedSiteId) ?? null;
}

function persistSiteSelection() {
	const url = new URL(location.href);
	if (selectedSiteId) url.searchParams.set("site", selectedSiteId);
	else url.searchParams.delete("site");
	history.replaceState(null, "", `${url.pathname}${url.search}${url.hash}`);
}

function renderSiteSelector() {
	const selector = byId("siteSelector");
	selector.disabled = sites.length === 0;
	selector.innerHTML =
		sites.length === 0
			? '<option value="">No sites configured</option>'
			: `<option value="">All websites</option>${sites
					.map(
						(site) =>
							`<option value="${escapeHtml(site.id)}"${site.id === selectedSiteId ? " selected" : ""}>${escapeHtml(site.name)}${site.enabled ? "" : " (disabled)"} | ${escapeHtml(site.publicHost)}</option>`,
					)
					.join("")}`;
	if (sites.length > 0) selector.value = selectedSiteId;
}

function renderErrorResponseOptions() {
	byId("errorPlaceholderList").innerHTML = (errorResponseDefaults.placeholders ?? [])
		.map(
			(placeholder) =>
				`<div class="placeholder-item"><code>&#123;&#123;${escapeHtml(placeholder.name)}&#125;&#125;</code><small>${escapeHtml(placeholder.description)}</small></div>`,
		)
		.join("");
	byId("errorJsonFieldList").innerHTML = (errorResponseDefaults.jsonFieldOptions ?? [])
		.map(
			(field) =>
				`<label class="json-field-option"><input type="checkbox" name="errorJsonField" value="${escapeHtml(field.name)}"><span><strong>${escapeHtml(field.label)}</strong><small>${escapeHtml(field.description)}</small></span></label>`,
		)
		.join("");
}

function renderChallengePlaceholders() {
	byId("challengePlaceholderList").innerHTML = (challengeDefaults.placeholders ?? [])
		.map(
			(placeholder) =>
				`<div class="placeholder-item"><code>&#123;&#123;${escapeHtml(placeholder.name)}&#125;&#125;</code><small>${escapeHtml(placeholder.description)}</small></div>`,
		)
		.join("");
}

function selectedErrorJsonFields() {
	return [...document.querySelectorAll('input[name="errorJsonField"]:checked')].map((input) => input.value);
}

function setErrorJsonFields(fields) {
	const selected = new Set(fields ?? []);
	document.querySelectorAll('input[name="errorJsonField"]').forEach((input) => {
		input.checked = selected.has(input.value);
	});
}

function updateErrorResponseControls() {
	const htmlMode = byId("siteErrorResponseMode").value === "html";
	byId("siteErrorHtmlSettings").classList.toggle("hidden", !htmlMode);
	byId("siteErrorJsonSettings").classList.toggle("hidden", htmlMode);
}

function healthBadgeClass(state) {
	return state === "healthy" ? "ok" : state === "unhealthy" ? "bad" : state === "degraded" ? "warn" : "info";
}

function updateHealthControls() {
	byId("siteHealthSettings").classList.toggle("hidden", !byId("siteHealthEnabled").checked);
	updateHealthDetectionNotice();
}

const HEALTH_DETECTION_WARNING_SECONDS = 15;

function updateHealthDetectionNotice() {
	const interval = Number(byId("siteHealthInterval").value);
	const threshold = Number(byId("siteHealthFailureThreshold").value);
	const notice = byId("siteHealthDetectionNotice");
	const detectionSeconds = interval * threshold;
	if (interval > 0 && threshold > 0 && detectionSeconds < HEALTH_DETECTION_WARNING_SECONDS) {
		notice.textContent = `With this interval and failure threshold, an incident opens after only ${detectionSeconds}s of continuous failures - a brief network blip could trigger a false alert. Consider a higher failure threshold.`;
		notice.classList.remove("hidden");
	} else {
		notice.classList.add("hidden");
	}
}

function renderOriginHealthBanner(status) {
	const banner = byId("originHealthBanner");
	if (!status || status.state === "disabled") {
		banner.classList.add("hidden");
		return;
	}
	const badge = byId("originHealthBannerBadge");
	badge.className = `badge ${healthBadgeClass(status.state)}`;
	badge.textContent = status.state;
	byId("originHealthBannerTitle").textContent =
		status.state === "unhealthy" ? "Origin unavailable" : status.state === "degraded" ? "Origin health degraded" : "Origin health";
	byId("originHealthBannerMessage").textContent = status.lastCheckedAt
		? `Last checked ${formatDate(status.lastCheckedAt)}${status.lastStatus ? `, HTTP ${status.lastStatus}` : ""}${status.lastError ? `: ${status.lastError}` : ""}`
		: "Waiting for the first health check.";
	banner.classList.toggle("hidden", status.state === "healthy");
}

function applySiteHealthStatus(status, events = [], backendEvents = []) {
	const state = status?.state ?? "disabled";
	const badge = byId("siteHealthStatusBadge");
	badge.className = `badge ${healthBadgeClass(state)}`;
	badge.textContent = state;
	byId("siteHealthLastChecked").textContent = formatDate(status?.lastCheckedAt);
	byId("siteHealthLastHealthy").textContent = formatDate(status?.lastHealthyAt);
	byId("siteHealthLastResponse").textContent = status?.lastStatus
		? `HTTP ${status.lastStatus}${status.lastLatencyMs !== null ? ` in ${formatDuration(status.lastLatencyMs)}` : ""}`
		: status?.lastLatencyMs !== null && status?.lastLatencyMs !== undefined
			? formatDuration(status.lastLatencyMs)
			: "-";
	byId("siteHealthFailures").textContent = formatNumber(status?.consecutiveFailures ?? 0);
	byId("siteHealthError").textContent = status?.lastError ?? (status?.lastCheckedAt ? "Latest health check passed." : "No health check has run yet.");
	const timeline = [
		...events.map((event) => ({ ...event, target: "Origin pool" })),
		...backendEvents.map((event) => ({ ...event, target: event.originName ?? event.origin_id ?? "Origin" })),
	].sort((left, right) => Number(right.created_at) - Number(left.created_at));
	byId("siteHealthEvents").innerHTML = timeline.length
		? timeline
				.map(
					(event) =>
						`<div class="health-event-item"><span>${formatDate(event.created_at)}</span><span class="badge ${healthBadgeClass(event.to_state)}">${escapeHtml(event.to_state)}</span><span><strong>${escapeHtml(event.target)}</strong>: ${escapeHtml(event.error ?? (event.status ? `HTTP ${event.status}` : `${event.from_state} to ${event.to_state}`))}</span></div>`,
				)
				.join("")
		: '<p class="muted">No health state changes yet.</p>';
}

async function loadSiteHealth(siteId) {
	if (!siteId) return;
	try {
		const result = await api(`/sites/${encodeURIComponent(siteId)}/health`, {}, false);
		applySiteHealthStatus(result.status, result.events ?? [], result.backendEvents ?? []);
		const site = sites.find((item) => item.id === siteId);
		if (site) site.originHealth = result.status;
		renderSites();
		if (siteId === selectedSiteId) renderOriginHealthBanner(result.status);
	} catch (error) {
		byId("siteHealthError").textContent = error.message;
	}
}

async function checkOriginNow(siteId = selectedSiteId) {
	if (!siteId) throw new Error("Select a site first");
	await api(`/sites/${encodeURIComponent(siteId)}/health/check`, { method: "POST" }, false);
	await Promise.all([loadSiteHealth(siteId), loadOverview()]);
	showToast("Origin health check completed.");
}

function renderOriginPool() {
	const container = byId("originPoolList");
	container.innerHTML = siteOrigins.length
		? siteOrigins
				.map((origin) => {
					const state = origin.health?.state ?? (origin.enabled ? "unknown" : "disabled");
					return `<div class="origin-pool-item"><div class="origin-pool-copy"><div class="origin-pool-title"><strong>${escapeHtml(origin.name)}</strong>${origin.isPrimary ? '<span class="badge info">primary</span>' : ""}<span class="badge ${healthBadgeClass(state)}">${escapeHtml(state)}</span>${origin.draining ? '<span class="badge warn">draining</span>' : ""}${origin.enabled ? "" : '<span class="badge warn">disabled</span>'}${origin.mtls?.enabled ? '<span class="badge info">mtls</span>' : ""}</div><div class="origin-pool-meta"><code>${escapeHtml(origin.originUrl)}</code><span>Priority ${formatNumber(origin.priority)} | Weight ${formatNumber(origin.weight)} | Health path: ${escapeHtml(origin.healthCheckPath || "site default")}${origin.health?.lastLatencyMs !== null && origin.health?.lastLatencyMs !== undefined ? ` | ${formatDuration(origin.health.lastLatencyMs)}` : ""}</span></div></div><div class="origin-pool-actions"><button class="button secondary compact" type="button" data-origin-check="${escapeHtml(origin.id)}">Check</button><button class="button secondary compact" type="button" data-origin-edit="${escapeHtml(origin.id)}">Edit</button>${origin.isPrimary ? "" : `<button class="button danger compact" type="button" data-origin-delete="${escapeHtml(origin.id)}">Delete</button>`}</div></div>`;
				})
				.join("")
		: '<p class="muted">No origins are configured.</p>';
}

function resetOriginForm() {
	editingOriginId = null;
	byId("originId").value = "";
	byId("originName").value = "";
	byId("originUrl").value = "";
	byId("originPriority").value = "10";
	byId("originWeight").value = "1";
	byId("originHealthPath").value = "";
	byId("originEnabled").checked = true;
	byId("originDraining").checked = false;
	byId("originMtlsEnabled").checked = false;
	byId("originMtlsStatus").textContent = "";
	byId("originMtlsCertificatePem").value = "";
	byId("originMtlsPrivateKeyPem").value = "";
	byId("originMtlsCaPem").value = "";
	byId("originTrustedCaStatus").textContent = "";
	byId("originMtlsActions").classList.add("hidden");
	byId("downloadOriginMtlsCertificate").classList.add("hidden");
	byId("originTrustedCaActions").classList.add("hidden");
	byId("downloadOriginTrustedCa").classList.add("hidden");
	byId("generatedOriginKeyPanel").classList.add("hidden");
	byId("generatedOriginKeyValue").textContent = "";
	for (const input of byId("originForm").querySelectorAll("input")) input.disabled = true;
	byId("saveOrigin").textContent = "Add origin";
	byId("originForm").classList.add("hidden");
	updateOriginMtlsControls();
}

function updateOriginMtlsControls() {
	byId("originMtlsSettings").classList.toggle("hidden", !byId("originMtlsEnabled").checked);
}

function editOrigin(id) {
	const origin = siteOrigins.find((item) => item.id === id);
	if (!origin) return;
	editingOriginId = origin.id;
	byId("originId").value = origin.id;
	byId("originName").value = origin.name;
	byId("originUrl").value = origin.originUrl;
	byId("originPriority").value = String(origin.priority);
	byId("originWeight").value = String(origin.weight);
	byId("originHealthPath").value = origin.healthCheckPath ?? "";
	byId("originEnabled").checked = Boolean(origin.enabled);
	byId("originDraining").checked = Boolean(origin.draining);
	byId("originMtlsEnabled").checked = Boolean(origin.mtls?.enabled);
	byId("originMtlsCertificatePem").value = "";
	byId("originMtlsPrivateKeyPem").value = "";
	byId("originMtlsCaPem").value = "";
	byId("originMtlsStatus").textContent = origin.mtls?.configured ? "Client certificate configured." : "No client certificate configured yet.";
	byId("originTrustedCaStatus").textContent = origin.mtls?.caConfigured ? "Trusted CA / origin certificate configured." : "No trusted CA configured yet.";
	byId("originMtlsActions").classList.remove("hidden");
	byId("downloadOriginMtlsCertificate").classList.toggle("hidden", !origin.mtls?.configured);
	byId("originTrustedCaActions").classList.remove("hidden");
	byId("downloadOriginTrustedCa").classList.toggle("hidden", !origin.mtls?.caConfigured);
	byId("generatedOriginKeyPanel").classList.add("hidden");
	byId("generatedOriginKeyValue").textContent = "";
	for (const input of byId("originForm").querySelectorAll("input")) input.disabled = false;
	byId("saveOrigin").textContent = "Save origin";
	byId("originForm").classList.remove("hidden");
	updateOriginMtlsControls();
	byId("originName").focus();
}

async function generateOriginMtlsCertificate() {
	if (!editingOriginId) return;
	const origin = siteOrigins.find((item) => item.id === editingOriginId);
	if (
		origin?.mtls?.configured &&
		!confirm(
			"Regenerate the mTLS client certificate for this origin? The previous certificate will stop working immediately, so update the origin's trust store afterward.",
		)
	) {
		return;
	}
	const button = byId("generateOriginMtlsCertificate");
	button.disabled = true;
	try {
		await api(`/origins/${encodeURIComponent(editingOriginId)}/mtls/generate`, { method: "POST" }, false);
		await loadOrigins(editingSiteId);
		const refreshed = siteOrigins.find((item) => item.id === editingOriginId);
		if (refreshed) {
			byId("originMtlsEnabled").checked = Boolean(refreshed.mtls?.enabled);
			byId("originMtlsStatus").textContent = "Client certificate configured.";
			byId("downloadOriginMtlsCertificate").classList.remove("hidden");
			updateOriginMtlsControls();
		}
		showToast("Client certificate generated. Download it and install it on your origin server.");
		downloadOriginMtlsCertificate();
	} catch (error) {
		showToast(error.message, "bad");
	} finally {
		button.disabled = false;
	}
}

function downloadOriginMtlsCertificate() {
	if (!editingOriginId) return;
	window.location.href = `${ADMIN_API}/origins/${encodeURIComponent(editingOriginId)}/mtls/certificate`;
}

function downloadTextFile(filename, content) {
	const blob = new Blob([content], { type: "application/x-pem-file" });
	const url = URL.createObjectURL(blob);
	const link = document.createElement("a");
	link.href = url;
	link.download = filename;
	document.body.appendChild(link);
	link.click();
	link.remove();
	URL.revokeObjectURL(url);
}

async function generateOriginCertificate() {
	if (!editingOriginId) return;
	const origin = siteOrigins.find((item) => item.id === editingOriginId);
	if (
		origin?.mtls?.caConfigured &&
		!confirm(
			"Regenerate the origin server certificate for this origin? The previous certificate will stop being trusted immediately, so install the new certificate and key on the origin right after this.",
		)
	) {
		return;
	}
	const button = byId("generateOriginCertificate");
	button.disabled = true;
	try {
		const result = await api(`/origins/${encodeURIComponent(editingOriginId)}/mtls/generate-origin-certificate`, { method: "POST" }, false);
		await loadOrigins(editingSiteId);
		byId("originTrustedCaStatus").textContent = "Trusted CA / origin certificate configured.";
		byId("downloadOriginTrustedCa").classList.remove("hidden");
		byId("generatedOriginKeyValue").textContent = result.privateKeyPem;
		byId("generatedOriginKeyPanel").classList.remove("hidden");
		showToast("Origin certificate generated. Save the private key now and install both on your origin server.");
	} catch (error) {
		showToast(error.message, "bad");
	} finally {
		button.disabled = false;
	}
}

function downloadOriginTrustedCa() {
	if (!editingOriginId) return;
	window.location.href = `${ADMIN_API}/origins/${encodeURIComponent(editingOriginId)}/mtls/trusted-ca`;
}

async function loadOrigins(siteId) {
	if (!siteId) return;
	try {
		const result = await api(`/sites/${encodeURIComponent(siteId)}/origins`, {}, false);
		siteOrigins = result.items ?? [];
		renderOriginPool();
	} catch (error) {
		byId("originPoolList").innerHTML = `<p class="error-text">${escapeHtml(error.message)}</p>`;
	}
}

async function saveOrigin(event) {
	event.preventDefault();
	if (!editingSiteId) return;
	for (const input of byId("originForm").querySelectorAll("input")) {
		if (!input.reportValidity()) return;
	}
	const button = byId("saveOrigin");
	button.disabled = true;
	try {
		const payload = {
			name: byId("originName").value.trim(),
			originUrl: byId("originUrl").value.trim(),
			priority: Number(byId("originPriority").value),
			weight: Number(byId("originWeight").value),
			healthCheckPath: byId("originHealthPath").value.trim(),
			enabled: byId("originEnabled").checked,
			draining: byId("originDraining").checked,
			mtlsEnabled: byId("originMtlsEnabled").checked,
		};
		const mtlsCertificatePem = byId("originMtlsCertificatePem").value.trim();
		const mtlsPrivateKeyPem = byId("originMtlsPrivateKeyPem").value.trim();
		const mtlsCaPem = byId("originMtlsCaPem").value.trim();
		if (mtlsCertificatePem || mtlsPrivateKeyPem) {
			payload.mtlsCertificatePem = mtlsCertificatePem;
			payload.mtlsPrivateKeyPem = mtlsPrivateKeyPem;
		}
		if (mtlsCaPem) payload.mtlsCaPem = mtlsCaPem;
		await api(
			editingOriginId ? `/origins/${encodeURIComponent(editingOriginId)}` : `/sites/${encodeURIComponent(editingSiteId)}/origins`,
			{ method: editingOriginId ? "PUT" : "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) },
			false,
		);
		const wasEditing = Boolean(editingOriginId);
		resetOriginForm();
		await Promise.all([loadOrigins(editingSiteId), loadSites(), loadSiteHealth(editingSiteId)]);
		const refreshedSite = sites.find((site) => site.id === editingSiteId);
		if (refreshedSite) byId("siteOriginUrl").value = refreshedSite.originUrl;
		showToast(wasEditing ? "Origin updated." : "Origin added.");
	} catch (error) {
		showToast(error.message, "bad");
	} finally {
		button.disabled = false;
	}
}

function pendingChangeForSite(id) {
	return sitePendingChanges.find((change) => change.entityId === id) ?? null;
}

function datetimeLocalToEpochMs(value) {
	if (!value) return null;
	const parsed = new Date(value);
	return Number.isNaN(parsed.getTime()) ? null : parsed.getTime();
}

function pendingChangeBadge(pending) {
	if (!pending) return "";
	const failed = pending.status === "failed";
	const label = failed ? "schedule failed" : `scheduled ${formatDate(pending.applyAt)}`;
	return `<span class="badge ${failed ? "bad" : "warn"}" title="${escapeHtml(pendingChangeSummaryText(pending))}">${escapeHtml(label)}</span>`;
}

function pendingChangeSummaryText(pending) {
	if (pending.status === "failed") {
		const reason = pending.lastError ? `: ${pending.lastError}` : "";
		return `${pending.summary} - failed after ${pending.attempts} attempt${pending.attempts === 1 ? "" : "s"}${reason}`;
	}
	return `${pending.summary}, at ${formatDate(pending.applyAt)}`;
}

function renderSitePendingChangeBanner(siteId) {
	byId("sitePendingChangeEffectiveAt").value = "";
	const pending = siteId ? pendingChangeForSite(siteId) : null;
	const banner = byId("sitePendingChangeBanner");
	banner.classList.toggle("hidden", !pending);
	if (!pending) return;
	const failed = pending.status === "failed";
	banner.classList.toggle("failed", failed);
	byId("sitePendingChangeLabel").textContent = failed ? "Scheduled change failed:" : "Scheduled change:";
	byId("sitePendingChangeSummary").textContent = pendingChangeSummaryText(pending);
	byId("sitePendingChangeApplyNow").textContent = failed ? "Retry now" : "Apply now";
	byId("sitePendingChangeCancel").textContent = failed ? "Dismiss" : "Cancel";
}

async function applySitePendingChangeNow() {
	if (!editingSiteId) return;
	const button = byId("sitePendingChangeApplyNow");
	button.disabled = true;
	try {
		await api(`/sites/${encodeURIComponent(editingSiteId)}/pending-change/apply-now`, { method: "POST" }, false);
		await loadSites();
		editSite(editingSiteId);
		await reloadSelectedSite();
		showToast("Scheduled change applied.");
	} catch (error) {
		showToast(error.message, "bad");
	} finally {
		button.disabled = false;
	}
}

async function cancelSitePendingChange() {
	if (!editingSiteId) return;
	const button = byId("sitePendingChangeCancel");
	button.disabled = true;
	try {
		await api(`/sites/${encodeURIComponent(editingSiteId)}/pending-change`, { method: "DELETE" }, false);
		await loadSites();
		editSite(editingSiteId);
		showToast("Scheduled change cancelled.");
	} catch (error) {
		showToast(error.message, "bad");
	} finally {
		button.disabled = false;
	}
}

function renderSites() {
	const container = byId("sitesList");
	if (sites.length === 0) {
		container.innerHTML = '<div class="empty-state-inline">No sites are configured. Create the first protected site.</div>';
		return;
	}
	container.innerHTML = sites
		.map((site) => {
			return `<div class="site-list-item ${site.id === selectedSiteId ? "selected" : ""} ${site.enabled ? "" : "disabled"}">
    <div>
      <div class="site-list-title"><strong>${escapeHtml(site.name)}</strong><span class="badge ${site.enabled ? "ok" : "warn"}">${site.enabled ? "enabled" : "disabled"}</span><span class="badge info">${site.defaultAccessMode === "bypass" ? "unprotected" : "challenge"}</span>${site.websocket?.mode === "deny" ? '<span class="badge warn">WebSocket off</span>' : ""}${site.healthCheck?.enabled ? `<span class="badge ${healthBadgeClass(site.originHealth?.state)}">origin ${escapeHtml(site.originHealth?.state ?? "unknown")}</span>` : ""}${pendingChangeBadge(pendingChangeForSite(site.id))}</div>
      <div class="site-list-meta"><code title="${escapeHtml(site.publicHost)}">${escapeHtml(site.publicHost)}</code><span title="${escapeHtml(site.originUrl)}">${escapeHtml(site.originUrl)}</span></div>
    </div>
    <div class="site-list-actions"><button class="button secondary compact" type="button" data-site-select="${escapeHtml(site.id)}">Use</button><button class="button secondary compact" type="button" data-site-edit="${escapeHtml(site.id)}">Edit</button></div>
  </div>`;
		})
		.join("");
}

function setSiteEditorTab(name) {
	if (name === "tls" && !editingSiteId) return;
	activeSiteEditorTab = name;
	document.querySelectorAll("[data-site-editor-panel]").forEach((panel) => {
		panel.classList.toggle("hidden", panel.dataset.siteEditorPanel !== name);
	});
	document.querySelectorAll("[data-site-editor-tab]").forEach((tab) => {
		const selected = tab.dataset.siteEditorTab === name;
		tab.classList.toggle("active", selected);
		tab.setAttribute("aria-selected", String(selected));
		if (tab.dataset.siteEditorTab === "tls") {
			tab.disabled = !editingSiteId;
			tab.title = editingSiteId ? "Manage HTTPS for this site" : "Save the site before configuring HTTPS";
		}
	});
	byId("siteFormActions").classList.toggle("hidden", name === "tls");
	byId("generatedSecretPanel").classList.toggle("hidden", name !== "general" || byId("generatedSecretPanel").dataset.available !== "true");
}

function setRouteEditorTab(name) {
	activeRouteEditorTab = name;
	document.querySelectorAll("[data-route-editor-panel]").forEach((panel) => {
		panel.classList.toggle("hidden", panel.dataset.routeEditorPanel !== name);
	});
	document.querySelectorAll("[data-route-editor-tab]").forEach((tab) => {
		const selected = tab.dataset.routeEditorTab === name;
		tab.classList.toggle("active", selected);
		tab.setAttribute("aria-selected", String(selected));
	});
	byId("routePolicyLayout").classList.toggle("network-tab-active", name === "network");
}

function applyWebSocketInputLimits() {
	const limits = [
		["ConnectTimeout", websocketDefaults.connectTimeoutMs],
		["IdleTimeout", websocketDefaults.idleTimeoutSeconds],
		["MaxPayload", websocketDefaults.maxPayloadBytes],
		["PreOpenQueue", websocketDefaults.preOpenQueueBytes],
		["UpstreamBuffer", websocketDefaults.upstreamBufferBytes],
	];
	for (const [suffix, maximum] of limits) {
		byId(`siteWebSocket${suffix}`).max = String(maximum);
		byId(`routeWebSocket${suffix}`).max = String(maximum);
	}
}

function updateSiteWebSocketControls() {
	byId("siteWebSocketSettings").classList.toggle("hidden", byId("siteWebSocketMode").value === "deny");
	byId("siteWebSocketAvailability").textContent = websocketDefaults.available ? "Available" : "Instance disabled";
	byId("siteWebSocketAvailability").className = `badge ${websocketDefaults.available ? "ok" : "warn"}`;
	byId("siteWebSocketDisabledNotice").classList.toggle("hidden", websocketDefaults.available);
}

function updateSiteHttpCacheControls() {
	byId("siteHttpCacheSettings").classList.toggle("hidden", !byId("siteHttpCacheEnabled").checked);
}

function updateSiteHttpBodyCaptureControls() {
	byId("siteHttpBodyCaptureSettings").classList.toggle("hidden", !byId("siteHttpBodyCaptureEnabled").checked);
}

function updateSiteHttpHeaderCaptureControls() {
	byId("siteHttpHeaderCaptureSettings").classList.toggle("hidden", !byId("siteHttpHeaderCaptureEnabled").checked);
}

function updateSiteHttpCorsControls() {
	byId("siteHttpCorsSettings").classList.toggle("hidden", !byId("siteHttpCorsEnabled").checked);
	const wildcard = byId("siteHttpCorsOrigins")
		.value.split(/[\s,]+/u)
		.map((value) => value.trim())
		.includes("*");
	byId("siteHttpCorsCredentialsWarning").classList.toggle("hidden", !(wildcard && byId("siteHttpCorsCredentials").checked));
}

function updateSiteHttpHstsControls() {
	byId("siteHttpHstsSettings").classList.toggle("hidden", !byId("siteHttpHstsEnabled").checked);
	const maxAge = Number(byId("siteHttpHstsMaxAge").value) || 0;
	byId("siteHttpHstsMaxAgeDays").textContent = `About ${(maxAge / 86_400).toFixed(1)} days.`;
}

function updateSiteProtectionControls() {
	const mode = byId("siteHttpProtectionMode").value;
	const badge = byId("siteProtectionModeBadge");
	badge.textContent = mode === "block" ? "Blocking" : mode === "monitor" ? "Monitor" : "Disabled";
	badge.className = `badge ${mode === "block" ? "bad" : mode === "monitor" ? "info" : "warn"}`;
	const selectedId = byId("siteHttpProtectionRuleset").value === "default" ? managedProtection.defaultRuleSetId : byId("siteHttpProtectionRuleset").value;
	const ruleSet = managedProtection.items.find((item) => item.id === selectedId);
	byId("siteProtectionRulesetHelp").textContent = ruleSet
		? `${ruleSet.title} ${ruleSet.version} - ${ruleSet.description}`
		: "The active default ruleset is loaded by BurrowGate.";
}

function openSelectedSiteCacheSettings() {
	setActiveTab("sites");
	if (selectedSiteId) editSite(selectedSiteId);
	setSiteEditorTab("http");
}

function openSelectedSiteProtectionSettings() {
	setActiveTab("sites");
	if (selectedSiteId) editSite(selectedSiteId);
	setSiteEditorTab("protection");
}

function renderCacheMetrics(metrics) {
	const value = metrics ?? {};
	byId("cacheHitRatio").textContent = `${(Number(value.hitRatio ?? 0) * 100).toFixed(2)}%`;
	byId("cacheLookups").textContent = `${formatNumber(value.hits)} / ${formatNumber(value.misses)}`;
	byId("cacheEntries").textContent = `${formatNumber(value.entries)} / ${formatNumber(value.maxEntries)}`;
	byId("cacheBytes").textContent = `${formatBytes(value.bytes)} / ${formatBytes(value.maxBytes)}`;
	byId("cacheBypasses").textContent = formatNumber(value.bypasses);
	byId("cacheStores").textContent = formatNumber(value.stores);
	byId("cacheEvictions").textContent = `${formatNumber(value.evictions)} / ${formatNumber(value.expired)}`;
	byId("cacheBytesServed").textContent = formatBytes(value.bytesServed);
}

async function loadCacheMetrics(siteId = selectedSiteId) {
	if (!siteId) return;
	const response = await api(`/cache?siteId=${encodeURIComponent(siteId)}`, {}, false);
	if (selectedSiteId !== siteId) return;
	renderCacheMetrics(response.metrics);
}

async function purgeSiteCache(allSites = false) {
	const siteId = selectedSiteId;
	if (!allSites && !siteId) return;
	const pathPrefix = allSites ? "" : byId("cachePurgePath").value.trim();
	const target = allSites ? "/cache/purge" : `/cache/purge?siteId=${encodeURIComponent(siteId)}`;
	const result = await api(
		target,
		{ method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(allSites ? { allSites: true } : { pathPrefix }) },
		false,
	);
	if (allSites) await loadCacheMetrics(siteId);
	else renderCacheMetrics(result.metrics);
	showToast(`Purged ${formatNumber(result.purged)} cached entr${result.purged === 1 ? "y" : "ies"}.`);
}

async function purgeRouteCache() {
	if (!editingRoutePolicyId) return;
	const result = await api("/cache/purge", {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({ routePolicyId: editingRoutePolicyId }),
	});
	showToast(`Purged ${formatNumber(result.purged)} cached entr${result.purged === 1 ? "y" : "ies"} for this route policy.`);
}

function resetSiteForm() {
	editingSiteId = null;
	byId("siteForm").reset();
	byId("siteId").value = "";
	byId("siteSessionTtl").value = "43200";
	byId("siteEventRetentionDays").value = String(defaultEventRetentionDays);
	byId("siteEnabled").checked = true;
	byId("siteDefaultAccessMode").value = "challenge";
	byId("siteIpExtractionPreset").value = "direct";
	byId("siteLoadBalancingAlgorithm").value = "failover";
	byId("siteLoadBalancingAffinity").checked = true;
	byId("siteOutboundFetchProtocol").value = "http1";
	byId("siteWebSocketMode").value = websocketDefaults.mode ?? "allow";
	byId("siteWebSocketConnectTimeout").value = String(websocketDefaults.connectTimeoutMs);
	byId("siteWebSocketIdleTimeout").value = String(websocketDefaults.idleTimeoutSeconds);
	byId("siteWebSocketMaxPayload").value = String(websocketDefaults.maxPayloadBytes);
	byId("siteWebSocketPreOpenQueue").value = String(websocketDefaults.preOpenQueueBytes);
	byId("siteWebSocketUpstreamBuffer").value = String(websocketDefaults.upstreamBufferBytes);
	updateSiteWebSocketControls();
	writeHttpPolicy("siteHttp", null, false);
	byId("siteHttpCacheMaxObject").max = String(httpCacheDefaults.instanceMaxObjectBytes);
	byId("siteHttpBodyCaptureMaxRequest").max = String(bodyCaptureDefaults.instanceMaxBytesCeiling);
	byId("siteHttpBodyCaptureMaxResponse").max = String(bodyCaptureDefaults.instanceMaxBytesCeiling);
	byId("originPoolRuntime").classList.add("hidden");
	siteOrigins = [];
	resetOriginForm();
	byId("siteHealthEnabled").checked = false;
	byId("siteHealthPath").value = "/health";
	byId("siteHealthInterval").value = "30";
	byId("siteHealthTimeout").value = "3000";
	byId("siteHealthFailureThreshold").value = "3";
	byId("siteHealthRecoveryThreshold").value = "2";
	byId("siteHealthFailureMode").value = "monitor";
	byId("siteHealthRuntime").classList.add("hidden");
	applySiteHealthStatus({ state: "disabled" }, []);
	updateHealthControls();
	byId("siteChallengePolicy").value = JSON.stringify(defaultChallengePolicy(), null, 2);
	byId("siteErrorResponseMode").value = errorResponseDefaults.mode ?? "json";
	byId("siteErrorHtmlTemplate").value = errorResponseDefaults.htmlTemplate ?? "";
	setErrorJsonFields(errorResponseDefaults.jsonFields ?? []);
	updateErrorResponseControls();
	byId("siteChallengeHtmlTemplate").value = challengeDefaults.htmlTemplate ?? "";
	byId("siteSigningSecret").value = "";
	byId("siteSigningSecret").type = "password";
	byId("siteFormTitle").textContent = "Create site";
	byId("siteFormSubtitle").textContent = "Add another hostname and origin to BurrowGate.";
	byId("siteSecretHelp").textContent = "Leave blank to generate a secure secret. The generated value is shown once after creation.";
	byId("saveSite").textContent = "Create";
	byId("deleteSite").classList.add("hidden");
	byId("cancelSiteEdit").classList.add("hidden");
	byId("generatedSecretPanel").classList.add("hidden");
	byId("generatedSecretPanel").dataset.available = "false";
	byId("siteTlsPanel").classList.add("hidden");
	currentTls = null;
	renderSitePendingChangeBanner(null);
	setSiteEditorTab("general");
}

function editSite(id) {
	const site = sites.find((item) => item.id === id);
	if (!site) return;
	editingSiteId = site.id;
	byId("siteId").value = site.id;
	byId("siteName").value = site.name;
	byId("sitePublicHost").value = site.publicHost;
	byId("siteOriginUrl").value = site.originUrl;
	byId("siteSessionTtl").value = String(site.sessionTtlSeconds);
	byId("siteEventRetentionDays").value = String(site.eventRetentionDays ?? defaultEventRetentionDays);
	byId("siteEnabled").checked = Boolean(site.enabled);
	byId("siteDefaultAccessMode").value = site.defaultAccessMode ?? "challenge";
	byId("siteIpExtractionPreset").value = site.ipExtractionPreset ?? "direct";
	byId("siteLoadBalancingAlgorithm").value = site.loadBalancer?.algorithm ?? "failover";
	byId("siteLoadBalancingAffinity").checked = site.loadBalancer?.affinity !== false;
	byId("siteOutboundFetchProtocol").value = site.outboundFetchProtocol ?? "http1";
	const websocket = site.websocket ?? websocketDefaults;
	byId("siteWebSocketMode").value = websocket.mode ?? "allow";
	byId("siteWebSocketConnectTimeout").value = String(websocket.connectTimeoutMs ?? websocketDefaults.connectTimeoutMs);
	byId("siteWebSocketIdleTimeout").value = String(websocket.idleTimeoutSeconds ?? websocketDefaults.idleTimeoutSeconds);
	byId("siteWebSocketMaxPayload").value = String(websocket.maxPayloadBytes ?? websocketDefaults.maxPayloadBytes);
	byId("siteWebSocketPreOpenQueue").value = String(websocket.preOpenQueueBytes ?? websocketDefaults.preOpenQueueBytes);
	byId("siteWebSocketUpstreamBuffer").value = String(websocket.upstreamBufferBytes ?? websocketDefaults.upstreamBufferBytes);
	updateSiteWebSocketControls();
	writeHttpPolicy("siteHttp", site.http, false);
	byId("siteHttpCacheMaxObject").max = String(httpCacheDefaults.instanceMaxObjectBytes);
	byId("siteHttpBodyCaptureMaxRequest").max = String(bodyCaptureDefaults.instanceMaxBytesCeiling);
	byId("siteHttpBodyCaptureMaxResponse").max = String(bodyCaptureDefaults.instanceMaxBytesCeiling);
	byId("originPoolRuntime").classList.remove("hidden");
	resetOriginForm();
	const health = site.healthCheck ?? {};
	byId("siteHealthEnabled").checked = Boolean(health.enabled);
	byId("siteHealthPath").value = health.path ?? "/health";
	byId("siteHealthInterval").value = String(health.intervalSeconds ?? 30);
	byId("siteHealthTimeout").value = String(health.timeoutMs ?? 3000);
	byId("siteHealthFailureThreshold").value = String(health.failureThreshold ?? 3);
	byId("siteHealthRecoveryThreshold").value = String(health.recoveryThreshold ?? 2);
	byId("siteHealthFailureMode").value = health.failureMode ?? "monitor";
	byId("siteHealthRuntime").classList.remove("hidden");
	updateHealthControls();
	applySiteHealthStatus(site.originHealth ?? { state: health.enabled ? "unknown" : "disabled" }, []);
	byId("siteSigningSecret").value = "";
	byId("siteChallengePolicy").value = JSON.stringify(site.challengePolicy, null, 2);
	byId("siteErrorResponseMode").value = site.errorResponse?.mode ?? "json";
	byId("siteErrorHtmlTemplate").value = site.errorResponse?.htmlTemplate ?? errorResponseDefaults.htmlTemplate ?? "";
	setErrorJsonFields(site.errorResponse?.jsonFields ?? errorResponseDefaults.jsonFields ?? []);
	updateErrorResponseControls();
	byId("siteChallengeHtmlTemplate").value = site.challengePage?.htmlTemplate ?? challengeDefaults.htmlTemplate ?? "";
	byId("siteFormTitle").textContent = `Edit ${site.name}`;
	byId("siteFormSubtitle").textContent = "Changes apply to new requests immediately. Existing session expiration timestamps are unchanged.";
	byId("siteSecretHelp").textContent = "Leave blank to keep the current secret, or enter a new value to rotate it.";
	byId("saveSite").textContent = "Save changes";
	byId("deleteSite").classList.remove("hidden");
	byId("cancelSiteEdit").classList.remove("hidden");
	byId("generatedSecretPanel").classList.add("hidden");
	byId("generatedSecretPanel").dataset.available = "false";
	renderSitePendingChangeBanner(site.id);
	setSiteEditorTab("general");
	byId("siteName").focus();
	void loadSiteTls(site.id);
	void loadSiteHealth(site.id);
	void loadOrigins(site.id);
}

function randomSecret(bytes = 48) {
	const data = new Uint8Array(bytes);
	crypto.getRandomValues(data);
	let binary = "";
	for (const value of data) binary += String.fromCharCode(value);
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

async function loadSites() {
	const response = await api("/sites", {}, false);
	sites = response.items ?? [];
	sitePendingChanges = response.pendingChanges ?? [];
	challengeProviders = response.challengeProviders ?? [];
	defaultEventRetentionDays = Number(response.defaultEventRetentionDays ?? 7);
	websocketDefaults = response.websocketDefaults ?? websocketDefaults;
	httpCacheDefaults = response.httpCacheDefaults ?? httpCacheDefaults;
	bodyCaptureDefaults = response.bodyCaptureDefaults ?? bodyCaptureDefaults;
	headerCaptureDefaults = response.headerCaptureDefaults ?? headerCaptureDefaults;
	managedProtection = response.managedProtection ?? managedProtection;
	const protectionRulesetSelect = byId("siteHttpProtectionRuleset");
	const selectedProtectionRuleset = protectionRulesetSelect.value;
	protectionRulesetSelect.innerHTML = `<option value="default">Default managed ruleset</option>${managedProtection.items
		.map((item) => `<option value="${escapeHtml(item.id)}">${escapeHtml(item.title)} ${escapeHtml(item.version)}</option>`)
		.join("")}`;
	if ([...protectionRulesetSelect.options].some((option) => option.value === selectedProtectionRuleset)) {
		protectionRulesetSelect.value = selectedProtectionRuleset;
	}
	updateSiteProtectionControls();
	applyWebSocketInputLimits();
	byId("routeHttpCacheMaxObject").max = String(httpCacheDefaults.instanceMaxObjectBytes);
	byId("routeHttpBodyCaptureMaxRequest").max = String(bodyCaptureDefaults.instanceMaxBytesCeiling);
	byId("routeHttpBodyCaptureMaxResponse").max = String(bodyCaptureDefaults.instanceMaxBytesCeiling);
	const firstErrorOptionsLoad = !errorResponseOptionsLoaded;
	const previousErrorJsonFields = errorResponseOptionsLoaded ? selectedErrorJsonFields() : null;
	errorResponseDefaults = response.errorResponseDefaults ?? errorResponseDefaults;
	renderErrorResponseOptions();
	challengeDefaults = response.challengeDefaults ?? challengeDefaults;
	renderChallengePlaceholders();
	errorResponseOptionsLoaded = true;
	if (firstErrorOptionsLoad && !editingSiteId) resetSiteForm();
	else if (previousErrorJsonFields) setErrorJsonFields(previousErrorJsonFields);
	const requestedId = new URL(location.href).searchParams.get("site");
	const currentValid = selectedSiteId === "" || sites.some((site) => site.id === selectedSiteId);
	const requestedValid = requestedId !== null && sites.some((site) => site.id === requestedId);
	if (!currentValid) selectedSiteId = requestedValid ? requestedId : "";
	persistSiteSelection();
	applyAutomaticDateRange();
	renderSiteSelector();
	renderSites();
	if (loadedTabs.has("access")) renderAccessList();
	const providerText = challengeProviders.length
		? challengeProviders.map((provider) => `${provider.name} (${provider.title})`).join(", ")
		: "No challenge providers are registered";
	byId("challengeProviderHelp").textContent = `Ordered JSON array. Available providers: ${providerText}.`;
	byId("routeChallengeHelp").textContent = `Leave blank to inherit the site chain. Available providers: ${providerText}.`;
	return response;
}

function resetSiteScopedPages() {
	tableState.traffic.page = 1;
	tableState.bandwidth.page = 1;
	tableState.sessions.page = 1;
	tableState.rules.page = 1;
	byId("eventOrigin").value = "";
	setTrafficOriginVisibility();
	latestMetrics = null;
	routePolicies = [];
	accessList = {
		settings: { enabled: false, sendUsernameToUpstream: false, sessionVerificationTokenEnabled: false, sessionVerificationTokenCreatedAt: null },
		users: [],
		availableUsers: [],
	};
	countryRules = [];
	asnRules = [];
	resetRoutePolicyForm();
}

async function reloadSelectedSite() {
	resetSiteScopedPages();
	for (const name of ["bandwidth", "cache", "sessions", "rules", "routes", "access"]) loadedTabs.delete(name);
	const tasks = [loadOverview(), loadMetrics(), refreshGeoAndReferrers(), loadTraffic()];
	if (activeTab === "cache") {
		loadedTabs.add("cache");
		tasks.push(loadCacheMetrics());
	}
	if (activeTab === "bandwidth") {
		loadedTabs.add("bandwidth");
		tasks.push(loadBandwidth());
	}
	if (activeTab === "sessions") {
		loadedTabs.add("sessions");
		tasks.push(loadSessions());
	}
	if (activeTab === "rules") {
		loadedTabs.add("rules");
		tasks.push(loadRules());
	}
	if (activeTab === "routes") {
		loadedTabs.add("routes");
		tasks.push(loadRoutePolicies());
	}
	if (activeTab === "access") {
		loadedTabs.add("access");
		tasks.push(loadAccessList());
	}
	await Promise.all(tasks);
	renderSites();
	markUpdated("Site changed");
}

async function chooseSite(id) {
	if ((id !== "" && !sites.some((site) => site.id === id)) || selectedSiteId === id) return;
	selectedSiteId = id;
	persistSiteSelection();
	applyAutomaticDateRange();
	renderSiteSelector();
	await reloadSelectedSite();
}

async function saveSite(event) {
	event.preventDefault();
	const submit = byId("saveSite");
	const editorTabBeforeSave = activeSiteEditorTab;
	submit.disabled = true;
	byId("generatedSecretPanel").classList.add("hidden");
	byId("generatedSecretPanel").dataset.available = "false";
	let challengePolicy;
	try {
		challengePolicy = JSON.parse(byId("siteChallengePolicy").value);
	} catch {
		setSiteEditorTab("access");
		showToast("Challenge policy must be valid JSON.", "bad");
		submit.disabled = false;
		return;
	}
	let httpPolicy;
	try {
		httpPolicy = readHttpPolicy("siteHttp", false);
	} catch (error) {
		setSiteEditorTab("http");
		showToast(error.message, "bad");
		submit.disabled = false;
		return;
	}
	const errorResponseMode = byId("siteErrorResponseMode").value;
	const errorJsonFields = selectedErrorJsonFields();
	if (errorResponseMode === "json" && errorJsonFields.length === 0) {
		setSiteEditorTab("responses");
		showToast("Select at least one JSON error field.", "bad");
		submit.disabled = false;
		return;
	}
	if (errorResponseMode === "html" && !byId("siteErrorHtmlTemplate").value.trim()) {
		setSiteEditorTab("responses");
		showToast("HTML error template cannot be empty.", "bad");
		submit.disabled = false;
		return;
	}
	const payload = {
		name: byId("siteName").value.trim(),
		publicHost: byId("sitePublicHost").value.trim(),
		originUrl: byId("siteOriginUrl").value.trim(),
		enabled: byId("siteEnabled").checked,
		defaultAccessMode: byId("siteDefaultAccessMode").value,
		ipExtractionPreset: byId("siteIpExtractionPreset").value,
		sessionTtlSeconds: Number(byId("siteSessionTtl").value),
		eventRetentionDays: Number(byId("siteEventRetentionDays").value),
		challengePolicy,
		originSigningSecret: byId("siteSigningSecret").value.trim(),
		errorResponseMode,
		errorHtmlTemplate: byId("siteErrorHtmlTemplate").value,
		errorJsonFields,
		challengeHtmlTemplate: byId("siteChallengeHtmlTemplate").value,
		healthCheck: {
			enabled: byId("siteHealthEnabled").checked,
			path: byId("siteHealthPath").value.trim(),
			intervalSeconds: Number(byId("siteHealthInterval").value),
			timeoutMs: Number(byId("siteHealthTimeout").value),
			failureThreshold: Number(byId("siteHealthFailureThreshold").value),
			recoveryThreshold: Number(byId("siteHealthRecoveryThreshold").value),
			failureMode: byId("siteHealthFailureMode").value,
		},
		loadBalancer: {
			algorithm: byId("siteLoadBalancingAlgorithm").value,
			affinity: byId("siteLoadBalancingAffinity").checked,
		},
		outboundFetchProtocol: byId("siteOutboundFetchProtocol").value,
		websocket: {
			mode: byId("siteWebSocketMode").value,
			connectTimeoutMs: Number(byId("siteWebSocketConnectTimeout").value),
			idleTimeoutSeconds: Number(byId("siteWebSocketIdleTimeout").value),
			maxPayloadBytes: Number(byId("siteWebSocketMaxPayload").value),
			preOpenQueueBytes: Number(byId("siteWebSocketPreOpenQueue").value),
			upstreamBufferBytes: Number(byId("siteWebSocketUpstreamBuffer").value),
		},
		http: httpPolicy,
		effectiveAt: datetimeLocalToEpochMs(byId("sitePendingChangeEffectiveAt").value),
	};
	try {
		const editing = Boolean(editingSiteId);
		const result = await api(
			editing ? `/sites/${encodeURIComponent(editingSiteId)}` : "/sites",
			{
				method: editing ? "PUT" : "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify(payload),
			},
			false,
		);
		const savedId = result.site.id;
		selectedSiteId = savedId;
		await loadSites();
		editSite(savedId);
		if (editing) setSiteEditorTab(editorTabBeforeSave);
		if (result.generatedSigningSecret) {
			byId("generatedSecretValue").textContent = result.generatedSigningSecret;
			byId("generatedSecretPanel").dataset.available = "true";
			byId("generatedSecretPanel").classList.remove("hidden");
		}
		await reloadSelectedSite();
		if (result.pendingChange) showToast(`Site updated. ${result.pendingChange.summary}, scheduled for ${formatDate(result.pendingChange.applyAt)}.`);
		else showToast(editing ? "Site updated." : "Site created.");
	} catch (error) {
		showToast(error.message, "bad");
	} finally {
		submit.disabled = false;
	}
}

async function deleteEditingSite() {
	const site = sites.find((item) => item.id === editingSiteId);
	if (!site) return;
	const confirmation = prompt(
		`Permanently delete ${site.name} and all of its traffic, bandwidth, sessions, policies, rules, origins, health history, alerts, challenges, and TLS data?\n\nType the site name to confirm:`,
	);
	if (confirmation === null) return;
	if (confirmation !== site.name) {
		showToast("The site name did not match. Nothing was deleted.", "bad");
		return;
	}
	const button = byId("deleteSite");
	button.disabled = true;
	try {
		const result = await api(`/sites/${encodeURIComponent(site.id)}`, { method: "DELETE" }, false);
		if (selectedSiteId === site.id) selectedSiteId = "";
		resetSiteForm();
		await loadSites();
		await reloadSelectedSite();
		showToast(result.warning || `${site.name} and its associated data were deleted.`, result.warning ? "bad" : "ok");
	} catch (error) {
		showToast(error.message, "bad");
	} finally {
		button.disabled = false;
	}
}

function routeAccessLabel(mode) {
	return { inherit: "inherit", challenge: "challenge", bypass: "unprotected", block: "blocked" }[mode] ?? mode;
}

function formatRateLimit(policy) {
	if (!policy.rateLimit?.enabled) return "No rate limit";
	if (policy.rateLimit.algorithm === "token-bucket") {
		return `${formatNumber(policy.rateLimit.max)} burst | +${formatNumber(policy.rateLimit.refillRate)} every ${formatDuration(policy.rateLimit.refillIntervalMs)}`;
	}
	return `${formatNumber(policy.rateLimit.max)} / ${formatDuration(policy.rateLimit.windowMs)}`;
}

function renderRoutePolicies() {
	const container = byId("routePolicyList");
	if (!selectedSiteId) {
		container.innerHTML = '<div class="empty-state-inline">Create or select a site before adding route policies.</div>';
		return;
	}
	if (routePolicies.length === 0) {
		container.innerHTML = '<div class="empty-state-inline">No route policies. The site default applies to every request.</div>';
		return;
	}
	container.innerHTML = routePolicies
		.map(
			(policy) => `<div class="route-policy-item ${policy.enabled ? "" : "disabled"}">
    <div class="route-policy-main">
      <div class="site-list-title"><strong>${escapeHtml(policy.name)}</strong><span class="badge ${policy.enabled ? "ok" : "warn"}">${policy.enabled ? "enabled" : "disabled"}</span><span class="badge ${policy.accessMode === "block" ? "bad" : policy.accessMode === "challenge" ? "warn" : "info"}">${escapeHtml(routeAccessLabel(policy.accessMode))}</span></div>
      <div class="route-policy-pattern"><code>${escapeHtml(policy.pathPattern)}</code><span>${policy.methods.length ? escapeHtml(policy.methods.join(", ")) : "All methods"}</span><span>Priority ${formatNumber(policy.priority)}</span></div>
      <div class="site-list-meta"><span>WebSocket: ${escapeHtml(policy.websocket?.mode ?? "inherit")}</span><span>Protection: ${escapeHtml(policy.http?.protection?.mode ?? "inherit")}</span><span>Cache: ${escapeHtml(policy.http?.cache?.mode ?? "inherit")}</span><span>${escapeHtml(formatRateLimit(policy))}</span><span>${escapeHtml(policy.rateLimit?.keyMode ?? "ip")} | ${escapeHtml(policy.rateLimit?.scope ?? "policy")}</span>${(policy.defaultIpAction ?? "inherit") !== "inherit" || (policy.defaultCountryAction ?? "inherit") !== "inherit" ? "<span>Network: custom</span>" : ""}${policy.challengePolicy ? `<span>${formatNumber(policy.challengePolicy.length)} custom challenge step${policy.challengePolicy.length === 1 ? "" : "s"}</span>` : ""}</div>
    </div>
    <div class="site-list-actions"><button class="button secondary compact" type="button" data-route-edit="${escapeHtml(policy.id)}">Edit</button><button class="button danger compact" type="button" data-route-delete="${escapeHtml(policy.id)}">Delete</button></div>
  </div>`,
		)
		.join("");
}

function updateRoutePolicyControls() {
	const rateEnabled = byId("routeRateEnabled").checked;
	byId("routeRateSettings").classList.toggle("hidden", !rateEnabled);
	const algorithm = byId("routeRateAlgorithm").value;
	document.querySelectorAll(".token-setting").forEach((element) => element.classList.toggle("hidden", algorithm !== "token-bucket"));
	document.querySelectorAll(".window-setting").forEach((element) => element.classList.toggle("hidden", algorithm === "token-bucket"));
	document.querySelectorAll(".precision-setting").forEach((element) => element.classList.toggle("hidden", algorithm !== "sliding-window"));
	byId("routeRateHeaderField").classList.toggle("hidden", byId("routeRateKeyMode").value !== "header-or-ip");
	byId("routeChallengeSettings").classList.toggle("hidden", byId("routePolicyAccessMode").value !== "challenge");
	byId("routeWebSocketSettings").classList.toggle("hidden", byId("routeWebSocketMode").value === "deny");
}

function resetRoutePolicyForm() {
	editingRoutePolicyId = null;
	byId("routePolicyForm").reset();
	byId("routePolicyId").value = "";
	byId("routePolicyPath").value = "/api/**";
	byId("routePolicyPriority").value = "0";
	byId("routePolicyAccessMode").value = "inherit";
	byId("routePolicyEnabled").checked = true;
	byId("routePolicyChallenge").value = "";
	byId("routeDefaultIpAction").value = "inherit";
	byId("routeDefaultCountryAction").value = "inherit";
	routeIpRules = [];
	routeCountryRules = [];
	routeAsnRules = [];
	renderRouteIpRules();
	renderRouteCountryRules();
	renderRouteAsnRules();
	byId("routeIpRuleNetworkCidr").value = "";
	byId("routeIpRuleAction").value = "block";
	byId("routeIpRuleExpiresAt").value = "";
	byId("routeIpRuleReason").value = "";
	byId("routeCountryRuleCountry").value = "";
	byId("routeCountryRuleAction").value = "block";
	byId("routeCountryRuleExpiresAt").value = "";
	byId("routeCountryRuleReason").value = "";
	byId("routeAsnRuleAsn").value = "";
	byId("routeAsnRuleAction").value = "block";
	byId("routeAsnRuleExpiresAt").value = "";
	byId("routeAsnRuleReason").value = "";
	byId("routeNetworkRulesSection").classList.add("hidden");
	byId("routeNetworkRulesPlaceholder").classList.remove("hidden");
	byId("routeWebSocketMode").value = "inherit";
	byId("routeWebSocketConnectTimeout").value = "";
	byId("routeWebSocketIdleTimeout").value = "";
	byId("routeWebSocketMaxPayload").value = "";
	byId("routeWebSocketPreOpenQueue").value = "";
	byId("routeWebSocketUpstreamBuffer").value = "";
	writeHttpPolicy("routeHttp", null, true);
	byId("routeHttpCacheMaxObject").max = String(httpCacheDefaults.instanceMaxObjectBytes);
	byId("routeHttpBodyCaptureMaxRequest").max = String(bodyCaptureDefaults.instanceMaxBytesCeiling);
	byId("routeHttpBodyCaptureMaxResponse").max = String(bodyCaptureDefaults.instanceMaxBytesCeiling);
	byId("purgeRouteCache").classList.add("hidden");
	byId("routeRateEnabled").checked = false;
	byId("routeRateAlgorithm").value = "sliding-window";
	byId("routeRateMax").value = "120";
	byId("routeRateWindow").value = "60000";
	byId("routeRatePrecision").value = "100";
	byId("routeRateRefillRate").value = "10";
	byId("routeRateRefillInterval").value = "1000";
	byId("routeRateKeyMode").value = "ip";
	byId("routeRateKeyHeader").value = "";
	byId("routeRateScope").value = "policy";
	byId("routePolicyFormTitle").textContent = "Create route policy";
	byId("routePolicyFormSubtitle").textContent = "Configure route-specific verification and API limits.";
	byId("saveRoutePolicy").textContent = "Create";
	byId("cancelRoutePolicyEdit").classList.add("hidden");
	updateRoutePolicyControls();
	setRouteEditorTab("general");
}

function editRoutePolicy(id) {
	const policy = routePolicies.find((item) => item.id === id);
	if (!policy) return;
	editingRoutePolicyId = policy.id;
	byId("routePolicyId").value = policy.id;
	byId("routePolicyName").value = policy.name;
	byId("routePolicyPath").value = policy.pathPattern;
	byId("routePolicyMethods").value = policy.methods.join(", ");
	byId("routePolicyPriority").value = String(policy.priority);
	byId("routePolicyAccessMode").value = policy.accessMode;
	byId("routePolicyEnabled").checked = Boolean(policy.enabled);
	byId("routePolicyChallenge").value = policy.challengePolicy ? JSON.stringify(policy.challengePolicy, null, 2) : "";
	byId("routeDefaultIpAction").value = policy.defaultIpAction ?? "inherit";
	byId("routeDefaultCountryAction").value = policy.defaultCountryAction ?? "inherit";
	byId("routeNetworkRulesSection").classList.remove("hidden");
	byId("routeNetworkRulesPlaceholder").classList.add("hidden");
	void loadRouteNetworkRules();
	const websocket = policy.websocket ?? {};
	byId("routeWebSocketMode").value = websocket.mode ?? "inherit";
	byId("routeWebSocketConnectTimeout").value = websocket.connectTimeoutMs ?? "";
	byId("routeWebSocketIdleTimeout").value = websocket.idleTimeoutSeconds ?? "";
	byId("routeWebSocketMaxPayload").value = websocket.maxPayloadBytes ?? "";
	byId("routeWebSocketPreOpenQueue").value = websocket.preOpenQueueBytes ?? "";
	byId("routeWebSocketUpstreamBuffer").value = websocket.upstreamBufferBytes ?? "";
	writeHttpPolicy("routeHttp", policy.http, true);
	byId("routeHttpCacheMaxObject").max = String(httpCacheDefaults.instanceMaxObjectBytes);
	byId("routeHttpBodyCaptureMaxRequest").max = String(bodyCaptureDefaults.instanceMaxBytesCeiling);
	byId("routeHttpBodyCaptureMaxResponse").max = String(bodyCaptureDefaults.instanceMaxBytesCeiling);
	byId("purgeRouteCache").classList.remove("hidden");
	byId("routeRateEnabled").checked = Boolean(policy.rateLimit.enabled);
	byId("routeRateAlgorithm").value = policy.rateLimit.algorithm;
	byId("routeRateMax").value = String(policy.rateLimit.max);
	byId("routeRateWindow").value = String(policy.rateLimit.windowMs);
	byId("routeRatePrecision").value = String(policy.rateLimit.precisionMs);
	byId("routeRateRefillRate").value = String(policy.rateLimit.refillRate);
	byId("routeRateRefillInterval").value = String(policy.rateLimit.refillIntervalMs);
	byId("routeRateKeyMode").value = policy.rateLimit.keyMode;
	byId("routeRateKeyHeader").value = policy.rateLimit.keyHeader ?? "";
	byId("routeRateScope").value = policy.rateLimit.scope;
	byId("routePolicyFormTitle").textContent = `Edit ${policy.name}`;
	byId("routePolicyFormSubtitle").textContent = "Changes affect new requests immediately; in-memory counters reset when the limiter configuration changes.";
	byId("saveRoutePolicy").textContent = "Save policy";
	byId("cancelRoutePolicyEdit").classList.remove("hidden");
	updateRoutePolicyControls();
	setRouteEditorTab("general");
	byId("routePolicyName").focus();
}

async function loadRoutePolicies() {
	if (!selectedSiteId) {
		routePolicies = [];
		renderRoutePolicies();
		return;
	}
	byId("routePolicyList").innerHTML = '<div class="empty-state-inline"><span class="spinner"></span> Loading route policies...</div>';
	try {
		const response = await api("/route-policies");
		routePolicies = response.items ?? [];
		renderRoutePolicies();
	} catch (error) {
		byId("routePolicyList").innerHTML = `<div class="empty-state-inline error-text">${escapeHtml(error.message)}</div>`;
	}
}

function renderRouteIpRules() {
	const body = byId("routeIpRules");
	if (routeIpRules.length === 0) {
		body.innerHTML = '<tr><td colspan="6" class="empty-cell">No IP rules configured for this route.</td></tr>';
		return;
	}
	body.innerHTML = routeIpRules
		.map((rule) => {
			const currentState = ruleState(rule);
			return `<tr class="rule-row ${currentState}">
      <td><span class="badge ${currentState === "active" ? "ok" : "warn"}">${currentState}</span></td>
      <td class="ip-cell"><code>${escapeHtml(rule.network_cidr)}</code></td>
      <td><span class="badge action-${escapeHtml(rule.action)}">${escapeHtml(networkActionLabel(rule.action))}</span></td>
      <td title="${escapeHtml(rule.reason)}">${escapeHtml(truncate(rule.reason || "-", 56))}</td>
      <td>${rule.expires_at === null ? "Never" : formatDate(rule.expires_at)}</td>
      <td><button class="button danger compact" data-route-rule-id="${escapeHtml(rule.id)}">Delete</button></td>
    </tr>`;
		})
		.join("");
}

function renderRouteCountryRules() {
	const body = byId("routeCountryRules");
	if (routeCountryRules.length === 0) {
		body.innerHTML = '<tr><td colspan="6" class="empty-cell">No country rules configured for this route.</td></tr>';
		return;
	}
	body.innerHTML = routeCountryRules
		.map((rule) => {
			const currentState = ruleState(rule);
			const code = String(rule.country_code || "ZZ").toUpperCase();
			return `<tr class="rule-row ${currentState}">
      <td><span class="badge ${currentState === "active" ? "ok" : "warn"}">${currentState}</span></td>
      <td>${countryBadge(code)} <span>${escapeHtml(countryDisplayName(code))}</span></td>
      <td><span class="badge action-${escapeHtml(rule.action)}">${escapeHtml(networkActionLabel(rule.action))}</span></td>
      <td title="${escapeHtml(rule.reason)}">${escapeHtml(truncate(rule.reason || "-", 56))}</td>
      <td>${rule.expires_at === null ? "Never" : formatDate(rule.expires_at)}</td>
      <td><button class="button danger compact" data-route-country-rule-id="${escapeHtml(rule.id)}">Delete</button></td>
    </tr>`;
		})
		.join("");
}

function renderRouteAsnRules() {
	const body = byId("routeAsnRules");
	if (routeAsnRules.length === 0) {
		body.innerHTML = '<tr><td colspan="6" class="empty-cell">No ASN rules configured for this route.</td></tr>';
		return;
	}
	body.innerHTML = routeAsnRules
		.map((rule) => {
			const currentState = ruleState(rule);
			return `<tr class="rule-row ${currentState}">
      <td><span class="badge ${currentState === "active" ? "ok" : "warn"}">${currentState}</span></td>
      <td><code>AS${rule.asn}</code></td>
      <td><span class="badge action-${escapeHtml(rule.action)}">${escapeHtml(networkActionLabel(rule.action))}</span></td>
      <td title="${escapeHtml(rule.reason)}">${escapeHtml(truncate(rule.reason || "-", 56))}</td>
      <td>${rule.expires_at === null ? "Never" : formatDate(rule.expires_at)}</td>
      <td><button class="button danger compact" data-route-asn-rule-id="${escapeHtml(rule.id)}">Delete</button></td>
    </tr>`;
		})
		.join("");
}

async function loadRouteNetworkRules() {
	if (!editingRoutePolicyId) return;
	const requestedId = editingRoutePolicyId;
	try {
		const response = await api(`/route-policies/${encodeURIComponent(requestedId)}/network-rules`);
		if (editingRoutePolicyId !== requestedId) return;
		routeIpRules = response.ipRules ?? [];
		routeCountryRules = response.countryRules ?? [];
		routeAsnRules = response.asnRules ?? [];
		renderRouteIpRules();
		renderRouteCountryRules();
		renderRouteAsnRules();
	} catch (error) {
		showToast(error.message, "bad");
	}
}

function renderAccessImportUsers() {
	const sourceSiteId = byId("accessImportSite").value;
	const users = accessList.availableUsers.filter((user) => user.siteIds?.includes(sourceSiteId));
	byId("accessImportUsers").innerHTML =
		users.length === 0
			? '<option value="" disabled>No users available from this site</option>'
			: users.map((user) => `<option value="${escapeHtml(user.id)}">${escapeHtml(user.username)}${user.enabled ? "" : " (disabled)"}</option>`).join("");
}

function renderAccessList() {
	byId("accessEnabled").checked = Boolean(accessList.settings.enabled);
	byId("accessSendUsername").checked = Boolean(accessList.settings.sendUsernameToUpstream);
	const verificationTokenEnabled = Boolean(accessList.settings.sessionVerificationTokenEnabled);
	byId("accessVerificationTokenStatus").textContent = verificationTokenEnabled ? "Verification token active" : "No verification token";
	byId("accessVerificationTokenStatus").className = `badge ${verificationTokenEnabled ? "ok" : ""}`;
	byId("generateAccessVerificationToken").textContent = verificationTokenEnabled ? "Regenerate token" : "Generate token";
	byId("revokeAccessVerificationToken").classList.toggle("hidden", !verificationTokenEnabled);
	const sourceIds = new Set(accessList.availableUsers.flatMap((user) => user.siteIds ?? []).filter((siteId) => siteId !== selectedSiteId));
	const source = byId("accessImportSite");
	const previousSource = source.value;
	source.innerHTML =
		'<option value="">Select a site</option>' +
		sites
			.filter((site) => sourceIds.has(site.id))
			.map((site) => `<option value="${escapeHtml(site.id)}">${escapeHtml(site.name)} | ${escapeHtml(site.publicHost)}</option>`)
			.join("");
	if (sourceIds.has(previousSource)) source.value = previousSource;
	renderAccessImportUsers();

	const container = byId("accessUserList");
	if (!selectedSiteId) {
		container.innerHTML = '<div class="empty-state-inline">Create or select a site before configuring access authentication.</div>';
		return;
	}
	if (accessList.users.length === 0) {
		container.innerHTML = '<div class="empty-state-inline">No users are assigned to this site.</div>';
		return;
	}
	container.innerHTML = accessList.users
		.map((user) => {
			const twoFactorEnrolled = user.totpEnrolled || user.webauthnCredentialCount > 0;
			const totpBadge = !user.totpRequired
				? '<span class="badge">2FA off</span>'
				: twoFactorEnrolled
					? '<span class="badge ok">2FA enrolled</span>'
					: '<span class="badge warn">2FA pending</span>';
			const webauthnBadge =
				user.webauthnCredentialCount > 0
					? `<span class="badge info">${formatNumber(user.webauthnCredentialCount)} security key${user.webauthnCredentialCount === 1 ? "" : "s"} (this site)</span>`
					: "";
			const tokenBadge = user.apiTokenEnabled ? '<span class="badge ok">API token active</span>' : "";
			return `<div class="route-policy-item ${user.enabled ? "" : "disabled"}" data-access-user-row="${escapeHtml(user.id)}">
    <div class="route-policy-main access-user-fields">
      <div class="site-list-title"><strong>${escapeHtml(user.username)}</strong><span class="badge ${user.enabled ? "ok" : "warn"}">${user.enabled ? "enabled" : "disabled"}</span>${user.siteCount > 1 ? `<span class="badge info">${formatNumber(user.siteCount)} sites</span>` : ""}${totpBadge}${webauthnBadge}${tokenBadge}</div>
      <div class="site-form-grid"><label><span>Username</span><input class="input" data-access-username value="${escapeHtml(user.username)}" maxlength="255"></label><label><span>New password</span><input class="input" data-access-password type="password" autocomplete="new-password" minlength="8" maxlength="1024" placeholder="Leave blank to keep current"></label></div>
      <label class="check-row"><input data-access-enabled type="checkbox"${user.enabled ? " checked" : ""}><span><strong>User enabled</strong><small class="muted">Changes to this shared identity apply on every assigned site.</small></span></label>
    </div>
    <div class="site-list-actions"><button class="button secondary compact" type="button" data-access-save="${escapeHtml(user.id)}">Save</button><button class="button danger compact" type="button" data-access-remove="${escapeHtml(user.id)}">Remove</button></div>
    <div class="site-list-actions security-actions">
      <button class="button secondary compact" type="button" data-access-totp-toggle="${escapeHtml(user.id)}" data-totp-required="${user.totpRequired}">${user.totpRequired ? "Don't require 2FA" : "Require 2FA"}</button>
      ${twoFactorEnrolled ? `<button class="button secondary compact" type="button" data-access-totp-reset="${escapeHtml(user.id)}">Reset 2FA</button>` : ""}
      <button class="button secondary compact" type="button" data-access-token-generate="${escapeHtml(user.id)}">${user.apiTokenEnabled ? "Regenerate API token" : "Generate API token"}</button>
      ${user.apiTokenEnabled ? `<button class="button danger compact" type="button" data-access-token-revoke="${escapeHtml(user.id)}">Revoke API token</button>` : ""}
    </div>
  </div>`;
		})
		.join("");
}

function renderAccessSso() {
	byId("accessSsoEnabled").checked = Boolean(accessSso.enabled);
	byId("accessSsoEnforce").checked = Boolean(accessSso.enforceSso);
	byId("accessSsoIssuer").value = accessSso.issuerUrl ?? "";
	byId("accessSsoClientId").value = accessSso.clientId ?? "";
	byId("accessSsoClientSecret").value = "";
	byId("accessSsoScopes").value = accessSso.scopes || "openid email profile";
	byId("accessSsoButtonLabel").value = accessSso.buttonLabel || "Single sign-on";
	byId("accessSsoSecretStatus").textContent = accessSso.clientSecretConfigured ? "A client secret is configured." : "No client secret is configured.";
	const site = sites.find((candidate) => candidate.id === selectedSiteId);
	byId("accessSsoRedirectUri").textContent = site ? `https://${site.publicHost}/_burrowgate/access/sso/callback` : "Select a site";
	byId("accessSsoBackchannelUri").textContent = site ? `https://${site.publicHost}/_burrowgate/access/sso/backchannel-logout` : "Select a site";
}

async function loadAccessList() {
	if (!selectedSiteId) {
		accessList = {
			settings: {
				enabled: false,
				sendUsernameToUpstream: false,
				sessionVerificationTokenEnabled: false,
				sessionVerificationTokenCreatedAt: null,
			},
			users: [],
			availableUsers: [],
		};
		accessSso = {
			enabled: false,
			enforceSso: false,
			issuerUrl: "",
			clientId: "",
			clientSecretConfigured: false,
			scopes: "openid email profile",
			buttonLabel: "Single sign-on",
		};
		renderAccessList();
		renderAccessSso();
		return;
	}
	byId("accessUserList").innerHTML = '<div class="empty-state-inline"><span class="spinner"></span> Loading access users...</div>';
	try {
		[accessList, accessSso] = await Promise.all([api("/access-list"), api("/access-list/sso")]);
		renderAccessList();
		renderAccessSso();
	} catch (error) {
		byId("accessUserList").innerHTML = `<div class="empty-state-inline error-text">${escapeHtml(error.message)}</div>`;
	}
}

async function saveAccessSettings() {
	accessList = await api("/access-list", {
		method: "PUT",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({ enabled: byId("accessEnabled").checked, sendUsernameToUpstream: byId("accessSendUsername").checked }),
	});
	renderAccessList();
	showToast("Access authentication settings saved.");
}

async function generateAccessVerificationToken() {
	const regenerate = Boolean(accessList.settings.sessionVerificationTokenEnabled);
	if (regenerate && !confirm("Regenerate the session verification token? The previous backend token will stop working immediately.")) return;
	const result = await api("/access-list/session-verification-token", { method: "POST" });
	await loadAccessList();
	window.prompt("Session verification token generated. Copy it now as it will not be shown again:", result.token);
}

async function revokeAccessVerificationToken() {
	if (!confirm("Revoke the session verification token? Separate backends using it will stop accepting sessions immediately.")) return;
	await api("/access-list/session-verification-token", { method: "DELETE" });
	await loadAccessList();
	showToast("Session verification token revoked.");
}

async function saveAccessSso() {
	const button = byId("saveAccessSso");
	button.disabled = true;
	try {
		const secret = byId("accessSsoClientSecret").value;
		accessSso = await api("/access-list/sso", {
			method: "PUT",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				enabled: byId("accessSsoEnabled").checked,
				enforceSso: byId("accessSsoEnforce").checked,
				issuerUrl: byId("accessSsoIssuer").value,
				clientId: byId("accessSsoClientId").value,
				...(secret ? { clientSecret: secret } : {}),
				scopes: byId("accessSsoScopes").value,
				buttonLabel: byId("accessSsoButtonLabel").value,
			}),
		});
		renderAccessSso();
		showToast("Single sign-on settings saved.");
	} catch (error) {
		showToast(error.message, "bad");
	} finally {
		button.disabled = false;
	}
}

async function loadAdminSso() {
	try {
		const settings = await api("/sso", {}, false);
		byId("adminSsoEnabled").checked = Boolean(settings.enabled);
		byId("adminSsoEnforce").checked = Boolean(settings.enforceSso);
		byId("adminSsoIssuer").value = settings.issuerUrl ?? "";
		byId("adminSsoClientId").value = settings.clientId ?? "";
		byId("adminSsoClientSecret").value = "";
		byId("adminSsoScopes").value = settings.scopes || "openid email profile";
		byId("adminSsoButtonLabel").value = settings.buttonLabel || "Single sign-on";
		byId("adminSsoSecretStatus").textContent = settings.clientSecretConfigured ? "A client secret is configured." : "No client secret is configured.";
		byId("adminSsoRedirectUri").textContent = `${location.origin}/_burrowgate/admin/sso/callback`;
		byId("adminSsoBackchannelUri").textContent = `${location.origin}/_burrowgate/admin/sso/backchannel-logout`;
	} catch (error) {
		showToast(error.message, "bad");
	}
}

async function saveAdminSso() {
	const button = byId("saveAdminSso");
	button.disabled = true;
	try {
		const secret = byId("adminSsoClientSecret").value;
		await api(
			"/sso",
			{
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					enabled: byId("adminSsoEnabled").checked,
					enforceSso: byId("adminSsoEnforce").checked,
					issuerUrl: byId("adminSsoIssuer").value,
					clientId: byId("adminSsoClientId").value,
					...(secret ? { clientSecret: secret } : {}),
					scopes: byId("adminSsoScopes").value,
					buttonLabel: byId("adminSsoButtonLabel").value,
				}),
			},
			false,
		);
		await loadAdminSso();
		showToast("Single sign-on settings saved.");
	} catch (error) {
		showToast(error.message, "bad");
	} finally {
		button.disabled = false;
	}
}

async function createAccessUser(event) {
	event.preventDefault();
	const form = event.currentTarget;
	const submit = form.querySelector('button[type="submit"]');
	submit.disabled = true;
	try {
		await api("/access-list/users", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ username: byId("accessUsername").value, password: byId("accessPassword").value, enabled: byId("accessUserEnabled").checked }),
		});
		form.reset();
		byId("accessUserEnabled").checked = true;
		showToast("User created and assigned.");
		await loadAccessList();
	} catch (error) {
		showToast(error.message, "bad");
	} finally {
		submit.disabled = false;
	}
}

async function importSelectedAccessUsers() {
	const userIds = [...byId("accessImportUsers").selectedOptions].map((option) => option.value).filter(Boolean);
	const result = await api("/access-list/import", {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({ userIds }),
	});
	showToast(`${formatNumber(result.imported)} user${result.imported === 1 ? "" : "s"} added.`);
	await loadAccessList();
}

async function saveRoutePolicy(event) {
	event.preventDefault();
	const submit = byId("saveRoutePolicy");
	const editorTabBeforeSave = activeRouteEditorTab;
	submit.disabled = true;
	let challengePolicy = null;
	const challengeText = byId("routePolicyChallenge").value.trim();
	if (challengeText) {
		try {
			challengePolicy = JSON.parse(challengeText);
		} catch {
			showToast("Route challenge policy must be valid JSON.", "bad");
			submit.disabled = false;
			return;
		}
	}
	let httpPolicy;
	try {
		httpPolicy = readHttpPolicy("routeHttp", true);
	} catch (error) {
		showToast(error.message, "bad");
		submit.disabled = false;
		return;
	}
	const payload = {
		name: byId("routePolicyName").value.trim(),
		pathPattern: byId("routePolicyPath").value.trim(),
		methods: byId("routePolicyMethods").value,
		priority: Number(byId("routePolicyPriority").value),
		accessMode: byId("routePolicyAccessMode").value,
		enabled: byId("routePolicyEnabled").checked,
		challengePolicy,
		defaultIpAction: byId("routeDefaultIpAction").value,
		defaultCountryAction: byId("routeDefaultCountryAction").value,
		rateLimitEnabled: byId("routeRateEnabled").checked,
		rateLimitAlgorithm: byId("routeRateAlgorithm").value,
		rateLimitMax: Number(byId("routeRateMax").value),
		rateLimitWindowMs: Number(byId("routeRateWindow").value),
		rateLimitPrecisionMs: Number(byId("routeRatePrecision").value),
		rateLimitRefillRate: Number(byId("routeRateRefillRate").value),
		rateLimitRefillIntervalMs: Number(byId("routeRateRefillInterval").value),
		rateLimitKeyMode: byId("routeRateKeyMode").value,
		rateLimitKeyHeader: byId("routeRateKeyHeader").value.trim(),
		rateLimitScope: byId("routeRateScope").value,
		websocket: {
			mode: byId("routeWebSocketMode").value,
			connectTimeoutMs: optionalNumberInput("routeWebSocketConnectTimeout"),
			idleTimeoutSeconds: optionalNumberInput("routeWebSocketIdleTimeout"),
			maxPayloadBytes: optionalNumberInput("routeWebSocketMaxPayload"),
			preOpenQueueBytes: optionalNumberInput("routeWebSocketPreOpenQueue"),
			upstreamBufferBytes: optionalNumberInput("routeWebSocketUpstreamBuffer"),
		},
		http: httpPolicy,
	};
	try {
		const editing = Boolean(editingRoutePolicyId);
		const response = await api(editing ? `/route-policies/${encodeURIComponent(editingRoutePolicyId)}` : "/route-policies", {
			method: editing ? "PUT" : "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(payload),
		});
		await Promise.all([loadRoutePolicies(), loadMetrics()]);
		editRoutePolicy(response.policy.id);
		if (editing) setRouteEditorTab(editorTabBeforeSave);
		showToast(editing ? "Route policy updated." : "Route policy created.");
	} catch (error) {
		showToast(error.message, "bad");
	} finally {
		submit.disabled = false;
	}
}

function certificateStatusClass(certificate) {
	if (!certificate) return "";
	if (certificate.status === "active" && Number(certificate.expiresAt) > Date.now()) return "ok";
	if (certificate.status === "renewal-failed") return "warn";
	return "bad";
}

function renderTls(data) {
	currentTls = data;
	const settings = data.settings;
	const certificate = data.certificate;
	byId("tlsMode").value = settings.mode;
	byId("tlsForceHttps").checked = Boolean(settings.forceHttps);
	byId("acmeEmail").value = settings.acmeEmail ?? data.defaults.acmeEmail ?? "";
	byId("acmeDirectoryUrl").value = settings.acmeDirectoryUrl ?? data.defaults.acmeDirectoryUrl;
	byId("acmeForceHttps").checked = Boolean(settings.forceHttps || !certificate);
	byId("uploadedForceHttps").checked = Boolean(settings.forceHttps);

	byId("tlsSummaryMode").textContent = settings.mode === "letsencrypt" ? "Let's Encrypt" : settings.mode === "uploaded" ? "Uploaded" : "Disabled";
	byId("tlsSummaryCertificate").textContent = certificate ? `${certificate.source} | ${certificate.status}` : "None";
	byId("tlsSummaryExpires").textContent = certificate?.expiresAt ? formatDate(certificate.expiresAt) : "-";
	byId("tlsSummaryIssuer").textContent = certificate?.issuer || "-";
	const badge = byId("tlsStatusBadge");
	badge.className = `badge ${certificateStatusClass(certificate)}`;
	badge.textContent = certificate ? certificate.status : "Not configured";
	byId("tlsLastError").textContent = certificate?.lastError || "";
	byId("tlsLastError").classList.toggle("hidden", !certificate?.lastError);
	byId("renewAcmeCertificate").classList.toggle("hidden", certificate?.source !== "letsencrypt");
	byId("removeCertificate").classList.toggle("hidden", !certificate);

	const bootstrapState =
		data.listener.bootstrapTlsEnabled && !certificate
			? " A temporary self-signed bootstrap certificate is active until a managed certificate is installed."
			: "";
	const httpsState = data.listener.httpsEnabled
		? `HTTPS listener: internal port ${data.listener.httpsPort}, public port ${data.listener.publicHttpsPort}.${bootstrapState}`
		: "HTTPS listener is disabled. Set BG_HTTPS_ENABLED=true and restart BurrowGate before activating a certificate.";
	const httpState = data.listener.httpEnabled
		? ` HTTP listener: internal port ${data.listener.httpPort}, public port ${data.listener.publicHttpPort}.`
		: " HTTP is disabled; HTTP-01 issuance cannot work.";
	byId("tlsListenerNotice").textContent = `${httpsState}${httpState}`;

	const directory = byId("acmeDirectoryUrl").value;
	byId("acmeEnvironmentWarning").textContent = directory.includes("staging")
		? "Staging mode: the issued certificate will not be trusted by browsers. Use this while testing ACME integration."
		: "Production ACME directory selected. Failed or repeated orders can consume provider rate limits.";

	const events = data.events ?? [];
	byId("certificateEvents").innerHTML =
		events.length === 0
			? '<p class="muted">No certificate activity yet.</p>'
			: events
					.map(
						(event) =>
							`<div class="certificate-event"><span class="badge ${event.level === "error" ? "bad" : event.level === "warning" ? "warn" : "ok"}">${escapeHtml(event.level)}</span><div>${escapeHtml(event.message)}</div><time class="muted">${formatDate(event.createdAt)}</time></div>`,
					)
					.join("");
}

async function loadSiteTls(siteId = editingSiteId) {
	if (!siteId) return;
	if (activeSiteEditorTab === "tls") byId("siteTlsPanel").classList.remove("hidden");
	const data = await api(`/sites/${encodeURIComponent(siteId)}/tls`, {}, false);
	if (editingSiteId === siteId) renderTls(data);
}

async function saveTlsSettings(event) {
	event.preventDefault();
	if (!editingSiteId) return;
	const button = byId("saveTlsSettings");
	await runWithButton(button, async () => {
		const data = await api(
			`/sites/${encodeURIComponent(editingSiteId)}/tls`,
			{
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ mode: byId("tlsMode").value, forceHttps: byId("tlsForceHttps").checked }),
			},
			false,
		);
		renderTls(data);
		showToast("HTTPS settings saved.");
	});
}

async function requestAcmeCertificate(event) {
	event.preventDefault();
	if (!editingSiteId) return;
	const button = byId("requestAcmeCertificate");
	await runWithButton(button, async () => {
		const data = await api(
			`/sites/${encodeURIComponent(editingSiteId)}/certificate/letsencrypt`,
			{
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					email: byId("acmeEmail").value.trim(),
					directoryUrl: byId("acmeDirectoryUrl").value.trim(),
					forceHttps: byId("acmeForceHttps").checked,
					termsAccepted: byId("acmeTermsAccepted").checked,
				}),
			},
			false,
		);
		renderTls(data);
		byId("acmeTermsAccepted").checked = false;
		showToast("Certificate issued and HTTPS listener reloaded.");
	});
}

async function uploadCertificate(event) {
	event.preventDefault();
	if (!editingSiteId) return;
	const button = byId("uploadCertificate");
	await runWithButton(button, async () => {
		const data = await api(
			`/sites/${encodeURIComponent(editingSiteId)}/certificate/upload`,
			{
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					certificatePem: byId("uploadedCertificatePem").value,
					privateKeyPem: byId("uploadedPrivateKeyPem").value,
					forceHttps: byId("uploadedForceHttps").checked,
				}),
			},
			false,
		);
		renderTls(data);
		byId("uploadedCertificatePem").value = "";
		byId("uploadedPrivateKeyPem").value = "";
		showToast("Certificate uploaded and activated.");
	});
}

async function renewAcmeCertificate() {
	if (!editingSiteId) return;
	const button = byId("renewAcmeCertificate");
	await runWithButton(button, async () => {
		const data = await api(`/sites/${encodeURIComponent(editingSiteId)}/certificate/renew`, { method: "POST" }, false);
		renderTls(data);
		showToast("Certificate renewed.");
	});
}

async function removeCertificate() {
	if (!editingSiteId || !confirm("Remove this site's certificate and disable HTTPS for it?")) return;
	const button = byId("removeCertificate");
	await runWithButton(button, async () => {
		const data = await api(`/sites/${encodeURIComponent(editingSiteId)}/certificate`, { method: "DELETE" }, false);
		renderTls(data);
		showToast("Certificate removed.");
	});
}

function chartTheme() {
	const styles = getComputedStyle(document.documentElement);
	const value = (name, fallback) => styles.getPropertyValue(name).trim() || fallback;
	return {
		grid: value("--chart-grid", "#273244"),
		text: value("--chart-text", "#94a3b8"),
		palette: [
			value("--chart-requests", "#8b5cf6"),
			value("--chart-blocked", "#f97316"),
			value("--chart-errors", "#f43f5e"),
			value("--chart-latency", "#22d3ee"),
			value("--chart-series-5", "#22c55e"),
			value("--chart-series-6", "#eab308"),
			value("--chart-series-7", "#ec4899"),
			value("--chart-series-8", "#64748b"),
		],
	};
}

function metricLabel(bucket, rangeDurationMs, detailed = false) {
	const date = new Date(Number(bucket));
	if (detailed) return formatDate(date);
	if (Number(rangeDurationMs) >= 24 * 3_600_000) {
		return date.toLocaleString([], {
			month: "short",
			day: "numeric",
			hour: "2-digit",
			minute: "2-digit",
			hour12: dateTimeFormat === "browser" ? undefined : dateTimeFormat === "mdy-12",
		});
	}
	return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: dateTimeFormat === "browser" ? undefined : dateTimeFormat === "mdy-12" });
}

function metricValueFormatter(format) {
	if (format === "duration") return (value) => formatDuration(Number(value));
	if (format === "bytes") return (value) => formatBytes(Number(value));
	if (format === "bitrate") return (value) => formatBitrate(Number(value));
	if (format === "percentage") return (value) => `${Number(value).toFixed(1)}%`;
	return (value) => formatNumber(Math.round(Number(value)));
}

function chartColor(key, index, theme) {
	const semantic = {
		requests: 0,
		hits: 0,
		misses: 1,
		bypasses: 3,
		hitRatio: 4,
		clean: 4,
		monitored: 1,
		created: 0,
		verified: 0,
		allow: 4,
		active: 4,
		averageLatency: 3,
		avgLatencyMs: 3,
		minLatencyMs: 4,
		maxLatencyMs: 2,
		timeoutPct: 2,
		bypassed: 3,
		challenge: 1,
		challenged: 1,
		expired: 1,
		blocked: 2,
		block: 2,
		revoked: 2,
		errors: 2,
		rateLimited: 5,
	};
	return theme.palette[semantic[key] ?? index % theme.palette.length];
}

function lineDataset(definition, index, points, theme) {
	const color = chartColor(definition.key, index, theme);
	return {
		label: definition.label,
		data: points.map((point) => Number(point[definition.key] ?? 0)),
		borderColor: color,
		backgroundColor: color,
		pointBackgroundColor: color,
		pointBorderColor: color,
		borderWidth: 2,
		pointRadius: 0,
		pointHoverRadius: 4,
		pointHitRadius: 16,
		tension: 0.25,
		fill: false,
	};
}

function barDataset(definition, index, points, theme, datasetCount) {
	const color = chartColor(definition.key, index, theme);
	return {
		label: definition.label,
		data: points.map((point) => Number(point[definition.key] ?? 0)),
		backgroundColor: datasetCount === 1 ? points.map((_, pointIndex) => theme.palette[pointIndex % theme.palette.length]) : color,
		borderColor: datasetCount === 1 ? points.map((_, pointIndex) => theme.palette[pointIndex % theme.palette.length]) : color,
		borderWidth: 1,
		borderRadius: 5,
		maxBarThickness: 52,
	};
}

function chartOptions(definition, formatter) {
	const theme = chartTheme();
	const showLegend = definition.datasets.length > 1;
	return {
		responsive: true,
		resizeDelay: 150,
		animation: false,
		normalized: true,
		interaction: { mode: definition.timeSeries ? "index" : "nearest", intersect: false },
		plugins: {
			legend: {
				display: showLegend,
				position: "bottom",
				labels: {
					color: theme.text,
					usePointStyle: true,
					pointStyle: definition.type === "line" ? "line" : "rectRounded",
					boxWidth: 18,
					boxHeight: 3,
					padding: 18,
				},
			},
			tooltip: {
				enabled: true,
				mode: definition.timeSeries ? "index" : "nearest",
				intersect: false,
				callbacks: {
					title(items) {
						const item = items[0];
						const point = definition.data[item.dataIndex];
						if (definition.timeSeries && point?.bucket !== undefined) {
							return metricLabel(point.bucket, Number(latestMetrics?.rangeDurationMs ?? selectedRangeTo - selectedRangeFrom), true);
						}
						return String(point?.label ?? item.label ?? "");
					},
					label(context) {
						return `${context.dataset.label}: ${formatter(context.parsed.y)}`;
					},
				},
			},
		},
		scales: {
			x: {
				grid: { display: false },
				border: { color: theme.grid },
				ticks: {
					color: theme.text,
					autoSkip: true,
					maxRotation: 0,
					minRotation: 0,
					maxTicksLimit: definition.timeSeries && Number(latestMetrics?.rangeDurationMs ?? selectedRangeTo - selectedRangeFrom) <= 3_600_000 ? 6 : 8,
				},
			},
			y: {
				beginAtZero: true,
				grid: { color: theme.grid },
				border: { display: false },
				ticks: {
					color: theme.text,
					precision: definition.valueFormat === "number" ? 0 : undefined,
					callback(value) {
						return formatter(value);
					},
				},
			},
		},
	};
}

function normalizeChartDefinition(definition) {
	const normalized = {
		...definition,
		datasets: [...(definition.datasets ?? [])],
		data: (definition.data ?? []).map((point) => ({ ...point })),
	};

	if (normalized.datasets.length === 0) {
		normalized.datasets.push({ key: "value", label: "No data" });
	}

	if (normalized.data.length === 0) {
		if (normalized.timeSeries) {
			const bucketMs = Number(latestMetrics?.bucketMs ?? 60_000);
			const bucketCount = Math.max(1, Number(latestMetrics?.bucketCount ?? 1));
			const endBucket = Math.floor(selectedRangeTo / bucketMs) * bucketMs;
			normalized.data = Array.from({ length: bucketCount }, (_, index) => ({
				bucket: endBucket - (bucketCount - index - 1) * bucketMs,
			}));
		} else {
			normalized.data = [{ label: "No data" }];
		}
	}

	for (const point of normalized.data) {
		for (const dataset of normalized.datasets) {
			if (!Number.isFinite(Number(point[dataset.key]))) point[dataset.key] = 0;
		}
	}

	return normalized;
}

const dateRangeSelectionPlugin = {
	id: "burrowgateDateRangeSelection",
	afterDatasetsDraw(chart) {
		const selection = chart.$dateRangeSelection;
		if (!selection?.dragging) return;
		const { ctx, chartArea } = chart;
		const left = Math.max(chartArea.left, Math.min(selection.startX, selection.currentX));
		const right = Math.min(chartArea.right, Math.max(selection.startX, selection.currentX));
		ctx.save();
		ctx.fillStyle = "rgba(139, 92, 246, 0.18)";
		ctx.strokeStyle = "rgba(167, 139, 250, 0.9)";
		ctx.lineWidth = 1;
		ctx.fillRect(left, chartArea.top, Math.max(0, right - left), chartArea.bottom - chartArea.top);
		ctx.strokeRect(left + 0.5, chartArea.top + 0.5, Math.max(0, right - left - 1), chartArea.bottom - chartArea.top - 1);
		ctx.restore();
	},
};

function attachDateRangeSelection(chart, definition) {
	const canvas = chart.canvas;
	canvas.$dateRangeCleanup?.();
	canvas.parentElement?.classList.toggle("time-selectable", Boolean(definition.timeSeries));
	if (!definition.timeSeries || definition.data.length < 2) return;

	const selection = { dragging: false, startX: 0, currentX: 0, pointerId: null };
	chart.$dateRangeSelection = selection;
	const canvasX = (event) => {
		const rect = canvas.getBoundingClientRect();
		return (event.clientX - rect.left) * (chart.width / rect.width);
	};
	const insidePlot = (x, y) => {
		const rect = canvas.getBoundingClientRect();
		const scaledY = (y - rect.top) * (chart.height / rect.height);
		return x >= chart.chartArea.left && x <= chart.chartArea.right && scaledY >= chart.chartArea.top && scaledY <= chart.chartArea.bottom;
	};
	const stop = () => {
		selection.dragging = false;
		selection.pointerId = null;
		chart.draw();
	};

	const pointerDown = (event) => {
		if (event.button !== 0) return;
		const x = canvasX(event);
		if (!insidePlot(x, event.clientY)) return;
		selection.dragging = true;
		selection.startX = x;
		selection.currentX = x;
		selection.pointerId = event.pointerId;
		canvas.setPointerCapture?.(event.pointerId);
		event.preventDefault();
		chart.draw();
	};
	const pointerMove = (event) => {
		if (!selection.dragging || selection.pointerId !== event.pointerId) return;
		selection.currentX = canvasX(event);
		event.preventDefault();
		chart.draw();
	};
	const pointerUp = (event) => {
		if (!selection.dragging || selection.pointerId !== event.pointerId) return;
		selection.currentX = canvasX(event);
		const distance = Math.abs(selection.currentX - selection.startX);
		if (distance < 8) {
			stop();
			return;
		}
		const scale = chart.scales.x;
		const left = Math.max(chart.chartArea.left, Math.min(selection.startX, selection.currentX));
		const right = Math.min(chart.chartArea.right, Math.max(selection.startX, selection.currentX));
		const startIndex = Math.max(0, Math.min(definition.data.length - 1, Math.floor(Number(scale.getValueForPixel(left)))));
		const endIndex = Math.max(startIndex, Math.min(definition.data.length - 1, Math.ceil(Number(scale.getValueForPixel(right)))));
		const bucketMs = Number(latestMetrics?.bucketMs ?? 60_000);
		const from = Math.max(selectedRangeFrom, Number(definition.data[startIndex]?.bucket ?? selectedRangeFrom));
		const to = Math.min(selectedRangeTo, Number(definition.data[endIndex]?.bucket ?? selectedRangeTo) + bucketMs);
		stop();
		if (to - from >= 60_000 && (from !== selectedRangeFrom || to !== selectedRangeTo)) {
			void applyDateRangeValues(from, to, "Graph selection applied").catch((error) => showToast(error.message, "bad"));
		}
	};
	const pointerCancel = () => stop();
	canvas.addEventListener("pointerdown", pointerDown);
	canvas.addEventListener("pointermove", pointerMove);
	canvas.addEventListener("pointerup", pointerUp);
	canvas.addEventListener("pointercancel", pointerCancel);
	canvas.$dateRangeCleanup = () => {
		canvas.removeEventListener("pointerdown", pointerDown);
		canvas.removeEventListener("pointermove", pointerMove);
		canvas.removeEventListener("pointerup", pointerUp);
		canvas.removeEventListener("pointercancel", pointerCancel);
	};
}

function createChart(canvasId, definition) {
	if (!window.Chart) throw new Error("Chart.js failed to load");
	const theme = chartTheme();
	const formatter = metricValueFormatter(definition.valueFormat);
	const labels = definition.data.map((point) =>
		definition.timeSeries
			? metricLabel(point.bucket, Number(latestMetrics?.rangeDurationMs ?? selectedRangeTo - selectedRangeFrom))
			: String(point.label ?? ""),
	);
	const datasets = definition.datasets.map((dataset, index) =>
		definition.type === "bar"
			? barDataset(dataset, index, definition.data, theme, definition.datasets.length)
			: lineDataset(dataset, index, definition.data, theme),
	);
	const chart = new window.Chart(byId(canvasId), {
		type: definition.type,
		data: { labels, datasets },
		options: chartOptions(definition, formatter),
		plugins: [dateRangeSelectionPlugin],
	});
	attachDateRangeSelection(chart, definition);
	return chart;
}

function summarizeChartDefinition(definition) {
	if (!definition?.datasets?.length || !definition.data?.length) return [];
	if (definition.datasets.length === 1 && !definition.timeSeries) {
		const [dataset] = definition.datasets;
		return definition.data.map((point) => ({ label: String(point.label ?? ""), count: Number(point[dataset.key] ?? 0) }));
	}
	const useAverage = definition.valueFormat === "duration";
	return definition.datasets.map((dataset) => {
		const values = definition.data.map((point) => Number(point[dataset.key] ?? 0));
		const total = values.reduce((sum, value) => sum + value, 0);
		return { label: dataset.label, count: useAverage ? total / values.length : total };
	});
}

function renderSummaryList(containerId, items, formatter = formatNumber) {
	const container = byId(containerId);
	if (!items || items.length === 0) {
		container.innerHTML = "";
		return;
	}
	const max = Math.max(0, ...items.map((item) => Number(item.count) || 0));
	if (max === 0) {
		container.innerHTML = '<p class="muted">No summary data is available.</p>';
		return;
	}
	container.innerHTML = items
		.slice(0, 6)
		.map((item) => {
			const percentage = Math.max(1, (Number(item.count) / max) * 100);
			return `<div class="breakdown-row"><div class="row between"><span>${escapeHtml(item.label)}</span><strong>${formatter(item.count)}</strong></div><div class="breakdown-track"><div style="width:${percentage}%"></div></div></div>`;
		})
		.join("");
}

function parseChartViewKey(key) {
	const [section, slot, bitrate] = key.split(":");
	return { section, slot, isBitrate: bitrate === "bitrate" };
}

async function fetchSectionMetrics(section) {
	return api(`/metrics?${queryString({ ...rangeQuery(), section })}`, {}, section !== "sites");
}

let chartViewRequestId = 0;

async function refreshChartView() {
	const requestId = ++chartViewRequestId;
	const { section, slot, isBitrate } = parseChartViewKey(chartViewSelection);
	let metrics = latestMetrics;
	if (section !== latestMetrics?.section) {
		try {
			metrics = await fetchSectionMetrics(section);
		} catch (error) {
			if (requestId !== chartViewRequestId) return;
			showToast(error.message, "bad");
			chartViewSelection = `${activeTab}:primary`;
			byId("chartView").value = chartViewSelection;
			metrics = latestMetrics;
		}
	}
	if (requestId !== chartViewRequestId || !metrics) return;

	const definition = normalizeChartDefinition(metrics[slot] ?? metrics.primary);
	const display = isBitrate ? bytesDefinitionToBitrate(definition, metrics.bucketMs) : definition;
	const select = byId("chartView");
	byId("primaryChartTitle").textContent = select.selectedOptions[0]?.textContent ?? display.title;
	byId("primaryChartSubtitle").textContent = display.subtitle;
	byId("trafficEmpty").classList.add("hidden");
	byId("trafficChart").classList.remove("hidden");

	trafficChart?.destroy();
	trafficChart = createChart("trafficChart", display);
	const showExplicitBreakdown = slot === "secondary" && metrics.breakdown?.length;
	const summaryItems = showExplicitBreakdown ? metrics.breakdown : summarizeChartDefinition(display);
	renderSummaryList("primarySummary", summaryItems, showExplicitBreakdown ? formatNumber : metricValueFormatter(display.valueFormat));
}

function renderMetrics() {
	if (!latestMetrics) return;
	if (latestMetrics.section === "bandwidth") renderBandwidthDetails(latestMetrics);
	if (latestMetrics.section === "cache") renderCacheDetails(latestMetrics.cache);
	if (latestMetrics.section === "protection") renderProtectionDetails(latestMetrics);
	void refreshChartView();
}

function renderCacheDetails(cache) {
	const totals = cache?.totals ?? {};
	byId("cacheHistoryHitRatio").textContent = `${(Number(totals.hitRatio ?? 0) * 100).toFixed(2)}%`;
	byId("cacheHistoryLookups").textContent = `${formatNumber(totals.hits)} / ${formatNumber(totals.misses)}`;
	byId("cacheHistoryBypasses").textContent = formatNumber(totals.bypasses);
	byId("cacheHistoryAvoided").textContent = formatNumber(totals.originRequestsAvoided);
	const paths = cache?.topPaths ?? [];
	byId("cacheTopPaths").innerHTML =
		paths.length === 0
			? '<tr><td colspan="5" class="empty-cell">No cache activity exists in this range.</td></tr>'
			: paths
					.map(
						(item) => `<tr>
			<td class="path-cell" title="${escapeHtml(item.path)}">${escapeHtml(truncate(item.path, 100))}</td>
			<td>${formatNumber(item.hits)}</td>
			<td>${formatNumber(item.misses)}</td>
			<td>${formatNumber(item.bypasses)}</td>
			<td>${(Number(item.hitRatio ?? 0) * 100).toFixed(2)}%</td>
		</tr>`,
					)
					.join("");
}

function renderProtectionDetails(metrics) {
	const protection = metrics?.protection ?? {};
	const totals = protection.totals ?? {};
	byId("protectionInspected").textContent = formatNumber(totals.inspected);
	byId("protectionMonitored").textContent = formatNumber(totals.monitored);
	byId("protectionBlocked").textContent = formatNumber(totals.blocked);
	byId("protectionRuleCount").textContent = formatNumber(protection.topRules?.length ?? 0);
	const configured = sites.find((site) => site.id === selectedSiteId)?.http?.protection;
	const catalog = metrics.rulesets ?? managedProtection;
	const selectedRuleSetId = configured?.rulesetId === "default" || !configured?.rulesetId ? catalog.defaultRuleSetId : configured.rulesetId;
	const ruleSet = catalog.items?.find((item) => item.id === selectedRuleSetId);
	const mode = configured?.mode ?? "monitor";
	byId("protectionRulesetSummary").innerHTML = ruleSet
		? `<div class="row responsive"><span class="badge ${mode === "block" ? "bad" : mode === "monitor" ? "info" : "warn"}">${escapeHtml(mode)}</span><strong>${escapeHtml(ruleSet.title)} ${escapeHtml(ruleSet.version)}</strong><span class="muted">${escapeHtml(ruleSet.description)}</span></div>`
		: '<p class="muted">No managed ruleset metadata is available.</p>';
	const rules = protection.topRules ?? [];
	byId("protectionTopRules").innerHTML =
		rules.length === 0
			? '<tr><td colspan="6" class="empty-cell">No managed protection rules matched in this range.</td></tr>'
			: rules
					.map(
						(rule) => `<tr>
			<td><code>${escapeHtml(rule.ruleId)}</code></td>
			<td>${escapeHtml(rule.category)}</td>
			<td><span class="badge ${rule.severity === "critical" || rule.severity === "high" ? "bad" : rule.severity === "medium" ? "warn" : "info"}">${escapeHtml(rule.severity)}</span></td>
			<td>${formatNumber(rule.monitored)}</td>
			<td>${formatNumber(rule.blocked)}</td>
			<td>${formatNumber(rule.count)}</td>
		</tr>`,
					)
					.join("");
}

function renderBandwidthDetails(metrics) {
	const totals = (metrics.primary?.data ?? []).reduce(
		(result, point) => {
			for (const key of ["clientUpload", "clientDownload", "upstreamUpload", "upstreamDownload"]) result[key] += Number(point[key] ?? 0);
			return result;
		},
		{ clientUpload: 0, clientDownload: 0, upstreamUpload: 0, upstreamDownload: 0 },
	);
	byId("bandwidthClientDownload").textContent = formatBytes(totals.clientDownload);
	byId("bandwidthClientUpload").textContent = formatBytes(totals.clientUpload);
	byId("bandwidthUpstreamDownload").textContent = formatBytes(totals.upstreamDownload);
	byId("bandwidthUpstreamUpload").textContent = formatBytes(totals.upstreamUpload);

	const protocols = metrics.protocols ?? [];
	byId("bandwidthProtocols").innerHTML =
		protocols.length === 0
			? ""
			: protocols
					.map(
						(item) =>
							`<div class="breakdown-row"><div class="row between"><span>${escapeHtml(item.protocol === "websocket" ? "WebSocket" : "HTTP")}</span><strong>${formatBytes(item.clientBytes)} client / ${formatBytes(item.upstreamBytes)} upstream</strong></div></div>`,
					)
					.join("");
}

async function loadMetrics() {
	const section = activeTab;
	try {
		const result = await api(
			`/metrics?${queryString({
				...rangeQuery(),
				section,
			})}`,
			{},
			section !== "sites",
		);
		if (activeTab !== section) return;
		latestMetrics = result;
		renderMetrics();
	} catch (error) {
		showToast(error.message, "bad");
	}
}

function countryDisplayName(code, fallback = "") {
	if (code === "ZZ") return "Unknown";
	if (code === "XX") return "Local / private network";
	try {
		return new Intl.DisplayNames(["en"], { type: "region" }).of(code) ?? (fallback || code);
	} catch {
		return fallback || code;
	}
}

function populateCountrySelects() {
	if (!geoMapGeometry) return;
	const countries = [...geoMapGeometry.paths.entries()]
		.map(([code, path]) => ({ code, name: path.dataset.name || countryDisplayName(code) }))
		.sort((left, right) => left.name.localeCompare(right.name));
	countries.push({ code: "ZZ", name: "Unknown / unmapped" }, { code: "XX", name: "Local / private network" });
	const configurations = [
		["eventCountry", "All countries"],
		["bandwidthCountry", "All countries"],
		["sessionCountry", "All countries"],
		["countryRuleCountry", "Select country"],
		["routeCountryRuleCountry", "Select country"],
	];
	for (const [id, emptyLabel] of configurations) {
		const select = byId(id);
		if (!select) continue;
		const current = select.value;
		select.innerHTML = `<option value="">${emptyLabel}</option>${countries.map((country) => `<option value="${country.code}">${escapeHtml(country.name)} (${country.code})</option>`).join("")}`;
		if ([...select.options].some((option) => option.value === current)) select.value = current;
	}
}

function geoLevel(value, maximum) {
	if (value <= 0 || maximum <= 0) return 0;
	return Math.max(1, Math.min(5, Math.ceil((Math.log1p(value) / Math.log1p(maximum)) * 5)));
}

function positionGeoTooltip(event, content) {
	const tooltip = byId("geoTooltip");
	const wrapper = tooltip.parentElement;
	const rect = wrapper.getBoundingClientRect();
	tooltip.innerHTML = content;
	tooltip.classList.remove("hidden");
	const x = event?.clientX ? event.clientX - rect.left + 12 : 16;
	const y = event?.clientY ? event.clientY - rect.top + 12 : 16;
	tooltip.style.left = `${Math.min(Math.max(8, x), Math.max(8, rect.width - 190))}px`;
	tooltip.style.top = `${Math.min(Math.max(8, y), Math.max(8, rect.height - 70))}px`;
}

function hideGeoTooltip() {
	byId("geoTooltip").classList.add("hidden");
}

function parseGeoViewBox(svg) {
	const [x, y, width, height] = (svg.getAttribute("viewBox") ?? "0 0 1010 666").split(/\s+/).map(Number);
	return { x, y, width, height };
}

function clampGeoZoom() {
	const { base, current } = geoZoom;
	current.width = Math.min(base.width, Math.max(base.width / GEO_ZOOM_MAX_SCALE, current.width));
	current.height = current.width * (base.height / base.width);
	current.x = Math.min(base.x + base.width - current.width, Math.max(base.x, current.x));
	current.y = Math.min(base.y + base.height - current.height, Math.max(base.y, current.y));
}

function applyGeoZoom() {
	const { base, current } = geoZoom;
	byId("geoMap").setAttribute("viewBox", `${current.x} ${current.y} ${current.width} ${current.height}`);
	const zoomed = current.width < base.width - 0.5;
	byId("geoMapWrap").classList.toggle("geo-zoomed", zoomed);
	byId("geoZoomOut").disabled = !zoomed;
	byId("geoZoomReset").disabled = !zoomed;
	byId("geoZoomIn").disabled = current.width <= base.width / GEO_ZOOM_MAX_SCALE + 0.5;
}

function zoomGeoMapAt(clientX, clientY, factor) {
	const svg = byId("geoMap");
	const rect = svg.getBoundingClientRect();
	if (!rect.width || !rect.height) return;
	const { current } = geoZoom;
	const pointX = current.x + ((clientX - rect.left) / rect.width) * current.width;
	const pointY = current.y + ((clientY - rect.top) / rect.height) * current.height;
	const newWidth = current.width * factor;
	const scaleChange = newWidth / current.width;
	current.width = newWidth;
	current.height = newWidth * (geoZoom.base.height / geoZoom.base.width);
	current.x = pointX - (pointX - current.x) * scaleChange;
	current.y = pointY - (pointY - current.y) * scaleChange;
	clampGeoZoom();
	applyGeoZoom();
}

function panGeoMap(deltaClientX, deltaClientY) {
	const svg = byId("geoMap");
	const rect = svg.getBoundingClientRect();
	if (!rect.width || !rect.height) return;
	const { current } = geoZoom;
	current.x -= (deltaClientX / rect.width) * current.width;
	current.y -= (deltaClientY / rect.height) * current.height;
	clampGeoZoom();
	applyGeoZoom();
}

function resetGeoZoom() {
	geoZoom.current = { ...geoZoom.base };
	applyGeoZoom();
}

function setupGeoMapZoom(svg) {
	geoZoom = { base: parseGeoViewBox(svg), current: parseGeoViewBox(svg) };
	applyGeoZoom();

	const wrap = byId("geoMapWrap");
	wrap.addEventListener(
		"wheel",
		(event) => {
			event.preventDefault();
			zoomGeoMapAt(event.clientX, event.clientY, event.deltaY < 0 ? 0.85 : 1 / 0.85);
		},
		{ passive: false },
	);

	let dragPointerId = null;
	let lastX = 0;
	let lastY = 0;
	svg.addEventListener("pointerdown", (event) => {
		if (event.button !== 0) return;
		dragPointerId = event.pointerId;
		lastX = event.clientX;
		lastY = event.clientY;
		svg.setPointerCapture(dragPointerId);
	});
	svg.addEventListener("pointermove", (event) => {
		if (event.pointerId !== dragPointerId) return;
		const deltaX = event.clientX - lastX;
		const deltaY = event.clientY - lastY;
		if (Math.abs(deltaX) < 1 && Math.abs(deltaY) < 1) return;
		hideGeoTooltip();
		panGeoMap(deltaX, deltaY);
		lastX = event.clientX;
		lastY = event.clientY;
	});
	const endGeoDrag = (event) => {
		if (event.pointerId !== dragPointerId) return;
		if (svg.hasPointerCapture(dragPointerId)) svg.releasePointerCapture(dragPointerId);
		dragPointerId = null;
	};
	svg.addEventListener("pointerup", endGeoDrag);
	svg.addEventListener("pointercancel", endGeoDrag);
	svg.addEventListener("dblclick", (event) => {
		event.preventDefault();
		zoomGeoMapAt(event.clientX, event.clientY, event.shiftKey ? 2 : 0.5);
	});

	byId("geoZoomIn").addEventListener("click", () => {
		const rect = svg.getBoundingClientRect();
		zoomGeoMapAt(rect.left + rect.width / 2, rect.top + rect.height / 2, 0.7);
	});
	byId("geoZoomOut").addEventListener("click", () => {
		const rect = svg.getBoundingClientRect();
		zoomGeoMapAt(rect.left + rect.width / 2, rect.top + rect.height / 2, 1 / 0.7);
	});
	byId("geoZoomReset").addEventListener("click", resetGeoZoom);
}

function renderGeoMap() {
	if (!geoMapGeometry || !geoMetrics) return;
	const config = geoConfigForScope(geoScopeSelection);
	const items = geoMetrics.items ?? [];
	const rangeDurationMs = geoMetrics.rangeDurationMs;
	const status = geoMetrics.status;
	const isBandwidth = config.unit === "bytes";
	const unit = config.unit;
	const metricTitle = config.label;
	const formatValue = isBandwidth ? formatBytes : formatNumber;
	const values = new Map(items.map((item) => [String(item.countryCode).toUpperCase(), Number(item.count)]));
	const maximum = Math.max(0, ...items.filter((item) => item.countryCode !== "ZZ" && item.countryCode !== "XX").map((item) => Number(item.count)));
	const total = items.reduce((sum, item) => sum + Number(item.count), 0);
	const rangeLabel = rangeDurationLabel(rangeDurationMs ?? selectedRangeTo - selectedRangeFrom);
	byId("geoSubtitle").textContent = `${metricTitle} by country (${rangeLabel})`;
	byId("geoTotal").textContent = isBandwidth ? formatBytes(total) : `${formatNumber(total)} ${unit}`;

	const svg = byId("geoMap");
	svg.setAttribute("aria-label", `World map showing ${unit} by country`);
	for (const [code, path] of geoMapGeometry.paths) {
		const value = values.get(code) ?? 0;
		const name = path.dataset.name ?? countryDisplayName(code);
		path.setAttribute("class", `geo-country geo-level-${geoLevel(value, maximum)}`);
		path.setAttribute("tabindex", value > 0 ? "0" : "-1");
		path.setAttribute("aria-label", `${name}: ${formatValue(value)}${isBandwidth ? "" : ` ${unit}`}`);
		path.dataset.value = String(value);
		path.dataset.unit = unit;
	}

	const sorted = [...items].sort((a, b) => Number(b.count) - Number(a.count));
	byId("geoCountryList").innerHTML =
		sorted.length === 0
			? '<p class="muted">No geographic data is available for this range.</p>'
			: sorted
					.slice(0, 10)
					.map((item) => {
						const code = String(item.countryCode).toUpperCase();
						const name = countryDisplayName(code);
						const percentage = total > 0 ? (Number(item.count) / total) * 100 : 0;
						return `<div class="geo-country-row"><div class="row between"><span><code>${escapeHtml(code)}</code> ${escapeHtml(name)}</span><strong>${formatValue(item.count)}</strong></div><div class="breakdown-track"><div style="width:${Math.max(1, percentage)}%"></div></div></div>`;
					})
					.join("");

	if (!status?.enabled) {
		byId("geoMapStatus").textContent = "GeoIP is disabled.";
		byId("geoMapStatus").classList.remove("hidden");
	} else if (!status.available) {
		byId("geoMapStatus").textContent = status.error ?? "GeoIP database is unavailable.";
		byId("geoMapStatus").classList.remove("hidden");
	} else {
		byId("geoMapStatus").classList.add("hidden");
	}
}

async function loadGeoMapGeometry() {
	if (geoMapGeometry) return;
	const response = await fetch("/_burrowgate/static/world.svg?v=2.0.0", { cache: "force-cache" });
	if (!response.ok) throw new Error("Unable to load world map");
	const documentNode = new DOMParser().parseFromString(await response.text(), "image/svg+xml");
	const sourceRoot = documentNode.documentElement;
	if (sourceRoot.nodeName.toLowerCase() === "parsererror") throw new Error("Invalid world map SVG");

	const svg = byId("geoMap");
	svg.setAttribute("viewBox", sourceRoot.getAttribute("viewBox") ?? "0 0 1010 666");
	svg.setAttribute("preserveAspectRatio", "xMidYMid meet");
	const fragment = document.createDocumentFragment();
	const paths = new Map();
	for (const sourcePath of sourceRoot.querySelectorAll("path")) {
		const code = String(sourcePath.id ?? "").toUpperCase();
		const data = sourcePath.getAttribute("d") ?? "";
		if (!code || !data) continue;
		const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
		const name = countryDisplayName(code, sourcePath.getAttribute("aria-label") ?? code);
		path.setAttribute("d", data);
		path.setAttribute("class", "geo-country geo-level-0");
		path.setAttribute("tabindex", "-1");
		path.dataset.code = code;
		path.dataset.name = name;
		path.dataset.value = "0";
		path.dataset.unit = "requests";
		const show = (event) =>
			positionGeoTooltip(
				event,
				`<strong>${escapeHtml(path.dataset.name)}</strong><span>${path.dataset.unit === "bytes" ? formatBytes(path.dataset.value) : `${formatNumber(path.dataset.value)} ${escapeHtml(path.dataset.unit)}`}</span>`,
			);
		path.addEventListener("pointerenter", show);
		path.addEventListener("pointermove", show);
		path.addEventListener("pointerleave", hideGeoTooltip);
		path.addEventListener("focus", show);
		path.addEventListener("blur", hideGeoTooltip);
		paths.set(code, path);
		fragment.append(path);
	}
	svg.replaceChildren(fragment);
	geoMapGeometry = { paths };
	populateCountrySelects();
	setupGeoMapZoom(svg);
}

async function loadGeoMetrics() {
	const requestId = ++geoRequestId;
	const config = geoConfigForScope(geoScopeSelection);
	await loadGeoMapGeometry();
	const result = await api(`/geo-metrics-tab?scope=${config.geoScope}&${queryString(rangeQuery())}`);
	if (requestId !== geoRequestId) return;
	geoMetrics = result;
	renderGeoMap();
}

async function loadAsnMetrics() {
	const requestId = ++asnRequestId;
	const scope = asnScopeSelection === "bandwidth" ? "requests" : asnScopeSelection;
	const result = await api(`/asn-metrics-tab?scope=${scope}&${queryString(rangeQuery())}`);
	if (requestId !== asnRequestId) return;
	asnMetrics = result;
	renderAsnList();
}

function renderAsnList() {
	if (!asnMetrics) return;
	const config = geoConfigForScope(asnScopeSelection === "bandwidth" ? "requests" : asnScopeSelection);
	const items = asnMetrics.items ?? [];
	const total = items.reduce((sum, item) => sum + Number(item.count), 0);
	const rangeLabel = rangeDurationLabel(asnMetrics.rangeDurationMs ?? selectedRangeTo - selectedRangeFrom);
	byId("asnSubtitle").textContent = `${config.label} by network provider (${rangeLabel})`;
	byId("asnTotal").textContent = `${formatNumber(total)} ${config.unit}`;
	byId("asnList").innerHTML =
		items.length === 0
			? '<p class="muted">No ASN data is available for this range.</p>'
			: items
					.map((item) => {
						const label = item.asn ? `AS${item.asn} ${item.org ?? ""}`.trim() : item.org || "Unknown";
						const percentage = total > 0 ? (Number(item.count) / total) * 100 : 0;
						return `<div class="geo-country-row"><div class="row between"><span title="${escapeHtml(label)}">${escapeHtml(truncate(label, 60))}</span><strong>${formatNumber(item.count)}</strong></div><div class="breakdown-track"><div style="width:${Math.max(1, percentage)}%"></div></div></div>`;
					})
					.join("");
	const status = asnMetrics.status;
	if (!status?.asn?.enabled) byId("asnSubtitle").title = "The ASN database is disabled.";
	else if (!status.asn.available) byId("asnSubtitle").title = status.asn.error ?? "The ASN database is unavailable.";
	else byId("asnSubtitle").title = "";
}

const TOP_LIST_KIND = {
	referrers: {
		endpoint: (config) => `referer-metrics-tab?scope=${config.refererScope}`,
		title: "Top referrers",
		field: "referrers",
		itemKey: "refererHost",
		subtitle: (rangeLabel) => `External referring domains for the selected range (${rangeLabel})`,
		empty: "No external referrers in this range.",
		totalUnit: "requests",
	},
	usernames: {
		endpoint: (config) => (config.usernameSource === "sessions" ? "session-username-metrics" : "access-username-metrics"),
		title: "Top usernames",
		field: "usernames",
		itemKey: "username",
		subtitle: (rangeLabel) => `Most active usernames in the selected range (${rangeLabel})`,
		empty: "No activity in this range.",
		totalUnit: "events",
	},
	ips: {
		endpoint: (config) => `ip-metrics-tab?scope=${config.ipScope}`,
		title: "Top offending IPs",
		field: "ips",
		itemKey: "ip",
		subtitle: (rangeLabel) => `Source IPs generating the most activity in the selected range (${rangeLabel})`,
		empty: "No matching activity in this range.",
		totalUnit: "requests",
	},
	paths: {
		endpoint: (config) => `path-metrics-tab?scope=${config.pathScope}`,
		title: "Top targeted paths",
		field: "paths",
		itemKey: "path",
		subtitle: (rangeLabel) => `Paths generating the most activity in the selected range (${rangeLabel})`,
		empty: "No matching activity in this range.",
		totalUnit: "requests",
	},
	ipsBandwidth: {
		endpoint: () => "ip-bandwidth-metrics-tab",
		title: "Top IPs by bandwidth",
		field: "ips",
		itemKey: "ip",
		subtitle: (rangeLabel) => `Source IPs generating the most bandwidth in the selected range (${rangeLabel})`,
		empty: "No bandwidth activity in this range.",
		totalUnit: "bytes",
		formatCount: formatBytes,
	},
};

async function loadTopList() {
	const requestId = ++topListRequestId;
	const config = geoConfigForScope(topListScopeSelection);
	const kind = TOP_LIST_KIND[config.topList];
	const endpoint = kind.endpoint(config);
	const result = await api(`/${endpoint}${endpoint.includes("?") ? "&" : "?"}${queryString(rangeQuery())}`);
	if (requestId !== topListRequestId) return;
	topListData = result;
	renderRefererList();
}

async function refreshGeoAndReferrers() {
	await Promise.all([loadGeoMetrics(), loadTopList(), loadAsnMetrics()]);
}

function renderRefererList() {
	const config = geoConfigForScope(topListScopeSelection);
	if (config.topList === "none" || !topListData) return;
	const kind = TOP_LIST_KIND[config.topList];
	const items = topListData[kind.field] ?? [];
	const total = items.reduce((sum, item) => sum + Number(item.count), 0);
	const rangeLabel = rangeDurationLabel(topListData.rangeDurationMs ?? selectedRangeTo - selectedRangeFrom);
	const formatCount = kind.formatCount ?? formatNumber;
	byId("refererTitle").textContent = byId("topListMode").selectedOptions[0]?.textContent ?? kind.title;
	byId("refererSubtitle").textContent = kind.subtitle(rangeLabel);
	byId("refererTotal").textContent = kind.formatCount ? formatCount(total) : `${formatNumber(total)} ${kind.totalUnit}`;
	byId("refererList").innerHTML =
		items.length === 0
			? `<p class="muted">${kind.empty}</p>`
			: items
					.map((item) => {
						const label = String(item[kind.itemKey] ?? "");
						const percentage = total > 0 ? (Number(item.count) / total) * 100 : 0;
						return `<div class="geo-country-row"><div class="row between"><span title="${escapeHtml(label)}">${escapeHtml(truncate(label, 60))}</span><strong>${formatCount(item.count)}</strong></div><div class="breakdown-track"><div style="width:${Math.max(1, percentage)}%"></div></div></div>`;
					})
					.join("");
}

async function applyDateRangeValues(from, to, updateLabel = "Dashboard updated") {
	dateRangeIsAutomatic = false;
	setDateRangeInputs(from, to);
	persistDateRange();
	tableState.traffic.page = 1;
	tableState.bandwidth.page = 1;
	tableState.sessions.page = 1;
	const tasks = [loadOverview(), loadMetrics(), refreshGeoAndReferrers()];
	if (loadedTabs.has("traffic")) tasks.push(loadTraffic());
	if (loadedTabs.has("bandwidth")) tasks.push(loadBandwidth());
	if (loadedTabs.has("sessions")) tasks.push(loadSessions());
	await Promise.all(tasks);
	markUpdated(updateLabel);
}

function markUpdated(prefix = "Updated") {
	byId("lastUpdated").textContent = `${prefix} ${formatTime()}`;
}

async function runWithButton(button, task) {
	button.disabled = true;
	try {
		await task();
	} finally {
		button.disabled = false;
	}
}

async function refreshDashboard() {
	const tasks = [loadOverview(), loadMetrics(), refreshGeoAndReferrers()];
	if (activeTab === "traffic") tasks.push(loadTraffic());
	if (activeTab === "bandwidth") tasks.push(loadBandwidth());
	if (activeTab === "cache") tasks.push(loadCacheMetrics());
	if (activeTab === "sessions") tasks.push(loadSessions());
	if (activeTab === "rules") tasks.push(loadRules());
	if (activeTab === "routes") tasks.push(loadRoutePolicies());
	if (activeTab === "access") tasks.push(loadAccessList());
	if (activeTab === "sites") tasks.push(loadSites());
	await Promise.all(tasks);
	markUpdated();
}

function setActiveTab(name) {
	activeTab = name;
	document.querySelectorAll(".tab").forEach((tab) => tab.classList.toggle("active", tab.dataset.tab === name));
	document.querySelectorAll(".tab-panel").forEach((panel) => panel.classList.add("hidden"));
	byId(`panel-${name}`).classList.remove("hidden");
	chartViewSelection = `${name}:primary`;
	byId("chartView").value = chartViewSelection;
	geoScopeSelection = GEO_TAB_CONFIG[name].geoScope;
	byId("geoMetricMode").value = geoScopeSelection;
	if (GEO_TAB_CONFIG[name].topList !== "none") {
		topListScopeSelection = GEO_TAB_CONFIG[name].geoScope;
		byId("topListMode").value = topListScopeSelection;
	}
	if (GEO_TAB_CONFIG[name].geoScope !== "bandwidth") {
		asnScopeSelection = GEO_TAB_CONFIG[name].geoScope;
		byId("asnMetricMode").value = asnScopeSelection;
	}
	void refreshGeoAndReferrers();
	void loadMetrics();
	if (name === "cache") void loadCacheMetrics();
	if (loadedTabs.has(name)) return;
	loadedTabs.add(name);
	if (name === "traffic") void loadTraffic();
	if (name === "bandwidth") void loadBandwidth();
	if (name === "sessions") void loadSessions();
	if (name === "rules") void loadRules();
	if (name === "routes") void loadRoutePolicies();
	if (name === "access") void loadAccessList();
	if (name === "sites") void loadSites();
}

function bindSortButtons() {
	document.querySelectorAll(".sort-button").forEach((button) => {
		button.addEventListener("click", () => {
			const panel = button.closest(".tab-panel");
			const name = panel.id.replace("panel-", "");
			const state = tableState[name];
			const sortBy = button.dataset.sort;
			if (state.sortBy === sortBy) state.sortDirection = state.sortDirection === "asc" ? "desc" : "asc";
			else {
				state.sortBy = sortBy;
				state.sortDirection = ["network_cidr", "action", "last_ip", "ip", "country_code"].includes(sortBy) ? "asc" : "desc";
			}
			state.page = 1;
			if (name === "traffic") void loadTraffic();
			if (name === "bandwidth") void loadBandwidth();
			if (name === "sessions") void loadSessions();
			if (name === "rules") void loadRules();
		});
	});
}

function bindFilters() {
	const trafficSearch = debounce(() => {
		tableState.traffic.page = 1;
		void loadTraffic();
	});
	byId("eventSearch").addEventListener("input", trafficSearch);
	byId("eventAsn").addEventListener("input", trafficSearch);
	for (const id of ["eventDecision", "eventCacheStatus", "eventProtectionStatus", "eventMethod", "eventStatus", "eventOrigin", "eventCountry"]) {
		byId(id).addEventListener("change", () => {
			tableState.traffic.page = 1;
			void loadTraffic();
		});
	}
	byId("eventPageSize").addEventListener("change", () => {
		tableState.traffic.page = 1;
		tableState.traffic.pageSize = Number(byId("eventPageSize").value);
		void loadTraffic();
	});

	const bandwidthSearch = debounce(() => {
		tableState.bandwidth.page = 1;
		void loadBandwidth();
	});
	byId("bandwidthSearch").addEventListener("input", bandwidthSearch);
	for (const id of ["bandwidthProtocol", "bandwidthCountry"]) {
		byId(id).addEventListener("change", () => {
			tableState.bandwidth.page = 1;
			void loadBandwidth();
		});
	}
	byId("bandwidthPageSize").addEventListener("change", () => {
		tableState.bandwidth.page = 1;
		tableState.bandwidth.pageSize = Number(byId("bandwidthPageSize").value);
		void loadBandwidth();
	});

	const sessionSearch = debounce(() => {
		tableState.sessions.page = 1;
		void loadSessions();
	});
	byId("sessionSearch").addEventListener("input", sessionSearch);
	byId("sessionAsn").addEventListener("input", sessionSearch);
	for (const id of ["sessionState", "sessionCountry"])
		byId(id).addEventListener("change", () => {
			tableState.sessions.page = 1;
			void loadSessions();
		});
	byId("sessionPageSize").addEventListener("change", () => {
		tableState.sessions.page = 1;
		tableState.sessions.pageSize = Number(byId("sessionPageSize").value);
		void loadSessions();
	});

	const ruleSearch = debounce(() => {
		tableState.rules.page = 1;
		void loadRules();
	});
	byId("ruleSearch").addEventListener("input", ruleSearch);
	for (const id of ["ruleAction", "ruleState"]) {
		byId(id).addEventListener("change", () => {
			tableState.rules.page = 1;
			void loadRules();
		});
	}
	byId("rulePageSize").addEventListener("change", () => {
		tableState.rules.page = 1;
		tableState.rules.pageSize = Number(byId("rulePageSize").value);
		void loadRules();
	});
}

async function loadCurrentAdmin() {
	currentAdmin = await api("/me", {}, false);
	applyCurrentAdminVisibility();
	return currentAdmin;
}

function applyCurrentAdminVisibility() {
	const isAdministrator = currentAdmin?.role === "administrator";
	byId("openUsers").classList.toggle("hidden", !isAdministrator);
	byId("openAudit").classList.toggle("hidden", !isAdministrator);
	byId("openSso").classList.toggle("hidden", !isAdministrator);
}

function openModal(name) {
	byId(`modal-${name}`).classList.remove("hidden");
	document.body.classList.add("modal-open");
	if (name === "users") void loadUsers();
	if (name === "audit") void loadAuditLog();
	if (name === "account") void loadAccount();
	if (name === "sso") void loadAdminSso();
}

function closeModal(name) {
	byId(`modal-${name}`).classList.add("hidden");
	if (!document.querySelector(".modal-overlay:not(.hidden)")) document.body.classList.remove("modal-open");
	if (name === "users") {
		editingPermissionsUserId = null;
		byId("userPermissionsCard").classList.add("hidden");
	}
}

function closeAllModals() {
	document.querySelectorAll(".modal-overlay:not(.hidden)").forEach((overlay) => closeModal(overlay.dataset.modal));
}

function userPermissionsSummary(user) {
	if (user.role === "administrator") return "All sites and streams";
	const parts = [];
	if (user.sitePermissions.length) parts.push(`${user.sitePermissions.length} site${user.sitePermissions.length === 1 ? "" : "s"}`);
	if (user.streamPermissions.length) parts.push(`${user.streamPermissions.length} stream${user.streamPermissions.length === 1 ? "" : "s"}`);
	return parts.length ? parts.join(", ") : "None";
}

function renderUsers() {
	const rows = usersData.items
		.map(
			(user) => `<tr>
        <td>${escapeHtml(user.username)}</td>
        <td><span class="badge ${user.role === "administrator" ? "info" : ""}">${user.role === "administrator" ? "Administrator" : "Member"}</span></td>
        <td>${user.totpEnrolled || user.webauthnCredentialCount > 0 ? '<span class="badge ok">Enrolled</span>' : '<span class="badge warn">Pending</span>'}</td>
        <td>${user.enabled ? '<span class="badge ok">Enabled</span>' : '<span class="badge bad">Disabled</span>'}</td>
        <td>${escapeHtml(userPermissionsSummary(user))}</td>
        <td class="row-actions">
          ${user.role === "administrator" ? "" : `<button class="button secondary compact" data-user-permissions="${escapeHtml(user.id)}" type="button">Permissions</button>`}
          <button class="button secondary compact" data-user-reset-password="${escapeHtml(user.id)}" type="button">Reset password</button>
          <button class="button secondary compact" data-user-reset-totp="${escapeHtml(user.id)}" type="button">Reset 2FA</button>
          <button class="button danger compact" data-user-delete="${escapeHtml(user.id)}" type="button">Delete</button>
        </td>
      </tr>`,
		)
		.join("");
	byId("users").innerHTML = rows || '<tr><td colspan="6" class="empty-cell">No users yet.</td></tr>';
}

async function loadUsers() {
	setTableLoading("users", 6);
	try {
		usersData = await api("/users", {}, false);
		renderUsers();
	} catch (error) {
		setTableError("users", 6, error);
	}
}

async function createUser(event) {
	event.preventDefault();
	const form = event.currentTarget;
	const payload = Object.fromEntries(new FormData(form));
	try {
		await api("/users", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) }, false);
		form.reset();
		showToast("User created.");
		await loadUsers();
	} catch (error) {
		showToast(error.message, "bad");
	}
}

function permissionsGrid(id, resources, current, resourceKey) {
	const currentByResource = new Map(current.map((entry) => [entry[resourceKey], entry.level]));
	byId(id).innerHTML = resources.length
		? resources
				.map((resource) => {
					const level = currentByResource.get(resource.id) ?? "none";
					return `<label class="permission-row"><span>${escapeHtml(resource.label)}</span><select class="select" data-permission-resource="${escapeHtml(resource.id)}">
          <option value="none" ${level === "none" ? "selected" : ""}>None</option>
          <option value="viewer" ${level === "viewer" ? "selected" : ""}>Viewer</option>
          <option value="manager" ${level === "manager" ? "selected" : ""}>Manager</option>
        </select></label>`;
				})
				.join("")
		: '<p class="muted">None configured yet.</p>';
}

function openUserPermissions(userId) {
	const user = usersData.items.find((item) => item.id === userId);
	if (!user) return;
	editingPermissionsUserId = userId;
	byId("userPermissionsTitle").textContent = `Permissions for ${user.username}`;
	permissionsGrid(
		"userSitePermissions",
		usersData.sites.map((site) => ({ id: site.id, label: site.name })),
		user.sitePermissions,
		"siteId",
	);
	permissionsGrid(
		"userStreamPermissions",
		usersData.streams.map((stream) => ({ id: stream.id, label: `${stream.name} (port ${stream.incomingPort})` })),
		user.streamPermissions,
		"streamId",
	);
	byId("userPermissionsCard").classList.remove("hidden");
}

async function saveUserPermissions() {
	if (!editingPermissionsUserId) return;
	const sitePermissions = [...document.querySelectorAll("#userSitePermissions [data-permission-resource]")]
		.map((select) => ({ siteId: select.dataset.permissionResource, level: select.value }))
		.filter((entry) => entry.level !== "none");
	const streamPermissions = [...document.querySelectorAll("#userStreamPermissions [data-permission-resource]")]
		.map((select) => ({ streamId: select.dataset.permissionResource, level: select.value }))
		.filter((entry) => entry.level !== "none");
	try {
		await api(
			`/users/${encodeURIComponent(editingPermissionsUserId)}`,
			{ method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ sitePermissions, streamPermissions }) },
			false,
		);
		showToast("Permissions updated.");
		byId("userPermissionsCard").classList.add("hidden");
		await loadUsers();
	} catch (error) {
		showToast(error.message, "bad");
	}
}

async function loadAccount() {
	const me = currentAdmin ?? (await loadCurrentAdmin());
	byId("accountSummary").textContent =
		`Signed in as ${me.username} (${me.role === "administrator" ? "Administrator" : "Member"}). Two-factor authentication: ${me.totpEnrolled || me.webauthnCredentialCount > 0 ? "enrolled" : "not enrolled"}.`;
	await loadWebauthnCredentials();
	byId("webauthnRegisterButton").disabled = !isWebauthnSupported();
}

async function loadWebauthnCredentials() {
	const list = byId("webauthnCredentialList");
	try {
		const credentials = await api("/me/webauthn", {}, false);
		list.innerHTML =
			credentials
				.map(
					(credential) => `<li class="site-list-item">
      <div class="site-list-title"><strong>${escapeHtml(credential.nickname || "Security key")}</strong></div>
      <div class="site-list-meta"><span>Registered ${new Date(credential.createdAt).toLocaleString()}</span>${credential.lastUsedAt ? `<span>Last used ${new Date(credential.lastUsedAt).toLocaleString()}</span>` : ""}</div>
      <div class="site-list-actions"><button class="button danger compact" type="button" data-webauthn-remove="${escapeHtml(credential.id)}">Remove</button></div>
    </li>`,
				)
				.join("") || '<li class="empty-state-inline">No security keys registered.</li>';
	} catch (error) {
		list.innerHTML = `<li class="empty-state-inline error-text">${escapeHtml(error.message)}</li>`;
	}
}

async function registerWebauthnCredential() {
	const button = byId("webauthnRegisterButton");
	button.disabled = true;
	try {
		const options = await api("/me/webauthn/register/options", { method: "POST" }, false);
		const credential = await registerCredential(options);
		const nickname = prompt("Name this security key (optional):", "") ?? "";
		await api(
			"/me/webauthn/register/verify",
			{
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ response: credential, nickname, challengeToken: options.challengeToken }),
			},
			false,
		);
		showToast("Security key registered.");
		await loadWebauthnCredentials();
	} catch (error) {
		showToast(error.message, "bad");
	} finally {
		button.disabled = !isWebauthnSupported();
	}
}

async function changePassword(event) {
	event.preventDefault();
	const form = event.currentTarget;
	const payload = Object.fromEntries(new FormData(form));
	try {
		await api("/me/password", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) }, false);
		showToast("Password changed. Please log in again.");
		setTimeout(() => {
			location.href = "/_burrowgate/admin/login";
		}, 1_500);
	} catch (error) {
		showToast(error.message, "bad");
	}
}

async function regenerateRecoveryCodes(event) {
	event.preventDefault();
	const form = event.currentTarget;
	const payload = Object.fromEntries(new FormData(form));
	try {
		const result = await api(
			"/me/recovery-codes/regenerate",
			{ method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) },
			false,
		);
		form.reset();
		const list = byId("newRecoveryCodes");
		list.innerHTML = result.codes.map((code) => `<li><code>${escapeHtml(code)}</code></li>`).join("");
		list.classList.remove("hidden");
		showToast("Recovery codes regenerated.");
	} catch (error) {
		showToast(error.message, "bad");
	}
}

function renderAuditLog(items) {
	byId("auditLog").innerHTML = items.length
		? items
				.map((entry) => {
					const resource = entry.resource_type ? (entry.resource_id ? `${entry.resource_type} (${entry.resource_id})` : entry.resource_type) : "";
					return `<tr>
        <td>${escapeHtml(formatDate(entry.created_at))}</td>
        <td>${escapeHtml(entry.actor_username)}</td>
        <td>${escapeHtml(entry.action)}</td>
        <td class="truncate-cell" title="${escapeHtml(resource)}">${escapeHtml(resource)}</td>
        <td class="truncate-cell" title="${escapeHtml(entry.summary)}">${escapeHtml(entry.summary)}</td>
        <td>${escapeHtml(entry.ip)}</td>
      </tr>`;
				})
				.join("")
		: '<tr><td colspan="6" class="empty-cell">No audit log entries.</td></tr>';
}

async function loadAuditLog() {
	setTableLoading("auditLog", 6);
	try {
		const state = tableState.auditLog;
		const params = queryString({
			page: state.page,
			pageSize: state.pageSize,
			search: byId("auditSearch").value,
			sortBy: state.sortBy,
			sortDirection: state.sortDirection,
		});
		const result = await api(`/audit-log?${params}`, {}, false);
		renderAuditLog(result.items);
		updatePagination("auditLog", result, loadAuditLog);
	} catch (error) {
		setTableError("auditLog", 6, error);
	}
}

async function purgeAuditLog() {
	const choice = prompt("Purge entries older than how many days? Enter 0 to purge all entries.", "90");
	if (choice === null) return;
	const days = Number(choice.trim());
	if (!Number.isFinite(days) || days < 0) {
		showToast("Enter a non-negative number of days.", "bad");
		return;
	}
	let confirmMessage = "Purge the entire audit log? This cannot be undone.";
	if (days > 0) {
		try {
			const cutoff = Date.now() - days * 86_400_000;
			const preview = await api(`/audit-log?until=${cutoff}&pageSize=1`, {}, false);
			confirmMessage =
				preview.total > 0
					? `This will purge ${preview.total} entr${preview.total === 1 ? "y" : "ies"} older than ${days} day(s). Continue?`
					: `No entries are older than ${days} day(s) yet, so nothing will be purged. Continue anyway?`;
		} catch {
			confirmMessage = `Purge audit log entries older than ${days} day(s)?`;
		}
	}
	if (!confirm(confirmMessage)) return;
	try {
		const payload = days === 0 ? { all: true } : { olderThanDays: days };
		const result = await api("/audit-log/purge", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) }, false);
		showToast(`Purged ${result.purged} entr${result.purged === 1 ? "y" : "ies"}.`);
		tableState.auditLog.page = 1;
		await loadAuditLog();
	} catch (error) {
		showToast(error.message, "bad");
	}
}

async function handleBodyClick(event) {
	const eventRow = event.target.closest("tr[data-event-id]");
	if (eventRow) {
		await openEventDetail(eventRow.dataset.eventId);
		return;
	}
	const resendButton = event.target.closest("button[data-resend-event]");
	if (resendButton) {
		await handleResendClick(resendButton);
		return;
	}
	const userPermissionsButton = event.target.closest("button[data-user-permissions]");
	if (userPermissionsButton) {
		openUserPermissions(userPermissionsButton.dataset.userPermissions);
		return;
	}
	const userResetPasswordButton = event.target.closest("button[data-user-reset-password]");
	if (userResetPasswordButton) {
		const password = prompt("New password for this user (minimum 8 characters):");
		if (!password) return;
		userResetPasswordButton.disabled = true;
		try {
			await api(
				`/users/${encodeURIComponent(userResetPasswordButton.dataset.userResetPassword)}/reset-password`,
				{ method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ password }) },
				false,
			);
			showToast("Password reset. The user has been signed out everywhere.");
		} catch (error) {
			showToast(error.message, "bad");
		} finally {
			userResetPasswordButton.disabled = false;
		}
		return;
	}
	const userResetTotpButton = event.target.closest("button[data-user-reset-totp]");
	if (userResetTotpButton) {
		if (!confirm("Reset two-factor authentication for this user? They will need to enroll again on next login.")) return;
		userResetTotpButton.disabled = true;
		try {
			await api(`/users/${encodeURIComponent(userResetTotpButton.dataset.userResetTotp)}/totp/reset`, { method: "POST" }, false);
			showToast("Two-factor authentication reset.");
			await loadUsers();
		} catch (error) {
			userResetTotpButton.disabled = false;
			showToast(error.message, "bad");
		}
		return;
	}
	const userDeleteButton = event.target.closest("button[data-user-delete]");
	if (userDeleteButton) {
		if (!confirm("Delete this user? This cannot be undone.")) return;
		userDeleteButton.disabled = true;
		try {
			await api(`/users/${encodeURIComponent(userDeleteButton.dataset.userDelete)}`, { method: "DELETE" }, false);
			showToast("User deleted.");
			await loadUsers();
		} catch (error) {
			userDeleteButton.disabled = false;
			showToast(error.message, "bad");
		}
		return;
	}
	const webauthnRemoveButton = event.target.closest("button[data-webauthn-remove]");
	if (webauthnRemoveButton) {
		if (!confirm("Remove this security key?")) return;
		webauthnRemoveButton.disabled = true;
		try {
			await api(`/me/webauthn/${encodeURIComponent(webauthnRemoveButton.dataset.webauthnRemove)}`, { method: "DELETE" }, false);
			showToast("Security key removed.");
			await loadWebauthnCredentials();
		} catch (error) {
			webauthnRemoveButton.disabled = false;
			showToast(error.message, "bad");
		}
		return;
	}

	const bandwidthBlockButton = event.target.closest("button[data-bandwidth-block]");
	if (bandwidthBlockButton) {
		const ip = bandwidthBlockButton.dataset.bandwidthBlock;
		if (!confirm(`Block ${ip} from the selected site?`)) return;
		bandwidthBlockButton.disabled = true;
		try {
			await api("/rules", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ networkCidr: ip, action: "block", reason: "Blocked from bandwidth monitor", expiresAt: null }),
			});
			showToast(`${ip} is now blocked for this site.`);
			await Promise.all([loadOverview(), loadMetrics()]);
		} catch (error) {
			bandwidthBlockButton.disabled = false;
			showToast(error.message, "bad");
		}
		return;
	}

	const selectSiteButton = event.target.closest("button[data-site-select]");
	if (selectSiteButton) {
		await chooseSite(selectSiteButton.dataset.siteSelect);
		return;
	}
	const editSiteButton = event.target.closest("button[data-site-edit]");
	if (editSiteButton) {
		editSite(editSiteButton.dataset.siteEdit);
		return;
	}
	const editOriginButton = event.target.closest("button[data-origin-edit]");
	if (editOriginButton) {
		editOrigin(editOriginButton.dataset.originEdit);
		return;
	}
	const checkOriginButton = event.target.closest("button[data-origin-check]");
	if (checkOriginButton && editingSiteId) {
		checkOriginButton.disabled = true;
		try {
			await api(`/origins/${encodeURIComponent(checkOriginButton.dataset.originCheck)}/check`, { method: "POST" }, false);
			await Promise.all([loadOrigins(editingSiteId), loadSiteHealth(editingSiteId), loadOverview()]);
			showToast("Origin health check completed.");
		} catch (error) {
			showToast(error.message, "bad");
		} finally {
			checkOriginButton.disabled = false;
		}
		return;
	}
	const deleteOriginButton = event.target.closest("button[data-origin-delete]");
	if (deleteOriginButton && editingSiteId) {
		if (!confirm("Delete this origin? Existing session assignments will select another healthy origin on their next request.")) return;
		deleteOriginButton.disabled = true;
		try {
			await api(`/origins/${encodeURIComponent(deleteOriginButton.dataset.originDelete)}`, { method: "DELETE" }, false);
			if (editingOriginId === deleteOriginButton.dataset.originDelete) resetOriginForm();
			await Promise.all([loadOrigins(editingSiteId), loadSiteHealth(editingSiteId)]);
			showToast("Origin deleted.");
		} catch (error) {
			deleteOriginButton.disabled = false;
			showToast(error.message, "bad");
		}
		return;
	}

	const editRouteButton = event.target.closest("button[data-route-edit]");
	if (editRouteButton) {
		editRoutePolicy(editRouteButton.dataset.routeEdit);
		return;
	}
	const deleteRouteButton = event.target.closest("button[data-route-delete]");
	if (deleteRouteButton) {
		if (!confirm("Delete this route policy? Requests will immediately fall back to the next matching policy or the site default.")) return;
		deleteRouteButton.disabled = true;
		try {
			await api(`/route-policies/${encodeURIComponent(deleteRouteButton.dataset.routeDelete)}`, { method: "DELETE" });
			if (editingRoutePolicyId === deleteRouteButton.dataset.routeDelete) resetRoutePolicyForm();
			showToast("Route policy deleted.");
			await Promise.all([loadRoutePolicies(), loadMetrics()]);
		} catch (error) {
			deleteRouteButton.disabled = false;
			showToast(error.message, "bad");
		}
		return;
	}

	const saveAccessUserButton = event.target.closest("button[data-access-save]");
	if (saveAccessUserButton) {
		const row = saveAccessUserButton.closest("[data-access-user-row]");
		if (!row) return;
		saveAccessUserButton.disabled = true;
		try {
			const response = await api(`/access-list/users/${encodeURIComponent(saveAccessUserButton.dataset.accessSave)}`, {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					username: row.querySelector("[data-access-username]").value,
					password: row.querySelector("[data-access-password]").value,
					enabled: row.querySelector("[data-access-enabled]").checked,
				}),
			});
			showToast(response.user.siteCount > 1 ? "Shared user updated on every assigned site." : "User updated.");
			await loadAccessList();
		} catch (error) {
			saveAccessUserButton.disabled = false;
			showToast(error.message, "bad");
		}
		return;
	}

	const removeAccessUserButton = event.target.closest("button[data-access-remove]");
	if (removeAccessUserButton) {
		const user = accessList.users.find((item) => item.id === removeAccessUserButton.dataset.accessRemove);
		const message =
			Number(user?.siteCount ?? 1) > 1
				? "Remove this user from the selected site? The shared identity remains available on its other sites."
				: "Remove this user? Because this is its only assigned site, the identity will be permanently deleted.";
		if (!confirm(message)) return;
		removeAccessUserButton.disabled = true;
		try {
			await api(`/access-list/users/${encodeURIComponent(removeAccessUserButton.dataset.accessRemove)}`, { method: "DELETE" });
			showToast("User removed from this site.");
			await loadAccessList();
		} catch (error) {
			removeAccessUserButton.disabled = false;
			showToast(error.message, "bad");
		}
		return;
	}

	const totpToggleButton = event.target.closest("button[data-access-totp-toggle]");
	if (totpToggleButton) {
		const required = totpToggleButton.dataset.totpRequired !== "true";
		totpToggleButton.disabled = true;
		try {
			await api(`/access-list/users/${encodeURIComponent(totpToggleButton.dataset.accessTotpToggle)}/totp`, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ required }),
			});
			showToast(required ? "Two-factor authentication is now required for this user." : "Two-factor authentication is no longer required.");
			await loadAccessList();
		} catch (error) {
			totpToggleButton.disabled = false;
			showToast(error.message, "bad");
		}
		return;
	}

	const totpResetButton = event.target.closest("button[data-access-totp-reset]");
	if (totpResetButton) {
		if (!confirm("Reset two-factor authentication for this user? They will need to enroll again on next login.")) return;
		totpResetButton.disabled = true;
		try {
			await api(`/access-list/users/${encodeURIComponent(totpResetButton.dataset.accessTotpReset)}/totp/reset`, { method: "POST" });
			showToast("Two-factor authentication reset.");
			await loadAccessList();
		} catch (error) {
			totpResetButton.disabled = false;
			showToast(error.message, "bad");
		}
		return;
	}

	const tokenGenerateButton = event.target.closest("button[data-access-token-generate]");
	if (tokenGenerateButton) {
		const isRegenerate = tokenGenerateButton.textContent.startsWith("Regenerate");
		if (isRegenerate && !confirm("Regenerate this user's API token? The previous token will stop working immediately.")) return;
		tokenGenerateButton.disabled = true;
		try {
			const result = await api(`/access-list/users/${encodeURIComponent(tokenGenerateButton.dataset.accessTokenGenerate)}/api-token`, { method: "POST" });
			await loadAccessList();
			window.prompt("API token generated. Copy it now as it will not be shown again:", result.token);
		} catch (error) {
			showToast(error.message, "bad");
		} finally {
			tokenGenerateButton.disabled = false;
		}
		return;
	}

	const tokenRevokeButton = event.target.closest("button[data-access-token-revoke]");
	if (tokenRevokeButton) {
		if (!confirm("Revoke this user's API token? Any automated clients using it will stop working immediately.")) return;
		tokenRevokeButton.disabled = true;
		try {
			await api(`/access-list/users/${encodeURIComponent(tokenRevokeButton.dataset.accessTokenRevoke)}/api-token`, { method: "DELETE" });
			showToast("API token revoked.");
			await loadAccessList();
		} catch (error) {
			tokenRevokeButton.disabled = false;
			showToast(error.message, "bad");
		}
		return;
	}

	const sessionButton = event.target.closest("button[data-session-id]");
	if (sessionButton) {
		if (!confirm("Revoke this access session immediately?")) return;
		sessionButton.disabled = true;
		try {
			await api(`/sessions/${encodeURIComponent(sessionButton.dataset.sessionId)}/revoke`, { method: "POST" });
			showToast("Session revoked.");
			await Promise.all([loadSessions(), loadOverview(), loadMetrics()]);
		} catch (error) {
			sessionButton.disabled = false;
			showToast(error.message, "bad");
		}
		return;
	}

	const countryRuleButton = event.target.closest("button[data-country-rule-id]");
	if (countryRuleButton) {
		if (!confirm("Delete this country rule?")) return;
		countryRuleButton.disabled = true;
		try {
			await api(`/country-rules/${encodeURIComponent(countryRuleButton.dataset.countryRuleId)}`, { method: "DELETE" });
			showToast("Country rule deleted.");
			await Promise.all([loadRules(), loadOverview(), loadMetrics()]);
		} catch (error) {
			countryRuleButton.disabled = false;
			showToast(error.message, "bad");
		}
		return;
	}

	const asnRuleButton = event.target.closest("button[data-asn-rule-id]");
	if (asnRuleButton) {
		if (!confirm("Delete this ASN rule?")) return;
		asnRuleButton.disabled = true;
		try {
			await api(`/asn-rules/${encodeURIComponent(asnRuleButton.dataset.asnRuleId)}`, { method: "DELETE" });
			showToast("ASN rule deleted.");
			await Promise.all([loadRules(), loadOverview(), loadMetrics()]);
		} catch (error) {
			asnRuleButton.disabled = false;
			showToast(error.message, "bad");
		}
		return;
	}

	const ruleButton = event.target.closest("button[data-rule-id]");
	if (ruleButton) {
		if (!confirm("Delete this IP rule?")) return;
		ruleButton.disabled = true;
		try {
			await api(`/rules/${encodeURIComponent(ruleButton.dataset.ruleId)}`, { method: "DELETE" });
			showToast("IP rule deleted.");
			await Promise.all([loadRules(), loadOverview(), loadMetrics()]);
		} catch (error) {
			ruleButton.disabled = false;
			showToast(error.message, "bad");
		}
		return;
	}

	const routeRuleButton = event.target.closest("button[data-route-rule-id]");
	if (routeRuleButton && editingRoutePolicyId) {
		if (!confirm("Delete this route IP rule?")) return;
		routeRuleButton.disabled = true;
		try {
			await api(`/route-policies/${encodeURIComponent(editingRoutePolicyId)}/rules/${encodeURIComponent(routeRuleButton.dataset.routeRuleId)}`, {
				method: "DELETE",
			});
			showToast("Route IP rule deleted.");
			await loadRouteNetworkRules();
		} catch (error) {
			routeRuleButton.disabled = false;
			showToast(error.message, "bad");
		}
		return;
	}

	const routeCountryRuleButton = event.target.closest("button[data-route-country-rule-id]");
	if (routeCountryRuleButton && editingRoutePolicyId) {
		if (!confirm("Delete this route country rule?")) return;
		routeCountryRuleButton.disabled = true;
		try {
			await api(
				`/route-policies/${encodeURIComponent(editingRoutePolicyId)}/country-rules/${encodeURIComponent(routeCountryRuleButton.dataset.routeCountryRuleId)}`,
				{ method: "DELETE" },
			);
			showToast("Route country rule deleted.");
			await loadRouteNetworkRules();
		} catch (error) {
			routeCountryRuleButton.disabled = false;
			showToast(error.message, "bad");
		}
		return;
	}

	const routeAsnRuleButton = event.target.closest("button[data-route-asn-rule-id]");
	if (routeAsnRuleButton && editingRoutePolicyId) {
		if (!confirm("Delete this route ASN rule?")) return;
		routeAsnRuleButton.disabled = true;
		try {
			await api(`/route-policies/${encodeURIComponent(editingRoutePolicyId)}/asn-rules/${encodeURIComponent(routeAsnRuleButton.dataset.routeAsnRuleId)}`, {
				method: "DELETE",
			});
			showToast("Route ASN rule deleted.");
			await loadRouteNetworkRules();
		} catch (error) {
			routeAsnRuleButton.disabled = false;
			showToast(error.message, "bad");
		}
	}
}

function handleBodyChange(event) {
	const ruleCheckbox = event.target.closest(".rule-select");
	if (ruleCheckbox) {
		if (ruleCheckbox.checked) selectedRuleIds.add(ruleCheckbox.dataset.ruleId);
		else selectedRuleIds.delete(ruleCheckbox.dataset.ruleId);
		updateBulkUnbanRulesButton();
		return;
	}
	if (event.target.id === "rulesSelectAll") {
		const checked = event.target.checked;
		for (const checkbox of document.querySelectorAll("#rules .rule-select")) {
			checkbox.checked = checked;
			if (checked) selectedRuleIds.add(checkbox.dataset.ruleId);
			else selectedRuleIds.delete(checkbox.dataset.ruleId);
		}
		updateBulkUnbanRulesButton();
	}
}

async function handleBulkUnbanRules() {
	if (selectedRuleIds.size === 0) return;
	if (!confirm(`Unban ${selectedRuleIds.size} selected IP rule(s)?`)) return;
	const button = byId("bulkUnbanRules");
	button.disabled = true;
	try {
		await api("/rules/bulk-delete", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ ids: [...selectedRuleIds] }),
		});
		showToast("Selected IP rules unbanned.");
		await Promise.all([loadRules(), loadOverview(), loadMetrics()]);
	} catch (error) {
		showToast(error.message, "bad");
		updateBulkUnbanRulesButton();
	}
}

function bindActions() {
	document.querySelectorAll(".tab").forEach((tab) => tab.addEventListener("click", () => setActiveTab(tab.dataset.tab)));
	byId("openUsers").addEventListener("click", () => openModal("users"));
	byId("openAudit").addEventListener("click", () => openModal("audit"));
	byId("openAccount").addEventListener("click", () => openModal("account"));
	byId("openSso").addEventListener("click", () => openModal("sso"));
	byId("saveAdminSso").addEventListener("click", () => void saveAdminSso());
	byId("saveAccessSso").addEventListener("click", () => void saveAccessSso());
	document.querySelectorAll(".modal-overlay").forEach((overlay) => {
		overlay.addEventListener("click", (event) => {
			if (event.target === overlay) closeModal(overlay.dataset.modal);
		});
		overlay.querySelector("[data-modal-close]").addEventListener("click", () => closeModal(overlay.dataset.modal));
	});
	document.addEventListener("keydown", (event) => {
		if (event.key === "Escape") closeAllModals();
	});
	byId("userForm").addEventListener("submit", createUser);
	byId("refreshUsers").addEventListener("click", () => void loadUsers());
	byId("closeUserPermissions").addEventListener("click", () => {
		editingPermissionsUserId = null;
		byId("userPermissionsCard").classList.add("hidden");
	});
	byId("saveUserPermissions").addEventListener("click", () => void saveUserPermissions());
	byId("passwordForm").addEventListener("submit", changePassword);
	byId("recoveryCodesForm").addEventListener("submit", regenerateRecoveryCodes);
	byId("webauthnRegisterButton").addEventListener("click", registerWebauthnCredential);
	byId("refreshAuditLog").addEventListener("click", () => void loadAuditLog());
	byId("purgeAuditLog").addEventListener("click", () => void purgeAuditLog());
	byId("auditSearch").addEventListener(
		"input",
		debounce(() => {
			tableState.auditLog.page = 1;
			void loadAuditLog();
		}),
	);
	document.querySelectorAll("[data-site-editor-tab]").forEach((tab) => tab.addEventListener("click", () => setSiteEditorTab(tab.dataset.siteEditorTab)));
	document.querySelectorAll("[data-route-editor-tab]").forEach((tab) => tab.addEventListener("click", () => setRouteEditorTab(tab.dataset.routeEditorTab)));
	byId("siteSelector").addEventListener("change", (event) => void chooseSite(event.currentTarget.value));
	byId("chartView").addEventListener("change", (event) => {
		chartViewSelection = event.currentTarget.value;
		void refreshChartView();
	});
	byId("geoMetricMode").addEventListener("change", (event) => {
		geoScopeSelection = event.currentTarget.value;
		void loadGeoMetrics();
	});
	byId("topListMode").addEventListener("change", (event) => {
		topListScopeSelection = event.currentTarget.value;
		void loadTopList();
	});
	byId("asnMetricMode").addEventListener("change", (event) => {
		asnScopeSelection = event.currentTarget.value;
		void loadAsnMetrics();
	});
	byId("dateTimeFormat").addEventListener("change", (event) => {
		saveDateTimeFormat(event.currentTarget.value);
		void refreshDashboard()
			.then(() => showToast("Date format updated."))
			.catch((error) => showToast(error.message, "bad"));
	});
	byId("newRoutePolicy").addEventListener("click", () => {
		resetRoutePolicyForm();
		byId("routePolicyName").focus();
	});
	byId("cancelRoutePolicyEdit").addEventListener("click", resetRoutePolicyForm);
	byId("resetRoutePolicyForm").addEventListener("click", () => (editingRoutePolicyId ? editRoutePolicy(editingRoutePolicyId) : resetRoutePolicyForm()));
	byId("routePolicyForm").addEventListener("submit", saveRoutePolicy);
	byId("routePolicyForm").addEventListener(
		"invalid",
		(event) => {
			const panel = event.target.closest("[data-route-editor-panel]");
			if (panel?.dataset.routeEditorPanel) setRouteEditorTab(panel.dataset.routeEditorPanel);
		},
		true,
	);
	byId("routeRateEnabled").addEventListener("change", updateRoutePolicyControls);
	byId("routeRateAlgorithm").addEventListener("change", updateRoutePolicyControls);
	byId("routeRateKeyMode").addEventListener("change", updateRoutePolicyControls);
	byId("routePolicyAccessMode").addEventListener("change", updateRoutePolicyControls);
	byId("routeWebSocketMode").addEventListener("change", updateRoutePolicyControls);
	byId("purgeRouteCache").addEventListener(
		"click",
		(event) =>
			void runWithButton(event.currentTarget, async () => {
				if (confirm("Purge every cached response stored by this route policy?")) await purgeRouteCache();
			}),
	);
	byId("refreshRoutePolicies").addEventListener(
		"click",
		(event) =>
			void runWithButton(event.currentTarget, async () => {
				await Promise.all([loadRoutePolicies(), loadMetrics()]);
				markUpdated("Route policies updated");
			}),
	);
	byId("accessUserForm").addEventListener("submit", createAccessUser);
	byId("accessImportSite").addEventListener("change", renderAccessImportUsers);
	byId("saveAccessSettings").addEventListener(
		"click",
		(event) =>
			void runWithButton(event.currentTarget, async () => {
				try {
					await saveAccessSettings();
					await loadMetrics();
				} catch (error) {
					showToast(error.message, "bad");
				}
			}),
	);
	byId("generateAccessVerificationToken").addEventListener(
		"click",
		(event) =>
			void runWithButton(event.currentTarget, async () => {
				try {
					await generateAccessVerificationToken();
				} catch (error) {
					showToast(error.message, "bad");
				}
			}),
	);
	byId("revokeAccessVerificationToken").addEventListener(
		"click",
		(event) =>
			void runWithButton(event.currentTarget, async () => {
				try {
					await revokeAccessVerificationToken();
				} catch (error) {
					showToast(error.message, "bad");
				}
			}),
	);
	byId("importAccessUsers").addEventListener(
		"click",
		(event) =>
			void runWithButton(event.currentTarget, async () => {
				try {
					await importSelectedAccessUsers();
				} catch (error) {
					showToast(error.message, "bad");
				}
			}),
	);
	byId("refreshAccessList").addEventListener(
		"click",
		(event) =>
			void runWithButton(event.currentTarget, async () => {
				await Promise.all([loadAccessList(), loadMetrics()]);
				markUpdated("Access list updated");
			}),
	);
	byId("newSite").addEventListener("click", () => {
		resetSiteForm();
		byId("siteName").focus();
	});
	byId("siteHttpCacheEnabled").addEventListener("change", updateSiteHttpCacheControls);
	byId("siteHttpBodyCaptureEnabled").addEventListener("change", updateSiteHttpBodyCaptureControls);
	byId("siteHttpHeaderCaptureEnabled").addEventListener("change", updateSiteHttpHeaderCaptureControls);
	byId("siteHttpCorsEnabled").addEventListener("change", updateSiteHttpCorsControls);
	byId("siteHttpCorsOrigins").addEventListener("input", updateSiteHttpCorsControls);
	byId("siteHttpCorsCredentials").addEventListener("change", updateSiteHttpCorsControls);
	byId("siteHttpHstsEnabled").addEventListener("change", updateSiteHttpHstsControls);
	byId("siteHttpHstsMaxAge").addEventListener("input", updateSiteHttpHstsControls);
	byId("siteHttpProtectionMode").addEventListener("change", updateSiteProtectionControls);
	byId("siteHttpProtectionRuleset").addEventListener("change", updateSiteProtectionControls);
	byId("openCacheDashboard").addEventListener("click", () => setActiveTab("cache"));
	byId("openProtectionDashboard").addEventListener("click", () => setActiveTab("protection"));
	byId("configureCache").addEventListener("click", openSelectedSiteCacheSettings);
	byId("configureProtection").addEventListener("click", openSelectedSiteProtectionSettings);
	byId("refreshCache").addEventListener(
		"click",
		(event) => void runWithButton(event.currentTarget, async () => await Promise.all([loadCacheMetrics(), loadMetrics()])),
	);
	byId("purgeCacheSite").addEventListener(
		"click",
		(event) =>
			void runWithButton(event.currentTarget, async () => {
				const prefix = byId("cachePurgePath").value.trim();
				if (confirm(prefix ? `Purge cached entries whose path starts with ${prefix}?` : "Purge every cached response for this site?"))
					await purgeSiteCache(false);
			}),
	);
	byId("purgeCacheAll").addEventListener(
		"click",
		(event) =>
			void runWithButton(event.currentTarget, async () => {
				if (confirm("Purge all in-memory static cache entries for every site?")) await purgeSiteCache(true);
			}),
	);
	byId("cancelSiteEdit").addEventListener("click", resetSiteForm);
	byId("resetSiteForm").addEventListener("click", () => (editingSiteId ? editSite(editingSiteId) : resetSiteForm()));
	byId("generateSiteSecret").addEventListener("click", () => {
		byId("siteSigningSecret").value = randomSecret();
		byId("siteSigningSecret").type = "text";
	});
	byId("copyGeneratedSecret").addEventListener("click", async () => {
		try {
			await navigator.clipboard.writeText(byId("generatedSecretValue").textContent);
			showToast("Signing secret copied.");
		} catch {
			showToast("Could not copy automatically. Select the secret and copy it manually.", "bad");
		}
	});
	byId("siteForm").addEventListener("submit", saveSite);
	byId("siteForm").addEventListener(
		"invalid",
		(event) => {
			const panel = event.target.closest("[data-site-editor-panel]");
			if (panel?.dataset.siteEditorPanel) setSiteEditorTab(panel.dataset.siteEditorPanel);
		},
		true,
	);
	byId("siteWebSocketMode").addEventListener("change", updateSiteWebSocketControls);
	byId("deleteSite").addEventListener("click", deleteEditingSite);
	byId("sitePendingChangeApplyNow").addEventListener("click", applySitePendingChangeNow);
	byId("sitePendingChangeCancel").addEventListener("click", cancelSitePendingChange);
	byId("saveOrigin").addEventListener("click", saveOrigin);
	byId("newOrigin").addEventListener("click", () => {
		resetOriginForm();
		for (const input of byId("originForm").querySelectorAll("input")) input.disabled = false;
		byId("originForm").classList.remove("hidden");
		byId("originName").focus();
	});
	byId("cancelOriginEdit").addEventListener("click", resetOriginForm);
	byId("originMtlsEnabled").addEventListener("change", updateOriginMtlsControls);
	byId("generateOriginMtlsCertificate").addEventListener("click", () => void generateOriginMtlsCertificate());
	byId("downloadOriginMtlsCertificate").addEventListener("click", downloadOriginMtlsCertificate);
	byId("generateOriginCertificate").addEventListener("click", () => void generateOriginCertificate());
	byId("downloadOriginTrustedCa").addEventListener("click", downloadOriginTrustedCa);
	byId("copyGeneratedOriginKey").addEventListener("click", async () => {
		try {
			await navigator.clipboard.writeText(byId("generatedOriginKeyValue").textContent);
			showToast("Private key copied.");
		} catch {
			showToast("Could not copy automatically. Select the key and copy it manually.", "bad");
		}
	});
	byId("downloadGeneratedOriginKey").addEventListener("click", () => {
		const origin = siteOrigins.find((item) => item.id === editingOriginId);
		const name = origin?.name?.replace(/[^a-zA-Z0-9._-]+/gu, "-") || "origin";
		downloadTextFile(`${name}-private-key.pem`, byId("generatedOriginKeyValue").textContent);
	});
	byId("siteHealthEnabled").addEventListener("change", updateHealthControls);
	byId("siteHealthInterval").addEventListener("input", updateHealthDetectionNotice);
	byId("siteHealthFailureThreshold").addEventListener("input", updateHealthDetectionNotice);
	byId("siteCheckOriginNow").addEventListener(
		"click",
		(event) => void runWithButton(event.currentTarget, () => checkOriginNow(editingSiteId)).catch((error) => showToast(error.message, "bad")),
	);
	byId("checkOriginNow").addEventListener(
		"click",
		(event) => void runWithButton(event.currentTarget, () => checkOriginNow(selectedSiteId)).catch((error) => showToast(error.message, "bad")),
	);
	byId("siteErrorResponseMode").addEventListener("change", updateErrorResponseControls);
	byId("resetErrorHtmlTemplate").addEventListener("click", () => {
		byId("siteErrorHtmlTemplate").value = errorResponseDefaults.htmlTemplate ?? "";
		showToast("Default HTML error template restored. Save the site to apply it.");
	});
	byId("resetChallengeHtmlTemplate").addEventListener("click", () => {
		byId("siteChallengeHtmlTemplate").value = challengeDefaults.htmlTemplate ?? "";
		showToast("Default challenge template restored. Save the site to apply it.");
	});
	byId("tlsSettingsForm").addEventListener("submit", (event) => void saveTlsSettings(event).catch((error) => showToast(error.message, "bad")));
	byId("acmeForm").addEventListener("submit", (event) => void requestAcmeCertificate(event).catch((error) => showToast(error.message, "bad")));
	byId("uploadCertificateForm").addEventListener("submit", (event) => void uploadCertificate(event).catch((error) => showToast(error.message, "bad")));
	byId("renewAcmeCertificate").addEventListener("click", () => void renewAcmeCertificate().catch((error) => showToast(error.message, "bad")));
	byId("removeCertificate").addEventListener("click", () => void removeCertificate().catch((error) => showToast(error.message, "bad")));
	byId("acmeDirectoryUrl").addEventListener("input", () => {
		byId("acmeEnvironmentWarning").textContent = byId("acmeDirectoryUrl").value.includes("staging")
			? "Staging mode: the issued certificate will not be trusted by browsers. Use this while testing ACME integration."
			: "Production ACME directory selected. Failed or repeated orders can consume provider rate limits.";
	});
	byId("refreshDashboard").addEventListener("click", (event) => void runWithButton(event.currentTarget, refreshDashboard));
	byId("refreshTraffic").addEventListener(
		"click",
		(event) =>
			void runWithButton(event.currentTarget, async () => {
				await Promise.all([loadTraffic(), loadOverview(), loadMetrics()]);
				markUpdated("Traffic updated");
			}),
	);
	byId("refreshBandwidth").addEventListener(
		"click",
		(event) =>
			void runWithButton(event.currentTarget, async () => {
				await Promise.all([loadBandwidth(), loadMetrics(), refreshGeoAndReferrers()]);
				markUpdated("Bandwidth updated");
			}),
	);
	byId("refreshSessions").addEventListener(
		"click",
		(event) =>
			void runWithButton(event.currentTarget, async () => {
				await Promise.all([loadSessions(), loadOverview(), loadMetrics()]);
				markUpdated("Sessions updated");
			}),
	);
	byId("refreshRules").addEventListener(
		"click",
		(event) =>
			void runWithButton(event.currentTarget, async () => {
				await Promise.all([loadRules(), loadOverview(), loadMetrics()]);
				markUpdated("Rules updated");
			}),
	);
	byId("saveNetworkDefaults").addEventListener("click", (event) => void runWithButton(event.currentTarget, saveNetworkDefaults));
	byId("countryRuleForm").addEventListener("submit", async (event) => {
		event.preventDefault();
		const form = event.currentTarget;
		const submit = form.querySelector('button[type="submit"]');
		submit.disabled = true;
		const data = Object.fromEntries(new FormData(form));
		const expiration = String(data.expiresAt ?? "").trim();
		data.expiresAt = expiration ? new Date(expiration).getTime() : null;
		try {
			await api("/country-rules", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify(data),
			});
			form.reset();
			showToast("Country rule added.");
			await Promise.all([loadRules(), loadOverview(), loadMetrics()]);
		} catch (error) {
			showToast(error.message, "bad");
		} finally {
			submit.disabled = false;
		}
	});
	byId("asnRuleForm").addEventListener("submit", async (event) => {
		event.preventDefault();
		const form = event.currentTarget;
		const submit = form.querySelector('button[type="submit"]');
		submit.disabled = true;
		const data = Object.fromEntries(new FormData(form));
		const expiration = String(data.expiresAt ?? "").trim();
		data.expiresAt = expiration ? new Date(expiration).getTime() : null;
		try {
			await api("/asn-rules", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify(data),
			});
			form.reset();
			showToast("ASN rule added.");
			await Promise.all([loadRules(), loadOverview(), loadMetrics()]);
		} catch (error) {
			showToast(error.message, "bad");
		} finally {
			submit.disabled = false;
		}
	});
	byId("applyDateRange").addEventListener(
		"click",
		(event) =>
			void runWithButton(event.currentTarget, async () => {
				try {
					const range = readDateRangeInputs();
					await applyDateRangeValues(range.from, range.to);
				} catch (error) {
					showToast(error.message, "bad");
				}
			}),
	);
	byId("resetDateRange").addEventListener(
		"click",
		(event) =>
			void runWithButton(event.currentTarget, async () => {
				try {
					const to = Date.now();
					await applyDateRangeValues(to - 24 * 3_600_000, to, "Last 24 hours applied");
				} catch (error) {
					showToast(error.message, "bad");
				}
			}),
	);
	for (const id of ["dateFrom", "dateTo"]) {
		byId(id).addEventListener("keydown", (event) => {
			if (event.key === "Enter") byId("applyDateRange").click();
		});
	}
	byId("logout").addEventListener("click", async () => {
		await api("/logout", { method: "POST" }, false);
		location.href = "/_burrowgate/admin/login";
	});
	byId("addRouteIpRule").addEventListener("click", async (event) => {
		if (!editingRoutePolicyId) return;
		const submit = event.currentTarget;
		if (!byId("routeIpRuleNetworkCidr").value.trim()) {
			showToast("Enter an IP address or CIDR.", "bad");
			return;
		}
		submit.disabled = true;
		const expiration = byId("routeIpRuleExpiresAt").value.trim();
		const data = {
			networkCidr: byId("routeIpRuleNetworkCidr").value,
			action: byId("routeIpRuleAction").value,
			reason: byId("routeIpRuleReason").value,
			expiresAt: expiration ? new Date(expiration).getTime() : null,
		};
		try {
			await api(`/route-policies/${encodeURIComponent(editingRoutePolicyId)}/rules`, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify(data),
			});
			byId("routeIpRuleNetworkCidr").value = "";
			byId("routeIpRuleReason").value = "";
			byId("routeIpRuleExpiresAt").value = "";
			showToast("Route IP rule added.");
			await loadRouteNetworkRules();
		} catch (error) {
			showToast(error.message, "bad");
		} finally {
			submit.disabled = false;
		}
	});
	byId("addRouteCountryRule").addEventListener("click", async (event) => {
		if (!editingRoutePolicyId) return;
		const submit = event.currentTarget;
		if (!byId("routeCountryRuleCountry").value) {
			showToast("Select a country.", "bad");
			return;
		}
		submit.disabled = true;
		const expiration = byId("routeCountryRuleExpiresAt").value.trim();
		const data = {
			countryCode: byId("routeCountryRuleCountry").value,
			action: byId("routeCountryRuleAction").value,
			reason: byId("routeCountryRuleReason").value,
			expiresAt: expiration ? new Date(expiration).getTime() : null,
		};
		try {
			await api(`/route-policies/${encodeURIComponent(editingRoutePolicyId)}/country-rules`, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify(data),
			});
			byId("routeCountryRuleCountry").value = "";
			byId("routeCountryRuleReason").value = "";
			byId("routeCountryRuleExpiresAt").value = "";
			showToast("Route country rule added.");
			await loadRouteNetworkRules();
		} catch (error) {
			showToast(error.message, "bad");
		} finally {
			submit.disabled = false;
		}
	});
	byId("addRouteAsnRule").addEventListener("click", async (event) => {
		if (!editingRoutePolicyId) return;
		const submit = event.currentTarget;
		if (!byId("routeAsnRuleAsn").value) {
			showToast("Enter an ASN.", "bad");
			return;
		}
		submit.disabled = true;
		const expiration = byId("routeAsnRuleExpiresAt").value.trim();
		const data = {
			asn: byId("routeAsnRuleAsn").value,
			action: byId("routeAsnRuleAction").value,
			reason: byId("routeAsnRuleReason").value,
			expiresAt: expiration ? new Date(expiration).getTime() : null,
		};
		try {
			await api(`/route-policies/${encodeURIComponent(editingRoutePolicyId)}/asn-rules`, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify(data),
			});
			byId("routeAsnRuleAsn").value = "";
			byId("routeAsnRuleReason").value = "";
			byId("routeAsnRuleExpiresAt").value = "";
			showToast("Route ASN rule added.");
			await loadRouteNetworkRules();
		} catch (error) {
			showToast(error.message, "bad");
		} finally {
			submit.disabled = false;
		}
	});
	byId("ruleForm").addEventListener("submit", async (event) => {
		event.preventDefault();
		const form = event.currentTarget;
		const submit = form.querySelector('button[type="submit"]');
		submit.disabled = true;
		const data = Object.fromEntries(new FormData(form));
		const expiration = String(data.expiresAt ?? "").trim();
		data.expiresAt = expiration ? new Date(expiration).getTime() : null;
		try {
			await api("/rules", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify(data),
			});
			form.reset();
			tableState.rules.page = 1;
			showToast("IP rule added.");
			await Promise.all([loadRules(), loadOverview(), loadMetrics()]);
		} catch (error) {
			showToast(error.message, "bad");
		} finally {
			submit.disabled = false;
		}
	});
	byId("bulkUnbanRules").addEventListener("click", () => void handleBulkUnbanRules());
	document.body.addEventListener("click", handleBodyClick);
	document.body.addEventListener("change", handleBodyChange);
	window.addEventListener(
		"pagehide",
		() => {
			trafficChart?.destroy();
		},
		{ once: true },
	);
}

async function start() {
	initializeDateTimeFormat();
	initializeDateRange();
	insertColumnsMenus({
		traffic: "trafficHeaderActions",
		bandwidth: "bandwidthHeaderActions",
		sessions: "sessionsHeaderActions",
		rules: "rulesHeaderActions",
	});
	bindColumnsMenus();
	bindSortButtons();
	bindFilters();
	bindActions();
	resetSiteForm();
	resetRoutePolicyForm();
	try {
		await loadCurrentAdmin();
		await loadSites();
		await loadOverview();
		await Promise.all([loadTraffic(), loadMetrics(), refreshGeoAndReferrers()]);
		markUpdated("Loaded");
	} catch (error) {
		showToast(error.message, "bad");
	}
}

void start();
