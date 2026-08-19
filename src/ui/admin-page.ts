import { APP_VERSION, authErrorToast, escapeHtml, page, tablerIcon } from "./layout.ts";

export function loginPage(error = "", sso?: { enabled: boolean; enforceSso: boolean; buttonLabel: string }): string {
	const passwordForm = `<form method="post" action="/_burrowgate/admin/login" class="grid"><label>Username<input class="input" name="username" autocomplete="username"></label><label>Password<input class="input" type="password" name="password" autocomplete="current-password"></label><button class="button" type="submit">Sign in</button></form>`;
	const ssoButton = sso?.enabled ? `<a class="button" href="/_burrowgate/admin/login/sso">${escapeHtml(sso.buttonLabel)}</a>` : "";
	const body =
		sso?.enabled && sso.enforceSso
			? `${ssoButton}<details class="totp-recovery"><summary>Use a local account instead</summary>${passwordForm}</details>`
			: sso?.enabled
				? `${ssoButton}<div class="auth-divider"><span>or</span></div>${passwordForm}`
				: passwordForm;
	return page(
		"Admin login",
		`<main class="shell challenge"><section class="card pad auth-card"><div class="brand"><span class="mark"></span> BurrowGate</div><h1 class="auth-title">Dashboard login</h1>${authErrorToast(error)}${body}</section></main>`,
	);
}

export function twoFactorEnrollPage(uri: string, secret: string, qrSvgMarkup: string, error = ""): string {
	const webauthnSection = `<div id="webauthnStatus" class="muted" hidden></div><button class="button" type="button" id="webauthnRegisterButton">Register a security key</button><div class="auth-divider"><span>or use an authenticator app</span></div>`;
	const totpSection = `<p class="muted">Scan this code with an authenticator app (Ente Auth, Aegis, Google Authenticator, ...), or enter the secret manually.</p><div class="totp-qr">${qrSvgMarkup}</div><p class="muted totp-secret">Secret: <code>${escapeHtml(secret)}</code></p><form method="post" action="/_burrowgate/admin/login/enroll" class="grid"><label>6-digit code<input class="input" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" autofocus></label><button class="button" type="submit">Verify and continue</button></form><p class="muted totp-url"><a href="${escapeHtml(uri)}">Open in authenticator app</a></p>`;
	const recoveryCodesSection = `<div id="webauthnRecoveryCodes" hidden><h2>Save your recovery codes</h2><p class="muted">Each code can be used once if you lose access to your second factor. Store them somewhere safe. They will not be shown again.</p><ul class="totp-recovery-codes" id="webauthnRecoveryCodesList"></ul><div class="recovery-continue"><a class="button" href="/_burrowgate/admin">Continue to dashboard</a></div></div>`;
	const script = `<script type="module">
import { isWebauthnSupported, registerCredential } from "/_burrowgate/static/webauthn-client.js";
const button = document.getElementById("webauthnRegisterButton");
const status = document.getElementById("webauthnStatus");
if (!isWebauthnSupported()) button.disabled = true;
button?.addEventListener("click", async () => {
	button.disabled = true;
	status.hidden = false;
	status.textContent = "Waiting for your security key...";
	try {
		const optionsResponse = await fetch("/_burrowgate/admin/login/webauthn/register/options", { method: "POST" });
		if (!optionsResponse.ok) throw new Error("Could not start registration");
		const options = await optionsResponse.json();
		const credential = await registerCredential(options);
		const verifyResponse = await fetch("/_burrowgate/admin/login/webauthn/register/verify", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ response: credential }),
		});
		const result = await verifyResponse.json();
		if (!verifyResponse.ok) throw new Error(result.error || "Registration failed");
		document.querySelector(".auth-card").querySelectorAll(":scope > :not(#webauthnRecoveryCodes)").forEach((node) => node.remove());
		const list = document.getElementById("webauthnRecoveryCodesList");
		for (const code of result.recoveryCodes) {
			const item = document.createElement("li");
			const codeEl = document.createElement("code");
			codeEl.textContent = code;
			item.append(codeEl);
			list.append(item);
		}
		document.getElementById("webauthnRecoveryCodes").hidden = false;
	} catch (error) {
		status.textContent = error instanceof Error ? error.message : "Registration failed";
		button.disabled = false;
	}
});
</script>`;
	return page(
		"Two-factor setup",
		`<main class="shell challenge"><section class="card pad auth-card"><div class="brand"><span class="mark"></span> BurrowGate</div><h1 class="auth-title">Set up two-factor authentication</h1>${authErrorToast(error)}${webauthnSection}${totpSection}${recoveryCodesSection}</section>${script}</main>`,
	);
}

export function twoFactorVerifyPage(methods: { hasWebauthn: boolean; hasTotp: boolean }, error = ""): string {
	const webauthnSection = methods.hasWebauthn
		? `<div id="webauthnStatus" class="muted" hidden></div><button class="button" type="button" id="webauthnAuthenticateButton">Use your security key</button>${methods.hasTotp ? `<div class="auth-divider"><span>or</span></div>` : ""}`
		: "";
	const totpSection = methods.hasTotp
		? `<form method="post" action="/_burrowgate/admin/login/verify" class="grid"><label>6-digit code<input class="input" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" autofocus></label><button class="button" type="submit">Verify</button></form>`
		: "";
	const script = methods.hasWebauthn
		? `<script type="module">
import { isWebauthnSupported, authenticateWithCredential } from "/_burrowgate/static/webauthn-client.js";
const button = document.getElementById("webauthnAuthenticateButton");
const status = document.getElementById("webauthnStatus");
if (!isWebauthnSupported()) button.disabled = true;
button?.addEventListener("click", async () => {
	button.disabled = true;
	status.hidden = false;
	status.textContent = "Waiting for your security key...";
	try {
		const optionsResponse = await fetch("/_burrowgate/admin/login/webauthn/authenticate/options", { method: "POST" });
		if (!optionsResponse.ok) throw new Error("Could not start verification");
		const options = await optionsResponse.json();
		const credential = await authenticateWithCredential(options);
		const verifyResponse = await fetch("/_burrowgate/admin/login/webauthn/authenticate/verify", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ response: credential }),
		});
		const result = await verifyResponse.json();
		if (!verifyResponse.ok) throw new Error(result.error || "Verification failed");
		window.location.href = "/_burrowgate/admin";
	} catch (error) {
		status.textContent = error instanceof Error ? error.message : "Verification failed";
		button.disabled = false;
	}
});
</script>`
		: "";
	return page(
		"Two-factor verification",
		`<main class="shell challenge"><section class="card pad auth-card"><div class="brand"><span class="mark"></span> BurrowGate</div><h1 class="auth-title">Enter your verification code</h1>${authErrorToast(error)}${webauthnSection}${totpSection}<details class="totp-recovery"><summary>Use a recovery code instead</summary><form method="post" action="/_burrowgate/admin/login/verify" class="grid"><label>Recovery code<input class="input" name="recoveryCode" autocomplete="off"></label><button class="button secondary" type="submit">Use recovery code</button></form></details></section>${script}</main>`,
	);
}

export function totpRecoveryCodesPage(codes: string[]): string {
	const items = codes.map((code) => `<li><code>${escapeHtml(code)}</code></li>`).join("");
	return page(
		"Recovery codes",
		`<main class="shell challenge"><section class="card pad auth-card"><div class="brand"><span class="mark"></span> BurrowGate</div><h1 class="auth-title">Save your recovery codes</h1><p class="muted">Each code can be used once if you lose access to your authenticator app. Store them somewhere safe. They will not be shown again.</p><ul class="totp-recovery-codes">${items}</ul><div class="recovery-continue"><a class="button" href="/_burrowgate/admin">Continue to dashboard</a></div></section></main>`,
	);
}

function sortButton(label: string, key: string): string {
	return `<button class="sort-button" data-sort="${key}">${label}<span aria-hidden="true"></span></button>`;
}

function pagination(id: string): string {
	return `<div class="pagination"><span id="${id}Summary" class="muted">-</span><div class="row"><button id="${id}Previous" class="button secondary compact" type="button">Previous</button><span id="${id}Page" class="page-number">Page 1</span><button id="${id}Next" class="button secondary compact" type="button">Next</button></div></div>`;
}

export function adminPage(): string {
	return page(
		"Dashboard",
		`<main class="shell dashboard-shell">
<header class="row between responsive dashboard-header">
  <div><div class="brand"><span class="mark"></span> BurrowGate<span class="version-tag">v${escapeHtml(APP_VERSION)}</span></div><nav class="dashboard-switch" aria-label="Dashboard"><a class="active" href="/_burrowgate/admin">Web Proxy</a><a href="/_burrowgate/admin/streams">Streams</a><a href="/_burrowgate/admin/notifications">Notifications</a><a href="/_burrowgate/admin/firewall-sync">Firewall Sync</a></nav><p id="siteDescription" class="muted header-subtitle">Reverse proxy control plane</p></div>
  <div class="dashboard-controls">
    <label class="site-picker"><span>Protected site</span><select id="siteSelector" class="select"><option>Loading sites...</option></select></label>
    <label class="site-picker"><span>Date format</span><select id="dateTimeFormat" class="select"><option value="iso-24" selected>YYYY-MM-DD HH:mm:ss</option><option value="dmy-24">DD/MM/YYYY HH:mm:ss</option><option value="mdy-12">MM/DD/YYYY hh:mm:ss AM/PM</option><option value="browser">Browser default</option></select></label>
    <div class="row dashboard-actions"><span id="lastUpdated" class="refresh-status">Loaded on demand</span><button id="openUsers" class="button secondary icon-button hidden" type="button" aria-label="Users" title="Users">${tablerIcon("users")}</button><button id="openSso" class="button secondary icon-button hidden" type="button" aria-label="Single sign-on" title="Single sign-on">${tablerIcon("key")}</button><button id="openAudit" class="button secondary icon-button hidden" type="button" aria-label="Audit log" title="Audit log">${tablerIcon("history")}</button><button id="openAccount" class="button secondary icon-button" type="button" aria-label="Account" title="Account">${tablerIcon("user")}</button><button id="refreshDashboard" class="button secondary icon-button" type="button" aria-label="Refresh dashboard" title="Refresh dashboard">${tablerIcon("refresh")}</button><button id="logout" class="button secondary icon-button" type="button" aria-label="Log out" title="Log out">${tablerIcon("logout")}</button></div>
  </div>
</header>

<section id="originHealthBanner" class="card origin-health-banner hidden" role="status">
  <div><span id="originHealthBannerBadge" class="badge">Unknown</span><strong id="originHealthBannerTitle">Origin health</strong><p id="originHealthBannerMessage" class="muted"></p></div>
  <button id="checkOriginNow" class="button secondary compact" type="button">Check now</button>
</section>

<section class="card date-range-card">
  <div class="date-range-layout">
    <div class="date-range-copy"><h2>Date range</h2><p class="muted">All charts, statistics, geographic data, traffic, and session results use this interval. Drag across a time-series graph to select a narrower range.</p></div>
    <label><span>From</span><input id="dateFrom" class="input" type="datetime-local" step="60"></label>
    <label><span>To</span><input id="dateTo" class="input" type="datetime-local" step="60"></label>
    <div class="row date-range-actions"><button id="applyDateRange" class="button" type="button">Apply</button><button id="resetDateRange" class="button secondary" type="button">Last 24 hours</button></div>
  </div>
</section>

<section class="grid stats">
  <article class="card pad stat"><span id="requestsStatLabel" class="muted">Requests (24h)</span><strong id="requests24h">-</strong></article>
  <article class="card pad stat"><span id="uniqueIpsStatLabel" class="muted">Unique IPs (24h)</span><strong id="uniqueIps24h">-</strong></article>
  <article class="card pad stat"><span id="blockedStatLabel" class="muted">Blocked (24h)</span><strong id="blocked24h">-</strong></article>
  <article class="card pad stat"><span id="errorsStatLabel" class="muted">5xx errors (24h)</span><strong id="errors24h">-</strong><small id="errorRate24h" class="muted">-</small></article>
  <article class="card pad stat"><span id="latencyStatLabel" class="muted">Average latency (24h)</span><strong id="averageLatency24h">-</strong></article>
  <article class="card pad stat"><span id="challengesStatLabel" class="muted">Challenges (24h)</span><strong id="challenges24h">-</strong></article>
  <article class="card pad stat"><span class="muted">Active sessions</span><strong id="activeSessions">-</strong></article>
	<article class="card pad stat"><span id="cacheHitRatioStatLabel" class="muted">Cache hit ratio (24h)</span><strong id="cacheHitRatioStat">-</strong></article>
</section>

<section class="grid charts-grid">
  <article class="card chart-card"><div class="pad row between responsive"><div><h2 id="primaryChartTitle">Traffic volume</h2><p id="primaryChartSubtitle" class="muted">Requests, blocked requests, and origin errors</p></div><select id="chartView" class="select select-small"><option value="traffic:primary">Traffic volume</option><option value="traffic:secondary">Origin latency</option><option value="traffic:methods">Requests by method</option><option value="bandwidth:primary">Client-side bandwidth</option><option value="bandwidth:primary:bitrate">Client-side bandwidth (bitrate)</option><option value="bandwidth:secondary">Upstream bandwidth</option><option value="bandwidth:secondary:bitrate">Upstream bandwidth (bitrate)</option><option value="cache:primary">Cache outcomes</option><option value="cache:secondary">Cache hit ratio</option><option value="protection:primary">Request protection outcomes</option><option value="protection:secondary">Top matched rules</option><option value="sessions:primary">Session lifecycle</option><option value="sessions:secondary">Active sessions</option><option value="rules:primary">Network rules created</option><option value="rules:secondary">Current rule state</option><option value="routes:primary">Route outcomes</option><option value="routes:secondary">Route policy configuration</option><option value="access:primary">Access authentication</option><option value="access:secondary">Assigned users</option><option value="sites:primary">Traffic by site</option><option value="sites:secondary">Origin latency by site</option><option value="connectivity:primary">Internet connectivity latency</option><option value="connectivity:secondary">Timed-out pings</option><option value="health:primary">Origin health-check latency</option><option value="health:secondary">Timed-out health checks</option><option value="system-cpu:secondary">CPU usage</option><option value="system-memory:secondary">Memory usage</option><option value="system-disk:secondary">Storage usage</option><option value="system-network-download:secondary">Network download</option><option value="system-network-upload:secondary">Network upload</option></select></div><div class="chart-layout"><div class="chart-wrap"><div class="chart-canvas-container"><canvas id="trafficChart"></canvas></div><div id="trafficEmpty" class="empty-state hidden">No data in this range.</div></div><aside id="primarySummary" class="chart-sidebar"></aside></div></article>
</section>

<section class="card geo-card">
  <div class="pad row between responsive">
    <div><h2>Geographic distribution</h2><p id="geoSubtitle" class="muted">Requests by country for the selected range</p></div>
    <select id="geoMetricMode" class="select select-small"><option value="requests">Requests</option><option value="bandwidth">Client bandwidth</option><option value="sessions">Sessions created</option><option value="blocked">Blocked requests</option><option value="protection">Matched requests</option><option value="cache">Cache hits</option><option value="access">Authentication events</option><option value="routes">Route enforcement actions</option><option value="sites">Requests (all sites)</option></select>
  </div>
  <div class="geo-layout">
    <div id="geoMapWrap" class="geo-map-wrap">
      <svg id="geoMap" class="geo-map" role="img" aria-label="World map showing requests by country"></svg>
      <div class="geo-zoom-controls">
        <button id="geoZoomIn" class="button secondary icon-button" type="button" aria-label="Zoom in" title="Zoom in">${tablerIcon("zoom-in")}</button>
        <button id="geoZoomOut" class="button secondary icon-button" type="button" aria-label="Zoom out" title="Zoom out" disabled>${tablerIcon("zoom-out")}</button>
        <button id="geoZoomReset" class="button secondary icon-button" type="button" aria-label="Reset zoom" title="Reset zoom" disabled>${tablerIcon("refresh")}</button>
      </div>
      <div id="geoTooltip" class="geo-tooltip hidden" role="status"></div>
      <div id="geoMapStatus" class="geo-map-status muted">Loading GeoIP data...</div>
    </div>
    <aside class="geo-sidebar">
      <div class="row between"><span class="muted">Top countries</span><strong id="geoTotal">0</strong></div>
      <div id="geoCountryList" class="geo-country-list"><p class="muted">No geographic data is available.</p></div>
      <div class="geo-legend"><span>Low</span><div class="geo-legend-scale"><i></i><i></i><i></i><i></i><i></i></div><span>High</span></div>
      <p class="geo-attribution muted">GeoIP data: <a href="https://www.maxmind.com" target="_blank" rel="noreferrer">MaxMind GeoLite2</a><br>Map geometry: <a href="https://github.com/VictorCazanave/svg-maps/tree/master/packages/world" target="_blank" rel="noreferrer">@svg-maps/world / MapSVG</a>, CC BY 4.0</p>
    </aside>
  </div>
</section>

<section class="card asn-card">
  <div class="pad row between responsive">
    <div><h2>Top ASNs</h2><p id="asnSubtitle" class="muted">Requests by network provider for the selected range</p></div>
    <select id="asnMetricMode" class="select select-small"><option value="requests">Requests</option><option value="sessions">Sessions created</option><option value="blocked">Blocked requests</option><option value="protection">Matched requests</option><option value="cache">Cache hits</option><option value="access">Authentication events</option><option value="routes">Route enforcement actions</option><option value="sites">Requests (all sites)</option></select>
  </div>
  <div class="pad-topless row between"><span class="muted">Top networks</span><strong id="asnTotal">0</strong></div>
  <div id="asnList" class="geo-country-list pad-topless"><p class="muted">No ASN data is available.</p></div>
  <p class="geo-attribution muted pad-topless">ASN data: <a href="https://www.maxmind.com" target="_blank" rel="noreferrer">MaxMind GeoLite2</a></p>
</section>

<section id="refererCard" class="card pad">
  <div class="row between responsive">
    <div><h2 id="refererTitle">Top referrers</h2><p id="refererSubtitle" class="muted">External referring domains for the selected range</p></div>
    <div class="row"><select id="topListMode" class="select select-small"><option value="requests">Top referrers (all requests)</option><option value="cache">Top referrers (cache hits)</option><option value="sites">Top referrers (all sites)</option><option value="sessions">Top usernames (sessions)</option><option value="access">Top usernames (authentication)</option><option value="blocked">Top offending IPs (blocked)</option><option value="routes">Top offending IPs (routes)</option><option value="protection">Top targeted paths (protection)</option><option value="paths-requests">Top requested paths (all traffic)</option><option value="bandwidth-ips">Top IPs by bandwidth</option></select><strong id="refererTotal">0</strong></div>
  </div>
  <div id="refererList" class="geo-country-list"><p class="muted">No external referrers in this range.</p></div>
</section>

<nav class="tabs" aria-label="Dashboard sections">
  <button class="tab active" data-tab="traffic" type="button">Traffic</button>
  <button class="tab" data-tab="bandwidth" type="button">Bandwidth</button>
	<button class="tab" data-tab="cache" type="button">Cache</button>
	<button class="tab" data-tab="protection" type="button">Protection</button>
  <button class="tab" data-tab="sessions" type="button">Sessions</button>
  <button class="tab" data-tab="rules" type="button">Network rules</button>
  <button class="tab" data-tab="routes" type="button">Routes</button>
  <button class="tab" data-tab="access" type="button">Access List</button>
  <button class="tab" data-tab="sites" type="button">Sites</button>
</nav>

<section id="panel-traffic" class="tab-panel">
  <article class="card">
    <div class="pad section-heading"><div><h2>Recent traffic</h2><p id="retentionNote" class="muted">Only a paginated result set is loaded.</p></div><div id="trafficHeaderActions" class="row"><button id="refreshTraffic" class="button secondary">Refresh</button></div></div>
    <div class="toolbar traffic-toolbar">
      <label class="search-field"><span>Search</span><input id="eventSearch" class="input" placeholder="ID, IP, path, user or session ID..."></label>
		<label><span>Decision</span><select id="eventDecision" class="select"><option value="">All</option><option value="proxied">HTTP verified</option><option value="proxied-authenticated">HTTP user authenticated</option><option value="proxied-unprotected">HTTP unprotected</option><option value="websocket-proxied">WebSocket verified</option><option value="websocket-authenticated">WebSocket user authenticated</option><option value="websocket-unprotected">WebSocket unprotected</option><option value="access-login-required">User login required</option><option value="access-login-failed">User login failed</option><option value="access-login-rate-limited">User login rate limited</option><option value="access-authenticated">User login succeeded</option><option value="blocked">IP blocked</option><option value="route-blocked">Route blocked</option><option value="managed-protection-blocked">Managed protection blocked</option><option value="websocket-policy-denied">WebSocket policy denied</option><option value="rate-limited">Rate limited</option><option value="request-limited">Request limited</option><option value="challenge-required">Challenge required</option><option value="allowlisted">HTTP allowlisted</option><option value="websocket-allowlisted">WebSocket allowlisted</option><option value="origin-unhealthy">Origin health maintenance</option><option value="origin-pool-unavailable">Origin pool unavailable</option><option value="origin-error">HTTP origin error</option><option value="websocket-origin-error">WebSocket origin error</option><option value="websocket-upgrade-failed">WebSocket upgrade failed</option><option value="websocket-disabled">WebSocket disabled</option></select></label>
		<label><span>Cache</span><select id="eventCacheStatus" class="select"><option value="">All</option><option value="hit">Hit</option><option value="miss">Miss</option><option value="bypass">Bypass</option></select></label>
		<label><span>Protection</span><select id="eventProtectionStatus" class="select"><option value="">All</option><option value="clean">Clean</option><option value="monitored">Would block</option><option value="blocked">Blocked</option></select></label>
      <label><span>Method</span><select id="eventMethod" class="select"><option value="">All</option><option>GET</option><option>HEAD</option><option>POST</option><option>PUT</option><option>PATCH</option><option>DELETE</option><option>OPTIONS</option></select></label>
      <label><span>Status</span><select id="eventStatus" class="select"><option value="">All</option><option value="1xx">1xx</option><option value="2xx">2xx</option><option value="3xx">3xx</option><option value="4xx">4xx</option><option value="5xx">5xx</option></select></label>
      <label id="eventOriginFilter" class="hidden"><span>Origin</span><select id="eventOrigin" class="select"><option value="">All origins</option></select></label>
      <label><span>Country</span><select id="eventCountry" class="select country-select"><option value="">All countries</option></select></label>
      <label><span>ASN</span><input id="eventAsn" class="input" type="number" min="1" step="1" placeholder="e.g. 15169"></label>
      <label><span>Rows</span><select id="eventPageSize" class="select page-size"><option>25</option><option selected>50</option><option>100</option><option>200</option></select></label>
    </div>
		<div class="table-wrap"><table class="table"><thead><tr><th>${sortButton("Time", "created_at")}</th><th>${sortButton("IP", "ip")}</th><th data-column="traffic:country">${sortButton("Country", "country_code")}</th><th data-column="traffic:asn">${sortButton("ASN", "asn")}</th><th data-column="traffic:method">${sortButton("Method", "method")}</th><th data-column="traffic:path">${sortButton("Path", "path")}</th><th data-column="traffic:referer">Referrer</th><th id="eventOriginColumnHeader" data-column="traffic:origin" class="hidden">Origin</th><th data-column="traffic:status">${sortButton("Status", "status")}</th><th data-column="traffic:decision">${sortButton("Decision", "decision")}</th><th data-column="traffic:cache">${sortButton("Cache", "cache_status")}</th><th data-column="traffic:protection">${sortButton("Protection", "protection_status")}</th><th data-column="traffic:latency">${sortButton("Latency", "latency_ms")}</th></tr></thead><tbody id="events"><tr><td colspan="12" class="empty-cell">Loading...</td></tr></tbody></table></div>
    ${pagination("events")}
  </article>
</section>

<section id="panel-bandwidth" class="tab-panel hidden">
  <section class="grid stats bandwidth-stats">
    <article class="card pad stat"><span class="muted">Sent to clients</span><strong id="bandwidthClientDownload">0 B</strong></article>
    <article class="card pad stat"><span class="muted">Received from clients</span><strong id="bandwidthClientUpload">0 B</strong></article>
    <article class="card pad stat"><span class="muted">Received from origins</span><strong id="bandwidthUpstreamDownload">0 B</strong></article>
    <article class="card pad stat"><span class="muted">Sent to origins</span><strong id="bandwidthUpstreamUpload">0 B</strong></article>
  </section>
  <article class="card">
    <div class="pad section-heading"><div><h2>Client bandwidth by IP</h2><p class="muted">HTTP and WebSocket payload bytes are counted. HTTP/TLS headers and transport framing are intentionally excluded.</p></div><div id="bandwidthHeaderActions" class="row"><button id="refreshBandwidth" class="button secondary">Refresh</button></div></div>
    <div class="toolbar bandwidth-toolbar">
      <label class="search-field"><span>Search</span><input id="bandwidthSearch" class="input" placeholder="IP..."></label>
      <label><span>Protocol</span><select id="bandwidthProtocol" class="select"><option value="">All</option><option value="http">HTTP</option><option value="websocket">WebSocket</option></select></label>
      <label><span>Country</span><select id="bandwidthCountry" class="select country-select"><option value="">All countries</option></select></label>
      <label><span>Rows</span><select id="bandwidthPageSize" class="select page-size"><option>25</option><option selected>50</option><option>100</option><option>200</option></select></label>
    </div>
    <div class="table-wrap"><table class="table"><thead><tr><th>${sortButton("IP", "ip")}</th><th data-column="bandwidth:country">${sortButton("Country", "country_code")}</th><th data-column="bandwidth:toClient">${sortButton("To client", "client_sent_bytes")}</th><th data-column="bandwidth:fromClient">${sortButton("From client", "client_received_bytes")}</th><th data-column="bandwidth:fromOrigin">${sortButton("From origin", "upstream_received_bytes")}</th><th data-column="bandwidth:toOrigin">${sortButton("To origin", "upstream_sent_bytes")}</th><th data-column="bandwidth:clientTotal">${sortButton("Client total", "client_total_bytes")}</th><th data-column="bandwidth:upstreamTotal">${sortButton("Upstream total", "upstream_total_bytes")}</th><th></th></tr></thead><tbody id="bandwidthIps"><tr><td colspan="9" class="empty-cell">Open the tab to load bandwidth.</td></tr></tbody></table></div>
    ${pagination("bandwidth")}
    <div id="bandwidthProtocols" class="breakdown"></div>
  </article>
</section>

<section id="panel-cache" class="tab-panel hidden">
	<section class="grid stats cache-history-stats">
		<article class="card pad stat"><span class="muted">Historical hit ratio</span><strong id="cacheHistoryHitRatio">0.00%</strong></article>
		<article class="card pad stat"><span class="muted">Hits / misses</span><strong id="cacheHistoryLookups">0 / 0</strong></article>
		<article class="card pad stat"><span class="muted">Bypasses</span><strong id="cacheHistoryBypasses">0</strong></article>
		<article class="card pad stat"><span class="muted">Origin requests avoided</span><strong id="cacheHistoryAvoided">0</strong></article>
	</section>
	<article class="card">
		<div class="pad section-heading"><div><h2>Runtime cache</h2><p class="muted">Current in-memory state and process-lifetime counters. These reset when BurrowGate restarts. Cached objects are never persisted to disk.</p></div><button id="refreshCache" class="button secondary" type="button">Refresh</button></div>
		<div class="tls-summary-grid cache-runtime-grid">
			<div><span class="muted">Runtime hit ratio</span><strong id="cacheHitRatio">0.00%</strong></div>
			<div><span class="muted">Hits / misses</span><strong id="cacheLookups">0 / 0</strong></div>
			<div><span class="muted">Entries</span><strong id="cacheEntries">0</strong></div>
			<div><span class="muted">Memory</span><strong id="cacheBytes">0 B</strong></div>
			<div><span class="muted">Bypasses</span><strong id="cacheBypasses">0</strong></div>
			<div><span class="muted">Stores</span><strong id="cacheStores">0</strong></div>
			<div><span class="muted">Evicted / expired</span><strong id="cacheEvictions">0 / 0</strong></div>
			<div><span class="muted">Cache bytes served</span><strong id="cacheBytesServed">0 B</strong></div>
		</div>
		<div class="toolbar cache-purge-toolbar">
			<label class="search-field"><span>Purge path prefix</span><input id="cachePurgePath" class="input" placeholder="/assets/"><small class="muted">Leave blank to purge every cached entry for this site.</small></label>
			<button id="purgeCacheSite" class="button secondary align-end" type="button">Purge site cache</button>
			<button id="purgeCacheAll" class="button danger align-end" type="button">Purge all sites</button>
			<button id="configureCache" class="button secondary align-end" type="button">Configure site cache</button>
		</div>
	</article>
	<article class="card">
		<div class="pad section-heading"><div><h2>Top cache paths</h2><p class="muted">Requests in the selected date range, ranked by cache hits.</p></div></div>
		<div class="table-wrap"><table class="table"><thead><tr><th>Path</th><th>Hits</th><th>Misses</th><th>Bypasses</th><th>Hit ratio</th></tr></thead><tbody id="cacheTopPaths"><tr><td colspan="5" class="empty-cell">Open the tab to load cache activity.</td></tr></tbody></table></div>
	</article>
</section>

<section id="panel-protection" class="tab-panel hidden">
	<section class="grid stats protection-history-stats">
		<article class="card pad stat"><span class="muted">Requests inspected</span><strong id="protectionInspected">0</strong></article>
		<article class="card pad stat"><span class="muted">Would block</span><strong id="protectionMonitored">0</strong></article>
		<article class="card pad stat"><span class="muted">Blocked</span><strong id="protectionBlocked">0</strong></article>
		<article class="card pad stat"><span class="muted">Matched rules</span><strong id="protectionRuleCount">0</strong></article>
	</section>
	<article class="card">
		<div class="pad section-heading"><div><h2>Managed ruleset</h2><p class="muted">Monitor mode records requests that would be blocked without changing the response sent by the origin.</p></div><button id="configureProtection" class="button secondary" type="button">Configure site protection</button></div>
		<div id="protectionRulesetSummary" class="pad pad-topless"><p class="muted">Loading managed ruleset information...</p></div>
	</article>
	<article class="card">
		<div class="pad section-heading"><div><h2>Top matched rules</h2><p class="muted">Only rule metadata is stored. Request bodies and matched values are not retained.</p></div></div>
		<div class="table-wrap"><table class="table"><thead><tr><th>Rule</th><th>Category</th><th>Severity</th><th>Would block</th><th>Blocked</th><th>Total</th></tr></thead><tbody id="protectionTopRules"><tr><td colspan="6" class="empty-cell">Open the tab to load protection activity.</td></tr></tbody></table></div>
	</article>
</section>

<section id="panel-sessions" class="tab-panel hidden">
  <article class="card">
    <div class="pad section-heading"><div><h2>Active and recent sessions</h2><p class="muted"><span class="state-swatch active"></span>Active <span class="state-swatch expired"></span>Expired <span class="state-swatch revoked"></span>Revoked</p></div><div id="sessionsHeaderActions" class="row"><button id="refreshSessions" class="button secondary">Refresh</button></div></div>
    <div class="toolbar compact-toolbar">
      <label class="search-field"><span>Search</span><input id="sessionSearch" class="input" placeholder="ID, IP, user..."></label>
      <label><span>State</span><select id="sessionState" class="select"><option value="">All</option><option value="active">Active</option><option value="expired">Expired</option><option value="revoked">Revoked</option></select></label>
      <label><span>Country</span><select id="sessionCountry" class="select country-select"><option value="">All countries</option></select></label>
      <label><span>ASN</span><input id="sessionAsn" class="input" type="number" min="1" step="1" placeholder="e.g. 15169"></label>
      <label><span>Rows</span><select id="sessionPageSize" class="select page-size"><option>25</option><option selected>50</option><option>100</option><option>200</option></select></label>
    </div>
    <div class="table-wrap"><table class="table"><thead><tr><th>State</th><th>Session</th><th>${sortButton("Last IP", "last_ip")}</th><th data-column="sessions:country">${sortButton("Country", "country_code")}</th><th data-column="sessions:asn">${sortButton("ASN", "asn")}</th><th data-column="sessions:created">${sortButton("Created", "created_at")}</th><th data-column="sessions:lastSeen">${sortButton("Last seen", "last_seen_at")}</th><th data-column="sessions:expires">${sortButton("Expires", "expires_at")}</th><th data-column="sessions:requests">${sortButton("Requests", "request_count")}</th><th></th></tr></thead><tbody id="sessions"><tr><td colspan="10" class="empty-cell">Open the tab to load sessions.</td></tr></tbody></table></div>
    ${pagination("sessions")}
  </article>
</section>

<section id="panel-rules" class="tab-panel hidden">
  <article class="card network-defaults-card">
    <div class="pad section-heading"><div><h2>Default network actions</h2><p class="muted">Explicit IP rules override ASN rules, which override country rules, which override these defaults.</p></div><button id="saveNetworkDefaults" class="button" type="button">Save</button></div>
    <div class="network-defaults-grid pad-topless">
      <label><span>Default IP action</span><select id="defaultIpAction" class="select"><option value="inherit">Allow and follow route policy</option><option value="allow">Allow and bypass verification</option><option value="block">Block all IPs</option><option value="challenge">Require challenge</option></select><small class="muted">Set to Block all IPs and add Allow and follow route policy rules to create an IP whitelist.</small></label>
      <label><span>Default country action</span><select id="defaultCountryAction" class="select"><option value="inherit">Use IP default</option><option value="allow">Allow and bypass verification</option><option value="block">Block all countries</option><option value="challenge">Require challenge</option></select><small class="muted">Set to Block all countries and add Allow and follow route policy rules to create a country whitelist.</small></label>
    </div>
    <p id="geoPolicyWarning" class="notice muted hidden"></p>
    <p id="asnPolicyWarning" class="notice muted hidden"></p>
  </article>

  <article class="card rule-create-card">
    <div class="pad"><h2>Add an IP rule</h2><form id="ruleForm" class="rule-form"><label><span>IP address or CIDR</span><input class="input" name="networkCidr" placeholder="203.0.113.4 or 203.0.113.0/24" required></label><label><span>Action</span><select class="select" name="action"><option value="block">Block</option><option value="pass">Allow and follow route policy</option><option value="allow">Allow and bypass verification</option><option value="challenge">Require challenge</option></select></label><label><span>Expires</span><input class="input" type="datetime-local" name="expiresAt"></label><label class="reason-field"><span>Reason</span><input class="input" name="reason" placeholder="Optional reason"></label><button class="button align-end" type="submit">Add rule</button></form></div>
  </article>
  <article class="card rules-list-card">
    <div class="pad section-heading"><div><h2>IP rules</h2><p class="muted">The longest matching CIDR wins. Explicit IP rules have the highest network-policy priority.</p></div><div id="rulesHeaderActions" class="row"><button id="bulkUnbanRules" class="button danger" type="button" disabled>Unban selected (0)</button><button id="refreshRules" class="button secondary">Refresh</button></div></div>
    <div class="toolbar compact-toolbar">
      <label class="search-field"><span>Search</span><input id="ruleSearch" class="input" placeholder="Network, reason, rule ID..."></label>
      <label><span>Action</span><select id="ruleAction" class="select"><option value="">All</option><option value="pass">Allow and follow route</option><option value="allow">Allow and bypass</option><option value="block">Block</option><option value="challenge">Challenge</option></select></label>
      <label><span>State</span><select id="ruleState" class="select"><option value="">All</option><option value="active">Active</option><option value="expired">Expired</option></select></label>
      <label><span>Rows</span><select id="rulePageSize" class="select page-size"><option>25</option><option selected>50</option><option>100</option><option>200</option></select></label>
    </div>
    <div class="table-wrap"><table class="table"><thead><tr><th><input id="rulesSelectAll" type="checkbox"></th><th>State</th><th>${sortButton("Network", "network_cidr")}</th><th>${sortButton("Action", "action")}</th><th data-column="rules:reason">Reason</th><th data-column="rules:ruleId">Rule ID</th><th data-column="rules:created">${sortButton("Created", "created_at")}</th><th data-column="rules:expires">${sortButton("Expires", "expires_at")}</th><th></th></tr></thead><tbody id="rules"><tr><td colspan="9" class="empty-cell">Open the tab to load rules.</td></tr></tbody></table></div>
    ${pagination("rules")}
  </article>

  <article class="card country-rule-card">
    <div class="pad"><h2>Add a country rule</h2><form id="countryRuleForm" class="country-rule-form"><label><span>Country</span><select id="countryRuleCountry" class="select country-select" name="countryCode" required><option value="">Select country</option></select></label><label><span>Action</span><select class="select" name="action"><option value="block">Block</option><option value="pass">Allow and follow route policy</option><option value="allow">Allow and bypass verification</option><option value="challenge">Require challenge</option></select></label><label><span>Expires</span><input class="input" type="datetime-local" name="expiresAt"></label><label class="reason-field"><span>Reason</span><input class="input" name="reason" placeholder="Optional reason"></label><button class="button align-end" type="submit">Add rule</button></form></div>
    <div class="table-wrap"><table class="table"><thead><tr><th>State</th><th>Country</th><th>Action</th><th>Reason</th><th>Created</th><th>Expires</th><th></th></tr></thead><tbody id="countryRules"><tr><td colspan="7" class="empty-cell">Open the tab to load country rules.</td></tr></tbody></table></div>
  </article>

  <article class="card country-rule-card">
    <div class="pad"><h2>Add an ASN rule</h2><form id="asnRuleForm" class="country-rule-form"><label><span>ASN</span><input id="asnRuleAsn" class="input" type="number" min="1" step="1" name="asn" placeholder="e.g. 15169" required></label><label><span>Action</span><select class="select" name="action"><option value="block">Block</option><option value="pass">Allow and follow route policy</option><option value="allow">Allow and bypass verification</option><option value="challenge">Require challenge</option></select></label><label><span>Expires</span><input class="input" type="datetime-local" name="expiresAt"></label><label class="reason-field"><span>Reason</span><input class="input" name="reason" placeholder="Optional reason"></label><button class="button align-end" type="submit">Add rule</button></form></div>
    <div class="table-wrap"><table class="table"><thead><tr><th>State</th><th>ASN</th><th>Action</th><th>Reason</th><th>Created</th><th>Expires</th><th></th></tr></thead><tbody id="asnRules"><tr><td colspan="7" class="empty-cell">Open the tab to load ASN rules.</td></tr></tbody></table></div>
  </article>
</section>

<section id="panel-routes" class="tab-panel hidden">
  <div id="routePolicyLayout" class="route-policy-layout">
    <article class="card route-policy-list-card">
      <div class="pad section-heading"><div><h2>Route policies</h2><p class="muted">The highest-priority matching policy controls access, transport, headers, and limits. A route's network rules take precedence over the site's for matching requests.</p></div><div class="row"><button id="refreshRoutePolicies" class="button secondary" type="button">Refresh</button><button id="newRoutePolicy" class="button" type="button">Create</button></div></div>
      <div id="routePolicyList" class="route-policy-list"><div class="empty-state-inline">Open the tab to load route policies.</div></div>
    </article>
    <article class="card route-policy-editor-card">
      <div class="pad">
        <div class="section-heading policy-editor-heading"><div><h2 id="routePolicyFormTitle">Create route policy</h2><p id="routePolicyFormSubtitle" class="muted">Configure route-specific verification and API limits.</p></div><button id="cancelRoutePolicyEdit" class="button secondary compact hidden" type="button">Cancel edit</button></div>
        <nav class="site-editor-tabs" aria-label="Route policy settings" role="tablist">
          <button class="site-editor-tab active" role="tab" type="button" data-route-editor-tab="general" aria-selected="true">General</button>
          <button class="site-editor-tab" role="tab" type="button" data-route-editor-tab="network" aria-selected="false">Network</button>
          <button class="site-editor-tab" role="tab" type="button" data-route-editor-tab="websocket" aria-selected="false">WebSocket</button>
          <button class="site-editor-tab" role="tab" type="button" data-route-editor-tab="protection" aria-selected="false">Protection</button>
          <button class="site-editor-tab" role="tab" type="button" data-route-editor-tab="http" aria-selected="false">HTTP</button>
          <button class="site-editor-tab" role="tab" type="button" data-route-editor-tab="cache" aria-selected="false">Cache</button>
          <button class="site-editor-tab" role="tab" type="button" data-route-editor-tab="bodyCapture" aria-selected="false">Body &amp; header capture</button>
          <button class="site-editor-tab" role="tab" type="button" data-route-editor-tab="rate" aria-selected="false">Rate limiting</button>
        </nav>
        <form id="routePolicyForm" class="site-form">
          <input id="routePolicyId" type="hidden">
          <section class="error-response-editor" data-route-editor-panel="general">
            <div class="section-heading error-response-heading"><div><h3>General settings</h3><p class="muted">Match requests by path and method, then choose the access mode for this route.</p></div></div>
            <div class="site-form-grid">
              <label><span>Name</span><input id="routePolicyName" class="input" maxlength="255" placeholder="JSON API" required><small class="muted">A descriptive label shown in the admin dashboard.</small></label>
              <label><span>Path pattern</span><input id="routePolicyPath" class="input" maxlength="2048" value="/api/**" placeholder="/api/**" required><small class="muted"><code>*</code> matches one path segment; <code>**</code> matches across segments.</small></label>
              <label><span>HTTP methods</span><input id="routePolicyMethods" class="input" placeholder="GET, POST - blank means all"><small class="muted">Comma-separated. WebSocket upgrades use GET.</small></label>
              <label><span>Priority</span><input id="routePolicyPriority" class="input" type="number" min="-100000" max="100000" value="0"><small class="muted">Higher-priority matching policies are evaluated first.</small></label>
              <label><span>Access mode</span><select id="routePolicyAccessMode" class="select"><option value="inherit">Inherit site default</option><option value="challenge">Require challenge</option><option value="bypass">Bypass browser verification</option><option value="block">Block route</option></select><small class="muted">Choose how BurrowGate handles requests matching this path.</small></label>
            </div>
            <label class="check-row"><input id="routePolicyEnabled" type="checkbox" checked><span><strong>Policy enabled</strong><small class="muted">Disabled policies remain stored but do not match requests.</small></span></label>
            <div id="routeChallengeSettings">
              <label><span>Challenge policy override</span><textarea id="routePolicyChallenge" class="input code-input" rows="8" spellcheck="false" placeholder="Leave blank to inherit the site's challenge chain"></textarea><small id="routeChallengeHelp" class="muted">Only used when this route requires a challenge. A blank value inherits the site policy.</small></label>
            </div>
          </section>
          <section class="error-response-editor hidden" data-route-editor-panel="network">
            <div class="section-heading error-response-heading"><div><h3>IP and country policy</h3><p class="muted">Rules here apply only to requests matching this route, and take precedence over the site's network rules.</p></div></div>
            <div class="site-form-grid">
              <label><span>Default IP action</span><select id="routeDefaultIpAction" class="select"><option value="inherit">Inherit site policy</option><option value="allow">Allow and bypass verification</option><option value="block">Block all IPs</option><option value="challenge">Require challenge</option></select><small class="muted">Applies when no IP, ASN, or country rule below matches.</small></label>
              <label><span>Default country action</span><select id="routeDefaultCountryAction" class="select"><option value="inherit">Use route IP default</option><option value="allow">Allow and bypass verification</option><option value="block">Block all countries</option><option value="challenge">Require challenge</option></select><small class="muted">Applies when no country rule below matches and no IP or ASN rule matched either.</small></label>
            </div>
            <p id="routeNetworkRulesPlaceholder" class="muted">Save this route policy before adding IP or country rules.</p>
            <div id="routeNetworkRulesSection" class="hidden">
              <div class="section-heading error-response-heading"><div><h3>IP rules</h3></div></div>
              <div id="routeIpRuleForm" class="rule-form"><label><span>IP address or CIDR</span><input id="routeIpRuleNetworkCidr" class="input" placeholder="203.0.113.4 or 203.0.113.0/24"></label><label><span>Action</span><select id="routeIpRuleAction" class="select"><option value="block">Block</option><option value="pass">Allow and follow route</option><option value="allow">Allow and bypass verification</option><option value="challenge">Require challenge</option></select></label><label><span>Expires</span><input id="routeIpRuleExpiresAt" class="input" type="datetime-local"></label><label class="reason-field"><span>Reason</span><input id="routeIpRuleReason" class="input" placeholder="Optional reason"></label><button id="addRouteIpRule" class="button align-end" type="button">Add rule</button></div>
              <div class="table-wrap"><table class="table"><thead><tr><th>State</th><th>Network</th><th>Action</th><th>Reason</th><th>Expires</th><th></th></tr></thead><tbody id="routeIpRules"><tr><td colspan="6" class="empty-cell">No IP rules configured for this route.</td></tr></tbody></table></div>
              <div class="section-heading error-response-heading"><div><h3>Country rules</h3></div></div>
              <div id="routeCountryRuleForm" class="country-rule-form"><label><span>Country</span><select id="routeCountryRuleCountry" class="select country-select"><option value="">Select country</option></select></label><label><span>Action</span><select id="routeCountryRuleAction" class="select"><option value="block">Block</option><option value="pass">Allow and follow route</option><option value="allow">Allow and bypass verification</option><option value="challenge">Require challenge</option></select></label><label><span>Expires</span><input id="routeCountryRuleExpiresAt" class="input" type="datetime-local"></label><label class="reason-field"><span>Reason</span><input id="routeCountryRuleReason" class="input" placeholder="Optional reason"></label><button id="addRouteCountryRule" class="button align-end" type="button">Add rule</button></div>
              <div class="table-wrap"><table class="table"><thead><tr><th>State</th><th>Country</th><th>Action</th><th>Reason</th><th>Expires</th><th></th></tr></thead><tbody id="routeCountryRules"><tr><td colspan="6" class="empty-cell">No country rules configured for this route.</td></tr></tbody></table></div>
              <div class="section-heading error-response-heading"><div><h3>ASN rules</h3></div></div>
              <div id="routeAsnRuleForm" class="country-rule-form"><label><span>ASN</span><input id="routeAsnRuleAsn" class="input" type="number" min="1" step="1" placeholder="e.g. 15169"></label><label><span>Action</span><select id="routeAsnRuleAction" class="select"><option value="block">Block</option><option value="pass">Allow and follow route</option><option value="allow">Allow and bypass verification</option><option value="challenge">Require challenge</option></select></label><label><span>Expires</span><input id="routeAsnRuleExpiresAt" class="input" type="datetime-local"></label><label class="reason-field"><span>Reason</span><input id="routeAsnRuleReason" class="input" placeholder="Optional reason"></label><button id="addRouteAsnRule" class="button align-end" type="button">Add rule</button></div>
              <div class="table-wrap"><table class="table"><thead><tr><th>State</th><th>ASN</th><th>Action</th><th>Reason</th><th>Expires</th><th></th></tr></thead><tbody id="routeAsnRules"><tr><td colspan="6" class="empty-cell">No ASN rules configured for this route.</td></tr></tbody></table></div>
            </div>
          </section>
          <section class="error-response-editor hidden" data-route-editor-panel="websocket">
            <div class="section-heading error-response-heading"><div><h3>WebSocket transport</h3><p class="muted">Override the site's WebSocket behavior for connections whose path matches this policy.</p></div></div>
            <div class="site-form-grid">
              <label><span>WebSocket mode</span><select id="routeWebSocketMode" class="select"><option value="inherit">Inherit site default</option><option value="allow">Allow</option><option value="deny">Deny</option></select><small class="muted">A denied upgrade receives a BurrowGate 403 response before an origin connection is opened.</small></label>
            </div>
            <div id="routeWebSocketSettings" class="site-form-grid">
              <label><span>Connect timeout (ms)</span><input id="routeWebSocketConnectTimeout" class="input" type="number" min="1000" step="1" placeholder="Inherit site"><small class="muted">Blank inherits the site value.</small></label>
              <label><span>Idle timeout (seconds)</span><input id="routeWebSocketIdleTimeout" class="input" type="number" min="10" step="1" placeholder="Inherit site"><small class="muted">Blank inherits the site value.</small></label>
              <label><span>Maximum message (bytes)</span><input id="routeWebSocketMaxPayload" class="input" type="number" min="1024" step="1" placeholder="Inherit site"><small class="muted">Applies in both directions.</small></label>
              <label><span>Pre-open queue (bytes)</span><input id="routeWebSocketPreOpenQueue" class="input" type="number" min="1024" step="1" placeholder="Inherit site"><small class="muted">Buffers origin messages until the browser upgrade opens.</small></label>
              <label><span>Upstream buffer (bytes)</span><input id="routeWebSocketUpstreamBuffer" class="input" type="number" min="1024" step="1" placeholder="Inherit site"><small class="muted">Closes slow origin connections before memory use exceeds this value.</small></label>
            </div>
          </section>
          <section class="error-response-editor hidden" data-route-editor-panel="protection">
            <div class="section-heading error-response-heading"><div><h3>Managed request protection</h3><p class="muted">Override enforcement for this route or exclude specific managed rule IDs.</p></div></div>
            <div class="site-form-grid">
              <label><span>Protection mode</span><select id="routeHttpProtectionMode" class="select"><option value="inherit">Inherit site default</option><option value="disabled">Disabled</option><option value="monitor">Monitor only</option><option value="block">Block matches</option></select><small class="muted">Monitor records what would be blocked while continuing to the origin.</small></label>
              <label><span>Additional excluded rule IDs</span><textarea id="routeHttpProtectionExcludedRules" class="input code-input compact-code-input" rows="4" spellcheck="false" placeholder="BG-CORE-2002"></textarea><small class="muted">Comma or whitespace separated. Route exclusions are added to site exclusions.</small></label>
            </div>
            <div class="section-heading error-response-heading"><div><h3>Auto temp-ban durations</h3><p class="muted">When Protection mode is Block, the source IP is temporarily banned for a duration based on the matched rule's severity. Blank inherits the site.</p></div></div>
            <div class="site-form-grid">
              <label><span>Low severity (seconds)</span><input id="routeHttpBanDurationLow" class="input" type="number" min="0" max="2592000" step="1" placeholder="Inherit site"></label>
              <label><span>Medium severity (seconds)</span><input id="routeHttpBanDurationMedium" class="input" type="number" min="0" max="2592000" step="1" placeholder="Inherit site"></label>
              <label><span>High severity (seconds)</span><input id="routeHttpBanDurationHigh" class="input" type="number" min="0" max="2592000" step="1" placeholder="Inherit site"></label>
              <label><span>Critical severity (seconds)</span><input id="routeHttpBanDurationCritical" class="input" type="number" min="0" max="2592000" step="1" placeholder="Inherit site"></label>
            </div>
            <div class="section-heading error-response-heading"><div><h3>Bandwidth limit</h3><p class="muted">Temp-ban an IP that pushes more than the configured amount of bandwidth through this route within the time window. Blank inherits the site.</p></div></div>
            <div class="site-form-grid">
              <label><span>Enforcement</span><select id="routeHttpBandwidthLimitEnabled" class="select"><option value="">Inherit site</option><option value="true">Enabled</option><option value="false">Disabled</option></select></label>
              <label><span>Threshold (MiB)</span><input id="routeHttpBandwidthLimitMaxMiB" class="input" type="number" min="1" step="1" placeholder="Inherit site"></label>
              <label><span>Window (seconds)</span><input id="routeHttpBandwidthLimitWindowSeconds" class="input" type="number" min="1" max="3600" step="1" placeholder="Inherit site"></label>
              <label><span>Ban duration (seconds)</span><input id="routeHttpBandwidthLimitBanSeconds" class="input" type="number" min="0" max="2592000" step="1" placeholder="Inherit site"></label>
            </div>
          </section>
          <section class="error-response-editor hidden" data-route-editor-panel="http">
            <div class="section-heading error-response-heading"><div><h3>HTTP headers and request limits</h3><p class="muted">Add route-specific header rules and override the site's request limits. Route header rules take precedence over matching site rules.</p></div></div>
            <div class="site-form-grid">
              <label><span>Maximum body (bytes)</span><input id="routeHttpMaxBodyBytes" class="input" type="number" min="0" max="1099511627776" step="1" placeholder="Inherit site"><small class="muted">Blank inherits the site. Use 0 for unlimited.</small></label>
              <label><span>Maximum request target (bytes)</span><input id="routeHttpMaxRequestTargetBytes" class="input" type="number" min="0" max="1048576" step="1" placeholder="Inherit site"><small class="muted">Limits the path and query string. Blank inherits; 0 is unlimited.</small></label>
              <label><span>Maximum request headers (bytes)</span><input id="routeHttpMaxHeaderBytes" class="input" type="number" min="0" max="1048576" step="1" placeholder="Inherit site"><small class="muted">Limits the combined parsed request headers. Blank inherits; 0 is unlimited.</small></label>
            </div>
            <div class="site-form-grid">
              <label><span>Set request headers</span><textarea id="routeHttpRequestHeadersSet" class="input code-input" rows="5" spellcheck="false" placeholder="X-Application: media"></textarea><small class="muted">One <code>Name: value</code> rule per line.</small></label>
              <label><span>Remove request headers</span><textarea id="routeHttpRequestHeadersRemove" class="input code-input" rows="5" spellcheck="false" placeholder="X-Legacy-Header"></textarea><small class="muted">One header name per line or comma-separated.</small></label>
              <label><span>Set response headers</span><textarea id="routeHttpResponseHeadersSet" class="input code-input" rows="5" spellcheck="false" placeholder="Cache-Control: private"></textarea><small class="muted">Applied to responses returned by the origin.</small></label>
              <label><span>Remove response headers</span><textarea id="routeHttpResponseHeadersRemove" class="input code-input" rows="5" spellcheck="false" placeholder="X-Powered-By"></textarea><small class="muted">One header name per line or comma-separated.</small></label>
            </div>
          </section>
          <section class="error-response-editor hidden" data-route-editor-panel="cache">
            <div class="section-heading error-response-heading"><div><h3>Safe static-asset cache</h3><p class="muted">Override cache behavior for matching assets. Safety checks remain mandatory.</p></div><button id="purgeRouteCache" class="button secondary compact hidden" type="button">Purge policy cache</button></div>
            <div class="site-form-grid">
              <label><span>Cache mode</span><select id="routeHttpCacheMode" class="select"><option value="inherit">Inherit site default</option><option value="enabled">Enable</option><option value="disabled">Disable</option></select><small class="muted">The route override applies only when this policy matches.</small></label>
              <label><span>TTL (seconds)</span><input id="routeHttpCacheTtl" class="input" type="number" min="1" max="604800" step="1" placeholder="Inherit site"><small class="muted">Origin max-age or s-maxage can shorten this value.</small></label>
              <label><span>Maximum object (bytes)</span><input id="routeHttpCacheMaxObject" class="input" type="number" min="1024" step="1" placeholder="Inherit site"><small class="muted">Blank inherits the site maximum.</small></label>
              <label><span>Cacheable extensions</span><textarea id="routeHttpCacheExtensions" class="input code-input compact-code-input" rows="4" spellcheck="false" placeholder="Inherit site extensions"></textarea><small class="muted">Comma or whitespace separated. Blank inherits.</small></label>
            </div>
          </section>
          <section class="error-response-editor hidden" data-route-editor-panel="bodyCapture">
            <div class="section-heading error-response-heading"><div><h3>Body capture</h3><p class="muted">Override body capture for requests matching this route. Only text-based content types are ever captured.</p></div></div>
            <div class="site-form-grid">
              <label><span>Body capture mode</span><select id="routeHttpBodyCaptureMode" class="select"><option value="inherit">Inherit site default</option><option value="enabled">Enable</option><option value="disabled">Disable</option></select><small class="muted">The route override applies only when this policy matches.</small></label>
              <label><span>Maximum request body (bytes)</span><input id="routeHttpBodyCaptureMaxRequest" class="input" type="number" min="0" step="1" placeholder="Inherit site"><small class="muted">Blank inherits the site value. 0 disables request body capture.</small></label>
              <label><span>Maximum response body (bytes)</span><input id="routeHttpBodyCaptureMaxResponse" class="input" type="number" min="0" step="1" placeholder="Inherit site"><small class="muted">Blank inherits the site value. 0 disables response body capture.</small></label>
              <label><span>Expires at</span><input id="routeHttpBodyCaptureExpiresAt" class="input" type="datetime-local"><small class="muted">Optional. Blank inherits the site expiration, if any.</small></label>
              <label class="site-origin-field"><span>Content types to capture</span><textarea id="routeHttpBodyCaptureContentTypes" class="input code-input compact-code-input" rows="4" spellcheck="false" placeholder="Inherit site content types"></textarea><small class="muted">Comma or whitespace separated, e.g. <code>application/json</code>. Use <code>*</code> for any text-based type. Blank inherits.</small></label>
            </div>
            <div class="section-heading error-response-heading"><div><h3>Header capture</h3><p class="muted">Override header capture for requests matching this route.</p></div></div>
            <div class="site-form-grid">
              <label><span>Header capture mode</span><select id="routeHttpHeaderCaptureMode" class="select"><option value="inherit">Inherit site default</option><option value="enabled">Enable</option><option value="disabled">Disable</option></select><small class="muted">The route override applies only when this policy matches.</small></label>
              <label><span>Redact Authorization/Cookie</span><select id="routeHttpHeaderCaptureRedactAuth" class="select"><option value="">Inherit site default</option><option value="true">Redact</option><option value="false">Capture in full</option></select></label>
              <label><span>Expires at</span><input id="routeHttpHeaderCaptureExpiresAt" class="input" type="datetime-local"><small class="muted">Optional. Blank inherits the site expiration, if any.</small></label>
              <label class="site-origin-field"><span>Additional headers to redact</span><textarea id="routeHttpHeaderCaptureRedactedHeaders" class="input code-input compact-code-input" rows="3" spellcheck="false" placeholder="Inherit site list"></textarea><small class="muted">Comma or whitespace separated. Blank inherits.</small></label>
            </div>
          </section>
          <section class="error-response-editor hidden" data-route-editor-panel="rate">
            <div class="section-heading error-response-heading"><div><h3>Rate limiting</h3><p class="muted">Rate limiting is independent of browser verification and works for JSON APIs and WebSocket handshakes. Counters are currently in-memory per BurrowGate process.</p></div></div>
            <label class="check-row"><input id="routeRateEnabled" type="checkbox"><span><strong>Enable rate limiting</strong></span></label>
            <div id="routeRateSettings" class="site-form-grid hidden">
              <label><span>Algorithm</span><select id="routeRateAlgorithm" class="select"><option value="sliding-window">Sliding window</option><option value="fixed-window">Fixed window</option><option value="token-bucket">Token bucket</option></select><small class="muted">Controls how request capacity is measured over time.</small></label>
              <label><span>Maximum / capacity</span><input id="routeRateMax" class="input" type="number" min="1" max="1000000" value="120"><small class="muted">Maximum requests per window, or token-bucket capacity.</small></label>
              <label class="window-setting"><span>Window (milliseconds)</span><input id="routeRateWindow" class="input" type="number" min="100" max="86400000" value="60000"><small class="muted">Time period used by fixed- and sliding-window limits.</small></label>
              <label class="precision-setting"><span>Precision (milliseconds)</span><input id="routeRatePrecision" class="input" type="number" min="10" max="60000" value="100"><small class="muted">Smaller buckets make sliding-window accounting more precise.</small></label>
              <label class="token-setting hidden"><span>Refill tokens</span><input id="routeRateRefillRate" class="input" type="number" min="1" max="1000000" value="10"><small class="muted">Number of tokens restored during each refill.</small></label>
              <label class="token-setting hidden"><span>Refill interval (milliseconds)</span><input id="routeRateRefillInterval" class="input" type="number" min="10" max="86400000" value="1000"><small class="muted">How often the configured tokens are restored.</small></label>
              <label><span>Client identity</span><select id="routeRateKeyMode" class="select"><option value="ip">IP address</option><option value="session-or-ip">Verified session, otherwise IP</option><option value="header-or-ip">Header value, otherwise IP</option></select><small class="muted">Determines which requests share the same rate-limit counter.</small></label>
              <label id="routeRateHeaderField" class="hidden"><span>Identity header</span><input id="routeRateKeyHeader" class="input" placeholder="x-api-key"><small class="muted">The value is hashed before it becomes an in-memory key. Use only a stable credential that your application validates; clients can rotate arbitrary header values.</small></label>
              <label><span>Counter scope</span><select id="routeRateScope" class="select"><option value="policy">Shared across this policy</option><option value="path">Separate per exact path</option><option value="method-path">Separate per method and path</option></select><small class="muted">Controls whether matching paths and methods share capacity.</small></label>
            </div>
          </section>
          <div class="row site-form-actions"><button id="saveRoutePolicy" class="button" type="submit">Create</button><button id="resetRoutePolicyForm" class="button secondary" type="button">Reset</button></div>
        </form>
      </div>
    </article>
  </div>
</section>

<section id="panel-access" class="tab-panel hidden">
  <div class="route-policy-layout">
    <div class="grid">
      <article class="card">
        <div class="pad section-heading"><div><h2>Access authentication</h2><p class="muted">Require a completed browser challenge and user sign-in before proxying requests.</p></div><button id="saveAccessSettings" class="button" type="button">Save</button></div>
        <div class="pad pad-topless grid">
          <label class="check-row"><input id="accessEnabled" type="checkbox"><span><strong>Require user authentication</strong><small class="muted">At least one active user must be assigned. Existing sessions without a user will be sent to sign in.</small></span></label>
          <label class="check-row"><input id="accessSendUsername" type="checkbox"><span><strong>Send authenticated username to upstream</strong><small class="muted">Adds signed identity headers and browser-readable <code>bg_authenticated_user</code> / <code>bg_identity_signature</code> cookies. Passwords are never forwarded.</small></span></label>
          <p class="notice muted">Application <code>Authorization</code> headers remain available to the origin. Use HTTPS whenever user authentication is enabled.</p>
          <p class="notice muted">A user's API token authenticates automated requests directly, bypassing the sign-in form, password, and two-factor code. Send it as <code>Authorization: Bearer &lt;token&gt;</code>.</p>
		  <div class="section-heading"><div><h3>Cross-site session verification</h3><p class="muted">Let a separate backend introspect short-lived session assertions with a server-only token.</p></div></div>
		  <div class="row"><span id="accessVerificationTokenStatus" class="badge">No verification token</span><button id="generateAccessVerificationToken" class="button secondary compact" type="button">Generate token</button><button id="revokeAccessVerificationToken" class="button danger compact hidden" type="button">Revoke token</button></div>
		  <p class="notice muted">The token is shown once. Store it only on the backend and configure the SDK with this frontend site's ID.</p>
        </div>
      </article>
      <article class="card">
        <div class="pad section-heading"><div><h2>Single sign-on</h2><p class="muted">Let this site's users sign in through an external identity provider instead of a local password. New accounts are provisioned and assigned to this site automatically.</p></div><button id="saveAccessSso" class="button" type="button">Save</button></div>
        <div class="pad pad-topless grid">
          <label class="check-row"><input id="accessSsoEnabled" type="checkbox"><span><strong>Enable single sign-on</strong><small class="muted">Adds a "Sign in with SSO" option to this site's sign-in page.</small></span></label>
          <label class="check-row"><input id="accessSsoEnforce" type="checkbox"><span><strong>Require single sign-on</strong><small class="muted">Hides the password form by default behind a "Use a local account instead" link.</small></span></label>
          <div class="site-form-grid">
            <label><span>Issuer URL</span><input id="accessSsoIssuer" class="input" type="url" placeholder="https://login.example.com/oauth2/default"></label>
            <label><span>Client ID</span><input id="accessSsoClientId" class="input" autocomplete="off"></label>
            <label><span>Client secret</span><input id="accessSsoClientSecret" class="input" type="password" autocomplete="new-password" placeholder="Leave blank to keep current"><small id="accessSsoSecretStatus" class="muted">No client secret is configured.</small></label>
            <label><span>Scopes</span><input id="accessSsoScopes" class="input" value="openid email profile"></label>
            <label><span>Button label</span><input id="accessSsoButtonLabel" class="input" value="Single sign-on"></label>
          </div>
          <p class="notice muted">Redirect URI to register at the identity provider: <code id="accessSsoRedirectUri"></code></p>
          <p class="notice muted">Back-channel logout URI (keeps sessions in sync when the provider's session ends): <code id="accessSsoBackchannelUri"></code></p>
        </div>
      </article>
      <article class="card">
        <div class="pad"><h2>Create user</h2><form id="accessUserForm" class="site-form"><div class="site-form-grid"><label><span>Username</span><input id="accessUsername" class="input" autocomplete="off" maxlength="255" placeholder="ziga" required><small class="muted">Usernames are lowercase and global across all sites.</small></label><label><span>Password</span><input id="accessPassword" class="input" type="password" autocomplete="new-password" minlength="8" maxlength="1024" required><small class="muted">Passwords are stored as secure hashes.</small></label></div><label class="check-row"><input id="accessUserEnabled" type="checkbox" checked><span><strong>User enabled</strong><small class="muted">Disabled shared users cannot sign in to any assigned site.</small></span></label><button class="button" type="submit">Create and assign</button></form></div>
      </article>
      <article class="card">
        <div class="pad"><h2>Add users from another site</h2><p class="muted">Users are linked to this site. Password changes continue to apply everywhere they are assigned.</p><div class="site-form"><label><span>Source site</span><select id="accessImportSite" class="select"><option value="">Select a site</option></select></label><label><span>Users</span><select id="accessImportUsers" class="select access-user-select" multiple size="6"></select></label><button id="importAccessUsers" class="button" type="button">Add selected users</button></div></div>
      </article>
    </div>
    <article class="card">
      <div class="pad section-heading"><div><h2>Assigned users</h2><p class="muted">Editing a shared identity affects every assigned site. Removing it here only removes this site membership.</p></div><button id="refreshAccessList" class="button secondary" type="button">Refresh</button></div>
      <div id="accessUserList" class="route-policy-list"><div class="empty-state-inline">Open the tab to load users.</div></div>
    </article>
  </div>
</section>

<section id="panel-sites" class="tab-panel hidden">
  <div class="sites-layout">
    <article class="card sites-list-card">
      <div class="pad section-heading"><div><h2>Protected sites</h2><p class="muted">Select a site to inspect its traffic, sessions, and rules.</p></div><button id="newSite" class="button" type="button">Create</button></div>
      <div id="sitesList" class="sites-list"><div class="empty-state-inline"><span class="spinner"></span> Loading sites...</div></div>
    </article>
    <article class="card site-editor-card">
      <div class="pad">
        <div class="section-heading site-editor-heading"><div><h2 id="siteFormTitle">Create site</h2><p id="siteFormSubtitle" class="muted">Add another hostname and origin to BurrowGate.</p></div><button id="cancelSiteEdit" class="button secondary compact hidden" type="button">Cancel edit</button></div>
        <nav class="site-editor-tabs" aria-label="Site settings" role="tablist">
          <button class="site-editor-tab active" role="tab" type="button" data-site-editor-tab="general" aria-selected="true">General</button>
          <button class="site-editor-tab" role="tab" type="button" data-site-editor-tab="access" aria-selected="false">Access</button>
          <button class="site-editor-tab" role="tab" type="button" data-site-editor-tab="websocket" aria-selected="false">WebSocket</button>
          <button class="site-editor-tab" role="tab" type="button" data-site-editor-tab="http" aria-selected="false">HTTP</button>
			<button class="site-editor-tab" role="tab" type="button" data-site-editor-tab="protection" aria-selected="false">Protection</button>
          <button class="site-editor-tab" role="tab" type="button" data-site-editor-tab="origins" aria-selected="false">Origins</button>
          <button class="site-editor-tab" role="tab" type="button" data-site-editor-tab="health" aria-selected="false">Health</button>
          <button class="site-editor-tab" role="tab" type="button" data-site-editor-tab="responses" aria-selected="false">Responses</button>
          <button class="site-editor-tab" role="tab" type="button" data-site-editor-tab="tls" aria-selected="false">HTTPS</button>
        </nav>
        <form id="originValidationForm"></form>
        <form id="siteForm" class="site-form">
          <input id="siteId" type="hidden">
          <section class="error-response-editor" data-site-editor-panel="general">
            <div class="section-heading error-response-heading"><div><h3>General settings</h3><p class="muted">Configure the site's public identity and primary origin.</p></div></div>
            <div class="site-form-grid">
              <label><span>Site name</span><input id="siteName" class="input" name="name" maxlength="255" placeholder="Main website" required><small class="muted">A friendly name used throughout the admin dashboard.</small></label>
              <label><span>Public host</span><input id="sitePublicHost" class="input" name="publicHost" maxlength="255" placeholder="example.com or localhost" required><small class="muted">Hostname and optional port, without a scheme or path.</small></label>
              <label class="site-origin-field"><span>Origin URL</span><input id="siteOriginUrl" class="input" name="originUrl" type="url" placeholder="http://127.0.0.1:3000" required><small class="muted">HTTP or HTTPS origin. A path prefix is supported.</small></label>
              <label><span>Schedule hostname change for</span><input id="sitePendingChangeEffectiveAt" class="input" type="datetime-local"><small class="muted">Only used when the public host changes on a site with an active certificate - the HTTPS listener rebuild is deferred to this time instead of happening immediately. Leave blank to apply now. All other changes always apply immediately.</small></label>
            </div>
            <label class="check-row"><input id="siteEnabled" name="enabled" type="checkbox" checked><span><strong>Site enabled</strong><small class="muted">Disabled sites stop matching incoming requests but keep their stored data.</small></span></label>
            <div id="sitePendingChangeBanner" class="pending-change-banner hidden">
              <div><strong id="sitePendingChangeLabel">Scheduled change:</strong> <span id="sitePendingChangeSummary"></span></div>
              <div class="pending-change-actions">
                <button id="sitePendingChangeApplyNow" class="button secondary compact" type="button">Apply now</button>
                <button id="sitePendingChangeCancel" class="button danger compact" type="button">Cancel</button>
              </div>
            </div>
          </section>
					<section class="error-response-editor hidden" data-site-editor-panel="protection">
						<div class="section-heading error-response-heading"><div><h3>Managed request protection</h3><p class="muted">Inspect requests with a versioned managed ruleset before they reach the origin.</p></div><span id="siteProtectionModeBadge" class="badge info">Monitor</span></div>
						<div class="site-form-grid">
							<label><span>Protection mode</span><select id="siteHttpProtectionMode" class="select"><option value="disabled">Disabled</option><option value="monitor" selected>Monitor only</option><option value="block">Block matches</option></select><small class="muted">Start in Monitor. Requests continue normally while potential blocks are recorded.</small></label>
							<label><span>Managed ruleset</span><select id="siteHttpProtectionRuleset" class="select"><option value="default">Default managed ruleset</option></select><small id="siteProtectionRulesetHelp" class="muted">The active default ruleset is loaded by BurrowGate.</small></label>
							<label class="site-origin-field"><span>Excluded rule IDs</span><textarea id="siteHttpProtectionExcludedRules" class="input code-input compact-code-input" rows="5" spellcheck="false" placeholder="BG-CORE-2002"></textarea><small class="muted">Comma or whitespace separated. Use narrow route exclusions when only one endpoint requires an exception.</small></label>
						</div>
						<div class="section-heading error-response-heading"><div><h3>Auto temp-ban durations</h3><p class="muted">When Protection mode is Block and a request matches a rule, the source IP is added to IP rules as a temporary block for the duration below, based on the matched rule's severity. Use 0 to disable auto-banning for that severity.</p></div></div>
						<div class="site-form-grid">
							<label><span>Low severity (seconds)</span><input id="siteHttpBanDurationLow" class="input" type="number" min="0" max="2592000" step="1" value="0" required></label>
							<label><span>Medium severity (seconds)</span><input id="siteHttpBanDurationMedium" class="input" type="number" min="0" max="2592000" step="1" value="600" required></label>
							<label><span>High severity (seconds)</span><input id="siteHttpBanDurationHigh" class="input" type="number" min="0" max="2592000" step="1" value="3600" required></label>
							<label><span>Critical severity (seconds)</span><input id="siteHttpBanDurationCritical" class="input" type="number" min="0" max="2592000" step="1" value="86400" required></label>
						</div>
						<div class="section-heading error-response-heading"><div><h3>Bandwidth limit</h3><p class="muted">Temp-ban an IP that pushes more than the configured amount of bandwidth through this site (or a route, if overridden) within the time window. Detection is periodic rather than instantaneous to keep the proxy path fast.</p></div></div>
						<div class="site-form-grid">
							<label class="check-row"><input id="siteHttpBandwidthLimitEnabled" type="checkbox"><span><strong>Enabled</strong><small class="muted">Off by default.</small></span></label>
							<label><span>Threshold (MiB)</span><input id="siteHttpBandwidthLimitMaxMiB" class="input" type="number" min="1" step="1" value="50" required></label>
							<label><span>Window (seconds)</span><input id="siteHttpBandwidthLimitWindowSeconds" class="input" type="number" min="1" max="3600" step="1" value="60" required></label>
							<label><span>Ban duration (seconds)</span><input id="siteHttpBandwidthLimitBanSeconds" class="input" type="number" min="0" max="2592000" step="1" value="3600" required></label>
						</div>
						<button id="openProtectionDashboard" class="button secondary" type="button">Open Protection dashboard</button>
					</section>
          <section class="error-response-editor hidden" data-site-editor-panel="access">
            <div class="section-heading error-response-heading"><div><h3>Traffic and access</h3><p class="muted">Control client identity, verification defaults, session lifetime, and stored traffic history.</p></div></div>
            <div class="site-form-grid">
              <label><span>Session lifetime (seconds)</span><input id="siteSessionTtl" class="input" name="sessionTtlSeconds" type="number" min="60" max="2592000" step="1" value="43200" required><small class="muted">How long a verified visitor session remains valid.</small></label>
              <label><span>Traffic retention (days)</span><input id="siteEventRetentionDays" class="input" name="eventRetentionDays" type="number" min="1" max="365" step="1" value="7" required><small class="muted">Request events and bandwidth buckets older than this are removed for this site.</small></label>
              <label><span>Default access mode</span><select id="siteDefaultAccessMode" class="select"><option value="challenge">Require challenge</option><option value="bypass">Disable browser verification</option></select><small class="muted">Route policies can override this per path.</small></label>
              <label><span>Client IP source</span><select id="siteIpExtractionPreset" class="select"><option value="direct">Direct connection</option><option value="cloudflare">Cloudflare</option><option value="aws">AWS</option><option value="gcp">Google Cloud</option><option value="azure">Azure</option><option value="vercel">Vercel</option><option value="nginx">nginx</option><option value="development">Development</option></select><small class="muted">Trusts the selected proxy's client-IP headers for this site. Keep Direct unless requests can only reach BurrowGate through that proxy.</small></label>
            </div>
          </section>
          <section class="error-response-editor hidden" data-site-editor-panel="websocket">
            <div class="section-heading error-response-heading"><div><h3>WebSocket transport</h3><p class="muted">Set the defaults for WebSocket connections to this site. Route policies can inherit or override them.</p></div><span id="siteWebSocketAvailability" class="badge ok">Available</span></div>
            <div class="site-form-grid">
              <label><span>WebSocket mode</span><select id="siteWebSocketMode" class="select"><option value="allow">Allow</option><option value="deny">Deny</option></select><small class="muted">Denying WebSockets does not affect ordinary HTTP traffic.</small></label>
            </div>
            <div id="siteWebSocketSettings" class="site-form-grid">
              <label><span>Connect timeout (ms)</span><input id="siteWebSocketConnectTimeout" class="input" type="number" min="1000" step="1" required><small class="muted">Maximum time to establish the origin connection.</small></label>
              <label><span>Idle timeout (seconds)</span><input id="siteWebSocketIdleTimeout" class="input" type="number" min="10" step="1" required><small class="muted">Closes a connection after no messages are transferred.</small></label>
              <label><span>Maximum message (bytes)</span><input id="siteWebSocketMaxPayload" class="input" type="number" min="1024" step="1" required><small class="muted">Maximum payload accepted in either direction.</small></label>
              <label><span>Pre-open queue (bytes)</span><input id="siteWebSocketPreOpenQueue" class="input" type="number" min="1024" step="1" required><small class="muted">Origin data buffered while the downstream upgrade completes.</small></label>
              <label><span>Upstream buffer (bytes)</span><input id="siteWebSocketUpstreamBuffer" class="input" type="number" min="1024" step="1" required><small class="muted">Maximum queued data while the origin is receiving slowly.</small></label>
            </div>
            <p id="siteWebSocketDisabledNotice" class="notice muted hidden">WebSocket proxying is disabled for this BurrowGate instance. Site settings are saved but cannot enable it above the instance policy.</p>
          </section>
          <section class="error-response-editor hidden" data-site-editor-panel="http">
            <div class="section-heading error-response-heading"><div><h3>Request limits</h3><p class="muted">Set safe HTTP request ceilings for this site. Matching route policies can inherit or override each limit.</p></div></div>
            <div class="site-form-grid">
              <label><span>Maximum body (bytes)</span><input id="siteHttpMaxBodyBytes" class="input" type="number" min="0" max="1099511627776" step="1" value="0" required><small class="muted">Rejects oversized bodies with 413. Use 0 for unlimited.</small></label>
              <label><span>Maximum request target (bytes)</span><input id="siteHttpMaxRequestTargetBytes" class="input" type="number" min="0" max="1048576" step="1" value="0" required><small class="muted">Limits the path and query string; 0 is unlimited.</small></label>
              <label><span>Maximum request headers (bytes)</span><input id="siteHttpMaxHeaderBytes" class="input" type="number" min="0" max="1048576" step="1" value="0" required><small class="muted">Limits the combined parsed request headers; 0 is unlimited.</small></label>
            </div>
            <div class="section-heading error-response-heading"><div><h3>Safe static-asset cache</h3><p class="muted">Cache public static responses in bounded memory. The cache never stores responses with cookies, private/no-store/no-cache directives, unsafe variants, ranges, HTML, JSON, or authenticated application requests.</p></div></div>
            <label class="check-row"><input id="siteHttpCacheEnabled" type="checkbox"><span><strong>Enable static-asset caching</strong><small class="muted">Disabled by default. Browser verification cookies are ignored for eligibility, but application cookies and Authorization always bypass cache.</small></span></label>
            <div id="siteHttpCacheSettings" class="site-form-grid hidden">
              <label><span>Maximum TTL (seconds)</span><input id="siteHttpCacheTtl" class="input" type="number" min="1" max="604800" step="1" required><small class="muted">Origin max-age or s-maxage can only shorten this value.</small></label>
              <label><span>Maximum object (bytes)</span><input id="siteHttpCacheMaxObject" class="input" type="number" min="1024" step="1" required><small class="muted">Objects above this size continue streaming but are not stored.</small></label>
              <label class="site-origin-field"><span>Cacheable extensions</span><textarea id="siteHttpCacheExtensions" class="input code-input compact-code-input" rows="4" spellcheck="false" required></textarea><small class="muted">Comma or whitespace separated. Keep this limited to static asset formats.</small></label>
            </div>
			<p class="notice muted">Historical metrics, runtime memory, and purge controls are available in the dedicated Cache tab.</p>
			<button id="openCacheDashboard" class="button secondary" type="button">Open Cache dashboard</button>
            <div class="section-heading error-response-heading"><div><h3>Body capture</h3><p class="muted">Store request and response bodies so they can be inspected from Recent traffic. Disabled by default, and only text-based content types are ever captured.</p></div></div>
            <label class="check-row"><input id="siteHttpBodyCaptureEnabled" type="checkbox"><span><strong>Enable body capture</strong><small class="muted">Keep the size limits low. Set an expiration if you only need this temporarily.</small></span></label>
            <div id="siteHttpBodyCaptureSettings" class="site-form-grid hidden">
              <label><span>Maximum request body (bytes)</span><input id="siteHttpBodyCaptureMaxRequest" class="input" type="number" min="0" step="1" required><small class="muted">0 disables request body capture.</small></label>
              <label><span>Maximum response body (bytes)</span><input id="siteHttpBodyCaptureMaxResponse" class="input" type="number" min="0" step="1" required><small class="muted">0 disables response body capture.</small></label>
              <label><span>Expires at</span><input id="siteHttpBodyCaptureExpiresAt" class="input" type="datetime-local"><small class="muted">Optional. New captures stop after this time; already-captured bodies are unaffected.</small></label>
              <label class="site-origin-field"><span>Content types to capture</span><textarea id="siteHttpBodyCaptureContentTypes" class="input code-input compact-code-input" rows="4" spellcheck="false" required></textarea><small class="muted">Comma or whitespace separated, e.g. <code>application/json</code>. Use <code>*</code> for any text-based type.</small></label>
            </div>
            <div class="section-heading error-response-heading"><div><h3>Header capture</h3><p class="muted">Store request and response headers so they can be inspected, and requests resent, from Recent traffic. Disabled by default.</p></div></div>
            <label class="check-row"><input id="siteHttpHeaderCaptureEnabled" type="checkbox"><span><strong>Enable header capture</strong><small class="muted">Set an expiration if you only need this temporarily.</small></span></label>
            <div id="siteHttpHeaderCaptureSettings" class="site-form-grid hidden">
              <label class="check-row"><input id="siteHttpHeaderCaptureRedactAuth" type="checkbox"><span><strong>Redact Authorization, Cookie, and Set-Cookie</strong><small class="muted">Recommended. The header name is still captured; only the value is hidden.</small></span></label>
              <label><span>Expires at</span><input id="siteHttpHeaderCaptureExpiresAt" class="input" type="datetime-local"><small class="muted">Optional. New captures stop after this time; already-captured headers are unaffected.</small></label>
              <label class="site-origin-field"><span>Additional headers to redact</span><textarea id="siteHttpHeaderCaptureRedactedHeaders" class="input code-input compact-code-input" rows="3" spellcheck="false"></textarea><small class="muted">Comma or whitespace separated, e.g. <code>x-api-key</code>.</small></label>
            </div>
            <div class="section-heading error-response-heading"><div><h3>Header policies</h3><p class="muted">Change headers at the origin boundary. BurrowGate keeps routing, framing, forwarding, and signed identity headers under proxy control.</p></div></div>
            <div class="site-form-grid">
              <label><span>Set request headers</span><textarea id="siteHttpRequestHeadersSet" class="input code-input" rows="6" spellcheck="false" placeholder="X-Application: media"></textarea><small class="muted">One <code>Name: value</code> rule per line.</small></label>
              <label><span>Remove request headers</span><textarea id="siteHttpRequestHeadersRemove" class="input code-input" rows="6" spellcheck="false" placeholder="X-Legacy-Header"></textarea><small class="muted">One header name per line or comma-separated.</small></label>
              <label><span>Set response headers</span><textarea id="siteHttpResponseHeadersSet" class="input code-input" rows="6" spellcheck="false" placeholder="Strict-Transport-Security: max-age=31536000"></textarea><small class="muted">Applied to responses returned by the origin.</small></label>
              <label><span>Remove response headers</span><textarea id="siteHttpResponseHeadersRemove" class="input code-input" rows="6" spellcheck="false" placeholder="X-Powered-By"></textarea><small class="muted">One header name per line or comma-separated. Removing <code>Set-Cookie</code> also removes origin cookies.</small></label>
            </div>
          </section>
          <section class="error-response-editor hidden" data-site-editor-panel="access">
            <div class="section-heading error-response-heading"><div><h3>Origin trust and verification</h3><p class="muted">Sign trusted identity headers and define the default browser challenge chain.</p></div></div>
            <label><span>Origin signing secret</span><div class="secret-row"><input id="siteSigningSecret" class="input" name="originSigningSecret" type="password" autocomplete="new-password" placeholder="Generated automatically for new sites"><button id="generateSiteSecret" class="button secondary" type="button">Generate</button></div><small id="siteSecretHelp" class="muted">Leave blank to generate a secure secret. The generated value is shown once after creation.</small></label>
            <label><span>Challenge policy</span><textarea id="siteChallengePolicy" class="input code-input" name="challengePolicy" rows="11" spellcheck="false" required></textarea><small id="challengeProviderHelp" class="muted">Ordered JSON array. Each provider is completed before the visitor receives a session.</small></label>
          </section>
          <section class="error-response-editor hidden" data-site-editor-panel="origins">
            <div class="section-heading error-response-heading"><div><h3>Load balancing</h3><p class="muted">Choose how BurrowGate selects from healthy origins.</p></div></div>
            <div class="site-form-grid">
              <label><span>Algorithm</span><select id="siteLoadBalancingAlgorithm" class="select"><option value="failover">Priority failover</option><option value="round-robin">Round robin</option><option value="weighted-round-robin">Weighted round robin</option></select><small class="muted">Priority failover uses the lowest healthy priority number.</small></label>
              <label class="check-row compact-check"><input id="siteLoadBalancingAffinity" type="checkbox" checked><span><strong>Sticky origin affinity</strong><small class="muted">Use the stored session assignment when available, otherwise deterministically select by client IP.</small></span></label>
            </div>
            <div id="originPoolRuntime" class="health-runtime hidden">
              <div class="section-heading compact-heading"><div><h4>Origin pool</h4><p class="muted">Unhealthy origins are excluded automatically. Draining origins keep existing sessions but receive no new assignments.</p></div><button id="newOrigin" class="button secondary compact" type="button">Add origin</button></div>
              <div id="originPoolList" class="health-event-list"><p class="muted">Loading origins...</p></div>
              <div id="originForm" class="site-form hidden">
                <input id="originId" type="hidden" form="originValidationForm">
                <div class="site-form-grid">
                  <label><span>Name</span><input id="originName" class="input" form="originValidationForm" maxlength="255" placeholder="Application node 2" required><small class="muted">Shown in monitoring, health history, and traffic tables.</small></label>
                  <label class="site-origin-field"><span>Origin URL</span><input id="originUrl" class="input" form="originValidationForm" type="url" placeholder="http://10.0.0.21:3000" required><small class="muted">Base HTTP or HTTPS address for this backend server.</small></label>
                  <label><span>Priority</span><input id="originPriority" class="input" form="originValidationForm" type="number" min="0" max="10000" value="10" required><small class="muted">Lower values are preferred in failover mode.</small></label>
                  <label><span>Weight</span><input id="originWeight" class="input" form="originValidationForm" type="number" min="1" max="1000" value="1" required><small class="muted">Relative traffic share in weighted round-robin mode.</small></label>
                  <label class="site-origin-field"><span>Health path override</span><input id="originHealthPath" class="input" form="originValidationForm" maxlength="2048" placeholder="Use the site health path"><small class="muted">Leave blank to use the site-level health-check path.</small></label>
                </div>
                <label class="check-row"><input id="originEnabled" form="originValidationForm" type="checkbox" checked><span><strong>Origin enabled</strong><small class="muted">Disabled origins remain configured but receive no traffic.</small></span></label>
                <label class="check-row"><input id="originDraining" form="originValidationForm" type="checkbox"><span><strong>Drain origin</strong><small class="muted">Existing sticky sessions continue using it; new assignments avoid it.</small></span></label>
                <div class="row site-form-actions"><button id="saveOrigin" class="button" type="button">Add origin</button><button id="cancelOriginEdit" class="button secondary" type="button">Cancel</button></div>
              </div>
            </div>
          </section>
          <section class="error-response-editor origin-health-editor hidden" data-site-editor-panel="health">
            <div class="section-heading error-response-heading"><div><h3>Origin health</h3><p class="muted">Probe a path on the configured origin and optionally fail fast with the site error page.</p></div><span id="siteHealthStatusBadge" class="badge">Disabled</span></div>
            <label class="check-row"><input id="siteHealthEnabled" type="checkbox"><span><strong>Enable origin health checks</strong><small class="muted">Checks run directly against the origin and do not pass through visitor access policies.</small></span></label>
            <div id="siteHealthSettings" class="site-form-grid hidden">
              <label class="site-origin-field"><span>Health-check path</span><input id="siteHealthPath" class="input" maxlength="2048" value="/health" placeholder="/health"><small class="muted">A GET request must return a 2xx response. Redirects are treated as failures.</small></label>
              <label><span>Check interval (seconds)</span><input id="siteHealthInterval" class="input" type="number" min="3" max="3600" value="10" required><small class="muted">Delay between scheduled probes of each enabled origin.</small></label>
              <label><span>Timeout (milliseconds)</span><input id="siteHealthTimeout" class="input" type="number" min="250" max="60000" value="3000" required><small class="muted">Maximum time allowed for one health-check response.</small></label>
              <label><span>Failures before unhealthy</span><input id="siteHealthFailureThreshold" class="input" type="number" min="1" max="20" value="3" required><small class="muted">Consecutive failed probes required to open an incident.</small></label>
              <label><span>Successes before recovery</span><input id="siteHealthRecoveryThreshold" class="input" type="number" min="1" max="20" value="2" required><small class="muted">Consecutive successful probes required to recover.</small></label>
              <label class="site-origin-field"><span>When unhealthy</span><select id="siteHealthFailureMode" class="select"><option value="monitor">Keep proxying and alert</option><option value="maintenance">Return the custom 503 maintenance page</option></select><small class="muted">Unknown and degraded states never block traffic.</small></label>
              <p id="siteHealthDetectionNotice" class="notice muted site-origin-field hidden"></p>
            </div>
            <div id="siteHealthRuntime" class="health-runtime hidden">
              <div class="health-summary-grid"><div><span class="muted">Last checked</span><strong id="siteHealthLastChecked">Never</strong></div><div><span class="muted">Last healthy</span><strong id="siteHealthLastHealthy">Never</strong></div><div><span class="muted">Response</span><strong id="siteHealthLastResponse">-</strong></div><div><span class="muted">Consecutive failures</span><strong id="siteHealthFailures">0</strong></div></div>
              <div class="row between responsive"><p id="siteHealthError" class="notice muted">No health check has run yet.</p><button id="siteCheckOriginNow" class="button secondary compact" type="button">Check now</button></div>
              <p class="muted">Latency and timed-out-check graphs are available from the chart selector on the Traffic tab, scoped to this site. Configure webhook alerts on the <a href="/_burrowgate/admin/notifications">Notifications</a> tab.</p>
              <div><strong>Recent state changes</strong><div id="siteHealthEvents" class="health-event-list"><p class="muted">No health state changes yet.</p></div></div>
            </div>
          </section>
          <section class="error-response-editor hidden" data-site-editor-panel="responses">
            <div class="section-heading error-response-heading"><div><h3>Error responses</h3><p class="muted">Customize errors generated by BurrowGate for this site.</p></div></div>
            <label><span>Response format</span><select id="siteErrorResponseMode" class="select"><option value="json">JSON</option><option value="html">HTML</option></select><small class="muted">Origin responses are not modified. This applies only to errors generated by BurrowGate.</small></label>
            <div id="siteErrorHtmlSettings" class="error-response-settings hidden">
              <div class="section-heading compact-heading"><div><h4>HTML template</h4><p class="muted">Placeholder values are HTML escaped before insertion.</p></div><button id="resetErrorHtmlTemplate" class="button secondary compact" type="button">Reset template</button></div>
              <textarea id="siteErrorHtmlTemplate" class="input code-input error-template-input" rows="22" spellcheck="false"></textarea>
              <div><strong>Available placeholders</strong><div id="errorPlaceholderList" class="placeholder-list"></div></div>
            </div>
            <div id="siteErrorJsonSettings" class="error-response-settings">
              <div><h4>JSON response fields</h4><p class="muted">Select the fields BurrowGate may include. Optional fields are omitted when they have no value.</p></div>
              <div id="errorJsonFieldList" class="json-field-grid"></div>
            </div>
          </section>
					<section class="error-response-editor hidden" data-site-editor-panel="responses">
						<div class="section-heading error-response-heading"><div><h3>Challenge page</h3><p class="muted">Customize the browser-verification page shown before a visitor receives a session.</p></div></div>
						<div class="error-response-settings">
							<div class="section-heading compact-heading"><div><h4>HTML template</h4><p class="muted">Placeholder values are HTML escaped. {{challengeScript}} is required.</p></div><button id="resetChallengeHtmlTemplate" class="button secondary compact" type="button">Reset template</button></div>
							<textarea id="siteChallengeHtmlTemplate" class="input code-input error-template-input" rows="22" spellcheck="false"></textarea>
							<div><strong>Available placeholders</strong><div id="challengePlaceholderList" class="placeholder-list"></div></div>
						</div>
					</section>
          <div id="generatedSecretPanel" class="secret-panel hidden"><div><strong>Save this origin signing secret</strong><p class="muted">BurrowGate will not display it again. Configure it on the protected origin to verify signed headers.</p><code id="generatedSecretValue"></code></div><button id="copyGeneratedSecret" class="button secondary" type="button">Copy</button></div>
          <div id="siteFormActions" class="row site-form-actions"><span id="siteSaveHint" class="muted">Save applies changes from every settings tab.</span><button id="saveSite" class="button" type="submit">Create</button><button id="resetSiteForm" class="button secondary" type="button">Reset</button><button id="deleteSite" class="button danger hidden" type="button">Delete site</button></div>
        </form>
        <section id="siteTlsPanel" class="tls-panel error-response-editor hidden" data-site-editor-panel="tls">
          <div class="section-heading error-response-heading tls-heading"><div><h3>HTTPS and certificates</h3><p class="muted">Terminate HTTPS directly in BurrowGate using an uploaded certificate or ACME HTTP-01.</p></div><span id="tlsStatusBadge" class="badge">Not configured</span></div>
          <div class="tls-summary-grid">
            <div><span class="muted">Mode</span><strong id="tlsSummaryMode">Disabled</strong></div>
            <div><span class="muted">Certificate</span><strong id="tlsSummaryCertificate">None</strong></div>
            <div><span class="muted">Expires</span><strong id="tlsSummaryExpires">-</strong></div>
            <div><span class="muted">Issuer</span><strong id="tlsSummaryIssuer">-</strong></div>
          </div>
          <p id="tlsListenerNotice" class="notice muted"></p>
          <p id="tlsLastError" class="badge bad hidden"></p>

          <form id="tlsSettingsForm" class="tls-form">
            <h3>HTTPS behavior</h3>
            <div class="site-form-grid">
              <label><span>TLS mode</span><select id="tlsMode" class="select"><option value="disabled">Disabled</option><option value="uploaded">Uploaded certificate</option><option value="letsencrypt">Let's Encrypt</option></select></label>
              <label class="check-row compact-check"><input id="tlsForceHttps" type="checkbox"><span><strong>Force HTTPS</strong><small class="muted">Redirect ordinary HTTP requests with status 308. ACME challenges remain available on HTTP.</small></span></label>
            </div>
            <button id="saveTlsSettings" class="button secondary" type="submit">Save HTTPS settings</button>
          </form>

          <div class="tls-method-grid">
            <form id="acmeForm" class="tls-method">
              <div><h3>Automatic certificate</h3><p class="muted">Issue and renew through an ACME provider using HTTP-01 on public port 80.</p></div>
              <label><span>Contact email</span><input id="acmeEmail" class="input" type="email" autocomplete="email" placeholder="admin@example.com" required></label>
              <label><span>ACME directory URL</span><input id="acmeDirectoryUrl" class="input" type="url" required></label>
              <label class="check-row compact-check"><input id="acmeForceHttps" type="checkbox" checked><span><strong>Force HTTPS after issuance</strong></span></label>
              <label class="check-row compact-check"><input id="acmeTermsAccepted" type="checkbox" required><span><strong>I accept the ACME provider's terms of service</strong></span></label>
              <div class="row responsive"><button id="requestAcmeCertificate" class="button" type="submit">Request certificate</button><button id="renewAcmeCertificate" class="button secondary hidden" type="button">Renew now</button></div>
              <p id="acmeEnvironmentWarning" class="notice muted"></p>
            </form>

            <form id="uploadCertificateForm" class="tls-method">
              <div><h3>Uploaded certificate</h3><p class="muted">Paste a PEM certificate chain and its matching private key. The private key is encrypted before storage.</p></div>
              <label><span>Certificate / full chain PEM</span><textarea id="uploadedCertificatePem" class="input code-input" rows="8" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----" required></textarea></label>
              <label><span>Private key PEM</span><textarea id="uploadedPrivateKeyPem" class="input code-input" rows="8" spellcheck="false" placeholder="-----BEGIN PRIVATE KEY-----" required></textarea></label>
              <label class="check-row compact-check"><input id="uploadedForceHttps" type="checkbox"><span><strong>Force HTTPS after upload</strong></span></label>
              <button id="uploadCertificate" class="button" type="submit">Upload and activate</button>
            </form>
          </div>

          <div class="tls-actions"><button id="removeCertificate" class="button danger hidden" type="button">Remove certificate</button></div>
          <div><h3>Certificate activity</h3><div id="certificateEvents" class="certificate-events"><p class="muted">No certificate activity yet.</p></div></div>
        </section>
      </div>
    </article>
  </div>
</section>
<div id="modal-users" class="modal-overlay hidden" data-modal="users">
  <div class="modal modal-large">
    <div class="modal-header"><h2>Users</h2><button class="button secondary icon-button modal-close" type="button" data-modal-close aria-label="Close">&times;</button></div>
    <div class="modal-body">
      <article class="card user-create-card">
        <div class="pad section-heading"><div><h2>Add a user</h2><p class="muted">New accounts must enroll two-factor authentication on first login.</p></div></div>
        <div class="pad pad-topless"><form id="userForm" class="form-row"><label><span>Username</span><input class="input" name="username" autocomplete="off" required></label><label><span>Password</span><input class="input" type="password" name="password" autocomplete="new-password" required></label><label><span>Role</span><select class="select" name="role"><option value="member">Member</option><option value="administrator">Administrator</option></select></label><button class="button align-end" type="submit">Add user</button></form></div>
      </article>
      <article class="card users-list-card">
        <div class="pad section-heading"><div><h2>Users</h2><p class="muted">Administrators have full access. Members need explicit Viewer or Manager permission per site and stream.</p></div><button id="refreshUsers" class="button secondary">Refresh</button></div>
        <div class="table-wrap"><table class="table"><thead><tr><th>Username</th><th>Role</th><th>2FA</th><th>Enabled</th><th>Permissions</th><th></th></tr></thead><tbody id="users"><tr><td colspan="6" class="empty-cell">Open Users to load accounts.</td></tr></tbody></table></div>
      </article>
      <article id="userPermissionsCard" class="card user-permissions-card hidden">
        <div class="pad section-heading"><div><h2 id="userPermissionsTitle">Permissions</h2><p class="muted">Grant Viewer for read-only access, or Manager to allow configuration changes. Administrator accounts always have full access.</p></div><button id="closeUserPermissions" class="button secondary" type="button">Close</button></div>
        <div class="pad pad-topless">
          <h3>Sites</h3>
          <div id="userSitePermissions" class="permissions-grid"></div>
          <h3>Streams</h3>
          <div id="userStreamPermissions" class="permissions-grid"></div>
          <div class="row align-end"><button id="saveUserPermissions" class="button" type="button">Save permissions</button></div>
        </div>
      </article>
    </div>
  </div>
</div>

<div id="modal-audit" class="modal-overlay hidden" data-modal="audit">
  <div class="modal modal-large">
    <div class="modal-header"><h2>Audit log</h2><button class="button secondary icon-button modal-close" type="button" data-modal-close aria-label="Close">&times;</button></div>
    <div class="modal-body">
      <article class="card">
        <div class="pad section-heading"><div><p class="muted">Every admin change is recorded with the acting user, IP, and a summary. Entries can only be purged, never edited.</p></div><div class="row"><button id="purgeAuditLog" class="button danger" type="button">Purge</button><button id="refreshAuditLog" class="button secondary">Refresh</button></div></div>
        <div class="toolbar compact-toolbar">
          <label class="search-field"><span>Search</span><input id="auditSearch" class="input" placeholder="Actor, summary, action..."></label>
          <label><span>Rows</span><select id="auditPageSize" class="select page-size"><option>25</option><option selected>50</option><option>100</option><option>200</option></select></label>
        </div>
        <div class="table-wrap"><table class="table"><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Resource</th><th>Summary</th><th>IP</th></tr></thead><tbody id="auditLog"><tr><td colspan="6" class="empty-cell">Open the audit log to load entries.</td></tr></tbody></table></div>
        ${pagination("auditLog")}
      </article>
    </div>
  </div>
</div>

<div id="modal-sso" class="modal-overlay hidden" data-modal="sso">
  <div class="modal">
    <div class="modal-header"><h2>Dashboard single sign-on</h2><button class="button secondary icon-button modal-close" type="button" data-modal-close aria-label="Close">&times;</button></div>
    <div class="modal-body">
      <article class="card">
        <div class="pad section-heading"><div><h2>OpenID Connect</h2><p class="muted">Let dashboard users sign in through an external identity provider (Authentik, Keycloak, Authelia, Microsoft ADFS, Azure/Entra ID, Okta, Duo, ...). New accounts are provisioned with the Member role and no permissions until an administrator grants access.</p></div><button id="saveAdminSso" class="button" type="button">Save</button></div>
        <div class="pad pad-topless grid">
          <label class="check-row"><input id="adminSsoEnabled" type="checkbox"><span><strong>Enable single sign-on</strong><small class="muted">Adds a "Sign in with SSO" option to the dashboard login page.</small></span></label>
          <label class="check-row"><input id="adminSsoEnforce" type="checkbox"><span><strong>Require single sign-on</strong><small class="muted">Hides the password form by default. A "Use a local account instead" link always remains available so administrators cannot be locked out.</small></span></label>
          <div class="site-form-grid">
            <label><span>Issuer URL</span><input id="adminSsoIssuer" class="input" type="url" placeholder="https://login.example.com/oauth2/default"><small class="muted">BurrowGate fetches <code>/.well-known/openid-configuration</code> from this URL.</small></label>
            <label><span>Client ID</span><input id="adminSsoClientId" class="input" autocomplete="off"></label>
            <label><span>Client secret</span><input id="adminSsoClientSecret" class="input" type="password" autocomplete="new-password" placeholder="Leave blank to keep current"><small id="adminSsoSecretStatus" class="muted">No client secret is configured.</small></label>
            <label><span>Scopes</span><input id="adminSsoScopes" class="input" value="openid email profile"></label>
            <label><span>Button label</span><input id="adminSsoButtonLabel" class="input" value="Single sign-on"></label>
          </div>
          <p class="notice muted">Redirect URI to register at the identity provider: <code id="adminSsoRedirectUri"></code></p>
          <p class="notice muted">Back-channel logout URI (keeps BurrowGate sessions in sync when the provider's session ends): <code id="adminSsoBackchannelUri"></code></p>
        </div>
      </article>
    </div>
  </div>
</div>

<div id="modal-account" class="modal-overlay hidden" data-modal="account">
  <div class="modal">
    <div class="modal-header"><h2>Account</h2><button class="button secondary icon-button modal-close" type="button" data-modal-close aria-label="Close">&times;</button></div>
    <div class="modal-body">
      <article class="card account-summary-card">
        <div class="pad section-heading"><div><h2>Your account</h2><p id="accountSummary" class="muted">-</p></div></div>
      </article>
      <article class="card account-password-card">
        <div class="pad"><h2>Change password</h2><form id="passwordForm" class="form-row"><label><span>Current password</span><input class="input" type="password" name="currentPassword" autocomplete="current-password" required></label><label><span>New password</span><input class="input" type="password" name="newPassword" autocomplete="new-password" required></label><button class="button align-end" type="submit">Change password</button></form></div>
      </article>
      <article class="card account-recovery-card">
        <div class="pad"><h2>Recovery codes</h2><p class="muted">Regenerating replaces all existing recovery codes and requires a current 6-digit code from your authenticator app.</p><form id="recoveryCodesForm" class="form-row"><label><span>6-digit code</span><input class="input" name="code" inputmode="numeric" maxlength="6" required></label><button class="button align-end" type="submit">Regenerate codes</button></form><ul id="newRecoveryCodes" class="totp-recovery-codes hidden"></ul></div>
      </article>
      <article class="card account-webauthn-card">
        <div class="pad"><h2>Security keys</h2><p class="muted">Register a hardware security key (e.g. a YubiKey) as an alternative to authenticator-app codes.</p><ul id="webauthnCredentialList" class="settings-list"></ul><button id="webauthnRegisterButton" class="button secondary" type="button">Register a security key</button></div>
      </article>
    </div>
  </div>
</div>

<div id="modal-event" class="modal-overlay hidden" data-modal="event">
  <div class="modal modal-xlarge">
    <div class="modal-header"><h2>Request detail</h2><button class="button secondary icon-button modal-close" type="button" data-modal-close aria-label="Close">&times;</button></div>
    <div class="modal-body">
      <div id="eventDetailBody">Loading...</div>
    </div>
  </div>
</div>
<div id="toast" class="toast hidden" role="status"></div>
</main><script src="/_burrowgate/static/chart.umd.js"></script><script type="module" src="/_burrowgate/static/admin.js"></script>`,
	);
}
