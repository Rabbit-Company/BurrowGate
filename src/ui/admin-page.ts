import { page } from "./layout.ts";

export function loginPage(error = ""): string {
	return page(
		"Admin login",
		`<main class="shell challenge"><section class="card pad auth-card"><div class="brand"><span class="mark"></span> BurrowGate</div><h1 class="auth-title">Dashboard login</h1>${error ? `<p class="badge bad auth-error">${error}</p>` : ""}<form method="post" action="/_burrowgate/admin/login" class="grid"><label>Username<input class="input" name="username" autocomplete="username"></label><label>Password<input class="input" type="password" name="password" autocomplete="current-password"></label><button class="button" type="submit">Sign in</button></form></section></main>`,
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
  <div><div class="brand"><span class="mark"></span> BurrowGate</div><p id="siteDescription" class="muted header-subtitle">Reverse proxy control plane</p></div>
  <div class="dashboard-controls">
    <label class="site-picker"><span>Protected site</span><select id="siteSelector" class="select"><option>Loading sites...</option></select></label>
    <div class="row dashboard-actions"><span id="lastUpdated" class="refresh-status">Loaded on demand</span><button id="refreshDashboard" class="button secondary" type="button">Refresh dashboard</button><button id="logout" class="button secondary">Log out</button></div>
  </div>
</header>

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
  <article class="card pad stat"><span class="muted">Active network rules</span><strong id="activeRules">-</strong></article>
</section>

<section class="grid charts-grid">
  <article class="card chart-card"><div class="pad"><h2 id="primaryChartTitle">Traffic volume</h2><p id="primaryChartSubtitle" class="muted">Requests, blocked requests, and origin errors</p></div><div class="chart-wrap"><div class="chart-canvas-container"><canvas id="trafficChart"></canvas></div><div id="trafficEmpty" class="empty-state hidden">No traffic in this range.</div></div></article>
  <article class="card chart-card"><div class="pad"><h2 id="secondaryChartTitle">Origin latency</h2><p id="secondaryChartSubtitle" class="muted">Average proxy response time per interval</p></div><div class="chart-wrap"><div class="chart-canvas-container"><canvas id="latencyChart"></canvas></div><div id="latencyEmpty" class="empty-state hidden">No latency data in this range.</div></div><div id="decisionBreakdown" class="breakdown"></div></article>
</section>

<section class="card geo-card">
  <div class="pad row between responsive">
    <div><h2>Geographic distribution</h2><p id="geoSubtitle" class="muted">Requests by country for the selected range</p></div>
    <select id="geoMetricMode" class="select select-small"><option value="requests">Requests</option><option value="sessions">Sessions</option></select>
  </div>
  <div class="geo-layout">
    <div class="geo-map-wrap">
      <svg id="geoMap" class="geo-map" role="img" aria-label="World map showing requests by country"></svg>
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

<nav class="tabs" aria-label="Dashboard sections">
  <button class="tab active" data-tab="traffic" type="button">Traffic</button>
  <button class="tab" data-tab="sessions" type="button">Sessions</button>
  <button class="tab" data-tab="rules" type="button">Network rules</button>
  <button class="tab" data-tab="routes" type="button">Routes</button>
  <button class="tab" data-tab="sites" type="button">Sites</button>
</nav>

<section id="panel-traffic" class="tab-panel">
  <article class="card">
    <div class="pad section-heading"><div><h2>Recent traffic</h2><p id="retentionNote" class="muted">Only a paginated result set is loaded.</p></div><button id="refreshTraffic" class="button secondary">Refresh</button></div>
    <div class="toolbar">
      <label class="search-field"><span>Search</span><input id="eventSearch" class="input" placeholder="IP, path, decision, session..."></label>
      <label><span>Decision</span><select id="eventDecision" class="select"><option value="">All</option><option value="proxied">HTTP verified</option><option value="proxied-unprotected">HTTP unprotected</option><option value="websocket-proxied">WebSocket verified</option><option value="websocket-unprotected">WebSocket unprotected</option><option value="blocked">IP blocked</option><option value="route-blocked">Route blocked</option><option value="rate-limited">Rate limited</option><option value="challenge-required">Challenge required</option><option value="allowlisted">HTTP allowlisted</option><option value="websocket-allowlisted">WebSocket allowlisted</option><option value="origin-error">HTTP origin error</option><option value="websocket-origin-error">WebSocket origin error</option><option value="websocket-upgrade-failed">WebSocket upgrade failed</option><option value="websocket-disabled">WebSocket disabled</option></select></label>
      <label><span>Method</span><select id="eventMethod" class="select"><option value="">All</option><option>GET</option><option>HEAD</option><option>POST</option><option>PUT</option><option>PATCH</option><option>DELETE</option><option>OPTIONS</option></select></label>
      <label><span>Status</span><select id="eventStatus" class="select"><option value="">All</option><option value="1xx">1xx</option><option value="2xx">2xx</option><option value="3xx">3xx</option><option value="4xx">4xx</option><option value="5xx">5xx</option></select></label>
      <label><span>Country</span><select id="eventCountry" class="select country-select"><option value="">All countries</option></select></label>
      <label><span>Rows</span><select id="eventPageSize" class="select page-size"><option>25</option><option selected>50</option><option>100</option><option>200</option></select></label>
    </div>
    <div class="table-wrap"><table class="table"><thead><tr><th>${sortButton("Time", "created_at")}</th><th>${sortButton("IP", "ip")}</th><th>${sortButton("Country", "country_code")}</th><th>${sortButton("Method", "method")}</th><th>${sortButton("Path", "path")}</th><th>${sortButton("Status", "status")}</th><th>${sortButton("Decision", "decision")}</th><th>${sortButton("Latency", "latency_ms")}</th></tr></thead><tbody id="events"><tr><td colspan="8" class="empty-cell">Loading...</td></tr></tbody></table></div>
    ${pagination("events")}
  </article>
</section>

<section id="panel-sessions" class="tab-panel hidden">
  <article class="card">
    <div class="pad section-heading"><div><h2>Active and recent sessions</h2><p class="muted"><span class="state-swatch active"></span>Active <span class="state-swatch expired"></span>Expired <span class="state-swatch revoked"></span>Revoked</p></div><button id="refreshSessions" class="button secondary">Refresh</button></div>
    <div class="toolbar compact-toolbar">
      <label class="search-field"><span>Search</span><input id="sessionSearch" class="input" placeholder="Session ID or IP..."></label>
      <label><span>State</span><select id="sessionState" class="select"><option value="">All</option><option value="active">Active</option><option value="expired">Expired</option><option value="revoked">Revoked</option></select></label>
      <label><span>Country</span><select id="sessionCountry" class="select country-select"><option value="">All countries</option></select></label>
      <label><span>Rows</span><select id="sessionPageSize" class="select page-size"><option>25</option><option selected>50</option><option>100</option><option>200</option></select></label>
    </div>
    <div class="table-wrap"><table class="table"><thead><tr><th>State</th><th>Session</th><th>${sortButton("Last IP", "last_ip")}</th><th>${sortButton("Country", "country_code")}</th><th>${sortButton("Created", "created_at")}</th><th>${sortButton("Last seen", "last_seen_at")}</th><th>${sortButton("Expires", "expires_at")}</th><th>${sortButton("Requests", "request_count")}</th><th></th></tr></thead><tbody id="sessions"><tr><td colspan="9" class="empty-cell">Open the tab to load sessions.</td></tr></tbody></table></div>
    ${pagination("sessions")}
  </article>
</section>

<section id="panel-rules" class="tab-panel hidden">
  <article class="card network-defaults-card">
    <div class="pad section-heading"><div><h2>Default network actions</h2><p class="muted">Explicit IP rules override country rules. Country rules override these defaults.</p></div><button id="saveNetworkDefaults" class="button" type="button">Save</button></div>
    <div class="network-defaults-grid pad-topless">
      <label><span>Default IP action</span><select id="defaultIpAction" class="select"><option value="inherit">Allow and follow route policy</option><option value="allow">Allow and bypass verification</option><option value="block">Block all IPs</option><option value="challenge">Require challenge</option></select><small class="muted">Set to Block all IPs and add Allow and follow route policy rules to create an IP whitelist.</small></label>
      <label><span>Default country action</span><select id="defaultCountryAction" class="select"><option value="inherit">Use IP default</option><option value="allow">Allow and bypass verification</option><option value="block">Block all countries</option><option value="challenge">Require challenge</option></select><small class="muted">Set to Block all countries and add Allow and follow route policy rules to create a country whitelist.</small></label>
    </div>
    <p id="geoPolicyWarning" class="notice muted hidden"></p>
  </article>

  <article class="card rule-create-card">
    <div class="pad"><h2>Add an IP rule</h2><form id="ruleForm" class="rule-form"><label><span>IP address or CIDR</span><input class="input" name="networkCidr" placeholder="203.0.113.4 or 203.0.113.0/24" required></label><label><span>Action</span><select class="select" name="action"><option value="block">Block</option><option value="pass">Allow and follow route policy</option><option value="allow">Allow and bypass verification</option><option value="challenge">Require challenge</option></select></label><label><span>Expires</span><input class="input" type="datetime-local" name="expiresAt"></label><label class="reason-field"><span>Reason</span><input class="input" name="reason" placeholder="Optional reason"></label><button class="button align-end" type="submit">Add rule</button></form></div>
  </article>
  <article class="card rules-list-card">
    <div class="pad section-heading"><div><h2>IP rules</h2><p class="muted">The longest matching CIDR wins. Explicit IP rules have the highest network-policy priority.</p></div><button id="refreshRules" class="button secondary">Refresh</button></div>
    <div class="toolbar compact-toolbar">
      <label class="search-field"><span>Search</span><input id="ruleSearch" class="input" placeholder="Network or reason..."></label>
      <label><span>Action</span><select id="ruleAction" class="select"><option value="">All</option><option value="pass">Allow and follow route</option><option value="allow">Allow and bypass</option><option value="block">Block</option><option value="challenge">Challenge</option></select></label>
      <label><span>State</span><select id="ruleState" class="select"><option value="">All</option><option value="active">Active</option><option value="expired">Expired</option></select></label>
      <label><span>Rows</span><select id="rulePageSize" class="select page-size"><option>25</option><option selected>50</option><option>100</option><option>200</option></select></label>
    </div>
    <div class="table-wrap"><table class="table"><thead><tr><th>State</th><th>${sortButton("Network", "network_cidr")}</th><th>${sortButton("Action", "action")}</th><th>Reason</th><th>${sortButton("Created", "created_at")}</th><th>${sortButton("Expires", "expires_at")}</th><th></th></tr></thead><tbody id="rules"><tr><td colspan="7" class="empty-cell">Open the tab to load rules.</td></tr></tbody></table></div>
    ${pagination("rules")}
  </article>

  <article class="card country-rule-card">
    <div class="pad"><h2>Add a country rule</h2><form id="countryRuleForm" class="country-rule-form"><label><span>Country</span><select id="countryRuleCountry" class="select country-select" name="countryCode" required><option value="">Select country</option></select></label><label><span>Action</span><select class="select" name="action"><option value="block">Block</option><option value="pass">Allow and follow route policy</option><option value="allow">Allow and bypass verification</option><option value="challenge">Require challenge</option></select></label><label><span>Expires</span><input class="input" type="datetime-local" name="expiresAt"></label><label class="reason-field"><span>Reason</span><input class="input" name="reason" placeholder="Optional reason"></label><button class="button align-end" type="submit">Add rule</button></form></div>
    <div class="table-wrap"><table class="table"><thead><tr><th>State</th><th>Country</th><th>Action</th><th>Reason</th><th>Created</th><th>Expires</th><th></th></tr></thead><tbody id="countryRules"><tr><td colspan="7" class="empty-cell">Open the tab to load country rules.</td></tr></tbody></table></div>
  </article>
</section>

<section id="panel-routes" class="tab-panel hidden">
  <div class="route-policy-layout">
    <article class="card route-policy-list-card">
      <div class="pad section-heading"><div><h2>Route policies</h2><p class="muted">The highest-priority matching policy controls access and rate limiting. IP blocks still apply globally.</p></div><div class="row"><button id="refreshRoutePolicies" class="button secondary" type="button">Refresh</button><button id="newRoutePolicy" class="button" type="button">Create</button></div></div>
      <div id="routePolicyList" class="route-policy-list"><div class="empty-state-inline">Open the tab to load route policies.</div></div>
    </article>
    <article class="card route-policy-editor-card">
      <div class="pad">
        <div class="section-heading"><div><h2 id="routePolicyFormTitle">Create route policy</h2><p id="routePolicyFormSubtitle" class="muted">Configure route-specific verification and API limits.</p></div><button id="cancelRoutePolicyEdit" class="button secondary compact hidden" type="button">Cancel edit</button></div>
        <form id="routePolicyForm" class="site-form">
          <input id="routePolicyId" type="hidden">
          <div class="site-form-grid">
            <label><span>Name</span><input id="routePolicyName" class="input" maxlength="255" placeholder="JSON API" required></label>
            <label><span>Path pattern</span><input id="routePolicyPath" class="input" maxlength="2048" value="/api/**" placeholder="/api/**" required><small class="muted"><code>*</code> matches one path segment; <code>**</code> matches across segments.</small></label>
            <label><span>HTTP methods</span><input id="routePolicyMethods" class="input" placeholder="GET, POST - blank means all"><small class="muted">Comma-separated. WebSocket upgrades use GET.</small></label>
            <label><span>Priority</span><input id="routePolicyPriority" class="input" type="number" min="-100000" max="100000" value="0"></label>
            <label><span>Access mode</span><select id="routePolicyAccessMode" class="select"><option value="inherit">Inherit site default</option><option value="challenge">Require challenge</option><option value="bypass">Bypass browser verification</option><option value="block">Block route</option></select></label>
          </div>
          <label class="check-row"><input id="routePolicyEnabled" type="checkbox" checked><span><strong>Policy enabled</strong><small class="muted">Disabled policies remain stored but do not match requests.</small></span></label>
          <div id="routeChallengeSettings">
            <label><span>Challenge policy override</span><textarea id="routePolicyChallenge" class="input code-input" rows="8" spellcheck="false" placeholder="Leave blank to inherit the site's challenge chain"></textarea><small id="routeChallengeHelp" class="muted">Only used when this route requires a challenge. A blank value inherits the site policy.</small></label>
          </div>
          <div class="policy-subsection">
            <label class="check-row"><input id="routeRateEnabled" type="checkbox"><span><strong>Enable rate limiting</strong><small class="muted">Rate limiting is independent of browser verification and works for JSON APIs and WebSocket handshakes. Counters are currently in-memory per BurrowGate process.</small></span></label>
            <div id="routeRateSettings" class="site-form-grid hidden">
              <label><span>Algorithm</span><select id="routeRateAlgorithm" class="select"><option value="sliding-window">Sliding window</option><option value="fixed-window">Fixed window</option><option value="token-bucket">Token bucket</option></select></label>
              <label><span>Maximum / capacity</span><input id="routeRateMax" class="input" type="number" min="1" max="1000000" value="120"></label>
              <label class="window-setting"><span>Window (milliseconds)</span><input id="routeRateWindow" class="input" type="number" min="100" max="86400000" value="60000"></label>
              <label class="precision-setting"><span>Precision (milliseconds)</span><input id="routeRatePrecision" class="input" type="number" min="10" max="60000" value="100"></label>
              <label class="token-setting hidden"><span>Refill tokens</span><input id="routeRateRefillRate" class="input" type="number" min="1" max="1000000" value="10"></label>
              <label class="token-setting hidden"><span>Refill interval (milliseconds)</span><input id="routeRateRefillInterval" class="input" type="number" min="10" max="86400000" value="1000"></label>
              <label><span>Client identity</span><select id="routeRateKeyMode" class="select"><option value="ip">IP address</option><option value="session-or-ip">Verified session, otherwise IP</option><option value="header-or-ip">Header value, otherwise IP</option></select></label>
              <label id="routeRateHeaderField" class="hidden"><span>Identity header</span><input id="routeRateKeyHeader" class="input" placeholder="x-api-key"><small class="muted">The value is hashed before it becomes an in-memory key. Use only a stable credential that your application validates; clients can rotate arbitrary header values.</small></label>
              <label><span>Counter scope</span><select id="routeRateScope" class="select"><option value="policy">Shared across this policy</option><option value="path">Separate per exact path</option><option value="method-path">Separate per method and path</option></select></label>
            </div>
          </div>
          <div class="row site-form-actions"><button id="saveRoutePolicy" class="button" type="submit">Create</button><button id="resetRoutePolicyForm" class="button secondary" type="button">Reset</button></div>
        </form>
      </div>
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
        <form id="siteForm" class="site-form">
          <input id="siteId" type="hidden">
          <div class="site-form-grid">
            <label><span>Site name</span><input id="siteName" class="input" name="name" maxlength="255" placeholder="Main website" required></label>
            <label><span>Public host</span><input id="sitePublicHost" class="input" name="publicHost" maxlength="255" placeholder="example.com or localhost" required><small class="muted">Hostname and optional port, without a scheme or path.</small></label>
            <label class="site-origin-field"><span>Origin URL</span><input id="siteOriginUrl" class="input" name="originUrl" type="url" placeholder="http://127.0.0.1:3000" required><small class="muted">HTTP or HTTPS origin. A path prefix is supported.</small></label>
            <label><span>Session lifetime (seconds)</span><input id="siteSessionTtl" class="input" name="sessionTtlSeconds" type="number" min="60" max="2592000" step="1" value="43200" required></label>
            <label><span>Traffic retention (days)</span><input id="siteEventRetentionDays" class="input" name="eventRetentionDays" type="number" min="1" max="365" step="1" value="7" required><small class="muted">Request events older than this are removed for this site.</small></label>
            <label><span>Default access mode</span><select id="siteDefaultAccessMode" class="select"><option value="challenge">Require challenge</option><option value="bypass">Disable browser verification</option></select><small class="muted">Route policies can override this per path.</small></label>
          </div>
          <label class="check-row"><input id="siteEnabled" name="enabled" type="checkbox" checked><span><strong>Site enabled</strong><small class="muted">Disabled sites stop matching incoming requests but keep their stored data.</small></span></label>
          <label><span>Origin signing secret</span><div class="secret-row"><input id="siteSigningSecret" class="input" name="originSigningSecret" type="password" autocomplete="new-password" placeholder="Generated automatically for new sites"><button id="generateSiteSecret" class="button secondary" type="button">Generate</button></div><small id="siteSecretHelp" class="muted">Leave blank to generate a secure secret. The generated value is shown once after creation.</small></label>
          <label><span>Challenge policy</span><textarea id="siteChallengePolicy" class="input code-input" name="challengePolicy" rows="11" spellcheck="false" required></textarea><small id="challengeProviderHelp" class="muted">Ordered JSON array. Each provider is completed before the visitor receives a session.</small></label>
          <section class="error-response-editor">
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
					<section class="error-response-editor">
						<div class="section-heading error-response-heading"><div><h3>Challenge page</h3><p class="muted">Customize the browser-verification page shown before a visitor receives a session.</p></div></div>
						<div class="error-response-settings">
							<div class="section-heading compact-heading"><div><h4>HTML template</h4><p class="muted">Placeholder values are HTML escaped. {{challengeScript}} is required.</p></div><button id="resetChallengeHtmlTemplate" class="button secondary compact" type="button">Reset template</button></div>
							<textarea id="siteChallengeHtmlTemplate" class="input code-input error-template-input" rows="22" spellcheck="false"></textarea>
							<div><strong>Available placeholders</strong><div id="challengePlaceholderList" class="placeholder-list"></div></div>
						</div>
					</section>
          <div id="generatedSecretPanel" class="secret-panel hidden"><div><strong>Save this origin signing secret</strong><p class="muted">BurrowGate will not display it again. Configure it on the protected origin to verify signed headers.</p><code id="generatedSecretValue"></code></div><button id="copyGeneratedSecret" class="button secondary" type="button">Copy</button></div>
          <div class="row site-form-actions"><button id="saveSite" class="button" type="submit">Create</button><button id="resetSiteForm" class="button secondary" type="button">Reset</button></div>
        </form>
        <section id="siteTlsPanel" class="tls-panel hidden">
          <div class="section-heading tls-heading"><div><h2>TLS certificate</h2><p class="muted">Terminate HTTPS directly in BurrowGate using an uploaded certificate or ACME HTTP-01.</p></div><span id="tlsStatusBadge" class="badge">Not configured</span></div>
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
<div id="toast" class="toast hidden" role="status"></div>
</main><script src="/_burrowgate/static/chart.umd.js"></script><script type="module" src="/_burrowgate/static/admin.js"></script>`,
	);
}
