import { page, tablerIcon } from "./layout.ts";

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
  <div><div class="brand"><span class="mark"></span> BurrowGate</div><nav class="dashboard-switch" aria-label="Dashboard"><a class="active" href="/_burrowgate/admin">Web Proxy</a><a href="/_burrowgate/admin/streams">Streams</a></nav><p id="siteDescription" class="muted header-subtitle">Reverse proxy control plane</p></div>
  <div class="dashboard-controls">
    <label class="site-picker"><span>Protected site</span><select id="siteSelector" class="select"><option>Loading sites...</option></select></label>
    <label class="site-picker"><span>Date format</span><select id="dateTimeFormat" class="select"><option value="iso-24" selected>YYYY-MM-DD HH:mm:ss</option><option value="dmy-24">DD/MM/YYYY HH:mm:ss</option><option value="mdy-12">MM/DD/YYYY hh:mm:ss AM/PM</option><option value="browser">Browser default</option></select></label>
    <div class="row dashboard-actions"><span id="lastUpdated" class="refresh-status">Loaded on demand</span><button id="refreshDashboard" class="button secondary icon-button" type="button" aria-label="Refresh dashboard" title="Refresh dashboard">${tablerIcon("refresh")}</button><button id="logout" class="button secondary icon-button" type="button" aria-label="Log out" title="Log out">${tablerIcon("logout")}</button></div>
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
  <article class="card pad stat"><span class="muted">Active network rules</span><strong id="activeRules">-</strong></article>
</section>

<section class="grid charts-grid">
  <article class="card chart-card"><div class="pad"><h2 id="primaryChartTitle">Traffic volume</h2><p id="primaryChartSubtitle" class="muted">Requests, blocked requests, and origin errors</p></div><div class="chart-wrap"><div class="chart-canvas-container"><canvas id="trafficChart"></canvas></div><div id="trafficEmpty" class="empty-state hidden">No traffic in this range.</div></div></article>
  <article class="card chart-card"><div class="pad"><h2 id="secondaryChartTitle">Origin latency</h2><p id="secondaryChartSubtitle" class="muted">Average proxy response time per interval</p></div><div class="chart-wrap"><div class="chart-canvas-container"><canvas id="latencyChart"></canvas></div><div id="latencyEmpty" class="empty-state hidden">No latency data in this range.</div></div><div id="decisionBreakdown" class="breakdown"></div></article>
</section>

<section class="card geo-card">
  <div class="pad row between responsive">
    <div><h2>Geographic distribution</h2><p id="geoSubtitle" class="muted">Requests by country for the selected range</p></div>
    <select id="geoMetricMode" class="select select-small"><option value="requests">Requests</option><option value="sessions">Sessions</option><option value="bandwidth">Client bandwidth</option></select>
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
  <button class="tab" data-tab="bandwidth" type="button">Bandwidth</button>
  <button class="tab" data-tab="sessions" type="button">Sessions</button>
  <button class="tab" data-tab="rules" type="button">Network rules</button>
  <button class="tab" data-tab="routes" type="button">Routes</button>
  <button class="tab" data-tab="access" type="button">Access List</button>
  <button class="tab" data-tab="sites" type="button">Sites</button>
</nav>

<section id="panel-traffic" class="tab-panel">
  <article class="card">
    <div class="pad section-heading"><div><h2>Recent traffic</h2><p id="retentionNote" class="muted">Only a paginated result set is loaded.</p></div><button id="refreshTraffic" class="button secondary">Refresh</button></div>
    <div class="toolbar traffic-toolbar">
      <label class="search-field"><span>Search</span><input id="eventSearch" class="input" placeholder="IP, path, decision, session..."></label>
      <label><span>Decision</span><select id="eventDecision" class="select"><option value="">All</option><option value="proxied">HTTP verified</option><option value="proxied-authenticated">HTTP user authenticated</option><option value="proxied-unprotected">HTTP unprotected</option><option value="websocket-proxied">WebSocket verified</option><option value="websocket-authenticated">WebSocket user authenticated</option><option value="websocket-unprotected">WebSocket unprotected</option><option value="access-login-required">User login required</option><option value="access-login-failed">User login failed</option><option value="access-login-rate-limited">User login rate limited</option><option value="access-authenticated">User login succeeded</option><option value="blocked">IP blocked</option><option value="route-blocked">Route blocked</option><option value="rate-limited">Rate limited</option><option value="challenge-required">Challenge required</option><option value="allowlisted">HTTP allowlisted</option><option value="websocket-allowlisted">WebSocket allowlisted</option><option value="origin-unhealthy">Origin health maintenance</option><option value="origin-pool-unavailable">Origin pool unavailable</option><option value="origin-error">HTTP origin error</option><option value="websocket-origin-error">WebSocket origin error</option><option value="websocket-upgrade-failed">WebSocket upgrade failed</option><option value="websocket-disabled">WebSocket disabled</option></select></label>
      <label><span>Method</span><select id="eventMethod" class="select"><option value="">All</option><option>GET</option><option>HEAD</option><option>POST</option><option>PUT</option><option>PATCH</option><option>DELETE</option><option>OPTIONS</option></select></label>
      <label><span>Status</span><select id="eventStatus" class="select"><option value="">All</option><option value="1xx">1xx</option><option value="2xx">2xx</option><option value="3xx">3xx</option><option value="4xx">4xx</option><option value="5xx">5xx</option></select></label>
      <label><span>Origin</span><select id="eventOrigin" class="select"><option value="">All origins</option></select></label>
      <label><span>Country</span><select id="eventCountry" class="select country-select"><option value="">All countries</option></select></label>
      <label><span>Rows</span><select id="eventPageSize" class="select page-size"><option>25</option><option selected>50</option><option>100</option><option>200</option></select></label>
    </div>
    <div class="table-wrap"><table class="table"><thead><tr><th>${sortButton("Time", "created_at")}</th><th>${sortButton("IP", "ip")}</th><th>${sortButton("Country", "country_code")}</th><th>${sortButton("Method", "method")}</th><th>${sortButton("Path", "path")}</th><th>Origin</th><th>${sortButton("Status", "status")}</th><th>${sortButton("Decision", "decision")}</th><th>${sortButton("Latency", "latency_ms")}</th></tr></thead><tbody id="events"><tr><td colspan="9" class="empty-cell">Loading...</td></tr></tbody></table></div>
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
    <div class="pad section-heading"><div><h2>Client bandwidth by IP</h2><p class="muted">HTTP and WebSocket payload bytes are counted. HTTP/TLS headers and transport framing are intentionally excluded.</p></div><button id="refreshBandwidth" class="button secondary">Refresh</button></div>
    <div class="toolbar bandwidth-toolbar">
      <label class="search-field"><span>Search</span><input id="bandwidthSearch" class="input" placeholder="IP or country code..."></label>
      <label><span>Protocol</span><select id="bandwidthProtocol" class="select"><option value="">All</option><option value="http">HTTP</option><option value="websocket">WebSocket</option></select></label>
      <label><span>Country</span><select id="bandwidthCountry" class="select country-select"><option value="">All countries</option></select></label>
      <label><span>Rows</span><select id="bandwidthPageSize" class="select page-size"><option>25</option><option selected>50</option><option>100</option><option>200</option></select></label>
    </div>
    <div class="table-wrap"><table class="table"><thead><tr><th>${sortButton("IP", "ip")}</th><th>${sortButton("Country", "country_code")}</th><th>${sortButton("To client", "client_sent_bytes")}</th><th>${sortButton("From client", "client_received_bytes")}</th><th>${sortButton("From origin", "upstream_received_bytes")}</th><th>${sortButton("To origin", "upstream_sent_bytes")}</th><th>${sortButton("Client total", "client_total_bytes")}</th><th>${sortButton("Upstream total", "upstream_total_bytes")}</th><th></th></tr></thead><tbody id="bandwidthIps"><tr><td colspan="9" class="empty-cell">Open the tab to load bandwidth.</td></tr></tbody></table></div>
    ${pagination("bandwidth")}
    <div id="bandwidthProtocols" class="breakdown"></div>
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
          <div class="policy-subsection">
            <label class="check-row"><input id="routeRateEnabled" type="checkbox"><span><strong>Enable rate limiting</strong><small class="muted">Rate limiting is independent of browser verification and works for JSON APIs and WebSocket handshakes. Counters are currently in-memory per BurrowGate process.</small></span></label>
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
          </div>
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
        <form id="originValidationForm"></form>
        <form id="siteForm" class="site-form">
          <input id="siteId" type="hidden">
          <div class="site-form-grid">
            <label><span>Site name</span><input id="siteName" class="input" name="name" maxlength="255" placeholder="Main website" required><small class="muted">A friendly name used throughout the admin dashboard.</small></label>
            <label><span>Public host</span><input id="sitePublicHost" class="input" name="publicHost" maxlength="255" placeholder="example.com or localhost" required><small class="muted">Hostname and optional port, without a scheme or path.</small></label>
            <label class="site-origin-field"><span>Origin URL</span><input id="siteOriginUrl" class="input" name="originUrl" type="url" placeholder="http://127.0.0.1:3000" required><small class="muted">HTTP or HTTPS origin. A path prefix is supported.</small></label>
            <label><span>Session lifetime (seconds)</span><input id="siteSessionTtl" class="input" name="sessionTtlSeconds" type="number" min="60" max="2592000" step="1" value="43200" required><small class="muted">How long a verified visitor session remains valid.</small></label>
            <label><span>Traffic retention (days)</span><input id="siteEventRetentionDays" class="input" name="eventRetentionDays" type="number" min="1" max="365" step="1" value="7" required><small class="muted">Request events and bandwidth buckets older than this are removed for this site.</small></label>
            <label><span>Default access mode</span><select id="siteDefaultAccessMode" class="select"><option value="challenge">Require challenge</option><option value="bypass">Disable browser verification</option></select><small class="muted">Route policies can override this per path.</small></label>
          </div>
          <label class="check-row"><input id="siteEnabled" name="enabled" type="checkbox" checked><span><strong>Site enabled</strong><small class="muted">Disabled sites stop matching incoming requests but keep their stored data.</small></span></label>
          <label><span>Origin signing secret</span><div class="secret-row"><input id="siteSigningSecret" class="input" name="originSigningSecret" type="password" autocomplete="new-password" placeholder="Generated automatically for new sites"><button id="generateSiteSecret" class="button secondary" type="button">Generate</button></div><small id="siteSecretHelp" class="muted">Leave blank to generate a secure secret. The generated value is shown once after creation.</small></label>
          <label><span>Challenge policy</span><textarea id="siteChallengePolicy" class="input code-input" name="challengePolicy" rows="11" spellcheck="false" required></textarea><small id="challengeProviderHelp" class="muted">Ordered JSON array. Each provider is completed before the visitor receives a session.</small></label>
          <section class="error-response-editor">
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
          <section class="error-response-editor origin-health-editor">
            <div class="section-heading error-response-heading"><div><h3>Origin health</h3><p class="muted">Probe a path on the configured origin and optionally fail fast with the site error page.</p></div><span id="siteHealthStatusBadge" class="badge">Disabled</span></div>
            <label class="check-row"><input id="siteHealthEnabled" type="checkbox"><span><strong>Enable origin health checks</strong><small class="muted">Checks run directly against the origin and do not pass through visitor access policies.</small></span></label>
            <div id="siteHealthSettings" class="site-form-grid hidden">
              <label class="site-origin-field"><span>Health-check path</span><input id="siteHealthPath" class="input" maxlength="2048" value="/health" placeholder="/health"><small class="muted">A GET request must return a 2xx response. Redirects are treated as failures.</small></label>
              <label><span>Check interval (seconds)</span><input id="siteHealthInterval" class="input" type="number" min="10" max="3600" value="30" required><small class="muted">Delay between scheduled probes of each enabled origin.</small></label>
              <label><span>Timeout (milliseconds)</span><input id="siteHealthTimeout" class="input" type="number" min="250" max="60000" value="3000" required><small class="muted">Maximum time allowed for one health-check response.</small></label>
              <label><span>Failures before unhealthy</span><input id="siteHealthFailureThreshold" class="input" type="number" min="1" max="20" value="3" required><small class="muted">Consecutive failed probes required to open an incident.</small></label>
              <label><span>Successes before recovery</span><input id="siteHealthRecoveryThreshold" class="input" type="number" min="1" max="20" value="2" required><small class="muted">Consecutive successful probes required to recover.</small></label>
              <label class="site-origin-field"><span>When unhealthy</span><select id="siteHealthFailureMode" class="select"><option value="monitor">Keep proxying and alert</option><option value="maintenance">Return the custom 503 maintenance page</option></select><small class="muted">Unknown and degraded states never block traffic.</small></label>
            </div>
            <div id="siteHealthRuntime" class="health-runtime hidden">
              <div class="health-summary-grid"><div><span class="muted">Last checked</span><strong id="siteHealthLastChecked">Never</strong></div><div><span class="muted">Last healthy</span><strong id="siteHealthLastHealthy">Never</strong></div><div><span class="muted">Response</span><strong id="siteHealthLastResponse">-</strong></div><div><span class="muted">Consecutive failures</span><strong id="siteHealthFailures">0</strong></div></div>
              <div class="row between responsive"><p id="siteHealthError" class="notice muted">No health check has run yet.</p><button id="siteCheckOriginNow" class="button secondary compact" type="button">Check now</button></div>
              <div><strong>Recent state changes</strong><div id="siteHealthEvents" class="health-event-list"><p class="muted">No health state changes yet.</p></div></div>
            </div>
          </section>
          <section class="error-response-editor">
            <div class="section-heading error-response-heading"><div><h3>Health alerts</h3><p class="muted">Send one alert when an incident opens and one when it recovers. Failed deliveries retry with backoff.</p></div></div>
            <label class="check-row"><input id="siteHealthAlertsEnabled" type="checkbox"><span><strong>Enable webhook alerts</strong><small id="siteHealthWebhookConfigured" class="muted">No webhook is configured.</small></span></label>
            <div id="siteHealthAlertSettings" class="site-form-grid hidden">
              <label><span>Webhook type</span><select id="siteHealthAlertProvider" class="select"><option value="generic">Generic JSON</option><option value="slack">Slack</option><option value="discord">Discord</option><option value="ntfy">ntfy</option></select><small class="muted">Formats alert payloads for the selected destination.</small></label>
              <label><span>Webhook URL</span><input id="siteHealthWebhookUrl" class="input" type="url" autocomplete="off" placeholder="https://alerts.example/hooks/..."><small class="muted">Leave blank while editing to keep the encrypted destination.</small></label>
              <label><span>Generic webhook signing secret</span><input id="siteHealthWebhookSecret" class="input" type="password" autocomplete="new-password" maxlength="4096" placeholder="Optional"><small class="muted">Adds an HMAC SHA-256 signature header. Leave blank to keep the current secret.</small></label>
              <label id="siteHealthClearWebhookRow" class="check-row compact-check hidden"><input id="siteHealthClearWebhook" type="checkbox"><span><strong>Remove stored webhook</strong><small class="muted">Alerts will be disabled when this site is saved.</small></span></label>
            </div>
            <div id="siteHealthAlertRuntime" class="health-runtime hidden"><strong>Recent alert deliveries</strong><div id="siteHealthAlertDeliveries" class="health-event-list"><p class="muted">No alerts have been queued.</p></div></div>
          </section>
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
          <div class="row site-form-actions"><button id="saveSite" class="button" type="submit">Create</button><button id="resetSiteForm" class="button secondary" type="button">Reset</button><button id="deleteSite" class="button danger hidden" type="button">Delete site</button></div>
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
