import { page, tablerIcon } from "./layout.ts";

function pagination(id: string): string {
	return `<div class="pagination"><span id="${id}Summary" class="muted">-</span><div class="row"><button id="${id}Previous" class="button secondary compact" type="button">Previous</button><span id="${id}Page" class="page-number">Page 1</span><button id="${id}Next" class="button secondary compact" type="button">Next</button></div></div>`;
}

function sortButton(label: string, key: string): string {
	return `<button class="sort-button" data-sort="${key}" type="button">${label}<span aria-hidden="true"></span></button>`;
}

export function streamsAdminPage(): string {
	return page(
		"Streams",
		`<main class="shell dashboard-shell">
<header class="row between responsive dashboard-header">
  <div><div class="brand"><span class="mark"></span> BurrowGate</div><nav class="dashboard-switch" aria-label="Dashboard"><a href="/_burrowgate/admin">Web Proxy</a><a class="active" href="/_burrowgate/admin/streams">Streams</a></nav><p class="muted header-subtitle">TCP and UDP stream proxy control plane</p></div>
  <div class="dashboard-controls"><label class="site-picker"><span>Stream</span><select id="streamSelector" class="select"><option value="">All streams</option></select></label><label class="site-picker"><span>Date format</span><select id="dateTimeFormat" class="select"><option value="iso-24" selected>YYYY-MM-DD HH:mm:ss</option><option value="dmy-24">DD/MM/YYYY HH:mm:ss</option><option value="mdy-12">MM/DD/YYYY hh:mm:ss AM/PM</option><option value="browser">Browser default</option></select></label><div class="row dashboard-actions"><span id="lastUpdated" class="refresh-status">Loaded on demand</span><button id="openUsers" class="button secondary icon-button hidden" type="button" aria-label="Users" title="Users">${tablerIcon("users")}</button><button id="openSso" class="button secondary icon-button hidden" type="button" aria-label="Single sign-on" title="Single sign-on">${tablerIcon("key")}</button><button id="openAudit" class="button secondary icon-button hidden" type="button" aria-label="Audit log" title="Audit log">${tablerIcon("history")}</button><button id="openAccount" class="button secondary icon-button" type="button" aria-label="Account" title="Account">${tablerIcon("user")}</button><button id="refreshDashboard" class="button secondary icon-button" type="button" aria-label="Refresh dashboard" title="Refresh dashboard">${tablerIcon("refresh")}</button><button id="logout" class="button secondary icon-button" type="button" aria-label="Log out" title="Log out">${tablerIcon("logout")}</button></div></div>
</header>

<section class="card date-range-card"><div class="date-range-layout"><div class="date-range-copy"><h2>Date range</h2><p class="muted">Lifecycle logs and transferred-data totals use this interval. Active connections are always live.</p></div><label><span>From</span><input id="dateFrom" class="input" type="datetime-local" step="60"></label><label><span>To</span><input id="dateTo" class="input" type="datetime-local" step="60"></label><div class="row date-range-actions"><button id="applyDateRange" class="button" type="button">Apply</button><button id="resetDateRange" class="button secondary" type="button">Last 24 hours</button></div></div></section>

<section class="grid stats stream-stats">
  <article class="card pad stat"><span class="muted">Active TCP connections</span><strong id="activeTcp">0</strong></article>
  <article class="card pad stat"><span class="muted">Active UDP peers</span><strong id="activeUdp">0</strong></article>
  <article class="card pad stat"><span id="rangeConnectionsLabel" class="muted">Connections (24h)</span><strong id="rangeConnections">0</strong></article>
  <article class="card pad stat"><span id="uniqueIpsLabel" class="muted">Unique IPs (24h)</span><strong id="uniqueIps">0</strong></article>
  <article class="card pad stat"><span id="clientToUpstreamLabel" class="muted">Client to origin (24h)</span><strong id="clientToUpstream">0 B</strong></article>
  <article class="card pad stat"><span id="upstreamToClientLabel" class="muted">Origin to client (24h)</span><strong id="upstreamToClient">0 B</strong></article>
  <article class="card pad stat"><span id="rangeErrorsLabel" class="muted">Errors (24h)</span><strong id="rangeErrors">0</strong></article>
  <article class="card pad stat"><span id="rangeBlockedLabel" class="muted">Blocked (24h)</span><strong id="rangeBlocked">0</strong></article>
</section>

<section class="grid charts-grid">
  <article class="card chart-card"><div class="pad"><h2 id="primaryChartTitle">Stream traffic volume</h2><p id="primaryChartSubtitle" class="muted">Connections, disconnections, and proxy errors</p></div><div class="chart-wrap"><div class="chart-canvas-container"><canvas id="streamTrafficChart"></canvas></div><div id="streamTrafficEmpty" class="empty-state hidden">No stream activity in this range.</div></div></article>
  <article class="card chart-card"><div class="pad"><h2 id="secondaryChartTitle">Stream data volume</h2><p id="secondaryChartSubtitle" class="muted">Payload bytes transferred in both proxy directions</p></div><div class="chart-wrap"><div class="chart-canvas-container"><canvas id="streamBandwidthChart"></canvas></div><div id="streamBandwidthEmpty" class="empty-state hidden">No stream bandwidth in this range.</div></div></article>
</section>

<section class="card geo-card">
  <div class="pad row between responsive"><div><h2>Geographic distribution</h2><p id="geoSubtitle" class="muted">Active connections by country</p></div><select id="geoMetricMode" class="select select-small"><option value="active">Active connections</option><option value="events">Traffic log</option><option value="bandwidth">Bandwidth</option></select></div>
  <div class="geo-layout"><div id="geoMapWrap" class="geo-map-wrap"><svg id="geoMap" class="geo-map" role="img" aria-label="World map showing active stream connections by country"></svg><div class="geo-zoom-controls"><button id="geoZoomIn" class="button secondary icon-button" type="button" aria-label="Zoom in" title="Zoom in">${tablerIcon("zoom-in")}</button><button id="geoZoomOut" class="button secondary icon-button" type="button" aria-label="Zoom out" title="Zoom out" disabled>${tablerIcon("zoom-out")}</button><button id="geoZoomReset" class="button secondary icon-button" type="button" aria-label="Reset zoom" title="Reset zoom" disabled>${tablerIcon("refresh")}</button></div><div id="geoTooltip" class="geo-tooltip hidden" role="status"></div><div id="geoMapStatus" class="geo-map-status muted">Loading GeoIP data...</div></div><aside class="geo-sidebar"><div class="row between"><span class="muted">Top countries</span><strong id="geoTotal">0</strong></div><div id="geoCountryList" class="geo-country-list"><p class="muted">No geographic data is available.</p></div><div class="geo-legend"><span>Low</span><div class="geo-legend-scale"><i></i><i></i><i></i><i></i><i></i></div><span>High</span></div><p class="geo-attribution muted">GeoIP data: <a href="https://www.maxmind.com" target="_blank" rel="noreferrer">MaxMind GeoLite2</a><br>Map geometry: <a href="https://github.com/VictorCazanave/svg-maps/tree/master/packages/world" target="_blank" rel="noreferrer">@svg-maps/world / MapSVG</a>, CC BY 4.0</p></aside></div>
</section>

<nav class="tabs" aria-label="Stream dashboard sections"><button class="tab active" data-tab="connections" type="button">Active connections</button><button class="tab" data-tab="events" type="button">Traffic log</button><button class="tab" data-tab="bandwidth" type="button">Bandwidth</button><button class="tab" data-tab="rules" type="button">Network rules</button><button class="tab" data-tab="protection" type="button">Protection</button><button class="tab" data-tab="streams" type="button">Streams</button></nav>

<section id="panel-connections" class="tab-panel"><article class="card"><div class="pad section-heading"><div><h2>Live TCP connections and UDP peers</h2><p id="udpPeerNotice" class="muted">UDP peers disconnect after the configured idle timeout.</p></div><div id="connectionsHeaderActions" class="row"><button id="refreshConnections" class="button secondary" type="button">Refresh</button></div></div><div class="table-wrap"><table class="table"><thead><tr><th>${sortButton("Protocol", "protocol")}</th><th>${sortButton("Incoming port", "incomingPort")}</th><th>${sortButton("Client", "clientIp")}</th><th data-column="connections:country">${sortButton("Country", "countryCode")}</th><th data-column="connections:connected">${sortButton("Connected", "connectedAt")}</th><th data-column="connections:lastActivity">${sortButton("Last activity", "lastActivityAt")}</th><th data-column="connections:toOrigin">${sortButton("To origin", "clientToUpstreamBytes")}</th><th data-column="connections:toClient">${sortButton("To client", "upstreamToClientBytes")}</th></tr></thead><tbody id="activeConnections"><tr><td colspan="8" class="empty-cell">Loading...</td></tr></tbody></table></div></article></section>

<section id="panel-events" class="tab-panel hidden"><article class="card"><div class="pad section-heading"><div><h2>Connection log</h2><p class="muted">TCP socket lifecycle events and synthetic UDP peer sessions.</p></div><div id="eventsHeaderActions" class="row"><button id="refreshEvents" class="button secondary" type="button">Refresh</button></div></div><div class="toolbar"><label class="search-field"><span>Search</span><input id="eventSearch" class="input" placeholder="IP, connection, reason, rule ID..."></label><label id="eventProtocolFilter"><span>Protocol</span><select id="eventProtocol" class="select"><option value="">All</option><option value="tcp">TCP</option><option value="udp">UDP</option></select></label><label><span>Event</span><select id="eventType" class="select"><option value="">All</option><option value="connected">Connected</option><option value="disconnected">Disconnected</option><option value="monitored">Monitored</option><option value="blocked">Blocked</option><option value="throttled">Throttled</option><option value="upstream-error">Upstream error</option><option value="listener-error">Listener error</option></select></label><label><span>Country</span><select id="eventCountry" class="select"><option value="">All countries</option></select></label></div><div class="table-wrap"><table class="table"><thead><tr><th>${sortButton("Time", "created_at")}</th><th>${sortButton("Client", "client_ip")}</th><th data-column="events:country">${sortButton("Country", "country_code")}</th><th data-column="events:event">${sortButton("Event", "event_type")}</th><th class="protocol-column">${sortButton("Protocol", "protocol")}</th><th class="port-column">${sortButton("Port", "incoming_port")}</th><th data-column="events:reason">${sortButton("Reason", "reason")}</th><th data-column="events:rule">${sortButton("Rule", "protection_rule_id")}</th><th data-column="events:toOrigin">${sortButton("To origin", "client_to_upstream_bytes")}</th><th data-column="events:toClient">${sortButton("To client", "upstream_to_client_bytes")}</th></tr></thead><tbody id="streamEvents"><tr><td colspan="10" class="empty-cell">Open the tab to load events.</td></tr></tbody></table></div>${pagination("events")}</article></section>

<section id="panel-bandwidth" class="tab-panel hidden"><article class="card"><div class="pad section-heading"><div><h2>Data proxied per IP and incoming port</h2><p class="muted">Payload bytes are aggregated in one-minute buckets.</p></div><div id="bandwidthHeaderActions" class="row"><button id="refreshBandwidth" class="button secondary" type="button">Refresh</button></div></div><div class="toolbar"><label class="search-field"><span>Search</span><input id="bandwidthSearch" class="input" placeholder="IP..."></label><label><span>Protocol</span><select id="bandwidthProtocol" class="select"><option value="">All</option><option value="tcp">TCP</option><option value="udp">UDP</option></select></label><label><span>Country</span><select id="bandwidthCountry" class="select"><option value="">All countries</option></select></label></div><div class="table-wrap"><table class="table"><thead><tr><th>${sortButton("IP", "ip")}</th><th data-column="bandwidth:country">${sortButton("Country", "country_code")}</th><th class="port-column">${sortButton("Incoming port", "incoming_port")}</th><th data-column="bandwidth:toOrigin">${sortButton("To origin", "client_to_upstream_bytes")}</th><th data-column="bandwidth:toClient">${sortButton("To client", "upstream_to_client_bytes")}</th><th data-column="bandwidth:total">${sortButton("Total", "total_bytes")}</th></tr></thead><tbody id="streamBandwidth"><tr><td colspan="6" class="empty-cell">Open the tab to load bandwidth.</td></tr></tbody></table></div>${pagination("bandwidth")}</article></section>

<section id="panel-rules" class="tab-panel hidden">
  <article class="card rules-stream-card">
    <div class="pad section-heading"><div><h2>Stream</h2><p class="muted">Network rules apply to one stream's incoming TCP/UDP traffic.</p></div><label class="site-picker"><span>Stream</span><select id="rulesStreamSelector" class="select"><option value="">No streams configured</option></select></label></div>
  </article>
  <article class="card network-defaults-card">
    <div class="pad section-heading"><div><h2>Default network actions</h2><p class="muted">Explicit IP rules override country rules. Country rules override these defaults.</p></div><button id="saveStreamNetworkDefaults" class="button" type="button">Save</button></div>
    <div class="network-defaults-grid pad-topless">
      <label><span>Default IP action</span><select id="streamDefaultIpAction" class="select"><option value="inherit">Allow the connection</option><option value="block">Block all IPs</option></select><small class="muted">Set to Block all IPs and add Allow rules to create an IP whitelist.</small></label>
      <label><span>Default country action</span><select id="streamDefaultCountryAction" class="select"><option value="inherit">Use IP default</option><option value="block">Block all countries</option></select><small class="muted">Set to Block all countries and add Allow rules to create a country whitelist.</small></label>
    </div>
    <p id="streamGeoPolicyWarning" class="notice muted hidden"></p>
  </article>

  <article class="card rule-create-card">
    <div class="pad"><h2>Add an IP rule</h2><form id="streamRuleForm" class="rule-form"><label><span>IP address or CIDR</span><input class="input" name="networkCidr" placeholder="203.0.113.4 or 203.0.113.0/24" required></label><label><span>Action</span><select class="select" name="action"><option value="block">Block</option><option value="allow">Allow</option></select></label><label><span>Expires</span><input class="input" type="datetime-local" name="expiresAt"></label><label class="reason-field"><span>Reason</span><input class="input" name="reason" placeholder="Optional reason"></label><button class="button align-end" type="submit">Add rule</button></form></div>
  </article>
  <article class="card rules-list-card">
    <div class="pad section-heading"><div><h2>IP rules</h2><p class="muted">The longest matching CIDR wins. Explicit IP rules have the highest network-policy priority.</p></div><div id="rulesHeaderActions" class="row"><button id="bulkDeleteStreamRules" class="button danger" type="button" disabled>Delete selected (0)</button><button id="refreshStreamRules" class="button secondary" type="button">Refresh</button></div></div>
    <div class="toolbar compact-toolbar">
      <label class="search-field"><span>Search</span><input id="streamRuleSearch" class="input" placeholder="Network, reason..."></label>
      <label><span>Action</span><select id="streamRuleAction" class="select"><option value="">All</option><option value="allow">Allow</option><option value="block">Block</option></select></label>
      <label><span>State</span><select id="streamRuleState" class="select"><option value="">All</option><option value="active">Active</option><option value="expired">Expired</option></select></label>
      <label><span>Rows</span><select id="streamRulePageSize" class="select page-size"><option>25</option><option selected>50</option><option>100</option><option>200</option></select></label>
    </div>
    <div class="table-wrap"><table class="table"><thead><tr><th><input id="streamRulesSelectAll" type="checkbox"></th><th>State</th><th>${sortButton("Network", "network_cidr")}</th><th>${sortButton("Action", "action")}</th><th data-column="rules:reason">Reason</th><th data-column="rules:created">${sortButton("Created", "created_at")}</th><th data-column="rules:expires">${sortButton("Expires", "expires_at")}</th><th></th></tr></thead><tbody id="streamRules"><tr><td colspan="8" class="empty-cell">Open the tab to load rules.</td></tr></tbody></table></div>
    ${pagination("streamRules")}
  </article>

  <article class="card country-rule-card">
    <div class="pad"><h2>Add a country rule</h2><form id="streamCountryRuleForm" class="country-rule-form"><label><span>Country</span><select id="streamCountryRuleCountry" class="select country-select" name="countryCode" required><option value="">Select country</option></select></label><label><span>Action</span><select class="select" name="action"><option value="block">Block</option><option value="allow">Allow</option></select></label><label><span>Expires</span><input class="input" type="datetime-local" name="expiresAt"></label><label class="reason-field"><span>Reason</span><input class="input" name="reason" placeholder="Optional reason"></label><button class="button align-end" type="submit">Add rule</button></form></div>
    <div class="table-wrap"><table class="table"><thead><tr><th>State</th><th>Country</th><th>Action</th><th>Reason</th><th>Created</th><th>Expires</th><th></th></tr></thead><tbody id="streamCountryRules"><tr><td colspan="7" class="empty-cell">Open the tab to load country rules.</td></tr></tbody></table></div>
  </article>
</section>

<section id="panel-protection" class="tab-panel hidden">
  <article class="card rules-stream-card">
    <div class="pad section-heading"><div><h2>Stream</h2><p class="muted">Protection rulesets apply to one stream's incoming TCP/UDP traffic. Enable multiple rulesets at once to combine, for example, general connection-abuse detection with an application-specific one.</p></div><label class="site-picker"><span>Stream</span><select id="protectionStreamSelector" class="select"><option value="">No streams configured</option></select></label></div>
  </article>
  <article class="card rules-stream-card">
    <div class="pad section-heading"><div><h2>Loaded rulesets</h2><p class="muted">Ships as editable JSON under <code>data/stream-rulesets/</code>. Select which ones apply below; disable individual rules with the excluded-rule-IDs field if one causes false positives.</p></div><button id="refreshProtectionCatalog" class="button secondary" type="button">Refresh</button></div>
    <div id="protectionCatalogList" class="pad pad-topless check-row-list"><p class="muted">Open the tab to load rulesets.</p></div>
  </article>
  <article class="card">
    <div class="pad section-heading"><div><h2>Protection settings</h2><p class="muted">Auto-bans the source IP when an enabled ruleset's rule matches, using the ban durations below.</p></div><button id="saveStreamProtection" class="button" type="button">Save</button></div>
    <div class="pad pad-topless site-form-grid">
      <label><span>Protection mode</span><select id="streamProtectionMode" class="select"><option value="disabled">Disabled</option><option value="monitor">Monitor only</option><option value="block">Block matches</option></select><small class="muted">Monitor records what would be blocked without disconnecting anyone.</small></label>
      <label class="site-origin-field"><span>Excluded rule IDs</span><textarea id="streamProtectionExcludedRules" class="input code-input compact-code-input" rows="4" spellcheck="false" placeholder="MC-010"></textarea><small class="muted">Comma or whitespace separated. Turns off specific rules without disabling the whole ruleset.</small></label>
    </div>
    <div class="pad pad-topless">
      <div class="section-heading error-response-heading"><div><h3>Auto temp-ban durations</h3><p class="muted">When Protection mode is Block, the source IP is temporarily banned for a duration based on the matched rule's severity. Use 0 to disable auto-banning for that severity.</p></div></div>
      <div class="site-form-grid stream-protection-ban">
        <label><span>Low severity (seconds)</span><input id="streamProtectionBanLow" class="input" type="number" min="0" max="2592000" step="1" value="0" required></label>
        <label><span>Medium severity (seconds)</span><input id="streamProtectionBanMedium" class="input" type="number" min="0" max="2592000" step="1" value="600" required></label>
        <label><span>High severity (seconds)</span><input id="streamProtectionBanHigh" class="input" type="number" min="0" max="2592000" step="1" value="3600" required></label>
        <label><span>Critical severity (seconds)</span><input id="streamProtectionBanCritical" class="input" type="number" min="0" max="2592000" step="1" value="86400" required></label>
      </div>
    </div>
  </article>
</section>

<section id="panel-streams" class="tab-panel hidden"><div class="streams-layout"><article class="card"><div class="pad section-heading"><div><h2>Configured streams</h2><p class="muted">TCP and UDP can share the same numeric incoming port.</p></div><button id="newStream" class="button" type="button">Create</button></div><div id="streamsList" class="sites-list"><div class="empty-state-inline">Loading streams...</div></div></article><article class="card"><div class="pad"><div class="section-heading"><div><h2 id="streamFormTitle">Create stream</h2><p class="muted">Forward raw TCP or UDP traffic to another host.</p></div><button id="cancelStreamEdit" class="button secondary compact hidden" type="button">Cancel edit</button></div><form id="streamForm" class="site-form"><input id="streamId" type="hidden"><div class="site-form-grid"><label><span>Incoming port</span><input id="incomingPort" class="input" type="number" min="1" max="65535" required><small class="muted">Public port BurrowGate listens on for the enabled protocols.</small></label><label><span>Forward host</span><input id="forwardHost" class="input" maxlength="255" placeholder="10.0.0.20" required><small class="muted">Hostname or IP address of the upstream TCP or UDP service.</small></label><label><span>Forward port</span><input id="forwardPort" class="input" type="number" min="1" max="65535" required><small class="muted">Destination port used when connecting to the upstream service.</small></label><label><span>Data retention (days)</span><input id="streamRetentionDays" class="input" type="number" min="1" max="365" required><small class="muted">Applies to connection logs and bandwidth history.</small></label><label><span>Max connections per IP</span><input id="streamMaxConnectionsPerIp" class="input" type="number" min="0" max="100000" required><small class="muted">Caps concurrent TCP connections and UDP peers from one IP. Use 0 for unlimited.</small></label><label><span>TLS certificate</span><select id="streamCertificate" class="select"><option value="">None / TLS passthrough</option></select><small class="muted">Terminates incoming TCP TLS. UDP always remains raw.</small></label><label><span>Client IP forwarding</span><select id="streamProxyProtocol" class="select"><option value="disabled">Disabled (default)</option><option value="v1">PROXY protocol v1</option><option value="v2">PROXY protocol v2</option></select><small class="muted">The upstream must explicitly trust and support the selected format. v1 applies to TCP only. v2 supports TCP and UDP.</small></label></div><div class="row protocol-toggles"><label class="check-row compact-check"><input id="streamTcp" type="checkbox" checked><span><strong>TCP</strong><small class="muted">Proxy connection-oriented TCP traffic.</small></span></label><label class="check-row compact-check"><input id="streamUdp" type="checkbox"><span><strong>UDP</strong><small class="muted">Proxy connectionless UDP datagrams.</small></span></label></div><p id="streamProtocolError" class="badge bad hidden">Enable at least one protocol.</p><div class="section-heading"><div><h3>Per-IP connection rate limiting</h3><p class="muted">Throttles how quickly new TCP connections and UDP peers can be opened from one source IP. Independent of the concurrent connection cap above.</p></div></div><label class="check-row compact-check"><input id="streamRateLimitEnabled" type="checkbox"><span><strong>Enable connection rate limiting</strong><small class="muted">Applies per source IP for this stream.</small></span></label><div id="streamRateLimitSettings" class="site-form-grid hidden"><label><span>Algorithm</span><select id="streamRateLimitAlgorithm" class="select"><option value="sliding-window">Sliding window</option><option value="fixed-window">Fixed window</option><option value="token-bucket">Token bucket</option></select><small class="muted">Controls how new-connection capacity is measured over time.</small></label><label><span>Maximum / capacity</span><input id="streamRateLimitMax" class="input" type="number" min="1" max="1000000" value="60"><small class="muted">Maximum new connections per window, or token-bucket capacity.</small></label><label class="window-setting"><span>Window (milliseconds)</span><input id="streamRateLimitWindow" class="input" type="number" min="100" max="86400000" value="60000"><small class="muted">Time period used by fixed- and sliding-window limits.</small></label><label class="precision-setting"><span>Precision (milliseconds)</span><input id="streamRateLimitPrecision" class="input" type="number" min="10" max="60000" value="100"><small class="muted">Smaller buckets make sliding-window accounting more precise.</small></label><label class="token-setting hidden"><span>Refill tokens</span><input id="streamRateLimitRefillRate" class="input" type="number" min="1" max="1000000" value="10"><small class="muted">Number of tokens restored during each refill.</small></label><label class="token-setting hidden"><span>Refill interval (milliseconds)</span><input id="streamRateLimitRefillInterval" class="input" type="number" min="10" max="3600000" value="1000"><small class="muted">How often the configured tokens are restored.</small></label></div><div class="section-heading"><div><h3>UDP amplification guard</h3><p class="muted">Caps how many reply bytes a UDP peer can receive relative to the bytes it has sent, preventing this stream from being abused as a reflection/amplification vector for spoofed traffic. Only applies to UDP.</p></div></div><div class="site-form-grid"><label><span>Max amplification ratio</span><input id="streamUdpAmplificationMaxRatio" class="input" type="number" min="0" max="10000" value="0"><small class="muted">Reply bytes are capped at roughly this multiple of bytes received from the client, plus a small fixed allowance. Use 0 to disable (default). Can throttle legitimate one-way or highly asymmetric UDP protocols (e.g. media streaming) if the client rarely sends data. Leave disabled unless you understand your protocol's traffic shape.</small></label></div><div class="row site-form-actions"><button id="saveStream" class="button" type="submit">Create</button><button id="resetStreamForm" class="button secondary" type="button">Reset</button></div></form></div></article></div></section>
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
        <div class="pad section-heading"><div><h2>OpenID Connect</h2><p class="muted">Let dashboard users sign in through an external identity provider (Okta, Entra ID, Google Workspace, Keycloak, ...). New accounts are provisioned with the Member role and no permissions until an administrator grants access. Shared with the Web Proxy dashboard.</p></div><button id="saveAdminSso" class="button" type="button">Save</button></div>
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
    </div>
  </div>
</div>
<div id="toast" class="toast hidden" role="status"></div></main><script src="/_burrowgate/static/chart.umd.js"></script><script type="module" src="/_burrowgate/static/streams-admin.js"></script>`,
	);
}
