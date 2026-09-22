import { APP_VERSION, dashboardSwitchNav, escapeHtml, page, tablerIcon } from "./layout.ts";

export function crowdSecPage(): string {
	return page(
		"CrowdSec",
		`<main class="shell dashboard-shell">
<header class="row between responsive dashboard-header">
  <div><div class="brand"><span class="mark"></span> BurrowGate<span class="version-tag">v${escapeHtml(APP_VERSION)}</span></div>${dashboardSwitchNav("crowdsec")}<p class="muted header-subtitle">Enforce decisions from a CrowdSec Local API on every request</p></div>
  <div class="dashboard-controls"><div class="row dashboard-actions"><button id="refreshDashboard" class="button secondary icon-button" type="button" aria-label="Refresh" title="Refresh">${tablerIcon("refresh")}</button><button id="logout" class="button secondary icon-button" type="button" aria-label="Log out" title="Log out">${tablerIcon("logout")}</button></div></div>
</header>

<section class="card firewall-section">
  <div class="pad section-heading">
    <div><h2>Decisions loaded</h2><p class="muted">Pulled from the Local API and held in this node's memory. Each node in a cluster polls independently, so these counters are for this node only.</p></div>
    <div id="decisionTotal" class="stat-value">-</div>
  </div>
  <div class="pad pad-topless">
    <div class="table-wrap"><table class="table"><thead><tr><th>Scope</th><th>Loaded</th><th>Remediation</th><th>Loaded</th></tr></thead><tbody id="decisionBreakdown"><tr><td colspan="4" class="empty-cell">Nothing loaded yet.</td></tr></tbody></table></div>
    <p id="decisionOrigins" class="muted"></p>
    <p id="decisionTruncated" class="muted hidden"></p>
  </div>
</section>

<section class="card firewall-section">
  <div class="pad section-heading"><div><h2>Poll status</h2><p class="muted">BurrowGate keeps a local copy of the decisions rather than asking the Local API during a request, so an unreachable Local API slows nothing down and blocks nobody new.</p></div><button id="refreshNow" class="button secondary" type="button">Resync now</button></div>
  <div class="pad pad-topless">
    <div class="table-wrap"><table class="table"><tbody id="statusRows"><tr><td colspan="2" class="empty-cell">Not configured.</td></tr></tbody></table></div>
  </div>
</section>

<section class="card firewall-section">
  <div class="pad section-heading"><div><h2>Local API connection</h2><p class="muted">Register BurrowGate as a remediation component on your CrowdSec host with <code>cscli bouncers add burrowgate</code>, then paste the key it prints below. Give each node in a cluster its own key so <code>cscli metrics</code> can tell them apart.</p></div></div>
  <div class="pad pad-topless">
    <div class="site-form-grid">
      <label><span>Local API URL</span><input id="lapiUrl" class="input" placeholder="http://127.0.0.1:8080"></label>
      <label><span>Bouncer API key</span><input id="apiKey" class="input" type="password" autocomplete="new-password" placeholder="Leave blank to keep the current key"><small class="muted">Leave blank to keep and test the key already stored. It is never sent back to this page.</small></label>
      <label class="check-row"><input id="verifyTls" type="checkbox" checked><span><strong>Verify TLS certificate</strong><small class="muted">Only applies to an https Local API. Uncheck for a self-signed certificate.</small></span></label>
      <label><span>Decision scopes</span>
        <div class="row">
          <label class="check-row compact-check"><input id="scopeIp" type="checkbox" checked><span>IP</span></label>
          <label class="check-row compact-check"><input id="scopeRange" type="checkbox" checked><span>Range</span></label>
          <label class="check-row compact-check"><input id="scopeCountry" type="checkbox"><span>Country</span></label>
          <label class="check-row compact-check"><input id="scopeAs" type="checkbox"><span>AS</span></label>
        </div>
        <small class="muted">Country and AS decisions are matched against the GeoIP data BurrowGate already resolves, so they cost nothing extra per request. Leave them off unless you actually issue them.</small>
      </label>
      <label><span>Poll interval (seconds)</span><input id="pollIntervalSeconds" class="input" type="number" min="2" max="3600"><small class="muted">How often to pull changes. CrowdSec's own default is 10 seconds.</small></label>
      <label><span>Full resync interval (seconds)</span><input id="fullSyncIntervalSeconds" class="input" type="number" min="60" max="86400"><small class="muted">How often to discard the incremental cursor and reload everything, correcting any drift.</small></label>
      <label><span>Request timeout (ms)</span><input id="requestTimeoutMs" class="input" type="number" min="500" max="60000"></label>
      <label><span>Unknown remediations</span><select id="unknownRemediation" class="select"><option value="ban">Treat as a ban</option><option value="captcha">Treat as a captcha</option><option value="ignore">Ignore</option></select><small class="muted">What to do with a remediation that is neither ban nor captcha, such as throttle.</small></label>
      <label><span>Alert after (minutes)</span><input id="alertAfterMinutes" class="input" type="number" min="0" max="1440"><small class="muted">Send a notification when the Local API has been unreachable this long. 0 disables it.</small></label>
    </div>

    <p id="testResult" class="notice muted hidden connection-result"></p>

    <div class="row site-form-actions connection-actions">
      <button id="testConnection" class="button secondary" type="button">Test connection</button>
      <label class="check-row compact-check"><input id="enabled" type="checkbox"><span>Enabled</span></label>
      <button id="save" class="button" type="button">Save</button>
    </div>
    <p class="muted">Enabling this only starts loading decisions. Whether a decision is acted on is decided per site and per route, and every site starts in <strong>monitor</strong> mode: matches appear in Recent Traffic while nothing is blocked. Switch a site to block or challenge once you are happy with what you see.</p>
  </div>
</section>

<section class="card firewall-section">
  <div class="pad section-heading"><div><h2>AppSec (WAF)</h2><p class="muted">CrowdSec's Application Security component inspects the live request rather than matching a known address. Unlike decisions, this costs an HTTP round-trip on every request it sees, so it is off until you set an endpoint and enable it on a site or route.</p></div></div>
  <div class="pad pad-topless">
    <div class="site-form-grid">
      <label><span>AppSec URL</span><input id="appsecUrl" class="input" placeholder="http://127.0.0.1:7422"><small class="muted">Leave blank to disable AppSec everywhere, whatever the site policies say.</small></label>
      <label><span>Timeout (ms)</span><input id="appsecTimeoutMs" class="input" type="number" min="10" max="10000"><small class="muted">CrowdSec's own default is 200ms. This is spent inside every inspected request.</small></label>
      <label><span>Max inspected body (bytes)</span><input id="appsecMaxBodyBytes" class="input" type="number" min="0" max="10485760"><small class="muted">Larger bodies are inspected on their headers and URI only, rather than being buffered into memory.</small></label>
      <label class="check-row"><input id="appsecFailOpen" type="checkbox" checked><span><strong>Allow requests when AppSec is unavailable</strong><small class="muted">Unchecked means a request that cannot be inspected is refused with 503, which takes the site down with the WAF.</small></span></label>
    </div>
    <p id="appsecTestResult" class="notice muted hidden connection-result"></p>
    <div class="row site-form-actions connection-actions">
      <button id="appsecTest" class="button secondary" type="button">Test AppSec</button>
      <button id="appsecSave" class="button" type="button">Save</button>
    </div>
    <p class="muted">Enable it per site or per route from the <strong>CrowdSec</strong> tab of a site or route policy. Start in Identify only to see what it would block.</p>
  </div>
</section>

<section class="card firewall-section">
  <div class="pad section-heading"><div><h2>Address lookup</h2><p class="muted">Check whether a specific address is currently covered by a decision on this node, and which one.</p></div></div>
  <div class="pad pad-topless">
    <div class="toolbar compact-toolbar">
      <label class="search-field"><span>IP address</span><input id="lookupIp" class="input" placeholder="203.0.113.5"></label>
      <button id="lookupRun" class="button" type="button">Look up</button>
    </div>
    <div id="lookupResult" class="muted">-</div>
  </div>
</section>

<div id="toast" class="toast hidden" role="status"></div></main><script type="module" src="/_burrowgate/static/crowdsec-admin.js"></script><script src="/_burrowgate/static/update-check.js"></script>`,
	);
}
