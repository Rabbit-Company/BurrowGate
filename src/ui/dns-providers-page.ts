import { APP_VERSION, dashboardSwitchNav, escapeHtml, page, tablerIcon } from "./layout.ts";

export function dnsProvidersPage(): string {
	return page(
		"DNS Providers",
		`<main class="shell dashboard-shell">
<header class="row between responsive dashboard-header">
  <div><div class="brand"><span class="mark"></span> BurrowGate<span class="version-tag">v${escapeHtml(APP_VERSION)}</span></div>${dashboardSwitchNav("dns-providers")}<p class="muted header-subtitle">TSIG-signed DNS servers used for Let's Encrypt DNS-01 issuance, when a site's port 80 isn't publicly reachable</p></div>
  <div class="dashboard-controls"><div class="row dashboard-actions"><button id="refreshDashboard" class="button secondary icon-button" type="button" aria-label="Refresh" title="Refresh">${tablerIcon("refresh")}</button><button id="logout" class="button secondary icon-button" type="button" aria-label="Log out" title="Log out">${tablerIcon("logout")}</button></div></div>
</header>

<section class="card firewall-section">
  <div class="pad section-heading"><div><h2>DNS providers</h2><p class="muted">Each provider is a self-hosted authoritative nameserver (BIND, PowerDNS, Technitium, Knot, ...) configured to accept signed dynamic updates (RFC 2136). Pick one from a site's TLS panel to issue a certificate with DNS-01 instead of HTTP-01.</p></div><button id="providerAdd" class="button" type="button">Add provider</button></div>
  <div class="table-wrap"><table class="table"><thead><tr><th>Name</th><th>Server</th><th>Zone</th><th></th></tr></thead><tbody id="providerRows"><tr><td colspan="4" class="empty-cell">No DNS providers configured yet.</td></tr></tbody></table></div>
</section>

<div id="modal-provider" class="modal-overlay hidden" data-modal="provider">
  <div class="modal">
    <div class="modal-header"><h2 id="providerDialogTitle">Add DNS provider</h2><button class="button secondary icon-button modal-close" type="button" data-modal-close aria-label="Close">&times;</button></div>
    <div class="modal-body">
      <input type="hidden" id="providerId">
      <div class="site-form-grid">
        <label><span>Name</span><input id="providerName" class="input" required placeholder="Home lab BIND"></label>
        <label><span>Nameserver</span><input id="providerServer" class="input" placeholder="ns1.example.com or an IP"></label>
        <label><span>Port</span><input id="providerPort" class="input" type="number" min="1" max="65535" placeholder="53"></label>
        <label><span>Zone</span><input id="providerZone" class="input" placeholder="example.com"><small class="muted">The zone this key is authorized to update - must match an update-policy/allow-update grant on the server.</small></label>
        <label><span>TSIG key name</span><input id="providerTsigKeyName" class="input" placeholder="burrowgate-key"></label>
        <label><span>TSIG secret</span><input id="providerTsigSecret" class="input" type="password" autocomplete="new-password" placeholder="Leave blank to keep the current secret"><small class="muted">Standard base64, e.g. the <code>secret</code> value from <code>tsig-keygen -a hmac-sha256 burrowgate-key</code>. Only hmac-sha256 is supported.</small></label>
        <label><span>Propagation wait (seconds)</span><input id="providerPropagationSeconds" class="input" type="number" min="0" placeholder="30"><small class="muted">How long to wait after publishing the TXT record before asking Let's Encrypt to validate it.</small></label>
      </div>

      <p id="providerTestResult" class="muted hidden"></p>

      <div class="row site-form-actions">
        <button id="providerTest" class="button secondary" type="button">Test connection</button>
        <button id="providerSave" class="button" type="button">Save</button>
      </div>
    </div>
  </div>
</div>

<div id="toast" class="toast hidden" role="status"></div></main><script type="module" src="/_burrowgate/static/dns-providers-admin.js"></script><script src="/_burrowgate/static/update-check.js"></script>`,
	);
}
