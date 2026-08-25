import { APP_VERSION, escapeHtml, page, tablerIcon } from "./layout.ts";

export function firewallSyncPage(): string {
	return page(
		"Firewall Sync",
		`<main class="shell dashboard-shell">
<header class="row between responsive dashboard-header">
  <div><div class="brand"><span class="mark"></span> BurrowGate<span class="version-tag">v${escapeHtml(APP_VERSION)}</span></div><nav class="dashboard-switch" aria-label="Dashboard"><a href="/_burrowgate/admin">Web Proxy</a><a href="/_burrowgate/admin/streams">Streams</a><a href="/_burrowgate/admin/host">Host</a><a href="/_burrowgate/admin/notifications">Notifications</a><a class="active" href="/_burrowgate/admin/firewall-sync">Firewall Sync</a><a href="/_burrowgate/admin/dns-providers">DNS Providers</a></nav><p class="muted header-subtitle">Push banned IPs to an external firewall so blocked traffic never reaches this host</p></div>
  <div class="dashboard-controls"><div class="row dashboard-actions"><button id="refreshDashboard" class="button secondary icon-button" type="button" aria-label="Refresh" title="Refresh">${tablerIcon("refresh")}</button><button id="logout" class="button secondary icon-button" type="button" aria-label="Log out" title="Log out">${tablerIcon("logout")}</button></div></div>
</header>

<section class="card firewall-section">
  <div class="pad section-heading"><div><h2>Currently banned</h2><p class="muted">Active blocking IP rules across all sites and streams, deduped, before any per-provider cap is applied.</p></div><div id="previewCount" class="stat-value">-</div></div>
  <div class="pad pad-topless"><code id="previewSample" class="muted">-</code><p id="previewExclusions" class="muted hidden"></p></div>
</section>

<section class="card firewall-section">
  <div class="pad section-heading"><div><h2>Never-ban whitelist</h2><p class="muted">IPs and CIDRs listed here are never pushed to a firewall, no matter what the ban rules say. Add your own admin/SSH IP before enabling any provider below, or a false-positive ban could lock you out of this VPS entirely.</p></div></div>
  <div class="pad pad-topless">
    <div class="toolbar compact-toolbar">
      <label class="search-field"><span>IP or CIDR</span><input id="whitelistCidr" class="input" placeholder="203.0.113.4 or 203.0.113.0/24"></label>
      <label><span>Note</span><input id="whitelistNote" class="input" placeholder="My admin IP"></label>
      <button id="whitelistUseMine" class="button secondary" type="button">Use my current IP</button>
      <button id="whitelistAdd" class="button" type="button">Add</button>
    </div>
    <div class="table-wrap"><table class="table"><thead><tr><th>CIDR</th><th>Note</th><th>Added</th><th></th></tr></thead><tbody id="whitelistRows"><tr><td colspan="4" class="empty-cell">No whitelist entries yet.</td></tr></tbody></table></div>
  </div>
</section>

<section class="card firewall-section">
  <div class="pad section-heading"><div><h2>Providers</h2><p class="muted">Every enabled provider receives the same deduped ban list, capped to its own entry limit (oldest bans evicted first).</p></div><button id="providerAdd" class="button" type="button">Add provider</button></div>
  <div class="table-wrap"><table class="table"><thead><tr><th>Name</th><th>Type</th><th>Enabled</th><th>Last sync</th><th>Applied / cap</th><th>Status</th><th></th></tr></thead><tbody id="providerRows"><tr><td colspan="7" class="empty-cell">No providers configured yet.</td></tr></tbody></table></div>
</section>

<div id="modal-provider" class="modal-overlay hidden" data-modal="provider">
  <div class="modal">
    <div class="modal-header"><h2 id="providerDialogTitle">Add provider</h2><button class="button secondary icon-button modal-close" type="button" data-modal-close aria-label="Close">&times;</button></div>
    <div class="modal-body">
      <input type="hidden" id="providerId">
      <div class="site-form-grid">
        <label><span>Name</span><input id="providerName" class="input" required></label>
        <label><span>Type</span><select id="providerType" class="select"><option value="unifi">UniFi Controller</option><option value="nftables">Local nftables</option><option value="ovh">OVH Edge Firewall</option><option value="aws-nacl">AWS VPC Network ACL</option></select></label>
        <label><span>Max entries</span><input id="providerMaxEntries" class="input" type="number" min="1"></label>
      </div>

      <div id="unifiFields" class="site-form-grid">
        <label><span>Controller URL</span><input id="unifiControllerUrl" class="input" placeholder="https://192.168.1.1"></label>
        <label><span>API base path</span><input id="unifiApiBasePath" class="input" placeholder="/proxy/network"><small class="muted">Almost always /proxy/network - API keys only work on UniFi OS consoles (UDM, Cloud Gateway, UniFi OS Server), which all use this prefix.</small></label>
        <label><span>API key</span><input id="unifiApiKey" class="input" type="password" autocomplete="new-password" placeholder="Leave blank to keep the current key"></label>
        <label class="check-row"><input id="unifiVerifyTls" type="checkbox" checked><span><strong>Verify TLS certificate</strong><small class="muted">Uncheck for a self-signed local controller certificate.</small></span></label>
        <label><span>Site</span><div class="row"><select id="unifiSite" class="select"><option value="">Click "Load sites" first</option></select><button id="unifiLoadSites" class="button secondary compact" type="button">Load sites</button></div><small id="unifiSitesStatus" class="muted"></small></label>
        <label><span>Traffic matching list name</span><input id="unifiGroupName" class="input" placeholder="BurrowGate-Banned-IPs"><small class="muted">BurrowGate creates/updates an IPv4 and an IPv6 Traffic Matching List with this name. Create one Firewall Policy yourself (Action: Block, Source: IP Address filter &rarr; Traffic Matching List &rarr; this name) - BurrowGate never creates or modifies policies.</small></label>
      </div>

      <div id="nftablesFields" class="site-form-grid hidden">
        <label><span>nft binary path</span><input id="nftBinaryPath" class="input" placeholder="nft"></label>
        <label class="check-row"><input id="nftUseSudo" type="checkbox"><span><strong>Run via sudo -n</strong><small class="muted">Requires a narrow sudoers rule for the nft binary.</small></span></label>
        <p class="muted">BurrowGate manages its own isolated <code>inet burrowgate</code> table/chain/sets - it never touches other firewall rules (ufw, firewalld, etc.) on this host.</p>
      </div>

      <div id="ovhFields" class="site-form-grid hidden">
        <label><span>API endpoint</span><input id="ovhEndpoint" class="input" placeholder="https://eu.api.ovh.com"><small class="muted">Regional API root, e.g. https://eu.api.ovh.com, https://ca.api.ovh.com, or https://api.us.ovhcloud.com.</small></label>
        <label><span>Application key</span><input id="ovhApplicationKey" class="input" placeholder="Created at ca.ovh.com/auth/api/createToken"></label>
        <label><span>Application secret</span><input id="ovhApplicationSecret" class="input" type="password" autocomplete="new-password" placeholder="Leave blank to keep the current secret"></label>
        <label>
          <span>Consumer key</span>
          <div class="row"><input id="ovhConsumerKey" class="input" type="password" autocomplete="new-password" placeholder="Leave blank to keep the current key"><button id="ovhRequestCredential" class="button secondary compact" type="button">Request access</button></div>
          <small id="ovhCredentialStatus" class="muted"></small>
        </label>
        <label><span>Protected IP</span><div class="row"><select id="ovhIp" class="select"><option value="">Click "Load IPs" first</option></select><button id="ovhLoadIps" class="button secondary compact" type="button">Load IPs</button></div><small id="ovhIpsStatus" class="muted"></small></label>
        <p class="muted">
          BurrowGate manages this firewall scoped to just the IP you select above - never your whole account. It has a hard limit of 20 rule slots and is IPv4-only.
          BurrowGate only ever adds/removes its own plain deny-by-IP rules - it never touches ALLOW rules or any other rule you add manually, and unmatched traffic is not
          blocked by BurrowGate's rules (OVH's edge firewall only blocks what an explicit rule matches - it doesn't deny everything else by default).
        </p>
      </div>

      <div id="awsFields" class="site-form-grid hidden">
        <label><span>Region</span><input id="awsRegion" class="input" placeholder="us-east-1"></label>
        <label><span>Access key ID</span><input id="awsAccessKeyId" class="input" placeholder="AKIA..."></label>
        <label><span>Secret access key</span><input id="awsSecretAccessKey" class="input" type="password" autocomplete="new-password" placeholder="Leave blank to keep the current secret"></label>
        <label><span>Session token</span><input id="awsSessionToken" class="input" type="password" autocomplete="new-password" placeholder="Only needed for temporary (STS) credentials"></label>
        <label><span>Network ACL</span><div class="row"><select id="awsNetworkAcl" class="select"><option value="">Click "Load Network ACLs" first</option></select><button id="awsLoadNacls" class="button secondary compact" type="button">Load Network ACLs</button></div><small id="awsNaclsStatus" class="muted"></small></label>
        <label><span>Rule number start</span><input id="awsRuleNumberStart" class="input" type="number" min="1" placeholder="1"><small class="muted">BurrowGate reserves 20 consecutive inbound rule numbers starting here. Pick a value that doesn't collide with any rule numbers you've assigned yourself - lower numbers are evaluated first.</small></label>
        <p class="muted">
          BurrowGate manages this Network ACL scoped to just the 20 reserved inbound rule numbers above - it never touches ALLOW rules or any other rule number range.
          It has a hard limit of 20 rule slots and is IPv4-only. Requires <code>ec2:DescribeNetworkAcls</code>, <code>ec2:CreateNetworkAclEntry</code>, and
          <code>ec2:DeleteNetworkAclEntry</code> IAM permissions.
        </p>
      </div>

      <label id="providerAckRow" class="check-row hidden"><input id="providerAcknowledge" type="checkbox"><span><strong>I understand the risk and want to enable this without a whitelist entry</strong><small class="muted">A false-positive ban could lock you out of this VPS entirely.</small></span></label>
      <p id="providerTestResult" class="muted hidden"></p>

      <div class="row site-form-actions">
        <button id="providerTest" class="button secondary" type="button">Test connection</button>
        <label class="check-row compact-check"><input id="providerEnabled" type="checkbox"><span>Enabled</span></label>
        <button id="providerSave" class="button" type="button">Save</button>
      </div>
    </div>
  </div>
</div>

<div id="toast" class="toast hidden" role="status"></div></main><script type="module" src="/_burrowgate/static/firewall-sync-admin.js"></script><script src="/_burrowgate/static/update-check.js"></script>`,
	);
}
