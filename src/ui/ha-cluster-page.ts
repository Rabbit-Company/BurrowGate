import { APP_VERSION, dashboardSwitchNav, escapeHtml, page, tablerIcon } from "./layout.ts";

export function haClusterPage(): string {
	return page(
		"Cluster",
		`<main class="shell dashboard-shell">
<header class="row between responsive dashboard-header">
  <div><div class="brand"><span class="mark"></span> BurrowGate<span class="version-tag">v${escapeHtml(APP_VERSION)}</span></div>${dashboardSwitchNav("cluster")}<p class="muted header-subtitle">Which BurrowGate instances are in this HA cluster and whether they're currently connected <span class="badge warn">Experimental</span></p></div>
  <div class="dashboard-controls"><div class="row dashboard-actions"><button id="refreshDashboard" class="button secondary icon-button" type="button" aria-label="Refresh" title="Refresh">${tablerIcon("refresh")}</button><button id="logout" class="button secondary icon-button" type="button" aria-label="Log out" title="Log out">${tablerIcon("logout")}</button></div></div>
</header>

<section class="card firewall-section">
  <div class="pad section-heading"><div><h2>This node's identity</h2><p class="muted">Its display name and the address other nodes reach it at - set this before generating a join code or promoting this node from elsewhere. Applies immediately, no restart.</p></div></div>
  <div class="pad pad-topless">
    <form id="identityForm" class="grid">
      <label><span>This node's name</span><input id="identityNodeName" class="input" name="nodeName" placeholder="e.g. primary-fra1"></label>
      <label><span>This node's admin URL</span><input id="identitySelfAdminUrl" class="input" name="selfAdminUrl" required placeholder="https://this-node.example.com"><small class="muted">Must be reachable by every other node in the cluster.</small></label>
      <button class="button" type="submit">Save</button>
    </form>
  </div>
</section>

<section class="card firewall-section">
  <div class="pad section-heading"><div><h2>Join an existing cluster</h2><p class="muted">Converts this node into a replica. Works even if this node is currently the primary of its own cluster of one - paste a join code from another primary's Cluster tab to link them together.</p></div></div>
  <div class="pad pad-topless">
    <form id="joinClusterForm" class="grid">
      <label><span>Join code</span><textarea id="joinCode" class="input" name="joinCode" rows="3" required placeholder="Paste the join code here"></textarea></label>
      <label><span>This node's admin URL</span><input id="joinSelfAdminUrl" class="input" name="selfAdminUrl" required placeholder="https://this-node.example.com"></label>
      <label><span>This node's name</span><input id="joinNodeName" class="input" name="nodeName" placeholder="e.g. replica-ams1"></label>
      <button class="button" type="submit">Join cluster (restarts this instance)</button>
    </form>
    <p class="muted"><strong>Note:</strong> joining replaces this node's data with a full copy of the cluster's data - anything it has locally (including sites/config from being a standalone primary) is discarded.</p>
  </div>
</section>

<section class="card firewall-section">
  <div class="pad section-heading"><div><h2>This node</h2><p class="muted">The instance currently serving this dashboard page.</p></div></div>
  <div class="pad pad-topless">
    <div class="table-wrap"><table class="table">
      <tbody id="selfRows"><tr><td colspan="4" class="empty-cell">Loading...</td></tr></tbody>
    </table></div>
    <div id="joinCodePanel" class="secret-panel hidden"><div><strong>Join code</strong><p class="muted">Paste this into another node's "Join an existing cluster" form. Expires in 15 minutes and can only be used once - generate a fresh one if it isn't used in time.</p><code id="joinCodeValue"></code></div><button id="copyJoinCode" class="button secondary" type="button">Copy</button></div>
    <button id="viewJoinCode" class="button secondary hidden" type="button">Generate join code</button>
    <button id="leaveCluster" class="button secondary danger hidden" type="button">Leave cluster (restarts this instance)</button>
  </div>
</section>

<section class="card firewall-section">
  <div class="pad section-heading"><div><h2>Cluster nodes</h2><p class="muted">Registered replicas, including offline nodes whose last-known version still participates in the cluster write-safety check.</p></div></div>
  <div class="pad pad-topless">
    <p id="clusterNotice" class="muted hidden"></p>
    <div class="table-wrap"><table class="table"><thead><tr><th>Name</th><th>Role</th><th>Version</th><th>Connected since</th><th>Sync</th><th></th></tr></thead><tbody id="nodeRows"><tr><td colspan="6" class="empty-cell">Loading...</td></tr></tbody></table></div>
  </div>
</section>

<section class="card firewall-section">
  <div class="pad section-heading"><div><h2>Dropped replication events</h2><p class="muted">Multi-writer events (sessions, bans, identity changes) the primary could not apply at all and gave up on, rather than retrying forever and blocking every later event from that node.</p></div></div>
  <div class="pad pad-topless">
    <div class="table-wrap"><table class="table"><thead><tr><th>Node</th><th>Entity</th><th>Operation</th><th>Reason</th><th>When</th></tr></thead><tbody id="deadLetterRows"><tr><td colspan="5" class="empty-cell">Loading...</td></tr></tbody></table></div>
  </div>
</section>

<div id="restartOverlay" class="restart-overlay hidden"><div class="restart-overlay-card"><p id="restartOverlayMessage">Restarting this instance to apply the change...</p><p id="restartOverlayError" class="muted hidden"></p></div></div>
<div id="toast" class="toast hidden" role="status"></div></main><script type="module" src="/_burrowgate/static/ha-cluster-admin.js"></script><script src="/_burrowgate/static/update-check.js"></script>`,
	);
}
