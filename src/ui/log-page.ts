import { APP_VERSION, dashboardSwitchNav, escapeHtml, page, tablerIcon } from "./layout.ts";

export function logPage(): string {
	return page(
		"Logs",
		`<main class="shell dashboard-shell">
<header class="row between responsive dashboard-header">
  <div><div class="brand"><span class="mark"></span> BurrowGate<span class="version-tag">v${escapeHtml(APP_VERSION)}</span></div>${dashboardSwitchNav("logs")}<p class="muted header-subtitle">Node-local application logs, daily files, and compressed archives</p></div>
  <div class="dashboard-controls">
    <label class="site-picker"><span>Date format</span><select id="dateTimeFormat" class="select"><option value="iso-24" selected>YYYY-MM-DD HH:mm:ss</option><option value="dmy-24">DD/MM/YYYY HH:mm:ss</option><option value="mdy-12">MM/DD/YYYY hh:mm:ss AM/PM</option><option value="browser">Browser default</option></select></label>
    <div class="row dashboard-actions"><span id="lastUpdated" class="refresh-status">Loaded on demand</span><button id="refreshDashboard" class="button secondary icon-button" type="button" aria-label="Refresh" title="Refresh">${tablerIcon("refresh")}</button><button id="logout" class="button secondary icon-button" type="button" aria-label="Log out" title="Log out">${tablerIcon("logout")}</button></div>
  </div>
</header>

<section class="card date-range-card"><div class="date-range-layout"><div class="date-range-copy"><h2>Log range</h2><p class="muted">The graph and searchable log list use this interval. Drag across the graph to zoom into a period. Compressed archives are download-only.</p></div><label><span>From</span><input id="dateFrom" class="input" type="datetime-local" step="60"></label><label><span>To</span><input id="dateTo" class="input" type="datetime-local" step="60"></label><div class="row date-range-actions"><button id="applyDateRange" class="button" type="button">Apply</button><button id="resetDateRange" class="button secondary" type="button">Last 24 hours</button></div></div></section>

<section class="grid charts-grid"><article class="card chart-card"><div class="pad row between responsive"><div><h2>Logs by level</h2><p id="logChartSubtitle" class="muted">Entries in uncompressed daily log files</p></div></div><div class="chart-layout"><div class="chart-wrap"><div class="chart-canvas-container time-selectable"><canvas id="logChart"></canvas></div><div id="logChartEmpty" class="empty-state hidden">No searchable logs in this range.</div></div><aside id="logChartSummary" class="chart-sidebar"></aside></div></article></section>

<section class="card log-settings-card">
  <div class="pad section-heading"><div><h2>File logging settings</h2><p class="muted">These settings apply only to this BurrowGate node and persist under its log directory.</p></div><button id="saveLogSettings" class="button" type="button">Save</button></div>
  <div class="pad pad-topless log-settings-grid">
    <label class="checkbox-field"><input id="fileLoggingEnabled" type="checkbox"><span><strong>Store logs in daily files</strong><small class="muted">Writes <code>YYYY-MM-DD.txt</code> under <code id="logDirectory">data/logs</code>.</small></span></label>
    <label><span>Logging level</span><select id="loggingLevel" class="select"><option value="error">Error</option><option value="warn">Warning</option><option value="audit">Audit</option><option value="info">Info</option><option value="http">HTTP</option><option value="debug">Debug</option><option value="verbose">Verbose</option><option value="silly">Silly</option></select><small class="muted">Includes the selected level and every more important level in console and file output.</small></label>
    <label><span>Compress after</span><div class="input-with-suffix"><input id="compressAfterDays" class="input" type="number" min="1" max="3649" step="1"><span>days</span></div><small class="muted">Older plain-text files become <code>.txt.gz</code> archives and can no longer be searched here.</small></label>
    <label><span>Delete after</span><div class="input-with-suffix"><input id="retentionDays" class="input" type="number" min="2" max="3650" step="1"><span>days</span></div><small class="muted">Automatically removes both plain-text logs and compressed archives.</small></label>
  </div>
  <p id="logSettingsNotice" class="notice muted hidden"></p>
</section>

<section class="card recent-logs-card">
  <div class="pad section-heading"><div><h2>Recent logs</h2><p id="searchableDates" class="muted">Only uncompressed daily files are searchable.</p></div></div>
  <div class="toolbar logs-toolbar"><label class="search-field"><span>Search</span><input id="logSearch" class="input" placeholder="Message or metadata..."></label><label><span>Level</span><select id="logLevelFilter" class="select"><option value="">All levels</option><option value="error">Error</option><option value="warn">Warning</option><option value="audit">Audit</option><option value="info">Info</option><option value="http">HTTP</option><option value="debug">Debug</option><option value="verbose">Verbose</option><option value="silly">Silly</option></select></label><label><span>Rows</span><select id="logPageSize" class="select page-size"><option>25</option><option selected>50</option><option>100</option><option>200</option></select></label></div>
  <div class="table-wrap"><table class="table logs-table"><thead><tr><th>Time</th><th>Level</th><th>Message</th><th>Metadata</th></tr></thead><tbody id="logRows"><tr><td colspan="4" class="empty-cell">Loading...</td></tr></tbody></table></div>
  <div class="pagination"><span id="logsSummary" class="muted">-</span><div class="row"><button id="logsPrevious" class="button secondary compact" type="button">Previous</button><span id="logsPage" class="page-number">Page 1</span><button id="logsNext" class="button secondary compact" type="button">Next</button></div></div>
</section>

<section class="card log-archives-card">
  <div class="pad section-heading"><div><h2>Compressed archives</h2><p class="muted">Archives can be downloaded or permanently deleted. Their contents are not searched by the dashboard.</p></div><button id="refreshArchives" class="button secondary" type="button">Refresh</button></div>
  <div class="table-wrap"><table class="table"><thead><tr><th>Date</th><th>Archive</th><th>Size</th><th>Compressed</th><th></th></tr></thead><tbody id="archiveRows"><tr><td colspan="5" class="empty-cell">Loading...</td></tr></tbody></table></div>
</section>

<div id="toast" class="toast hidden" role="status"></div></main><script src="/_burrowgate/static/chart.umd.js"></script><script type="module" src="/_burrowgate/static/log-admin.js"></script><script src="/_burrowgate/static/update-check.js"></script>`,
	);
}
