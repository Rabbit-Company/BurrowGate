import { APP_VERSION, escapeHtml, page, tablerIcon } from "./layout.ts";

export function hostPage(): string {
	return page(
		"Host",
		`<main class="shell dashboard-shell">
<header class="row between responsive dashboard-header">
  <div><div class="brand"><span class="mark"></span> BurrowGate<span class="version-tag">v${escapeHtml(APP_VERSION)}</span></div><nav class="dashboard-switch" aria-label="Dashboard"><a href="/_burrowgate/admin">Web Proxy</a><a href="/_burrowgate/admin/streams">Streams</a><a class="active" href="/_burrowgate/admin/host">Host</a><a href="/_burrowgate/admin/notifications">Notifications</a><a href="/_burrowgate/admin/firewall-sync">Firewall Sync</a></nav><p class="muted header-subtitle">Resource usage and internet connectivity for this host, independent of any single site or stream</p></div>
  <div class="dashboard-controls">
    <label class="site-picker"><span>Live refresh</span><select id="liveRefreshInterval" class="select"><option value="1000">Every 1s</option><option value="3000" selected>Every 3s</option><option value="5000">Every 5s</option><option value="10000">Every 10s</option><option value="30000">Every 30s</option></select></label>
    <label class="site-picker"><span>Date format</span><select id="dateTimeFormat" class="select"><option value="iso-24" selected>YYYY-MM-DD HH:mm:ss</option><option value="dmy-24">DD/MM/YYYY HH:mm:ss</option><option value="mdy-12">MM/DD/YYYY hh:mm:ss AM/PM</option><option value="browser">Browser default</option></select></label>
    <div class="row dashboard-actions"><span id="lastUpdated" class="refresh-status">Loaded on demand</span><button id="refreshDashboard" class="button secondary icon-button" type="button" aria-label="Refresh dashboard" title="Refresh dashboard">${tablerIcon("refresh")}</button><button id="logout" class="button secondary icon-button" type="button" aria-label="Log out" title="Log out">${tablerIcon("logout")}</button></div>
  </div>
</header>

<section class="card date-range-card">
  <div class="date-range-layout">
    <div class="date-range-copy"><h2>Date range</h2><p class="muted">The graph below uses this interval - drag across it to select a narrower range. The big number on each status tile above is always the latest live reading; a tile's smaller line of detail, if present, is instead an average over this range.</p></div>
    <label><span>From</span><input id="dateFrom" class="input" type="datetime-local" step="60"></label>
    <label><span>To</span><input id="dateTo" class="input" type="datetime-local" step="60"></label>
    <div class="row date-range-actions"><button id="applyDateRange" class="button" type="button">Apply</button><button id="resetDateRange" class="button secondary" type="button">Last 24 hours</button></div>
  </div>
</section>

<div class="row between host-section-heading"><h2>Live host status</h2><span class="live-indicator"><i class="live-dot"></i>Live</span></div>
<section class="grid stats host-stats">
  <article class="card pad stat host-meter" data-accent="cpu"><span class="muted">CPU usage</span><strong id="hostCpuValue">-</strong><small id="hostCpuDetail" class="muted">-</small><div class="breakdown-track host-meter-track"><div id="hostCpuMeter" style="width:0%"></div></div></article>
  <article class="card pad stat host-meter" data-accent="memory"><span class="muted">Memory usage</span><strong id="hostMemoryValue">-</strong><small id="hostMemoryDetail" class="muted">-</small><div class="breakdown-track host-meter-track"><div id="hostMemoryMeter" style="width:0%"></div></div></article>
  <article class="card pad stat host-meter" data-accent="disk"><span class="muted">Storage usage</span><strong id="hostDiskValue">-</strong><small id="hostDiskDetail" class="muted">-</small><div class="breakdown-track host-meter-track"><div id="hostDiskMeter" style="width:0%"></div></div></article>
  <article class="card pad stat host-meter" data-accent="download"><span class="muted">Network download</span><strong id="hostDownloadValue">-</strong><small id="hostDownloadDetail" class="muted">-</small></article>
  <article class="card pad stat host-meter" data-accent="upload"><span class="muted">Network upload</span><strong id="hostUploadValue">-</strong><small id="hostUploadDetail" class="muted">-</small></article>
  <article class="card pad stat host-meter" data-accent="latency"><span class="muted">Internet latency</span><strong id="hostLatencyValue">-</strong><small id="hostLatencyDetail" class="muted">-</small></article>
</section>

<section class="grid charts-grid">
  <article class="card chart-card"><div class="pad row between responsive"><div><h2 id="primaryChartTitle">Internet connectivity latency</h2><p id="primaryChartSubtitle" class="muted">Average ping round-trip time per interval</p></div><select id="chartView" class="select select-small"><option value="connectivity:primary">Internet connectivity latency</option><option value="connectivity:secondary">Timed-out pings</option><option value="system-cpu:secondary">CPU usage</option><option value="system-memory:secondary">Memory usage</option><option value="system-disk:secondary">Storage usage</option><option value="system-network-download:secondary">Network download</option><option value="system-network-upload:secondary">Network upload</option></select></div><div class="chart-layout"><div class="chart-wrap"><div class="chart-canvas-container"><canvas id="hostChart"></canvas></div><div id="hostChartEmpty" class="empty-state hidden">No data in this range.</div></div><aside id="hostChartSummary" class="chart-sidebar"></aside></div></article>
</section>

<div id="toast" class="toast hidden" role="status"></div></main><script src="/_burrowgate/static/chart.umd.js"></script><script type="module" src="/_burrowgate/static/host-admin.js"></script><script src="/_burrowgate/static/update-check.js"></script>`,
	);
}
