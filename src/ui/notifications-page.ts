import { APP_VERSION, escapeHtml, page, tablerIcon } from "./layout.ts";

interface NotificationEventTypeOption {
	value: string;
	label: string;
	description: string;
}

const SITE_EVENT_TYPES: NotificationEventTypeOption[] = [
	{ value: "origin_unhealthy", label: "Origin unhealthy", description: "A configured origin failed its health check." },
	{ value: "origin_recovered", label: "Origin recovered", description: "A previously unhealthy origin passed its health check again." },
	{ value: "pool_unhealthy", label: "All origins down", description: "Every origin for this site is unavailable." },
	{ value: "pool_recovered", label: "Origin pool recovered", description: "At least one origin is healthy again after a full outage." },
	{
		value: "internet_down",
		label: "Internet connectivity down",
		description: "The server lost internet connectivity (all monitored external targets are unreachable).",
	},
	{ value: "internet_up", label: "Internet connectivity restored", description: "Internet connectivity returned after an outage." },
	{ value: "ip_banned", label: "IP auto-banned", description: "An IP address was automatically blocked (bandwidth limit or WAF match)." },
];

const STREAM_EVENT_TYPES: NotificationEventTypeOption[] = [
	{ value: "stream_origin_unhealthy", label: "Origin unhealthy", description: "The stream's forward host/port stopped accepting TCP connections." },
	{ value: "stream_origin_recovered", label: "Origin recovered", description: "The stream's forward host/port started accepting TCP connections again." },
	{ value: "stream_ip_banned", label: "IP auto-banned", description: "An IP address was automatically blocked (bandwidth limit or WAF match)." },
	{
		value: "internet_down",
		label: "Internet connectivity down",
		description: "The server lost internet connectivity (all monitored external targets are unreachable).",
	},
	{ value: "internet_up", label: "Internet connectivity restored", description: "Internet connectivity returned after an outage." },
];

function sortButton(label: string, key: string): string {
	return `<button class="sort-button" data-sort="${key}" type="button">${label}<span aria-hidden="true"></span></button>`;
}

function pagination(id: string): string {
	return `<div class="pagination"><span id="${id}Summary" class="muted">-</span><div class="row"><button id="${id}Previous" class="button secondary compact" type="button">Previous</button><span id="${id}Page" class="page-number">Page 1</span><button id="${id}Next" class="button secondary compact" type="button">Next</button></div></div>`;
}

function eventTypeCheckboxes(options: NotificationEventTypeOption[]): string {
	return options
		.map(
			(option) =>
				`<label class="json-field-option"><input type="checkbox" name="notificationEventType" value="${option.value}" checked><span><strong>${escapeHtml(option.label)}</strong><small>${escapeHtml(option.description)}</small></span></label>`,
		)
		.join("");
}

function eventTypeFilterOptions(options: NotificationEventTypeOption[]): string {
	return options.map((option) => `<option value="${option.value}">${escapeHtml(option.label)}</option>`).join("");
}

function notificationCard(prefix: string, title: string, description: string, eventTypes: NotificationEventTypeOption[]): string {
	return `<article class="card">
  <div class="pad section-heading"><div><h2>${title}</h2><p class="muted">${description}</p></div><label class="site-picker"><span>${title}</span><select id="${prefix}Selector" class="select"><option value="">None configured</option></select></label></div>
  <div id="${prefix}Empty" class="pad pad-topless muted">Select a ${title.toLowerCase()} to configure its notifications.</div>
  <div id="${prefix}Body" class="hidden">
    <div class="pad">
      <label class="check-row"><input id="${prefix}Enabled" type="checkbox"><span><strong>Enable webhook notifications</strong><small id="${prefix}WebhookConfigured" class="muted">No webhook is configured.</small></span></label>
      <div id="${prefix}Settings" class="site-form-grid hidden">
        <label><span>Webhook type</span><select id="${prefix}Provider" class="select"><option value="generic">Generic JSON</option><option value="slack">Slack</option><option value="discord">Discord</option><option value="ntfy">ntfy</option></select><small class="muted">Formats alert payloads for the selected destination.</small></label>
        <label><span>Webhook URL</span><input id="${prefix}WebhookUrl" class="input" type="url" autocomplete="off" placeholder="https://alerts.example/hooks/..."><small class="muted">Leave blank while editing to keep the encrypted destination.</small></label>
        <label><span>Generic webhook signing secret</span><input id="${prefix}WebhookSecret" class="input" type="password" autocomplete="new-password" maxlength="4096" placeholder="Optional"><small class="muted">Adds an HMAC SHA-256 signature header. Leave blank to keep the current secret.</small></label>
        <label id="${prefix}ClearWebhookRow" class="check-row compact-check hidden"><input id="${prefix}ClearWebhook" type="checkbox"><span><strong>Remove stored webhook</strong><small class="muted">Notifications will be disabled when this is saved.</small></span></label>
      </div>
      <div class="json-field-grid">${eventTypeCheckboxes(eventTypes)}</div>
    </div>
    <div class="pad pad-topless row"><button id="${prefix}Save" class="button" type="button">Save</button></div>
  </div>
</article>`;
}

function notificationLogCard(prefix: string, title: string, eventTypes: NotificationEventTypeOption[]): string {
	return `<article class="card">
  <div class="pad section-heading"><div><h2>${title} notifications</h2><p class="muted">All events recorded for the selected ${title.toLowerCase()}, whether or not delivery succeeded.</p></div></div>
  <div class="toolbar compact-toolbar">
    <label class="search-field"><span>Search</span><input id="${prefix}LogSearch" class="input" placeholder="Summary, type..."></label>
    <label><span>Type</span><select id="${prefix}LogType" class="select"><option value="">All</option>${eventTypeFilterOptions(eventTypes)}</select></label>
    <label><span>Status</span><select id="${prefix}LogStatus" class="select"><option value="">All</option><option value="pending">Pending</option><option value="delivered">Delivered</option><option value="failed">Failed</option></select></label>
    <label><span>Rows</span><select id="${prefix}LogPageSize" class="select page-size"><option>25</option><option selected>50</option><option>100</option><option>200</option></select></label>
  </div>
  <div class="table-wrap"><table class="table"><thead><tr><th>${sortButton("Time", "created_at")}</th><th>${sortButton("Type", "type")}</th><th>${sortButton("Status", "status")}</th><th>Summary</th><th>Details</th></tr></thead><tbody id="${prefix}Log"><tr><td colspan="5" class="empty-cell">Select a ${title.toLowerCase()} to load its notifications.</td></tr></tbody></table></div>
  ${pagination(`${prefix}Log`)}
</article>`;
}

export function notificationsPage(): string {
	return page(
		"Notifications",
		`<main class="shell dashboard-shell">
<header class="row between responsive dashboard-header">
  <div><div class="brand"><span class="mark"></span> BurrowGate<span class="version-tag">v${escapeHtml(APP_VERSION)}</span></div><nav class="dashboard-switch" aria-label="Dashboard"><a href="/_burrowgate/admin">Web Proxy</a><a href="/_burrowgate/admin/streams">Streams</a><a class="active" href="/_burrowgate/admin/notifications">Notifications</a><a href="/_burrowgate/admin/firewall-sync">Firewall Sync</a></nav><p class="muted header-subtitle">Webhook alerts for origin health, internet connectivity, and auto-bans</p></div>
  <div class="dashboard-controls"><div class="row dashboard-actions"><button id="refreshDashboard" class="button secondary icon-button" type="button" aria-label="Refresh" title="Refresh">${tablerIcon("refresh")}</button><button id="logout" class="button secondary icon-button" type="button" aria-label="Log out" title="Log out">${tablerIcon("logout")}</button></div></div>
</header>
<div class="grid notification-sections">
${notificationCard("siteNotif", "Site", "Alerts for a web proxy site: origin health, internet connectivity, and IP auto-bans.", SITE_EVENT_TYPES)}
${notificationCard("streamNotif", "Stream", "Alerts for a TCP/UDP stream: origin health, internet connectivity, and IP auto-bans.", STREAM_EVENT_TYPES)}
</div>
<div class="grid notification-sections">
${notificationLogCard("siteNotif", "Site", SITE_EVENT_TYPES)}
${notificationLogCard("streamNotif", "Stream", STREAM_EVENT_TYPES)}
</div>
<div id="toast" class="toast hidden" role="status"></div></main><script type="module" src="/_burrowgate/static/notifications-admin.js"></script>`,
	);
}
