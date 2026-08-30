import packageMetadata from "../../package.json" with { type: "json" };

export const APP_VERSION = packageMetadata.version;

export type DashboardTabKey = "web-proxy" | "streams" | "host" | "notifications" | "firewall-sync" | "dns-providers" | "cluster";

export function dashboardSwitchNav(active: DashboardTabKey): string {
	const tabs: Array<{ key: DashboardTabKey; href: string; label: string }> = [
		{ key: "web-proxy", href: "/_burrowgate/admin", label: "Web Proxy" },
		{ key: "streams", href: "/_burrowgate/admin/streams", label: "Streams" },
		{ key: "host", href: "/_burrowgate/admin/host", label: "Host" },
		{ key: "notifications", href: "/_burrowgate/admin/notifications", label: "Notifications" },
		{ key: "firewall-sync", href: "/_burrowgate/admin/firewall-sync", label: "Firewall Sync" },
		{ key: "dns-providers", href: "/_burrowgate/admin/dns-providers", label: "DNS Providers" },
	];
	tabs.push({ key: "cluster", href: "/_burrowgate/admin/cluster", label: "Cluster" });
	return `<nav class="dashboard-switch" aria-label="Dashboard">${tabs.map((tab) => `<a${tab.key === active ? ' class="active"' : ""} href="${tab.href}">${escapeHtml(tab.label)}</a>`).join("")}</nav>`;
}

export function escapeHtml(value: unknown): string {
	return String(value ?? "")
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;")
		.replaceAll("'", "&#039;");
}

export function tablerIcon(name: "refresh" | "logout" | "users" | "history" | "user" | "key" | "zoom-in" | "zoom-out"): string {
	const paths = {
		refresh: '<path d="M20 11a8.1 8.1 0 0 0 -15.5 -2m-.5 -4v4h4"/><path d="M4 13a8.1 8.1 0 0 0 15.5 2m.5 4v-4h-4"/>',
		"zoom-in": '<path d="M10 4a6 6 0 1 0 0 12a6 6 0 0 0 0 -12z"/><path d="M21 21l-6 -6"/><path d="M7 10l6 0"/><path d="M10 7l0 6"/>',
		"zoom-out": '<path d="M10 4a6 6 0 1 0 0 12a6 6 0 0 0 0 -12z"/><path d="M21 21l-6 -6"/><path d="M7 10l6 0"/>',
		logout: '<path d="M10 8v-2a2 2 0 0 1 2 -2h7v16h-7a2 2 0 0 1 -2 -2v-2"/><path d="M15 12h-12l3 -3"/><path d="M6 15l-3 -3"/>',
		users:
			'<path d="M9 7m-4 0a4 4 0 1 0 8 0a4 4 0 1 0 -8 0"/><path d="M3 21v-2a4 4 0 0 1 4 -4h4a4 4 0 0 1 4 4v2"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/><path d="M21 21v-2a4 4 0 0 0 -3 -3.85"/>',
		history: '<path d="M12 8l0 4l2 2"/><path d="M3.05 11a9 9 0 1 1 .5 4m-.5 5v-5h5"/>',
		user: '<path d="M8 7a4 4 0 1 0 8 0a4 4 0 0 0 -8 0"/><path d="M6 21v-2a4 4 0 0 1 4 -4h4a4 4 0 0 1 4 4v2"/>',
		key: '<path d="M16.555 3.843l3.602 3.602a2.877 2.877 0 0 1 0 4.069l-2.643 2.643a2.877 2.877 0 0 1 -4.069 0l-.301 -.301l-6.558 6.558a2 2 0 0 1 -1.239 .578l-.175 .008h-1.172a1 1 0 0 1 -.993 -.883l-.007 -.117v-1.172a2 2 0 0 1 .467 -1.284l.119 -.13l.414 -.414h2v-2h2v-2l2.144 -2.144l-.301 -.301a2.877 2.877 0 0 1 0 -4.069l2.643 -2.643a2.877 2.877 0 0 1 4.069 0z"/><path d="M15 9h.01"/>',
	}[name];
	return `<svg class="tabler-icon" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${paths}</svg>`;
}

export function authErrorToast(error: string): string {
	if (!error) return "";
	return `<div class="toast bad" role="status" id="authErrorToast">${escapeHtml(error)}</div><script>setTimeout(function(){var t=document.getElementById("authErrorToast");if(t)t.remove();},5000);</script>`;
}

export function page(title: string, body: string, script = ""): string {
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#111827"><title>${escapeHtml(title)} | BurrowGate</title><link rel="icon" type="image/svg+xml" href="/_burrowgate/static/favicon.svg"><link rel="stylesheet" href="/_burrowgate/static/burrowgate.css"></head><body>${body}${script ? `<script>${script}</script>` : ""}</body></html>`;
}
