export function escapeHtml(value: unknown): string {
	return String(value ?? "")
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;")
		.replaceAll("'", "&#039;");
}

export function tablerIcon(name: "refresh" | "logout"): string {
	const paths =
		name === "refresh"
			? '<path d="M20 11a8.1 8.1 0 0 0 -15.5 -2m-.5 -4v4h4"/><path d="M4 13a8.1 8.1 0 0 0 15.5 2m.5 4v-4h-4"/>'
			: '<path d="M10 8v-2a2 2 0 0 1 2 -2h7v16h-7a2 2 0 0 1 -2 -2v-2"/><path d="M15 12h-12l3 -3"/><path d="M6 15l-3 -3"/>';
	return `<svg class="tabler-icon" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${paths}</svg>`;
}

export function page(title: string, body: string, script = ""): string {
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#111827"><title>${escapeHtml(title)} | BurrowGate</title><link rel="icon" type="image/svg+xml" href="/_burrowgate/static/favicon.svg"><link rel="stylesheet" href="/_burrowgate/static/burrowgate.css"></head><body>${body}${script ? `<script>${script}</script>` : ""}</body></html>`;
}
