export function escapeHtml(value: unknown): string {
	return String(value ?? "")
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;")
		.replaceAll("'", "&#039;");
}

export function page(title: string, body: string, script = ""): string {
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#111827"><title>${escapeHtml(title)} | BurrowGate</title><link rel="icon" type="image/svg+xml" href="/_burrowgate/static/favicon.svg"><link rel="stylesheet" href="/_burrowgate/static/burrowgate.css"></head><body>${body}${script ? `<script>${script}</script>` : ""}</body></html>`;
}
