import { config } from "../config.ts";
import { Logger } from "../logger.ts";
import { pinnedHaTlsOptions } from "../services/ha-tls-service.ts";
import { jsonResponse } from "../utils/http.ts";

const FORWARDED_HEADERS = ["cookie", "x-burrowgate-admin", "content-type"];
const FORWARD_LOOP_GUARD_HEADER = "x-burrowgate-ha-forwarded";

function isAlreadyForwarded(request: Request): boolean {
	return request.headers.get(FORWARD_LOOP_GUARD_HEADER) === "1";
}

async function forwardRequestToPrimary(request: Request): Promise<Response> {
	const target = new URL(new URL(request.url).pathname + new URL(request.url).search, config.ha.primaryAdminUrl!);
	const headers = new Headers();
	for (const name of FORWARDED_HEADERS) {
		const value = request.headers.get(name);
		if (value) headers.set(name, value);
	}
	headers.set(FORWARD_LOOP_GUARD_HEADER, "1");
	const hasBody = request.method !== "GET" && request.method !== "HEAD";
	const response = await fetch(target, {
		method: request.method,
		headers,
		body: hasBody ? await request.clone().arrayBuffer() : undefined,
		redirect: "manual",
		signal: AbortSignal.timeout(10_000),
		tls: await pinnedHaTlsOptions(),
	});
	const responseHeaders = new Headers(response.headers);
	responseHeaders.delete("content-encoding");
	responseHeaders.delete("content-length");
	return new Response(await response.arrayBuffer(), { status: response.status, headers: responseHeaders });
}

export async function forwardToPrimaryIfReplica(request: Request): Promise<Response | null> {
	if (!config.ha.enabled || config.ha.role !== "replica") return null;
	if (!config.ha.primaryAdminUrl) {
		return jsonResponse({ error: "This replica is misconfigured: BG_HA_PRIMARY_ADMIN_URL is not set" }, 500);
	}
	if (isAlreadyForwarded(request)) return null;
	try {
		return await forwardRequestToPrimary(request);
	} catch (error) {
		Logger.error("[BurrowGate] HA: failed to forward admin write to the primary", { error, url: request.url });
		return jsonResponse({ error: "The primary BurrowGate instance is unreachable - this replica cannot apply admin writes right now" }, 503);
	}
}

export async function tryForwardToPrimary(request: Request): Promise<Response | null> {
	if (!config.ha.enabled || config.ha.role !== "replica" || !config.ha.primaryAdminUrl) return null;
	if (isAlreadyForwarded(request)) return null;
	try {
		return await forwardRequestToPrimary(request);
	} catch (error) {
		Logger.warn("[BurrowGate] HA: failed to forward status request to the primary, falling back to a local view", { error, url: request.url });
		return null;
	}
}
