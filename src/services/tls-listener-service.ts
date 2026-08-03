import type { Web } from "@rabbit-company/web";
import { config, withRequestTransport, type RequestTransport } from "../config.ts";
import { bootstrapTlsOption } from "./bootstrap-tls-service.ts";
import { certificateTlsOptions } from "./certificate-service.ts";
import { handleWebSocketUpgrade, isWebSocketUpgrade, websocketProxyHandler, type WebSocketUpgradeServer } from "./websocket-proxy-service.ts";

interface StoppableServer {
	stop(closeActiveConnections?: boolean): void | Promise<void>;
}

interface BunWebApplication {
	handleBun(request: Request, server: unknown): Promise<Response>;
}

let reloadHandler: (() => Promise<void>) | null = null;

export function requestTlsReload(): Promise<void> {
	return reloadHandler ? reloadHandler() : Promise.resolve();
}

export class TlsListenerManager {
	private httpServer: StoppableServer | null = null;
	private httpsServer: StoppableServer | null = null;
	private reloading: Promise<void> | null = null;

	constructor(private readonly app: Web<any>) {
		reloadHandler = async () => await this.reloadHttps();
	}

	private async dispatch(request: Request, server: WebSocketUpgradeServer, transport: RequestTransport): Promise<Response | undefined> {
		if (isWebSocketUpgrade(request)) {
			// Bun requires the original Request object for server.upgrade(). Pass the
			// listener transport separately rather than cloning the upgrade request.
			return await handleWebSocketUpgrade(request, server, transport);
		}
		const web = this.app as unknown as BunWebApplication;
		return await withRequestTransport(transport, async () => await web.handleBun(request, server));
	}

	private serve(options: { port: number; tls?: Bun.TLSOptions | Bun.TLSOptions[] }): StoppableServer {
		const transport: RequestTransport = options.tls ? "https" : "http";
		return Bun.serve({
			hostname: config.host,
			port: options.port,
			...(options.tls ? { tls: options.tls } : {}),
			fetch: async (request, server) => await this.dispatch(request, server as unknown as WebSocketUpgradeServer, transport),
			websocket: websocketProxyHandler,
		}) as StoppableServer;
	}

	async start(): Promise<void> {
		if (!config.http.enabled && !config.https.enabled) {
			throw new Error("At least one of BG_HTTP_ENABLED or BG_HTTPS_ENABLED must be true");
		}
		if (config.http.enabled) {
			this.httpServer = this.serve({ port: config.http.port });
			console.log(`[BurrowGate] HTTP listening on http://${config.host}:${config.http.port}`);
		}
		if (config.https.enabled) await this.reloadHttps();
	}

	async reloadHttps(): Promise<void> {
		if (!config.https.enabled) return;
		if (this.reloading) return await this.reloading;
		this.reloading = this.replaceHttpsListener().finally(() => {
			this.reloading = null;
		});
		return await this.reloading;
	}

	private async replaceHttpsListener(): Promise<void> {
		const managedCertificates = await certificateTlsOptions();
		const bootstrap = await bootstrapTlsOption();
		const tls = bootstrap ? [bootstrap, ...managedCertificates] : managedCertificates;
		if (tls.length === 0) {
			if (this.httpsServer) {
				await this.httpsServer.stop(true);
				this.httpsServer = null;
			}
			console.warn("[BurrowGate] HTTPS is enabled, but no certificate is available.");
			return;
		}

		// Bun does not replace listener TLS material through server.reload(). Recreate
		// the HTTPS listener after certificate issuance or renewal. Active WSS
		// connections are closed during this uncommon certificate-control operation.
		if (this.httpsServer) {
			await this.httpsServer.stop(true);
			this.httpsServer = null;
		}
		this.httpsServer = this.serve({ port: config.https.port, tls });
		console.log(
			`[BurrowGate] HTTPS listening on https://${config.host}:${config.https.port} with ${managedCertificates.length} managed certificate(s)${bootstrap ? " plus bootstrap fallback" : ""}`,
		);
	}
}
