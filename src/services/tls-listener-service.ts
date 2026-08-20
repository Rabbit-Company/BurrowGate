import type { Web } from "@rabbit-company/web";
import { config, withRequestTransport, type RequestTransport } from "../config.ts";
import { bootstrapTlsOption, type TlsCertificateOption } from "./bootstrap-tls-service.ts";
import { certificateTlsOptions } from "./certificate-service.ts";
import { handleWebSocketUpgrade, isWebSocketUpgrade, websocketProxyHandler, type WebSocketUpgradeServer } from "./websocket-proxy-service.ts";
import { Logger } from "../logger.ts";

interface StoppableServer {
	stop(closeActiveConnections?: boolean): Promise<void>;
}

interface BunWebApplication {
	handleBun(request: Request, server: unknown): Promise<Response>;
}

interface ListenerDependencies {
	serve?: (options: Bun.Serve.Options<any>) => StoppableServer;
	managedCertificates?: () => Promise<TlsCertificateOption[]>;
	bootstrapCertificate?: () => Promise<TlsCertificateOption | null>;
}

const REQUEST_IDLE_TIMEOUT_SECONDS = 255;

const reloadHandlers = new Set<() => Promise<void>>();

export function registerTlsReloadHandler(handler: () => Promise<void>): () => void {
	reloadHandlers.add(handler);
	return () => reloadHandlers.delete(handler);
}

export function requestTlsReload(): Promise<void> {
	return Promise.all([...reloadHandlers].map(async (handler) => await handler())).then(() => undefined);
}

export class TlsListenerManager {
	private httpServer: StoppableServer | null = null;
	private httpsServer: StoppableServer | null = null;
	private reloading: Promise<void> | null = null;
	private readonly drainingServers = new Set<StoppableServer>();

	constructor(
		private readonly app: Web<any>,
		private readonly dependencies: ListenerDependencies = {},
	) {
		registerTlsReloadHandler(async () => await this.reloadHttps());
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

	private serve(options: { port: number; tls?: Bun.TLSOptions | Bun.TLSOptions[]; reusePort?: boolean }): StoppableServer {
		const transport: RequestTransport = options.tls ? "https" : "http";
		const serve = this.dependencies.serve ?? ((serveOptions: Bun.Serve.Options<any>) => Bun.serve(serveOptions));
		return serve({
			hostname: config.host,
			port: options.port,
			idleTimeout: REQUEST_IDLE_TIMEOUT_SECONDS,
			...(options.reusePort ? { reusePort: true } : {}),
			...(options.tls ? { tls: options.tls } : {}),
			...(options.tls && config.https.http3Enabled ? { http3: true } : {}),
			fetch: async (request, server) => await this.dispatch(request, server as unknown as WebSocketUpgradeServer, transport),
			websocket: websocketProxyHandler,
		});
	}

	async start(): Promise<void> {
		if (!config.http.enabled && !config.https.enabled) {
			throw new Error("At least one of BG_HTTP_ENABLED or BG_HTTPS_ENABLED must be true");
		}
		if (config.http.enabled) {
			this.httpServer = this.serve({ port: config.http.port });
			Logger.info(`[BurrowGate] HTTP listening on http://${config.host}:${config.http.port}`);
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

	private drainServer(server: StoppableServer): void {
		this.drainingServers.add(server);
		let completed = false;
		const timeout = setTimeout(() => {
			if (completed) return;
			void server.stop(true).catch((error) => {
				Logger.error("[BurrowGate] Unable to force-close the previous HTTPS listener", error);
			});
		}, config.https.listenerDrainTimeoutMs);
		(timeout as unknown as { unref?: () => void }).unref?.();

		void server
			.stop(false)
			.then(() => {
				completed = true;
				clearTimeout(timeout);
				this.drainingServers.delete(server);
			})
			.catch((error) => {
				completed = true;
				clearTimeout(timeout);
				this.drainingServers.delete(server);
				Logger.error("[BurrowGate] Unable to drain the previous HTTPS listener", error);
			});
	}

	private async replaceHttpsListener(): Promise<void> {
		const managedCertificates = await (this.dependencies.managedCertificates ?? certificateTlsOptions)();
		const bootstrap = await (this.dependencies.bootstrapCertificate ?? bootstrapTlsOption)();
		const tls = bootstrap ? [bootstrap, ...managedCertificates] : managedCertificates;
		const previous = this.httpsServer;

		if (tls.length === 0) {
			if (previous) {
				this.httpsServer = null;
				this.drainServer(previous);
			}
			Logger.warn("[BurrowGate] HTTPS is enabled, but no certificate is available.");
			return;
		}

		let replacement: StoppableServer;
		try {
			// Every HTTPS listener uses SO_REUSEPORT so a replacement can bind before
			// the current listener is drained. Starting the replacement first prevents
			// a failed reload from taking port 443 offline.
			replacement = this.serve({
				port: config.https.port,
				tls,
				reusePort: true,
			});
		} catch (error) {
			Logger.error("[BurrowGate] Unable to start the replacement HTTPS listener. The current listener remains active.", { error });
			throw new Error("The certificate was stored, but BurrowGate could not activate the replacement HTTPS listener. The existing listener remains active.", {
				cause: error,
			});
		}

		this.httpsServer = replacement;
		Logger.info(
			`[BurrowGate] HTTPS listening on https://${config.host}:${config.https.port} with ${managedCertificates.length} managed certificate(s)${bootstrap ? " plus bootstrap fallback" : ""}${config.https.http3Enabled ? " (HTTP/3 enabled, experimental)" : ""}`,
		);

		// Do not await this from the certificate-management request. The request may
		// itself be running on the previous HTTPS listener and must be allowed to
		// finish before that listener is force-closed.
		if (previous) this.drainServer(previous);
	}
}
