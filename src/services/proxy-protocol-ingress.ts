import { createConnection, createServer, type Server, type Socket } from "node:net";
import { parseCidr, type ParsedCidr } from "../utils/ip.ts";
import {
	isProxyHeaderPrefix,
	isTrustedProxy,
	normalizeProxyAddress,
	parseIncomingProxyHeader,
	parseTrustedProxyCidrs,
	type IncomingProxyConnection,
} from "./incoming-proxy-protocol.ts";

/** Reads incoming PROXY headers before passing connections to Bun. */
export class ProxyProtocolIngress {
	private readonly server: Server;
	private readonly sockets = new Set<Socket>();
	private readonly connections = new Map<string, IncomingProxyConnection>();
	private readonly waiters = new Map<string, Set<(connection: IncomingProxyConnection) => void>>();
	private readonly trusted: ParsedCidr[];
	private targetPort: number;

	constructor(
		private readonly options: { hostname: string; port: number; targetPort: number; trustedCidrs: string[]; headerTimeoutMs?: number; allowDirect?: boolean },
	) {
		this.targetPort = options.targetPort;
		this.trusted = parseTrustedProxyCidrs(options.trustedCidrs).map((cidr) => parseCidr(cidr)!);
		if (!this.trusted.length) throw new Error("Incoming PROXY protocol requires at least one trusted load balancer IP address or CIDR");
		this.server = createServer({ allowHalfOpen: true }, (socket) => this.accept(socket));
	}

	get port(): number {
		return (this.server.address() as { port: number }).port;
	}
	setTarget(port: number): void {
		this.targetPort = port;
	}

	async start(): Promise<void> {
		await new Promise<void>((resolve, reject) => {
			this.server.once("error", reject);
			this.server.listen({ host: this.options.hostname, port: this.options.port }, () => {
				this.server.off("error", reject);
				resolve();
			});
		});
	}

	async connectionForPeer(port: number, targetPort = this.targetPort): Promise<IncomingProxyConnection> {
		const key = `${targetPort}:${port}`;
		const connection = this.connections.get(key);
		if (connection) return connection;
		// Bun can accept the local socket before node:net reports its connect event.
		return await new Promise((resolve, reject) => {
			const entries = this.waiters.get(key) ?? new Set();
			const complete = (value: IncomingProxyConnection) => {
				clearTimeout(timer);
				entries.delete(complete);
				if (!entries.size) this.waiters.delete(key);
				resolve(value);
			};
			const timer = setTimeout(() => {
				entries.delete(complete);
				if (!entries.size) this.waiters.delete(key);
				reject(new Error("Unregistered PROXY protocol backend connection"));
			}, 1000);
			entries.add(complete);
			this.waiters.set(key, entries);
		});
	}

	private track(socket: Socket): void {
		this.sockets.add(socket);
		socket.once("close", () => this.sockets.delete(socket));
	}

	private accept(client: Socket): void {
		this.track(client);
		client.on("error", () => client.destroy());
		if (!isTrustedProxy(client.remoteAddress ?? "", this.trusted)) {
			if (!this.options.allowDirect) {
				client.destroy();
				return;
			}
			client.pause();
			this.bridge(client, this.directConnection(client), Buffer.alloc(0), true);
			return;
		}
		client.setNoDelay(true);
		let buffered: Buffer = Buffer.alloc(0);
		const timer = setTimeout(() => client.destroy(), this.options.headerTimeoutMs ?? 5000);
		timer.unref();
		client.once("close", () => clearTimeout(timer));
		const receive = (chunk: Buffer) => {
			buffered = buffered.length ? Buffer.concat([buffered, chunk]) : chunk;
			try {
				if (this.options.allowDirect && isProxyHeaderPrefix(buffered) === false) {
					clearTimeout(timer);
					client.off("data", receive);
					client.pause();
					this.bridge(client, this.directConnection(client), buffered);
					return;
				}
				const parsed = parseIncomingProxyHeader(buffered);
				if (!parsed) return;
				clearTimeout(timer);
				client.off("data", receive);
				client.pause();
				const connection = { ...(parsed.connection ?? this.directConnection(client)), proxyProtocol: true };
				this.bridge(client, connection, buffered.subarray(parsed.bytes));
			} catch {
				client.destroy();
			}
		};
		client.on("data", receive);
	}

	private directConnection(client: Socket): IncomingProxyConnection {
		return {
			sourceAddress: normalizeProxyAddress(client.remoteAddress!),
			sourcePort: client.remotePort!,
			destinationAddress: normalizeProxyAddress(client.localAddress!),
			destinationPort: client.localPort!,
		};
	}

	private bridge(client: Socket, connection: IncomingProxyConnection, initialPayload: Buffer, inspectDirect = false): void {
		const targetPort = this.targetPort;
		const backend = createConnection({ host: "127.0.0.1", port: targetPort, allowHalfOpen: true });
		this.track(backend);
		let key: string | undefined;
		backend.on("error", () => {
			backend.destroy();
			client.destroy();
		});
		client.once("close", () => backend.destroy());
		backend.once("close", (hadError) => {
			if (key !== undefined && this.connections.get(key) === connection) this.connections.delete(key);
			if (hadError || !backend.readableEnded) client.destroy();
			else client.end();
		});
		backend.once("connect", () => {
			if (client.destroyed) {
				backend.destroy();
				return;
			}
			key = `${targetPort}:${backend.localPort!}`;
			this.connections.set(key, connection);
			for (const complete of [...(this.waiters.get(key) ?? [])]) complete(connection);
			backend.setNoDelay(true);
			backend.pipe(client);
			if (inspectDirect) {
				let buffered: Buffer = Buffer.alloc(0);
				let timer: ReturnType<typeof setTimeout> | undefined;
				client.once("close", () => clearTimeout(timer));
				const inspect = (chunk: Buffer) => {
					buffered = buffered.length ? Buffer.concat([buffered, chunk]) : chunk;
					const headerPrefix = isProxyHeaderPrefix(buffered);
					if (headerPrefix === true) {
						client.destroy();
						return;
					}
					if (headerPrefix === null) {
						timer ??= setTimeout(() => client.destroy(), this.options.headerTimeoutMs ?? 5000);
						return;
					}
					clearTimeout(timer);
					client.off("data", inspect);
					client.pause();
					const ready = backend.write(buffered);
					if (ready) client.pipe(backend);
					else backend.once("drain", () => client.pipe(backend));
				};
				client.on("data", inspect);
				client.once("end", () => backend.end());
				client.resume();
				return;
			}
			// Wait for the backend to drain before forwarding more data.
			const ready = initialPayload.length === 0 || backend.write(initialPayload);
			const resume = () => {
				if (!client.destroyed) client.pipe(backend);
			};
			if (ready) resume();
			else backend.once("drain", resume);
		});
	}

	async stop(closeActiveConnections = true): Promise<void> {
		if (closeActiveConnections) for (const socket of this.sockets) socket.destroy();
		await new Promise<void>((resolve, reject) => this.server.close((error) => (error ? reject(error) : resolve())));
	}
}
