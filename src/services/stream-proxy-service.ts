import { lookup } from "node:dns/promises";
import { config } from "../config.ts";
import { repository } from "../db/repository.ts";
import { Logger } from "../logger.ts";
import type { StreamEventRecord, StreamProtocol, StreamRecord } from "../types.ts";
import { randomId } from "../utils/crypto.ts";
import { streamCertificateTlsOption } from "./certificate-service.ts";
import { lookupCountryCode } from "./geoip-service.ts";
import { evaluateStreamIp } from "./stream-ip-rule-service.ts";
import { checkStreamConnectionRate } from "./stream-rate-limit-service.ts";
import { recordStreamEvent, recordStreamTraffic } from "./stream-monitoring-service.ts";
import { registerTlsReloadHandler } from "./tls-listener-service.ts";
import { openMetrics } from "./openmetrics-service.ts";

type TcpSocket = Bun.Socket<TcpConnection>;

interface TcpConnection {
	id: string;
	record: StreamRecord;
	client: TcpSocket;
	upstream: TcpSocket | null;
	openedAt: number;
	lastActivityAt: number;
	clientIp: string;
	clientPort: number;
	countryCode: string | null;
	clientToUpstreamBytes: number;
	upstreamToClientBytes: number;
	toUpstream: Uint8Array[];
	toClient: Uint8Array[];
	queuedBytes: number;
	closed: boolean;
	clientEnded: boolean;
}

interface TcpRuntime {
	record: StreamRecord;
	fingerprint: string;
	listener: Bun.TCPSocketListener<TcpConnection>;
}

interface UdpPeer {
	id: string;
	record: StreamRecord;
	clientIp: string;
	clientPort: number;
	countryCode: string | null;
	openedAt: number;
	lastActivityAt: number;
	clientToUpstreamBytes: number;
	upstreamToClientBytes: number;
	upstream: Bun.udp.ConnectedSocket<"buffer">;
	pendingUpstream: Uint8Array[];
	closed: boolean;
}

interface UdpReply {
	peer: UdpPeer;
	data: Uint8Array;
}

interface UdpRuntime {
	record: StreamRecord;
	fingerprint: string;
	socket: Bun.udp.Socket<"buffer">;
	forwardAddress: string;
	peers: Map<string, UdpPeer>;
	pendingPeers: Map<string, Promise<UdpPeer>>;
	pendingReplies: UdpReply[];
	cleanupTimer: ReturnType<typeof setInterval>;
	closed: boolean;
}

export interface StreamRuntimeStatus {
	id: string;
	tcp: "disabled" | "active" | "error";
	udp: "disabled" | "active" | "error";
	error: string | null;
	activeTcpConnections: number;
	activeUdpPeers: number;
}

export interface ActiveStreamConnection {
	id: string;
	streamId: string;
	incomingPort: number;
	protocol: StreamProtocol;
	clientIp: string;
	clientPort: number;
	countryCode: string | null;
	connectedAt: number;
	lastActivityAt: number;
	clientToUpstreamBytes: number;
	upstreamToClientBytes: number;
}

interface StreamProxyDependencies {
	listen?: (options: Bun.TCPSocketListenOptions<TcpConnection>) => Bun.TCPSocketListener<TcpConnection>;
	connect?: (options: Bun.TCPSocketConnectOptions<TcpConnection>) => Promise<TcpSocket>;
	udpSocket?: typeof Bun.udpSocket;
	resolveHost?: (hostname: string) => Promise<string>;
	tlsOption?: (certificateId: string) => Promise<Bun.TLSOptions>;
}

function copyChunk(data: Uint8Array): Uint8Array {
	return Buffer.from(data);
}

function event(input: Omit<StreamEventRecord, "id" | "created_at">): StreamEventRecord {
	return { id: randomId("stream_evt"), created_at: Date.now(), ...input };
}

function runtimeError(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

function tcpFingerprint(record: StreamRecord): string {
	return JSON.stringify([record.incoming_port, record.forward_host, record.forward_port, record.certificate_id]);
}

function udpFingerprint(record: StreamRecord): string {
	return JSON.stringify([record.incoming_port, record.forward_host, record.forward_port]);
}

function udpPeerKey(address: string, port: number): string {
	return JSON.stringify([address, port]);
}

export class StreamProxyManager {
	private tcpRuntimes = new Map<string, TcpRuntime>();
	private udpRuntimes = new Map<string, UdpRuntime>();
	private tcpConnections = new Map<string, TcpConnection>();
	private statuses = new Map<string, StreamRuntimeStatus>();
	private mutations: Promise<void> = Promise.resolve();

	constructor(private readonly dependencies: StreamProxyDependencies = {}) {
		registerTlsReloadHandler(async () => await this.reloadTlsStreams());
	}

	private monitorEvent(input: Omit<StreamEventRecord, "id" | "created_at">): void {
		recordStreamEvent(event(input));
	}

	private statusFor(record: StreamRecord): StreamRuntimeStatus {
		let status = this.statuses.get(record.id);
		if (!status) {
			status = {
				id: record.id,
				tcp: record.tcp_enabled === 1 ? "error" : "disabled",
				udp: record.udp_enabled === 1 ? "error" : "disabled",
				error: null,
				activeTcpConnections: 0,
				activeUdpPeers: 0,
			};
			this.statuses.set(record.id, status);
		}
		return status;
	}

	private updateCounts(streamId: string): void {
		const status = this.statuses.get(streamId);
		if (!status) return;
		status.activeTcpConnections = [...this.tcpConnections.values()].filter((connection) => connection.record.id === streamId && !connection.closed).length;
		status.activeUdpPeers = this.udpRuntimes.get(streamId)?.peers.size ?? 0;
		openMetrics.setStreamRuntime(status);
	}

	async start(): Promise<void> {
		for (const record of await repository.allStreams()) {
			try {
				await this.applyNow(record);
			} catch (error) {
				Logger.error(`[BurrowGate] Unable to activate stream on port ${record.incoming_port}`, { error });
			}
		}
	}

	async apply(record: StreamRecord): Promise<void> {
		const operation = this.mutations.then(async () => await this.applyNow(record));
		this.mutations = operation.catch(() => undefined);
		return await operation;
	}

	private syncRecord(record: StreamRecord): void {
		const tcpRuntime = this.tcpRuntimes.get(record.id);
		if (tcpRuntime) tcpRuntime.record = record;
		const udpRuntime = this.udpRuntimes.get(record.id);
		if (udpRuntime) udpRuntime.record = record;
	}

	private async applyNow(record: StreamRecord, forceTls = false): Promise<void> {
		const previousTcp = this.tcpRuntimes.get(record.id)?.record;
		const previousUdp = this.udpRuntimes.get(record.id)?.record;
		const tcpChanged = record.tcp_enabled !== 1 || forceTls || this.tcpRuntimes.get(record.id)?.fingerprint !== tcpFingerprint(record);
		const udpChanged = record.udp_enabled !== 1 || this.udpRuntimes.get(record.id)?.fingerprint !== udpFingerprint(record);
		const status = this.statusFor(record);
		status.error = null;
		try {
			if (record.tcp_enabled !== 1) {
				this.stopTcp(record.id);
				status.tcp = "disabled";
			} else if (tcpChanged) {
				this.stopTcp(record.id);
				await this.startTcp(record);
				status.tcp = "active";
			}
			if (record.udp_enabled !== 1) {
				this.stopUdp(record.id, "stream reconfigured");
				status.udp = "disabled";
			} else if (udpChanged) {
				this.stopUdp(record.id, "stream reconfigured");
				await this.startUdp(record);
				status.udp = "active";
			}
			this.syncRecord(record);
		} catch (error) {
			status.error = runtimeError(error);
			if (tcpChanged) {
				this.stopTcp(record.id);
				if (previousTcp) await this.startTcp(previousTcp).catch(() => undefined);
			}
			if (udpChanged) {
				this.stopUdp(record.id, "activation rollback");
				if (previousUdp) await this.startUdp(previousUdp).catch(() => undefined);
			}
			status.tcp = this.tcpRuntimes.has(record.id) ? "active" : record.tcp_enabled === 1 ? "error" : "disabled";
			status.udp = this.udpRuntimes.has(record.id) ? "active" : record.udp_enabled === 1 ? "error" : "disabled";
			this.monitorEvent({
				stream_id: record.id,
				incoming_port: record.incoming_port,
				connection_id: null,
				protocol: record.tcp_enabled === 1 ? "tcp" : "udp",
				event_type: "listener-error",
				client_ip: null,
				client_port: null,
				country_code: null,
				reason: "listener activation failed",
				error: runtimeError(error),
				client_to_upstream_bytes: 0,
				upstream_to_client_bytes: 0,
			});
			throw error;
		} finally {
			this.updateCounts(record.id);
		}
	}

	async remove(streamId: string): Promise<void> {
		const operation = this.mutations.then(() => {
			this.stopTcp(streamId);
			for (const connection of [...this.tcpConnections.values()]) {
				if (connection.record.id === streamId) this.finishTcp(connection, "stream removed");
			}
			this.stopUdp(streamId, "stream removed");
			this.statuses.delete(streamId);
			openMetrics.clearStreamRuntime(streamId);
		});
		this.mutations = operation.catch(() => undefined);
		return await operation;
	}

	private async reloadTlsStreams(): Promise<void> {
		for (const record of await repository.allStreams()) {
			if (record.tcp_enabled === 1 && record.certificate_id) await this.applyNow(record, true);
		}
	}

	private queueTcp(connection: TcpConnection, direction: "upstream" | "client", data: Uint8Array): void {
		const chunk = copyChunk(data);
		connection.queuedBytes += chunk.byteLength;
		if (connection.queuedBytes > config.streams.maxBufferedBytes) {
			this.finishTcp(connection, "backpressure buffer exceeded", new Error("TCP stream buffer limit exceeded"));
			return;
		}
		(direction === "upstream" ? connection.toUpstream : connection.toClient).push(chunk);
		(direction === "upstream" ? connection.client : connection.upstream)?.pause();
	}

	private recordTcpBytes(connection: TcpConnection, direction: "upstream" | "client", count: number): void {
		if (count <= 0) return;
		if (direction === "upstream") connection.clientToUpstreamBytes += count;
		else connection.upstreamToClientBytes += count;
		recordStreamTraffic(
			{
				streamId: connection.record.id,
				incomingPort: connection.record.incoming_port,
				ip: connection.clientIp,
				countryCode: connection.countryCode,
				protocol: "tcp",
			},
			direction === "upstream" ? { clientToUpstreamBytes: count } : { upstreamToClientBytes: count },
		);
	}

	private writeTcp(connection: TcpConnection, direction: "upstream" | "client", data: Uint8Array): void {
		if (connection.closed) return;
		connection.lastActivityAt = Date.now();
		const destination = direction === "upstream" ? connection.upstream : connection.client;
		if (!destination) {
			this.queueTcp(connection, direction, data);
			return;
		}
		const written = destination.write(data);
		if (written < 0) {
			this.finishTcp(connection, "socket write failed", new Error("TCP destination is closed"));
			return;
		}
		this.recordTcpBytes(connection, direction, written);
		if (written < data.byteLength) this.queueTcp(connection, direction, data.subarray(written));
	}

	private flushTcp(connection: TcpConnection, direction: "upstream" | "client"): void {
		if (connection.closed) return;
		const destination = direction === "upstream" ? connection.upstream : connection.client;
		if (!destination) return;
		const queue = direction === "upstream" ? connection.toUpstream : connection.toClient;
		while (queue.length) {
			const chunk = queue[0]!;
			const written = destination.write(chunk);
			if (written < 0) return this.finishTcp(connection, "socket write failed", new Error("TCP destination is closed"));
			this.recordTcpBytes(connection, direction, written);
			connection.queuedBytes -= written;
			if (written < chunk.byteLength) {
				queue[0] = chunk.subarray(written);
				return;
			}
			queue.shift();
		}
		(direction === "upstream" ? connection.client : connection.upstream)?.resume();
	}

	private finishTcp(connection: TcpConnection, reason: string, error?: Error): void {
		if (connection.closed) return;
		connection.closed = true;
		this.tcpConnections.delete(connection.id);
		connection.client.terminate();
		connection.upstream?.terminate();
		if (error) {
			this.monitorEvent({
				stream_id: connection.record.id,
				incoming_port: connection.record.incoming_port,
				connection_id: connection.id,
				protocol: "tcp",
				event_type: "upstream-error",
				client_ip: connection.clientIp,
				client_port: connection.clientPort,
				country_code: connection.countryCode,
				reason,
				error: error.message,
				client_to_upstream_bytes: connection.clientToUpstreamBytes,
				upstream_to_client_bytes: connection.upstreamToClientBytes,
			});
		}
		this.monitorEvent({
			stream_id: connection.record.id,
			incoming_port: connection.record.incoming_port,
			connection_id: connection.id,
			protocol: "tcp",
			event_type: "disconnected",
			client_ip: connection.clientIp,
			client_port: connection.clientPort,
			country_code: connection.countryCode,
			reason,
			error: error?.message ?? null,
			client_to_upstream_bytes: connection.clientToUpstreamBytes,
			upstream_to_client_bytes: connection.upstreamToClientBytes,
		});
		this.updateCounts(connection.record.id);
	}

	private async admitTcp(connection: TcpConnection, tls: boolean): Promise<void> {
		if (connection.closed) return;
		const record = this.tcpRuntimes.get(connection.record.id)?.record ?? connection.record;
		let decision: Awaited<ReturnType<typeof evaluateStreamIp>> | null = null;
		try {
			decision = await evaluateStreamIp(record, connection.clientIp);
		} catch (error) {
			Logger.error(`[BurrowGate] Unable to evaluate network policy for stream ${record.id}`, { error });
		}
		if (connection.closed) return;
		let blockedReason: string | null = decision?.action === "block" ? (decision.reason ?? "Blocked by network rule") : null;
		if (!blockedReason && record.max_connections_per_ip > 0) {
			const activeFromIp = [...this.tcpConnections.values()].filter(
				(other) => other.id !== connection.id && !other.closed && other.record.id === record.id && other.clientIp === connection.clientIp,
			).length;
			if (activeFromIp >= record.max_connections_per_ip) blockedReason = `Per-IP connection limit reached (${record.max_connections_per_ip})`;
		}
		if (!blockedReason) {
			const rate = checkStreamConnectionRate(record, connection.clientIp);
			if (rate.limited) blockedReason = `Connection rate limit exceeded, retry in ${rate.retryAfterSeconds}s`;
		}
		if (blockedReason) {
			this.monitorEvent({
				stream_id: record.id,
				incoming_port: record.incoming_port,
				connection_id: connection.id,
				protocol: "tcp",
				event_type: "blocked",
				client_ip: connection.clientIp,
				client_port: connection.clientPort,
				country_code: connection.countryCode,
				reason: blockedReason,
				error: null,
				client_to_upstream_bytes: 0,
				upstream_to_client_bytes: 0,
			});
			this.finishTcp(connection, blockedReason);
			return;
		}
		this.monitorEvent({
			stream_id: record.id,
			incoming_port: record.incoming_port,
			connection_id: connection.id,
			protocol: "tcp",
			event_type: "connected",
			client_ip: connection.clientIp,
			client_port: connection.clientPort,
			country_code: connection.countryCode,
			reason: tls ? "TLS terminated" : "raw TCP",
			error: null,
			client_to_upstream_bytes: 0,
			upstream_to_client_bytes: 0,
		});
		void this.openTcpUpstream(connection);
	}

	private async openTcpUpstream(connection: TcpConnection): Promise<void> {
		const connect = this.dependencies.connect ?? ((options) => Bun.connect(options));
		const connectTimer = setTimeout(
			() => this.finishTcp(connection, "upstream connection timeout", new Error("TCP upstream connection timed out")),
			config.streams.connectTimeoutSeconds * 1_000,
		);
		(connectTimer as unknown as { unref?: () => void }).unref?.();
		try {
			const upstream = await connect({
				hostname: connection.record.forward_host,
				port: connection.record.forward_port,
				data: connection,
				allowHalfOpen: true,
				socket: {
					open: (socket) => {
						if (connection.closed) {
							socket.terminate();
							return;
						}
						connection.upstream = socket;
						socket.timeout(config.streams.idleTimeoutSeconds);
						this.flushTcp(connection, "upstream");
						if (connection.clientEnded) socket.end();
					},
					data: (_socket, data) => this.writeTcp(connection, "client", data),
					drain: () => this.flushTcp(connection, "upstream"),
					end: () => {
						connection.client.end();
					},
					close: (_socket, error) => this.finishTcp(connection, "upstream closed", error),
					error: (_socket, error) => this.finishTcp(connection, "upstream error", error),
					connectError: (_socket, error) => this.finishTcp(connection, "upstream connection failed", error),
					timeout: () => this.finishTcp(connection, "upstream idle timeout"),
				},
			});
			if (connection.closed) upstream.terminate();
			else connection.upstream = upstream;
		} catch (error) {
			this.finishTcp(connection, "upstream connection failed", error instanceof Error ? error : new Error(String(error)));
		} finally {
			clearTimeout(connectTimer);
		}
	}

	private async startTcp(record: StreamRecord): Promise<void> {
		const listen = this.dependencies.listen ?? ((options) => Bun.listen(options));
		const tls = record.certificate_id ? await (this.dependencies.tlsOption ?? streamCertificateTlsOption)(record.certificate_id) : undefined;
		const listener = listen({
			hostname: config.host,
			port: record.incoming_port,
			...(tls ? { tls } : {}),
			allowHalfOpen: true,
			socket: {
				open: async (client) => {
					const clientIp = client.remoteAddress;
					const connection: TcpConnection = {
						id: randomId("stream_conn"),
						record,
						client,
						upstream: null,
						openedAt: Date.now(),
						lastActivityAt: Date.now(),
						clientIp,
						clientPort: client.remotePort,
						countryCode: lookupCountryCode(clientIp),
						clientToUpstreamBytes: 0,
						upstreamToClientBytes: 0,
						toUpstream: [],
						toClient: [],
						queuedBytes: 0,
						closed: false,
						clientEnded: false,
					};
					client.data = connection;
					client.timeout(config.streams.idleTimeoutSeconds);
					this.tcpConnections.set(connection.id, connection);
					this.updateCounts(record.id);
					await this.admitTcp(connection, Boolean(tls));
				},
				data: (client, data) => this.writeTcp(client.data, "upstream", data),
				drain: (client) => this.flushTcp(client.data, "client"),
				end: (client) => {
					client.data.clientEnded = true;
					client.data.upstream?.end();
				},
				close: (client, error) => this.finishTcp(client.data, "client closed", error),
				error: (client, error) => this.finishTcp(client.data, "client error", error),
				timeout: (client) => this.finishTcp(client.data, "client idle timeout"),
			},
		});
		this.tcpRuntimes.set(record.id, { record, fingerprint: tcpFingerprint(record), listener });
		Logger.info(
			`[BurrowGate] TCP stream listening on ${config.host}:${record.incoming_port} -> ${record.forward_host}:${record.forward_port}${tls ? " with TLS termination" : ""}`,
		);
	}

	private stopTcp(streamId: string): void {
		const runtime = this.tcpRuntimes.get(streamId);
		if (!runtime) return;
		runtime.listener.stop(false);
		this.tcpRuntimes.delete(streamId);
	}

	private async createUdpPeer(runtime: UdpRuntime, clientIp: string, clientPort: number): Promise<UdpPeer> {
		if (runtime.peers.size >= config.streams.maxUdpPeersPerStream) {
			const oldest = [...runtime.peers.values()].sort((a, b) => a.lastActivityAt - b.lastActivityAt)[0];
			if (oldest) this.closeUdpPeer(runtime, oldest, "peer limit eviction");
		}
		const udpSocket = this.dependencies.udpSocket ?? Bun.udpSocket;
		const id = randomId("stream_peer");
		let peer!: UdpPeer;
		const upstream = await udpSocket({
			binaryType: "buffer",
			connect: { hostname: runtime.forwardAddress, port: runtime.record.forward_port },
			socket: {
				data: (_socket, data, _port, _address, flags) => {
					if (!peer || peer.closed || runtime.closed) return;
					peer.lastActivityAt = Date.now();
					if (flags.truncated) return this.closeUdpPeer(runtime, peer, "truncated upstream datagram", new Error("UDP datagram was truncated"));
					const sent = runtime.socket.send(data, peer.clientPort, peer.clientIp);
					if (sent) this.recordUdpBytes(peer, "client", data.byteLength);
					else if (runtime.pendingReplies.length < config.streams.maxPendingDatagrams) runtime.pendingReplies.push({ peer, data: copyChunk(data) });
					else this.closeUdpPeer(runtime, peer, "UDP reply queue exceeded", new Error("UDP reply queue limit exceeded"));
				},
				drain: () => {
					if (peer) this.flushUdpUpstream(peer);
				},
				error: (_socket, error) => {
					if (peer) this.closeUdpPeer(runtime, peer, "upstream UDP error", error);
				},
			},
		});
		if (runtime.closed) {
			upstream.close();
			throw new Error("UDP stream was closed while creating a peer");
		}
		peer = {
			id,
			record: runtime.record,
			clientIp,
			clientPort,
			countryCode: lookupCountryCode(clientIp),
			openedAt: Date.now(),
			lastActivityAt: Date.now(),
			clientToUpstreamBytes: 0,
			upstreamToClientBytes: 0,
			upstream,
			pendingUpstream: [],
			closed: false,
		};
		runtime.peers.set(udpPeerKey(clientIp, clientPort), peer);
		this.monitorEvent({
			stream_id: runtime.record.id,
			incoming_port: runtime.record.incoming_port,
			connection_id: peer.id,
			protocol: "udp",
			event_type: "connected",
			client_ip: peer.clientIp,
			client_port: peer.clientPort,
			country_code: peer.countryCode,
			reason: "first datagram",
			error: null,
			client_to_upstream_bytes: 0,
			upstream_to_client_bytes: 0,
		});
		this.updateCounts(runtime.record.id);
		return peer;
	}

	private async udpPeer(runtime: UdpRuntime, clientIp: string, clientPort: number): Promise<UdpPeer> {
		const key = udpPeerKey(clientIp, clientPort);
		const existing = runtime.peers.get(key);
		if (existing) return existing;
		let pending = runtime.pendingPeers.get(key);
		if (!pending) {
			pending = this.createUdpPeer(runtime, clientIp, clientPort).finally(() => runtime.pendingPeers.delete(key));
			runtime.pendingPeers.set(key, pending);
		}
		return await pending;
	}

	private recordUdpBytes(peer: UdpPeer, direction: "upstream" | "client", count: number): void {
		if (direction === "upstream") peer.clientToUpstreamBytes += count;
		else peer.upstreamToClientBytes += count;
		recordStreamTraffic(
			{ streamId: peer.record.id, incomingPort: peer.record.incoming_port, ip: peer.clientIp, countryCode: peer.countryCode, protocol: "udp" },
			direction === "upstream" ? { clientToUpstreamBytes: count } : { upstreamToClientBytes: count },
		);
	}

	private async handleUdpData(runtime: UdpRuntime, data: Uint8Array, clientPort: number, clientIp: string, truncated: boolean): Promise<void> {
		try {
			const key = udpPeerKey(clientIp, clientPort);
			if (!runtime.peers.has(key) && !runtime.pendingPeers.has(key)) {
				let blockedReason: string | null = null;
				try {
					const decision = await evaluateStreamIp(runtime.record, clientIp);
					if (decision.action === "block") blockedReason = decision.reason ?? "Blocked by network rule";
				} catch (error) {
					Logger.error(`[BurrowGate] Unable to evaluate network policy for stream ${runtime.record.id}`, { error });
				}
				if (!blockedReason && runtime.record.max_connections_per_ip > 0) {
					const activeFromIp = [...runtime.peers.values()].filter((peer) => peer.clientIp === clientIp).length;
					if (activeFromIp >= runtime.record.max_connections_per_ip) {
						blockedReason = `Per-IP connection limit reached (${runtime.record.max_connections_per_ip})`;
					}
				}
				if (!blockedReason) {
					const rate = checkStreamConnectionRate(runtime.record, clientIp);
					if (rate.limited) blockedReason = `Connection rate limit exceeded, retry in ${rate.retryAfterSeconds}s`;
				}
				if (blockedReason) {
					this.monitorEvent({
						stream_id: runtime.record.id,
						incoming_port: runtime.record.incoming_port,
						connection_id: null,
						protocol: "udp",
						event_type: "blocked",
						client_ip: clientIp,
						client_port: clientPort,
						country_code: lookupCountryCode(clientIp),
						reason: blockedReason,
						error: null,
						client_to_upstream_bytes: 0,
						upstream_to_client_bytes: 0,
					});
					return;
				}
			}
			const peer = await this.udpPeer(runtime, clientIp, clientPort);
			if (peer.closed) return;
			peer.lastActivityAt = Date.now();
			if (truncated) return this.closeUdpPeer(runtime, peer, "truncated client datagram", new Error("UDP datagram was truncated"));
			const sent = peer.upstream.send(data);
			if (sent) this.recordUdpBytes(peer, "upstream", data.byteLength);
			else if (peer.pendingUpstream.length < config.streams.maxPendingDatagrams) peer.pendingUpstream.push(copyChunk(data));
			else this.closeUdpPeer(runtime, peer, "UDP upstream queue exceeded", new Error("UDP upstream queue limit exceeded"));
		} catch (error) {
			Logger.error(`[BurrowGate] Unable to create UDP peer for ${clientIp}:${clientPort}`, { error });
		}
	}

	private flushUdpUpstream(peer: UdpPeer): void {
		while (!peer.closed && peer.pendingUpstream.length) {
			const data = peer.pendingUpstream[0]!;
			if (!peer.upstream.send(data)) return;
			peer.pendingUpstream.shift();
			this.recordUdpBytes(peer, "upstream", data.byteLength);
		}
	}

	private flushUdpReplies(runtime: UdpRuntime): void {
		while (runtime.pendingReplies.length) {
			const reply = runtime.pendingReplies[0]!;
			if (reply.peer.closed) {
				runtime.pendingReplies.shift();
				continue;
			}
			if (!runtime.socket.send(reply.data, reply.peer.clientPort, reply.peer.clientIp)) return;
			runtime.pendingReplies.shift();
			this.recordUdpBytes(reply.peer, "client", reply.data.byteLength);
		}
	}

	private closeUdpPeer(runtime: UdpRuntime, peer: UdpPeer, reason: string, error?: Error): void {
		if (peer.closed) return;
		peer.closed = true;
		peer.upstream.close();
		runtime.peers.delete(udpPeerKey(peer.clientIp, peer.clientPort));
		if (error) {
			this.monitorEvent({
				stream_id: peer.record.id,
				incoming_port: peer.record.incoming_port,
				connection_id: peer.id,
				protocol: "udp",
				event_type: "upstream-error",
				client_ip: peer.clientIp,
				client_port: peer.clientPort,
				country_code: peer.countryCode,
				reason,
				error: error.message,
				client_to_upstream_bytes: peer.clientToUpstreamBytes,
				upstream_to_client_bytes: peer.upstreamToClientBytes,
			});
		}
		this.monitorEvent({
			stream_id: peer.record.id,
			incoming_port: peer.record.incoming_port,
			connection_id: peer.id,
			protocol: "udp",
			event_type: "disconnected",
			client_ip: peer.clientIp,
			client_port: peer.clientPort,
			country_code: peer.countryCode,
			reason,
			error: error?.message ?? null,
			client_to_upstream_bytes: peer.clientToUpstreamBytes,
			upstream_to_client_bytes: peer.upstreamToClientBytes,
		});
		this.updateCounts(peer.record.id);
	}

	private async startUdp(record: StreamRecord): Promise<void> {
		const resolveHost = this.dependencies.resolveHost ?? (async (hostname) => (await lookup(hostname)).address);
		const forwardAddress = await resolveHost(record.forward_host);
		const udpSocket = this.dependencies.udpSocket ?? Bun.udpSocket;
		let runtime!: UdpRuntime;
		const socket = await udpSocket({
			hostname: config.host,
			port: record.incoming_port,
			binaryType: "buffer",
			socket: {
				data: (_socket, data, port, address, flags) => void this.handleUdpData(runtime, data, port, address, flags.truncated),
				drain: () => this.flushUdpReplies(runtime),
				error: (_socket, error) => {
					this.statusFor(record).error = error.message;
					Logger.error(`[BurrowGate] UDP stream error on port ${record.incoming_port}`, { error });
				},
			},
		});
		const cleanupTimer = setInterval(
			() => {
				const cutoff = Date.now() - config.streams.udpPeerIdleTimeoutSeconds * 1_000;
				for (const peer of runtime.peers.values()) if (peer.lastActivityAt <= cutoff) this.closeUdpPeer(runtime, peer, "UDP peer idle timeout");
			},
			Math.min(10_000, config.streams.udpPeerIdleTimeoutSeconds * 500),
		);
		(cleanupTimer as unknown as { unref?: () => void }).unref?.();
		runtime = {
			record,
			fingerprint: udpFingerprint(record),
			socket,
			forwardAddress,
			peers: new Map(),
			pendingPeers: new Map(),
			pendingReplies: [],
			cleanupTimer,
			closed: false,
		};
		this.udpRuntimes.set(record.id, runtime);
		Logger.info(`[BurrowGate] UDP stream listening on ${config.host}:${record.incoming_port} -> ${forwardAddress}:${record.forward_port}`);
	}

	private stopUdp(streamId: string, reason: string): void {
		const runtime = this.udpRuntimes.get(streamId);
		if (!runtime) return;
		runtime.closed = true;
		clearInterval(runtime.cleanupTimer);
		for (const peer of [...runtime.peers.values()]) this.closeUdpPeer(runtime, peer, reason);
		runtime.socket.close();
		this.udpRuntimes.delete(streamId);
	}

	statusesView(): StreamRuntimeStatus[] {
		for (const id of this.statuses.keys()) this.updateCounts(id);
		return [...this.statuses.values()].map((status) => ({ ...status }));
	}

	activeConnections(): ActiveStreamConnection[] {
		const tcp: ActiveStreamConnection[] = [...this.tcpConnections.values()]
			.filter((connection) => !connection.closed)
			.map((connection) => ({
				id: connection.id,
				streamId: connection.record.id,
				incomingPort: connection.record.incoming_port,
				protocol: "tcp",
				clientIp: connection.clientIp,
				clientPort: connection.clientPort,
				countryCode: connection.countryCode,
				connectedAt: connection.openedAt,
				lastActivityAt: connection.lastActivityAt,
				clientToUpstreamBytes: connection.clientToUpstreamBytes,
				upstreamToClientBytes: connection.upstreamToClientBytes,
			}));
		const udp: ActiveStreamConnection[] = [...this.udpRuntimes.values()].flatMap((runtime) =>
			[...runtime.peers.values()].map((peer) => ({
				id: peer.id,
				streamId: peer.record.id,
				incomingPort: peer.record.incoming_port,
				protocol: "udp" as const,
				clientIp: peer.clientIp,
				clientPort: peer.clientPort,
				countryCode: peer.countryCode,
				connectedAt: peer.openedAt,
				lastActivityAt: peer.lastActivityAt,
				clientToUpstreamBytes: peer.clientToUpstreamBytes,
				upstreamToClientBytes: peer.upstreamToClientBytes,
			})),
		);
		return [...tcp, ...udp].sort((a, b) => b.connectedAt - a.connectedAt);
	}

	async enforceNetworkPolicy(record: StreamRecord): Promise<void> {
		this.syncRecord(record);
		const tcpTargets = [...this.tcpConnections.values()].filter((connection) => connection.record.id === record.id && !connection.closed);
		for (const connection of tcpTargets) {
			if (connection.closed) continue;
			let decision: Awaited<ReturnType<typeof evaluateStreamIp>> | null = null;
			try {
				decision = await evaluateStreamIp(record, connection.clientIp);
			} catch (error) {
				Logger.error(`[BurrowGate] Unable to evaluate network policy for stream ${record.id}`, { error });
			}
			if (decision?.action !== "block") continue;
			this.monitorEvent({
				stream_id: record.id,
				incoming_port: record.incoming_port,
				connection_id: connection.id,
				protocol: "tcp",
				event_type: "blocked",
				client_ip: connection.clientIp,
				client_port: connection.clientPort,
				country_code: connection.countryCode,
				reason: decision.reason ?? "Blocked by network rule",
				error: null,
				client_to_upstream_bytes: 0,
				upstream_to_client_bytes: 0,
			});
			this.finishTcp(connection, decision.reason ?? "blocked by network rule");
		}
		const runtime = this.udpRuntimes.get(record.id);
		if (!runtime) return;
		for (const peer of [...runtime.peers.values()]) {
			if (peer.closed) continue;
			let decision: Awaited<ReturnType<typeof evaluateStreamIp>> | null = null;
			try {
				decision = await evaluateStreamIp(record, peer.clientIp);
			} catch (error) {
				Logger.error(`[BurrowGate] Unable to evaluate network policy for stream ${record.id}`, { error });
			}
			if (decision?.action !== "block") continue;
			this.monitorEvent({
				stream_id: record.id,
				incoming_port: record.incoming_port,
				connection_id: peer.id,
				protocol: "udp",
				event_type: "blocked",
				client_ip: peer.clientIp,
				client_port: peer.clientPort,
				country_code: peer.countryCode,
				reason: decision.reason ?? "Blocked by network rule",
				error: null,
				client_to_upstream_bytes: 0,
				upstream_to_client_bytes: 0,
			});
			this.closeUdpPeer(runtime, peer, decision.reason ?? "blocked by network rule");
		}
	}
}

export const streamProxyManager = new StreamProxyManager();
