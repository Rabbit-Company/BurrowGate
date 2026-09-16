import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { createConnection, type Socket } from "node:net";
import { connect as connectTls } from "node:tls";
import { connect as connectHttp2 } from "node:http2";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Web } from "@rabbit-company/web";
import { config, requestIsSecure } from "../src/config.ts";
import { incomingProxyConnection } from "../src/services/incoming-proxy-protocol.ts";
import { ProxyProtocolIngress } from "../src/services/proxy-protocol-ingress.ts";
import { proxyProtocolHeader } from "../src/services/stream-proxy-protocol.ts";
import { TlsListenerManager } from "../src/services/tls-listener-service.ts";
import { StreamProxyManager } from "../src/services/stream-proxy-service.ts";
import { buildStream } from "../src/services/stream-service.ts";
import { haTlsCertificate, resetHaTlsCertificateCache } from "../src/services/ha-tls-service.ts";
import { clientIpForUpgrade } from "../src/services/websocket-proxy-service.ts";
import { createSite } from "../src/services/site-service.ts";
import { repository } from "../src/db/repository.ts";
import { loadBalancer } from "../src/services/load-balancer-service.ts";

const originalHttp = { ...config.http };
const originalHttps = { ...config.https };
const originalHa = { ...config.ha };
const originalHost = config.host;
const originalDataDirectory = config.dataDirectory;
const originalTrusted = config.proxyProtocol.trustedCidrs;
const originalAllowDirect = config.proxyProtocol.allowDirect;
const listeners: TlsListenerManager[] = [];
const streams: Array<{ manager: StreamProxyManager; id: string }> = [];
const servers: Array<{ stop(force?: boolean): void | Promise<void> }> = [];
const sockets = new Set<Socket>();
const siteIds: string[] = [];
let directory = "";

beforeEach(async () => {
	config.host = "127.0.0.1";
	Object.assign(config.http, { enabled: true, port: 0, proxyProtocol: true });
	Object.assign(config.https, { enabled: false, port: 0, proxyProtocol: true, http2Enabled: false, http3Enabled: false });
	config.proxyProtocol.trustedCidrs = ["127.0.0.1/32"];
	config.proxyProtocol.allowDirect = false;
	directory = await mkdtemp(join(tmpdir(), "bg-proxy-ingress-"));
	config.dataDirectory = directory;
	Object.assign(config.ha, { selfAdminUrl: null, tlsCertFile: null, tlsKeyFile: null });
	resetHaTlsCertificateCache();
});

afterEach(async () => {
	for (const socket of sockets) socket.destroy();
	sockets.clear();
	await Promise.all(listeners.splice(0).map((manager) => manager.stop()));
	for (const { manager, id } of streams.splice(0)) await manager.remove(id);
	for (const server of servers.splice(0)) await server.stop(true);
	for (const siteId of siteIds.splice(0)) {
		await repository.deleteSiteCascade(siteId);
		await loadBalancer.refreshSite(siteId);
	}
	Object.assign(config.http, originalHttp);
	Object.assign(config.https, originalHttps);
	Object.assign(config.ha, originalHa);
	config.host = originalHost;
	config.dataDirectory = originalDataDirectory;
	config.proxyProtocol.trustedCidrs = originalTrusted;
	config.proxyProtocol.allowDirect = originalAllowDirect;
	resetHaTlsCertificateCache();
	await rm(directory, { recursive: true, force: true });
});

function header(version: "v1" | "v2", ip = "203.0.113.8"): Buffer {
	return proxyProtocolHeader(version, "tcp", { sourceAddress: ip, sourcePort: 45678, destinationAddress: "192.0.2.20", destinationPort: 443 });
}

async function socketTo(port: number): Promise<Socket> {
	const socket = createConnection({ host: "127.0.0.1", port });
	sockets.add(socket);
	await new Promise<void>((resolve, reject) => {
		socket.once("connect", resolve);
		socket.once("error", reject);
	});
	return socket;
}

function readAll(socket: Socket): Promise<string> {
	return new Promise((resolve, reject) => {
		const data: Buffer[] = [];
		const timer = setTimeout(() => {
			socket.destroy();
			reject(new Error(`Timed out reading the proxy response: ${Buffer.concat(data).toString()}`));
		}, 3000);
		socket.on("data", (chunk) => data.push(Buffer.from(chunk)));
		socket.once("error", reject);
		socket.once("close", () => {
			clearTimeout(timer);
			resolve(Buffer.concat(data).toString());
		});
	});
}

function listenerPort(manager: TlsListenerManager, transport = "http"): number {
	return (manager as unknown as Record<string, ProxyProtocolIngress>)[`${transport}Ingress`]!.port;
}

async function siteListener(tls = false): Promise<TlsListenerManager> {
	const app = new Web();
	app.get("/client", async (ctx) => {
		// Check that the request and upgrade handler use the same client address.
		const connection = incomingProxyConnection(ctx.req);
		const upgradeIp = await clientIpForUpgrade(ctx.req, { requestIP: () => ({ address: "127.0.0.1" }), upgrade: () => false }, "nginx");
		return Response.json({ ip: ctx.clientIp, port: connection?.sourcePort ?? null, secure: requestIsSecure(ctx.req), upgradeIp });
	});
	config.http.enabled = !tls;
	config.https.enabled = tls;
	const certificate = tls ? await haTlsCertificate() : null;
	const manager = new TlsListenerManager(app, { managedCertificates: async () => [], bootstrapCertificate: async () => certificate });
	listeners.push(manager);
	await manager.start();
	return manager;
}

const httpRequest = "GET /client HTTP/1.1\r\nHost: example.test\r\nX-Forwarded-For: 1.2.3.4\r\nConnection: close\r\n\r\n";

describe("Sites behind a load balancer", () => {
	test("preserves client metadata for HTTP/2 requests after a v2 header and TLS negotiation", async () => {
		config.https.http2Enabled = true;
		const manager = await siteListener(true);
		const raw = await socketTo(listenerPort(manager, "https"));
		raw.write(header("v2"));
		const tls = connectTls({ socket: raw, ca: (await haTlsCertificate()).cert, servername: "localhost", ALPNProtocols: ["h2"] });
		sockets.add(tls);
		const session = connectHttp2("https://localhost", { createConnection: () => tls });
		try {
			const request = session.request({ ":path": "/client", "x-forwarded-for": "1.2.3.4" });
			const response = await new Promise<string>((resolve, reject) => {
				let body = "";
				const timer = setTimeout(() => reject(new Error("HTTP/2 response timed out")), 3000);
				request.on("data", (chunk) => {
					body += chunk.toString();
				});
				request.on("error", (error) => {
					clearTimeout(timer);
					reject(error);
				});
				session.on("error", (error) => {
					clearTimeout(timer);
					reject(error);
				});
				request.on("end", () => {
					clearTimeout(timer);
					resolve(body);
				});
				request.end();
			});
			expect(JSON.parse(response)).toMatchObject({ ip: "203.0.113.8", secure: true });
		} finally {
			session.destroy();
		}
	});

	test("retains one client identity over keep-alive requests and isolates concurrent clients", async () => {
		const manager = await siteListener();
		const request = httpRequest.replace("Connection: close", "Connection: keep-alive");
		const results = await Promise.all(
			["203.0.113.8", "203.0.113.9"].map(async (ip) => {
				const socket = await socketTo(listenerPort(manager));
				const response = readAll(socket);
				socket.write(Buffer.concat([header("v2", ip), Buffer.from(request + httpRequest)]));
				return { ip, response: await response };
			}),
		);
		for (const { ip, response } of results) expect(response.split(`"ip":"${ip}"`)).toHaveLength(3);
	});

	test("upgrades a real WebSocket request and forwards its PROXY client IP to the origin", async () => {
		let forwardedIp = "";
		const origin = Bun.serve({
			hostname: "127.0.0.1",
			port: 0,
			fetch(request, server) {
				forwardedIp = request.headers.get("x-forwarded-for") ?? "";
				if (server.upgrade(request)) return;
				return new Response("Upgrade failed", { status: 400 });
			},
			websocket: {
				message(socket) {
					socket.send("pong");
				},
			},
		});
		servers.push(origin);
		const host = `proxy-ws-${crypto.randomUUID()}.test`;
		const { site } = await createSite({
			name: "PROXY WebSocket",
			publicHost: host,
			originUrl: `http://127.0.0.1:${origin.port}`,
			defaultAccessMode: "bypass",
			ipExtractionPreset: "nginx",
		});
		siteIds.push(site.id);
		await loadBalancer.refreshSite(site.id);
		const manager = await siteListener();
		const socket = await socketTo(listenerPort(manager));
		const response = readAll(socket);
		let upgraded = false;
		socket.on("data", (chunk) => {
			if (!upgraded && chunk.toString().includes("101 ")) {
				upgraded = true;
				const mask = [1, 2, 3, 4];
				socket.write(Buffer.from([0x81, 0x84, ...mask, ...[...Buffer.from("ping")].map((byte, index) => byte ^ mask[index]!)]));
			}
			if (Buffer.from(chunk).includes(Buffer.from("pong"))) socket.end();
		});
		socket.write(
			Buffer.concat([
				header("v2"),
				Buffer.from(
					`GET /echo HTTP/1.1\r\nHost: ${host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nX-Forwarded-For: 1.2.3.4\r\n\r\n`,
				),
			]),
		);
		expect(await response).toContain("pong");
		expect(upgraded).toBe(true);
		expect(forwardedIp).toBe("203.0.113.8");
	});

	test("allows direct HTTP and HTTPS alongside PROXY traffic, while rejecting headers from untrusted direct peers", async () => {
		config.proxyProtocol.allowDirect = true;
		const manager = await siteListener();
		const socket = await socketTo(listenerPort(manager));
		const response = readAll(socket);
		socket.write(httpRequest);
		expect(await response).toContain('"ip":"127.0.0.1"');
		await manager.stop();
		listeners.pop();
		config.proxyProtocol.trustedCidrs = ["192.0.2.1/32"];
		const tlsManager = await siteListener(true);
		const raw = await socketTo(listenerPort(tlsManager, "https"));
		const tls = connectTls({ socket: raw, ca: (await haTlsCertificate()).cert, servername: "localhost" });
		sockets.add(tls);
		const tlsResponse = readAll(tls);
		tls.write(httpRequest);
		expect(await tlsResponse).toContain('"ip":"127.0.0.1"');
		const forged = await socketTo(listenerPort(tlsManager, "https"));
		const rejected = readAll(forged);
		forged.write(header("v1"));
		expect(await rejected).toBe("");
	});

	for (const version of ["v1", "v2"] as const) {
		test(`${version}: reads a fragmented header before HTTP and preserves the client address over spoofed HTTP headers`, async () => {
			const manager = await siteListener();
			const socket = await socketTo(listenerPort(manager));
			const response = readAll(socket);
			const headerBytes = header(version);
			socket.write(headerBytes.subarray(0, 5));
			await new Promise((resolve) => setTimeout(resolve, 10));
			socket.write(Buffer.concat([headerBytes.subarray(5), Buffer.from(httpRequest)]));
			const result = await response;
			expect(result).toContain('"ip":"203.0.113.8"');
			expect(result).toContain('"upgradeIp":"203.0.113.8"');
			expect(result).toContain('"secure":false');
		});
	}

	test("strips the v2 header before TLS and keeps accepting clients after a certificate reload", async () => {
		const manager = await siteListener(true);
		const port = listenerPort(manager, "https");
		for (let attempt = 0; attempt < 2; attempt++) {
			const raw = await socketTo(port);
			raw.write(header("v2"));
			const tls = connectTls({ socket: raw, ca: (await haTlsCertificate()).cert, servername: "localhost" });
			sockets.add(tls);
			const response = readAll(tls);
			tls.write(httpRequest);
			const result = await response;
			expect(result).toContain('"ip":"203.0.113.8"');
			expect(result).toContain('"secure":true');
			if (attempt === 0) await manager.reloadHttps();
		}
		expect(listenerPort(manager, "https")).toBe(port);
	});

	test("rejects a direct request and an untrusted sender before dispatching HTTP", async () => {
		const manager = await siteListener();
		const direct = await socketTo(listenerPort(manager));
		const directResponse = readAll(direct);
		direct.write(httpRequest);
		expect(await directResponse).toBe("");
		await manager.stop();
		listeners.pop();
		config.proxyProtocol.trustedCidrs = ["192.0.2.1/32"];
		const untrustedManager = await siteListener();
		const untrusted = await socketTo(listenerPort(untrustedManager));
		const response = readAll(untrusted);
		untrusted.write(Buffer.concat([header("v1"), Buffer.from(httpRequest)]));
		expect(await response).toBe("");
	});
});

test("a TCP stream applies the forwarded IP before admission and forwards it upstream without double headers or counting the header", async () => {
	let received = Buffer.alloc(0);
	let active: ReturnType<StreamProxyManager["activeConnections"]> = [];
	const origin = Bun.listen({
		hostname: "127.0.0.1",
		port: 0,
		socket: {
			data(socket, data) {
				received = Buffer.concat([received, Buffer.from(data)]);
				active = manager.activeConnections();
				socket.end("accepted");
			},
		},
	});
	servers.push(origin);
	const probe = Bun.listen({ hostname: "127.0.0.1", port: 0, socket: { data() {} } });
	const port = probe.port;
	probe.stop(true);
	const record = await buildStream({
		name: "Ingress test",
		incomingPort: port,
		forwardHost: "127.0.0.1",
		forwardPort: origin.port,
		incomingProxyProtocol: true,
		trustedProxyCidrs: ["127.0.0.1/32"],
		proxyProtocol: "v1",
	});
	const manager = new StreamProxyManager();
	streams.push({ manager, id: record.id });
	await manager.apply(record);
	const socket = await socketTo(port);
	const response = readAll(socket);
	socket.write(Buffer.concat([header("v2"), Buffer.from("payload")]));
	expect(await response).toBe("accepted");
	expect(received.toString()).toBe("PROXY TCP4 203.0.113.8 192.0.2.20 45678 443\r\npayload");
	expect(active).toMatchObject([{ clientIp: "203.0.113.8", clientPort: 45678, clientToUpstreamBytes: 7 }]);
});

test("a stream's connection cap groups clients by the reported IP, rather than the shared load balancer", async () => {
	const origin = Bun.listen({
		hostname: "127.0.0.1",
		port: 0,
		socket: {
			open(socket) {
				socket.write("accepted");
			},
			data() {},
		},
	});
	servers.push(origin);
	const probe = Bun.listen({ hostname: "127.0.0.1", port: 0, socket: { data() {} } });
	const port = probe.port;
	probe.stop(true);
	const record = await buildStream({
		name: "Ingress cap test",
		incomingPort: port,
		forwardHost: "127.0.0.1",
		forwardPort: origin.port,
		incomingProxyProtocol: true,
		trustedProxyCidrs: ["127.0.0.1"],
		maxConnectionsPerIp: 1,
	});
	const manager = new StreamProxyManager();
	streams.push({ manager, id: record.id });
	await manager.apply(record);
	const connectClient = async (ip: string) => {
		const socket = await socketTo(port);
		const data = new Promise<string>((resolve, reject) => {
			const timer = setTimeout(() => reject(new Error("Stream admission timed out")), 1000);
			socket.once("data", (chunk) => {
				clearTimeout(timer);
				resolve(chunk.toString());
			});
			socket.once("close", () => {
				clearTimeout(timer);
				resolve("");
			});
		});
		socket.write(header("v1", ip));
		return await data;
	};
	expect(await connectClient("203.0.113.8")).toBe("accepted");
	expect(await connectClient("203.0.113.8")).toBe("");
	expect(await connectClient("203.0.113.9")).toBe("accepted");
	expect(
		manager
			.activeConnections()
			.map((connection) => connection.clientIp)
			.sort(),
	).toEqual(["203.0.113.8", "203.0.113.9"]);
});

test("consumes the incoming header before a TCP Stream terminates TLS", async () => {
	let received = "";
	const origin = Bun.listen({
		hostname: "127.0.0.1",
		port: 0,
		socket: {
			data(socket, data) {
				received += Buffer.from(data).toString();
				socket.end("plaintext");
			},
		},
	});
	servers.push(origin);
	const probe = Bun.listen({ hostname: "127.0.0.1", port: 0, socket: { data() {} } });
	const port = probe.port;
	probe.stop(true);
	const certificate = await haTlsCertificate();
	const record = await buildStream({
		name: "Ingress TLS test",
		incomingPort: port,
		forwardHost: "127.0.0.1",
		forwardPort: origin.port,
		incomingProxyProtocol: true,
		trustedProxyCidrs: ["127.0.0.1"],
	});
	record.certificate_id = "test-certificate";
	const manager = new StreamProxyManager({ tlsOption: async () => certificate });
	streams.push({ manager, id: record.id });
	await manager.apply(record);
	const raw = await socketTo(port);
	raw.write(header("v2"));
	const tls = connectTls({ socket: raw, ca: certificate.cert, servername: "localhost" });
	sockets.add(tls);
	const response = readAll(tls);
	tls.write("payload");
	expect(await response).toBe("plaintext");
	expect(received).toBe("payload");
});

test("an incomplete header times out without reaching the application", async () => {
	let dispatched = false;
	const backend = Bun.serve({
		hostname: "127.0.0.1",
		port: 0,
		fetch: () => {
			dispatched = true;
			return new Response("unexpected");
		},
	});
	servers.push(backend);
	const ingress = new ProxyProtocolIngress({ hostname: "127.0.0.1", port: 0, targetPort: backend.port!, trustedCidrs: ["127.0.0.1"], headerTimeoutMs: 30 });
	await ingress.start();
	servers.push(ingress);
	const socket = await socketTo(ingress.port);
	const response = readAll(socket);
	socket.write("PROXY ");
	expect(await response).toBe("");
	expect(dispatched).toBe(false);
});

test("relays a large upload and response without truncation under backpressure", async () => {
	const payload = "abcdef0123456789".repeat(256 * 1024);
	const backend = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: async (request) => new Response(await request.arrayBuffer()) });
	servers.push(backend);
	const ingress = new ProxyProtocolIngress({ hostname: "127.0.0.1", port: 0, targetPort: backend.port!, trustedCidrs: ["127.0.0.1"] });
	await ingress.start();
	servers.push(ingress);
	const socket = await socketTo(ingress.port);
	const response = readAll(socket);
	socket.write(
		Buffer.concat([
			header("v2"),
			Buffer.from(`POST / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\nContent-Length: ${payload.length}\r\n\r\n${payload}`),
		]),
	);
	socket.pause();
	await new Promise((resolve) => setTimeout(resolve, 30));
	socket.resume();
	const received = await response;
	expect(received.slice(received.indexOf("\r\n\r\n") + 4)).toBe(payload);
});
