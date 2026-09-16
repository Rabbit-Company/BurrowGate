import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Web } from "@rabbit-company/web";
import { config } from "../src/config.ts";
import { db } from "../src/db/client.ts";
import { repository } from "../src/db/repository.ts";
import { registerAdminRoutes } from "../src/routes/admin-routes.ts";
import { haMeshService } from "../src/services/ha-mesh-service.ts";
import { haTlsCertificate, resetHaTlsCertificateCache } from "../src/services/ha-tls-service.ts";
import { APP_VERSION } from "../src/ui/layout.ts";
import { sha256Hex } from "../src/utils/crypto.ts";

const app = new Web();
registerAdminRoutes(app);
const originalHa = { ...config.ha };
const originalDataDirectory = config.dataDirectory;
let directory = "";
let nodeId = "";
const credential = "pending-enrolled-node-credential";

beforeEach(async () => {
	directory = await mkdtemp(join(tmpdir(), "bg-ha-certificate-bootstrap-"));
	config.dataDirectory = directory;
	config.ha.enabled = true;
	config.ha.tlsCertFile = null;
	config.ha.tlsKeyFile = null;
	config.ha.selfAdminUrl = null;
	resetHaTlsCertificateCache();
	nodeId = crypto.randomUUID();
	const enrollmentHash = await sha256Hex(crypto.randomUUID());
	const now = Date.now();
	await repository.createHaEnrollmentCode(enrollmentHash, now + 60_000);
	expect(
		await repository.redeemHaEnrollmentCode(
			enrollmentHash,
			now,
			{
				node_id: nodeId,
				name: "pending-replica",
				version: APP_VERSION,
				admin_url: "https://replica.test",
				first_seen_at: now,
				last_seen_at: now,
			},
			await sha256Hex(credential),
		),
	).toBe(true);
});

afterEach(async () => {
	await db`DELETE FROM ha_cluster_members WHERE node_id=${nodeId}`;
	Object.assign(config.ha, originalHa);
	config.dataDirectory = originalDataDirectory;
	resetHaTlsCertificateCache();
	if (directory) await rm(directory, { recursive: true, force: true });
});

function certificateRequest(token = credential): Request {
	return new Request("https://primary.test/_burrowgate/api/admin/ha/certificate", {
		headers: { authorization: `Bearer ${token}` },
	});
}

describe("HA certificate recovery before first mesh activation", () => {
	test("an enrolled, pending replica can recover the primary certificate but cannot resolve admin sessions", async () => {
		expect(await repository.haMemberByCredentialHash(await sha256Hex(credential))).toMatchObject({ active: false });
		const response = await app.handle(certificateRequest());
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ cert: (await haTlsCertificate()).cert });
		const sessionResponse = await app.handle(
			new Request("https://primary.test/_burrowgate/api/admin/ha/resolve-admin-session", {
				method: "POST",
				headers: { authorization: `Bearer ${credential}`, "content-type": "application/json" },
				body: JSON.stringify({ tokenHash: "a".repeat(64) }),
			}),
		);
		expect(sessionResponse.status).toBe(401);
	});

	test("unknown and revoked credentials cannot obtain the certificate", async () => {
		expect((await app.handle(certificateRequest("unknown-credential"))).status).toBe(401);
		await db`UPDATE ha_cluster_members SET revoked_at=${Date.now()} WHERE node_id=${nodeId}`;
		expect((await app.handle(certificateRequest())).status).toBe(401);
	});
});

test("a replica connects over WSS after the primary restarts and regenerates its certificate for the saved address", async () => {
	const mesh = haMeshService as unknown as { caCertificate: string | null; tlsOptions(): { ca: string } | undefined };
	const originalCa = mesh.caCertificate;
	const connect = async (certificate: { cert: string; key: string }, trustedCertificate = certificate.cert): Promise<{ opened: boolean; code: number }> => {
		const server = Bun.serve({
			hostname: "127.0.0.2",
			port: 0,
			tls: certificate,
			fetch(request, server) {
				if (server.upgrade(request)) return;
				return new Response("Upgrade failed", { status: 400 });
			},
			websocket: { message() {} },
		});
		mesh.caCertificate = trustedCertificate;
		const socket = new WebSocket(`wss://127.0.0.2:${server.port}/_ha/stream`, { tls: mesh.tlsOptions() });
		try {
			return await new Promise((resolve, reject) => {
				let opened = false;
				const timeout = setTimeout(() => reject(new Error("WSS connection timed out")), 3_000);
				socket.addEventListener("open", () => {
					opened = true;
					socket.close();
				});
				socket.addEventListener("close", (event) => {
					clearTimeout(timeout);
					resolve({ opened, code: event.code });
				});
			});
		} finally {
			socket.close();
			await server.stop(true);
		}
	};
	try {
		const initial = await haTlsCertificate();
		expect(await connect(initial)).toMatchObject({ opened: false, code: 1015 });
		config.ha.selfAdminUrl = "https://127.0.0.2";
		resetHaTlsCertificateCache();
		const regenerated = await haTlsCertificate();
		expect(await connect(regenerated)).toMatchObject({ opened: true });
		expect(await connect(regenerated, initial.cert)).toMatchObject({ opened: false, code: 1015 });
	} finally {
		mesh.caCertificate = originalCa;
	}
});
