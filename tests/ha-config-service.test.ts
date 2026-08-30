import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { config } from "../src/config.ts";
import { db } from "../src/db/client.ts";
import { repository } from "../src/db/repository.ts";
import {
	deriveMeshUrl,
	haEnrollmentClient,
	joinCluster,
	leaveCluster,
	loadHaClusterConfigAtBoot,
	updateNodeIdentity,
	viewJoinCode,
} from "../src/services/ha-config-service.ts";
import { decryptSecret, encryptSecret } from "../src/services/secret-encryption-service.ts";
import { APP_VERSION } from "../src/ui/layout.ts";
import { fromBase64Url, sha256Hex, toBase64Url } from "../src/utils/crypto.ts";

const originalHa = { ...config.ha };
const originalDataDirectory = config.dataDirectory;
let tlsDataDirectory = "";

beforeEach(async () => {
	tlsDataDirectory = await mkdtemp(join(tmpdir(), "burrowgate-ha-config-test-"));
	config.dataDirectory = tlsDataDirectory;
});

afterEach(async () => {
	Object.assign(config.ha, originalHa);
	config.dataDirectory = originalDataDirectory;
	await db`DELETE FROM ha_cluster_config`;
	await db`DELETE FROM ha_cluster_members`;
	if (tlsDataDirectory) await rm(tlsDataDirectory, { recursive: true, force: true });
});

describe("loadHaClusterConfigAtBoot", () => {
	test("seeds ha_cluster_config from env-derived config.ha.* on first boot", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		config.ha.sharedToken = "env-token";
		config.ha.nodeName = "env-node";
		await loadHaClusterConfigAtBoot();
		const row = await repository.haClusterConfigRow();
		expect(row).not.toBeNull();
		expect(row!.enabled).toBe(1);
		expect(row!.role).toBe("primary");
		expect(row!.node_name).toBe("env-node");
		expect(row!.self_admin_url).toBeNull();
		expect(await decryptSecret(row!.shared_token_encrypted!)).toBe("env-token");
	});

	test("a truly fresh boot (no env vars touched) defaults to enabled+primary with an auto-generated token", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		config.ha.sharedToken = null;
		config.ha.primaryUrl = null;
		config.ha.primaryAdminUrl = null;
		await loadHaClusterConfigAtBoot();
		expect(config.ha.enabled).toBe(true);
		expect(config.ha.role).toBe("primary");
		expect(config.ha.sharedToken).toBeTruthy();
		expect(config.ha.sharedToken!.length).toBeGreaterThan(20);
		const row = await repository.haClusterConfigRow();
		expect(row?.role).toBe("primary");
		expect(row?.shared_token_encrypted).not.toBeNull();
	});

	test("a replica boot with no shared token set via env still fails validation (nothing to generate it from)", async () => {
		config.ha.role = "replica";
		config.ha.sharedToken = null;
		config.ha.primaryUrl = "https://primary.test:7443";
		config.ha.primaryAdminUrl = "https://primary.test";
		await expect(loadHaClusterConfigAtBoot()).rejects.toThrow(/BG_HA_SHARED_TOKEN/);
	});

	test("seeds a disabled row when HA is not enabled via env vars", async () => {
		config.ha.enabled = false;
		await loadHaClusterConfigAtBoot();
		const row = await repository.haClusterConfigRow();
		expect(row!.enabled).toBe(0);
	});

	test("an existing row is the live source of truth, overriding whatever is currently in config.ha.*", async () => {
		await repository.insertHaClusterConfig({
			enabled: true,
			role: "replica",
			nodeName: "db-node",
			primaryUrl: "https://primary.test:7443",
			primaryAdminUrl: "https://primary.test",
			sharedTokenEncrypted: await encryptSecret("db-token"),
			selfAdminUrl: "https://replica.test",
			clusterEpoch: 0,
		});

		config.ha.enabled = false;
		config.ha.role = "primary";
		config.ha.nodeName = "stale-env-name";

		await loadHaClusterConfigAtBoot();

		const resolvedRole: string | null = config.ha.role;
		expect(config.ha.enabled).toBe(true);
		expect(resolvedRole).toBe("replica");
		expect(config.ha.nodeName).toBe("db-node");
		expect(config.ha.primaryUrl).toBe("https://primary.test:7443");
		expect(config.ha.primaryAdminUrl).toBe("https://primary.test");
		expect(config.ha.sharedToken).toBe("db-token");
		expect(config.ha.selfAdminUrl).toBe("https://replica.test");
	});

	test("restores a stale-primary authority fence from durable config on boot", async () => {
		await repository.insertHaClusterConfig({
			enabled: true,
			role: "primary",
			nodeName: "stale-primary",
			primaryUrl: null,
			primaryAdminUrl: null,
			sharedTokenEncrypted: await encryptSecret("db-token"),
			selfAdminUrl: "https://stale-primary.test",
			clusterEpoch: 3,
		});
		await repository.fenceHaPrimaryAuthority(4, "newer-node", 123456);
		config.ha.authorityFence = null;

		await loadHaClusterConfigAtBoot();

		expect(config.ha.authorityFence as { observedEpoch: number; sourceNodeId: string; observedAt: number } | null).toEqual({
			observedEpoch: 4,
			sourceNodeId: "newer-node",
			observedAt: 123456,
		});
	});

	test("throws via validateHaConfig if the resolved config is invalid (replica with no primary URL)", async () => {
		await repository.insertHaClusterConfig({
			enabled: true,
			role: "replica",
			nodeName: "broken-node",
			primaryUrl: null,
			primaryAdminUrl: null,
			sharedTokenEncrypted: await encryptSecret("token"),
			selfAdminUrl: null,
			clusterEpoch: 0,
		});
		await expect(loadHaClusterConfigAtBoot()).rejects.toThrow(/BG_HA_PRIMARY_URL/);
	});

	test("rejects persisted plaintext HA topology URLs at boot", async () => {
		await repository.insertHaClusterConfig({
			enabled: true,
			role: "replica",
			nodeName: "plaintext-replica",
			primaryUrl: "http://primary.test:7443",
			primaryAdminUrl: "http://primary.test",
			sharedTokenEncrypted: await encryptSecret("replica-token"),
			selfAdminUrl: "http://replica.test",
			clusterEpoch: 0,
		});
		await expect(loadHaClusterConfigAtBoot()).rejects.toThrow(/HTTPS URL/);
	});

	test("rejects failover timing that could elect a replacement before the old primary fences", async () => {
		config.ha.role = "primary";
		config.ha.sharedToken = "timing-test-token";
		config.ha.autoFailoverEnabled = true;
		config.ha.electionTimeoutBaseSeconds = 30;

		config.ha.quorumLossFenceSeconds = 11;
		await expect(loadHaClusterConfigAtBoot()).rejects.toThrow(/Unsafe HA failover timing/);
	});
});

describe("deriveMeshUrl", () => {
	test("keeps https, replacing the port and dropping the path, keeping the hostname", () => {
		expect(deriveMeshUrl("https://node.example:8443/anything", 7443)).toBe("https://node.example:7443");
	});

	test("refuses to derive a mesh endpoint from a plaintext admin URL", () => {
		expect(() => deriveMeshUrl("http://node.example", 7443)).toThrow(/HTTPS/);
	});
});

describe("updateNodeIdentity / joinCluster / viewJoinCode round trip", () => {
	test("updateNodeIdentity persists and applies live config immediately, without restarting or touching role", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		await loadHaClusterConfigAtBoot();
		const tokenBefore = config.ha.sharedToken;

		await updateNodeIdentity({ nodeName: "primary-a", selfAdminUrl: "https://primary-a.test" });

		expect(config.ha.role).toBe("primary");
		expect(config.ha.nodeName).toBe("primary-a");
		expect(config.ha.selfAdminUrl).toBe("https://primary-a.test");
		expect(config.ha.sharedToken).toBe(tokenBefore);

		const row = await repository.haClusterConfigRow();
		expect(row?.role).toBe("primary");
		expect(row?.self_admin_url).toBe("https://primary-a.test");
	});

	test("updateNodeIdentity also works on an existing replica", async () => {
		await repository.insertHaClusterConfig({
			enabled: true,
			role: "replica",
			nodeName: "replica-node",
			primaryUrl: "https://primary.test:7443",
			primaryAdminUrl: "https://primary.test",
			sharedTokenEncrypted: await encryptSecret("replica-token"),
			selfAdminUrl: null,
			clusterEpoch: 0,
		});
		await loadHaClusterConfigAtBoot();
		await updateNodeIdentity({ selfAdminUrl: "https://replica-node.test" });
		expect(config.ha.role).toBe("replica");
		expect(config.ha.selfAdminUrl).toBe("https://replica-node.test");
		const row = await repository.haClusterConfigRow();
		expect(row?.role).toBe("replica");
		expect(row?.self_admin_url).toBe("https://replica-node.test");
	});

	test("updateNodeIdentity rejects a malformed selfAdminUrl", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		await loadHaClusterConfigAtBoot();
		await expect(updateNodeIdentity({ selfAdminUrl: "not-a-url" })).rejects.toThrow(/absolute HTTPS URL/);
	});

	test("updateNodeIdentity rejects plaintext and credential-bearing admin URLs", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		await loadHaClusterConfigAtBoot();
		await expect(updateNodeIdentity({ selfAdminUrl: "http://primary.test" })).rejects.toThrow(/HTTPS/);
		await expect(updateNodeIdentity({ selfAdminUrl: "https://user:secret@primary.test" })).rejects.toThrow(/embedded credentials/);
	});

	test("viewJoinCode round-trips into joinCluster on a second node", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		await loadHaClusterConfigAtBoot();
		await updateNodeIdentity({ nodeName: "primary-b", selfAdminUrl: "https://primary-b.test:9000" });

		const originalHaNodeId = repository.haNodeId;
		repository.haNodeId = async () => "simulated-primary-b-node-id";
		const code = await viewJoinCode();
		repository.haNodeId = originalHaNodeId;
		expect(typeof code).toBe("string");
		expect(code.length).toBeGreaterThan(0);
		const decodedCode = JSON.parse(new TextDecoder().decode(fromBase64Url(code))) as { v: number; primaryCertificate: string };
		expect(decodedCode.v).toBe(5);
		expect(decodedCode.primaryCertificate).toContain("BEGIN CERTIFICATE");

		const primaryToken = config.ha.sharedToken;

		Object.assign(config.ha, originalHa);
		await db`DELETE FROM ha_cluster_config`;
		config.ha.enabled = true;
		config.ha.role = "primary";
		await loadHaClusterConfigAtBoot();

		const originalRedeem = haEnrollmentClient.redeem;
		let redemptionCertificate = "";
		haEnrollmentClient.redeem = async (_meshUrl, _enrollmentCode, primaryCertificate) => {
			redemptionCertificate = primaryCertificate;
			return primaryToken!;
		};
		await joinCluster({ joinCode: code, selfAdminUrl: "https://replica-b.test" });
		haEnrollmentClient.redeem = originalRedeem;

		const roleAfterJoin: string = config.ha.role;
		expect(config.ha.enabled).toBe(true);
		expect(roleAfterJoin).toBe("replica");
		expect(config.ha.primaryUrl).toBe("https://primary-b.test:7443");
		expect(config.ha.primaryAdminUrl).toBe("https://primary-b.test:9000");
		expect(config.ha.sharedToken).toBeTruthy();
		expect(redemptionCertificate).toBe(decodedCode.primaryCertificate);
		expect(await Bun.file(join(tlsDataDirectory, "tls", "ha-primary-ca.pem")).text()).toBe(decodedCode.primaryCertificate);
	});

	test("enrollment pins the join-code certificate on the initial TLS request", async () => {
		const originalFetch = globalThis.fetch;
		let capturedTls: unknown;
		globalThis.fetch = (async (_input: Parameters<typeof fetch>[0], init?: RequestInit) => {
			capturedTls = (init as (RequestInit & { tls?: unknown }) | undefined)?.tls;
			return Response.json({ sharedToken: "cluster-token" });
		}) as typeof fetch;
		try {
			expect(
				await haEnrollmentClient.redeem("https://primary.test:7443", "one-time-code", "pinned-certificate", {
					nodeId: "joining-node-id",
					name: "joining-node",
					version: "1.0.0",
					adminUrl: "https://joining-node.test:9000",
				}),
			).toBe("cluster-token");
			expect(capturedTls).toMatchObject({ ca: "pinned-certificate", checkServerIdentity: expect.any(Function) });
		} finally {
			globalThis.fetch = originalFetch;
		}
	});

	test("joinCluster adopts the join code's cluster epoch, not always 0", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		await loadHaClusterConfigAtBoot();
		await updateNodeIdentity({ nodeName: "epoch-primary", selfAdminUrl: "https://epoch-primary.test:9000" });

		config.ha.epoch = 3;

		const originalHaNodeId = repository.haNodeId;
		repository.haNodeId = async () => "simulated-epoch-primary-node-id";
		const code = await viewJoinCode();
		repository.haNodeId = originalHaNodeId;
		const primaryToken = config.ha.sharedToken;

		Object.assign(config.ha, originalHa);
		await db`DELETE FROM ha_cluster_config`;
		config.ha.enabled = true;
		config.ha.role = "primary";
		await loadHaClusterConfigAtBoot();

		const originalRedeem = haEnrollmentClient.redeem;
		haEnrollmentClient.redeem = async () => primaryToken!;
		await joinCluster({ joinCode: code, selfAdminUrl: "https://epoch-joiner.test" });
		haEnrollmentClient.redeem = originalRedeem;

		expect(config.ha.epoch).toBe(3);
		const row = await repository.haClusterConfigRow();
		expect(row?.cluster_epoch).toBe(3);
	});

	test("joinCluster succeeds even when this node is already a (self-)primary", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		await loadHaClusterConfigAtBoot();
		await updateNodeIdentity({ nodeName: "other-cluster-primary", selfAdminUrl: "https://other-cluster-primary.test" });
		const originalHaNodeId = repository.haNodeId;
		repository.haNodeId = async () => "simulated-other-cluster-primary-node-id";
		const code = await viewJoinCode();
		repository.haNodeId = originalHaNodeId;
		const primaryToken = config.ha.sharedToken;

		Object.assign(config.ha, originalHa);
		await db`DELETE FROM ha_cluster_config`;
		config.ha.enabled = true;
		config.ha.role = "primary";
		await loadHaClusterConfigAtBoot();

		const originalRedeem = haEnrollmentClient.redeem;
		haEnrollmentClient.redeem = async () => primaryToken!;
		await joinCluster({ joinCode: code, selfAdminUrl: "https://x.test" });
		haEnrollmentClient.redeem = originalRedeem;
		const roleAfterJoin: string = config.ha.role;
		expect(roleAfterJoin).toBe("replica");
		expect(config.ha.primaryAdminUrl).toBe("https://other-cluster-primary.test");
	});

	test("joinCluster resets this node's bootstrap/cursor state and clears any queued relay events", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		await loadHaClusterConfigAtBoot();
		await repository.markBootstrapped(123);
		await db`INSERT INTO session_relay_outbox (entity_type,entity_id,op,payload_json,created_at) VALUES ('admin_session','sess_1','insert','{}',${Date.now()})`;
		expect(await repository.needsBootstrap()).toBe(false);

		await updateNodeIdentity({ nodeName: "rejoin-source-node", selfAdminUrl: "https://rejoin-source-node.test" });
		const originalHaNodeId = repository.haNodeId;
		repository.haNodeId = async () => "simulated-rejoin-target-node-id";
		const code = await viewJoinCode();
		repository.haNodeId = originalHaNodeId;
		const primaryToken = config.ha.sharedToken;

		const originalRedeem = haEnrollmentClient.redeem;
		haEnrollmentClient.redeem = async () => primaryToken!;
		await joinCluster({ joinCode: code, selfAdminUrl: "https://rejoin-replica.test" });
		haEnrollmentClient.redeem = originalRedeem;

		expect(await repository.needsBootstrap()).toBe(true);
		const outboxRows = (await db`SELECT * FROM session_relay_outbox`) as unknown[];
		expect(outboxRows).toHaveLength(0);
	});

	test("joinCluster wipes this node's own pre-join changelog history, not just the cursor", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		await loadHaClusterConfigAtBoot();
		await db`INSERT INTO replication_changelog (entity_type,entity_id,op,payload_json,created_at) VALUES ('site','pre-join-site','insert','{}',${Date.now()})`;
		await db`UPDATE replication_changelog_state SET high_watermark=(SELECT MAX(seq) FROM replication_changelog) WHERE id=1`;
		expect(await repository.latestChangelogSeq()).toBeGreaterThan(0);

		await updateNodeIdentity({ nodeName: "rejoin-source-node-2", selfAdminUrl: "https://rejoin-source-node-2.test" });
		const originalHaNodeId = repository.haNodeId;
		repository.haNodeId = async () => "simulated-rejoin-target-node-id-2";
		const code = await viewJoinCode();
		repository.haNodeId = originalHaNodeId;
		const primaryToken = config.ha.sharedToken;

		const originalRedeem = haEnrollmentClient.redeem;
		haEnrollmentClient.redeem = async () => primaryToken!;
		await joinCluster({ joinCode: code, selfAdminUrl: "https://rejoin-replica-2.test" });
		haEnrollmentClient.redeem = originalRedeem;

		const changelogRows = (await db`SELECT * FROM replication_changelog`) as unknown[];
		expect(changelogRows).toHaveLength(0);
		expect(await repository.latestChangelogSeq()).toBe(0);
	});

	test("joinCluster rejects a join code generated by this same node", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		await loadHaClusterConfigAtBoot();
		await updateNodeIdentity({ nodeName: "self-join-node", selfAdminUrl: "https://self-join-node.test" });
		const code = await viewJoinCode();
		await expect(joinCluster({ joinCode: code, selfAdminUrl: "https://self-join-node.test" })).rejects.toThrow(/can't join a cluster to itself/);
	});

	test("joinCluster rejects a garbled join code", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		await loadHaClusterConfigAtBoot();
		await expect(joinCluster({ joinCode: "not-valid-base64-json", selfAdminUrl: "https://x.test" })).rejects.toThrow(/not valid/);
	});

	test("joinCluster rejects another application version before redeeming or changing local state", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		await loadHaClusterConfigAtBoot();
		await updateNodeIdentity({ selfAdminUrl: "https://version-primary.test" });
		const code = await viewJoinCode();
		const decoded = JSON.parse(new TextDecoder().decode(fromBase64Url(code))) as { primaryVersion: string };
		decoded.primaryVersion = APP_VERSION === "0.0.1" ? "0.0.2" : "0.0.1";
		const mismatchedCode = toBase64Url(new TextEncoder().encode(JSON.stringify(decoded)));
		const originalRedeem = haEnrollmentClient.redeem;
		let redeemCalls = 0;
		haEnrollmentClient.redeem = async () => {
			redeemCalls += 1;
			return "must-not-be-used";
		};
		try {
			await expect(joinCluster({ joinCode: mismatchedCode, selfAdminUrl: "https://version-replica.test" })).rejects.toThrow(/runs BurrowGate/);
			expect(redeemCalls).toBe(0);
			expect(config.ha.role).toBe("primary");
		} finally {
			haEnrollmentClient.redeem = originalRedeem;
		}
	});

	test("a primary with registered replicas cannot join another cluster and orphan them", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		await loadHaClusterConfigAtBoot();
		await updateNodeIdentity({ selfAdminUrl: "https://existing-primary.test" });
		const originalHaNodeId = repository.haNodeId;
		repository.haNodeId = async () => "different-cluster-primary";
		const code = await viewJoinCode();
		repository.haNodeId = originalHaNodeId;
		const now = Date.now();
		await repository.upsertHaClusterMember({
			node_id: "existing-replica",
			name: "existing-replica",
			version: APP_VERSION,
			admin_url: "https://existing-replica.test",
			first_seen_at: now,
			last_seen_at: now,
			credential_hash: await sha256Hex("existing-replica-credential"),
		});

		const originalRedeem = haEnrollmentClient.redeem;
		let redeemCalls = 0;
		haEnrollmentClient.redeem = async () => {
			redeemCalls += 1;
			return "must-not-be-used";
		};
		try {
			await expect(joinCluster({ joinCode: code, selfAdminUrl: "https://joining-node.test" })).rejects.toThrow(/without a primary/);
			expect(redeemCalls).toBe(0);
			expect(config.ha.role).toBe("primary");
		} finally {
			haEnrollmentClient.redeem = originalRedeem;
		}
	});

	test("viewJoinCode refuses on a non-primary node", async () => {
		config.ha.enabled = true;
		config.ha.role = "replica";
		await expect(viewJoinCode()).rejects.toThrow(/Only the primary/);
	});
});

describe("leaveCluster", () => {
	test("refuses on a primary - there is nothing to leave", async () => {
		config.ha.enabled = true;
		config.ha.role = "primary";
		await loadHaClusterConfigAtBoot();
		await expect(leaveCluster()).rejects.toThrow(/nothing to leave/);
	});

	test("turns a replica back into a standalone primary, preserving its identity and clearing the old primary pointer", async () => {
		await repository.insertHaClusterConfig({
			enabled: true,
			role: "replica",
			nodeName: "leaving-node",
			primaryUrl: "https://old-primary.test:7443",
			primaryAdminUrl: "https://old-primary.test",
			sharedTokenEncrypted: await encryptSecret("old-cluster-token"),
			selfAdminUrl: "https://leaving-node.test",
			clusterEpoch: 0,
		});
		await loadHaClusterConfigAtBoot();
		const tokenBefore = config.ha.sharedToken;

		await leaveCluster();

		const roleAfter: string = config.ha.role;
		expect(roleAfter).toBe("primary");
		expect(config.ha.nodeName).toBe("leaving-node");
		expect(config.ha.selfAdminUrl).toBe("https://leaving-node.test");
		expect(config.ha.primaryUrl).toBeNull();
		expect(config.ha.primaryAdminUrl).toBeNull();
		expect(config.ha.sharedToken).toBeTruthy();
		expect(config.ha.sharedToken).not.toBe(tokenBefore);

		const row = await repository.haClusterConfigRow();
		expect(row?.role).toBe("primary");
		expect(row?.primary_url).toBeNull();
		expect(row?.primary_admin_url).toBeNull();
	});

	test("a node that just left can immediately produce a working join code again", async () => {
		await repository.insertHaClusterConfig({
			enabled: true,
			role: "replica",
			nodeName: "leaving-node-2",
			primaryUrl: "https://old-primary-2.test:7443",
			primaryAdminUrl: "https://old-primary-2.test",
			sharedTokenEncrypted: await encryptSecret("old-cluster-token-2"),
			selfAdminUrl: "https://leaving-node-2.test",
			clusterEpoch: 0,
		});
		await loadHaClusterConfigAtBoot();
		await leaveCluster();
		const code = await viewJoinCode();
		expect(typeof code).toBe("string");
		expect(code.length).toBeGreaterThan(0);
	});
});
