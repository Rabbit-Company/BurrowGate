import { afterEach, describe, expect, test } from "bun:test";
import { repository } from "../src/db/repository.ts";
import { FirewallSyncService, type FirewallSyncAdapter } from "../src/services/firewall-sync-service.ts";
import { addIpRule } from "../src/services/ip-rule-service.ts";
import { createSite } from "../src/services/site-service.ts";
import type { FirewallSyncProviderRecord, FirewallSyncProviderType } from "../src/types.ts";

interface FakeAdapterState {
	calls: string[][];
	shouldFail: boolean;
}

async function noopTestConnection() {
	return { ok: true, message: "ok" };
}

async function noopTeardown() {}

function fakeAdapter(state: FakeAdapterState): FirewallSyncAdapter {
	return {
		async reconcile(_configJson, cidrs) {
			state.calls.push(cidrs);
			if (state.shouldFail) throw new Error("simulated failure");
		},
		testConnection: noopTestConnection,
		teardown: noopTeardown,
	};
}

function serviceWithFakeAdapters(adapters: Partial<Record<FirewallSyncProviderType, FirewallSyncAdapter>>): FirewallSyncService {
	const noop: FirewallSyncAdapter = { async reconcile() {}, testConnection: noopTestConnection, teardown: noopTeardown };
	return new FirewallSyncService({
		unifi: adapters.unifi ?? noop,
		nftables: adapters.nftables ?? noop,
		ovh: adapters.ovh ?? noop,
		"aws-nacl": adapters["aws-nacl"] ?? noop,
	});
}

async function insertProvider(overrides: Partial<FirewallSyncProviderRecord> = {}): Promise<FirewallSyncProviderRecord> {
	const now = Date.now();
	const record: FirewallSyncProviderRecord = {
		id: `firewall_sync_provider_${crypto.randomUUID()}`,
		name: "Test provider",
		type: "nftables",
		enabled: 1,
		max_entries: 100_000,
		config_json: "{}",
		acknowledged_no_whitelist: 1,
		last_checked_at: null,
		last_synced_at: null,
		last_sync_status: null,
		last_sync_error: null,
		last_applied_count: 0,
		last_applied_hash: null,
		created_at: now,
		updated_at: now,
		...overrides,
	};
	await repository.insertFirewallSyncProvider(record);
	return record;
}

async function site() {
	return (await createSite({ name: "Firewall sync service", publicHost: `fw-svc-${crypto.randomUUID()}.test`, originUrl: "http://origin.test" })).site;
}

afterEach(async () => {
	for (const provider of await repository.allFirewallSyncProviders()) await repository.deleteFirewallSyncProvider(provider.id);
});

describe("FirewallSyncService.syncNow", () => {
	test("caps the pushed set to the provider's max_entries, keeping the most recent bans", async () => {
		const s = await site();
		const subnet = `241.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
		await addIpRule(s.id, `${subnet}.1`, "block", "a", null);
		await new Promise((resolve) => setTimeout(resolve, 2));
		await addIpRule(s.id, `${subnet}.2`, "block", "b", null);
		const provider = await insertProvider({ max_entries: 1 });
		const state: FakeAdapterState = { calls: [], shouldFail: false };
		const service = serviceWithFakeAdapters({ nftables: fakeAdapter(state) });

		await service.syncNow(provider.id);

		expect(state.calls.length).toBe(1);
		expect(state.calls[0]!.length).toBe(1);
		expect(state.calls[0]).toContain(`${subnet}.2`);
	});

	test("always pushes for real, even if the desired set hash matches the last successful push (unlike the automatic tick)", async () => {
		const s = await site();
		await addIpRule(s.id, "203.0.113.10", "block", "a", null);
		const provider = await insertProvider();
		const state: FakeAdapterState = { calls: [], shouldFail: false };
		const service = serviceWithFakeAdapters({ nftables: fakeAdapter(state) });

		await service.syncNow(provider.id);
		expect(state.calls.length).toBe(1);

		await service.syncNow(provider.id);
		expect(state.calls.length).toBe(2);
	});

	test("retries on the next call after a failure", async () => {
		const s = await site();
		await addIpRule(s.id, "203.0.113.20", "block", "a", null);
		const provider = await insertProvider();
		const state: FakeAdapterState = { calls: [], shouldFail: true };
		const service = serviceWithFakeAdapters({ nftables: fakeAdapter(state) });

		await service.syncNow(provider.id);
		let stored = await repository.firewallSyncProviderById(provider.id);
		expect(stored!.last_sync_status).toBe("error");
		expect(stored!.last_applied_hash).toBeNull();

		state.shouldFail = false;
		await service.syncNow(provider.id);
		stored = await repository.firewallSyncProviderById(provider.id);
		expect(stored!.last_sync_status).toBe("ok");
		expect(state.calls.length).toBe(2);
	});
});

describe("FirewallSyncService tick", () => {
	function tick(service: FirewallSyncService): Promise<void> {
		return (service as unknown as { tick(): Promise<void> }).tick();
	}

	test("skips calling the adapter on the next tick when the desired set hash has not changed since the last successful push", async () => {
		const s = await site();
		await addIpRule(s.id, "203.0.113.11", "block", "a", null);
		await insertProvider();
		const state: FakeAdapterState = { calls: [], shouldFail: false };
		const service = serviceWithFakeAdapters({ nftables: fakeAdapter(state) });

		await tick(service);
		expect(state.calls.length).toBe(1);

		await tick(service);
		expect(state.calls.length).toBe(1);
	});

	test("a failure in one provider does not prevent another enabled provider from reconciling", async () => {
		const s = await site();
		await addIpRule(s.id, "203.0.113.30", "block", "a", null);
		const failing = await insertProvider({ name: "Failing", config_json: JSON.stringify({ marker: "failing" }) });
		const working = await insertProvider({ name: "Working", config_json: JSON.stringify({ marker: "working" }) });
		const failState: FakeAdapterState = { calls: [], shouldFail: true };
		const workState: FakeAdapterState = { calls: [], shouldFail: false };
		const service = new FirewallSyncService({
			unifi: { async reconcile() {}, testConnection: noopTestConnection, teardown: noopTeardown },
			ovh: { async reconcile() {}, testConnection: noopTestConnection, teardown: noopTeardown },
			"aws-nacl": { async reconcile() {}, testConnection: noopTestConnection, teardown: noopTeardown },
			nftables: {
				async reconcile(configJson, cidrs) {
					const isFailing = configJson === failing.config_json;
					(isFailing ? failState : workState).calls.push(cidrs);
					if (isFailing && failState.shouldFail) throw new Error("simulated failure");
				},
				testConnection: noopTestConnection,
				teardown: noopTeardown,
			},
		});

		await tick(service);

		expect(failState.calls.length).toBe(1);
		expect(workState.calls.length).toBe(1);
		const workingAfter = await repository.firewallSyncProviderById(working.id);
		expect(workingAfter!.last_sync_status).toBe("ok");
	});

	test("concurrent ticks are single-flighted - a second tick started while the first is running is a no-op", async () => {
		const s = await site();
		await addIpRule(s.id, "203.0.113.40", "block", "a", null);
		await insertProvider();
		let releaseFirstCall: (() => void) | null = null;
		const gate = new Promise<void>((resolve) => {
			releaseFirstCall = resolve;
		});
		let callCount = 0;
		const service = new FirewallSyncService({
			unifi: { async reconcile() {}, testConnection: noopTestConnection, teardown: noopTeardown },
			ovh: { async reconcile() {}, testConnection: noopTestConnection, teardown: noopTeardown },
			"aws-nacl": { async reconcile() {}, testConnection: noopTestConnection, teardown: noopTeardown },
			nftables: {
				async reconcile() {
					callCount += 1;
					await gate;
				},
				testConnection: noopTestConnection,
				teardown: noopTeardown,
			},
		});

		const firstTick = tick(service);
		const secondTick = tick(service);
		releaseFirstCall!();
		await Promise.all([firstTick, secondTick]);

		expect(callCount).toBe(1);
	});
});

describe("FirewallSyncService.deleteProvider", () => {
	test("tears down the remote entries before removing the local row", async () => {
		const provider = await insertProvider();
		const teardownCalls: string[] = [];
		const service = serviceWithFakeAdapters({
			nftables: {
				async reconcile() {},
				testConnection: noopTestConnection,
				async teardown(configJson) {
					teardownCalls.push(configJson);
				},
			},
		});

		const result = await service.deleteProvider(provider.id);

		expect(result.teardownError).toBeNull();
		expect(teardownCalls).toEqual([provider.config_json]);
		expect(await repository.firewallSyncProviderById(provider.id)).toBeNull();
	});

	test("still removes the local row even when the remote teardown fails, and reports why", async () => {
		const provider = await insertProvider();
		const service = serviceWithFakeAdapters({
			nftables: {
				async reconcile() {},
				testConnection: noopTestConnection,
				async teardown() {
					throw new Error("still referenced by a firewall policy");
				},
			},
		});

		const result = await service.deleteProvider(provider.id);

		expect(result.teardownError).toBe("still referenced by a firewall policy");
		expect(await repository.firewallSyncProviderById(provider.id)).toBeNull();
	});

	test("deleting an already-gone provider is a no-op, not an error", async () => {
		const service = serviceWithFakeAdapters({});
		const result = await service.deleteProvider("firewall_sync_provider_does_not_exist");
		expect(result.teardownError).toBeNull();
	});
});
