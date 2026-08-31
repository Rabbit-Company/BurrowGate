import { afterEach, describe, expect, test } from "bun:test";
import { config } from "../src/config.ts";
import { repository } from "../src/db/repository.ts";
import {
	HaPrimaryAuthorityFenceError,
	HaPromotionWriteFenceError,
	haPrimaryWriteBarrier,
	isPrimaryAdminWriteRequest,
} from "../src/services/ha-write-barrier.ts";

afterEach(() => {
	config.ha.fencedForPromotion = false;
	config.ha.authorityFence = null;
	expect(haPrimaryWriteBarrier.activeWriteCount()).toBe(0);
});

describe("haPrimaryWriteBarrier.runPrimaryWrite", () => {
	test("admits and runs an operation when nothing is fenced", async () => {
		const result = await haPrimaryWriteBarrier.runPrimaryWrite(async () => "ok");
		expect(result).toBe("ok");
	});

	test("rejects immediately with HaPromotionWriteFenceError when already fenced, without ever admitting it", async () => {
		config.ha.fencedForPromotion = true;
		let ran = false;
		await expect(
			haPrimaryWriteBarrier.runPrimaryWrite(async () => {
				ran = true;
			}),
		).rejects.toBeInstanceOf(HaPromotionWriteFenceError);
		expect(ran).toBe(false);
		expect(haPrimaryWriteBarrier.activeWriteCount()).toBe(0);
	});

	test("rejects writes when this primary has durably lost authority", async () => {
		config.ha.authorityFence = { observedEpoch: 4, sourceNodeId: "newer-node", observedAt: Date.now() };
		let ran = false;
		await expect(
			haPrimaryWriteBarrier.runPrimaryWrite(async () => {
				ran = true;
			}),
		).rejects.toBeInstanceOf(HaPrimaryAuthorityFenceError);
		expect(ran).toBe(false);
	});

	test("a nested call inherits the outer lease and is not rejected even if fencing starts mid-flight", async () => {
		const result = await haPrimaryWriteBarrier.runPrimaryWrite(async () => {
			config.ha.fencedForPromotion = true;
			return await haPrimaryWriteBarrier.runPrimaryWrite(async () => "inner result");
		});
		expect(result).toBe("inner result");
	});

	test("an admitted request can complete a guarded repository write after promotion closes admission", async () => {
		const previousEnabled = config.ha.enabled;
		const previousRole = config.ha.role;
		config.ha.enabled = true;
		config.ha.role = "primary";
		let promotionPromise: Promise<void> | null = null;
		try {
			await haPrimaryWriteBarrier.runPrimaryWrite(async () => {
				promotionPromise = haPrimaryWriteBarrier.beginPromotion();
				expect(config.ha.fencedForPromotion).toBe(true);
				await repository.deletePendingChange(`missing-${crypto.randomUUID()}`);
			});
			await promotionPromise!;
		} finally {
			config.ha.enabled = previousEnabled;
			config.ha.role = previousRole;
			haPrimaryWriteBarrier.endPromotion();
		}
	});

	test("propagates the operation's own rejection and still releases the lease", async () => {
		await expect(
			haPrimaryWriteBarrier.runPrimaryWrite(async () => {
				throw new Error("simulated write failure");
			}),
		).rejects.toThrow("simulated write failure");
		expect(haPrimaryWriteBarrier.activeWriteCount()).toBe(0);
	});
});

describe("haPrimaryWriteBarrier.beginPromotion", () => {
	test("resolves immediately and fences when there are no active writes", async () => {
		expect(config.ha.fencedForPromotion).toBe(false);
		await haPrimaryWriteBarrier.beginPromotion();
		expect(config.ha.fencedForPromotion).toBe(true);
		haPrimaryWriteBarrier.endPromotion();
	});

	test("refuses to start a second promotion while one is already in progress", async () => {
		config.ha.fencedForPromotion = true;
		await expect(haPrimaryWriteBarrier.beginPromotion()).rejects.toThrow(/already in progress/);
		haPrimaryWriteBarrier.endPromotion();
	});

	test("waits for an in-flight admitted write to finish, and closes admission to new ones in the meantime", async () => {
		let releaseWrite: (() => void) | null = null;
		const writeGate = new Promise<void>((resolve) => {
			releaseWrite = resolve;
		});
		const writePromise = haPrimaryWriteBarrier.runPrimaryWrite(async () => {
			await writeGate;
			return "write committed";
		});
		await new Promise((resolve) => setTimeout(resolve, 10));
		expect(haPrimaryWriteBarrier.activeWriteCount()).toBe(1);

		let promotionSettled = false;
		const promotionPromise = haPrimaryWriteBarrier.beginPromotion().then(() => {
			promotionSettled = true;
		});
		await new Promise((resolve) => setTimeout(resolve, 50));
		expect(promotionSettled).toBe(false);
		expect(config.ha.fencedForPromotion).toBe(true);

		await expect(haPrimaryWriteBarrier.runPrimaryWrite(async () => "too late")).rejects.toBeInstanceOf(HaPromotionWriteFenceError);

		releaseWrite!();
		expect(await writePromise).toBe("write committed");
		await promotionPromise;
		expect(promotionSettled).toBe(true);

		haPrimaryWriteBarrier.endPromotion();
	});

	test("waits for multiple in-flight writes and only resolves once every one of them has drained", async () => {
		const gates: Array<() => void> = [];
		const writes = [0, 1, 2].map((i) =>
			haPrimaryWriteBarrier.runPrimaryWrite(async () => {
				await new Promise<void>((resolve) => gates.push(resolve));
				return i;
			}),
		);
		await new Promise((resolve) => setTimeout(resolve, 10));
		expect(haPrimaryWriteBarrier.activeWriteCount()).toBe(3);

		let promotionSettled = false;
		const promotionPromise = haPrimaryWriteBarrier.beginPromotion().then(() => {
			promotionSettled = true;
		});

		gates[0]!();
		gates[1]!();
		await new Promise((resolve) => setTimeout(resolve, 30));
		expect(promotionSettled).toBe(false);

		gates[2]!();
		await Promise.all(writes);
		await promotionPromise;
		expect(promotionSettled).toBe(true);

		haPrimaryWriteBarrier.endPromotion();
	});

	test("times out and un-fences if an admitted write never finishes within the deadline", async () => {
		let releaseWrite: (() => void) | null = null;
		const writeGate = new Promise<void>((resolve) => {
			releaseWrite = resolve;
		});
		const writePromise = haPrimaryWriteBarrier.runPrimaryWrite(async () => {
			await writeGate;
		});
		await new Promise((resolve) => setTimeout(resolve, 10));

		await expect(haPrimaryWriteBarrier.beginPromotion(50)).rejects.toThrow(/Timed out waiting for active configuration writes/);
		expect(config.ha.fencedForPromotion).toBe(false);

		releaseWrite!();
		await writePromise;
	});
});

describe("haPrimaryWriteBarrier.endPromotion", () => {
	test("clears the fence set by beginPromotion", async () => {
		await haPrimaryWriteBarrier.beginPromotion();
		expect(config.ha.fencedForPromotion).toBe(true);
		haPrimaryWriteBarrier.endPromotion();
		expect(config.ha.fencedForPromotion).toBe(false);
	});
});

describe("isPrimaryAdminWriteRequest", () => {
	test("is false for a read (GET) admin API request", () => {
		expect(isPrimaryAdminWriteRequest(new Request("https://primary.test/_burrowgate/api/admin/sites"))).toBe(false);
	});

	test("is false for a mutating request outside the admin API", () => {
		expect(isPrimaryAdminWriteRequest(new Request("https://primary.test/_burrowgate/api/access/login", { method: "POST" }))).toBe(false);
	});

	test("is true for a mutating admin API request", () => {
		expect(isPrimaryAdminWriteRequest(new Request("https://primary.test/_burrowgate/api/admin/sites", { method: "POST" }))).toBe(true);
		expect(isPrimaryAdminWriteRequest(new Request("https://primary.test/_burrowgate/api/admin/sites/site-1", { method: "PUT" }))).toBe(true);
		expect(isPrimaryAdminWriteRequest(new Request("https://primary.test/_burrowgate/api/admin/sites/site-1", { method: "PATCH" }))).toBe(true);
		expect(isPrimaryAdminWriteRequest(new Request("https://primary.test/_burrowgate/api/admin/sites/site-1", { method: "DELETE" }))).toBe(true);
	});

	test("exempts node-local logging, logout, recovery-code consumption, and promote even though they mutate", () => {
		expect(isPrimaryAdminWriteRequest(new Request("https://primary.test/_burrowgate/api/admin/logs/settings", { method: "PUT" }))).toBe(false);
		expect(isPrimaryAdminWriteRequest(new Request("https://primary.test/_burrowgate/api/admin/logs/archives/2026-08-30.txt.gz", { method: "DELETE" }))).toBe(
			false,
		);
		expect(isPrimaryAdminWriteRequest(new Request("https://primary.test/_burrowgate/api/admin/logout", { method: "POST" }))).toBe(false);
		expect(isPrimaryAdminWriteRequest(new Request("https://primary.test/_burrowgate/api/admin/ha/consume-recovery-code", { method: "POST" }))).toBe(false);
		expect(isPrimaryAdminWriteRequest(new Request("https://primary.test/_burrowgate/api/admin/ha/promote/some-node", { method: "POST" }))).toBe(false);
	});
});
