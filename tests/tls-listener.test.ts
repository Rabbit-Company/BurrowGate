import { describe, expect, test } from "bun:test";
import { TlsListenerManager } from "../src/services/tls-listener-service.ts";

function certificate() {
	return {
		serverName: "example.test",
		cert: "certificate",
		key: "private-key",
	};
}

function fakeServer(events: string[], name: string) {
	return {
		async stop(force = false): Promise<void> {
			events.push(`${name}:stop:${force ? "force" : "graceful"}`);
		},
	};
}

describe("HTTPS listener replacement", () => {
	test("starts the replacement before draining the previous listener", async () => {
		const events: string[] = [];
		let generation = 0;
		const manager = new TlsListenerManager({} as any, {
			serve(options) {
				generation += 1;
				events.push(`serve:${generation}:${options.reusePort === true ? "reuse" : "exclusive"}`);
				return fakeServer(events, `server:${generation}`);
			},
			managedCertificates: async () => [certificate()],
			bootstrapCertificate: async () => null,
		});

		await manager.reloadHttps();
		await manager.reloadHttps();
		await Promise.resolve();

		expect(events[0]).toBe("serve:1:reuse");
		expect(events[1]).toBe("serve:2:reuse");
		expect(events[2]).toBe("server:1:stop:graceful");
	});

	test("keeps the previous listener active when replacement binding fails", async () => {
		const events: string[] = [];
		let generation = 0;
		const manager = new TlsListenerManager({} as any, {
			serve() {
				generation += 1;
				if (generation === 2) throw new Error("bind failed");
				return fakeServer(events, `server:${generation}`);
			},
			managedCertificates: async () => [certificate()],
			bootstrapCertificate: async () => null,
		});

		await manager.reloadHttps();
		await expect(manager.reloadHttps()).rejects.toThrow("existing listener remains active");
		expect(events).toEqual([]);
	});
});
