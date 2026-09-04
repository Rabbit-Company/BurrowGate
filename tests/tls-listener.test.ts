import { describe, expect, test } from "bun:test";
import { config } from "../src/config.ts";
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

	test("only passes http3 to the HTTPS listener when BG_HTTP3_ENABLED is on", async () => {
		const seen: Array<boolean | undefined> = [];
		const manager = new TlsListenerManager({} as any, {
			serve(options) {
				seen.push((options as { http3?: boolean }).http3);
				return fakeServer([], "server");
			},
			managedCertificates: async () => [certificate()],
			bootstrapCertificate: async () => null,
		});

		await manager.reloadHttps();
		expect(seen).toEqual([undefined]);

		config.https.http3Enabled = true;
		try {
			await manager.reloadHttps();
		} finally {
			config.https.http3Enabled = false;
		}
		expect(seen).toEqual([undefined, true]);
	});

	test("only passes http2 to the HTTPS listener when BG_HTTP2_ENABLED is on", async () => {
		const seen: Array<boolean | undefined> = [];
		const manager = new TlsListenerManager({} as any, {
			serve(options) {
				seen.push((options as { http2?: boolean }).http2);
				return fakeServer([], "server");
			},
			managedCertificates: async () => [certificate()],
			bootstrapCertificate: async () => null,
		});

		await manager.reloadHttps();
		expect(seen).toEqual([undefined]);

		config.https.http2Enabled = true;
		try {
			await manager.reloadHttps();
		} finally {
			config.https.http2Enabled = false;
		}
		expect(seen).toEqual([undefined, true]);
	});

	test("http2 and http3 can both be enabled on the same HTTPS listener", async () => {
		const seen: Array<{ http2?: boolean; http3?: boolean }> = [];
		const manager = new TlsListenerManager({} as any, {
			serve(options) {
				seen.push({ http2: (options as { http2?: boolean }).http2, http3: (options as { http3?: boolean }).http3 });
				return fakeServer([], "server");
			},
			managedCertificates: async () => [certificate()],
			bootstrapCertificate: async () => null,
		});

		config.https.http2Enabled = true;
		config.https.http3Enabled = true;
		try {
			await manager.reloadHttps();
		} finally {
			config.https.http2Enabled = false;
			config.https.http3Enabled = false;
		}
		expect(seen).toEqual([{ http2: true, http3: true }]);
	});
});
