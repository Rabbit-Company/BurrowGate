import { afterAll, afterEach, beforeEach, describe, expect, test } from "bun:test";
import { repository } from "../src/db/repository.ts";
import { crowdSecDecisions, type RawCrowdSecDecision } from "../src/services/crowdsec-decision-store.ts";
import { crowdSecService, normalizeLapiUrl, parseCrowdSecScopes, parseUnknownRemediation, saveCrowdSecSettings } from "../src/services/crowdsec-service.ts";

interface RecordedRequest {
	startup: string | null;
	scopes: string | null;
	apiKey: string | null;
	userAgent: string | null;
}

interface MockLapi {
	server: { port?: number; stop: (closeActiveConnections?: boolean) => Promise<void> };
	url: string;
	requests: RecordedRequest[];
	respond: (handler: (request: RecordedRequest) => Response) => void;
}

function decision(overrides: Partial<RawCrowdSecDecision> & { value: string }): RawCrowdSecDecision {
	return { id: 1, type: "ban", scope: "Ip", duration: "4h", origin: "CAPI", scenario: "crowdsecurity/http-probing", ...overrides };
}

function startMockLapi(): MockLapi {
	const requests: RecordedRequest[] = [];
	let handler: (request: RecordedRequest) => Response = () => Response.json({ new: [], deleted: [] });

	const server = Bun.serve({
		port: 0,
		fetch(request) {
			const url = new URL(request.url);
			const recorded: RecordedRequest = {
				startup: url.searchParams.get("startup"),
				scopes: url.searchParams.get("scopes"),
				apiKey: request.headers.get("x-api-key"),
				userAgent: request.headers.get("user-agent"),
			};
			requests.push(recorded);
			if (url.pathname !== "/v1/decisions/stream") return new Response("not found", { status: 404 });
			return handler(recorded);
		},
	});

	return {
		server,
		url: `http://127.0.0.1:${server.port!}`,
		requests,
		respond(next) {
			handler = next;
		},
	};
}

let lapi: MockLapi;

beforeEach(async () => {
	lapi = startMockLapi();
	crowdSecDecisions.clear();
});

afterEach(async () => {
	await lapi.server.stop(true);
	crowdSecDecisions.clear();
	const settings = await repository.ensureCrowdSecSettings();
	await repository.saveCrowdSecSettings({ ...settings, enabled: 0, lapi_url: null, api_key_encrypted: null, updated_at: Date.now() });
	await crowdSecService.reload();
});

afterAll(() => {
	crowdSecService.stop();
});

/**
 * Saving settings reloads the poller, which polls immediately. Awaiting that here means each test
 * starts settled, with `requests[0]` being the first poll.
 */
async function connect(overrides: Record<string, unknown> = {}): Promise<void> {
	await saveCrowdSecSettings({
		enabled: true,
		lapiUrl: lapi.url,
		apiKey: "test-key",
		pollIntervalSeconds: 3_600,
		fullSyncIntervalSeconds: 86_400,
		requestTimeoutMs: 2_000,
		...overrides,
	});
	await crowdSecService.poll();
}

describe("normalizeLapiUrl", () => {
	test("keeps the origin and any path prefix, dropping trailing slashes", () => {
		expect(normalizeLapiUrl("http://127.0.0.1:8080/")).toBe("http://127.0.0.1:8080");
		expect(normalizeLapiUrl("  https://crowdsec.internal:8080  ")).toBe("https://crowdsec.internal:8080");
		expect(normalizeLapiUrl("http://127.0.0.1:8080/crowdsec/")).toBe("http://127.0.0.1:8080/crowdsec");
	});

	test("rejects unusable values", () => {
		expect(() => normalizeLapiUrl("")).toThrow();
		expect(() => normalizeLapiUrl("127.0.0.1:8080")).toThrow();
		expect(() => normalizeLapiUrl("ftp://127.0.0.1")).toThrow();
	});
});

describe("parseCrowdSecScopes", () => {
	test("accepts an array or a comma-separated string, deduped", () => {
		expect(parseCrowdSecScopes(["ip", "range"])).toBe("ip,range");
		expect(parseCrowdSecScopes("ip, range, ip")).toBe("ip,range");
		expect(parseCrowdSecScopes(["IP", "AS"])).toBe("ip,as");
	});

	test("rejects unsupported and empty selections", () => {
		expect(() => parseCrowdSecScopes(["username"])).toThrow();
		expect(() => parseCrowdSecScopes([])).toThrow();
	});
});

describe("parseUnknownRemediation", () => {
	test("accepts the three handling choices", () => {
		expect(parseUnknownRemediation("ban")).toBe("ban");
		expect(parseUnknownRemediation("captcha")).toBe("captcha");
		expect(parseUnknownRemediation("ignore")).toBe("ignore");
	});

	test("rejects anything else", () => {
		expect(() => parseUnknownRemediation("drop")).toThrow();
	});
});

describe("polling the Local API", () => {
	test("the first poll asks for a full snapshot and loads it", async () => {
		lapi.respond(() => Response.json({ new: [decision({ id: 1, value: "203.0.113.5" }), decision({ id: 2, value: "203.0.113.6" })], deleted: [] }));
		await connect();

		expect(lapi.requests[0]?.startup).toBe("true");
		expect(crowdSecDecisions.stats().total).toBe(2);
		expect(crowdSecDecisions.lookup("203.0.113.5", null, null)).not.toBeNull();
	});

	test("authenticates with the bouncer key and identifies itself", async () => {
		lapi.respond(() => Response.json({ new: [], deleted: [] }));
		await connect();

		expect(lapi.requests[0]?.apiKey).toBe("test-key");
		expect(lapi.requests[0]?.userAgent).toStartWith("burrowgate/");
	});

	test("requests the configured scopes", async () => {
		lapi.respond(() => Response.json({ new: [], deleted: [] }));
		await connect({ scopes: ["ip", "range", "country", "as"] });

		expect(lapi.requests[0]?.scopes).toBe("ip,range,country,as");
	});

	test("the second poll is incremental and merges into what is already loaded", async () => {
		lapi.respond((request) =>
			request.startup === "true"
				? Response.json({ new: [decision({ id: 1, value: "203.0.113.5" })], deleted: [] })
				: Response.json({ new: [decision({ id: 2, value: "203.0.113.6" })], deleted: [decision({ id: 1, value: "203.0.113.5" })] }),
		);
		await connect();
		await crowdSecService.poll();

		expect(lapi.requests[1]?.startup).toBe("false");
		expect(crowdSecDecisions.lookup("203.0.113.5", null, null)).toBeNull();
		expect(crowdSecDecisions.lookup("203.0.113.6", null, null)).not.toBeNull();
	});

	test("tolerates a Local API that sends null instead of an empty array", async () => {
		lapi.respond(() => new Response(JSON.stringify({ new: null, deleted: null }), { headers: { "content-type": "application/json" } }));
		await connect();

		expect(crowdSecService.status().lastPollStatus).toBe("ok");
		expect(crowdSecDecisions.stats().total).toBe(0);
	});

	test("a full resync replaces the set rather than merging into it", async () => {
		lapi.respond((request) =>
			request.startup === "true" && lapi.requests.length > 1
				? Response.json({ new: [decision({ id: 9, value: "198.51.100.1" })], deleted: [] })
				: Response.json({ new: [decision({ id: 1, value: "203.0.113.5" })], deleted: [] }),
		);
		await connect();
		await crowdSecService.refreshNow();

		expect(crowdSecDecisions.lookup("203.0.113.5", null, null)).toBeNull();
		expect(crowdSecDecisions.lookup("198.51.100.1", null, null)).not.toBeNull();
	});
});

describe("failure handling", () => {
	test("keeps the decisions already loaded when a poll fails", async () => {
		lapi.respond(() => Response.json({ new: [decision({ id: 1, value: "203.0.113.5" })], deleted: [] }));
		await connect();

		lapi.respond(() => new Response("upstream exploded", { status: 500 }));
		await crowdSecService.poll();

		expect(crowdSecService.status().lastPollStatus).toBe("error");
		expect(crowdSecDecisions.lookup("203.0.113.5", null, null)).not.toBeNull();
	});

	test("a failed poll forces the next one back to a full snapshot", async () => {
		lapi.respond(() => Response.json({ new: [], deleted: [] }));
		await connect();
		expect(lapi.requests[0]?.startup).toBe("true");

		lapi.respond(() => new Response("nope", { status: 500 }));
		await crowdSecService.poll();
		expect(crowdSecService.status().nextPollIsFullSync).toBe(true);

		lapi.respond(() => Response.json({ new: [], deleted: [] }));
		await crowdSecService.poll();
		expect(lapi.requests[2]?.startup).toBe("true");
	});

	test("explains a rejected API key rather than reporting a bare status code", async () => {
		lapi.respond(() => new Response("forbidden", { status: 403 }));
		await connect();

		expect(crowdSecService.status().lastPollError).toContain("rejected the bouncer API key");
	});

	test("explains a URL that has no stream endpoint", async () => {
		lapi.respond(() => new Response("not found", { status: 404 }));
		await connect();

		expect(crowdSecService.status().lastPollError).toContain("/v1/decisions/stream");
	});

	test("counts consecutive failures and clears them on recovery", async () => {
		lapi.respond(() => new Response("nope", { status: 500 }));
		await connect();
		const afterConnect = crowdSecService.status().consecutiveFailures;
		expect(afterConnect).toBeGreaterThan(0);
		await crowdSecService.poll();
		expect(crowdSecService.status().consecutiveFailures).toBe(afterConnect + 1);

		lapi.respond(() => Response.json({ new: [], deleted: [] }));
		await crowdSecService.poll();
		expect(crowdSecService.status().consecutiveFailures).toBe(0);
		expect(crowdSecService.status().lastPollStatus).toBe("ok");
	});

	test("an unreachable Local API does not throw out of the poll", async () => {
		await connect();
		await lapi.server.stop(true);
		expect(crowdSecService.poll()).resolves.toBeUndefined();
	});
});

describe("enabling and disabling", () => {
	test("disabling drops the loaded decisions so enforcement stops immediately", async () => {
		lapi.respond(() => Response.json({ new: [decision({ id: 1, value: "203.0.113.5" })], deleted: [] }));
		await connect();
		expect(crowdSecDecisions.empty).toBe(false);

		await saveCrowdSecSettings({ enabled: false });
		expect(crowdSecDecisions.empty).toBe(true);
	});

	test("a disabled integration never contacts the Local API", async () => {
		await connect({ enabled: false });
		await crowdSecService.poll();
		expect(lapi.requests.length).toBe(0);
	});
});

describe("remediation mapping", () => {
	test("an unknown remediation follows the configured fallback", async () => {
		lapi.respond(() => Response.json({ new: [decision({ id: 1, type: "throttle", value: "203.0.113.5" })], deleted: [] }));
		await connect({ unknownRemediation: "captcha" });

		expect(crowdSecDecisions.lookup("203.0.113.5", null, null)?.remediation).toBe("captcha");
	});

	test("an unknown remediation can be ignored entirely", async () => {
		lapi.respond(() => Response.json({ new: [decision({ id: 1, type: "throttle", value: "203.0.113.5" })], deleted: [] }));
		await connect({ unknownRemediation: "ignore" });

		expect(crowdSecDecisions.lookup("203.0.113.5", null, null)).toBeNull();
	});
});

describe("status view", () => {
	test("reports the connection without exposing the key", async () => {
		lapi.respond(() => Response.json({ new: [], deleted: [] }));
		await connect();
		const status = crowdSecService.status();

		expect(status.enabled).toBe(true);
		expect(status.configured).toBe(true);
		expect(status.apiKeyConfigured).toBe(true);
		expect(JSON.stringify(status)).not.toContain("test-key");
	});
});
