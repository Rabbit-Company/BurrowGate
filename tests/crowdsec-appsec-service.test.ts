import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
	appSecHttpVersion,
	bufferBodyForAppSec,
	buildAppSecHeaders,
	inspectWithAppSec,
	normalizeAppSecUrl,
	testAppSecConnection,
	type AppSecConnection,
} from "../src/services/crowdsec-appsec-service.ts";

interface Seen {
	method: string;
	headers: Record<string, string>;
	body: string;
}

interface MockAppSec {
	server: { port?: number; stop: (force?: boolean) => Promise<void> };
	url: string;
	seen: Seen[];
	respond: (handler: () => Response | Promise<Response>) => void;
}

function startMockAppSec(): MockAppSec {
	const seen: Seen[] = [];
	let handler: () => Response | Promise<Response> = () => Response.json({ action: "allow" });
	const server = Bun.serve({
		port: 0,
		async fetch(request) {
			seen.push({
				method: request.method,
				headers: Object.fromEntries([...request.headers].map(([name, value]) => [name.toLowerCase(), value])),
				body: await request.text(),
			});
			return await handler();
		},
	});
	return {
		server,
		url: `http://127.0.0.1:${server.port!}`,
		seen,
		respond(next) {
			handler = next;
		},
	};
}

let appsec: MockAppSec;

function connection(overrides: Partial<AppSecConnection> = {}): AppSecConnection {
	return { url: appsec.url, apiKey: "test-key", timeoutMs: 2_000, verifyTls: true, ...overrides };
}

function input(overrides: Partial<Parameters<typeof inspectWithAppSec>[0]> = {}) {
	return {
		ip: "203.0.113.5",
		url: new URL("http://example.test/login?next=%2Fadmin"),
		method: "GET",
		headers: new Headers({ "user-agent": "curl/8", cookie: "session=abc", accept: "*/*" }),
		httpVersion: "1.1",
		body: null,
		...overrides,
	};
}

beforeEach(() => {
	appsec = startMockAppSec();
});

afterEach(async () => {
	await appsec.server.stop(true);
});

describe("appSecHttpVersion", () => {
	test("maps versions to the integer form CrowdSec expects", () => {
		expect(appSecHttpVersion("1.1")).toBe("11");
		expect(appSecHttpVersion("1.0")).toBe("10");
		expect(appSecHttpVersion("2.0")).toBe("20");
		expect(appSecHttpVersion("3")).toBe("30");
		expect(appSecHttpVersion(null)).toBe("11");
	});
});

describe("normalizeAppSecUrl", () => {
	test("keeps origin and prefix, dropping trailing slashes", () => {
		expect(normalizeAppSecUrl("http://127.0.0.1:7422/")).toBe("http://127.0.0.1:7422");
		expect(normalizeAppSecUrl("  http://appsec:7422/inspect/  ")).toBe("http://appsec:7422/inspect");
	});

	test("rejects unusable values", () => {
		expect(() => normalizeAppSecUrl("")).toThrow();
		expect(() => normalizeAppSecUrl("127.0.0.1:7422")).toThrow();
		expect(() => normalizeAppSecUrl("ftp://127.0.0.1")).toThrow();
	});
});

describe("buildAppSecHeaders", () => {
	test("sets the protocol's metadata headers", () => {
		const headers = buildAppSecHeaders(input(), "secret-key");
		expect(headers.get("x-crowdsec-appsec-ip")).toBe("203.0.113.5");
		expect(headers.get("x-crowdsec-appsec-uri")).toBe("/login?next=%2Fadmin");
		expect(headers.get("x-crowdsec-appsec-host")).toBe("example.test");
		expect(headers.get("x-crowdsec-appsec-verb")).toBe("GET");
		expect(headers.get("x-crowdsec-appsec-api-key")).toBe("secret-key");
		expect(headers.get("x-crowdsec-appsec-user-agent")).toBe("curl/8");
		expect(headers.get("x-crowdsec-appsec-http-version")).toBe("11");
	});

	test("forwards the original headers so rules can inspect them", () => {
		const headers = buildAppSecHeaders(input(), "k");
		expect(headers.get("cookie")).toBe("session=abc");
		expect(headers.get("accept")).toBe("*/*");
	});

	test("drops hop-by-hop headers and the original content-length", () => {
		const headers = buildAppSecHeaders(
			input({
				headers: new Headers({ connection: "keep-alive", "transfer-encoding": "chunked", "content-length": "99", host: "elsewhere.test", accept: "*/*" }),
			}),
			"k",
		);
		expect(headers.get("connection")).toBeNull();
		expect(headers.get("transfer-encoding")).toBeNull();
		expect(headers.get("content-length")).toBeNull();
		expect(headers.get("host")).toBeNull();
		expect(headers.get("accept")).toBe("*/*");
	});
});

describe("inspectWithAppSec", () => {
	test("a 200 allows the request", async () => {
		appsec.respond(() => Response.json({ action: "allow" }));
		const result = await inspectWithAppSec(input(), connection());
		expect(result.status).toBe("clean");
		expect(result.action).toBe("allow");
	});

	test("a bodyless request is sent as GET", async () => {
		await inspectWithAppSec(input(), connection());
		expect(appsec.seen[0]?.method).toBe("GET");
	});

	test("a request with a body is sent as POST, carrying the body", async () => {
		const body = new TextEncoder().encode('{"user":"admin","pass":"x"}');
		await inspectWithAppSec(input({ method: "POST", body }), connection());
		expect(appsec.seen[0]?.method).toBe("POST");
		expect(appsec.seen[0]?.body).toBe('{"user":"admin","pass":"x"}');
		expect(appsec.seen[0]?.headers["x-crowdsec-appsec-verb"]).toBe("POST");
	});

	test("a 403 blocks and carries the action and status", async () => {
		appsec.respond(() => Response.json({ action: "ban", http_status: 403 }, { status: 403 }));
		const result = await inspectWithAppSec(input(), connection());
		expect(result.status).toBe("blocked");
		expect(result.action).toBe("ban");
		expect(result.httpStatus).toBe(403);
	});

	test("a 403 asking for a captcha reports that action", async () => {
		appsec.respond(() => Response.json({ action: "captcha", http_status: 403 }, { status: 403 }));
		expect((await inspectWithAppSec(input(), connection())).action).toBe("captcha");
	});

	test("a 403 with an unusable body still blocks, defaulting to ban", async () => {
		appsec.respond(() => new Response("not json", { status: 403 }));
		const result = await inspectWithAppSec(input(), connection());
		expect(result.status).toBe("blocked");
		expect(result.action).toBe("ban");
		expect(result.httpStatus).toBe(403);
	});

	test("a 401 is reported as an error, not a block", async () => {
		appsec.respond(() => new Response(null, { status: 401 }));
		const result = await inspectWithAppSec(input(), connection());
		expect(result.status).toBe("error");
		expect(result.error).toContain("API key");
	});

	test("a 500 is reported as an error, not a block", async () => {
		appsec.respond(() => new Response(null, { status: 500 }));
		const result = await inspectWithAppSec(input(), connection());
		expect(result.status).toBe("error");
		expect(result.error).toContain("500");
	});

	test("an unreachable component returns an error rather than throwing", async () => {
		const result = await inspectWithAppSec(input(), connection({ url: "http://127.0.0.1:9" }));
		expect(result.status).toBe("error");
		expect(result.error).not.toBeNull();
	});

	test("a component slower than the timeout returns an error rather than hanging", async () => {
		appsec.respond(async () => {
			await Bun.sleep(300);
			return Response.json({ action: "allow" });
		});
		const result = await inspectWithAppSec(input(), connection({ timeoutMs: 50 }));
		expect(result.status).toBe("error");
	});

	test("reports how long the inspection took", async () => {
		const result = await inspectWithAppSec(input(), connection());
		expect(result.durationMs).toBeGreaterThanOrEqual(0);
	});
});

describe("testAppSecConnection", () => {
	test("reports success against a reachable component", async () => {
		const outcome = await testAppSecConnection(appsec.url, "k", true);
		expect(outcome.ok).toBe(true);
		expect(outcome.message).toContain("Connected");
	});

	test("reports failure against an unreachable one", async () => {
		const outcome = await testAppSecConnection("http://127.0.0.1:9", "k", true);
		expect(outcome.ok).toBe(false);
	});

	test("rejects an invalid URL without throwing", async () => {
		expect((await testAppSecConnection("not-a-url", "k", true)).ok).toBe(false);
	});
});

function bodyRequest(body: string, extraHeaders: Record<string, string> = {}): Request {
	// A real incoming request carries content-length; a constructed one does not, so it is set here.
	return new Request("http://x.test/login", {
		method: "POST",
		headers: { "content-length": String(new TextEncoder().encode(body).byteLength), ...extraHeaders },
		body,
	});
}

describe("bufferBodyForAppSec", () => {
	test("returns nothing for a GET", async () => {
		const result = await bufferBodyForAppSec(new Request("http://x.test/"), 1_024);
		expect(result.body).toBeNull();
		expect(result.outcome).toBe("none");
	});

	test("buffers a small body", async () => {
		const result = await bufferBodyForAppSec(bodyRequest("hello"), 1_024);
		expect(new TextDecoder().decode(result.body!)).toBe("hello");
		expect(result.outcome).toBe("inspected");
	});

	test("refuses a body larger than the cap, leaving the stream untouched", async () => {
		const request = bodyRequest("x".repeat(2_048));
		const result = await bufferBodyForAppSec(request, 1_024);
		expect(result.body).toBeNull();
		expect(result.outcome).toBe("oversized");
		expect(request.bodyUsed).toBe(false);
	});

	/**
	 * The important one. A chunked body has no declared length, and reading it to measure it would
	 * buffer an upload of any size into memory and leave it unforwardable.
	 */
	test("never touches a chunked body, whose size cannot be known in advance", async () => {
		const stream = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(new TextEncoder().encode("x".repeat(4_096)));
				controller.close();
			},
		});
		const request = new Request("http://x.test/upload", { method: "POST", body: stream, duplex: "half" } as RequestInit & { duplex: string });
		const result = await bufferBodyForAppSec(request, 1_024);
		expect(result.body).toBeNull();
		expect(result.outcome).toBe("unknown-length");
		expect(request.bodyUsed).toBe(false);
	});

	test("a zero cap disables body inspection without consuming anything", async () => {
		const request = bodyRequest("hello");
		const result = await bufferBodyForAppSec(request, 0);
		expect(result.outcome).toBe("disabled");
		expect(request.bodyUsed).toBe(false);
	});

	test("a buffered request can still be rebuilt and forwarded", async () => {
		const original = bodyRequest('{"a":1}', { "content-type": "application/json" });
		const buffered = await bufferBodyForAppSec(original, 1_024);
		const rebuilt = new Request(original, { body: buffered.body });
		expect(await rebuilt.text()).toBe('{"a":1}');
		expect(rebuilt.headers.get("content-type")).toBe("application/json");
		expect(rebuilt.method).toBe("POST");
	});
});
