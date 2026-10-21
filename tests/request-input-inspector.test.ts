import { afterAll, describe, expect, test } from "bun:test";
import { proxyRequest, RequestInputRejectedError } from "../src/services/proxy-service.ts";
import { requestLimitViolation, type RequestLimits, type ResolvedHttpPolicy } from "../src/services/http-policy-service.ts";
import { FormBodyInspector, formBodyKind, multipartBoundary } from "../src/services/request-input-inspector.ts";
import type { SiteRecord } from "../src/types.ts";

const unlimited: RequestLimits = {
	maxBodyBytes: 0,
	maxRequestTargetBytes: 0,
	maxHeaderBytes: 0,
	maxHeaderCount: 0,
	maxInputFields: 0,
	maxMultipartParts: 0,
	maxInputNestingDepth: 0,
};

const encoder = new TextEncoder();

function post(contentType: string, headers: Record<string, string> = {}): Request {
	return new Request("https://example.test/form", { method: "POST", headers: { "content-type": contentType, ...headers }, body: "" });
}

function multipart(boundary: string, parts: { headers: string; body: string }[]): string {
	return `${parts.map((part) => `--${boundary}\r\n${part.headers}\r\n\r\n${part.body}\r\n`).join("")}--${boundary}--\r\n`;
}

function field(name: string, value = "x"): { headers: string; body: string } {
	return { headers: `Content-Disposition: form-data; name="${name}"`, body: value };
}

function inspectBytewise(inspector: FormBodyInspector, body: string) {
	const bytes = encoder.encode(body);
	for (let index = 0; index < bytes.length; index++) {
		const violation = inspector.push(bytes.subarray(index, index + 1));
		if (violation) return violation;
	}
	return null;
}

describe("PHP-compatible form detection", () => {
	test("cuts the media type where PHP does and ignores case", () => {
		expect(formBodyKind("Multipart/Form-Data; boundary=x")).toBe("multipart");
		expect(formBodyKind("application/x-www-form-urlencoded,charset=utf-8")).toBe("urlencoded");
		expect(formBodyKind("application/x-www-form-urlencoded charset")).toBe("urlencoded");
		expect(formBodyKind("multipart/form-data\t; boundary=x")).toBeNull();
		expect(formBodyKind("application/json")).toBeNull();
		expect(formBodyKind(null)).toBeNull();
	});

	test("extracts the boundary the way PHP's rfc1867 parser does", () => {
		expect(multipartBoundary("multipart/form-data; boundary=abc123")).toBe("abc123");
		expect(multipartBoundary('multipart/form-data; boundary="a b;c"; charset=x')).toBe("a b;c");
		expect(multipartBoundary("multipart/form-data; boundary=abc,def")).toBe("abc");
		expect(multipartBoundary("multipart/form-data; BOUNDARY=Upper")).toBe("Upper");
		expect(multipartBoundary("multipart/form-data; x-boundary=first; boundary=second")).toBe("first");
		expect(multipartBoundary('multipart/form-data; boundary="unterminated')).toBeNull();
		expect(multipartBoundary("multipart/form-data")).toBeNull();
	});
});

describe("pre-body input limits", () => {
	test("rejects requests with too many headers", () => {
		const headers: Record<string, string> = {};
		for (let index = 0; index < 5; index++) headers[`x-h${index}`] = "1";
		const request = new Request("https://example.test/", { headers });
		expect(requestLimitViolation(request, { ...unlimited, maxHeaderCount: 4 })?.code).toBe("request_headers_too_many");
		expect(requestLimitViolation(request, { ...unlimited, maxHeaderCount: 5 })).toBeNull();
	});

	test("counts query fields on both separators and skips empty segments", () => {
		const limits = { ...unlimited, maxInputFields: 3 };
		expect(requestLimitViolation(new Request("https://example.test/?a=1&&b=2;c=3&"), limits)).toBeNull();
		expect(requestLimitViolation(new Request("https://example.test/?a=1&b=2;c=3&d"), limits)).toMatchObject({
			status: 414,
			code: "request_input_fields_too_many",
		});
	});

	test("counts literal and percent-encoded brackets in query keys only", () => {
		const limits = { ...unlimited, maxInputNestingDepth: 2 };
		expect(requestLimitViolation(new Request("https://example.test/?a[b][c]=[[[[[["), limits)).toBeNull();
		expect(requestLimitViolation(new Request("https://example.test/?a[b]%5Bc%5b=1"), limits)?.code).toBe("request_input_nesting_too_deep");
	});

	test("refuses form bodies it cannot inspect", () => {
		const limits = { ...unlimited, maxMultipartParts: 10 };
		expect(requestLimitViolation(post("multipart/form-data"), limits)).toMatchObject({ status: 400, code: "request_multipart_boundary_invalid" });
		expect(requestLimitViolation(post(`multipart/form-data; boundary=${"b".repeat(201)}`), limits)?.code).toBe("request_multipart_boundary_invalid");
		expect(requestLimitViolation(post("multipart/form-data; boundary=x", { "content-encoding": "gzip" }), limits)).toMatchObject({
			status: 415,
			code: "request_form_encoding_unsupported",
		});
		expect(requestLimitViolation(post("multipart/form-data; boundary=x", { "content-encoding": "identity" }), limits)).toBeNull();
	});

	test("leaves form bodies alone when no input limit applies to them", () => {
		expect(requestLimitViolation(post("multipart/form-data"), unlimited)).toBeNull();
		expect(requestLimitViolation(post("multipart/form-data"), { ...unlimited, maxInputFields: 10 })).toBeNull();
		expect(FormBodyInspector.forRequest(post("multipart/form-data; boundary=x"), unlimited, [])).toBeNull();
		expect(FormBodyInspector.forRequest(post("application/json"), { ...unlimited, maxInputNestingDepth: 1 }, ["X"])).toBeNull();
	});
});

describe("streaming form body inspection", () => {
	test("counts URL-encoded body fields and nesting", () => {
		const limits = { ...unlimited, maxInputFields: 3, maxInputNestingDepth: 1 };
		const request = post("application/x-www-form-urlencoded");
		expect(inspectBytewise(FormBodyInspector.forRequest(request, limits, [])!, "a=1&b[x]=2&c=[[[")).toBeNull();
		expect(inspectBytewise(FormBodyInspector.forRequest(request, limits, [])!, "a=1&b=2&c=3&d=4")).toMatchObject({
			status: 413,
			code: "request_input_fields_too_many",
		});
		expect(inspectBytewise(FormBodyInspector.forRequest(request, limits, [])!, "a%5B%5b=1")?.code).toBe("request_input_nesting_too_deep");
	});

	test("counts multipart parts across chunk boundaries", () => {
		const request = post("multipart/form-data; boundary=XyZ");
		const body = multipart("XyZ", [field("a"), field("b"), field("c")]);
		expect(inspectBytewise(FormBodyInspector.forRequest(request, { ...unlimited, maxMultipartParts: 4 }, [])!, body)).toBeNull();
		expect(inspectBytewise(FormBodyInspector.forRequest(request, { ...unlimited, maxMultipartParts: 3 }, [])!, body)).toMatchObject({
			status: 413,
			code: "request_multipart_parts_too_many",
		});
	});

	test("measures nesting across folded part headers but not in part content", () => {
		const request = post("multipart/form-data; boundary=b");
		const limits = { ...unlimited, maxInputNestingDepth: 3 };
		const shallow = multipart("b", [field("a[x][y]", "[[[[[[[[")]);
		expect(inspectBytewise(FormBodyInspector.forRequest(request, limits, [])!, shallow)).toBeNull();
		const folded = multipart("b", [{ headers: 'Content-Disposition: form-data;\r\n name="a[1][2]\r\n\t[3][4]"', body: "x" }]);
		expect(inspectBytewise(FormBodyInspector.forRequest(request, limits, [])!, folded)?.code).toBe("request_input_nesting_too_deep");
	});

	test("finds a blocked field name case-insensitively, however the body is split", () => {
		const request = post("multipart/form-data; boundary=b");
		const blocked = ["PHP_SESSION_UPLOAD_PROGRESS"];
		const body = multipart("b", [
			field("php_session_upload_progress", "1"),
			{ headers: 'Content-Disposition: form-data; name="f"; filename="a"', body: "data" },
		]);
		expect(inspectBytewise(FormBodyInspector.forRequest(request, unlimited, blocked)!, body)).toMatchObject({
			status: 403,
			code: "request_form_field_blocked",
		});
		expect(inspectBytewise(FormBodyInspector.forRequest(request, unlimited, blocked)!, multipart("b", [field("ordinary")]))).toBeNull();
	});

	test("keeps returning the violation after the first rejected chunk", () => {
		const inspector = FormBodyInspector.forRequest(post("application/x-www-form-urlencoded"), { ...unlimited, maxInputFields: 1 }, [])!;
		expect(inspector.push(encoder.encode("a=1&b=2"))?.code).toBe("request_input_fields_too_many");
		expect(inspector.push(encoder.encode(""))?.code).toBe("request_input_fields_too_many");
	});
});

describe("form inspection through the proxy", () => {
	let originRequests = 0;
	let originReceived = "";
	const origin = Bun.serve({
		hostname: "127.0.0.1",
		port: 0,
		async fetch(request) {
			originRequests++;
			originReceived = "";
			const decoder = new TextDecoder();
			try {
				for await (const chunk of request.body ?? []) originReceived += decoder.decode(chunk, { stream: true });
			} catch {}
			return new Response(`received ${originReceived.length}`);
		},
	});
	afterAll(() => origin.stop(true));

	const site = {
		id: "site-input-inspection-test",
		name: "Input inspection test",
		public_host: "proxy.test",
		origin_url: `http://127.0.0.1:${origin.port}`,
		origin_signing_secret: "test-signing-secret-that-is-at-least-32-characters",
		ip_extraction_preset: "direct",
		enabled: 1,
		session_ttl_seconds: 3_600,
	} as SiteRecord;

	function policy(limits: Partial<RequestLimits>, blockedMultipartFields: string[] = []): ResolvedHttpPolicy {
		return {
			requestHeaders: { set: [], remove: [] },
			responseHeaders: { set: [], remove: [] },
			limits: { ...unlimited, ...limits },
			blockedMultipartFields,
			cache: { mode: "disabled", ttlSeconds: 3_600, maxObjectBytes: 5_242_880, extensions: [] },
			protection: { mode: "disabled", rulesetId: "default", excludedRuleIds: [] },
			banDurations: { low: 0, medium: 600, high: 3_600, critical: 86_400 },
			bandwidthLimit: { enabled: false, maxBytes: 50 * 1_024 * 1_024, windowSeconds: 60, banSeconds: 3_600, scopeId: site.id },
			bodyCapture: { mode: "disabled", maxRequestBytes: 4_096, maxResponseBytes: 4_096, expiresAt: null, contentTypes: ["*"] },
			headerCapture: { mode: "disabled", redactAuthHeaders: true, redactedHeaders: [], expiresAt: null },
			cors: {
				mode: "disabled",
				allowedOrigins: [],
				allowedMethods: ["GET", "HEAD", "POST"],
				allowedHeaders: [],
				exposedHeaders: [],
				allowCredentials: false,
				maxAgeSeconds: 86_400,
			},
			hsts: { mode: "disabled", maxAgeSeconds: 15_552_000, includeSubDomains: false, preload: false },
		};
	}

	function send(request: Request, httpPolicy: ResolvedHttpPolicy) {
		return proxyRequest(request, site, "127.0.0.1", null, undefined, null, false, null, site.origin_url, httpPolicy);
	}

	test("rejects a buffered form body without contacting the origin", async () => {
		originRequests = 0;
		const body = multipart("b", [field("PHP_SESSION_UPLOAD_PROGRESS", "1"), field("a")]);
		const request = new Request("http://proxy.test/upload.php", {
			method: "POST",
			headers: { "content-type": "multipart/form-data; boundary=b", "content-length": String(encoder.encode(body).byteLength) },
			body,
		});
		const rejection = await send(request, policy({}, ["PHP_SESSION_UPLOAD_PROGRESS"])).catch((error: unknown) => error);
		expect(rejection).toBeInstanceOf(RequestInputRejectedError);
		expect((rejection as RequestInputRejectedError).violation.code).toBe("request_form_field_blocked");
		expect(originRequests).toBe(0);
	});

	test("rejects a streamed body at the chunk that breaks the limit", async () => {
		originReceived = "";
		const chunks = [encoder.encode("a=1&b=2&"), encoder.encode("c=3&d=4")];
		const body = new ReadableStream<Uint8Array>({
			pull(controller) {
				const chunk = chunks.shift();
				if (chunk) controller.enqueue(chunk);
				else controller.close();
			},
		});
		const request = new Request("http://proxy.test/form.php", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body });
		const rejection = await send(request, policy({ maxInputFields: 3 })).catch((error: unknown) => error);
		expect(rejection).toBeInstanceOf(RequestInputRejectedError);
		expect((rejection as RequestInputRejectedError).violation.code).toBe("request_input_fields_too_many");
		await Bun.sleep(20);
		expect(originReceived).not.toContain("c=3");
	});

	test("forwards form bodies that stay within the limits", async () => {
		const body = multipart("b", [field("a[b]"), field("c")]);
		const request = new Request("http://proxy.test/form.php", { method: "POST", headers: { "content-type": "multipart/form-data; boundary=b" }, body });
		const { response } = await send(request, policy({ maxMultipartParts: 10, maxInputNestingDepth: 4 }, ["PHP_SESSION_UPLOAD_PROGRESS"]));
		expect(response.status).toBe(200);
		expect(await response.text()).toBe(`received ${encoder.encode(body).byteLength}`);
	});
});
