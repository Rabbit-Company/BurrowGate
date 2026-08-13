import { describe, expect, test } from "bun:test";
import { captureBufferedBody, isTextContentType, tapBodyForCapture } from "../src/services/body-capture-service.ts";

function streamOf(...chunks: string[]): ReadableStream<Uint8Array> {
	const encoder = new TextEncoder();
	return new ReadableStream({
		start(controller) {
			for (const chunk of chunks) controller.enqueue(encoder.encode(chunk));
			controller.close();
		},
	});
}

async function drain(stream: ReadableStream<Uint8Array> | null): Promise<string> {
	if (!stream) return "";
	const reader = stream.getReader();
	const decoder = new TextDecoder();
	let text = "";
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		text += decoder.decode(value, { stream: true });
	}
	return text;
}

describe("isTextContentType", () => {
	test("allows common text and structured-data content types", () => {
		expect(isTextContentType("text/plain")).toBe(true);
		expect(isTextContentType("text/html; charset=utf-8")).toBe(true);
		expect(isTextContentType("application/json")).toBe(true);
		expect(isTextContentType("application/json; charset=utf-8")).toBe(true);
		expect(isTextContentType("application/vnd.api+json")).toBe(true);
		expect(isTextContentType("application/xml")).toBe(true);
		expect(isTextContentType("application/x-www-form-urlencoded")).toBe(true);
	});

	test("rejects binary and missing content types", () => {
		expect(isTextContentType("image/png")).toBe(false);
		expect(isTextContentType("application/octet-stream")).toBe(false);
		expect(isTextContentType(null)).toBe(false);
		expect(isTextContentType(undefined)).toBe(false);
		expect(isTextContentType("")).toBe(false);
	});
});

describe("captureBufferedBody", () => {
	test("captures the full body when under the limit", () => {
		const body = new TextEncoder().encode('{"ok":true}');
		const captured = captureBufferedBody(body, "application/json", 4_096);
		expect(captured).toEqual({ text: '{"ok":true}', truncated: false, contentType: "application/json" });
	});

	test("truncates when the body exceeds the limit", () => {
		const body = new TextEncoder().encode("0123456789");
		const captured = captureBufferedBody(body, "text/plain", 4);
		expect(captured).toEqual({ text: "0123", truncated: true, contentType: "text/plain" });
	});

	test("returns null for non-text content types", () => {
		expect(captureBufferedBody(new Uint8Array([1, 2, 3]), "image/png", 4_096)).toBeNull();
	});

	test("returns null when capture is disabled (maxBytes 0)", () => {
		expect(captureBufferedBody(new TextEncoder().encode("hi"), "text/plain", 0)).toBeNull();
	});
});

describe("tapBodyForCapture", () => {
	test("forwards every byte untouched while capturing a small text body", async () => {
		const { body, captured } = tapBodyForCapture(streamOf("hello ", "world"), "text/plain", 4_096);
		const forwarded = await drain(body);
		expect(forwarded).toBe("hello world");
		expect(await captured).toEqual({ text: "hello world", truncated: false, contentType: "text/plain" });
	});

	test("truncates capture at the byte cap without dropping forwarded bytes", async () => {
		const { body, captured } = tapBodyForCapture(streamOf("0123456789"), "text/plain", 4);
		const forwarded = await drain(body);
		expect(forwarded).toBe("0123456789");
		expect(await captured).toEqual({ text: "0123", truncated: true, contentType: "text/plain" });
	});

	test("does not tap the stream for non-text content types", async () => {
		const { body, captured } = tapBodyForCapture(streamOf("binary-ish"), "application/octet-stream", 4_096);
		expect(await captured).toBeNull();
		expect(await drain(body)).toBe("binary-ish");
	});

	test("does not tap the stream when capture is disabled (maxBytes 0)", async () => {
		const { body, captured } = tapBodyForCapture(streamOf("hello"), "text/plain", 0);
		expect(await captured).toBeNull();
		expect(await drain(body)).toBe("hello");
	});

	test("returns null capture for a null body", async () => {
		const { body, captured } = tapBodyForCapture(null, "text/plain", 4_096);
		expect(body).toBeNull();
		expect(await captured).toBeNull();
	});

	test("decompresses a gzip-encoded body for capture while forwarding the compressed bytes untouched", async () => {
		const plain = "body { font-family: Arial; }".repeat(3);
		const compressed = Bun.gzipSync(new TextEncoder().encode(plain));
		const { body, captured } = tapBodyForCapture(new Blob([compressed]).stream(), "text/css", 4_096, "gzip");
		const forwarded = new Uint8Array(await new Response(body).arrayBuffer());
		expect(forwarded).toEqual(new Uint8Array(compressed));
		expect(await captured).toEqual({ text: plain, truncated: false, contentType: "text/css" });
	});

	test("stops decompressing a large gzip body once maxBytes of decoded text is reached, without draining the whole compressed source", async () => {
		let filler = "";
		let seed = 7;
		for (let i = 0; i < 200_000; i++) {
			seed = (seed * 1_103_515_245 + 12_345) & 0x7fffffff;
			filler += (seed % 36).toString(36);
		}
		const compressed = Bun.gzipSync(new TextEncoder().encode(filler));
		expect(compressed.byteLength).toBeGreaterThan(8_000);

		let suppliedBytes = 0;
		let sourceFinished = false;
		const chunkSize = 4_096;
		const throttledSource = new ReadableStream<Uint8Array>({
			async pull(controller) {
				if (suppliedBytes >= compressed.byteLength) {
					sourceFinished = true;
					controller.close();
					return;
				}
				const piece = compressed.subarray(suppliedBytes, Math.min(suppliedBytes + chunkSize, compressed.byteLength));
				suppliedBytes += piece.byteLength;
				controller.enqueue(piece);
				await new Promise((resolve) => setTimeout(resolve, 2));
			},
		});

		const { captured } = tapBodyForCapture(throttledSource, "text/plain", 1_024, "gzip");
		const result = await captured;
		expect(result?.truncated).toBe(true);
		expect(result?.text.length).toBe(1_024);
		expect(sourceFinished).toBe(false);
		expect(suppliedBytes).toBeLessThan(compressed.byteLength);
	});

	test("decompresses a brotli-encoded body for capture", async () => {
		const { brotliCompressSync } = await import("node:zlib");
		const plain = '{"hello":"world"}';
		const compressed = brotliCompressSync(new TextEncoder().encode(plain));
		const { captured } = tapBodyForCapture(new Blob([compressed]).stream(), "application/json", 4_096, "br");
		expect(await captured).toEqual({ text: plain, truncated: false, contentType: "application/json" });
	});

	test("does not capture a compressed body with an unsupported encoding", async () => {
		const { body, captured } = tapBodyForCapture(streamOf("whatever bytes"), "text/plain", 4_096, "compress");
		expect(await captured).toBeNull();
		expect(await drain(body)).toBe("whatever bytes");
	});

	test("gives up cleanly on a truncated/corrupt gzip stream instead of returning garbage", async () => {
		const compressed = Bun.gzipSync(new TextEncoder().encode("hello world, this is a longer body"));
		const truncated = compressed.subarray(0, Math.floor(compressed.byteLength / 2));
		const { captured } = tapBodyForCapture(new Blob([truncated]).stream(), "text/plain", 4_096, "gzip");
		expect(await captured).toBeNull();
	});
});

describe("captureBufferedBody with content-encoding", () => {
	test("decompresses a gzip-encoded buffered body", () => {
		const plain = "username=admin&password=hunter2";
		const compressed = Bun.gzipSync(new TextEncoder().encode(plain));
		expect(captureBufferedBody(compressed, "application/x-www-form-urlencoded", 4_096, "gzip")).toEqual({
			text: plain,
			truncated: false,
			contentType: "application/x-www-form-urlencoded",
		});
	});

	test("truncates after decompressing, not before", () => {
		const plain = "0123456789";
		const compressed = Bun.gzipSync(new TextEncoder().encode(plain));
		expect(captureBufferedBody(compressed, "text/plain", 4, "gzip")).toEqual({ text: "0123", truncated: true, contentType: "text/plain" });
	});

	test("returns null for an unsupported encoding", () => {
		expect(captureBufferedBody(new TextEncoder().encode("hi"), "text/plain", 4_096, "compress")).toBeNull();
	});
});
