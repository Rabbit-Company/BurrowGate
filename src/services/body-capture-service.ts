import { Readable } from "node:stream";
import {
	brotliDecompressSync,
	createBrotliDecompress,
	createGunzip,
	createInflate,
	createZstdDecompress,
	gunzipSync,
	inflateRawSync,
	inflateSync,
	zstdDecompressSync,
} from "node:zlib";

const TEXT_CONTENT_TYPE = /^(text\/|application\/(json|xml|javascript|x-javascript|x-www-form-urlencoded|x-ndjson|ld\+json)$|.*\+(json|xml)$)/u;

export function isTextContentType(contentType: string | null | undefined): boolean {
	if (!contentType) return false;
	const base = contentType.split(";")[0]?.trim().toLowerCase() ?? "";
	return base.length > 0 && TEXT_CONTENT_TYPE.test(base);
}

const ANY_TEXT_CONTENT_TYPE: readonly string[] = ["*"];

function isAllowedContentType(contentType: string | null | undefined, allowedContentTypes: readonly string[]): boolean {
	if (!isTextContentType(contentType)) return false;
	if (allowedContentTypes.includes("*")) return true;
	const base = contentType!.split(";")[0]!.trim().toLowerCase();
	return allowedContentTypes.includes(base);
}

export interface CapturedBody {
	text: string;
	truncated: boolean;
	contentType: string | null;
}

type CompressedFormat = "gzip" | "deflate" | "brotli" | "zstd";
type DecompressionFormat = "identity" | CompressedFormat | "unsupported";

function decompressionFormat(contentEncoding: string | null | undefined): DecompressionFormat {
	const value = contentEncoding?.trim().toLowerCase();
	if (!value || value === "identity") return "identity";
	if (value === "gzip" || value === "x-gzip") return "gzip";
	if (value === "deflate") return "deflate";
	if (value === "br") return "brotli";
	if (value === "zstd") return "zstd";
	return "unsupported";
}

function decompressBufferSync(buffer: Uint8Array, format: CompressedFormat): Uint8Array | null {
	try {
		switch (format) {
			case "gzip":
				return new Uint8Array(gunzipSync(buffer));
			case "brotli":
				return new Uint8Array(brotliDecompressSync(buffer));
			case "zstd":
				return new Uint8Array(zstdDecompressSync(buffer));
			case "deflate":
				try {
					return new Uint8Array(inflateSync(buffer));
				} catch {
					return new Uint8Array(inflateRawSync(buffer));
				}
		}
	} catch {
		return null;
	}
}

function concatChunks(chunks: Uint8Array[]): Uint8Array {
	const total = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
	const combined = new Uint8Array(total);
	let offset = 0;
	for (const chunk of chunks) {
		combined.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return combined;
}

export function captureBufferedBody(
	buffer: Uint8Array,
	contentType: string | null,
	maxBytes: number,
	contentEncoding: string | null = null,
	allowedContentTypes: readonly string[] = ANY_TEXT_CONTENT_TYPE,
): CapturedBody | null {
	if (maxBytes <= 0 || !isAllowedContentType(contentType, allowedContentTypes)) return null;
	const format = decompressionFormat(contentEncoding);
	if (format === "unsupported") return null;
	const decoded = format === "identity" ? buffer : decompressBufferSync(buffer, format);
	if (!decoded) return null;
	const truncated = decoded.byteLength > maxBytes;
	const slice = truncated ? decoded.subarray(0, maxBytes) : decoded;
	return { text: new TextDecoder().decode(slice), truncated, contentType: contentType ?? null };
}

export function tapBodyForCapture(
	body: ReadableStream<Uint8Array> | null,
	contentType: string | null,
	maxBytes: number,
	contentEncoding: string | null = null,
	allowedContentTypes: readonly string[] = ANY_TEXT_CONTENT_TYPE,
): { body: ReadableStream<Uint8Array> | null; captured: Promise<CapturedBody | null> } {
	if (!body || maxBytes <= 0 || !isAllowedContentType(contentType, allowedContentTypes)) {
		return { body, captured: Promise.resolve(null) };
	}
	const format = decompressionFormat(contentEncoding);
	if (format === "unsupported") return { body, captured: Promise.resolve(null) };
	if (format === "identity") return tapIdentityBody(body, contentType, maxBytes);

	const [forwardBranch, captureBranch] = body.tee();
	return { body: forwardBranch, captured: captureCompressed(captureBranch, contentType, maxBytes, format) };
}

function tapIdentityBody(
	body: ReadableStream<Uint8Array>,
	contentType: string | null,
	maxBytes: number,
): { body: ReadableStream<Uint8Array>; captured: Promise<CapturedBody | null> } {
	let settle: (value: CapturedBody | null) => void;
	const captured = new Promise<CapturedBody | null>((resolve) => {
		settle = resolve;
	});
	let settled = false;
	const chunks: Uint8Array[] = [];
	let received = 0;

	const tapped = body.pipeThrough(
		new TransformStream<Uint8Array, Uint8Array>({
			transform(chunk, controller) {
				if (!settled) {
					const remaining = maxBytes - received;
					if (remaining > 0) {
						const piece = chunk.byteLength > remaining ? chunk.subarray(0, remaining) : chunk;
						chunks.push(piece);
						received += piece.byteLength;
					}
					if (received >= maxBytes) {
						settled = true;
						settle(bufferedCapture(chunks, contentType, true));
					}
				}
				controller.enqueue(chunk);
			},
			flush() {
				if (!settled) {
					settled = true;
					settle(chunks.length > 0 ? bufferedCapture(chunks, contentType, false) : null);
				}
			},
		}),
	);
	return { body: tapped, captured };
}

function createDecompressTransform(format: CompressedFormat) {
	switch (format) {
		case "gzip":
			return createGunzip();
		case "brotli":
			return createBrotliDecompress();
		case "zstd":
			return createZstdDecompress();
		case "deflate":
			return createInflate();
	}
}

async function captureCompressed(
	stream: ReadableStream<Uint8Array>,
	contentType: string | null,
	maxBytes: number,
	format: CompressedFormat,
): Promise<CapturedBody | null> {
	const decompressTransform = createDecompressTransform(format);
	decompressTransform.on("error", () => {});
	const nodeSource = Readable.fromWeb(stream as any);
	nodeSource.on("error", () => {});
	const decompressed = Readable.toWeb(nodeSource.pipe(decompressTransform)) as unknown as ReadableStream<Uint8Array>;

	const reader = decompressed.getReader();
	const chunks: Uint8Array[] = [];
	let received = 0;
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			if (!value || value.byteLength === 0) continue;
			const remaining = maxBytes - received;
			const piece = value.byteLength > remaining ? value.subarray(0, remaining) : value;
			chunks.push(piece);
			received += piece.byteLength;
			if (received >= maxBytes) {
				void reader.cancel().catch(() => {});
				return bufferedCapture(chunks, contentType, true);
			}
		}
	} catch {
		return null;
	}
	return chunks.length > 0 ? bufferedCapture(chunks, contentType, false) : null;
}

function bufferedCapture(chunks: Uint8Array[], contentType: string | null, truncated: boolean): CapturedBody {
	return { text: new TextDecoder().decode(concatChunks(chunks)), truncated, contentType };
}
