import type { RequestLimits, RequestLimitViolation } from "./http-policy-service.ts";

export type FormBodyKind = "urlencoded" | "multipart";

const MAX_BOUNDARY_LENGTH = 200;

const LF = 0x0a;
const CR = 0x0d;
const AMPERSAND = 0x26;
const SEMICOLON = 0x3b;
const EQUALS = 0x3d;
const PERCENT = 0x25;
const DIGIT_5 = 0x35;
const OPEN_BRACKET = 0x5b;
const LOWER_B = 0x62;
const UPPER_B = 0x42;

const FIELD_START = /[^&;]/g;
const KEY_STOP = /[&;=[]|%5b/gi;
const VALUE_STOP = /[&;]/g;

function asciiLowercase(value: string): string {
	return value.replace(/[A-Z]+/gu, (letters) => letters.toLowerCase());
}

function latin1Bytes(value: string): Uint8Array {
	const bytes = new Uint8Array(value.length);
	for (let index = 0; index < value.length; index++) bytes[index] = value.charCodeAt(index) & 0xff;
	return bytes;
}

function latin1Text(chunk: Uint8Array): string {
	return Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength).toString("latin1");
}

function headerCount(headers: Headers): number {
	const count = (headers as Headers & { count?: number }).count;
	if (typeof count === "number") return count;
	let iterated = 0;
	for (const _ of headers) iterated++;
	return iterated;
}

export function formBodyKind(contentType: string | null): FormBodyKind | null {
	if (!contentType) return null;
	const end = contentType.search(/[;, ]/u);
	const mediaType = asciiLowercase(end === -1 ? contentType : contentType.slice(0, end));
	if (mediaType === "application/x-www-form-urlencoded") return "urlencoded";
	if (mediaType === "multipart/form-data") return "multipart";
	return null;
}

export function multipartBoundary(contentType: string): string | null {
	let start = contentType.indexOf("boundary");
	if (start === -1) start = asciiLowercase(contentType).indexOf("boundary");
	if (start === -1) return null;
	const equals = contentType.indexOf("=", start);
	if (equals === -1) return null;
	let boundary = contentType.slice(equals + 1);
	if (boundary.startsWith('"')) {
		const end = boundary.indexOf('"', 1);
		if (end === -1) return null;
		boundary = boundary.slice(1, end);
	} else {
		const end = boundary.search(/[,;]/u);
		if (end !== -1) boundary = boundary.slice(0, end);
	}
	return boundary;
}

class UrlEncodedScanner {
	fields = 0;
	maxDepth = 0;
	private atFieldStart = true;
	private inKey = false;
	private depth = 0;
	private percent = 0;

	feed(text: string): void {
		let index = 0;
		while (index < text.length) {
			if (this.percent === 0) {
				const stop = this.atFieldStart ? FIELD_START : this.inKey ? KEY_STOP : VALUE_STOP;
				stop.lastIndex = index;
				const match = stop.exec(text);
				if (!match) {
					if (this.inKey && !this.atFieldStart) {
						if (text.length - index >= 2 && text.endsWith("%5")) this.percent = 2;
						else if (text.endsWith("%")) this.percent = 1;
					}
					return;
				}
				index = match.index;
			}
			this.step(text.charCodeAt(index));
			index++;
		}
	}

	private step(byte: number): void {
		if (byte === AMPERSAND || byte === SEMICOLON) {
			this.atFieldStart = true;
			return;
		}
		if (this.atFieldStart) {
			this.atFieldStart = false;
			this.fields++;
			this.inKey = true;
			this.depth = 0;
			this.percent = 0;
		}
		if (!this.inKey) return;
		if (byte === EQUALS) {
			this.inKey = false;
			return;
		}
		if (byte === OPEN_BRACKET || (this.percent === 2 && (byte === LOWER_B || byte === UPPER_B))) {
			this.depth++;
			if (this.depth > this.maxDepth) this.maxDepth = this.depth;
		} else if (this.percent === 1 && byte === DIGIT_5) {
			this.percent = 2;
			return;
		}
		this.percent = byte === PERCENT ? 1 : 0;
	}
}

class MultipartScanner {
	parts = 0;
	maxDepth = 0;
	private readonly delimiter: Buffer;
	private carry = Buffer.alloc(0);
	private mode: "delimiter-line" | "headers" | "content" = "content";
	private lineLength = 0;
	private depth = 0;

	constructor(boundary: string) {
		this.delimiter = Buffer.from(latin1Bytes(`--${boundary}`));
	}

	feed(chunk: Uint8Array): void {
		const data = Buffer.concat([this.carry, chunk]);
		let cursor = this.carry.length;
		let searchFrom = 0;
		for (;;) {
			const match = data.indexOf(this.delimiter, searchFrom);
			const end = match === -1 ? data.length : match + this.delimiter.length;
			this.walk(data, cursor, end);
			if (match === -1) break;
			this.parts++;
			this.mode = "delimiter-line";
			cursor = end;
			searchFrom = match + 1;
		}
		this.carry = Buffer.from(data.subarray(Math.max(0, data.length - (this.delimiter.length - 1))));
	}

	private walk(data: Buffer, from: number, to: number): void {
		for (let index = from; index < to && this.mode !== "content"; index++) {
			const byte = data[index]!;
			if (this.mode === "delimiter-line") {
				if (byte === LF) {
					this.mode = "headers";
					this.lineLength = 0;
					this.depth = 0;
				}
				continue;
			}
			if (byte === LF) {
				if (this.lineLength === 0) this.mode = "content";
				this.lineLength = 0;
				continue;
			}
			if (byte === CR) continue;
			this.lineLength++;
			if (byte === OPEN_BRACKET) {
				this.depth++;
				if (this.depth > this.maxDepth) this.maxDepth = this.depth;
			}
		}
	}
}

class BlockedNameScanner {
	private readonly pattern: RegExp;
	private readonly carryLength: number;
	private carry = "";

	constructor(names: readonly string[]) {
		this.pattern = new RegExp(names.map((name) => name.replace(/[.*+?^${}()|[\]\\/]/gu, "\\$&")).join("|"), "i");
		this.carryLength = Math.max(...names.map((name) => name.length)) - 1;
	}

	feed(chunk: Uint8Array): boolean {
		const text = this.carry + latin1Text(chunk);
		this.carry = text.slice(Math.max(0, text.length - this.carryLength));
		return this.pattern.test(text);
	}
}

export function formInspectionActive(kind: FormBodyKind, limits: RequestLimits, blockedMultipartFields: readonly string[]): boolean {
	if (limits.maxInputNestingDepth > 0) return true;
	if (kind === "urlencoded") return limits.maxInputFields > 0;
	return limits.maxMultipartParts > 0 || blockedMultipartFields.length > 0;
}

function nestingViolation(): RequestLimitViolation {
	return { status: 400, code: "request_input_nesting_too_deep", message: "A request field is nested deeper than this route's configured limit." };
}

export function requestInputViolation(
	request: Request,
	url: URL,
	limits: RequestLimits,
	blockedMultipartFields: readonly string[],
): RequestLimitViolation | null {
	if (limits.maxHeaderCount > 0) {
		if (headerCount(request.headers) > limits.maxHeaderCount) {
			return { status: 431, code: "request_headers_too_many", message: "The request has more headers than this route's configured limit." };
		}
	}
	if ((limits.maxInputFields > 0 || limits.maxInputNestingDepth > 0) && url.search.length > 1) {
		const scanner = new UrlEncodedScanner();
		scanner.feed(url.search.slice(1));
		if (limits.maxInputFields > 0 && scanner.fields > limits.maxInputFields) {
			return { status: 414, code: "request_input_fields_too_many", message: "The query string has more fields than this route's configured limit." };
		}
		if (limits.maxInputNestingDepth > 0 && scanner.maxDepth > limits.maxInputNestingDepth) return nestingViolation();
	}
	if (request.method === "GET" || request.method === "HEAD") return null;
	const contentType = request.headers.get("content-type");
	const kind = formBodyKind(contentType);
	if (!kind || !formInspectionActive(kind, limits, blockedMultipartFields)) return null;
	const contentEncoding = request.headers.get("content-encoding")?.trim().toLowerCase();
	if (contentEncoding && contentEncoding !== "identity") {
		return {
			status: 415,
			code: "request_form_encoding_unsupported",
			message: "Form bodies with a Content-Encoding cannot be inspected and are not accepted on this route.",
		};
	}
	if (kind === "multipart") {
		const boundary = multipartBoundary(contentType!);
		if (!boundary || boundary.length > MAX_BOUNDARY_LENGTH) {
			return { status: 400, code: "request_multipart_boundary_invalid", message: "The multipart request has a missing or invalid boundary." };
		}
	}
	return null;
}

export class FormBodyInspector {
	private readonly urlEncoded: UrlEncodedScanner | null;
	private readonly multipart: MultipartScanner | null;
	private readonly blocked: BlockedNameScanner | null;
	private violation: RequestLimitViolation | null = null;

	private constructor(
		boundary: string | null,
		private readonly limits: RequestLimits,
		blockedMultipartFields: readonly string[],
	) {
		this.urlEncoded = boundary === null ? new UrlEncodedScanner() : null;
		this.multipart = boundary === null ? null : new MultipartScanner(boundary);
		this.blocked = boundary === null || blockedMultipartFields.length === 0 ? null : new BlockedNameScanner(blockedMultipartFields);
	}

	static forRequest(request: Request, limits: RequestLimits, blockedMultipartFields: readonly string[]): FormBodyInspector | null {
		const contentType = request.headers.get("content-type");
		const kind = formBodyKind(contentType);
		if (!kind || !formInspectionActive(kind, limits, blockedMultipartFields)) return null;
		if (kind === "urlencoded") return new FormBodyInspector(null, limits, []);
		const boundary = multipartBoundary(contentType!);
		if (!boundary || boundary.length > MAX_BOUNDARY_LENGTH) return null;
		return new FormBodyInspector(boundary, limits, blockedMultipartFields);
	}

	push(chunk: Uint8Array): RequestLimitViolation | null {
		if (this.violation) return this.violation;
		if (this.urlEncoded) {
			this.urlEncoded.feed(latin1Text(chunk));
			if (this.limits.maxInputFields > 0 && this.urlEncoded.fields > this.limits.maxInputFields) {
				return this.reject({
					status: 413,
					code: "request_input_fields_too_many",
					message: "The form body has more fields than this route's configured limit.",
				});
			}
			if (this.limits.maxInputNestingDepth > 0 && this.urlEncoded.maxDepth > this.limits.maxInputNestingDepth) return this.reject(nestingViolation());
			return null;
		}
		if (this.blocked?.feed(chunk)) {
			return this.reject({
				status: 403,
				code: "request_form_field_blocked",
				message: "The multipart body contains a field name that is blocked on this route.",
			});
		}
		const multipart = this.multipart!;
		multipart.feed(chunk);
		if (this.limits.maxMultipartParts > 0 && multipart.parts > this.limits.maxMultipartParts) {
			return this.reject({
				status: 413,
				code: "request_multipart_parts_too_many",
				message: "The multipart body has more parts than this route's configured limit.",
			});
		}
		if (this.limits.maxInputNestingDepth > 0 && multipart.maxDepth > this.limits.maxInputNestingDepth) return this.reject(nestingViolation());
		return null;
	}

	private reject(violation: RequestLimitViolation): RequestLimitViolation {
		this.violation = violation;
		return violation;
	}
}
