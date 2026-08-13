export const BURROWGATE_SESSION_ASSERTION_HEADER = "x-burrowgate-session-assertion";

export type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export interface BurrowGateClientOptions {
	/** Base URL of any HTTP(S) listener served by the BurrowGate instance. */
	baseUrl: string | URL;
	/** ID of the frontend site that issued the browser session assertion. */
	siteId: string;
	/** Server-only verification token generated from the site's Access List settings. */
	verificationToken: string;
	/** Optional fetch implementation. Defaults to globalThis.fetch. */
	fetch?: FetchLike;
	/** Introspection request timeout. Defaults to 5 seconds. */
	timeoutMs?: number;
	/** Maximum time to cache a successful introspection. Defaults to 5 seconds; use 0 to disable. */
	cacheTtlMs?: number;
	/** Maximum number of active assertions retained in memory. Defaults to 10,000. */
	maxCacheEntries?: number;
}

export interface BurrowGateUser {
	id: string;
	username: string;
}

export interface BurrowGateSession {
	active: true;
	siteId: string;
	sessionId: string;
	user: BurrowGateUser;
	authenticatedAt: number;
	expiresAt: number;
	assertionExpiresAt: number;
}

export interface BrowserSessionAssertion {
	token: string;
	expiresAt: number;
	user: BurrowGateUser;
}

export class BurrowGateError extends Error {
	constructor(
		message: string,
		readonly status?: number,
		readonly originalError?: unknown,
	) {
		super(message);
		this.name = "BurrowGateError";
	}
}

export class BurrowGateAuthenticationError extends BurrowGateError {
	constructor(message = "A valid BurrowGate session assertion is required") {
		super(message, 401);
		this.name = "BurrowGateAuthenticationError";
	}
}

function required(value: string, label: string): string {
	const normalized = value.trim();
	if (!normalized) throw new TypeError(`${label} is required`);
	return normalized;
}

function validSession(value: unknown): value is BurrowGateSession {
	if (!value || typeof value !== "object") return false;
	const session = value as Partial<BurrowGateSession>;
	return (
		session.active === true &&
		typeof session.siteId === "string" &&
		typeof session.sessionId === "string" &&
		typeof session.authenticatedAt === "number" &&
		typeof session.expiresAt === "number" &&
		typeof session.assertionExpiresAt === "number" &&
		Boolean(session.user) &&
		typeof session.user?.id === "string" &&
		typeof session.user?.username === "string"
	);
}

export function sessionAssertionFromRequest(request: Request, headerName = BURROWGATE_SESSION_ASSERTION_HEADER): string | null {
	return request.headers.get(headerName)?.trim() || null;
}

export function sessionAssertionFromHeaders(
	headers: Headers | { get(name: string): string | null | undefined } | Record<string, string | string[] | undefined>,
	headerName = BURROWGATE_SESSION_ASSERTION_HEADER,
): string | null {
	const getter = (headers as { get?: unknown }).get;
	if (typeof getter === "function") return getter.call(headers, headerName)?.trim() || null;
	const record = headers as Record<string, string | string[] | undefined>;
	const value = record[headerName.toLowerCase()] ?? record[headerName];
	return (Array.isArray(value) ? value[0] : value)?.trim() || null;
}

function copySession(session: BurrowGateSession): BurrowGateSession {
	return { ...session, user: { ...session.user } };
}

export class BurrowGateClient {
	readonly baseUrl: URL;
	readonly siteId: string;
	readonly verificationToken: string;
	readonly timeoutMs: number;
	readonly cacheTtlMs: number;
	readonly maxCacheEntries: number;
	private readonly fetchImplementation: FetchLike;
	private readonly cache = new Map<string, { session: BurrowGateSession; expiresAt: number }>();
	private readonly inFlight = new Map<string, Promise<BurrowGateSession | null>>();
	private lastCachePruneAt = 0;

	constructor(options: BurrowGateClientOptions) {
		this.baseUrl = new URL(options.baseUrl);
		if (!["http:", "https:"].includes(this.baseUrl.protocol)) throw new TypeError("baseUrl must use HTTP or HTTPS");
		this.siteId = required(options.siteId, "siteId");
		this.verificationToken = required(options.verificationToken, "verificationToken");
		this.timeoutMs = options.timeoutMs ?? 5_000;
		if (!Number.isFinite(this.timeoutMs) || this.timeoutMs <= 0) throw new TypeError("timeoutMs must be a positive number");
		this.cacheTtlMs = options.cacheTtlMs ?? 5_000;
		if (!Number.isFinite(this.cacheTtlMs) || this.cacheTtlMs < 0) throw new TypeError("cacheTtlMs must be zero or a positive number");
		this.maxCacheEntries = options.maxCacheEntries ?? 10_000;
		if (!Number.isInteger(this.maxCacheEntries) || this.maxCacheEntries <= 0) throw new TypeError("maxCacheEntries must be a positive integer");
		this.fetchImplementation = options.fetch ?? globalThis.fetch;
		if (!this.fetchImplementation) throw new TypeError("A fetch implementation is required");
	}

	async introspect(sessionAssertion: string): Promise<BurrowGateSession | null> {
		const token = required(sessionAssertion, "sessionAssertion");
		const now = Date.now();
		const cached = this.cache.get(token);
		if (cached) {
			if (cached.expiresAt > now) {
				this.cache.delete(token);
				this.cache.set(token, cached);
				return copySession(cached.session);
			}
			this.cache.delete(token);
		}
		const pending = this.inFlight.get(token);
		if (pending) {
			const session = await pending;
			return session ? copySession(session) : null;
		}
		const request = this.requestIntrospection(token);
		this.inFlight.set(token, request);
		try {
			const session = await request;
			if (session) this.storeCachedSession(token, session);
			return session ? copySession(session) : null;
		} finally {
			if (this.inFlight.get(token) === request) this.inFlight.delete(token);
		}
	}

	private async requestIntrospection(token: string): Promise<BurrowGateSession | null> {
		const endpoint = new URL("/_burrowgate/api/access/session/introspect", this.baseUrl);
		const controller = new AbortController();
		const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
		let response: Response;
		try {
			response = await this.fetchImplementation(endpoint, {
				method: "POST",
				headers: {
					authorization: `Bearer ${this.verificationToken}`,
					"content-type": "application/json",
					accept: "application/json",
					"x-burrowgate-site-id": this.siteId,
				},
				body: JSON.stringify({ token }),
				signal: controller.signal,
			});
		} catch (error) {
			throw new BurrowGateError(
				error instanceof Error && error.name === "AbortError" ? "BurrowGate introspection timed out" : "BurrowGate introspection failed",
				undefined,
				error,
			);
		} finally {
			clearTimeout(timeout);
		}

		let body: unknown;
		try {
			body = await response.json();
		} catch (error) {
			throw new BurrowGateError("BurrowGate returned an invalid introspection response", response.status, error);
		}
		if (!response.ok) {
			const message = body && typeof body === "object" && "error" in body ? String((body as { error: unknown }).error) : "BurrowGate introspection failed";
			throw new BurrowGateError(message, response.status);
		}
		if (body && typeof body === "object" && (body as { active?: unknown }).active === false) return null;
		if (!validSession(body) || body.siteId !== this.siteId) throw new BurrowGateError("BurrowGate returned an invalid introspection response", response.status);
		return body;
	}

	private storeCachedSession(token: string, session: BurrowGateSession): void {
		if (this.cacheTtlMs === 0) return;
		const now = Date.now();
		const expiresAt = Math.min(now + this.cacheTtlMs, session.assertionExpiresAt, session.expiresAt);
		if (expiresAt <= now) return;
		if (now - this.lastCachePruneAt >= 1_000 || this.cache.size >= this.maxCacheEntries) this.pruneCache(now);
		while (this.cache.size >= this.maxCacheEntries) {
			const oldest = this.cache.keys().next().value as string | undefined;
			if (oldest === undefined) break;
			this.cache.delete(oldest);
		}
		this.cache.set(token, { session: copySession(session), expiresAt });
	}

	/** Remove expired entries. Cached sessions are never returned after their expiry even before pruning. */
	pruneCache(now: number = Date.now()): number {
		let removed = 0;
		for (const [token, entry] of this.cache) {
			if (entry.expiresAt > now) continue;
			this.cache.delete(token);
			removed += 1;
		}
		this.lastCachePruneAt = now;
		return removed;
	}

	/** Invalidate one assertion, or every cached assertion when no value is supplied. */
	clearCache(sessionAssertion?: string): void {
		if (sessionAssertion === undefined) this.cache.clear();
		else this.cache.delete(sessionAssertion.trim());
	}

	get cacheSize(): number {
		this.pruneCache();
		return this.cache.size;
	}

	async authenticate(request: Request, headerName = BURROWGATE_SESSION_ASSERTION_HEADER): Promise<BurrowGateSession | null> {
		const assertion = sessionAssertionFromRequest(request, headerName);
		return assertion ? await this.introspect(assertion) : null;
	}

	async authenticateHeaders(
		headers: Headers | { get(name: string): string | null | undefined } | Record<string, string | string[] | undefined>,
		headerName = BURROWGATE_SESSION_ASSERTION_HEADER,
	): Promise<BurrowGateSession | null> {
		const assertion = sessionAssertionFromHeaders(headers, headerName);
		return assertion ? await this.introspect(assertion) : null;
	}

	async requireSession(request: Request, headerName = BURROWGATE_SESSION_ASSERTION_HEADER): Promise<BurrowGateSession> {
		const session = await this.authenticate(request, headerName);
		if (!session) throw new BurrowGateAuthenticationError();
		return session;
	}
}

export async function createBrowserSessionAssertion(
	baseUrl?: string | URL,
	fetchImplementation: FetchLike = globalThis.fetch,
): Promise<BrowserSessionAssertion> {
	const browserOrigin = (globalThis as typeof globalThis & { location?: { origin?: string } }).location?.origin;
	const resolvedBaseUrl = baseUrl ?? browserOrigin;
	if (!resolvedBaseUrl) throw new TypeError("baseUrl is required outside a browser");
	const response = await fetchImplementation(new URL("/_burrowgate/access/session-token", resolvedBaseUrl), {
		method: "POST",
		credentials: "include",
		headers: { accept: "application/json" },
	});
	let body: Partial<BrowserSessionAssertion> & { error?: unknown };
	try {
		body = (await response.json()) as Partial<BrowserSessionAssertion> & { error?: unknown };
	} catch (error) {
		throw new BurrowGateError("BurrowGate returned an invalid session assertion response", response.status, error);
	}
	if (!response.ok) throw new BurrowGateError(body.error ? String(body.error) : "Unable to create a BurrowGate session assertion", response.status);
	if (!body.token || typeof body.expiresAt !== "number" || !body.user?.id || !body.user.username) {
		throw new BurrowGateError("BurrowGate returned an invalid session assertion response", response.status);
	}
	return body as BrowserSessionAssertion;
}
