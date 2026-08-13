export const BURROWGATE_SESSION_ASSERTION_HEADER = "x-burrowgate-session-assertion";
export class BurrowGateError extends Error {
    status;
    originalError;
    constructor(message, status, originalError) {
        super(message);
        this.status = status;
        this.originalError = originalError;
        this.name = "BurrowGateError";
    }
}
export class BurrowGateAuthenticationError extends BurrowGateError {
    constructor(message = "A valid BurrowGate session assertion is required") {
        super(message, 401);
        this.name = "BurrowGateAuthenticationError";
    }
}
function required(value, label) {
    const normalized = value.trim();
    if (!normalized)
        throw new TypeError(`${label} is required`);
    return normalized;
}
function validSession(value) {
    if (!value || typeof value !== "object")
        return false;
    const session = value;
    return (session.active === true &&
        typeof session.siteId === "string" &&
        typeof session.sessionId === "string" &&
        typeof session.authenticatedAt === "number" &&
        typeof session.expiresAt === "number" &&
        typeof session.assertionExpiresAt === "number" &&
        Boolean(session.user) &&
        typeof session.user?.id === "string" &&
        typeof session.user?.username === "string");
}
export function sessionAssertionFromRequest(request, headerName = BURROWGATE_SESSION_ASSERTION_HEADER) {
    return request.headers.get(headerName)?.trim() || null;
}
export function sessionAssertionFromHeaders(headers, headerName = BURROWGATE_SESSION_ASSERTION_HEADER) {
    const getter = headers.get;
    if (typeof getter === "function")
        return getter.call(headers, headerName)?.trim() || null;
    const record = headers;
    const value = record[headerName.toLowerCase()] ?? record[headerName];
    return (Array.isArray(value) ? value[0] : value)?.trim() || null;
}
function copySession(session) {
    return { ...session, user: { ...session.user } };
}
export class BurrowGateClient {
    baseUrl;
    siteId;
    verificationToken;
    timeoutMs;
    cacheTtlMs;
    maxCacheEntries;
    fetchImplementation;
    cache = new Map();
    inFlight = new Map();
    lastCachePruneAt = 0;
    constructor(options) {
        this.baseUrl = new URL(options.baseUrl);
        if (!["http:", "https:"].includes(this.baseUrl.protocol))
            throw new TypeError("baseUrl must use HTTP or HTTPS");
        this.siteId = required(options.siteId, "siteId");
        this.verificationToken = required(options.verificationToken, "verificationToken");
        this.timeoutMs = options.timeoutMs ?? 5_000;
        if (!Number.isFinite(this.timeoutMs) || this.timeoutMs <= 0)
            throw new TypeError("timeoutMs must be a positive number");
        this.cacheTtlMs = options.cacheTtlMs ?? 5_000;
        if (!Number.isFinite(this.cacheTtlMs) || this.cacheTtlMs < 0)
            throw new TypeError("cacheTtlMs must be zero or a positive number");
        this.maxCacheEntries = options.maxCacheEntries ?? 10_000;
        if (!Number.isInteger(this.maxCacheEntries) || this.maxCacheEntries <= 0)
            throw new TypeError("maxCacheEntries must be a positive integer");
        this.fetchImplementation = options.fetch ?? globalThis.fetch;
        if (!this.fetchImplementation)
            throw new TypeError("A fetch implementation is required");
    }
    async introspect(sessionAssertion) {
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
            if (session)
                this.storeCachedSession(token, session);
            return session ? copySession(session) : null;
        }
        finally {
            if (this.inFlight.get(token) === request)
                this.inFlight.delete(token);
        }
    }
    async requestIntrospection(token) {
        const endpoint = new URL("/_burrowgate/api/access/session/introspect", this.baseUrl);
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
        let response;
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
        }
        catch (error) {
            throw new BurrowGateError(error instanceof Error && error.name === "AbortError" ? "BurrowGate introspection timed out" : "BurrowGate introspection failed", undefined, error);
        }
        finally {
            clearTimeout(timeout);
        }
        let body;
        try {
            body = await response.json();
        }
        catch (error) {
            throw new BurrowGateError("BurrowGate returned an invalid introspection response", response.status, error);
        }
        if (!response.ok) {
            const message = body && typeof body === "object" && "error" in body ? String(body.error) : "BurrowGate introspection failed";
            throw new BurrowGateError(message, response.status);
        }
        if (body && typeof body === "object" && body.active === false)
            return null;
        if (!validSession(body) || body.siteId !== this.siteId)
            throw new BurrowGateError("BurrowGate returned an invalid introspection response", response.status);
        return body;
    }
    storeCachedSession(token, session) {
        if (this.cacheTtlMs === 0)
            return;
        const now = Date.now();
        const expiresAt = Math.min(now + this.cacheTtlMs, session.assertionExpiresAt, session.expiresAt);
        if (expiresAt <= now)
            return;
        if (now - this.lastCachePruneAt >= 1_000 || this.cache.size >= this.maxCacheEntries)
            this.pruneCache(now);
        while (this.cache.size >= this.maxCacheEntries) {
            const oldest = this.cache.keys().next().value;
            if (oldest === undefined)
                break;
            this.cache.delete(oldest);
        }
        this.cache.set(token, { session: copySession(session), expiresAt });
    }
    /** Remove expired entries. Cached sessions are never returned after their expiry even before pruning. */
    pruneCache(now = Date.now()) {
        let removed = 0;
        for (const [token, entry] of this.cache) {
            if (entry.expiresAt > now)
                continue;
            this.cache.delete(token);
            removed += 1;
        }
        this.lastCachePruneAt = now;
        return removed;
    }
    /** Invalidate one assertion, or every cached assertion when no value is supplied. */
    clearCache(sessionAssertion) {
        if (sessionAssertion === undefined)
            this.cache.clear();
        else
            this.cache.delete(sessionAssertion.trim());
    }
    get cacheSize() {
        this.pruneCache();
        return this.cache.size;
    }
    async authenticate(request, headerName = BURROWGATE_SESSION_ASSERTION_HEADER) {
        const assertion = sessionAssertionFromRequest(request, headerName);
        return assertion ? await this.introspect(assertion) : null;
    }
    async authenticateHeaders(headers, headerName = BURROWGATE_SESSION_ASSERTION_HEADER) {
        const assertion = sessionAssertionFromHeaders(headers, headerName);
        return assertion ? await this.introspect(assertion) : null;
    }
    async requireSession(request, headerName = BURROWGATE_SESSION_ASSERTION_HEADER) {
        const session = await this.authenticate(request, headerName);
        if (!session)
            throw new BurrowGateAuthenticationError();
        return session;
    }
}
export async function createBrowserSessionAssertion(baseUrl, fetchImplementation = globalThis.fetch) {
    const browserOrigin = globalThis.location?.origin;
    const resolvedBaseUrl = baseUrl ?? browserOrigin;
    if (!resolvedBaseUrl)
        throw new TypeError("baseUrl is required outside a browser");
    const response = await fetchImplementation(new URL("/_burrowgate/access/session-token", resolvedBaseUrl), {
        method: "POST",
        credentials: "include",
        headers: { accept: "application/json" },
    });
    let body;
    try {
        body = (await response.json());
    }
    catch (error) {
        throw new BurrowGateError("BurrowGate returned an invalid session assertion response", response.status, error);
    }
    if (!response.ok)
        throw new BurrowGateError(body.error ? String(body.error) : "Unable to create a BurrowGate session assertion", response.status);
    if (!body.token || typeof body.expiresAt !== "number" || !body.user?.id || !body.user.username) {
        throw new BurrowGateError("BurrowGate returned an invalid session assertion response", response.status);
    }
    return body;
}
//# sourceMappingURL=mod.js.map