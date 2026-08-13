/**
 * Default HTTP request header used to carry a short-lived BurrowGate session
 * assertion from a browser to a separate backend.
 */
export const BURROWGATE_SESSION_ASSERTION_HEADER = "x-burrowgate-session-assertion";
/** Base error thrown for BurrowGate transport, configuration, or response failures. */
export class BurrowGateError extends Error {
    /** HTTP status returned by BurrowGate, when available. */
    status;
    /** Original runtime error, when available. */
    originalError;
    /**
     * Creates a BurrowGate SDK error.
     *
     * @param message Human-readable failure description.
     * @param status HTTP status returned by BurrowGate, when available.
     * @param originalError Original runtime error, when available.
     */
    constructor(message, status, originalError) {
        super(message);
        this.name = "BurrowGateError";
        this.status = status;
        this.originalError = originalError;
    }
}
/** Error thrown by helpers that require an active authenticated session. */
export class BurrowGateAuthenticationError extends BurrowGateError {
    /** Creates an authentication error with HTTP status 401. */
    constructor(message = "A valid BurrowGate session assertion is required") {
        super(message, 401);
        this.name = "BurrowGateAuthenticationError";
    }
}
function resolveFetch(fetchImplementation) {
    if (fetchImplementation)
        return fetchImplementation;
    if (typeof globalThis.fetch !== "function")
        throw new TypeError("A fetch implementation is required");
    return globalThis.fetch.bind(globalThis);
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
/**
 * Reads a session assertion from a standard Web `Request`.
 *
 * @param request Incoming backend request.
 * @param headerName Header to read (defaults to {@link BURROWGATE_SESSION_ASSERTION_HEADER}).
 * @returns The trimmed assertion, or `null` when the header is absent or empty.
 */
export function sessionAssertionFromRequest(request, headerName = BURROWGATE_SESSION_ASSERTION_HEADER) {
    return request.headers.get(headerName)?.trim() || null;
}
/**
 * Reads a session assertion from Web headers, a `get(name)` compatible header
 * collection, or a plain runtime header record.
 *
 * @param headers Incoming backend request headers.
 * @param headerName Header to read (defaults to {@link BURROWGATE_SESSION_ASSERTION_HEADER}).
 * @returns The trimmed assertion, or `null` when the header is absent or empty.
 */
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
/**
 * Server-side client that introspects browser assertions with BurrowGate and
 * optionally caches successful results for a short, bounded period.
 *
 * Never construct this class in browser code because its verification token is
 * a server-only secret. Use {@link BrowserSessionAssertionClient} in browsers.
 */
export class BurrowGateClient {
    /** Normalized BurrowGate base URL. */
    baseUrl;
    /** Frontend site ID whose assertions this client accepts. */
    siteId;
    /** Server-only credential used for introspection. */
    verificationToken;
    /** Maximum duration of one introspection request in milliseconds. */
    timeoutMs;
    /** Maximum successful-introspection cache duration in milliseconds. */
    cacheTtlMs;
    /** Maximum number of successful introspection results cached in memory. */
    maxCacheEntries;
    fetchImplementation;
    cache = new Map();
    inFlight = new Map();
    lastCachePruneAt = 0;
    /** Creates a server-side BurrowGate assertion introspection client. */
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
        this.fetchImplementation = resolveFetch(options.fetch);
    }
    /**
     * Verifies one assertion, using a fresh cached result when available.
     *
     * @returns An active session, or `null` for an invalid, expired, or revoked assertion.
     * @throws {@link BurrowGateError} when introspection cannot be completed safely.
     */
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
    /** Performs one uncached request to BurrowGate's introspection endpoint. */
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
    /** Stores a successful result within both the configured TTL and assertion expiry. */
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
    /**
     * Removes expired cache entries.
     *
     * Cached sessions are never returned after expiry even if this method has not
     * been called explicitly.
     *
     * @returns Number of entries removed.
     */
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
    /** Invalidates one assertion, or every cached assertion when no value is supplied. */
    clearCache(sessionAssertion) {
        if (sessionAssertion === undefined)
            this.cache.clear();
        else
            this.cache.delete(sessionAssertion.trim());
    }
    /** Number of currently live successful-introspection cache entries. */
    get cacheSize() {
        this.pruneCache();
        return this.cache.size;
    }
    /**
     * Authenticates a standard Web request using its assertion header.
     *
     * @returns An active session, or `null` when no valid assertion is present.
     */
    async authenticate(request, headerName = BURROWGATE_SESSION_ASSERTION_HEADER) {
        const assertion = sessionAssertionFromRequest(request, headerName);
        return assertion ? await this.introspect(assertion) : null;
    }
    /**
     * Authenticates request headers without requiring a Web `Request` object.
     *
     * @returns An active session, or `null` when no valid assertion is present.
     */
    async authenticateHeaders(headers, headerName = BURROWGATE_SESSION_ASSERTION_HEADER) {
        const assertion = sessionAssertionFromHeaders(headers, headerName);
        return assertion ? await this.introspect(assertion) : null;
    }
    /**
     * Authenticates a Web request and throws when no active session is present.
     *
     * @throws {@link BurrowGateAuthenticationError} for a missing or inactive session.
     */
    async requireSession(request, headerName = BURROWGATE_SESSION_ASSERTION_HEADER) {
        const session = await this.authenticate(request, headerName);
        if (!session)
            throw new BurrowGateAuthenticationError();
        return session;
    }
}
/**
 * Mints a new short-lived assertion for the current authenticated browser
 * session by calling `POST /_burrowgate/access/session-token`.
 *
 * The assertion lifetime is controlled by BurrowGate's
 * `BG_ACCESS_SESSION_ASSERTION_TTL_SECONDS` setting and is also capped by the
 * remaining parent-session lifetime. The default is five minutes.
 *
 * @param baseUrl BurrowGate frontend-site origin (defaults to the browser origin).
 * @param fetchImplementation Optional runtime fetch implementation.
 * @throws {@link BurrowGateError} when the session is unauthenticated or the response is invalid.
 */
export async function createBrowserSessionAssertion(baseUrl, fetchImplementation) {
    const browserOrigin = globalThis.location?.origin;
    const resolvedBaseUrl = baseUrl ?? browserOrigin;
    if (!resolvedBaseUrl)
        throw new TypeError("baseUrl is required outside a browser");
    const response = await resolveFetch(fetchImplementation)(new URL("/_burrowgate/access/session-token", resolvedBaseUrl), {
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
function copyAssertion(assertion) {
    return { ...assertion, user: { ...assertion.user } };
}
/**
 * Browser-side in-memory assertion manager.
 *
 * The client fetches an assertion when started, returns the current token
 * synchronously while it is valid, and refreshes it in the background shortly
 * before expiry. Assertions are intentionally not persisted to local storage,
 * session storage, cookies, or IndexedDB.
 *
 * @example Configure once, then use the authenticated fetch and logout helpers.
 * ```ts
 * const auth = new BrowserSessionAssertionClient({
 *   apiBaseUrl: "https://api.example.com",
 * });
 *
 * const response = await auth.fetch("/items");
 * await auth.logout();
 * ```
 */
export class BrowserSessionAssertionClient {
    /** Normalized BurrowGate frontend-site base URL. */
    baseUrl;
    /** Normalized base URL used by authenticated API requests. */
    apiBaseUrl;
    /** Number of milliseconds before expiry at which background refresh begins. */
    refreshAheadMs;
    /** Number of milliseconds before a failed background refresh is retried. */
    retryDelayMs;
    fetchImplementation;
    onUpdate;
    onError;
    assertion = null;
    refreshPromise = null;
    refreshTimer = null;
    running = false;
    generation = 0;
    /** Creates a browser assertion manager and starts it unless `autoStart` is false. */
    constructor(options = {}) {
        const browserOrigin = globalThis.location?.origin;
        const resolvedBaseUrl = options.baseUrl ?? browserOrigin;
        if (!resolvedBaseUrl)
            throw new TypeError("baseUrl is required outside a browser");
        this.baseUrl = new URL(resolvedBaseUrl);
        if (!["http:", "https:"].includes(this.baseUrl.protocol))
            throw new TypeError("baseUrl must use HTTP or HTTPS");
        this.apiBaseUrl = new URL(options.apiBaseUrl ?? this.baseUrl);
        if (!["http:", "https:"].includes(this.apiBaseUrl.protocol))
            throw new TypeError("apiBaseUrl must use HTTP or HTTPS");
        if (!this.apiBaseUrl.pathname.endsWith("/"))
            this.apiBaseUrl.pathname += "/";
        this.refreshAheadMs = options.refreshAheadMs ?? 30_000;
        if (!Number.isFinite(this.refreshAheadMs) || this.refreshAheadMs < 0)
            throw new TypeError("refreshAheadMs must be zero or a positive number");
        this.retryDelayMs = options.retryDelayMs ?? 5_000;
        if (!Number.isFinite(this.retryDelayMs) || this.retryDelayMs <= 0)
            throw new TypeError("retryDelayMs must be a positive number");
        this.fetchImplementation = resolveFetch(options.fetch);
        this.onUpdate = options.onUpdate;
        this.onError = options.onError;
        if (options.autoStart !== false)
            this.start();
    }
    /**
     * Current valid assertion, or `null` before the first successful fetch and
     * after expiry. A defensive copy is returned.
     */
    get currentAssertion() {
        if (!this.assertion || this.assertion.expiresAt <= Date.now())
            return null;
        return copyAssertion(this.assertion);
    }
    /** Current valid assertion token, or `null` when no valid assertion is ready. */
    get token() {
        return this.currentAssertion?.token ?? null;
    }
    /** Whether background refresh is currently enabled. */
    get isRunning() {
        return this.running;
    }
    /**
     * Starts background assertion maintenance.
     *
     * This method is idempotent. The first refresh happens asynchronously. Use
     * {@link getAssertion} or {@link getToken} when the caller must wait for it.
     */
    start() {
        if (this.running)
            return;
        this.running = true;
        this.runBackgroundRefresh();
    }
    /** Stops future background refreshes without deleting the current assertion. */
    stop() {
        this.running = false;
        if (this.refreshTimer !== null)
            clearTimeout(this.refreshTimer);
        this.refreshTimer = null;
    }
    /**
     * Returns the current assertion immediately when valid, otherwise waits for
     * one network refresh. Concurrent callers share the same refresh request.
     */
    async getAssertion() {
        const current = this.currentAssertion;
        return current ?? (await this.refresh());
    }
    /** Returns the current token, waiting for a refresh only when necessary. */
    async getToken() {
        return (await this.getAssertion()).token;
    }
    /**
     * Sends an authenticated API request.
     *
     * Relative URLs resolve against `apiBaseUrl`. The assertion header is added
     * automatically without removing existing headers. Requests to another
     * origin are rejected to prevent accidentally disclosing an assertion.
     *
     * @param input API URL or Request. Relative strings are supported.
     * @param init Standard fetch options.
     */
    async fetch(input, init) {
        const target = new URL(input instanceof Request ? input.url : input, this.apiBaseUrl);
        if (target.origin !== this.apiBaseUrl.origin) {
            throw new TypeError(`Refusing to send a BurrowGate assertion outside ${this.apiBaseUrl.origin}`);
        }
        const token = await this.getToken();
        const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
        headers.set(BURROWGATE_SESSION_ASSERTION_HEADER, token);
        return await this.fetchImplementation(input instanceof Request ? input : target, { ...init, headers });
    }
    /**
     * Revokes the current BurrowGate browser session and clears local state.
     *
     * Background refresh is stopped before the request. Local assertions remain
     * cleared even if the network request fails, and the failure is reported as a
     * {@link BurrowGateError}.
     */
    async logout() {
        this.stop();
        this.clear();
        const response = await this.fetchImplementation(new URL("/_burrowgate/access/logout", this.baseUrl), {
            method: "POST",
            credentials: "include",
            headers: { accept: "application/json" },
        });
        if (response.ok)
            return;
        let message = "Unable to log out of BurrowGate";
        try {
            const body = (await response.json());
            if (body.error)
                message = String(body.error);
        }
        catch {
            // Keep the generic message when the response is not JSON.
        }
        throw new BurrowGateError(message, response.status);
    }
    /**
     * Forces a new assertion request and replaces the in-memory value.
     * Concurrent refresh calls share one request.
     */
    async refresh() {
        if (this.refreshPromise)
            return copyAssertion(await this.refreshPromise);
        const generation = this.generation;
        const request = createBrowserSessionAssertion(this.baseUrl, this.fetchImplementation).then((assertion) => {
            if (generation !== this.generation)
                throw new BurrowGateAuthenticationError("The BurrowGate assertion request was cancelled");
            if (assertion.expiresAt <= Date.now())
                throw new BurrowGateError("BurrowGate returned an already expired session assertion");
            this.assertion = copyAssertion(assertion);
            this.onUpdate?.(copyAssertion(assertion));
            if (this.running)
                this.scheduleRefresh(assertion.expiresAt);
            return assertion;
        });
        this.refreshPromise = request;
        try {
            return copyAssertion(await request);
        }
        finally {
            if (this.refreshPromise === request)
                this.refreshPromise = null;
        }
    }
    /** Clears the in-memory assertion. Background maintenance remains enabled. */
    clear() {
        this.generation += 1;
        this.assertion = null;
        this.refreshPromise = null;
        if (this.refreshTimer !== null)
            clearTimeout(this.refreshTimer);
        this.refreshTimer = null;
        if (this.running)
            this.runBackgroundRefresh();
    }
    /** Schedules the next refresh before the current assertion expires. */
    scheduleRefresh(expiresAt) {
        if (!this.running)
            return;
        if (this.refreshTimer !== null)
            clearTimeout(this.refreshTimer);
        const remaining = Math.max(0, expiresAt - Date.now());
        const effectiveRefreshAhead = Math.min(this.refreshAheadMs, Math.max(1_000, remaining * 0.2));
        const delay = Math.max(1_000, remaining - effectiveRefreshAhead);
        this.refreshTimer = setTimeout(() => this.runBackgroundRefresh(), delay);
    }
    /** Schedules another background attempt after a refresh failure. */
    scheduleRetry() {
        if (!this.running)
            return;
        if (this.refreshTimer !== null)
            clearTimeout(this.refreshTimer);
        this.refreshTimer = setTimeout(() => this.runBackgroundRefresh(), this.retryDelayMs);
    }
    /** Starts a background refresh and reports failures without rejecting globally. */
    runBackgroundRefresh() {
        if (!this.running)
            return;
        this.refreshTimer = null;
        void this.refresh().catch((error) => {
            if (!this.running)
                return;
            this.onError?.(error);
            this.scheduleRetry();
        });
    }
}
//# sourceMappingURL=mod.js.map