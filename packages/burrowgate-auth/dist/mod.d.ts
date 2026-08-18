/**
 * Default HTTP request header used to carry a short-lived BurrowGate session
 * assertion from a browser to a separate backend.
 */
export declare const BURROWGATE_SESSION_ASSERTION_HEADER = "x-burrowgate-session-assertion";
/** A runtime-neutral subset of `fetch` accepted by the SDK. */
export type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;
/** Configuration for the server-side {@link BurrowGateClient}. */
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
    /** Maximum time to cache a successful introspection. Defaults to 5 seconds (use 0 to disable). */
    cacheTtlMs?: number;
    /** Maximum number of active assertions retained in memory. Defaults to 10,000. */
    maxCacheEntries?: number;
}
/** A BurrowGate access-list identity that has been verified server-side. */
export interface BurrowGateUser {
    /** Stable BurrowGate access-list user ID. */
    id: string;
    /** Normalized username, commonly the user's email address for SSO accounts. */
    username: string;
}
/** Active session identity returned by BurrowGate's introspection endpoint. */
export interface BurrowGateSession {
    /** Always `true` for an active introspection result. */
    active: true;
    /** ID of the BurrowGate site that issued the assertion. */
    siteId: string;
    /** Opaque BurrowGate session record ID. This is not the browser session secret. */
    sessionId: string;
    /** Verified access-list user. */
    user: BurrowGateUser;
    /** Unix timestamp in milliseconds at which the user authenticated. */
    authenticatedAt: number;
    /** Unix timestamp in milliseconds at which the parent session expires. */
    expiresAt: number;
    /** Unix timestamp in milliseconds at which the supplied assertion expires. */
    assertionExpiresAt: number;
}
/** Short-lived assertion minted for an authenticated browser session. */
export interface BrowserSessionAssertion {
    /** Signed assertion to send in {@link BURROWGATE_SESSION_ASSERTION_HEADER}. */
    token: string;
    /** Unix timestamp in milliseconds at which this assertion expires. */
    expiresAt: number;
    /** User associated with the authenticated browser session. */
    user: BurrowGateUser;
}
/**
 * Configuration for {@link BrowserSessionAssertionClient}, which keeps a
 * browser assertion fresh in memory.
 */
export interface BrowserSessionAssertionClientOptions {
    /** BurrowGate frontend-site origin. Defaults to the current browser origin. */
    baseUrl?: string | URL;
    /**
     * Base URL for authenticated API requests. Defaults to `baseUrl`. Relative
     * URLs passed to {@link BrowserSessionAssertionClient.fetch} resolve here.
     */
    apiBaseUrl?: string | URL;
    /** Optional fetch implementation. Defaults to `globalThis.fetch`. */
    fetch?: FetchLike;
    /** How early to refresh before expiry. Defaults to 30 seconds. */
    refreshAheadMs?: number;
    /** Delay before retrying a failed background refresh. Defaults to 5 seconds. */
    retryDelayMs?: number;
    /** Start background refresh immediately. Defaults to `true`. */
    autoStart?: boolean;
    /** Optional callback invoked after a new assertion is stored. */
    onUpdate?: (assertion: BrowserSessionAssertion) => void;
    /** Optional callback invoked when a background refresh fails. */
    onError?: (error: unknown) => void;
}
/** Base error thrown for BurrowGate transport, configuration, or response failures. */
export declare class BurrowGateError extends Error {
    /** HTTP status returned by BurrowGate, when available. */
    readonly status?: number;
    /** Original runtime error, when available. */
    readonly originalError?: unknown;
    /**
     * Creates a BurrowGate SDK error.
     *
     * @param message Human-readable failure description.
     * @param status HTTP status returned by BurrowGate, when available.
     * @param originalError Original runtime error, when available.
     */
    constructor(message: string, status?: number, originalError?: unknown);
}
/** Error thrown by helpers that require an active authenticated session. */
export declare class BurrowGateAuthenticationError extends BurrowGateError {
    /** Creates an authentication error with HTTP status 401. */
    constructor(message?: string);
}
/**
 * Reads a session assertion from a standard Web `Request`.
 *
 * @param request Incoming backend request.
 * @param headerName Header to read (defaults to {@link BURROWGATE_SESSION_ASSERTION_HEADER}).
 * @returns The trimmed assertion, or `null` when the header is absent or empty.
 */
export declare function sessionAssertionFromRequest(request: Request, headerName?: string): string | null;
/**
 * Reads a session assertion from Web headers, a `get(name)` compatible header
 * collection, or a plain runtime header record.
 *
 * @param headers Incoming backend request headers.
 * @param headerName Header to read (defaults to {@link BURROWGATE_SESSION_ASSERTION_HEADER}).
 * @returns The trimmed assertion, or `null` when the header is absent or empty.
 */
export declare function sessionAssertionFromHeaders(headers: Headers | {
    get(name: string): string | null | undefined;
} | Record<string, string | string[] | undefined>, headerName?: string): string | null;
/**
 * Server-side client that introspects browser assertions with BurrowGate and
 * optionally caches successful results for a short, bounded period.
 *
 * Never construct this class in browser code because its verification token is
 * a server-only secret. Use {@link BrowserSessionAssertionClient} in browsers.
 */
export declare class BurrowGateClient {
    /** Normalized BurrowGate base URL. */
    readonly baseUrl: URL;
    /** Frontend site ID whose assertions this client accepts. */
    readonly siteId: string;
    /** Server-only credential used for introspection. */
    readonly verificationToken: string;
    /** Maximum duration of one introspection request in milliseconds. */
    readonly timeoutMs: number;
    /** Maximum successful-introspection cache duration in milliseconds. */
    readonly cacheTtlMs: number;
    /** Maximum number of successful introspection results cached in memory. */
    readonly maxCacheEntries: number;
    private readonly fetchImplementation;
    private readonly cache;
    private readonly inFlight;
    private lastCachePruneAt;
    /** Creates a server-side BurrowGate assertion introspection client. */
    constructor(options: BurrowGateClientOptions);
    /**
     * Verifies one assertion, using a fresh cached result when available.
     *
     * @returns An active session, or `null` for an invalid, expired, or revoked assertion.
     * @throws {@link BurrowGateError} when introspection cannot be completed safely.
     */
    introspect(sessionAssertion: string): Promise<BurrowGateSession | null>;
    /** Performs one uncached request to BurrowGate's introspection endpoint. */
    private requestIntrospection;
    /** Stores a successful result within both the configured TTL and assertion expiry. */
    private storeCachedSession;
    /**
     * Removes expired cache entries.
     *
     * Cached sessions are never returned after expiry even if this method has not
     * been called explicitly.
     *
     * @returns Number of entries removed.
     */
    pruneCache(now?: number): number;
    /** Invalidates one assertion, or every cached assertion when no value is supplied. */
    clearCache(sessionAssertion?: string): void;
    /** Number of currently live successful-introspection cache entries. */
    get cacheSize(): number;
    /**
     * Authenticates a standard Web request using its assertion header.
     *
     * @returns An active session, or `null` when no valid assertion is present.
     */
    authenticate(request: Request, headerName?: string): Promise<BurrowGateSession | null>;
    /**
     * Authenticates request headers without requiring a Web `Request` object.
     *
     * @returns An active session, or `null` when no valid assertion is present.
     */
    authenticateHeaders(headers: Headers | {
        get(name: string): string | null | undefined;
    } | Record<string, string | string[] | undefined>, headerName?: string): Promise<BurrowGateSession | null>;
    /**
     * Authenticates a Web request and throws when no active session is present.
     *
     * @throws {@link BurrowGateAuthenticationError} for a missing or inactive session.
     */
    requireSession(request: Request, headerName?: string): Promise<BurrowGateSession>;
}
/** Reason a call to {@link verifyOriginRequest} did not produce a trusted result. */
export type OriginVerificationFailureReason = 
/** One or more required `X-BurrowGate-*` headers were absent, so the request did not come through BurrowGate. */
"missing-headers"
/** `X-BurrowGate-Timestamp` is further from the current time than `maxAgeSeconds` allows. */
 | "stale-timestamp"
/** `X-BurrowGate-Signature` does not match the recomputed HMAC for this secret. */
 | "invalid-signature"
/** `X-BurrowGate-Authenticated-User` was present without a matching, valid `X-BurrowGate-Identity-Signature` (or vice versa). */
 | "invalid-identity-signature";
/** Result of a failed {@link verifyOriginRequest} call. */
export interface OriginVerificationFailure {
    /** Always `false`. Treat the request as not having come through BurrowGate. */
    valid: false;
    /** Why verification failed. */
    reason: OriginVerificationFailureReason;
}
/** Result of a successful {@link verifyOriginRequest} call. */
export interface OriginVerifiedRequest {
    /** Always `true`. */
    valid: true;
    /** Opaque BurrowGate session ID, or the access mode (e.g. `allowlisted`) when no session exists. Cryptographically bound to the signature. */
    sessionId: string;
    /** Client IP BurrowGate observed for this request. Cryptographically bound to the signature. */
    clientIp: string;
    /** ISO 3166-1 country code, `XX` for a private/local address, or `ZZ` when unresolved. Cryptographically bound to the signature. */
    country: string;
    /** Unix timestamp in seconds at which BurrowGate signed this request. */
    timestamp: number;
    /** BurrowGate's origin access mode for this request (`verified`, `allowlisted`, or `bypass`). Not itself covered by the signature; informational only. */
    accessMode: string | null;
    /** Whether BurrowGate considers this request authenticated. Not itself covered by the signature; informational only. */
    verified: boolean;
    /** Authenticated access-list username, verified against `X-BurrowGate-Identity-Signature`. `null` when identity forwarding is not enabled for this request. */
    authenticatedUser: string | null;
}
/** Result of {@link verifyOriginRequest}: a discriminated union on `valid`. */
export type OriginVerificationResult = OriginVerifiedRequest | OriginVerificationFailure;
/** Options for {@link verifyOriginRequest}. */
export interface VerifyOriginRequestOptions {
    /**
     * Maximum allowed difference, in seconds, between `X-BurrowGate-Timestamp`
     * and the current time. Defaults to 60. Set to 0 to disable the freshness
     * check entirely (not recommended: without it, a captured request can be
     * replayed indefinitely).
     */
    maxAgeSeconds?: number;
}
/**
 * Verifies that a request actually passed through BurrowGate and was not
 * forged or tampered with by a client that reached the origin directly,
 * using only the site's `origin_signing_secret` (no network call).
 *
 * Call this as the first thing in the request handler, before reading the
 * request body. `X-BurrowGate-Timestamp` is stamped when BurrowGate signs the
 * outgoing request, before the body is forwarded, so a large or slow upload
 * does not affect the freshness check - but only if verification happens
 * before the body is consumed. Verifying after buffering a large upload would
 * measure upload time against `maxAgeSeconds` and could fail spuriously.
 *
 * @param request Incoming request as received by the origin.
 * @param originSigningSecret The protected site's origin signing secret (same value shown in BurrowGate's site editor).
 * @returns A discriminated result: check `result.valid` before trusting any field.
 * @throws {@link TypeError} for an empty `originSigningSecret` or an invalid `maxAgeSeconds`.
 */
export declare function verifyOriginRequest(request: Request, originSigningSecret: string, options?: VerifyOriginRequestOptions): Promise<OriginVerificationResult>;
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
export declare function createBrowserSessionAssertion(baseUrl?: string | URL, fetchImplementation?: FetchLike): Promise<BrowserSessionAssertion>;
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
export declare class BrowserSessionAssertionClient {
    /** Normalized BurrowGate frontend-site base URL. */
    readonly baseUrl: URL;
    /** Normalized base URL used by authenticated API requests. */
    readonly apiBaseUrl: URL;
    /** Number of milliseconds before expiry at which background refresh begins. */
    readonly refreshAheadMs: number;
    /** Number of milliseconds before a failed background refresh is retried. */
    readonly retryDelayMs: number;
    private readonly fetchImplementation;
    private readonly onUpdate?;
    private readonly onError?;
    private assertion;
    private refreshPromise;
    private refreshTimer;
    private running;
    private generation;
    /** Creates a browser assertion manager and starts it unless `autoStart` is false. */
    constructor(options?: BrowserSessionAssertionClientOptions);
    /**
     * Current valid assertion, or `null` before the first successful fetch and
     * after expiry. A defensive copy is returned.
     */
    get currentAssertion(): BrowserSessionAssertion | null;
    /** Current valid assertion token, or `null` when no valid assertion is ready. */
    get token(): string | null;
    /** Whether background refresh is currently enabled. */
    get isRunning(): boolean;
    /**
     * Starts background assertion maintenance.
     *
     * This method is idempotent. The first refresh happens asynchronously. Use
     * {@link getAssertion} or {@link getToken} when the caller must wait for it.
     */
    start(): void;
    /** Stops future background refreshes without deleting the current assertion. */
    stop(): void;
    /**
     * Returns the current assertion immediately when valid, otherwise waits for
     * one network refresh. Concurrent callers share the same refresh request.
     */
    getAssertion(): Promise<BrowserSessionAssertion>;
    /** Returns the current token, waiting for a refresh only when necessary. */
    getToken(): Promise<string>;
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
    fetch(input: string | URL | Request, init?: RequestInit): Promise<Response>;
    /**
     * Revokes the current BurrowGate browser session and clears local state.
     *
     * Background refresh is stopped before the request. Local assertions remain
     * cleared even if the network request fails, and the failure is reported as a
     * {@link BurrowGateError}.
     */
    logout(): Promise<void>;
    /**
     * Forces a new assertion request and replaces the in-memory value.
     * Concurrent refresh calls share one request.
     */
    refresh(): Promise<BrowserSessionAssertion>;
    /** Clears the in-memory assertion. Background maintenance remains enabled. */
    clear(): void;
    /** Schedules the next refresh before the current assertion expires. */
    private scheduleRefresh;
    /** Schedules another background attempt after a refresh failure. */
    private scheduleRetry;
    /** Starts a background refresh and reports failures without rejecting globally. */
    private runBackgroundRefresh;
}
//# sourceMappingURL=mod.d.ts.map