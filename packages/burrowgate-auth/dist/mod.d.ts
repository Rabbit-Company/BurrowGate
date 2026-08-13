export declare const BURROWGATE_SESSION_ASSERTION_HEADER = "x-burrowgate-session-assertion";
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
export declare class BurrowGateError extends Error {
    readonly status?: number | undefined;
    readonly originalError?: unknown;
    constructor(message: string, status?: number | undefined, originalError?: unknown);
}
export declare class BurrowGateAuthenticationError extends BurrowGateError {
    constructor(message?: string);
}
export declare function sessionAssertionFromRequest(request: Request, headerName?: string): string | null;
export declare function sessionAssertionFromHeaders(headers: Headers | {
    get(name: string): string | null | undefined;
} | Record<string, string | string[] | undefined>, headerName?: string): string | null;
export declare class BurrowGateClient {
    readonly baseUrl: URL;
    readonly siteId: string;
    readonly verificationToken: string;
    readonly timeoutMs: number;
    readonly cacheTtlMs: number;
    readonly maxCacheEntries: number;
    private readonly fetchImplementation;
    private readonly cache;
    private readonly inFlight;
    private lastCachePruneAt;
    constructor(options: BurrowGateClientOptions);
    introspect(sessionAssertion: string): Promise<BurrowGateSession | null>;
    private requestIntrospection;
    private storeCachedSession;
    /** Remove expired entries. Cached sessions are never returned after their expiry even before pruning. */
    pruneCache(now?: number): number;
    /** Invalidate one assertion, or every cached assertion when no value is supplied. */
    clearCache(sessionAssertion?: string): void;
    get cacheSize(): number;
    authenticate(request: Request, headerName?: string): Promise<BurrowGateSession | null>;
    authenticateHeaders(headers: Headers | {
        get(name: string): string | null | undefined;
    } | Record<string, string | string[] | undefined>, headerName?: string): Promise<BurrowGateSession | null>;
    requireSession(request: Request, headerName?: string): Promise<BurrowGateSession>;
}
export declare function createBrowserSessionAssertion(baseUrl?: string | URL, fetchImplementation?: FetchLike): Promise<BrowserSessionAssertion>;
//# sourceMappingURL=mod.d.ts.map