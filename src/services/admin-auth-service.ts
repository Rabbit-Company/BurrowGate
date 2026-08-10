import { config, cookieCanBeIssuedForRequest, secureCookieForRequest } from "../config.ts";
import { repository } from "../db/repository.ts";
import type { AdminUserRecord } from "../types.ts";
import { parseCookies, serializeCookie } from "../utils/cookies.ts";
import { randomToken } from "../utils/crypto.ts";
import { LoginFailureTracker } from "./access-list-service.ts";

export type PendingLoginMode = "totp-enroll" | "totp-verify";

interface PendingLogin {
	userId: string;
	mode: PendingLoginMode;
	tentativeSecret: string | null;
	expiresAt: number;
}

const PENDING_COOKIE = "bg_admin_pending";
const PENDING_SWEEP_INTERVAL_MS = 30_000;
const pendingLogins = new Map<string, PendingLogin>();
let lastPendingSweepAt = 0;

const passwordFailures = new LoginFailureTracker(config.admin.loginMaxFailureKeys);
const totpFailures = new LoginFailureTracker(config.admin.loginMaxFailureKeys);
let dummyHash: Promise<string> | null = null;

function sweepPendingLogins(now: number): void {
	if (now - lastPendingSweepAt < PENDING_SWEEP_INTERVAL_MS) return;
	lastPendingSweepAt = now;
	for (const [token, entry] of pendingLogins) if (entry.expiresAt <= now) pendingLogins.delete(token);
}

export async function authenticateAdminPassword(
	ip: string,
	usernameInput: unknown,
	passwordInput: unknown,
): Promise<{ user: AdminUserRecord | null; retryAfterSeconds: number }> {
	const username = String(usernameInput ?? "")
		.trim()
		.toLowerCase();
	const suppliedPassword = String(passwordInput ?? "");
	const password = suppliedPassword.length <= 1024 ? suppliedPassword : "";
	const now = Date.now();
	const keys = [`ip:${ip}`, `user:${username}`];
	const retryAfterSeconds = passwordFailures.status(keys, now);
	if (retryAfterSeconds > 0) return { user: null, retryAfterSeconds };
	const user = username ? await repository.adminUserByUsername(username) : null;
	dummyHash ??= Bun.password.hash("burrowgate-dummy-admin-password", { algorithm: "argon2id" });
	const valid = await Bun.password.verify(password, user?.password_hash ?? (await dummyHash));
	if (!valid || !user || user.enabled !== 1) {
		passwordFailures.record(keys, now);
		return { user: null, retryAfterSeconds: 0 };
	}
	passwordFailures.clear(keys);
	return { user, retryAfterSeconds: 0 };
}

export function totpAttemptRetryAfterSeconds(pendingToken: string): number {
	return totpFailures.status([`pending:${pendingToken}`], Date.now());
}

export function recordTotpFailure(pendingToken: string): void {
	totpFailures.record([`pending:${pendingToken}`], Date.now());
}

export function clearTotpFailures(pendingToken: string): void {
	totpFailures.clear([`pending:${pendingToken}`]);
}

export function beginPendingLogin(mode: PendingLoginMode, userId: string): string {
	const now = Date.now();
	sweepPendingLogins(now);
	const token = randomToken();
	pendingLogins.set(token, { userId, mode, tentativeSecret: null, expiresAt: now + config.admin.pendingLoginTtlSeconds * 1_000 });
	return token;
}

export function pendingLoginToken(request: Request): string | null {
	return parseCookies(request.headers.get("cookie")).get(PENDING_COOKIE) ?? null;
}

export function resolvePendingLogin(request: Request, mode: PendingLoginMode): { token: string; entry: PendingLogin } | null {
	const token = pendingLoginToken(request);
	if (!token) return null;
	const entry = pendingLogins.get(token);
	if (!entry || entry.expiresAt <= Date.now() || entry.mode !== mode) return null;
	return { token, entry };
}

export function setPendingLoginSecret(token: string, secret: string): void {
	const entry = pendingLogins.get(token);
	if (entry) entry.tentativeSecret = secret;
}

export function consumePendingLogin(token: string): void {
	pendingLogins.delete(token);
}

export function pendingLoginCookie(request: Request, token: string): string {
	if (!cookieCanBeIssuedForRequest(request)) throw new Error("Insecure request cannot receive a pending-login cookie");
	return serializeCookie(PENDING_COOKIE, token, {
		secure: secureCookieForRequest(request),
		httpOnly: true,
		sameSite: "Strict",
		maxAge: config.admin.pendingLoginTtlSeconds,
	});
}

export function clearPendingLoginCookie(request: Request): string {
	return serializeCookie(PENDING_COOKIE, "", { secure: secureCookieForRequest(request), httpOnly: true, sameSite: "Strict", maxAge: 0 });
}
