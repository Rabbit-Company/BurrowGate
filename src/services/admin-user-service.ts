import { join } from "node:path";
import { config } from "../config.ts";
import { repository } from "../db/repository.ts";
import { Logger } from "../logger.ts";
import type { AdminAccessLevel, AdminRole, AdminUserRecord } from "../types.ts";
import { randomId, randomToken } from "../utils/crypto.ts";
import { readNonEmpty, writePrivateFile } from "./runtime-bootstrap-service.ts";
import { decryptSecret } from "./secret-encryption-service.ts";
import { generateRecoveryCodes, verifyCode as verifyTotpCode } from "./totp-service.ts";

export interface AdminUserInput {
	username?: unknown;
	password?: unknown;
	role?: unknown;
	enabled?: unknown;
	sitePermissions?: unknown;
	streamPermissions?: unknown;
}

export interface AdminUserView {
	id: string;
	username: string;
	role: AdminRole;
	enabled: boolean;
	totpEnrolled: boolean;
	createdAt: number;
	updatedAt: number;
	sitePermissions: Array<{ siteId: string; level: Exclude<AdminAccessLevel, "none"> }>;
	streamPermissions: Array<{ streamId: string; level: Exclude<AdminAccessLevel, "none"> }>;
}

function normalizeAdminUsername(value: unknown): string {
	const username = String(value ?? "")
		.trim()
		.toLowerCase();
	if (!username) throw new Error("Username is required");
	if (username.length > 255) throw new Error("Username must be at most 255 characters");
	if (!/^[a-z0-9][a-z0-9._@+-]*$/u.test(username)) {
		throw new Error("Username may contain lowercase letters, numbers, dots, underscores, @, +, and hyphens");
	}
	return username;
}

function passwordValue(value: unknown, required: boolean): string | null {
	if (value === undefined || value === null || value === "") {
		if (required) throw new Error("Password is required");
		return null;
	}
	const password = String(value);
	if (password.length < 8) throw new Error("Password must be at least 8 characters");
	if (password.length > 1024) throw new Error("Password must be at most 1024 characters");
	return password;
}

function roleValue(value: unknown, fallback: AdminRole): AdminRole {
	if (value === undefined) return fallback;
	if (value === "administrator" || value === "member") return value;
	throw new Error("Role must be 'administrator' or 'member'");
}

function booleanValue(value: unknown, fallback: boolean): boolean {
	if (value === undefined) return fallback;
	if (typeof value === "boolean") return value;
	if (value === 1 || value === "1" || value === "true") return true;
	if (value === 0 || value === "0" || value === "false") return false;
	throw new Error("Boolean value expected");
}

function permissionListValue(value: unknown, key: "siteId" | "streamId"): Array<{ id: string; level: Exclude<AdminAccessLevel, "none"> }> {
	if (value === undefined) return [];
	if (!Array.isArray(value)) throw new Error("Permissions must be a list");
	const result: Array<{ id: string; level: Exclude<AdminAccessLevel, "none"> }> = [];
	for (const entry of value) {
		if (!entry || typeof entry !== "object") throw new Error("Invalid permission entry");
		const record = entry as Record<string, unknown>;
		const id = String(record[key] ?? "").trim();
		const level = record.level;
		if (!id) throw new Error("Permission entry is missing an id");
		if (level !== "viewer" && level !== "manager") throw new Error("Permission level must be 'viewer' or 'manager'");
		result.push({ id, level });
	}
	return result;
}

async function userView(user: AdminUserRecord): Promise<AdminUserView> {
	const [sitePermissions, streamPermissions] = await Promise.all([
		repository.adminSitePermissionsForUser(user.id),
		repository.adminStreamPermissionsForUser(user.id),
	]);
	return {
		id: user.id,
		username: user.username,
		role: user.role,
		enabled: user.enabled === 1,
		totpEnrolled: user.totp_secret_encrypted !== null,
		createdAt: Number(user.created_at),
		updatedAt: Number(user.updated_at),
		sitePermissions: sitePermissions.map((permission) => ({ siteId: permission.site_id, level: permission.level })),
		streamPermissions: streamPermissions.map((permission) => ({ streamId: permission.stream_id, level: permission.level })),
	};
}

async function applyPermissions(userId: string, input: AdminUserInput): Promise<void> {
	if (input.sitePermissions !== undefined) {
		const sitePermissions = permissionListValue(input.sitePermissions, "siteId");
		for (const permission of sitePermissions) {
			if (!(await repository.siteById(permission.id))) throw new Error("One of the selected sites no longer exists");
		}
		await repository.replaceAdminSitePermissions(
			userId,
			sitePermissions.map((permission) => ({ siteId: permission.id, level: permission.level })),
		);
	}
	if (input.streamPermissions !== undefined) {
		const streamPermissions = permissionListValue(input.streamPermissions, "streamId");
		for (const permission of streamPermissions) {
			if (!(await repository.streamById(permission.id))) throw new Error("One of the selected streams no longer exists");
		}
		await repository.replaceAdminStreamPermissions(
			userId,
			streamPermissions.map((permission) => ({ streamId: permission.id, level: permission.level })),
		);
	}
}

export async function listAdminUsers(): Promise<AdminUserView[]> {
	return Promise.all((await repository.allAdminUsers()).map(userView));
}

export async function adminUserView(userId: string): Promise<AdminUserView> {
	const user = await repository.adminUserById(userId);
	if (!user) throw new Error("Admin user not found");
	return userView(user);
}

export async function createAdminUser(input: AdminUserInput, createdByUserId: string): Promise<AdminUserView> {
	const username = normalizeAdminUsername(input.username);
	if (await repository.adminUserByUsername(username)) throw new Error("This username already exists");
	const password = passwordValue(input.password, true)!;
	const now = Date.now();
	const user: AdminUserRecord = {
		id: randomId("admin"),
		username,
		password_hash: await Bun.password.hash(password, { algorithm: "argon2id" }),
		role: roleValue(input.role, "member"),
		totp_secret_encrypted: null,
		totp_enrolled_at: null,
		must_enroll_totp: 1,
		enabled: booleanValue(input.enabled, true) ? 1 : 0,
		created_at: now,
		updated_at: now,
		created_by_user_id: createdByUserId,
	};
	await repository.insertAdminUser(user);
	await applyPermissions(user.id, input);
	return userView(user);
}

export async function updateAdminUser(userId: string, input: AdminUserInput): Promise<AdminUserView> {
	const existing = await repository.adminUserById(userId);
	if (!existing) throw new Error("Admin user not found");
	const username = input.username === undefined ? existing.username : normalizeAdminUsername(input.username);
	const conflict = await repository.adminUserByUsername(username);
	if (conflict && conflict.id !== userId) throw new Error("This username already exists");
	const role = roleValue(input.role, existing.role);
	const enabled = booleanValue(input.enabled, existing.enabled === 1);
	const losesAdministratorStatus = existing.role === "administrator" && existing.enabled === 1 && (role !== "administrator" || !enabled);
	if (losesAdministratorStatus && (await repository.countEnabledAdministrators(userId)) === 0) {
		throw new Error("At least one enabled Administrator account must remain");
	}
	const password = passwordValue(input.password, false);
	const updated: AdminUserRecord = {
		...existing,
		username,
		password_hash: password ? await Bun.password.hash(password, { algorithm: "argon2id" }) : existing.password_hash,
		role,
		enabled: enabled ? 1 : 0,
		updated_at: Date.now(),
	};
	await repository.updateAdminUser(updated);
	await applyPermissions(userId, input);
	if (password || role !== existing.role || !enabled) await repository.revokeAdminSessionsForUser(userId);
	return userView(updated);
}

export async function deleteAdminUser(userId: string): Promise<void> {
	const existing = await repository.adminUserById(userId);
	if (!existing) throw new Error("Admin user not found");
	if (existing.role === "administrator" && existing.enabled === 1 && (await repository.countEnabledAdministrators(userId)) === 0) {
		throw new Error("At least one enabled Administrator account must remain");
	}
	await repository.deleteAdminUserCascade(userId);
}

export async function resetAdminUserPassword(userId: string, password: unknown): Promise<void> {
	const existing = await repository.adminUserById(userId);
	if (!existing) throw new Error("Admin user not found");
	const value = passwordValue(password, true)!;
	await repository.updateAdminUser({
		...existing,
		password_hash: await Bun.password.hash(value, { algorithm: "argon2id" }),
		updated_at: Date.now(),
	});
	await repository.revokeAdminSessionsForUser(userId);
}

export async function resetAdminUserTotp(userId: string): Promise<void> {
	const existing = await repository.adminUserById(userId);
	if (!existing) throw new Error("Admin user not found");
	await repository.updateAdminUser({ ...existing, totp_secret_encrypted: null, totp_enrolled_at: null, must_enroll_totp: 1, updated_at: Date.now() });
	await repository.replaceAdminRecoveryCodes(userId, []);
	await repository.revokeAdminSessionsForUser(userId);
}

export async function changeOwnPassword(userId: string, currentPassword: unknown, newPassword: unknown): Promise<void> {
	const existing = await repository.adminUserById(userId);
	if (!existing) throw new Error("Admin user not found");
	if (!(await Bun.password.verify(String(currentPassword ?? ""), existing.password_hash))) {
		throw new Error("Current password is incorrect");
	}
	const value = passwordValue(newPassword, true)!;
	await repository.updateAdminUser({ ...existing, password_hash: await Bun.password.hash(value, { algorithm: "argon2id" }), updated_at: Date.now() });
	await repository.revokeAdminSessionsForUser(userId);
}

export async function regenerateOwnRecoveryCodes(userId: string, totpCode: unknown): Promise<string[]> {
	const existing = await repository.adminUserById(userId);
	if (!existing) throw new Error("Admin user not found");
	if (!existing.totp_secret_encrypted) throw new Error("Two-factor authentication is not enrolled");
	const secret = await decryptSecret(existing.totp_secret_encrypted);
	if (!(await verifyTotpCode(secret, String(totpCode ?? "")))) throw new Error("Invalid verification code");
	const codes = await generateRecoveryCodes();
	const now = Date.now();
	await repository.replaceAdminRecoveryCodes(
		userId,
		codes.map((code) => ({ id: randomId("rc"), user_id: userId, code_hash: code.hash, created_at: now, used_at: null })),
	);
	return codes.map((code) => code.plaintext);
}

export async function ensureBootstrapAdministrator(): Promise<void> {
	if (await repository.anyAdminUserExists()) return;
	const username = config.admin.username;
	const path = join(config.dataDirectory, "bootstrap-admin-password.txt");
	let password = await readNonEmpty(path);
	const generated = !password;
	password ??= config.admin.password || randomToken(24);
	if (generated) await writePrivateFile(path, password);
	const now = Date.now();
	await repository.insertAdminUser({
		id: randomId("admin"),
		username,
		password_hash: await Bun.password.hash(password, { algorithm: "argon2id" }),
		role: "administrator",
		totp_secret_encrypted: null,
		totp_enrolled_at: null,
		must_enroll_totp: 1,
		enabled: 1,
		created_at: now,
		updated_at: now,
		created_by_user_id: null,
	});
	Logger.info("[BurrowGate] Bootstrapped first Administrator account:");
	Logger.info(`[BurrowGate]   Username: ${username}`);
	if (generated) Logger.info(`[BurrowGate]   Password: ${password}`);
	Logger.info(`[BurrowGate] Credentials saved to ${path}. Two-factor authentication enrollment is required on first login.`);
}
