import { repository } from "../db/repository.ts";
import type { AdminAccessLevel, AdminRole, AdminSessionRecord } from "../types.ts";
import { jsonResponse } from "../utils/http.ts";

export interface AuthenticatedAdmin {
	id: string;
	username: string;
	role: AdminRole;
}

export async function resolveAdminUser(session: AdminSessionRecord): Promise<AuthenticatedAdmin | null> {
	if (!session.user_id) return null;
	const user = await repository.adminUserById(session.user_id);
	if (!user || user.enabled !== 1) return null;
	return { id: user.id, username: user.username, role: user.role };
}

export function isAdministrator(user: AuthenticatedAdmin): boolean {
	return user.role === "administrator";
}

export async function siteAccessLevel(user: AuthenticatedAdmin, siteId: string): Promise<AdminAccessLevel> {
	if (isAdministrator(user)) return "manager";
	const permission = await repository.adminSitePermission(user.id, siteId);
	return permission?.level ?? "none";
}

export async function streamAccessLevel(user: AuthenticatedAdmin, streamId: string): Promise<AdminAccessLevel> {
	if (isAdministrator(user)) return "manager";
	const permission = await repository.adminStreamPermission(user.id, streamId);
	return permission?.level ?? "none";
}

export function requireLevel(level: AdminAccessLevel, need: "view" | "manage"): Response | null {
	if (level === "none") return jsonResponse({ error: "Forbidden" }, 403);
	if (need === "manage" && level !== "manager") return jsonResponse({ error: "Forbidden" }, 403);
	return null;
}

export function requireAdministrator(user: AuthenticatedAdmin): Response | null {
	return isAdministrator(user) ? null : jsonResponse({ error: "Administrator access required" }, 403);
}
