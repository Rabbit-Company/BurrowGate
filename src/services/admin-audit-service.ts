import { repository, type AuditLogQuery, type PageResult } from "../db/repository.ts";
import type { AdminAuditLogRecord } from "../types.ts";
import { randomId } from "../utils/crypto.ts";
import type { AuthenticatedAdmin } from "./admin-permission-service.ts";

export interface AdminAuditInput {
	actor: AuthenticatedAdmin;
	action: string;
	resourceType?: string | null;
	resourceId?: string | null;
	summary: string;
	detail?: unknown;
	ip: string;
}

export async function recordAdminAudit(input: AdminAuditInput): Promise<void> {
	await repository.insertAdminAuditEntry({
		id: randomId("audit"),
		actor_user_id: input.actor.id,
		actor_username: input.actor.username,
		action: input.action,
		resource_type: input.resourceType ?? null,
		resource_id: input.resourceId ?? null,
		summary: input.summary,
		detail_json: input.detail !== undefined ? JSON.stringify(input.detail) : null,
		ip: input.ip,
		created_at: Date.now(),
	});
}

export async function pagedAdminAuditLog(query: AuditLogQuery): Promise<PageResult<AdminAuditLogRecord>> {
	return repository.pagedAdminAuditLog(query);
}

export async function purgeAdminAuditLog(actor: AuthenticatedAdmin, ip: string, options: { olderThanDays?: number; all?: boolean }): Promise<number> {
	let purged: number;
	let summary: string;
	if (options.all) {
		purged = await repository.purgeAllAdminAuditLog();
		summary = `Purged all ${purged} audit log entr${purged === 1 ? "y" : "ies"}`;
	} else {
		const days = Number(options.olderThanDays);
		if (!Number.isFinite(days) || days < 0) throw new Error("olderThanDays must be a non-negative number");
		const cutoff = Date.now() - days * 86_400_000;
		purged = await repository.purgeAdminAuditLogOlderThan(cutoff);
		summary = `Purged ${purged} audit log entr${purged === 1 ? "y" : "ies"} older than ${days} day${days === 1 ? "" : "s"}`;
	}
	await recordAdminAudit({ actor, action: "audit_log.purge", summary, ip });
	return purged;
}
