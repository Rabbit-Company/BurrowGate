import { config } from "../config.ts";
import { APP_VERSION } from "../ui/layout.ts";
import { jsonResponse } from "../utils/http.ts";

const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

function isVersionFenceExempt(pathname: string): boolean {
	return (
		pathname === "/_burrowgate/api/admin/logout" ||
		pathname.startsWith("/_burrowgate/api/admin/logs") ||
		pathname === "/_burrowgate/api/admin/ha/consume-recovery-code" ||
		pathname === "/_burrowgate/api/admin/ha/resolve-admin-session" ||
		pathname === "/_burrowgate/api/admin/ha/identity" ||
		pathname === "/_burrowgate/api/admin/ha/join" ||
		pathname === "/_burrowgate/api/admin/ha/leave" ||
		pathname.startsWith("/_burrowgate/api/admin/ha/nodes/")
	);
}

export function haVersionWriteGuard(request: Request): Response | null {
	if (!MUTATING_METHODS.has(request.method) || !config.ha.enabled || config.ha.role !== "primary") return null;
	const pathname = new URL(request.url).pathname;
	if (!pathname.startsWith("/_burrowgate/api/admin/") || isVersionFenceExempt(pathname)) return null;
	if (config.ha.versionMismatchNodes.length === 0) return null;
	return jsonResponse(
		{
			error: "Cluster configuration is read-only until every registered BurrowGate node runs the same version as the primary",
			code: "cluster_version_mismatch",
			primaryVersion: APP_VERSION,
			mismatchedNodes: config.ha.versionMismatchNodes,
		},
		409,
	);
}
