import type { StoredLogEntry } from "./daily-file-log-service.ts";
import { describeSchema, type SearchSchema } from "./search-query.ts";

const country = (column: string) => `COALESCE(${column},'ZZ')`;

export const trafficSearchSchema: SearchSchema = {
	id: "traffic",
	label: "Recent traffic",
	fields: [
		{ name: "ip", type: "ip", sql: "ip", description: "Client IP address. Wildcards (10.0.*) and IPv4 CIDR (10.0.0.0/8) work." },
		{ name: "path", type: "text", sql: "path", description: "Request path including the query string." },
		{ name: "method", type: "text", sql: "method", description: "HTTP method.", values: ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] },
		{ name: "status", type: "status", sql: "status", description: "Response status. Accepts 404, >=500, 400..499 and 4xx." },
		{ name: "decision", type: "text", sql: "decision", description: "What BurrowGate did with the request, such as proxied, blocked or rate-limited." },
		{
			name: "user",
			aliases: ["username"],
			type: "text",
			sql: "COALESCE(NULLIF(access_username,''), origin_username)",
			description: "Signed-in user: the access-list user, or else the user reported by the origin.",
		},
		{ name: "access_user", type: "text", sql: "access_username", description: "User signed in through a BurrowGate access list." },
		{ name: "origin_user", type: "text", sql: "origin_username", description: "User reported by the origin with a signed header." },
		{ name: "country", type: "country", sql: country("country_code"), description: "Two-letter country code; ZZ is unknown." },
		{ name: "asn", type: "number", sql: "asn", description: "Autonomous system number." },
		{ name: "asn_org", aliases: ["org"], type: "text", sql: "asn_org", description: "Network operator of the ASN." },
		{ name: "bot", type: "text", sql: "COALESCE(bot_name, bot_id)", description: "Identified bot name." },
		{ name: "bot_category", type: "text", sql: "bot_category", description: "Bot category, such as search or ai." },
		{ name: "referer", aliases: ["referrer"], type: "text", sql: "referer_host", description: "Referring host." },
		{ name: "cache", type: "text", sql: "cache_status", description: "Static cache result.", values: ["hit", "miss", "bypass"] },
		{ name: "protection", type: "text", sql: "protection_status", description: "Managed protection outcome.", values: ["clean", "monitored", "blocked"] },
		{ name: "rule", type: "text", sql: "protection_rule_id", description: "Managed protection rule that matched." },
		{ name: "latency", type: "number", sql: "latency_ms", description: "Response time in milliseconds." },
		{ name: "session", type: "text", sql: "session_id", description: "Browser session ID." },
		{ name: "id", type: "text", sql: "id", description: "Request ID." },
		{ name: "origin", type: "text", sql: "origin_id", description: "Origin ID that served the request." },
		{ name: "site", type: "text", sql: "site_id", description: "Site ID." },
	],
	textSql: ["ip", "path", "protection_rule_id", "access_username", "origin_username", "referer_host", "bot_name"],
	exactSql: ["id", "session_id"],
};

export const sessionSearchSchema: SearchSchema = {
	id: "sessions",
	label: "Sessions",
	fields: [
		{ name: "ip", type: "ip", sql: "s.last_ip", description: "Most recent client IP." },
		{ name: "initial_ip", type: "ip", sql: "s.initial_ip", description: "IP the session started from." },
		{ name: "user", aliases: ["username"], type: "text", sql: "au.username", description: "Access-list user signed in on the session." },
		{ name: "country", type: "country", sql: country("s.country_code"), description: "Two-letter country code; ZZ is unknown." },
		{ name: "asn", type: "number", sql: "s.asn", description: "Autonomous system number." },
		{ name: "asn_org", aliases: ["org"], type: "text", sql: "s.asn_org", description: "Network operator of the ASN." },
		{ name: "requests", type: "number", sql: "s.request_count", description: "Requests made with the session." },
		{ name: "id", type: "text", sql: "s.id", description: "Session ID." },
		{ name: "ua_hash", type: "text", sql: "s.user_agent_hash", description: "Hash of the browser's User-Agent." },
		{ name: "site", type: "text", sql: "s.site_id", description: "Site ID." },
	],
	textSql: ["s.initial_ip", "s.last_ip", "au.username"],
	exactSql: ["s.id", "s.user_agent_hash"],
};

export const ipRuleSearchSchema: SearchSchema = {
	id: "ip-rules",
	label: "IP rules",
	fields: [
		{ name: "cidr", aliases: ["ip"], type: "ip", sql: "network_cidr", description: "IP address or network of the rule." },
		{ name: "action", type: "text", sql: "action", description: "Rule action.", values: ["block", "pass", "allow", "challenge"] },
		{ name: "reason", type: "text", sql: "reason", description: "Reason recorded with the rule." },
		{ name: "rule", type: "text", sql: "rule_id", description: "Protection rule that created an automatic ban." },
	],
	textSql: ["network_cidr", "reason", "rule_id"],
};

export const streamRuleSearchSchema: SearchSchema = {
	id: "stream-rules",
	label: "Stream IP rules",
	fields: [
		{ name: "cidr", aliases: ["ip"], type: "ip", sql: "network_cidr", description: "IP address or network of the rule." },
		{ name: "action", type: "text", sql: "action", description: "Rule action.", values: ["block", "allow"] },
		{ name: "reason", type: "text", sql: "reason", description: "Reason recorded with the rule." },
	],
	textSql: ["network_cidr", "reason"],
};

export const bandwidthSearchSchema: SearchSchema = {
	id: "bandwidth",
	label: "Bandwidth by IP",
	fields: [
		{ name: "ip", type: "ip", sql: "ip", description: "Client IP address." },
		{ name: "country", type: "country", sql: country("country_code"), description: "Two-letter country code; ZZ is unknown." },
		{ name: "protocol", type: "text", sql: "protocol", description: "Transport protocol.", values: ["http", "websocket"] },
		{ name: "site", type: "text", sql: "site_id", description: "Site ID." },
	],
	textSql: ["ip"],
};

export const streamBandwidthSearchSchema: SearchSchema = {
	id: "stream-bandwidth",
	label: "Stream bandwidth",
	fields: [
		{ name: "ip", type: "ip", sql: "ip", description: "Client IP address." },
		{ name: "country", type: "country", sql: country("country_code"), description: "Two-letter country code; ZZ is unknown." },
		{ name: "protocol", type: "text", sql: "protocol", description: "Transport protocol.", values: ["tcp", "udp"] },
		{ name: "port", type: "number", sql: "incoming_port", description: "Listening port." },
		{ name: "stream", type: "text", sql: "stream_id", description: "Stream ID." },
	],
	textSql: ["ip"],
};

export const streamEventSearchSchema: SearchSchema = {
	id: "stream-events",
	label: "Stream events",
	fields: [
		{ name: "ip", type: "ip", sql: "client_ip", description: "Client IP address." },
		{ name: "type", type: "text", sql: "event_type", description: "Event type, such as connect, disconnect, blocked or error." },
		{ name: "protocol", type: "text", sql: "protocol", description: "Transport protocol.", values: ["tcp", "udp"] },
		{ name: "user", aliases: ["username"], type: "text", sql: "username", description: "Player or user name reported by the stream protocol." },
		{ name: "reason", type: "text", sql: "reason", description: "Why the connection was blocked or closed." },
		{ name: "error", type: "text", sql: "error", description: "Error message." },
		{ name: "country", type: "country", sql: country("country_code"), description: "Two-letter country code; ZZ is unknown." },
		{ name: "asn", type: "number", sql: "asn", description: "Autonomous system number." },
		{ name: "asn_org", aliases: ["org"], type: "text", sql: "asn_org", description: "Network operator of the ASN." },
		{ name: "port", type: "number", sql: "incoming_port", description: "Listening port." },
		{ name: "duration", type: "number", sql: "duration_ms", description: "Connection duration in milliseconds." },
		{ name: "rule", type: "text", sql: "protection_rule_id", description: "Stream protection rule that matched." },
		{ name: "connection", type: "text", sql: "connection_id", description: "Connection ID." },
		{ name: "stream", type: "text", sql: "stream_id", description: "Stream ID." },
	],
	textSql: ["client_ip", "reason", "error", "username"],
	exactSql: ["connection_id", "protection_rule_id"],
};

export const auditLogSearchSchema: SearchSchema = {
	id: "audit-log",
	label: "Audit log",
	fields: [
		{ name: "actor", aliases: ["user", "username"], type: "text", sql: "actor_username", description: "Administrator who made the change." },
		{ name: "action", type: "text", sql: "action", description: "Action identifier, such as site.update." },
		{ name: "summary", type: "text", sql: "summary", description: "Human-readable summary." },
		{ name: "resource_type", type: "text", sql: "resource_type", description: "Kind of resource changed." },
		{ name: "resource", type: "text", sql: "resource_id", description: "ID of the resource changed." },
		{ name: "ip", type: "ip", sql: "ip", description: "IP address the change came from." },
	],
	textSql: ["actor_username", "summary", "action"],
};

export const notificationSearchSchema: SearchSchema = {
	id: "notifications",
	label: "Notifications",
	fields: [
		{ name: "type", type: "text", sql: "ne.type", description: "Notification type." },
		{ name: "severity", type: "text", sql: "ne.severity", description: "Severity.", values: ["info", "warning", "critical"] },
		{ name: "status", type: "text", sql: "no.status", description: "Delivery status." },
		{ name: "summary", type: "text", sql: "ne.summary", description: "Notification text." },
		{ name: "error", type: "text", sql: "no.last_error", description: "Last delivery error." },
	],
	textSql: ["ne.summary", "ne.type"],
};

function valueAtPath(root: unknown, path: string): unknown {
	let value = root;
	for (const key of path.split(".")) {
		if (value === null || typeof value !== "object") return undefined;
		const record = value as Record<string, unknown>;
		const match = Object.keys(record).find((candidate) => candidate.toLowerCase() === key.toLowerCase());
		value = match === undefined ? undefined : record[match];
	}
	return value;
}

function metadataValue(entry: StoredLogEntry, path: string): unknown {
	return valueAtPath(entry.metadata, path) ?? valueAtPath(valueAtPath(entry.metadata, "metadata"), path);
}

export const logSearchSchema: SearchSchema = {
	id: "logs",
	label: "Logs",
	fields: [
		{
			name: "level",
			type: "text",
			get: (entry: StoredLogEntry) => entry.level,
			description: "Log level.",
			values: ["error", "warn", "audit", "info", "http", "debug"],
		},
		{ name: "message", aliases: ["msg"], type: "text", get: (entry: StoredLogEntry) => entry.message, description: "Log message." },
	],
	text: (entry: StoredLogEntry) => JSON.stringify(entry),
	dynamic: (entry: StoredLogEntry, path: string) => metadataValue(entry, path.startsWith("metadata.") ? path.slice("metadata.".length) : path),
};

export const searchSchemas = [
	trafficSearchSchema,
	sessionSearchSchema,
	ipRuleSearchSchema,
	bandwidthSearchSchema,
	auditLogSearchSchema,
	notificationSearchSchema,
	streamEventSearchSchema,
	streamRuleSearchSchema,
	streamBandwidthSearchSchema,
	logSearchSchema,
];

export function searchSchemaCatalog() {
	return searchSchemas.map(describeSchema);
}
