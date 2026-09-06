import { errorResponse, jsonBody, jsonResponse, ref, type PathItemObject } from "../types.ts";

const durability = {
	durabilityConfirmed: { type: "boolean" as const, description: "Whether a majority of HA mesh nodes have confirmed durability of this write." },
};

export const integrationPaths: Record<string, PathItemObject> = {
	"/firewall-sync/whoami": {
		get: {
			summary: "Get the caller's own apparent client IP",
			description: 'Administrator only. Used by the admin UI to help pick a sensible never-ban whitelist entry (e.g. "whitelist my own IP").',
			tags: ["Firewall sync"],
			operationId: "firewallSyncWhoami",
			responses: {
				"200": jsonResponse("", { type: "object", required: ["ip"], properties: { ip: { type: ["string", "null"] } } }),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required."),
			},
		},
	},
	"/firewall-sync/providers/unifi/sites": {
		post: {
			summary: "Probe a UniFi controller and list its sites",
			description:
				'Administrator only. Used by the admin UI\'s "Load sites" button; works against unsaved form values. If apiKey is omitted, falls back to the API key already stored on providerId (useful when editing a provider without re-entering its key).',
			tags: ["Firewall sync"],
			operationId: "probeUnifiSites",
			requestBody: jsonBody({
				type: "object",
				properties: {
					controllerUrl: { type: "string" },
					apiBasePath: { type: "string", default: "/proxy/network" },
					verifyTls: { type: "boolean", default: true },
					apiKey: { type: "string", description: "Plaintext API key. Omitted to fall back to providerId's stored key." },
					providerId: { type: "string", description: "An existing provider's ID, to fall back to its stored API key." },
				},
			}),
			responses: {
				"200": jsonResponse("", { type: "object", required: ["items"], properties: { items: { type: "array", items: ref("FirewallSyncUnifiSiteOption") } } }),
				"400": errorResponse("Unable to connect or list sites (bad URL, bad/missing API key, or the console returned its web UI instead of the API)."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
			},
		},
	},
	"/firewall-sync/providers/ovh/ips": {
		post: {
			summary: "Probe an OVH account and list its IP blocks",
			description:
				"Administrator only. Used by the admin UI's \"Load IPs\" button; works against unsaved form values, falling back to providerId's stored application secret / consumer key for whichever of the two is left blank.",
			tags: ["Firewall sync"],
			operationId: "probeOvhIps",
			requestBody: jsonBody({
				type: "object",
				properties: {
					endpoint: { type: "string", default: "https://eu.api.ovh.com" },
					applicationKey: { type: "string" },
					applicationSecret: { type: "string", description: "Plaintext. Omitted to fall back to providerId's stored value." },
					consumerKey: { type: "string", description: "Plaintext. Omitted to fall back to providerId's stored value." },
					providerId: { type: "string" },
				},
			}),
			responses: {
				"200": jsonResponse("", { type: "object", required: ["items"], properties: { items: { type: "array", items: ref("FirewallSyncOvhIpOption") } } }),
				"400": errorResponse("Unable to connect or list IPs (missing credentials, or the OVH API rejected the request)."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
			},
		},
	},
	"/firewall-sync/providers/ovh/credential": {
		post: {
			summary: "Request a new OVH consumer key",
			description:
				"Administrator only. Starts OVH's consumer-key acquisition flow, scoped to just the /ip/* resource tree. The admin must open validationUrl and approve access before the returned consumerKey becomes usable.",
			tags: ["Firewall sync"],
			operationId: "requestOvhCredential",
			requestBody: jsonBody({
				type: "object",
				properties: { endpoint: { type: "string", default: "https://eu.api.ovh.com" }, applicationKey: { type: "string" } },
			}),
			responses: {
				"200": jsonResponse("", ref("FirewallSyncOvhCredentialRequestResult")),
				"400": errorResponse("Application key missing, or the OVH API rejected the request."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
			},
		},
	},
	"/firewall-sync/providers/aws-nacl/network-acls": {
		post: {
			summary: "Probe an AWS account and list its Network ACLs",
			description:
				"Administrator only. Used by the admin UI's \"Load Network ACLs\" button; works against unsaved form values, falling back to providerId's stored secret access key / session token for whichever is left blank.",
			tags: ["Firewall sync"],
			operationId: "probeAwsNacls",
			requestBody: jsonBody({
				type: "object",
				properties: {
					region: { type: "string", default: "us-east-1" },
					accessKeyId: { type: "string" },
					secretAccessKey: { type: "string", description: "Plaintext. Omitted to fall back to providerId's stored value." },
					sessionToken: { type: "string", description: "Plaintext STS session token. Omitted to fall back to providerId's stored value (if any)." },
					providerId: { type: "string" },
				},
			}),
			responses: {
				"200": jsonResponse("", { type: "object", required: ["items"], properties: { items: { type: "array", items: ref("FirewallSyncAwsNaclOption") } } }),
				"400": errorResponse("Unable to connect or list Network ACLs (missing credentials, or the EC2 API rejected the request)."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
			},
		},
	},
	"/firewall-sync/preview": {
		get: {
			summary: "Preview the aggregated, filtered ban list",
			description:
				"Administrator only. Shows what would currently be pushed to every enabled provider: the deduplicated, whitelist- and private-range-filtered set of active bans (sample capped to the first 20), plus how many were excluded and why.",
			tags: ["Firewall sync"],
			operationId: "previewFirewallSyncBans",
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["totalCount", "sample", "totalActiveCount", "excludedPrivateCount", "excludedWhitelistedCount"],
					properties: {
						totalCount: { type: "integer", description: "Total number of CIDRs that would be pushed (before any per-provider maxEntries cap)." },
						sample: { type: "array", maxItems: 20, items: { type: "string" }, description: "First 20 bannable CIDRs, for display." },
						totalActiveCount: { type: "integer", description: "Total active bans before deduplication or filtering." },
						excludedPrivateCount: {
							type: "integer",
							description: "Excluded for being a private/loopback range - always excluded, independent of the whitelist.",
						},
						excludedWhitelistedCount: { type: "integer", description: "Excluded for matching an admin-managed never-ban whitelist entry." },
					},
				}),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required."),
			},
		},
	},
	"/firewall-sync/providers": {
		get: {
			summary: "List firewall sync providers",
			description: "Administrator only.",
			tags: ["Firewall sync"],
			operationId: "listFirewallSyncProviders",
			responses: {
				"200": jsonResponse("", { type: "object", required: ["items"], properties: { items: { type: "array", items: ref("FirewallSyncProvider") } } }),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required."),
			},
		},
		post: {
			summary: "Create a firewall sync provider",
			description: "Administrator only.",
			tags: ["Firewall sync"],
			operationId: "createFirewallSyncProvider",
			requestBody: jsonBody(ref("FirewallSyncProviderInput")),
			responses: {
				"201": jsonResponse("", { allOf: [ref("FirewallSyncProvider")], type: "object", required: ["durabilityConfirmed"], properties: durability }),
				"400": errorResponse(
					"Invalid input (unsupported type, missing name, or a type-specific required field such as controllerUrl/applicationKey/accessKeyId is missing).",
				),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
			},
		},
	},
	"/firewall-sync/providers/{id}": {
		put: {
			summary: "Update a firewall sync provider",
			description: "Administrator only. type is immutable and not accepted here.",
			tags: ["Firewall sync"],
			operationId: "updateFirewallSyncProvider",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			requestBody: jsonBody(ref("FirewallSyncProviderInput")),
			responses: {
				"200": jsonResponse("", { allOf: [ref("FirewallSyncProvider")], type: "object", required: ["durabilityConfirmed"], properties: durability }),
				"400": errorResponse(
					"Invalid input, no provider with this ID, or enabled was set to true without at least one whitelist CIDR and without acknowledgedNoWhitelist.",
				),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
			},
		},
		delete: {
			summary: "Delete a firewall sync provider",
			description:
				"Administrator only. Attempts a best-effort remote teardown first (drops the nftables table, deletes the UniFi traffic matching lists, etc.) - a teardown failure (e.g. a UniFi list still referenced by a Firewall Policy) is reported back via teardownError but does NOT block deleting the local row.",
			tags: ["Firewall sync"],
			operationId: "deleteFirewallSyncProvider",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["ok", "teardownError", "durabilityConfirmed"],
					properties: { ok: { type: "boolean", const: true }, teardownError: { type: ["string", "null"] }, ...durability },
				}),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
			},
		},
	},
	"/firewall-sync/providers/{id}/test": {
		post: {
			summary: "Test a firewall sync provider's connection",
			description:
				"Administrator only. Exercises the provider's read path (and, for UniFi, checks whether its managed list already exists) without modifying anything.",
			tags: ["Firewall sync"],
			operationId: "testFirewallSyncProvider",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			responses: {
				"200": jsonResponse(
					"`ok: false` with a message is used for a reachable-but-rejected test; an unreachable/thrown failure surfaces as 400 instead.",
					ref("ConnectionTestResult"),
				),
				"400": errorResponse("No provider with this ID, or the connection attempt itself threw (network error, auth failure, etc.)."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
			},
		},
	},
	"/firewall-sync/providers/{id}/sync-now": {
		post: {
			summary: "Push this provider's ban list immediately",
			description: "Administrator only. Bypasses the tick's hash-based skip (which exists only to cut automatic polling load), so this always pushes for real.",
			tags: ["Firewall sync"],
			operationId: "syncFirewallSyncProviderNow",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			responses: {
				"200": jsonResponse("", { type: "object", required: ["ok"], properties: { ok: { type: "boolean", const: true } } }),
				"400": errorResponse("No provider with this ID, or the push failed."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
			},
		},
	},
	"/firewall-sync/whitelist": {
		get: {
			summary: "List never-ban whitelist CIDRs",
			description: "Administrator only. Private/loopback ranges are always excluded from bans too, independent of this admin-managed list.",
			tags: ["Firewall sync"],
			operationId: "listFirewallSyncWhitelistCidrs",
			responses: {
				"200": jsonResponse("", { type: "object", required: ["items"], properties: { items: { type: "array", items: ref("FirewallSyncWhitelistCidr") } } }),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required."),
			},
		},
		post: {
			summary: "Add a never-ban whitelist CIDR",
			description: "Administrator only.",
			tags: ["Firewall sync"],
			operationId: "addFirewallSyncWhitelistCidr",
			requestBody: jsonBody({
				type: "object",
				required: ["networkCidr"],
				properties: { networkCidr: { type: "string", description: "A single IP or CIDR range." }, note: { type: "string" } },
			}),
			responses: {
				"201": jsonResponse("", { allOf: [ref("FirewallSyncWhitelistCidr")], type: "object", required: ["durabilityConfirmed"], properties: durability }),
				"400": errorResponse("networkCidr is missing or not a valid IP address / CIDR range."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
			},
		},
	},
	"/firewall-sync/whitelist/{id}": {
		delete: {
			summary: "Remove a never-ban whitelist CIDR",
			description: "Administrator only.",
			tags: ["Firewall sync"],
			operationId: "deleteFirewallSyncWhitelistCidr",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["ok", "durabilityConfirmed"],
					properties: { ok: { type: "boolean", const: true }, ...durability },
				}),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
			},
		},
	},

	"/dns-providers": {
		get: {
			summary: "List DNS providers",
			description: "Administrator only.",
			tags: ["DNS providers"],
			operationId: "listDnsProviders",
			responses: {
				"200": jsonResponse("", { type: "object", required: ["items"], properties: { items: { type: "array", items: ref("DnsProvider") } } }),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required."),
			},
		},
		post: {
			summary: "Create a DNS provider",
			description: "Administrator only. Used for DNS-01 certificate issuance. Only type `rfc2136` is currently supported.",
			tags: ["DNS providers"],
			operationId: "createDnsProvider",
			requestBody: jsonBody(ref("DnsProviderInput")),
			responses: {
				"201": jsonResponse("", ref("DnsProvider")),
				"400": errorResponse("Invalid input (unsupported type, missing name, or a missing required rfc2136 field: server, zone, tsigKeyName, or tsigSecret)."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
			},
		},
	},
	"/dns-providers/{id}": {
		put: {
			summary: "Update a DNS provider",
			description: "Administrator only. type is immutable and not accepted here.",
			tags: ["DNS providers"],
			operationId: "updateDnsProvider",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			requestBody: jsonBody(ref("DnsProviderInput")),
			responses: {
				"200": jsonResponse("", ref("DnsProvider")),
				"400": errorResponse("Invalid input, or no DNS provider with this ID."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
			},
		},
		delete: {
			summary: "Delete a DNS provider",
			description: "Administrator only. Refused while any site still uses this provider for DNS-01 issuance - switch those sites off DNS-01 first.",
			tags: ["DNS providers"],
			operationId: "deleteDnsProvider",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			responses: {
				"200": jsonResponse("", { type: "object", required: ["ok"], properties: { ok: { type: "boolean", const: true } } }),
				"400": errorResponse("No DNS provider with this ID, or one or more sites still depend on it for DNS-01 issuance (named in the error message)."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
			},
		},
	},
	"/dns-providers/{id}/test": {
		post: {
			summary: "Test a DNS provider's connection",
			description:
				"Administrator only. Creates then immediately deletes a probe TXT record (_burrowgate-test.<zone>) via a real signed RFC 2136 update, to verify the server accepts it end-to-end.",
			tags: ["DNS providers"],
			operationId: "testDnsProvider",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			responses: {
				"200": jsonResponse(
					"`ok: false` with a message is used for a reachable-but-rejected update; an unreachable/thrown failure surfaces as 400 instead.",
					ref("ConnectionTestResult"),
				),
				"400": errorResponse("No DNS provider with this ID, or the connection attempt itself threw (network error, TSIG failure, etc.)."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
			},
		},
	},
};
