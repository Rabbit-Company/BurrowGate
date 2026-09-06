import type { JsonSchema } from "./types.ts";

export const integrationSchemas: Record<string, JsonSchema> = {
	FirewallSyncUnifiConfig: {
		type: "object",
		description: "Config shape when type is `unifi`. A UniFi OS console (UDM/Cloud Gateway/UniFi OS Server) managed via its Integration API.",
		required: ["controllerUrl", "apiBasePath", "site", "listName", "apiKeyConfigured", "verifyTls"],
		properties: {
			controllerUrl: { type: "string", description: "Base URL of the UniFi OS console, e.g. https://192.168.1.1." },
			apiBasePath: {
				type: "string",
				default: "/proxy/network",
				description: "Almost always /proxy/network - the path prefix the console's Network application is served behind.",
			},
			site: { type: "string", description: 'UniFi site ID (UUID), selected via POST .../providers/unifi/sites ("Load sites").' },
			listName: {
				type: "string",
				default: "BurrowGate-Banned-IPs",
				description: "Base name for the managed Traffic Matching Lists; an ' (IPv6)' suffix is added for the IPv6 list.",
			},
			apiKeyConfigured: { type: "boolean", description: "Whether a console API key is stored." },
			verifyTls: { type: "boolean", default: true },
		},
	},
	FirewallSyncUnifiConfigInput: {
		type: "object",
		description: "Input config shape when type is `unifi`. controllerUrl is required to create; all fields are optional on update (existing values are kept).",
		properties: {
			controllerUrl: { type: "string" },
			apiBasePath: { type: "string", default: "/proxy/network" },
			site: { type: "string", description: 'UniFi site ID (UUID), selected via POST .../providers/unifi/sites ("Load sites").' },
			listName: { type: "string", default: "BurrowGate-Banned-IPs" },
			apiKey: { type: "string", description: "Plaintext console API key. Omit to keep the currently stored key." },
			verifyTls: { type: "boolean", default: true },
		},
	},
	FirewallSyncNftablesConfig: {
		type: "object",
		description: "Config shape when type is `nftables`. Manages an isolated `inet burrowgate` table/chain/sets on the BurrowGate host itself via the nft CLI.",
		required: ["nftBinaryPath", "useSudo"],
		properties: {
			nftBinaryPath: { type: "string", default: "nft", description: "Path to (or bare name of) the nft binary." },
			useSudo: { type: "boolean", default: false, description: "Prefix nft invocations with `sudo -n`. Alternative: grant nft cap_net_admin directly." },
		},
	},
	FirewallSyncNftablesConfigInput: {
		type: "object",
		description: "Input config shape when type is `nftables`. All fields optional; omitted fields keep their current value (or default on create).",
		properties: {
			nftBinaryPath: { type: "string", default: "nft" },
			useSudo: { type: "boolean", default: false },
		},
	},
	FirewallSyncOvhConfig: {
		type: "object",
		description: "Config shape when type is `ovh`. Manages OVH's per-IP edge firewall (a fixed 20 rule-slot allowance) via the OVH API.",
		required: ["endpoint", "applicationKey", "applicationSecretConfigured", "consumerKeyConfigured", "ipBlock"],
		properties: {
			endpoint: { type: "string", default: "https://eu.api.ovh.com", description: "OVH API region endpoint." },
			applicationKey: { type: "string" },
			applicationSecretConfigured: { type: "boolean" },
			consumerKeyConfigured: {
				type: "boolean",
				description: 'Whether a consumer key is stored - obtain one via POST .../providers/ovh/credential ("Request access").',
			},
			ipBlock: { type: "string", description: 'OVH IP block, e.g. 51.75.1.2/32, selected via POST .../providers/ovh/ips ("Load IPs").' },
		},
	},
	FirewallSyncOvhConfigInput: {
		type: "object",
		description: "Input config shape when type is `ovh`. applicationKey is required to create; all fields are optional on update (existing values are kept).",
		properties: {
			endpoint: { type: "string", default: "https://eu.api.ovh.com" },
			applicationKey: { type: "string" },
			applicationSecret: { type: "string", description: "Plaintext application secret. Omit to keep the currently stored value." },
			consumerKey: { type: "string", description: 'Plaintext consumer key, from the "Request access" flow. Omit to keep the currently stored value.' },
			ipBlock: { type: "string", description: 'OVH IP block, selected via POST .../providers/ovh/ips ("Load IPs").' },
		},
	},
	FirewallSyncAwsNaclConfig: {
		type: "object",
		description: "Config shape when type is `aws-nacl`. Manages a reserved block of 20 rule numbers on an AWS Network ACL via the EC2 API.",
		required: ["region", "accessKeyId", "secretAccessKeyConfigured", "sessionTokenConfigured", "networkAclId", "ruleNumberStart"],
		properties: {
			region: { type: "string", default: "us-east-1" },
			accessKeyId: { type: "string" },
			secretAccessKeyConfigured: { type: "boolean" },
			sessionTokenConfigured: { type: "boolean", description: "Whether an (optional) STS session token is stored, for temporary credentials." },
			networkAclId: { type: "string", description: 'Selected via POST .../providers/aws-nacl/network-acls ("Load Network ACLs").' },
			ruleNumberStart: {
				type: "integer",
				minimum: 1,
				maximum: 32_747,
				default: 1,
				description: "First of the 20 consecutive rule numbers BurrowGate reserves on the ACL (capped so the reserved block never exceeds rule number 32766).",
			},
		},
	},
	FirewallSyncAwsNaclConfigInput: {
		type: "object",
		description: "Input config shape when type is `aws-nacl`. accessKeyId is required to create; all fields are optional on update (existing values are kept).",
		properties: {
			region: { type: "string", default: "us-east-1" },
			accessKeyId: { type: "string" },
			secretAccessKey: { type: "string", description: "Plaintext secret access key. Omit to keep the currently stored value." },
			sessionToken: {
				type: "string",
				description: "Plaintext STS session token, for temporary credentials. Omit to keep the currently stored value (if any).",
			},
			networkAclId: { type: "string", description: 'Selected via POST .../providers/aws-nacl/network-acls ("Load Network ACLs").' },
			ruleNumberStart: { type: "integer", minimum: 1, maximum: 32_747, default: 1 },
		},
	},

	FirewallSyncProvider: {
		type: "object",
		description: "A configured firewall-sync destination that receives the aggregated, filtered set of currently-banned CIDRs.",
		required: [
			"id",
			"name",
			"type",
			"enabled",
			"maxEntries",
			"acknowledgedNoWhitelist",
			"config",
			"lastCheckedAt",
			"lastSyncedAt",
			"lastSyncStatus",
			"lastSyncError",
			"lastAppliedCount",
		],
		properties: {
			id: { type: "string" },
			name: { type: "string" },
			type: { type: "string", enum: ["unifi", "nftables", "ovh", "aws-nacl"] },
			enabled: { type: "boolean" },
			maxEntries: { type: "integer", description: "Ceiling on how many CIDRs are pushed. Clamped to 20 for ovh and aws-nacl (their fixed rule-slot limit)." },
			acknowledgedNoWhitelist: {
				type: "boolean",
				description: "Enabling a provider with an empty never-ban whitelist requires this acknowledgement, to avoid an admin locking themselves out.",
			},
			config: {
				oneOf: [
					{ $ref: "#/components/schemas/FirewallSyncUnifiConfig" },
					{ $ref: "#/components/schemas/FirewallSyncNftablesConfig" },
					{ $ref: "#/components/schemas/FirewallSyncOvhConfig" },
					{ $ref: "#/components/schemas/FirewallSyncAwsNaclConfig" },
				],
				description: "Shape is determined by `type` - see FirewallSync{Unifi,Nftables,Ovh,AwsNacl}Config.",
			},
			lastCheckedAt: { type: ["integer", "null"], description: "Unix milliseconds of the last reconcile attempt (successful or not)." },
			lastSyncedAt: { type: ["integer", "null"], description: "Unix milliseconds of the last successful push." },
			lastSyncStatus: { type: ["string", "null"], enum: ["ok", "error", null] },
			lastSyncError: { type: ["string", "null"] },
			lastAppliedCount: { type: "integer", description: "Number of CIDRs applied on the last successful push." },
		},
	},
	FirewallSyncProviderInput: {
		type: "object",
		description: "name and type are required on create; all fields are optional on update (existing values are kept). config's shape depends on type.",
		properties: {
			name: { type: "string" },
			type: { type: "string", enum: ["unifi", "nftables", "ovh", "aws-nacl"], description: "Immutable after creation - not accepted on update." },
			enabled: { type: "boolean", default: false, description: "Turning this on requires at least one whitelist CIDR, unless acknowledgedNoWhitelist is set." },
			maxEntries: {
				type: "integer",
				description: "Defaults to the type's own default (20 for ovh/aws-nacl, otherwise instance-configured); always clamped to 20 for ovh and aws-nacl.",
			},
			acknowledgedNoWhitelist: { type: "boolean", default: false },
			config: {
				oneOf: [
					{ $ref: "#/components/schemas/FirewallSyncUnifiConfigInput" },
					{ $ref: "#/components/schemas/FirewallSyncNftablesConfigInput" },
					{ $ref: "#/components/schemas/FirewallSyncOvhConfigInput" },
					{ $ref: "#/components/schemas/FirewallSyncAwsNaclConfigInput" },
				],
				description: "Shape must match `type` - see FirewallSync{Unifi,Nftables,Ovh,AwsNacl}ConfigInput.",
			},
		},
	},
	FirewallSyncWhitelistCidr: {
		type: "object",
		description:
			"A never-ban CIDR: excluded from every provider's push regardless of ban state. Private/loopback ranges are always excluded too, independent of this list.",
		required: ["id", "networkCidr", "note", "createdAt"],
		properties: {
			id: { type: "string" },
			networkCidr: { type: "string", description: "A single IP or CIDR range." },
			note: { type: ["string", "null"] },
			createdAt: { type: "integer" },
		},
	},

	FirewallSyncUnifiSiteOption: {
		type: "object",
		description: "src/services/firewall-sync/unifi-adapter.ts UnifiSiteOption - one selectable entry from POST .../providers/unifi/sites.",
		required: ["id", "name"],
		properties: { id: { type: "string" }, name: { type: "string" } },
	},
	FirewallSyncOvhIpOption: {
		type: "object",
		description: "src/services/firewall-sync/ovh-adapter.ts OvhIpOption - one selectable entry from POST .../providers/ovh/ips.",
		required: ["block", "serviceName"],
		properties: { block: { type: "string", description: "e.g. 51.75.1.2/32." }, serviceName: { type: ["string", "null"] } },
	},
	FirewallSyncOvhCredentialRequestResult: {
		type: "object",
		description:
			"src/services/firewall-sync/ovh-adapter.ts OvhCredentialRequestResult, from POST .../providers/ovh/credential. The admin must open validationUrl and approve access before the consumerKey becomes usable.",
		required: ["consumerKey", "validationUrl", "state"],
		properties: {
			consumerKey: { type: "string" },
			validationUrl: { type: "string" },
			state: { type: "string" },
		},
	},
	FirewallSyncAwsNaclOption: {
		type: "object",
		description: "src/services/firewall-sync/aws-nacl-adapter.ts AwsNaclOption - one selectable entry from POST .../providers/aws-nacl/network-acls.",
		required: ["networkAclId", "vpcId", "isDefault"],
		properties: {
			networkAclId: { type: "string" },
			vpcId: { type: "string" },
			isDefault: { type: "boolean", description: "Whether this is the VPC's default Network ACL." },
		},
	},

	ConnectionTestResult: {
		type: "object",
		required: ["ok", "message"],
		properties: { ok: { type: "boolean" }, message: { type: "string" } },
	},

	DnsRfc2136Config: {
		type: "object",
		description:
			"Config shape when type is `rfc2136` (the only currently supported DNS provider type). Drives DNS-01 challenge TXT records via RFC 2136 dynamic update, TSIG-signed.",
		required: ["server", "port", "zone", "tsigKeyName", "tsigAlgorithm", "tsigSecretConfigured", "propagationSeconds"],
		properties: {
			server: { type: "string", description: "Nameserver hostname or IP accepting RFC 2136 dynamic updates." },
			port: { type: "integer", minimum: 1, maximum: 65_535, default: 53 },
			zone: { type: "string", description: "DNS zone name; normalized with a trailing dot, e.g. example.com." },
			tsigKeyName: { type: "string", description: "TSIG key name; normalized with a trailing dot." },
			tsigAlgorithm: { type: "string", const: "hmac-sha256", description: "Only hmac-sha256 is currently supported." },
			tsigSecretConfigured: { type: "boolean" },
			propagationSeconds: {
				type: "integer",
				minimum: 0,
				default: 30,
				description: "Delay after creating a TXT record before proceeding, to allow DNS propagation.",
			},
		},
	},
	DnsRfc2136ConfigInput: {
		type: "object",
		description:
			"Input config shape when type is `rfc2136`. server, zone, and tsigKeyName are required on create (as is tsigSecret, since no secret can pre-exist); all fields are optional on update (existing values are kept, apart from tsigSecret which must be re-supplied to change it).",
		properties: {
			server: { type: "string" },
			port: { type: "integer", minimum: 1, maximum: 65_535, default: 53 },
			zone: { type: "string" },
			tsigKeyName: { type: "string" },
			tsigSecret: { type: "string", description: "Plaintext, base64-encoded TSIG secret. Omit to keep the currently stored secret." },
			propagationSeconds: { type: "integer", minimum: 0, default: 30 },
		},
	},
	DnsProvider: {
		type: "object",
		required: ["id", "name", "type", "config", "createdAt", "updatedAt"],
		properties: {
			id: { type: "string" },
			name: { type: "string" },
			type: { type: "string", enum: ["rfc2136"] },
			config: { $ref: "#/components/schemas/DnsRfc2136Config" },
			createdAt: { type: "integer" },
			updatedAt: { type: "integer" },
		},
	},
	DnsProviderInput: {
		type: "object",
		description: "name and type are required on create; all fields are optional on update (existing values are kept). config's shape depends on type.",
		properties: {
			name: { type: "string" },
			type: { type: "string", enum: ["rfc2136"], description: "Immutable after creation - not accepted on update." },
			config: { $ref: "#/components/schemas/DnsRfc2136ConfigInput" },
		},
	},
};
