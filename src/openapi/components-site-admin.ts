import type { JsonSchema } from "./types.ts";

export const siteAdminSchemas: Record<string, JsonSchema> = {
	StaticCacheMetrics: {
		type: "object",
		required: [
			"hits",
			"misses",
			"bypasses",
			"stores",
			"evictions",
			"expired",
			"purges",
			"purgedEntries",
			"bytesServed",
			"entries",
			"bytes",
			"hitRatio",
			"maxEntries",
			"maxBytes",
		],
		properties: {
			hits: { type: "integer", description: "Cache hits since start-up (or since siteId scoping began, if scoped)." },
			misses: { type: "integer" },
			bypasses: { type: "integer", description: "Requests that were cacheable in principle but bypassed the cache." },
			stores: { type: "integer" },
			evictions: { type: "integer", description: "Entries evicted for capacity reasons (LRU-style, not an explicit purge)." },
			expired: { type: "integer", description: "Entries removed because their TTL elapsed." },
			purges: { type: "integer", description: "Number of purge operations performed (not entries removed)." },
			purgedEntries: { type: "integer", description: "Total entries removed across all purge operations." },
			bytesServed: { type: "integer" },
			entries: { type: "integer", description: "Current entry count. Instance-wide unless a siteId was requested." },
			bytes: { type: "integer", description: "Current total cached bytes. Instance-wide unless a siteId was requested." },
			hitRatio: { type: "number", minimum: 0, maximum: 1, description: "hits / (hits + misses), or 0 if there have been no lookups." },
			maxEntries: { type: "integer", description: "Instance-wide entry-count ceiling." },
			maxBytes: { type: "integer", description: "Instance-wide total-bytes ceiling." },
		},
	},
	CachePurgeInput: {
		type: "object",
		description:
			"siteId is a query parameter, not a body field - see the operation's parameters. If allSites is not true, siteId selects the site to purge (all of its cached entries, or narrowed by routePolicyId/pathPrefix).",
		properties: {
			allSites: {
				type: "boolean",
				description: "Purge every site's cache instance-wide. Requires administrator access; ignores siteId, routePolicyId, and pathPrefix.",
			},
			routePolicyId: { type: "string", description: "Limit the purge to entries cached under this route policy of the selected site." },
			pathPrefix: {
				type: "string",
				maxLength: 2048,
				description: "Limit the purge to entries whose path starts with this prefix. Must start with exactly one slash and contain no ? or #.",
			},
		},
	},

	AccessUser: {
		type: "object",
		description: "A global end-user identity that can be assigned to one or more protected sites' access lists (see docs/ACCESS_LISTS.md).",
		required: [
			"id",
			"username",
			"enabled",
			"siteCount",
			"createdAt",
			"updatedAt",
			"siteIds",
			"totpRequired",
			"totpEnrolled",
			"webauthnCredentialCount",
			"apiTokenEnabled",
			"apiTokenCreatedAt",
		],
		properties: {
			id: { type: "string" },
			username: { type: "string", maxLength: 255 },
			enabled: { type: "boolean", description: "Disabling revokes this user's current authenticated sessions on every assigned site." },
			siteCount: { type: "integer", description: "Number of sites this identity is assigned to." },
			createdAt: { type: "integer", description: "Unix milliseconds." },
			updatedAt: { type: "integer" },
			siteIds: {
				type: "array",
				items: { type: "string" },
				description: "Populated on the access-list listing; may be empty on responses returned from a single-user action.",
			},
			totpRequired: { type: "boolean" },
			totpEnrolled: { type: "boolean", description: "Whether a TOTP secret has been enrolled (independent of totpRequired)." },
			webauthnCredentialCount: { type: "integer", description: "WebAuthn credentials registered for this user on the currently-selected site." },
			apiTokenEnabled: {
				type: "boolean",
				description: "Whether this user has a site-visitor API token (distinct from dashboard API tokens - see the api-token endpoints below).",
			},
			apiTokenCreatedAt: { type: ["integer", "null"] },
		},
	},
	AccessUserInput: {
		type: "object",
		description: "All fields are optional on update (existing values are kept); username and password are required on create.",
		properties: {
			username: {
				type: "string",
				maxLength: 255,
				pattern: "^[a-z0-9][a-z0-9._@+-]*$",
				description: "Case-insensitive (normalized to lowercase). May contain letters, numbers, dots, underscores, @, +, and hyphens.",
			},
			password: { type: "string", minLength: 8, maxLength: 1024, description: "Changing it revokes this user's current sessions on every assigned site." },
			enabled: { type: "boolean", default: true },
		},
	},
	AccessList: {
		type: "object",
		description: "The access-list settings and users for one site.",
		required: ["settings", "users", "availableUsers"],
		properties: {
			settings: {
				type: "object",
				required: ["enabled", "sendUsernameToUpstream", "sessionVerificationTokenEnabled", "sessionVerificationTokenCreatedAt"],
				properties: {
					enabled: { type: "boolean", description: "Cannot be enabled with zero active assigned users." },
					sendUsernameToUpstream: {
						type: "boolean",
						description: "Adds X-BurrowGate-Authenticated-User and X-BurrowGate-Identity-Signature to proxied requests - see docs/ACCESS_LISTS.md.",
					},
					sessionVerificationTokenEnabled: { type: "boolean" },
					sessionVerificationTokenCreatedAt: { type: ["integer", "null"] },
				},
			},
			users: { type: "array", items: { $ref: "#/components/schemas/AccessUser" }, description: "Users currently assigned to this site." },
			availableUsers: {
				type: "array",
				items: { $ref: "#/components/schemas/AccessUser" },
				description: "Existing global identities assigned to at least one other site but not this one, for the 'add users from another site' picker.",
			},
		},
	},
	AccessListSettingsInput: {
		type: "object",
		description: "Partial update; omitted fields keep their current value.",
		properties: {
			enabled: { type: "boolean" },
			sendUsernameToUpstream: { type: "boolean" },
		},
	},

	SiteSsoSettings: {
		type: "object",
		description: "Per-site OpenID Connect single sign-on configuration for access-list accounts - independent of dashboard SSO. See docs/SSO.md.",
		required: ["enabled", "enforceSso", "issuerUrl", "clientId", "clientSecretConfigured", "scopes", "buttonLabel"],
		properties: {
			enabled: { type: "boolean" },
			enforceSso: {
				type: "boolean",
				description:
					"Hides the local password form behind a 'use a local account instead' link. UX guidance only, not an access-control boundary - a valid local password still works.",
			},
			issuerUrl: { type: "string", description: "Empty string if not configured." },
			clientId: { type: "string", description: "Empty string if not configured." },
			clientSecretConfigured: { type: "boolean", description: "Whether a client secret is stored. The secret itself is never returned." },
			scopes: { type: "string" },
			buttonLabel: { type: "string" },
		},
	},
	SiteSsoSettingsInput: {
		type: "object",
		description:
			"All fields are optional on update (existing values are kept). Enabling requires issuerUrl, clientId, and a stored client secret (existing or newly supplied) to already be present, and validates issuerUrl by fetching its OIDC discovery document.",
		properties: {
			enabled: { type: "boolean" },
			enforceSso: { type: "boolean" },
			issuerUrl: { type: "string" },
			clientId: { type: "string" },
			clientSecret: { type: "string", description: "Write-only. Omit to keep the existing stored secret; blank values are ignored." },
			scopes: { type: "string", default: "openid email profile" },
			buttonLabel: { type: "string", default: "Single sign-on" },
		},
	},

	TlsSite: {
		type: "object",
		required: ["settings", "certificate", "events", "listener", "defaults"],
		properties: {
			settings: {
				type: "object",
				required: ["mode", "forceHttps", "acmeEmail", "acmeDirectoryUrl", "acmeChallengeType", "acmeDnsProviderId"],
				properties: {
					mode: { type: "string", enum: ["disabled", "uploaded", "letsencrypt"] },
					forceHttps: { type: "boolean" },
					acmeEmail: { type: ["string", "null"] },
					acmeDirectoryUrl: { type: ["string", "null"] },
					acmeChallengeType: { type: "string", enum: ["http-01", "dns-01"] },
					acmeDnsProviderId: { type: ["string", "null"], description: "RFC 2136 DNS provider ID, used only when acmeChallengeType is dns-01." },
				},
			},
			certificate: {
				type: ["object", "null"],
				description: "Null if no certificate is stored for this site.",
				required: [
					"id",
					"source",
					"status",
					"primaryDomain",
					"alternativeNames",
					"issuer",
					"serialNumber",
					"validFrom",
					"expiresAt",
					"nextRenewalAt",
					"lastAttemptAt",
					"lastError",
					"updatedAt",
				],
				properties: {
					id: { type: "string" },
					source: { type: "string", enum: ["uploaded", "letsencrypt"] },
					status: {
						type: "string",
						enum: ["pending", "active", "renewal-failed", "expired", "invalid"],
						description: "Computed as expired if past expiresAt, regardless of the stored status.",
					},
					primaryDomain: { type: "string" },
					alternativeNames: { type: "array", items: { type: "string" } },
					issuer: { type: ["string", "null"] },
					serialNumber: { type: ["string", "null"] },
					validFrom: { type: ["integer", "null"], description: "Unix milliseconds." },
					expiresAt: { type: ["integer", "null"] },
					nextRenewalAt: { type: ["integer", "null"], description: "Set only for letsencrypt certificates - when BurrowGate will attempt automatic renewal." },
					lastAttemptAt: { type: ["integer", "null"] },
					lastError: { type: ["string", "null"] },
					updatedAt: { type: "integer" },
				},
			},
			events: {
				type: "array",
				items: {
					type: "object",
					required: ["id", "level", "message", "details", "createdAt"],
					properties: {
						id: { type: "string" },
						level: { type: "string", enum: ["info", "warning", "error"] },
						message: { type: "string" },
						details: { type: "object", additionalProperties: true },
						createdAt: { type: "integer" },
					},
				},
			},
			listener: {
				type: "object",
				required: ["httpEnabled", "httpPort", "publicHttpPort", "httpsEnabled", "httpsPort", "publicHttpsPort", "bootstrapTlsEnabled"],
				properties: {
					httpEnabled: { type: "boolean" },
					httpPort: { type: "integer" },
					publicHttpPort: { type: "integer" },
					httpsEnabled: { type: "boolean" },
					httpsPort: { type: "integer" },
					publicHttpsPort: { type: "integer" },
					bootstrapTlsEnabled: { type: "boolean" },
				},
			},
			defaults: {
				type: "object",
				required: ["acmeDirectoryUrl", "acmeEmail", "staging"],
				properties: {
					acmeDirectoryUrl: { type: "string" },
					acmeEmail: { type: ["string", "null"] },
					staging: { type: "boolean", description: "Whether the instance-wide default ACME directory URL looks like a staging endpoint." },
				},
			},
		},
	},
	TlsSettingsInput: {
		type: "object",
		description:
			"All fields are optional; existing values are kept. Setting mode to uploaded or letsencrypt requires a matching active certificate to already be stored (upload or issue it first). Selecting acmeChallengeType dns-01 or supplying acmeDnsProviderId requires administrator access.",
		properties: {
			mode: { type: "string", enum: ["disabled", "uploaded", "letsencrypt"] },
			forceHttps: { type: "boolean", description: "Forced to false whenever mode is disabled." },
			acmeEmail: { type: "string" },
			acmeDirectoryUrl: { type: "string", description: "Must use HTTPS." },
			acmeChallengeType: { type: "string", enum: ["http-01", "dns-01"] },
			acmeDnsProviderId: { type: "string", description: "Required (and only used) when acmeChallengeType is dns-01." },
		},
	},
	CertificateUploadInput: {
		type: "object",
		required: ["certificatePem", "privateKeyPem"],
		properties: {
			certificatePem: { type: "string", maxLength: 524_288, description: "PEM certificate, optionally a full chain. Must cover the site's public hostname." },
			privateKeyPem: { type: "string", maxLength: 262_144, description: "PEM private key matching the certificate's public key." },
			forceHttps: { type: "boolean", default: false },
		},
	},
	CertificateLetsEncryptInput: {
		type: "object",
		description: "Selecting challengeType dns-01 or supplying dnsProviderId requires administrator access.",
		properties: {
			email: { type: "string", description: "Defaults to the instance's configured ACME email if omitted." },
			directoryUrl: { type: "string", description: "Defaults to the instance's configured ACME directory URL (production or staging) if omitted." },
			forceHttps: { type: "boolean", default: false },
			termsAccepted: { type: "boolean", description: "Must be true for issuance to proceed." },
			challengeType: { type: "string", enum: ["http-01", "dns-01"], default: "http-01" },
			dnsProviderId: {
				type: "string",
				description: "Required (and only used) when challengeType is dns-01 - an RFC 2136 DNS provider configured on this instance.",
			},
		},
	},
};
