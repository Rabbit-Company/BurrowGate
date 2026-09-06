import type { JsonSchema } from "./types.ts";

export const identitySchemas: Record<string, JsonSchema> = {
	AdminUser: {
		type: "object",
		description: "A dashboard administrator or member account (AdminUserView). Never includes the password hash or TOTP secret.",
		required: [
			"id",
			"username",
			"role",
			"enabled",
			"totpEnrolled",
			"webauthnCredentialCount",
			"createdAt",
			"updatedAt",
			"sitePermissions",
			"streamPermissions",
		],
		properties: {
			id: { type: "string" },
			username: { type: "string", maxLength: 255, description: "Lowercased. Letters, digits, dots, underscores, @, +, and hyphens." },
			role: { type: "string", enum: ["administrator", "member"], description: "An administrator implicitly has manager access to every site and stream." },
			enabled: { type: "boolean" },
			totpEnrolled: { type: "boolean" },
			webauthnCredentialCount: { type: "integer" },
			createdAt: { type: "integer", description: "Unix milliseconds." },
			updatedAt: { type: "integer", description: "Unix milliseconds." },
			sitePermissions: {
				type: "array",
				items: {
					type: "object",
					required: ["siteId", "level"],
					properties: { siteId: { type: "string" }, level: { type: "string", enum: ["viewer", "manager"] } },
				},
				description: "Ignored (and irrelevant) for an administrator, who already has manager access to every site.",
			},
			streamPermissions: {
				type: "array",
				items: {
					type: "object",
					required: ["streamId", "level"],
					properties: { streamId: { type: "string" }, level: { type: "string", enum: ["viewer", "manager"] } },
				},
			},
		},
	},
	AdminUserInput: {
		type: "object",
		description:
			"All fields are optional on update (existing values are kept); username and password are required on create. Changing role/enabled/password on an update revokes the user's existing sessions.",
		properties: {
			username: { type: "string", maxLength: 255, description: "Lowercased on save. Letters, digits, dots, underscores, @, +, and hyphens." },
			password: { type: "string", minLength: 8, maxLength: 1024, description: "Required on create. Omit on update to keep the existing password." },
			role: {
				type: "string",
				enum: ["administrator", "member"],
				default: "member",
				description: "At least one enabled administrator must remain; an update or delete that would leave zero is rejected.",
			},
			enabled: { type: "boolean", default: true },
			sitePermissions: {
				type: "array",
				description: "Replaces the full set of site grants. Omit the field to leave existing grants untouched.",
				items: {
					type: "object",
					required: ["siteId", "level"],
					properties: { siteId: { type: "string" }, level: { type: "string", enum: ["viewer", "manager"] } },
				},
			},
			streamPermissions: {
				type: "array",
				description: "Replaces the full set of stream grants. Omit the field to leave existing grants untouched.",
				items: {
					type: "object",
					required: ["streamId", "level"],
					properties: { streamId: { type: "string" }, level: { type: "string", enum: ["viewer", "manager"] } },
				},
			},
		},
	},

	AdminWebauthnCredential: {
		type: "object",
		description: "A registered WebAuthn/security-key credential belonging to the caller's own account (AdminWebauthnCredentialView).",
		required: ["id", "nickname", "createdAt", "lastUsedAt", "deviceType", "backedUp"],
		properties: {
			id: { type: "string" },
			nickname: { type: ["string", "null"] },
			createdAt: { type: "integer", description: "Unix milliseconds." },
			lastUsedAt: { type: ["integer", "null"], description: "Unix milliseconds, or null if never used to sign in." },
			deviceType: { type: ["string", "null"], description: "e.g. `singleDevice` or `multiDevice`, as reported by the authenticator at registration." },
			backedUp: { type: "boolean" },
		},
	},
	WebauthnCeremonyPayload: {
		type: "object",
		additionalProperties: true,
		description:
			"A standard WebAuthn ceremony payload - either the registration options challenge BurrowGate hands to the browser's navigator.credentials.create(), or the attestation response the browser hands back. Shaped per the WebAuthn Level 2/3 spec (binary fields such as challenge/rawId/attestationObject are base64url-encoded ArrayBuffers); not reproduced field-by-field here since the exact set depends on the authenticator and the @simplewebauthn library version in use.",
	},

	AdminSsoSettings: {
		type: "object",
		description: "Instance-wide dashboard single sign-on configuration (AdminSsoSettingsView). One shared OIDC identity provider for all dashboard accounts.",
		required: ["enabled", "enforceSso", "issuerUrl", "clientId", "clientSecretConfigured", "scopes", "buttonLabel"],
		properties: {
			enabled: { type: "boolean" },
			enforceSso: {
				type: "boolean",
				description:
					"When true, the password form is hidden behind a 'Use a local account instead' link rather than removed - a break-glass path always remains so a misconfigured identity provider can never lock out every administrator.",
			},
			issuerUrl: { type: "string", description: "The OIDC issuer; `<issuerUrl>/.well-known/openid-configuration` is fetched for discovery." },
			clientId: { type: "string" },
			clientSecretConfigured: { type: "boolean", description: "Whether a client secret is currently stored. The secret itself is never returned." },
			scopes: { type: "string", description: "Space-separated OAuth scopes requested at the authorization endpoint." },
			buttonLabel: { type: "string", description: "Label shown on the dashboard's sign-in button." },
		},
	},
	AdminSsoSettingsInput: {
		type: "object",
		description:
			"All fields are optional; an omitted field keeps its current value. Enabling requires a non-empty issuerUrl, clientId, and a stored client secret (existing or newly supplied) - the issuer is also re-discovered at save time and the update is rejected if discovery fails.",
		properties: {
			enabled: { type: "boolean" },
			enforceSso: { type: "boolean" },
			issuerUrl: { type: "string" },
			clientId: { type: "string" },
			clientSecret: {
				type: "string",
				description: "Write-only; never echoed back. Omit (or send blank) to keep the existing stored secret - it is never cleared implicitly.",
			},
			scopes: { type: "string", default: "openid email profile" },
			buttonLabel: { type: "string", default: "Single sign-on" },
		},
	},

	AuditLogEntry: {
		type: "object",
		description: "One admin audit-log record. Returned verbatim from storage (not remapped to camelCase) - field names are the storage column names.",
		required: ["id", "actor_user_id", "actor_username", "action", "resource_type", "resource_id", "summary", "detail_json", "ip", "created_at"],
		properties: {
			id: { type: "string" },
			actor_user_id: { type: ["string", "null"], description: "Null if the acting user has since been deleted." },
			actor_username: { type: "string", description: "Snapshotted at the time of the action, independent of the user's current username." },
			action: { type: "string", description: "A dotted action code, e.g. `admin_user.create`, `admin_sso.settings.update`, `audit_log.purge`." },
			resource_type: { type: ["string", "null"], description: "e.g. `admin_user`, `site`, `api_token`. Null for actions with no single associated resource." },
			resource_id: { type: ["string", "null"] },
			summary: { type: "string", description: "Human-readable one-line description of what happened." },
			detail_json: { type: ["string", "null"], description: "Free-form JSON-encoded string with additional detail, or null." },
			ip: { type: "string" },
			created_at: { type: "integer", description: "Unix milliseconds." },
		},
	},

	AdminSessionRecord: {
		type: "object",
		description:
			"A raw dashboard session record, returned verbatim from storage. HA-internal only - used by a replica node resolving a bearer session token's admin identity against the primary.",
		required: ["id", "token_hash", "username", "user_id", "created_at", "expires_at", "last_seen_at", "sso_sid"],
		properties: {
			id: { type: "string" },
			token_hash: { type: "string" },
			username: { type: "string" },
			user_id: { type: ["string", "null"] },
			created_at: { type: "integer", description: "Unix milliseconds." },
			expires_at: { type: "integer", description: "Unix milliseconds." },
			last_seen_at: { type: "integer", description: "Unix milliseconds." },
			sso_sid: { type: ["string", "null"], description: "The SSO provider's session ID (`sid` claim), if this session was created via SSO login." },
		},
	},

	SiteNotificationPolicy: {
		type: "object",
		description:
			"A site's health-alert notification settings (SiteNotificationPolicyView). A slimmer, dedicated counterpart to the `healthCheck.alerts` sub-object of Site.",
		required: ["enabled", "provider", "webhookConfigured", "eventTypes"],
		properties: {
			enabled: { type: "boolean" },
			provider: { type: "string", enum: ["generic", "slack", "discord", "ntfy"] },
			webhookConfigured: { type: "boolean", description: "Whether a webhook URL is currently stored. The URL itself is never returned." },
			eventTypes: { $ref: "#/components/schemas/NotificationEventTypeMap" },
		},
	},
	SiteNotificationPolicyInput: {
		type: "object",
		description: "All fields are optional; an omitted field keeps its current value.",
		properties: {
			enabled: { type: "boolean" },
			provider: { type: "string", enum: ["generic", "slack", "discord", "ntfy"] },
			webhookUrl: { type: "string", description: "Set or replace the stored webhook URL." },
			webhookSecret: { type: "string", maxLength: 4096, description: "Used to sign outgoing webhook payloads." },
			clearWebhook: { type: "boolean", default: false, description: "If true, removes the stored webhook URL and secret instead of setting them." },
			eventTypes: { $ref: "#/components/schemas/NotificationEventTypeMap" },
		},
	},
};
