import { errorResponse, jsonBody, jsonResponse, ref, type PathItemObject } from "../types.ts";

const HA_INTERNAL_SECURITY = [{ HaSharedToken: [] }];

export const identityPaths: Record<string, PathItemObject> = {
	"/me": {
		get: {
			summary: "Get your own account",
			tags: ["Account"],
			operationId: "getOwnAccount",
			responses: {
				"200": jsonResponse("", ref("AdminUser")),
				"401": errorResponse("Not signed in."),
			},
		},
	},
	"/me/password": {
		post: {
			summary: "Change your own password",
			description: "Revokes every other session for this account, so re-authentication is required elsewhere.",
			tags: ["Account"],
			operationId: "changeOwnPassword",
			requestBody: jsonBody({
				type: "object",
				required: ["currentPassword", "newPassword"],
				properties: { currentPassword: { type: "string" }, newPassword: { type: "string", minLength: 8, maxLength: 1024 } },
			}),
			responses: {
				"200": jsonResponse("", { type: "object", required: ["ok"], properties: { ok: { type: "boolean", const: true } } }),
				"400": errorResponse("Current password is incorrect, or the new password is invalid."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("CSRF validation failed (session-authenticated requests only)."),
			},
		},
	},
	"/me/recovery-codes/regenerate": {
		post: {
			summary: "Regenerate your own two-factor recovery codes",
			description: "Requires a valid current TOTP code. Invalidates all previously issued recovery codes. Two-factor authentication must already be enrolled.",
			tags: ["Account"],
			operationId: "regenerateOwnRecoveryCodes",
			requestBody: jsonBody({ type: "object", required: ["code"], properties: { code: { type: "string", description: "Current 6-digit TOTP code." } } }),
			responses: {
				"200": jsonResponse("The new codes, shown once and never again.", {
					type: "object",
					required: ["codes"],
					properties: { codes: { type: "array", items: { type: "string" } } },
				}),
				"400": errorResponse("Invalid verification code, or two-factor authentication is not enrolled."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("CSRF validation failed (session-authenticated requests only)."),
			},
		},
	},
	"/me/webauthn": {
		get: {
			summary: "List your own security keys",
			tags: ["Account"],
			operationId: "listOwnWebauthnCredentials",
			responses: {
				"200": jsonResponse("", { type: "array", items: ref("AdminWebauthnCredential") }),
				"401": errorResponse("Not signed in."),
			},
		},
	},
	"/me/webauthn/register/options": {
		post: {
			summary: "Begin registering a new security key",
			description: "Returns WebAuthn registration options for navigator.credentials.create(), plus a challengeToken to pass back to the verify step.",
			tags: ["Account"],
			operationId: "beginOwnWebauthnRegistration",
			responses: {
				"200": jsonResponse("", {
					allOf: [ref("WebauthnCeremonyPayload")],
					type: "object",
					required: ["challengeToken"],
					properties: { challengeToken: { type: "string", description: "Opaque token identifying this in-progress registration ceremony; expires shortly." } },
				}),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("CSRF validation failed (session-authenticated requests only)."),
			},
		},
	},
	"/me/webauthn/register/verify": {
		post: {
			summary: "Complete registering a new security key",
			tags: ["Account"],
			operationId: "verifyOwnWebauthnRegistration",
			requestBody: jsonBody({
				type: "object",
				required: ["response", "challengeToken"],
				properties: {
					response: { allOf: [ref("WebauthnCeremonyPayload")], description: "The browser's attestation response from navigator.credentials.create()." },
					nickname: { type: "string", maxLength: 255 },
					challengeToken: { type: "string", description: "From the register/options response." },
				},
			}),
			responses: {
				"200": jsonResponse("", { type: "object", required: ["ok"], properties: { ok: { type: "boolean", const: true } } }),
				"400": errorResponse("Invalid JSON, or the attestation failed verification."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("CSRF validation failed (session-authenticated requests only)."),
				"428": errorResponse("The registration challenge expired (or was never issued to this account) - request new options and try again."),
			},
		},
	},
	"/me/webauthn/{id}/rename": {
		post: {
			summary: "Rename one of your own security keys",
			tags: ["Account"],
			operationId: "renameOwnWebauthnCredential",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			requestBody: jsonBody({ type: "object", required: ["nickname"], properties: { nickname: { type: "string", maxLength: 255 } } }),
			responses: {
				"200": jsonResponse("", { type: "object", required: ["ok"], properties: { ok: { type: "boolean", const: true } } }),
				"400": errorResponse("Security key not found, or the nickname is too long."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("CSRF validation failed (session-authenticated requests only)."),
			},
		},
	},
	"/me/webauthn/{id}": {
		delete: {
			summary: "Remove one of your own security keys",
			tags: ["Account"],
			operationId: "removeOwnWebauthnCredential",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			responses: {
				"200": jsonResponse("", { type: "object", required: ["ok"], properties: { ok: { type: "boolean", const: true } } }),
				"400": errorResponse("Security key not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("CSRF validation failed (session-authenticated requests only)."),
			},
		},
	},

	"/sso": {
		get: {
			summary: "Get the instance's dashboard SSO settings",
			description: "Administrator only.",
			tags: ["Instance SSO"],
			operationId: "getAdminSsoSettings",
			responses: {
				"200": jsonResponse("", ref("AdminSsoSettings")),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required."),
			},
		},
		put: {
			summary: "Update the instance's dashboard SSO settings",
			description: "Administrator only. See docs/SSO.md for the OIDC flow this configures.",
			tags: ["Instance SSO"],
			operationId: "updateAdminSsoSettings",
			requestBody: jsonBody(ref("AdminSsoSettingsInput")),
			responses: {
				"200": jsonResponse("", ref("AdminSsoSettings")),
				"400": errorResponse("Invalid input (e.g. a malformed issuer URL, missing client secret, or discovery against the issuer failed)."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
			},
		},
	},

	"/users": {
		get: {
			summary: "List admin users",
			description: "Administrator only. Also returns the site and stream catalog the dashboard uses to render permission pickers.",
			tags: ["Admin users"],
			operationId: "listAdminUsers",
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["items", "sites", "streams"],
					properties: {
						items: { type: "array", items: ref("AdminUser") },
						sites: { type: "array", items: { type: "object", required: ["id", "name"], properties: { id: { type: "string" }, name: { type: "string" } } } },
						streams: {
							type: "array",
							items: {
								type: "object",
								required: ["id", "name", "incomingPort", "forwardHost", "forwardPort"],
								properties: {
									id: { type: "string" },
									name: { type: "string" },
									incomingPort: { type: "integer" },
									forwardHost: { type: "string" },
									forwardPort: { type: "integer" },
								},
							},
						},
					},
				}),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required."),
			},
		},
		post: {
			summary: "Create an admin user",
			description: "Administrator only.",
			tags: ["Admin users"],
			operationId: "createAdminUser",
			requestBody: jsonBody(ref("AdminUserInput")),
			responses: {
				"201": jsonResponse("", { type: "object", required: ["user"], properties: { user: ref("AdminUser") } }),
				"400": errorResponse("Invalid input, or this username already exists."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
			},
		},
	},
	"/users/{id}": {
		patch: {
			summary: "Update an admin user",
			description:
				"Administrator only. Changing role, enabled, or password revokes all of the target user's existing sessions. Rejected if it would leave zero enabled administrators.",
			tags: ["Admin users"],
			operationId: "updateAdminUser",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			requestBody: jsonBody(ref("AdminUserInput")),
			responses: {
				"200": jsonResponse("", { type: "object", required: ["user"], properties: { user: ref("AdminUser") } }),
				"400": errorResponse("Invalid input, this username already exists, or the update would leave zero enabled administrators."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
				"404": errorResponse("Admin user not found."),
			},
		},
		delete: {
			summary: "Delete an admin user",
			description: "Administrator only. Cannot delete your own account, and rejected if it would leave zero enabled administrators.",
			tags: ["Admin users"],
			operationId: "deleteAdminUser",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			responses: {
				"200": jsonResponse("", { type: "object", required: ["deleted"], properties: { deleted: { type: "boolean", const: true } } }),
				"400": errorResponse("You cannot delete your own account, or this would leave zero enabled administrators."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
				"404": errorResponse("Admin user not found."),
			},
		},
	},
	"/users/{id}/reset-password": {
		post: {
			summary: "Reset another admin user's password",
			description: "Administrator only. Revokes all of the target user's existing sessions.",
			tags: ["Admin users"],
			operationId: "resetAdminUserPassword",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			requestBody: jsonBody({ type: "object", required: ["password"], properties: { password: { type: "string", minLength: 8, maxLength: 1024 } } }),
			responses: {
				"200": jsonResponse("", { type: "object", required: ["ok"], properties: { ok: { type: "boolean", const: true } } }),
				"400": errorResponse("Invalid password."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
				"404": errorResponse("Admin user not found."),
			},
		},
	},
	"/users/{id}/totp/reset": {
		post: {
			summary: "Reset another admin user's two-factor authentication",
			description:
				"Administrator only. Clears the user's TOTP enrollment, recovery codes, and all WebAuthn credentials, forces re-enrollment on next login, and revokes all of the target user's existing sessions.",
			tags: ["Admin users"],
			operationId: "resetAdminUserTwoFactor",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			responses: {
				"200": jsonResponse("", { type: "object", required: ["ok"], properties: { ok: { type: "boolean", const: true } } }),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
				"404": errorResponse("Admin user not found."),
			},
		},
	},

	"/audit-log": {
		get: {
			summary: "List audit log entries",
			description: "Administrator only. Paged and filterable.",
			tags: ["Audit log"],
			operationId: "listAuditLog",
			parameters: [
				{ name: "page", in: "query", schema: { type: "integer", minimum: 1, default: 1 } },
				{ name: "pageSize", in: "query", schema: { type: "integer", minimum: 10, maximum: 200 } },
				{ name: "search", in: "query", schema: { type: "string" } },
				{ name: "actorUserId", in: "query", schema: { type: "string" } },
				{ name: "action", in: "query", schema: { type: "string" } },
				{ name: "resourceType", in: "query", schema: { type: "string" } },
				{ name: "resourceId", in: "query", schema: { type: "string" } },
				{ name: "since", in: "query", description: "Unix milliseconds, inclusive.", schema: { type: "integer" } },
				{ name: "until", in: "query", description: "Unix milliseconds, inclusive.", schema: { type: "integer" } },
				{ name: "sortBy", in: "query", schema: { type: "string", enum: ["created_at", "action", "actor_username", "resource_type"], default: "created_at" } },
				{ name: "sortDirection", in: "query", schema: { type: "string", enum: ["asc", "desc"], default: "desc" } },
			],
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["items", "page", "pageSize", "total", "totalPages"],
					properties: {
						items: { type: "array", items: ref("AuditLogEntry") },
						page: { type: "integer" },
						pageSize: { type: "integer" },
						total: { type: "integer" },
						totalPages: { type: "integer" },
					},
				}),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required."),
			},
		},
	},
	"/audit-log/purge": {
		post: {
			summary: "Purge audit log entries",
			description: "Administrator only. Either supply `all: true` to purge every entry, or `olderThanDays` to purge only entries older than that many days.",
			tags: ["Audit log"],
			operationId: "purgeAuditLog",
			requestBody: jsonBody({
				type: "object",
				properties: {
					olderThanDays: { type: "number", minimum: 0, description: "Ignored if `all` is true." },
					all: { type: "boolean", default: false },
				},
			}),
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["purged"],
					properties: { purged: { type: "integer", description: "Number of entries removed." } },
				}),
				"400": errorResponse("olderThanDays is missing or negative (and all was not set to true)."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Administrator access required, or CSRF validation failed."),
			},
		},
	},

	"/logout": {
		post: {
			summary: "Sign out",
			description: "Revokes every session token presented in the request's cookies and clears the dashboard's session cookies.",
			tags: ["Account"],
			operationId: "logout",
			responses: {
				"200": jsonResponse("", { type: "object", required: ["loggedOut"], properties: { loggedOut: { type: "boolean", const: true } } }),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("CSRF validation failed (session-authenticated requests only)."),
			},
		},
	},

	"/ha/certificate": {
		get: {
			summary: "[HA-internal] Fetch this node's HA mesh TLS certificate",
			description:
				"Called by a joining or reconnecting HA node to pin this node's certificate. Authenticated with a per-node HA bearer credential, not a dashboard session or API token - see the `HaSharedToken` security scheme.",
			tags: ["HA-internal"],
			operationId: "haGetCertificate",
			security: HA_INTERNAL_SECURITY,
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["cert"],
					properties: { cert: { type: "string", description: "PEM-encoded certificate (private key withheld)." } },
				}),
				"401": errorResponse("Missing or invalid HA bearer credential."),
				"404": errorResponse("High availability is not enabled on this node."),
			},
		},
	},
	"/ha/resolve-admin-session": {
		post: {
			summary: "[HA-internal] Resolve a session token hash to its session record",
			description:
				"Called by a replica to validate a dashboard session cookie it received directly, by asking the primary (the source of truth for sessions). Primary-only. Authenticated with a per-node HA bearer credential - see the `HaSharedToken` security scheme.",
			tags: ["HA-internal"],
			operationId: "haResolveAdminSession",
			security: HA_INTERNAL_SECURITY,
			requestBody: jsonBody({
				type: "object",
				required: ["tokenHash"],
				properties: { tokenHash: { type: "string", pattern: "^[a-f0-9]{64}$", description: "SHA-256 hex digest of the session token." } },
			}),
			responses: {
				"200": jsonResponse("`session` is null if the token hash is unknown or the session has expired.", {
					type: "object",
					required: ["session"],
					properties: { session: { oneOf: [{ type: "null" }, ref("AdminSessionRecord")] } },
				}),
				"400": errorResponse("Invalid token hash, or this node is not the HA primary."),
				"401": errorResponse("Missing or invalid HA bearer credential."),
				"404": errorResponse("High availability is not enabled on this node."),
			},
		},
	},
	"/ha/consume-recovery-code": {
		post: {
			summary: "[HA-internal] Consume a two-factor recovery code on behalf of a replica",
			description:
				"Called by a replica when a user signs in with a recovery code, since recovery codes may only be consumed once and the primary is the source of truth. Primary-only. Authenticated with a per-node HA bearer credential - see the `HaSharedToken` security scheme.",
			tags: ["HA-internal"],
			operationId: "haConsumeRecoveryCode",
			security: HA_INTERNAL_SECURITY,
			requestBody: jsonBody({
				type: "object",
				required: ["userId", "codeHash"],
				properties: { userId: { type: "string" }, codeHash: { type: "string", description: "Hash of the recovery code, as stored." } },
			}),
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["consumed"],
					properties: { consumed: { type: "boolean", description: "False if the code was already used, or never existed, for this user." } },
				}),
				"400": errorResponse("userId and codeHash are required, or this node is not the HA primary."),
				"401": errorResponse("Missing or invalid HA bearer credential."),
				"404": errorResponse("High availability is not enabled on this node."),
			},
		},
	},

	"/sites/{id}/notification-policy": {
		get: {
			summary: "Get a site's notification policy",
			description: "Requires viewer-level access to this site.",
			tags: ["Sites"],
			operationId: "getSiteNotificationPolicy",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			responses: {
				"200": jsonResponse("", ref("SiteNotificationPolicy")),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to this site)."),
				"404": errorResponse("Site not found."),
			},
		},
		put: {
			summary: "Update a site's notification policy",
			description:
				"Requires manager-level access to this site. A slimmer counterpart to updating the site's full healthCheck.alerts sub-object via PUT /sites/{id}.",
			tags: ["Sites"],
			operationId: "updateSiteNotificationPolicy",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			requestBody: jsonBody(ref("SiteNotificationPolicyInput")),
			responses: {
				"200": jsonResponse("", ref("SiteNotificationPolicy")),
				"400": errorResponse("Invalid input (e.g. notifications enabled without a webhook URL configured)."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("Site not found."),
			},
		},
	},
};
