import { errorResponse, jsonBody, jsonResponse, ref, type PathItemObject } from "../types.ts";

const siteIdQueryParam = { name: "siteId", in: "query", required: true, schema: { type: "string" } } as const;
const siteIdQueryParamOptional = {
	name: "siteId",
	in: "query",
	required: false,
	description: "Omit to operate instance-wide (only cache metrics and cache purge support this).",
	schema: { type: "string" },
} as const;
const userIdPathParam = { name: "id", in: "path", required: true, description: "Access-list user ID.", schema: { type: "string" } } as const;
const siteIdPathParam = { name: "id", in: "path", required: true, description: "Site ID.", schema: { type: "string" } } as const;

export const siteAdminPaths: Record<string, PathItemObject> = {
	"/cache": {
		get: {
			summary: "Get static-cache metrics",
			description: "Returns instance-wide metrics if siteId is omitted, or metrics scoped to one site.",
			tags: ["Cache"],
			operationId: "getCacheMetrics",
			parameters: [siteIdQueryParamOptional],
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["metrics", "site"],
					properties: { metrics: ref("StaticCacheMetrics"), site: { oneOf: [{ type: "null" }, ref("Site")] } },
				}),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to the selected site)."),
			},
		},
	},
	"/cache/purge": {
		post: {
			summary: "Purge cached static assets",
			description:
				"With allSites: true, purges every site's cache and requires administrator access; routePolicyId and pathPrefix are ignored in that case. Otherwise siteId (query) selects the site to purge, narrowed by routePolicyId and/or pathPrefix, and requires manager-level access to that site.",
			tags: ["Cache"],
			operationId: "purgeCache",
			parameters: [siteIdQueryParamOptional],
			requestBody: jsonBody(ref("CachePurgeInput")),
			responses: {
				"200": jsonResponse("", {
					type: "object",
					required: ["purged", "metrics"],
					properties: { purged: { type: "integer", description: "Number of cache entries removed." }, metrics: ref("StaticCacheMetrics") },
				}),
				"400": errorResponse("Invalid input, or the selected site/route policy was not found."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse(
					"Forbidden (allSites without administrator access, manager-level access required for a site-scoped purge, or CSRF validation failed).",
				),
				"404": errorResponse("Selected site was not found."),
			},
		},
	},

	"/access-list": {
		get: {
			summary: "Get a site's access-list settings and users",
			description: "Requires viewer-level access to the selected site.",
			tags: ["Access list"],
			operationId: "getAccessList",
			parameters: [siteIdQueryParam],
			responses: {
				"200": jsonResponse("", ref("AccessList")),
				"400": errorResponse("No site selected, or no sites exist yet."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to this site)."),
			},
		},
		put: {
			summary: "Update a site's access-list settings",
			description:
				"Requires manager-level access to the selected site. Cannot enable the access list while it has zero active assigned users - add and enable at least one user first.",
			tags: ["Access list"],
			operationId: "updateAccessListSettings",
			parameters: [siteIdQueryParam],
			requestBody: jsonBody(ref("AccessListSettingsInput")),
			responses: {
				"200": jsonResponse("", ref("AccessList")),
				"400": errorResponse("Invalid input, no site selected, or enabling with no active assigned users."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
			},
		},
	},
	"/access-list/session-verification-token": {
		post: {
			summary: "Generate a session-verification token",
			description:
				"Requires manager-level access to the selected site. The plaintext token is returned once, for an origin to verify a caller's authenticated BurrowGate session out-of-band; generating a new one invalidates the previous token.",
			tags: ["Access list"],
			operationId: "generateSessionVerificationToken",
			parameters: [siteIdQueryParam],
			responses: {
				"201": jsonResponse("", {
					type: "object",
					required: ["token", "createdAt"],
					properties: { token: { type: "string", description: "Plaintext token, prefixed bgsv_. Never shown again." }, createdAt: { type: "integer" } },
				}),
				"400": errorResponse("No site selected."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
			},
		},
		delete: {
			summary: "Revoke the session-verification token",
			description: "Requires manager-level access to the selected site.",
			tags: ["Access list"],
			operationId: "revokeSessionVerificationToken",
			parameters: [siteIdQueryParam],
			responses: {
				"200": jsonResponse("", { type: "object", required: ["ok"], properties: { ok: { type: "boolean", const: true } } }),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("Selected site was not found."),
			},
		},
	},
	"/access-list/sso": {
		get: {
			summary: "Get a site's access-list SSO settings",
			description: "Requires viewer-level access to the selected site. See docs/SSO.md - this is independent of dashboard SSO.",
			tags: ["Access list"],
			operationId: "getAccessListSso",
			parameters: [siteIdQueryParam],
			responses: {
				"200": jsonResponse("", ref("SiteSsoSettings")),
				"400": errorResponse("No site selected."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to this site)."),
			},
		},
		put: {
			summary: "Update a site's access-list SSO settings",
			description: "Requires manager-level access to the selected site.",
			tags: ["Access list"],
			operationId: "updateAccessListSso",
			parameters: [siteIdQueryParam],
			requestBody: jsonBody(ref("SiteSsoSettingsInput")),
			responses: {
				"200": jsonResponse("", ref("SiteSsoSettings")),
				"400": errorResponse("Invalid input (missing issuer/client configuration while enabling, an invalid issuer URL, or discovery failed)."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
			},
		},
	},
	"/access-list/users": {
		post: {
			summary: "Create an access-list user",
			description: "Requires manager-level access to the selected site. Creates a new global identity and assigns it to this site.",
			tags: ["Access list"],
			operationId: "createAccessUser",
			parameters: [siteIdQueryParam],
			requestBody: jsonBody(ref("AccessUserInput")),
			responses: {
				"201": jsonResponse("", { type: "object", required: ["user"], properties: { user: ref("AccessUser") } }),
				"400": errorResponse("Invalid input, no site selected, or this username already exists (add the existing user instead)."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
			},
		},
	},
	"/access-list/users/{id}": {
		put: {
			summary: "Update an access-list user",
			description:
				"Requires manager-level access to the selected site. Password and enabled-state changes apply to every site this identity is assigned to, and revoke its current sessions on the affected sites.",
			tags: ["Access list"],
			operationId: "updateAccessUser",
			parameters: [userIdPathParam, siteIdQueryParam],
			requestBody: jsonBody(ref("AccessUserInput")),
			responses: {
				"200": jsonResponse("", { type: "object", required: ["user"], properties: { user: ref("AccessUser") } }),
				"400": errorResponse("Invalid input, this username already exists, or disabling would leave an enabled access list with no active user."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("Access user not found on the selected site, or no site selected."),
			},
		},
		delete: {
			summary: "Remove an access-list user from a site",
			description:
				"Requires manager-level access to the selected site. Revokes the user's sessions on this site. Removing the identity's last remaining site membership permanently deletes the global identity.",
			tags: ["Access list"],
			operationId: "removeAccessUser",
			parameters: [userIdPathParam, siteIdQueryParam],
			responses: {
				"200": jsonResponse("", { type: "object", required: ["ok"], properties: { ok: { type: "boolean", const: true } } }),
				"400": errorResponse("This is the last active user on an enabled access list."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("Access user not found on the selected site, or no site selected."),
			},
		},
	},
	"/access-list/users/{id}/totp": {
		post: {
			summary: "Set whether an access-list user must use two-factor authentication",
			description: "Requires manager-level access to the selected site. Changing this revokes the user's current sessions.",
			tags: ["Access list"],
			operationId: "setAccessUserTotpRequired",
			parameters: [userIdPathParam, siteIdQueryParam],
			requestBody: jsonBody({ type: "object", required: ["required"], properties: { required: { type: "boolean" } } }),
			responses: {
				"200": jsonResponse("", { type: "object", required: ["user"], properties: { user: ref("AccessUser") } }),
				"400": errorResponse("No site selected."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("Access user not found on the selected site."),
			},
		},
	},
	"/access-list/users/{id}/totp/reset": {
		post: {
			summary: "Reset an access-list user's two-factor enrollment",
			description:
				"Requires manager-level access to the selected site. Clears any enrolled TOTP secret and this site's WebAuthn credentials for the user, and revokes their current sessions; the user must re-enroll on next login.",
			tags: ["Access list"],
			operationId: "resetAccessUserTotp",
			parameters: [userIdPathParam, siteIdQueryParam],
			responses: {
				"200": jsonResponse("", { type: "object", required: ["user"], properties: { user: ref("AccessUser") } }),
				"400": errorResponse("No site selected."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("Access user not found on the selected site."),
			},
		},
	},
	"/access-list/users/{id}/api-token": {
		post: {
			summary: "Generate a site-visitor API token for an access-list user",
			description:
				"Requires manager-level access to the selected site. This is a separate per-visitor credential from the dashboard API tokens in /me/api-tokens - it lets an access-list user authenticate as themself without a browser session. The plaintext token is returned once and replaces any previous token for this user.",
			tags: ["Access list"],
			operationId: "generateAccessUserApiToken",
			parameters: [userIdPathParam, siteIdQueryParam],
			responses: {
				"201": jsonResponse("", {
					type: "object",
					required: ["user", "token"],
					properties: { user: ref("AccessUser"), token: { type: "string", description: "Plaintext token. Never shown again." } },
				}),
				"400": errorResponse("No site selected."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("Access user not found on the selected site."),
			},
		},
		delete: {
			summary: "Revoke an access-list user's API token",
			description: "Requires manager-level access to the selected site.",
			tags: ["Access list"],
			operationId: "revokeAccessUserApiToken",
			parameters: [userIdPathParam, siteIdQueryParam],
			responses: {
				"200": jsonResponse("", { type: "object", required: ["user"], properties: { user: ref("AccessUser") } }),
				"400": errorResponse("No site selected."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("Access user not found on the selected site."),
			},
		},
	},
	"/access-list/import": {
		post: {
			summary: "Add existing access-list users to a site",
			description:
				"Requires manager-level access to the selected site. Links each already-existing global identity in userIds to this site (does not copy a password hash); IDs already assigned to the site are skipped rather than erroring.",
			tags: ["Access list"],
			operationId: "importAccessUsers",
			parameters: [siteIdQueryParam],
			requestBody: jsonBody({
				type: "object",
				required: ["userIds"],
				properties: { userIds: { type: "array", items: { type: "string" }, minItems: 1, description: "Access-user IDs to assign to the selected site." } },
			}),
			responses: {
				"201": jsonResponse("", {
					type: "object",
					required: ["imported"],
					properties: { imported: { type: "integer", description: "Number of new memberships created." } },
				}),
				"400": errorResponse("No IDs supplied, one of the selected users no longer exists, or no site selected."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("Selected site was not found."),
			},
		},
	},

	"/sites/{id}/tls": {
		get: {
			summary: "Get a site's TLS and certificate status",
			description: "Requires viewer-level access to this site.",
			tags: ["TLS"],
			operationId: "getSiteTls",
			parameters: [siteIdPathParam],
			responses: {
				"200": jsonResponse("", ref("TlsSite")),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden (no access to this site)."),
				"404": errorResponse("Site not found."),
			},
		},
		put: {
			summary: "Update a site's TLS settings",
			description:
				"Requires manager-level access to this site. Setting mode to uploaded or letsencrypt requires a matching active certificate already stored for that source - upload or issue one first. Selecting acmeChallengeType dns-01 or supplying acmeDnsProviderId requires administrator access.",
			tags: ["TLS"],
			operationId: "updateSiteTls",
			parameters: [siteIdPathParam],
			requestBody: jsonBody(ref("TlsSettingsInput")),
			responses: {
				"200": jsonResponse("", ref("TlsSite")),
				"400": errorResponse("Invalid input, or the selected mode has no matching active certificate."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, DNS-01/DNS-provider selection without administrator access, or CSRF validation failed."),
				"404": errorResponse("Site not found."),
			},
		},
	},
	"/sites/{id}/certificate/upload": {
		post: {
			summary: "Upload a certificate for a site",
			description:
				"Requires manager-level access to this site. Validates that the certificate is parseable and not expired, covers the site's public hostname, and that the private key matches. Activates the certificate and sets TLS mode to uploaded.",
			tags: ["TLS"],
			operationId: "uploadSiteCertificate",
			parameters: [siteIdPathParam],
			requestBody: jsonBody(ref("CertificateUploadInput")),
			responses: {
				"201": jsonResponse("", ref("TlsSite")),
				"400": errorResponse("Missing certificate/key, invalid PEM, key mismatch, expired certificate, or hostname not covered."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("Site not found."),
			},
		},
	},
	"/sites/{id}/certificate/letsencrypt": {
		post: {
			summary: "Issue a Let's Encrypt certificate for a site",
			description:
				"Requires manager-level access to this site. Selecting challengeType dns-01 or supplying dnsProviderId requires administrator access. See docs/TLS.md for the HTTP-01 and DNS-01 (RFC 2136) prerequisites.",
			tags: ["TLS"],
			operationId: "issueSiteLetsEncryptCertificate",
			parameters: [siteIdPathParam],
			requestBody: jsonBody(ref("CertificateLetsEncryptInput")),
			responses: {
				"201": jsonResponse("", ref("TlsSite")),
				"400": errorResponse("Issuance failed (terms not accepted, unreachable challenge, provider error, and so on)."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, DNS-01/DNS-provider selection without administrator access, or CSRF validation failed."),
				"404": errorResponse("Site not found."),
			},
		},
	},
	"/sites/{id}/certificate/renew": {
		post: {
			summary: "Renew a site's Let's Encrypt certificate",
			description:
				"Requires manager-level access to this site. Only valid when the site's current certificate source is letsencrypt; reuses the stored ACME email/directory URL.",
			tags: ["TLS"],
			operationId: "renewSiteCertificate",
			parameters: [siteIdPathParam],
			responses: {
				"200": jsonResponse("", ref("TlsSite")),
				"400": errorResponse("This site does not have a Let's Encrypt certificate, or renewal failed."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("Site not found."),
			},
		},
	},
	"/sites/{id}/certificate": {
		delete: {
			summary: "Remove a site's TLS certificate",
			description: "Requires manager-level access to this site. Disables TLS mode and force-HTTPS. Blocked while a stream still depends on this certificate.",
			tags: ["TLS"],
			operationId: "deleteSiteCertificate",
			parameters: [siteIdPathParam],
			responses: {
				"200": jsonResponse("", ref("TlsSite")),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("Forbidden, or CSRF validation failed."),
				"404": errorResponse("Site not found."),
				"409": errorResponse("A stream still depends on this site's certificate; the error message names the dependent stream(s) and their ports."),
			},
		},
	},
};
