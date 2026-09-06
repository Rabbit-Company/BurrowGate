import { errorResponse, jsonBody, jsonResponse, ref, type PathItemObject } from "../types.ts";

export const apiTokenPaths: Record<string, PathItemObject> = {
	"/me/api-tokens": {
		get: {
			summary: "List your own API tokens",
			tags: ["API tokens"],
			operationId: "listApiTokens",
			responses: {
				"200": jsonResponse("The caller's own tokens (never another user's).", {
					type: "object",
					required: ["tokens"],
					properties: { tokens: { type: "array", items: ref("ApiToken") } },
				}),
				"401": errorResponse("Not signed in."),
			},
		},
		post: {
			summary: "Create an API token",
			description:
				"A monitoring-scope token may only be created by an administrator. A full-access token may be created by any enabled user, for themself, and inherits exactly that user's own role and site/stream permissions.",
			tags: ["API tokens"],
			operationId: "createApiToken",
			requestBody: jsonBody(ref("ApiTokenInput")),
			responses: {
				"201": jsonResponse("The plaintext token is included once, in the `token` field. It is never shown again.", ref("ApiTokenCreated")),
				"400": errorResponse("Invalid name, scope, or expiry - or a non-administrator attempted to create a monitoring-scope token."),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("CSRF validation failed (session-authenticated requests only; does not apply to a bearer-token request)."),
			},
		},
	},
	"/me/api-tokens/{id}": {
		delete: {
			summary: "Revoke an API token",
			description: "Revocation takes effect immediately. Only the token's own owner may revoke it.",
			tags: ["API tokens"],
			operationId: "revokeApiToken",
			parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
			responses: {
				"200": jsonResponse("Revoked.", { type: "object", required: ["ok"], properties: { ok: { type: "boolean", const: true } } }),
				"401": errorResponse("Not signed in."),
				"403": errorResponse("CSRF validation failed (session-authenticated requests only)."),
				"404": errorResponse("No token with this ID owned by the caller."),
			},
		},
	},
};
