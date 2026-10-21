import type { PathItemObject } from "../types.ts";

export const SEARCH_PARAMETER_DESCRIPTION =
	"Dashboard search. Free text, field:value terms, -field:value to exclude, field:* and -field:* for has / has no value, * and ? wildcards, number comparisons (status:>=500, status:4xx), and AND / OR / NOT with parentheses. GET /search-fields lists the fields for each list. Invalid syntax returns 400 with code invalid_search.";

export const searchPaths: Record<string, PathItemObject> = {
	"/search-fields": {
		get: {
			summary: "List searchable fields",
			description: "Returns, for every searchable dashboard list, the fields its search parameter accepts, with their types and descriptions.",
			tags: ["Search"],
			operationId: "listSearchFields",
			responses: {
				"200": {
					description: "Field catalog per list.",
					content: {
						"application/json": {
							schema: {
								type: "object",
								required: ["schemas"],
								properties: {
									schemas: {
										type: "array",
										items: {
											type: "object",
											required: ["id", "label", "dynamicFields", "fields"],
											properties: {
												id: { type: "string" },
												label: { type: "string" },
												dynamicFields: { type: "boolean", description: "Whether any other dotted name is accepted and looked up in entry metadata." },
												fields: {
													type: "array",
													items: {
														type: "object",
														required: ["name", "aliases", "type", "description"],
														properties: {
															name: { type: "string" },
															aliases: { type: "array", items: { type: "string" } },
															type: { type: "string", enum: ["text", "number", "ip", "country", "status"] },
															description: { type: "string" },
															values: { type: "array", items: { type: "string" } },
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
				"401": { description: "Not signed in." },
			},
		},
	},
};
