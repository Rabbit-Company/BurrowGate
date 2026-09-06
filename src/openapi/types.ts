export type JsonSchema = {
	type?: "object" | "array" | "string" | "number" | "integer" | "boolean" | "null" | Array<string>;
	description?: string;
	enum?: readonly (string | number | null)[];
	const?: string | number | boolean | null;
	format?: string;
	default?: unknown;
	example?: unknown;
	minimum?: number;
	maximum?: number;
	minLength?: number;
	maxLength?: number;
	pattern?: string;
	minItems?: number;
	maxItems?: number;
	items?: JsonSchema;
	properties?: Record<string, JsonSchema>;
	required?: readonly string[];
	additionalProperties?: boolean | JsonSchema;
	oneOf?: readonly JsonSchema[];
	anyOf?: readonly JsonSchema[];
	allOf?: readonly JsonSchema[];
	$ref?: string;
};

export function ref(name: string): JsonSchema {
	return { $ref: `#/components/schemas/${name}` };
}

export interface ParameterObject {
	name: string;
	in: "query" | "path" | "header";
	description?: string;
	required?: boolean;
	deprecated?: boolean;
	schema: JsonSchema;
}

export interface MediaTypeObject {
	schema: JsonSchema;
}

export interface RequestBodyObject {
	description?: string;
	required?: boolean;
	content: Record<string, MediaTypeObject>;
}

export interface ResponseObject {
	description: string;
	content?: Record<string, MediaTypeObject>;
}

export interface OperationObject {
	summary: string;
	description?: string;
	tags: readonly string[];
	operationId: string;
	parameters?: readonly ParameterObject[];
	requestBody?: RequestBodyObject;
	responses: Record<string, ResponseObject>;
	security?: readonly Record<string, readonly string[]>[];
}

export type PathItemObject = Partial<Record<"get" | "post" | "put" | "patch" | "delete", OperationObject>>;

export const errorResponse = (description: string): ResponseObject => ({
	description,
	content: { "application/json": { schema: ref("ErrorResponse") } },
});

export const jsonResponse = (description: string, schema: JsonSchema): ResponseObject => ({
	description,
	content: { "application/json": { schema } },
});

export const jsonBody = (schema: JsonSchema, description?: string): RequestBodyObject => ({
	required: true,
	description,
	content: { "application/json": { schema } },
});

/** Every admin endpoint accepts either dashboard session cookie name or a full-access API bearer token. */
export const SESSION_OR_FULL_TOKEN_SECURITY: readonly Record<string, readonly string[]>[] = [
	{ AdminSession: [] },
	{ AdminSessionHttp: [] },
	{ ApiTokenFull: [] },
];
