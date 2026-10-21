import { jsonResponse } from "../utils/http.ts";
import { parseSearch, SearchSyntaxError, type ParsedSearch, type SearchSchema } from "../services/search-query.ts";

export function searchParam(url: URL, schema: SearchSchema): ParsedSearch | Response {
	try {
		return parseSearch(url.searchParams.get("search"), schema);
	} catch (error) {
		if (error instanceof SearchSyntaxError) {
			return jsonResponse({ error: `Invalid search: ${error.message}`, code: "invalid_search", position: error.position }, 400);
		}
		throw error;
	}
}
