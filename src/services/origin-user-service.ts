import type { SiteRecord } from "../types.ts";
import { hmacSha256Hex, timingSafeEqualText } from "../utils/crypto.ts";

// The origin reports its own signed-in user back to BurrowGate with these
// response headers. They are verified, recorded on the request event, and
// always removed before the response reaches the client.
export const ORIGIN_USER_HEADER = "x-burrowgate-origin-user";
export const ORIGIN_USER_SIGNATURE_HEADER = "x-burrowgate-origin-user-signature";
const ORIGIN_USERNAME_PATTERN = /^[^\u0000-\u001f\u007f]{1,255}$/u;

/**
 * Returns the username the origin reported for this request, or null when the
 * origin sent none or its signature does not match. The signature is an
 * HMAC-SHA256 over the request's own `X-BurrowGate-Signature` and the username,
 * keyed with the site's origin signing secret, so a report cannot be replayed
 * onto another request.
 */
export async function verifiedOriginUser(site: SiteRecord, requestSignature: string | null, responseHeaders: Headers): Promise<string | null> {
	const username = responseHeaders.get(ORIGIN_USER_HEADER);
	const signature = responseHeaders.get(ORIGIN_USER_SIGNATURE_HEADER);
	if (!username || !signature || !requestSignature || !ORIGIN_USERNAME_PATTERN.test(username)) return null;
	const expected = await hmacSha256Hex(site.origin_signing_secret, [requestSignature, username].join("\n"));
	return (await timingSafeEqualText(expected, signature.toLowerCase())) ? username : null;
}
