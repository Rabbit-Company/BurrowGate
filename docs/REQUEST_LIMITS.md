# Request and form input limits

Request limits put ceilings on what a client can send before the origin spends any memory on the request. They are set per site under **HTTP -> Request limits**, and route policies can inherit or override each one. Every numeric limit defaults to `0`, meaning unlimited.

| Limit                           | Checked against                                                                                          | Response                                |
| ------------------------------- | -------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| Maximum body (bytes)            | Declared `Content-Length`, and the bytes actually streamed for chunked bodies                            | `413`                                   |
| Maximum request target (bytes)  | Path plus query string                                                                                   | `414`                                   |
| Maximum request headers (bytes) | Combined parsed header names and values                                                                  | `431`                                   |
| Maximum header count            | Number of parsed request headers                                                                         | `431`                                   |
| Maximum input fields            | Query-string fields, and URL-encoded form body fields, each counted separately                           | `414` for the query, `413` for the body |
| Maximum multipart parts         | Parts of a `multipart/form-data` body                                                                    | `413`                                   |
| Maximum input nesting depth     | Brackets in a field name such as `a[b][c]`, in the query, URL-encoded bodies, and multipart part headers | `400`                                   |
| Blocked multipart fields        | Field names that reject a multipart body when they appear in it                                          | `403`                                   |

Rejected requests are recorded in Recent Traffic with the `request-limited` decision.

## How form bodies are inspected

Bodies are inspected chunk by chunk as they stream to the origin, without buffering. Each chunk is inspected before it is forwarded, so the chunk that crosses a limit never reaches the origin. For bodies of 1 MiB or less with a `Content-Length`, the whole body is inspected before the origin is contacted. For larger or chunked bodies the origin has already received the earlier, accepted chunks when the upload is cut off.

BurrowGate decides that a body is a form, and finds its multipart boundary, the same way PHP's request parser does. Where the two parsers could still read a body differently, BurrowGate counts conservatively, as follows.

- Fields are split on both `&` and `;`, and an encoded `%5B` in a key counts as a bracket.
- Every occurrence of `--boundary` counts as a part delimiter, including the closing one. A body with N parts therefore counts as N + 1.
- Brackets are summed over a part's whole header block, so a field name folded across header lines is measured in full. Brackets in a `filename` count too.

When any form limit applies to a body, BurrowGate also rejects form bodies it cannot inspect reliably:

- a form body with a `Content-Encoding` other than `identity` (`415`), because some web servers decompress request bodies before PHP reads them
- a multipart body with a missing, unterminated, or longer than 200-character boundary (`400`)

### Blocked multipart fields

A blocked name is matched case-insensitively against the raw multipart body, not against parsed part headers. This prevents a crafted header encoding from hiding the field from BurrowGate while the origin still reads it. It also means any multipart body containing the name is rejected, including an uploaded file that happens to contain it, so only list distinctive names. A list holds up to 32 names of 1 to 128 visible ASCII characters.

## PHP origins

The **Apply PHP preset** button fills in the proxy-side measures from the PHP security advisory of 21 October 2026 (CVE-2026-109618 and CVE-2026-109619):

| Setting                     | Preset value                                        |
| --------------------------- | --------------------------------------------------- |
| Maximum body                | 8 MiB (raise to 32 MiB if the site accepts uploads) |
| Maximum header count        | 100                                                 |
| Maximum input fields        | 1000                                                |
| Maximum multipart parts     | 1000                                                |
| Maximum input nesting depth | 16                                                  |
| Blocked multipart fields    | `PHP_SESSION_UPLOAD_PROGRESS`                       |

The preset only fills in the form. Review the values and save the site to apply them.

These limits reduce exposure but do not fix the vulnerabilities, so update PHP as well. CVE-2026-109618 is reached by driving PHP out of memory while it parses a request. The limits bound how much request data PHP has to parse, but a large legitimate request or an application-level allocation can still reach the vulnerable path. CVE-2026-109619 is reached through fatal errors, timeouts and early diagnostics in a worker. Blocking `PHP_SESSION_UPLOAD_PROGRESS` covers the confirmed session upload-progress path, the proxy-side equivalent of `session.upload_progress.enabled=0`. A proxy cannot see the other variants. If the site sets a custom `session.upload_progress.name`, block that name instead.
