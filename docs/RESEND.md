# Resend

Every row in the dashboard's **Recent Traffic** table can be replayed directly
from its detail view - useful for iterating on an API endpoint without leaving
the dashboard or reaching for a separate HTTP client.

Resend requires **manage** access to the site (not just view access), since it
is a state-changing action that can repeat a request's real side effects.

## What gets sent

- **Method and path** are taken from the original request.
- **Headers** come from [header capture](HEADER_CAPTURE.md) when it was
  enabled for that request. A redacted header (`Authorization`, `Cookie`,
  ...) shows an empty field labeled as redacted - fill in a real value to
  send it, or leave it blank to omit it entirely. An **Additional / override
  headers** field (`Name: value`, one per line) can add or override any
  header, including ones that were never captured.
- **Content-Type** defaults automatically from the captured body's content
  type (recorded by [body capture](BODY_CAPTURE.md) independently of header
  capture) whenever a body is being sent and nothing else already set it.
- **Body** defaults to the captured request body when [body capture](BODY_CAPTURE.md)
  was enabled, and is always editable before sending.

Nothing is required to have been captured beforehand - a GET with no headers
and no body resends just fine with only the method and path.

## Where the request goes

The request is sent to the site's real public host, exactly the way an
external client would reach it - not to BurrowGate's internal listener
directly. As long as the site's DNS points at this BurrowGate instance (the
normal case), the replayed request still goes through the full pipeline (WAF,
rate limiting, access control) exactly as deployed.

## Redirects

A redirect back to the same public host is followed automatically (up to 10
hops), so testing an endpoint that responds "created, fetch the result here"
doesn't require a second manual resend:

- `303`, and `301`/`302` on a non-`GET`/`HEAD` request, convert to a bodyless
  `GET` for the next hop, matching standard client redirect behavior.
- `307`/`308` always preserve the method and body on the next hop, per spec -
  including when that redirects back to the identical path. If an endpoint
  does this indefinitely, BurrowGate stops after 10 hops rather than looping
  forever; the full chain is still shown so it's clear what happened.
- A redirect to a **different** host is never followed automatically, so
  captured or overridden headers (such as `Authorization`) are never silently
  resent to an unrelated third party. The raw redirect response is shown
  instead.

The full hop-by-hop chain - method, path, status, and the `Location` received

- is shown in the result, along with why a hop wasn't followed when it
  stopped short of a final response.

## Confirmation and auditing

Resending anything other than `GET`/`HEAD` prompts for confirmation first,
since it may repeat a real side effect (a duplicate order, charge, or write).
Every resend is recorded in the admin audit log alongside other
manage-level actions.
