# Searching lists

Every searchable list in the dashboard (Recent traffic, sessions, IP rules, bandwidth, the audit log, notifications, stream events, stream rules, stream bandwidth, and Logs) shares one query language in its search box. Plain words work as before and match anywhere in the list's main text columns. The other filters on the page still apply, and are combined with the search.

Click the **?** next to a search box to see the syntax and that list's fields.

## Syntax

| Query                                   | Meaning                                                  |
| --------------------------------------- | -------------------------------------------------------- |
| `health`                                | Free text, matched as a substring                        |
| `path:/api/login`                       | Field equals the value, ignoring case                    |
| `path:/health*`                         | `*` matches any characters and `?` matches one character |
| `-path:/health*` or `NOT path:/health*` | Exclude matches                                          |
| `user:*`                                | The field has a value                                    |
| `-user:*`                               | The field is empty                                       |
| `-user:alice`                           | Exclude one value. Rows without a user are kept          |
| `status:>=500`, `latency:<100`          | Compare numbers (`>`, `>=`, `<`, `<=`)                   |
| `status:400..499`, `status:4xx`         | Number ranges                                            |
| `ip:10.0.0.0/8`, `ip:10.0.*`            | IPv4 CIDR on /8, /16, /24 or /32, or a wildcard          |
| `path:(/a OR /b)`                       | Several values for one field                             |
| `a OR (b AND NOT c)`                    | Boolean logic. Terms side by side are ANDed              |
| `path:"/a b"`                           | Quotes keep spaces and turn wildcards off                |
| `path:/a\*`                             | A backslash makes the next character literal             |

A word that looks like `name:value` but whose name is not a field of that list, such as `usr:alice`, is searched as plain text and a warning appears under the box. IPv6 addresses and URLs are always searched as text. Invalid syntax shows the problem under the box and the list does not load until it is fixed.

## Filtering from a request

In a request's detail view, every field has **+** and **−** buttons. **+** shows only requests with that value and **−** hides them. On an empty field they become "has no value" and "has a value". The clause is added to the search box, replacing its opposite if present.

## Logs

The Logs page searches `level` and `message`. Any other field name is looked up in the entry's metadata, and nested keys work too, for example `siteId:abc` or `error.code:*`.

## API

Each list endpoint's `search` parameter accepts the same syntax. `GET /_burrowgate/api/admin/search-fields` returns every list's fields. Invalid syntax returns `400` with `code: "invalid_search"` and the character `position`, and successful responses include `searchWarnings`.

## Limits

A query can be up to 2,000 characters, with at most 64 terms nested at most 8 groups deep. Field matching is case-insensitive and cannot use the database indexes, so on very large traffic tables a narrow date range keeps searches fast. The same was already true of free-text search.
