# Managed request protection

Managed request protection evaluates HTTP requests against a versioned rule set before authentication, cache lookup, or origin forwarding. New and existing sites default to **Monitor** mode: matching requests continue normally, while BurrowGate records what the rule set would have blocked. Switch a site or an individual route to **Block** only after reviewing its monitored traffic.

## Modes and scope

- **Disabled** skips inspection.
- **Monitor** records clean and matched requests without changing the response.
- **Block** returns a generic `403` response for matches and does not contact the origin.
- Route policies can inherit the site mode or override it with any mode.
- Rule IDs can be excluded at site and route level. Route exclusions are added to site exclusions.

The bundled `burrowgate-core` rule set is intentionally small. It detects common traversal, sensitive-file probing, query-string injection, and ambiguous request-framing indicators. It inspects the request target, query parameters, and selected framing headers with bounded input sizes. It does not inspect request bodies and is not a replacement for OWASP CRS.

## Review workflow

The **Protection** dashboard shows inspected, would-block, and blocked totals together with the most frequently matched primary rules. Recent Traffic can be filtered by protection outcome, and each event retains the rule-set ID/version plus all matches. Matching input values are not stored, returned to blocked clients, or used as OpenMetrics labels.

A practical rollout is:

1. Leave the site in Monitor mode.
2. Review would-block events across representative traffic.
3. Exclude a rule only for a documented application incompatibility, preferably on the narrowest route.
4. Change the route or site to Block mode.
5. Keep monitoring blocked requests and revisit exclusions after rule-set upgrades.
