import type { RoutePolicyRecord, SiteRecord } from "../types.ts";
import { crowdSecDecisions, type CrowdSecDecision } from "./crowdsec-decision-store.ts";

/**
 * Per-site and per-route handling of CrowdSec decisions, shaped like `network-privacy-service`.
 *
 * Ban and captcha are configured separately because a ban ends the request while a captcha only
 * sends the visitor through the challenge chain, which is worth enabling on its own.
 */

export type CrowdSecBanMode = "disabled" | "monitor" | "block";
export type CrowdSecCaptchaMode = "disabled" | "monitor" | "challenge";

export interface CrowdSecPolicy {
	ban: CrowdSecBanMode;
	captcha: CrowdSecCaptchaMode;
	/**
	 * Forward the request to CrowdSec's AppSec component for inspection.
	 *
	 * Off by default and opt-in per route, because unlike the other two this costs an HTTP
	 * round-trip on every matching request rather than a memory lookup.
	 */
	appsec: CrowdSecBanMode;
}

export type CrowdSecEnforcement = "none" | "monitor" | "block" | "challenge";

export interface CrowdSecEvaluation {
	decision: CrowdSecDecision | null;
	enforcement: CrowdSecEnforcement;
	/** True when an explicit allow/pass rule kept an otherwise-enforced decision from acting. */
	bypassed: boolean;
}

/** New and existing sites start in monitor, so enabling the integration changes nothing until an operator opts a site in. */
export const DEFAULT_CROWDSEC_POLICY: CrowdSecPolicy = { ban: "monitor", captcha: "monitor", appsec: "disabled" };

function banMode(value: unknown, fallback: CrowdSecBanMode): CrowdSecBanMode {
	if (value === undefined) return fallback;
	const normalized = String(value).trim().toLowerCase();
	if (normalized === "disabled" || normalized === "monitor" || normalized === "block") return normalized;
	throw new Error("The CrowdSec ban mode must be disabled, monitor, or block");
}

function captchaMode(value: unknown, fallback: CrowdSecCaptchaMode): CrowdSecCaptchaMode {
	if (value === undefined) return fallback;
	const normalized = String(value).trim().toLowerCase();
	if (normalized === "disabled" || normalized === "monitor" || normalized === "challenge") return normalized;
	throw new Error("The CrowdSec captcha mode must be disabled, monitor, or challenge");
}

export function parseCrowdSecPolicy(value: unknown, fallback: CrowdSecPolicy = DEFAULT_CROWDSEC_POLICY): CrowdSecPolicy {
	if (value === undefined) return { ...fallback };
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("The CrowdSec policy must be an object");
	const input = value as Record<string, unknown>;
	return {
		ban: banMode(input.ban, fallback.ban),
		captcha: captchaMode(input.captcha, fallback.captcha),
		appsec: banMode(input.appsec, fallback.appsec),
	};
}

export function storedCrowdSecPolicy(json: string | null | undefined, fallback: CrowdSecPolicy = DEFAULT_CROWDSEC_POLICY): CrowdSecPolicy {
	if (!json) return { ...fallback };
	try {
		return parseCrowdSecPolicy(JSON.parse(json), fallback);
	} catch {
		return { ...fallback };
	}
}

export function serializeCrowdSecPolicy(value: unknown, fallback?: string | null): string {
	return JSON.stringify(parseCrowdSecPolicy(value, storedCrowdSecPolicy(fallback)));
}

export function serializeRouteCrowdSecPolicy(value: unknown, fallback?: string | null): string | null {
	if (value === undefined) return fallback ?? null;
	if (value === null || value === "") return null;
	return JSON.stringify(parseCrowdSecPolicy(value));
}

/** A route's policy replaces the site's rather than merging with it, matching how route policies behave elsewhere. */
export function resolvedCrowdSecPolicy(site: SiteRecord, route: RoutePolicyRecord | null): CrowdSecPolicy {
	return route?.crowdsec_policy_json ? storedCrowdSecPolicy(route.crowdsec_policy_json) : storedCrowdSecPolicy(site.crowdsec_policy_json);
}

/**
 * An operator's own IP/ASN allow rule outranks a remote blocklist, so a community-list false
 * positive cannot lock someone out of their own site. Same rule network privacy applies.
 */
export function crowdSecBlockIsBypassed(source: string, action: string | null): boolean {
	return ["ip-rule", "asn-rule"].includes(source) && (action === "allow" || action === "pass");
}

function enforcementFor(decision: CrowdSecDecision, policy: CrowdSecPolicy): CrowdSecEnforcement {
	if (decision.remediation === "ban") {
		if (policy.ban === "block") return "block";
		return policy.ban === "monitor" ? "monitor" : "none";
	}
	if (policy.captcha === "challenge") return "challenge";
	return policy.captcha === "monitor" ? "monitor" : "none";
}

/** `countryCode` and `asn` come from the request's network decision, so those scopes need no extra GeoIP work. */
export function evaluateCrowdSec(
	ip: string,
	countryCode: string | null,
	asn: number | null,
	policy: CrowdSecPolicy,
	source: string,
	action: string | null,
	now = Date.now(),
): CrowdSecEvaluation {
	if (policy.ban === "disabled" && policy.captcha === "disabled") return { decision: null, enforcement: "none", bypassed: false };
	if (crowdSecDecisions.empty) return { decision: null, enforcement: "none", bypassed: false };

	const decision = crowdSecDecisions.lookup(ip, countryCode, asn, now);
	if (!decision) return { decision: null, enforcement: "none", bypassed: false };

	const enforcement = enforcementFor(decision, policy);
	if ((enforcement === "block" || enforcement === "challenge") && crowdSecBlockIsBypassed(source, action)) {
		// Still reported, so the dashboard shows the match and the override.
		return { decision, enforcement: "monitor", bypassed: true };
	}
	return { decision, enforcement, bypassed: false };
}

export interface CrowdSecEventDetail {
	remediation: string;
	scope: string;
	value: string;
	origin: string;
	scenario: string;
	enforcement: CrowdSecEnforcement;
	bypassed?: true;
}

/** Record of the match for `request_events.crowdsec_json`. */
export function crowdSecEventDetail(evaluation: CrowdSecEvaluation): CrowdSecEventDetail | null {
	if (!evaluation.decision) return null;
	const { remediation, scope, value, origin, scenario } = evaluation.decision;
	return {
		remediation,
		scope,
		value,
		origin,
		scenario,
		enforcement: evaluation.enforcement,
		...(evaluation.bypassed ? { bypassed: true as const } : {}),
	};
}

/** Reason text for the block page and the traffic log. */
export function crowdSecReason(decision: CrowdSecDecision): string {
	const scenario = decision.scenario ? ` for ${decision.scenario}` : "";
	const origin = decision.origin === "CAPI" ? "the CrowdSec community blocklist" : `CrowdSec (${decision.origin})`;
	return `This request was blocked by ${origin}${scenario}.`;
}

/**
 * Stream policy. A TCP or UDP stream has no challenge chain, so a `captcha` decision cannot be
 * served the way it is over HTTP. Its mode is therefore block rather than challenge, and it
 * defaults to monitor so a captcha never silently escalates into a dropped connection.
 */
export interface StreamCrowdSecPolicy {
	ban: CrowdSecBanMode;
	captcha: CrowdSecBanMode;
}

export const DEFAULT_STREAM_CROWDSEC_POLICY: StreamCrowdSecPolicy = { ban: "monitor", captcha: "monitor" };

export function parseStreamCrowdSecPolicy(value: unknown, fallback: StreamCrowdSecPolicy = DEFAULT_STREAM_CROWDSEC_POLICY): StreamCrowdSecPolicy {
	if (value === undefined) return { ...fallback };
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("The CrowdSec policy must be an object");
	const input = value as Record<string, unknown>;
	return { ban: banMode(input.ban, fallback.ban), captcha: banMode(input.captcha, fallback.captcha) };
}

export function storedStreamCrowdSecPolicy(
	json: string | null | undefined,
	fallback: StreamCrowdSecPolicy = DEFAULT_STREAM_CROWDSEC_POLICY,
): StreamCrowdSecPolicy {
	if (!json) return { ...fallback };
	try {
		return parseStreamCrowdSecPolicy(JSON.parse(json), fallback);
	} catch {
		return { ...fallback };
	}
}

export function serializeStreamCrowdSecPolicy(value: unknown, fallback?: string | null): string {
	return JSON.stringify(parseStreamCrowdSecPolicy(value, storedStreamCrowdSecPolicy(fallback)));
}

function streamEnforcementFor(decision: CrowdSecDecision, policy: StreamCrowdSecPolicy): CrowdSecEnforcement {
	const mode = decision.remediation === "ban" ? policy.ban : policy.captcha;
	if (mode === "block") return "block";
	return mode === "monitor" ? "monitor" : "none";
}

/** The stream equivalent of `evaluateCrowdSec`, using the ASN and country the stream already resolved. */
export function evaluateStreamCrowdSec(
	ip: string,
	countryCode: string | null,
	asn: number | null,
	policy: StreamCrowdSecPolicy,
	source: string,
	action: string | null,
	now = Date.now(),
): CrowdSecEvaluation {
	if (policy.ban === "disabled" && policy.captcha === "disabled") return { decision: null, enforcement: "none", bypassed: false };
	if (crowdSecDecisions.empty) return { decision: null, enforcement: "none", bypassed: false };

	const decision = crowdSecDecisions.lookup(ip, countryCode, asn, now);
	if (!decision) return { decision: null, enforcement: "none", bypassed: false };

	const enforcement = streamEnforcementFor(decision, policy);
	if (enforcement === "block" && crowdSecBlockIsBypassed(source, action)) {
		return { decision, enforcement: "monitor", bypassed: true };
	}
	return { decision, enforcement, bypassed: false };
}

/** Reason text for a blocked stream connection. */
export function crowdSecStreamBlockedReason(evaluation: CrowdSecEvaluation): string | null {
	if (evaluation.enforcement !== "block" || !evaluation.decision) return null;
	const { origin, scenario } = evaluation.decision;
	const source = origin === "CAPI" ? "the CrowdSec community blocklist" : `CrowdSec (${origin})`;
	return scenario ? `Blocked by ${source} for ${scenario}` : `Blocked by ${source}`;
}
