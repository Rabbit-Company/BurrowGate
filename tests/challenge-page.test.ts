import { describe, expect, test } from "bun:test";
import { DEFAULT_CHALLENGE_HTML_TEMPLATE, renderChallengePage, validateChallengeHtmlTemplate } from "../src/services/challenge-page-service.ts";
import { powSha256Provider } from "../src/challenges/providers/pow-sha256.ts";
import type { ChallengeFlowRecord, ChallengeStepRecord, SiteRecord } from "../src/types.ts";

function site(overrides: Partial<SiteRecord> = {}): SiteRecord {
	return {
		id: "site-challenge-test",
		name: "Challenge test",
		public_host: "example.test",
		origin_url: "http://127.0.0.1:3000",
		origin_signing_secret: "test-signing-secret-that-is-at-least-32-characters",
		ip_extraction_preset: "direct",
		enabled: 1,
		session_ttl_seconds: 3_600,
		challenge_policy_json: "[]",
		challenge_auto_ban_enabled: 0,
		challenge_auto_ban_max_failures: 5,
		challenge_auto_ban_seconds: 3_600,
		default_access_mode: "challenge",
		event_retention_days: 7,
		default_ip_action: "inherit",
		default_country_action: "inherit",
		error_response_mode: "json",
		error_html_template: "",
		error_json_fields_json: '["error","status"]',
		challenge_html_template: DEFAULT_CHALLENGE_HTML_TEMPLATE,
		created_at: Date.now(),
		updated_at: Date.now(),
		...overrides,
	};
}

const flow: ChallengeFlowRecord = {
	id: "flow_123",
	site_id: "site-challenge-test",
	return_path: "/dashboard",
	client_ip: "203.0.113.10",
	user_agent_hash: "ua",
	current_step: 0,
	policy_json: "[]",
	status: "pending",
	created_at: Date.now(),
	expires_at: Date.now() + 60_000,
	completed_at: null,
};

const step: ChallengeStepRecord = {
	id: "step_123",
	flow_id: "flow_123",
	step_index: 0,
	provider: "pow-sha256",
	config_json: '{"difficulty":18}',
	private_data_json: '{"seed":"abc","difficulty":18}',
	public_data_json: '{"kind":"pow-sha256","seed":"abc","difficulty":18,"expiresAt":0}',
	status: "pending",
	attempts: 0,
	created_at: Date.now(),
	expires_at: Date.now() + 60_000,
	completed_at: null,
};

describe("custom site challenge pages", () => {
	test("injects the bootstrap and client script and provider copy", () => {
		const html = renderChallengePage(site(), new Request("https://example.test/_burrowgate/verify?flow=flow_123"), flow, step, powSha256Provider);
		expect(html).toContain("window.__BURROWGATE_CHALLENGE__=");
		expect(html).toContain('src="/_burrowgate/static/challenges/pow-sha256.js"');
		expect(html).toContain(powSha256Provider.title);
		expect(html).toContain('id="status"');
		expect(html).toContain('id="attempts"');
		expect(html).not.toContain("{{challengeScript}}");
	});

	test("escapes placeholder values but leaves the injected script intact", () => {
		const html = renderChallengePage(
			site({ name: 'Ha<script>alert("x")</script>' }),
			new Request("https://example.test/_burrowgate/verify?flow=flow_123"),
			flow,
			step,
			powSha256Provider,
		);
		expect(html).toContain("Ha&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;");
		// The only real <script> tags are the two BurrowGate injects.
		expect(html.match(/<script/g)?.length).toBe(2);
	});

	test("neutralizes </script> breakout in bootstrap public data", () => {
		const breakoutStep: ChallengeStepRecord = { ...step, public_data_json: '{"kind":"pow-sha256","seed":"</script><b>","difficulty":18}' };
		const html = renderChallengePage(site(), new Request("https://example.test/"), flow, breakoutStep, powSha256Provider);
		expect(html).not.toContain("</script><b>");
		expect(html).toContain("\\u003c/script>");
	});

	test("requires a non-empty template that contains the script placeholder", () => {
		expect(() => validateChallengeHtmlTemplate("   ")).toThrow();
		expect(() => validateChallengeHtmlTemplate("<h1>{{title}}</h1>")).toThrow();
		expect(validateChallengeHtmlTemplate("<h1>{{title}}</h1>{{challengeScript}}")).toContain("{{challengeScript}}");
		expect(validateChallengeHtmlTemplate(undefined)).toBe(DEFAULT_CHALLENGE_HTML_TEMPLATE);
	});
});
