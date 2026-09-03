import { challengeRegistry } from "../challenges/index.ts";
import { config } from "../config.ts";
import { repository } from "../db/repository.ts";
import type { ChallengeFlowRecord, ChallengePolicyStep, ChallengeStepRecord, SiteRecord } from "../types.ts";
import { randomId } from "../utils/crypto.ts";
import { safeReturnPath } from "../utils/http.ts";
import { createAccessSession } from "./session-service.ts";
import { recordChallengeFailure, recordChallengeSuccess } from "./challenge-failure-ban-service.ts";

export async function createFlow(
	site: SiteRecord,
	returnPath: string,
	ip: string,
	uaHash: string,
	policy?: ChallengePolicyStep[],
): Promise<ChallengeFlowRecord> {
	const now = Date.now();
	const policyJson = policy ? JSON.stringify(policy) : site.challenge_policy_json;
	const flow: ChallengeFlowRecord = {
		id: randomId("flow"),
		site_id: site.id,
		return_path: safeReturnPath(returnPath),
		client_ip: ip,
		user_agent_hash: uaHash,
		current_step: 0,
		policy_json: policyJson,
		status: "pending",
		created_at: now,
		expires_at: now + config.challengeTtlSeconds * 1000,
		completed_at: null,
	};
	await repository.insertFlow(flow);
	return flow;
}

export async function currentStep(flow: ChallengeFlowRecord): Promise<ChallengeStepRecord> {
	const existing = await repository.step(flow.id, flow.current_step);
	if (existing) return existing;
	const policy = JSON.parse(flow.policy_json) as ChallengePolicyStep[];
	const spec = policy[flow.current_step];
	if (!spec) throw new Error("Challenge flow has no current step");
	const provider = challengeRegistry.get(spec.provider);
	const material = await provider.create(
		{ flowId: flow.id, siteId: flow.site_id, clientIp: flow.client_ip, userAgentHash: flow.user_agent_hash, expiresAt: flow.expires_at },
		spec.config,
	);
	const now = Date.now();
	const step: ChallengeStepRecord = {
		id: randomId("step"),
		flow_id: flow.id,
		step_index: flow.current_step,
		provider: spec.provider,
		config_json: JSON.stringify(spec.config),
		private_data_json: JSON.stringify(material.privateData),
		public_data_json: JSON.stringify(material.publicData),
		status: "pending",
		attempts: 0,
		created_at: now,
		expires_at: flow.expires_at,
		completed_at: null,
	};
	await repository.insertStep(step);
	return step;
}

export async function verifyFlow(
	request: Request,
	flowId: string,
	answer: unknown,
): Promise<{ done: boolean; redirect?: string; cookie?: string; next?: ChallengeStepRecord; reason?: string }> {
	const flow = await repository.flow(flowId);
	if (!flow || flow.status !== "pending" || flow.expires_at <= Date.now()) return { done: false, reason: "Challenge expired" };
	const site = await repository.siteById(flow.site_id);
	if (!site) return { done: false, reason: "Site no longer exists" };
	const step = await currentStep(flow);
	if (step.attempts >= config.maxChallengeAttempts) return { done: false, reason: "Too many attempts" };
	const provider = challengeRegistry.get(step.provider);
	const result = await provider.verify(
		{
			flowId: flow.id,
			siteId: flow.site_id,
			clientIp: flow.client_ip,
			userAgentHash: flow.user_agent_hash,
			expiresAt: flow.expires_at,
			attempts: step.attempts,
			createdAt: step.created_at,
		},
		JSON.parse(step.config_json),
		JSON.parse(step.private_data_json),
		answer,
	);
	if (!result.success) {
		await repository.failStepAttempt(step.id);
		recordChallengeFailure(site, flow.client_ip);
		return { done: false, reason: result.reason ?? "Verification failed" };
	}
	recordChallengeSuccess(site, flow.client_ip);
	const consumedAt = Date.now();
	if (!(await repository.consumeStep(step.id, consumedAt))) return { done: false, reason: "This proof was already consumed" };
	await repository.completeStep(step.id, consumedAt);
	const policy = JSON.parse(flow.policy_json) as ChallengePolicyStep[];
	if (flow.current_step + 1 < policy.length) {
		await repository.updateFlowStep(flow.id, flow.current_step + 1);
		const updated = { ...flow, current_step: flow.current_step + 1 };
		return { done: false, next: await currentStep(updated) };
	}
	await repository.completeFlow(flow.id, Date.now());
	const session = await createAccessSession(request, site, flow.client_ip, flow.user_agent_hash, { providers: policy.map((p) => p.provider) });
	return { done: true, redirect: flow.return_path, cookie: session.cookie };
}
