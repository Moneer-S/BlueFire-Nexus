import type { CompositionEvidenceContext } from "../src/lib/composition-evidence";
import { attemptFixture, contextFixture, objectiveFixture, proposalFixture, testDigest } from "./composition-fixture";
import { knowledgeResponse } from "./composition-knowledge-fixture";

export function evidenceFixture() {
  const objective = objectiveFixture();
  objective.attempts = [1, 2].map(index => {
    const attempt = attemptFixture();
    attempt.job_id = `job-${String(index).repeat(32)}`;
    attempt.request.composition_attempt.attempt_id = `attempt-${String(index).repeat(32)}`;
    attempt.request.composition_attempt.run_id = `run-history-${index}`;
    (attempt.progress.verified_result as { run_id: string }).run_id = attempt.request.composition_attempt.run_id;
    return attempt;
  });
  const prior = objective.attempts[1]!.request.composition_attempt.attempt_id;
  const knowledge = knowledgeResponse(objective, [objective.attempts[0]!.request.composition_attempt.attempt_id]);
  const base = contextFixture();
  const context: CompositionEvidenceContext = { ...base, initial_proposal: null, initial_scenario: null, schema_version: "bluefire.composition-evidence-proposal-context.v1", context_digest: `sha256:${"e".repeat(64)}`, facts: { ...base.facts, prior_attempt_id: prior }, historical_context: { knowledge_digest: knowledge.knowledge_digest, attempt_ids: knowledge.attempts.map(attempt => attempt.attempt_id), attempts: knowledge.attempts, choices: [{ attempt_id: knowledge.attempts[0]!.attempt_id, compiled_digest: testDigest, semantic_digest: testDigest, step_id: "seed", behavior_id: base.snapshot.methods[0]!.behavior_id, parameters: { record_count: 8 }, inputs: {} }] } };
  const proposal = proposalFixture();
  proposal.job.request.submitted_request = { ...(proposal.job.request.submitted_request as Record<string, unknown>), schema_version: "bluefire.composition-evidence-proposal-request.v1", prior_attempt_id: prior, context_digest: context.context_digest, attempt_ids: context.historical_context.attempt_ids, knowledge_digest: knowledge.knowledge_digest };
  proposal.job.request.context = context;
  proposal.proposal = { ...proposal.proposal!, schema_version: "bluefire.composition-ai-result.v2", model_context_digest: testDigest, prior_attempt_id: prior, context_digest: context.context_digest, knowledge_digest: knowledge.knowledge_digest, reconsideration: { reconsidered_choices: [{ attempt_id: knowledge.attempts[0]!.attempt_id, compiled_digest: testDigest, step_id: "seed", finding_refs: [{ finding_id: knowledge.attempts[0]!.findings[0]!.finding_id, record_ref: knowledge.attempts[0]!.findings[0]!.record_ref }], reason: "Reconsider the original collection choice using the saved observation." }], refresh_requirements: [{ prerequisite: "retained_receiver_control", explanation: "Recheck the retained receiver before dispatch." }, { prerequisite: "runner_environment", explanation: "Recheck the runner environment before dispatch." }, { prerequisite: "attempt_cleanup", explanation: "Verify cleanup from the latest settled attempt." }] } };
  Object.assign(proposal.proposal.provider, { usage: { input_tokens: 100, output_tokens: 250, total_tokens: 350 } });
  return { objective, knowledge, context, proposal, prior };
}
