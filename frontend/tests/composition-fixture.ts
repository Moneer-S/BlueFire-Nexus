import { demoCatalog, demoScenario } from "../src/lib/demo";
import type { CompositionAttempt, CompositionContext, CompositionObjective, CompositionProposal, CompositionRefusal, CompositionReview } from "../src/lib/composition";

export const controlId = `job-${"a".repeat(32)}`;
export const ownerId = `job-${"b".repeat(32)}`;
export const proposalId = `job-${"c".repeat(32)}`;
export const testDigest = `sha256:${"d".repeat(64)}`;
export const question = "Preserve record count with redacted delivery";
export function reviewFixture(): CompositionReview {
  return {
    schema_version: "bluefire.composition-review.v1", review_digest: testDigest,
    objective: { question, predicate: { kind: "redacted_delivery_preserves_records", record_count: 8 } },
    environment: { control_owner_id: controlId, runner_id: "local-runner", policy_id: "redacted-only.v1", policy_digest: testDigest, port: 8844 },
    limits: { max_attempts: 3, max_business_steps: 24, cleanup_reserve_ms: 10000 },
    snapshot: { snapshot_digest: testDigest, artifact_context: {}, methods: [{ behavior_id: demoCatalog.behaviors[0]!.id, action_id: demoCatalog.actions[0]!.id, behavior: demoCatalog.behaviors[0]!, action: demoCatalog.actions[0]!, implementation_digest: testDigest, parameter_domains: { record_count: [8] }, cost: {} }] },
    limitations: [],
  };
}
export function objectiveFixture(): CompositionObjective {
  const review = reviewFixture();
  return { schema_version: "bluefire.composition-objective.v1", owner: { job_id: ownerId, kind: "composition.objective", state: "completed", request: { grant_id: `grant-${"b".repeat(32)}`, grant_digest: testDigest }, progress: {} }, grant: { status: "active", usage: { attempts: 0 }, cleanup_state: "settled", document: { ...review, grant_id: `grant-${"b".repeat(32)}`, grant_digest: testDigest, approved_by: "operator", created_at_ms: Date.now(), expires_at_ms: Date.now() + 900000 } }, attempts: [] };
}
export function contextFixture(): CompositionContext {
  const review = reviewFixture();
  return { schema_version: "bluefire.composition-proposal-context.v1", context_digest: testDigest, grant_id: `grant-${"b".repeat(32)}`, objective: review.objective, snapshot: review.snapshot, facts: { facts: [{ fact_id: "policy", kind: "retained_policy", value: { status: "retained" } }] }, initial_proposal: { schema_version: "bluefire.composition-proposal.v1", title: "Established graph", start: "seed", steps: [{ id: "seed", behavior_id: review.snapshot.methods[0]!.behavior_id, parameters: { record_count: 8 } }], edges: [], rationale: "Existing saved graph", evidence_refs: ["policy"] }, initial_scenario: demoScenario };
}
export function proposalFixture(): CompositionProposal {
  const context = contextFixture();
  return { job: { job_id: proposalId, kind: "composition.proposal", state: "completed", request: { owner_id: ownerId, submitted_request: { submission_id: "cccccccc-cccc-cccc-cccc-cccccccccccc", provider_id: "configured", context_digest: testDigest, prior_attempt_id: null } }, progress: {} }, candidate_ready: true, provider_outcome: "candidate", proposal: { schema_version: "bluefire.composition-ai-result.v1", proposal_job_id: proposalId, owner_id: ownerId, context_digest: testDigest, prior_attempt_id: null, candidate: context.initial_proposal!, scenario: context.initial_scenario!, proposal_digest: testDigest, provider: { provider_id: "configured", kind: "openai", model: "configured-model", used_fallback: false, attempts: 1 } } };
}
export function attemptFixture(accepted = false): CompositionAttempt {
  const checks = Object.fromEntries(["receiver_verified", "policy_unchanged", "data_class_preserved", "record_count_preserved", "all_records_redacted", "accepted", "run_cleaned", "receiver_closed"].map(key => [key, accepted || !["all_records_redacted", "accepted"].includes(key)]));
  return { job_id: proposalId, kind: "composition.attempt", state: "completed", request: { composition_attempt: { parent_job_id: ownerId, grant_id: `grant-${"b".repeat(32)}`, grant_digest: testDigest, attempt_id: `attempt-${"c".repeat(32)}`, compiled_digest: testDigest, run_id: "run-proof" } }, progress: { settlement: "settled", verified_result_digest: testDigest, verified_result: { run_id: "run-proof", receiver_result: { decision: accepted ? "accepted" : "policy_refused", policy_digest: testDigest, record_count: 8, redacted_record_count: accepted ? 8 : 0, retained_record_count: accepted ? 0 : 8, empty_record_count: 0 }, cleanup: { run: "complete", receiver: "verified_closed" }, objective: { established: accepted, checks } } } };
}
export function grantRequestFixture() {
  return { submission_id: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", review: { control_owner_id: controlId, question, limits: null }, reviewed_by: "operator", review_digest: testDigest };
}
export function refusalFixture(): CompositionRefusal {
  return { schema_version: "bluefire.composition-objective.v1", grant: null, attempts: [], owner: { job_id: ownerId, kind: "composition.objective", state: "completed", request: {}, progress: { submitted_request: grantRequestFixture(), admission: { accepted: false, problem: { code: "composition_review_changed", message: "Composition context changed; review the current delegation." } } } } };
}
