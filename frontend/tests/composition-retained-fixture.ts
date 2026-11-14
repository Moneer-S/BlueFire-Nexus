import type { CompositionContext, CompositionObjective, CompositionProposal, CompositionReview, CompositionReviewRequest } from "../src/lib/composition";
import type { CompositionEvidenceContext } from "../src/lib/composition-evidence";
import { RECEIVER_RETAINED_PACK, RETAINED_MATERIALIZE_METHOD, retainedPolicy, type RetainedCompositionContinuation, type RetainedCompositionSource } from "../src/lib/composition-retained";
import { attemptFixture, contextFixture, objectiveFixture, proposalFixture, reviewFixture, testDigest } from "./composition-fixture";
import { evidenceFixture } from "./composition-evidence-fixture";
import { knowledgeResponse } from "./composition-knowledge-fixture";

export function retainedReviewFixture(): CompositionReview {
  const review = reviewFixture();
  const method = structuredClone(review.snapshot.methods[0]!);
  method.behavior_id = RETAINED_MATERIALIZE_METHOD; method.action_id = RETAINED_MATERIALIZE_METHOD;
  method.behavior = { ...method.behavior, id: RETAINED_MATERIALIZE_METHOD, title: "Use a retained generated result" };
  method.action = { ...method.action, id: RETAINED_MATERIALIZE_METHOD };
  method.parameter_domains = { source_ref: [] };
  return { ...review, schema_version: "bluefire.composition-review.v2", pack: RECEIVER_RETAINED_PACK, retention: retainedPolicy, native_materialization: { method: RETAINED_MATERIALIZE_METHOD, readiness: "ready", implementation_digest: testDigest }, snapshot: { ...review.snapshot, schema_version: "bluefire.retained-receiver-capability-snapshot.v1", pack: RECEIVER_RETAINED_PACK, methods: [...review.snapshot.methods, method], artifact_context: { environment_digest: testDigest, materialization: "sealed_generated_jsonl_fresh_materialization", data_class: "generated_public_jsonl", retention: retainedPolicy } } };
}
export function retainedRequestFixture(): CompositionReviewRequest {
  const review = retainedReviewFixture();
  return { schema_version: "bluefire.composition-review-request.v2", pack: RECEIVER_RETAINED_PACK, control_owner_id: review.environment.control_owner_id, question: review.objective.question, limits: null };
}
export function retainedObjectiveFixture(): CompositionObjective {
  const objective = objectiveFixture(), review = retainedReviewFixture();
  objective.grant.document = { ...objective.grant.document, schema_version: "bluefire.capability-grant.v2", pack: RECEIVER_RETAINED_PACK, snapshot: review.snapshot };
  return objective;
}
export function retainedFixture(history = false) {
  const base = evidenceFixture();
  const objective = retainedObjectiveFixture();
  objective.attempts = base.objective.attempts;
  objective.attempts.forEach((attempt, index) => {
    attempt.request.composition_attempt.run_id = `run-20261029T12000${index}Z-${String(index + 1).repeat(16)}`;
    attempt.state = "failed"; delete attempt.progress.verified_result; delete attempt.progress.verified_result_digest;
  });
  const source: RetainedCompositionSource = { run_id: objective.attempts[0]!.request.composition_attempt.run_id, attempt_id: objective.attempts[0]!.request.composition_attempt.attempt_id, lineage_id: `lineage-${"1".repeat(32)}`, step_id: "stage", artifact: "bundle", artifact_type: "artifact.sandbox.bundle.v1", sha256: "a".repeat(64), size_bytes: 128, source_ref: testDigest };
  objective.attempts.forEach(attempt => {
    const continuation: RetainedCompositionContinuation = { schema_version: "bluefire.retained-continuation.v1", source, prior_run_id: attempt.request.composition_attempt.run_id, later_failure: { step_id: "deliver", outcome: "failed" }, receiver_decision: "unknown", cleanup: { run: "complete", receiver: "verified_closed" }, continuation_digest: testDigest };
    attempt.progress.retained_continuation = continuation;
  });
  const prior = objective.attempts[1]!.request.composition_attempt.attempt_id;
  const knowledge = knowledgeResponse(objective, [source.attempt_id]);
  const ordinary: CompositionContext = { ...contextFixture(), schema_version: "bluefire.retained-composition-proposal-context.v1", snapshot: objective.grant.document.snapshot, context_digest: base.context.context_digest, initial_proposal: null, initial_scenario: null, facts: { ...base.context.facts, prior_attempt_id: prior }, retained_artifacts: { policy: retainedPolicy, available_sources: [source], availability: "available" } };
  const context: CompositionContext | CompositionEvidenceContext = history ? { ...ordinary, schema_version: "bluefire.retained-composition-evidence-context.v1", historical_context: { ...base.context.historical_context, attempts: knowledge.attempts, knowledge_digest: knowledge.knowledge_digest, attempt_ids: knowledge.attempts.map(attempt => attempt.attempt_id) } } : ordinary;
  const proposal: CompositionProposal = proposalFixture();
  proposal.job.request.context = context;
  proposal.job.request.submitted_request = { submission_id: "cccccccc-cccc-cccc-cccc-cccccccccccc", provider_id: "configured", context_digest: context.context_digest, prior_attempt_id: prior, ...(history ? { schema_version: "bluefire.composition-evidence-proposal-request.v1", knowledge_digest: knowledge.knowledge_digest, attempt_ids: knowledge.attempts.map(attempt => attempt.attempt_id) } : {}) };
  proposal.proposal = { ...proposal.proposal!, schema_version: "bluefire.composition-ai-result.v3", context_digest: context.context_digest, prior_attempt_id: prior, model_context_digest: testDigest, candidate: { ...proposal.proposal!.candidate, title: "Continue with the kept generated result", start: "reuse", steps: [{ id: "reuse", behavior_id: RETAINED_MATERIALIZE_METHOD, parameters: { source_ref: source.source_ref } }] }, reconsideration: history ? base.proposal.proposal!.reconsideration : null, ...(history ? { knowledge_digest: knowledge.knowledge_digest } : {}) };
  if (history) proposal.proposal.reconsideration!.reconsidered_choices[0]!.finding_refs = [{ finding_id: knowledge.attempts[0]!.findings[0]!.finding_id, record_ref: knowledge.attempts[0]!.findings[0]!.record_ref }];
  return { objective, source, prior, knowledge, context, proposal };
}

export function retainedFreshRecoveryFixture() {
  const value = retainedFixture();
  const steps: NonNullable<CompositionProposal["proposal"]>["candidate"]["steps"] = [
    { id: "seed", behavior_id: "sandbox.fixture.create.v1", parameters: { record_count: 8 } },
    { id: "prepare", behavior_id: "sandbox.fixture.transform.v1", parameters: { redact_values: true }, inputs: { workspace: { from_step: "seed", artifact: "workspace" } } },
    { id: "inspect", behavior_id: "sandbox.discovery.list.v1", parameters: {}, inputs: { fixture: { from_step: "prepare", artifact: "fixture" } } },
    { id: "stage", behavior_id: "sandbox.collection.stage.v1", parameters: { bundle_format: "jsonl" }, inputs: { records: { from_step: "inspect", artifact: "records" } } },
    { id: "send", behavior_id: "sandbox.peer.handoff.v1", parameters: { port: 8844 }, inputs: { bundle: { from_step: "stage", artifact: "bundle" } } },
    { id: "clean", behavior_id: "sandbox.cleanup.v1", parameters: { verify_removal: true }, inputs: { workspace: { from_step: "seed", artifact: "workspace" } } },
  ];
  const template = value.objective.grant.document.snapshot.methods[0]!;
  const extra = steps.filter(step => !value.objective.grant.document.snapshot.methods.some(method => method.behavior_id === step.behavior_id)).map(step => ({ ...structuredClone(template), behavior_id: step.behavior_id, action_id: step.behavior_id, behavior: { ...template.behavior, id: step.behavior_id, title: step.id === "prepare" ? "Redact generated values" : `Fresh ${step.id}` }, action: { ...template.action, id: step.behavior_id }, parameter_domains: Object.fromEntries(Object.entries(step.parameters).map(([key, item]) => [key, [item]])) }));
  value.objective.grant.document.snapshot.methods.push(...extra);
  const actual = attemptFixture().progress;
  (actual.verified_result as { run_id: string }).run_id = value.objective.attempts[1]!.request.composition_attempt.run_id;
  Object.assign(value.objective.attempts[1]!.progress, { verified_result: actual.verified_result, verified_result_digest: actual.verified_result_digest });
  const context: CompositionContext = { ...value.context, schema_version: "bluefire.retained-composition-proposal-context.v1", context_digest: `sha256:${"f".repeat(64)}`, facts: { ...value.context.facts, facts: [...value.context.facts.facts, { fact_id: "result", kind: "receiver_result", value: (actual.verified_result as { receiver_result: unknown }).receiver_result }, { fact_id: "cleanup", kind: "cleanup", value: { run: "complete", receiver: "verified_closed" } }] }, retained_artifacts: { ...value.context.retained_artifacts!, available_sources: [], availability: "none_available" } };
  const candidate = { ...value.proposal.proposal!.candidate, title: "Fresh generation within this objective", start: "seed", steps, edges: [...steps.slice(0, -1).map((step, index) => ({ from_step: step.id, outcome: "success" as const, to_step: steps[index + 1]!.id })), ...(["blocked", "failed", "partial"] as const).map(outcome => ({ from_step: "send", outcome, to_step: "clean" }))], evidence_refs: ["policy", "result", "cleanup"], rationale: "Retained bytes are unavailable. Explicitly generate and redact fresh records using the verified prior refusal and cleanup." };
  const proposal = structuredClone(value.proposal);
  proposal.job.request.context = context;
  (proposal.job.request.submitted_request as Record<string, unknown>).context_digest = context.context_digest;
  proposal.proposal = { ...proposal.proposal!, context_digest: context.context_digest, candidate, scenario: { ...proposal.proposal!.scenario, title: candidate.title, start: candidate.start, steps: candidate.steps.map(step => ({ ...step, inputs: step.inputs ?? {}, alternates: [] })), edges: candidate.edges } };
  return { ...value, currentContext: context, freshProposal: proposal };
}
