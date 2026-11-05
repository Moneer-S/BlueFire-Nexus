/* global structuredClone */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "vitest";
import { URL } from "node:url";
import { EVIDENCE_PURPOSE, receiverEvidenceRequestAllowed, verifyReceiverEvidenceProposal } from "./receiver-evidence-proposal.mjs";

const stable = value => Array.isArray(value) ? value.map(stable) : value !== null && typeof value === "object"
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value;
const hash = value => `sha256:${createHash("sha256").update(JSON.stringify(stable(value))).digest("hex")}`;
const ownerId = `job-${"a".repeat(32)}`;
const attemptId = `attempt-${"b".repeat(32)}`;
const jobId = `job-${"b".repeat(32)}`;
const proposalId = "job-12345678123442348234123456789abc";
const runId = "run-20261029T003000Z-1234567890abcdef";
const origin = "http://127.0.0.1:12345";
const contextDigest = `sha256:${"c".repeat(64)}`;
const knowledgeDigest = `sha256:${"d".repeat(64)}`;

test("history routes require separate authorization and exact settled source selection", () => {
  const expected = { origin, ownerId, attemptId, settlement: "settled", objectiveEstablished: false,
    authorizations: 2, knowledgeDigest, contextDigest, providerId: "owned-provider" };
  const body = { schema_version: "bluefire.composition-evidence-context-query.v1", prior_attempt_id: attemptId,
    attempt_ids: [attemptId], knowledge_digest: knowledgeDigest };
  const url = new URL(`${origin}/api/v1/composition/objectives/${ownerId}/proposal-context`);
  assert.equal(receiverEvidenceRequestAllowed(url, body, expected), true);
  for (const patch of [{ authorizations: 1 }, { settlement: "pending" }, { objectiveEstablished: true },
    { attemptId: "attempt-other" }, { ownerId: "job-other" }, { knowledgeDigest: contextDigest }]) {
    assert.equal(receiverEvidenceRequestAllowed(url, body, { ...expected, ...patch }), false);
  }
  for (const patch of [{ arbitrary: true }, { prior_attempt_id: null }, { attempt_ids: [attemptId, attemptId] },
    { schema_version: "bluefire.composition-proposal-context.v1" }, { knowledge_digest: contextDigest }]) {
    assert.equal(receiverEvidenceRequestAllowed(url, { ...body, ...patch }, expected), false);
  }
  assert.equal(receiverEvidenceRequestAllowed(new URL(`${url}?all=1`), body, expected), false);
  const submit = { ...body, schema_version: "bluefire.composition-evidence-proposal-request.v1",
    submission_id: "12345678-1234-4234-8234-123456789abc", provider_id: expected.providerId, context_digest: contextDigest };
  const submitUrl = new URL(`${origin}/api/v1/composition/objectives/${ownerId}/proposals`);
  assert.equal(receiverEvidenceRequestAllowed(submitUrl, submit, expected, true), true);
  for (const patch of [{ provider_id: "other" }, { context_digest: knowledgeDigest }, { submission_id: "anything" }]) {
    assert.equal(receiverEvidenceRequestAllowed(submitUrl, { ...submit, ...patch }, expected, true), false);
  }
  assert.equal(receiverEvidenceRequestAllowed(new URL(`${origin}/api/v1/composition/objectives/${ownerId}/attempts`), submit, expected, true), false);
});

function fixture() {
  const record = { evidence_id: "evidence-original", step_id: "stage_records", behavior_id: "sandbox.collection.stage.v1",
    action_id: "sandbox.collection.stage.v1", provenance: "observed", timestamp: "2026-10-29T00:30:00Z",
    content_hash: `sha256:${"c".repeat(64)}`, record_hash: `sha256:${"d".repeat(64)}` };
  const run = { run_id: runId, status: "incomplete", mode: "execute", finalized_at: "2026-10-29T00:30:01Z",
    manifest: { run_id: runId, schema_version: "1.0" }, evidence: { records: [record] } };
  const sourceBinding = { run_id: runId, mode: "execute", finalized_at: run.finalized_at,
    manifest_digest: hash(run.manifest), evidence_digest: `sha256:${"e".repeat(64)}`, evidence_count: 1 };
  const attempt = { job_id: jobId, state: "completed", request: { composition_attempt: {
    parent_job_id: ownerId, attempt_id: attemptId, run_id: runId, compiled_digest: contextDigest,
  } }, progress: { verified_result: { objective: { established: false } } } };
  const ref = { owner_id: ownerId, attempt_id: attemptId, job_id: jobId, run_id: runId,
    evidence_id: record.evidence_id, record_hash: record.record_hash, source_binding_digest: hash(sourceBinding) };
  const finding = { finding_id: `finding-${hash(ref).slice(7)}`, evidence_id: record.evidence_id,
    step_id: record.step_id, behavior_id: record.behavior_id, action_id: record.action_id,
    provenance: "observed", observed_at: record.timestamp, content_hash: record.content_hash,
    record_hash: record.record_hash, semantic_kind: "observed_collection", summary: { record_count: 8 },
    applicability: { status: "historical_only", reason: "current_state_not_verified" }, record_ref: ref };
  const knowledge = { schema_version: "bluefire.composition-knowledge.v1", owner_id: ownerId, attempts: [{
    attempt_id: attemptId, job_id: jobId, run_id: runId, state: "settled", job_state: "completed",
    run_status: "incomplete", source_status: "verified", source_binding: sourceBinding, problem: null,
    findings_total: 1, findings_truncated: false, findings: [finding],
  }] };
  knowledge.knowledge_digest = hash(knowledge);
  const initial = { start: "transform_fixture", steps: [
    { id: "transform_fixture", behavior_id: "sandbox.fixture.transform.v1", parameters: { redact_values: false } },
    { id: "stage_records", behavior_id: "sandbox.collection.stage.v1", parameters: { bundle_format: "jsonl" } },
  ], edges: [{ from_step: "transform_fixture", outcome: "success", to_step: "stage_records" }] };
  const candidate = structuredClone(initial);
  candidate.steps[0].parameters.redact_values = true;
  candidate.evidence_refs = ["current-policy"];
  const context = { schema_version: "bluefire.composition-evidence-proposal-context.v1", context_digest: contextDigest,
    facts: { prior_attempt_id: attemptId, facts: [{ fact_id: "current-policy" }] },
    historical_context: { knowledge_digest: knowledge.knowledge_digest, attempt_ids: [attemptId], attempts: knowledge.attempts,
      choices: [{ attempt_id: attemptId, compiled_digest: contextDigest, step_id: "transform_fixture",
        behavior_id: "sandbox.fixture.transform.v1", parameters: { redact_values: false } }] } };
  const value = { candidate_ready: true, provider_outcome: "candidate", job: { job_id: proposalId, state: "completed",
    request: { owner_id: ownerId, context, submitted_request: { schema_version: "bluefire.composition-evidence-proposal-request.v1",
      submission_id: "12345678-1234-4234-8234-123456789abc", provider_id: "owned-provider", context_digest: contextDigest,
      prior_attempt_id: attemptId, attempt_ids: [attemptId], knowledge_digest: knowledge.knowledge_digest } } },
    proposal: { schema_version: "bluefire.composition-ai-result.v2", owner_id: ownerId, proposal_job_id: proposalId,
      prior_attempt_id: attemptId, provider: { provider_id: "owned-provider", model: "test-provider", attempts: 1, used_fallback: false },
      context_digest: contextDigest, proposal_digest: contextDigest, knowledge_digest: knowledge.knowledge_digest,
      model_context_digest: contextDigest, candidate, reconsideration: { reconsidered_choices: [{ attempt_id: attemptId,
        compiled_digest: contextDigest, step_id: "transform_fixture", finding_refs: [{ finding_id: finding.finding_id, record_ref: ref }],
        reason: "The later observation retained all unredacted records." }], refresh_requirements:
        ["attempt_cleanup", "retained_receiver_control", "runner_environment"].map(prerequisite => ({ prerequisite, explanation: "Verify current prerequisite before execution." })) } } };
  return { value, expected: { ownerId, attempt, run, sourceBinding, knowledge, initial, providerId: "owned-provider", model: "test-provider" } };
}

test("history proof binds the earlier choice to a later saved finding without claiming execution", () => {
  const { value, expected } = fixture();
  const before = JSON.stringify({ value, expected });
  const proof = verifyReceiverEvidenceProposal(value, expected);
  assert.equal(proof.purpose, EVIDENCE_PURPOSE);
  assert.equal(proof.later_finding_reused, true);
  assert.equal(proof.original_objective_established, false);
  assert.equal(JSON.stringify({ value, expected }), before);
});

test("history proof refuses substituted records, changed effects and invented freshness", () => {
  for (const mutate of [
    value => { value.proposal.prior_attempt_id = "attempt-other"; },
    value => { value.proposal.knowledge_digest = contextDigest; },
    value => { value.proposal.candidate.steps[1].parameters.bundle_format = "tar"; },
    value => { value.proposal.candidate.evidence_refs = ["historical-resource-is-current"]; },
    value => { value.proposal.reconsideration.reconsidered_choices[0].finding_refs[0] = { finding_id: "finding-other", record_ref: {} }; },
    value => { value.proposal.reconsideration.reconsidered_choices[0].compiled_digest = knowledgeDigest; },
    value => { value.proposal.reconsideration.refresh_requirements.pop(); },
    value => { value.job.request.submitted_request.provider_id = "other"; },
    value => { value.proposal.provider.used_fallback = true; },
  ]) {
    const { value, expected } = fixture();
    mutate(value);
    assert.throws(() => verifyReceiverEvidenceProposal(value, expected));
  }
  const { value, expected } = fixture();
  expected.attempt.progress.verified_result.objective.established = true;
  assert.throws(() => verifyReceiverEvidenceProposal(value, expected));
});
