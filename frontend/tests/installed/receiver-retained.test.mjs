/* global structuredClone */
import assert from "node:assert/strict";
import { test } from "vitest";
import { URL } from "node:url";
import { retainedState, retainedPostAllowed } from "./receiver-retained.mjs";
import { retainedHash, assertRetainedSource, assertMetadataOnly, verifyRetainedOriginal, verifyRetainedContinuation, RETAINED_PACK, RETAINED_QUESTION, RETAINED_REVIEWER, RETAINED_METHOD } from "./receiver-retained-proof.mjs";

const origin = "http://127.0.0.1:12345";
const ownerId = `job-${"a".repeat(32)}`;
const controlId = `job-${"b".repeat(32)}`;
const attemptId = `attempt-${"c".repeat(32)}`;
const runId = "run-20261029T003000Z-1234567890abcdef";
const receiptA = "d".repeat(64), receiptB = "e".repeat(64);
const digest = letter => `sha256:${letter.repeat(64)}`;

test("retained routes preserve distinct v2 review and exact owned attempts", () => {
  const state = retainedState();
  state.active = true;
  const counted = [];
  const options = { origin, controlId, providerId: "provider", count: key => { counted.push(key); return true; } };
  const review = { schema_version: "bluefire.composition-review-request.v2", pack: RETAINED_PACK, control_owner_id: controlId, question: RETAINED_QUESTION, limits: null };
  assert.equal(retainedPostAllowed(state, new URL(`${origin}/api/v1/composition/context`), review, options), true);
  assert.equal(retainedPostAllowed(state, new URL(`${origin}/api/v1/composition/context`), { ...review, control_owner_id: ownerId }, options), false);
  state.review = { review_digest: digest("a") };
  const grant = { review, submission_id: "12345678-1234-4234-8234-123456789abc", reviewed_by: RETAINED_REVIEWER, review_digest: digest("a") };
  assert.equal(retainedPostAllowed(state, new URL(`${origin}/api/v1/composition/objectives`), grant, options), true);
  assert.equal(state.ownerId, "job-12345678123442348234123456789abc");
  state.proposals = ["job-proposal"];
  state.candidate = { fixed: "approved-graph" };
  const attempt = { submission_id: "12345678-1234-4234-8234-123456789abd", proposal: state.candidate, prior_attempt_id: null };
  const attemptUrl = new URL(`${origin}/api/v1/composition/objectives/${state.ownerId}/attempts`);
  assert.equal(retainedPostAllowed(state, attemptUrl, { ...attempt, proposal: {} }, options), false);
  assert.equal(retainedPostAllowed(state, attemptUrl, attempt, options), true);
  assert.equal(retainedPostAllowed(state, attemptUrl, attempt, options), false, "No repeat before the distinct reviewed continuation");
  state.first = { attempt_id: attemptId, run_id: runId };
  state.knowledge = { knowledge_digest: digest("c") };
  const history = { schema_version: "bluefire.composition-evidence-context-query.v1", prior_attempt_id: attemptId, attempt_ids: [attemptId], knowledge_digest: digest("c") };
  const historyUrl = new URL(`${origin}/api/v1/composition/objectives/${state.ownerId}/proposal-context`);
  assert.equal(retainedPostAllowed(state, historyUrl, history, options), true);
  assert.equal(retainedPostAllowed(state, historyUrl, { ...history, attempt_ids: [attemptId, attemptId] }, options), false);
  assert.equal(retainedPostAllowed(state, historyUrl, { prior_attempt_id: null }, options), false);
  assert.equal(counted.filter(key => key === "retained_attempt").length, 1);
});

function originalFixture() {
  const sourceBody = { run_id: runId, attempt_id: attemptId, lineage_id: `lineage-${"f".repeat(64)}`,
    step_id: "stage_records", artifact: "bundle", artifact_type: "artifact.sandbox.bundle.v1", sha256: "1".repeat(64), size_bytes: 400 };
  const source = { ...sourceBody, source_ref: retainedHash(sourceBody) };
  const producer = { evidence_id: "produced", record_hash: digest("2"), step_id: "stage_records", provenance: "executed", content: {} };
  const observed = { evidence_id: "observed", record_hash: digest("3"), step_id: "stage_records", provenance: "observed",
    parent_evidence_ids: [producer.evidence_id], content: { sha256: source.sha256, size_bytes: source.size_bytes } };
  const grant = { grant_id: `grant-${"a".repeat(32)}`, grant_digest: digest("4"), environment: { policy_digest: digest("5") } };
  const run = { run_id: runId, mode: "execute", status: "incomplete", finalized_at: "2026-10-29T00:30:00Z",
    manifest: { run_id: runId, bundle_hash: digest("6"), files: { "artifacts.json": { hash: digest("7") } } },
    evidence: { records: [producer, observed] }, cleanup: { success: true, outstanding_receipt_count: 0 },
    steps: [{ step_id: "stage_records", status: "success", action_id: "sandbox.collection.stage.v1", evidence_ids: ["produced", "observed"],
      artifacts: { bundle: { retained_source: source, sha256: source.sha256, size: source.size_bytes, receipt_ids: [receiptA] } } }],
    events: [{ sequence: 1, event_type: "artifact.retained", data: { source } },
      { sequence: 2, event_type: "step.completed", data: { action_id: "sandbox.peer.handoff.v1" } },
      { sequence: 3, event_type: "step.completed", data: { action_id: "sandbox.cleanup.v1" } }] };
  const capture = { schema_version: "bluefire.retained-artifact-capture.v1", source,
    producer_record_hash: producer.record_hash, observation_record_hash: observed.record_hash };
  capture.capture_digest = retainedHash(capture);
  const attempt = { job_id: `job-${"c".repeat(32)}`, state: "completed", request: { composition_attempt: {
    parent_job_id: ownerId, grant_id: grant.grant_id, grant_digest: grant.grant_digest, attempt_id: attemptId, run_id: runId } },
  progress: { settlement: "settled", receiver_closed: true, retained_artifact_capture: capture,
    receiver_observation: { state: "verified", terminal: { decision: { authenticated: true, decision: "policy_refused" } }, process_exit: { returncode: 0 } }, verified_result: {
      run_id: runId, source_binding: { run_id: runId, evidence_count: 2, finalized_at: run.finalized_at, manifest_digest: retainedHash(run.manifest) },
      objective: { established: false, checks: { policy_unchanged: true } }, receiver_result: { policy_digest: grant.environment.policy_digest,
        decision: "policy_refused", record_count: 8, redacted_record_count: 0, retained_record_count: 8, empty_record_count: 0 },
      cleanup: { run: "complete", receiver: "verified_closed" } } } };
  return { run, attempt, source, expected: { ownerId, grant } };
}

function continuationFixture() {
  const first = originalFixture();
  const original = verifyRetainedOriginal(first.attempt, first.run, first.expected).original;
  const run = structuredClone(first.run), attempt = structuredClone(first.attempt);
  run.run_id = "run-20261029T004000Z-fedcba0987654321";
  run.manifest.run_id = run.run_id;
  attempt.job_id = `job-${"8".repeat(32)}`;
  attempt.request.composition_attempt.run_id = run.run_id;
  attempt.request.composition_attempt.attempt_id = `attempt-${"8".repeat(32)}`;
  const materialized = { step_id: "reuse_retained_bundle", action_id: RETAINED_METHOD, status: "success", execution_disposition: "execute",
    evidence_ids: ["new-produced", "new-observed"], artifacts: { workspace: { type: "artifact.sandbox.workspace.v1", fixture_path: "fixtures/input.jsonl",
      sha256: first.source.sha256, size: first.source.size_bytes, record_count: 8, historical_source_ref: first.source.source_ref,
      historical_source: first.source, receipt_ids: [receiptB] } } };
  run.steps = [materialized, ...["sandbox.fixture.transform.v1", "sandbox.discovery.metadata.v1", "sandbox.collection.stage.v1", "sandbox.peer.handoff.v1", "sandbox.cleanup.v1"]
    .map(action_id => ({ action_id, status: "success", execution_disposition: "execute" }))];
  run.evidence.records = [{ evidence_id: "new-produced", provenance: "executed" }, { evidence_id: "new-observed", provenance: "observed",
    parent_evidence_ids: ["new-produced"], content: { sha256: first.source.sha256, size_bytes: first.source.size_bytes, path: "fixtures/input.jsonl" } }];
  run.materialization_steps = [];
  run.checkpoint_materialization = null;
  run.scenario = { steps: [{ behavior_id: "sandbox.fixture.transform.v1", parameters: { redact_values: true }, inputs: { workspace: { from_step: "reuse_retained_bundle", artifact: "workspace" } } },
    { behavior_id: "sandbox.cleanup.v1", inputs: { workspace: { from_step: "reuse_retained_bundle", artifact: "workspace" } } }] };
  const result = attempt.progress.verified_result;
  attempt.progress.receiver_observation.terminal.decision.decision = "accepted";
  result.run_id = run.run_id;
  result.source_binding.run_id = run.run_id;
  result.source_binding.manifest_digest = retainedHash(run.manifest);
  result.objective.established = true;
  result.receiver_result = { ...result.receiver_result, decision: "accepted", redacted_record_count: 8, retained_record_count: 0 };
  return { run, attempt, expected: { ...first.expected, source: first.source, original } };
}

test("retention proof binds capture to its original producer before refusal and cleanup", () => {
  const { run, attempt, source, expected } = originalFixture();
  const proof = verifyRetainedOriginal(attempt, run, expected);
  assert.deepEqual(proof.source, source);
  assert.equal(proof.original.objective_established, false);
  for (const mutate of [
    value => { value.events[0].sequence = 4; },
    value => { value.evidence.records[1].content.sha256 = "0".repeat(64); },
    value => { value.steps[0].status = "failed"; },
    value => { value.cleanup.success = false; },
    value => { value.payload_hex = "00"; },
  ]) { const changed = structuredClone(run); mutate(changed); assert.throws(() => verifyRetainedOriginal(attempt, changed, expected)); }
  const failedExit = structuredClone(attempt);
  failedExit.progress.receiver_observation.process_exit.returncode = 1;
  assert.throws(() => verifyRetainedOriginal(failedExit, run, expected));
});

test("fresh materialization proof requires exact bytes, new receipt, independent observation and no prefix replay", () => {
  const { run, attempt, expected } = continuationFixture();
  const proof = verifyRetainedContinuation(attempt, run, expected);
  assert.equal(proof.objective_established, true);
  assert.equal(proof.source_ref, expected.source.source_ref);
  for (const mutate of [
    value => { value.steps[0].artifacts.workspace.sha256 = "0".repeat(64); },
    value => { value.steps[0].artifacts.workspace.receipt_ids = [receiptA]; },
    value => { value.evidence.records[1].provenance = "runner_reported"; },
    value => { value.steps[1].action_id = "sandbox.fixture.create.v1"; },
    value => { value.materialization_steps = [{ prefix: "replayed" }]; },
    value => { value.scenario.steps[0].inputs.workspace.from_step = "old-producer"; },
  ]) { const changed = structuredClone(run); mutate(changed); assert.throws(() => verifyRetainedContinuation(attempt, changed, expected)); }
  const wrongTerminal = structuredClone(attempt);
  wrongTerminal.progress.receiver_observation.terminal.decision.decision = "policy_refused";
  assert.throws(() => verifyRetainedContinuation(wrongTerminal, run, expected));
});

test("source metadata cannot substitute a different artifact or carry raw bytes", () => {
  const { source } = originalFixture();
  assert.equal(assertRetainedSource(source), source);
  assert.throws(() => assertRetainedSource({ ...source, size_bytes: 262145 }));
  assert.throws(() => assertRetainedSource({ ...source, run_id: "run-other" }));
  assertMetadataOnly({ retained_artifacts: { available_sources: [source] } });
  assert.throws(() => assertMetadataOnly({ nested: [{ payload_hex_chunks: ["00"] }] }));
});
