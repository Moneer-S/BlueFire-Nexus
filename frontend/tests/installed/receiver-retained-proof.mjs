import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { isDeepStrictEqual as same } from "node:util";
import { receiverRunIsNotDemo } from "./receiver-guards.mjs";

export const RETAINED_PACK = "bluefire.receiver-composition-pack.v2";
export const RETAINED_METHOD = "sandbox.collection.materialize-retained.v1";
export const RETAINED_PURPOSE = "bluefire_receiver_retained_composition_proposal";
export const RETAINED_PURPOSE_LABEL = "Propose receiver graphs that keep and reuse generated results";
export const RETAINED_QUESTION = "Can the same generated records be reused and redacted after a receiver refusal?";
export const RETAINED_REVIEWER = "Installed retained-result verifier";
const stable = value => Array.isArray(value) ? value.map(stable) : value !== null && typeof value === "object"
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value;
export const retainedHash = value => `sha256:${createHash("sha256").update(JSON.stringify(stable(value))).digest("hex")}`;
export const exact = (value, keys) => value !== null && typeof value === "object" && !Array.isArray(value)
  && same(Object.keys(value).sort(), [...keys].sort());
const digest = value => typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);

export function assertRetainedSource(source) {
  assert.ok(exact(source, ["run_id", "attempt_id", "lineage_id", "step_id", "artifact", "artifact_type", "sha256", "size_bytes", "source_ref"]));
  assert.match(source.run_id, /^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$/);
  assert.match(source.attempt_id, /^attempt-[0-9a-f]{32}$/);
  assert.ok(typeof source.lineage_id === "string" && source.lineage_id.length > 0);
  assert.equal(source.artifact, "bundle");
  assert.equal(source.artifact_type, "artifact.sandbox.bundle.v1");
  assert.match(source.sha256, /^[0-9a-f]{64}$/);
  assert.ok(Number.isSafeInteger(source.size_bytes) && source.size_bytes > 0 && source.size_bytes <= 262144);
  const { source_ref: ref, ...body } = source;
  assert.equal(ref, retainedHash(body));
  return source;
}

export function assertMetadataOnly(value) {
  if (Array.isArray(value)) { for (const item of value) assertMetadataOnly(item); return; }
  if (value !== null && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      assert.ok(!["payload", "payload_hex", "payload_hex_chunks", "raw_bytes", "raw_content"].includes(key), "Public/model context must not contain retained bytes");
      assertMetadataOnly(item);
    }
  }
}

function verifiedAttempt(attempt, run, { ownerId, grant, accepted }) {
  const marker = attempt.request.composition_attempt;
  const verified = attempt.progress.verified_result;
  assert.equal(attempt.progress.settlement, "settled");
  assert.equal(attempt.state, "completed");
  assert.equal(marker.parent_job_id, ownerId);
  assert.equal(marker.grant_id, grant.grant_id);
  assert.equal(marker.grant_digest, grant.grant_digest);
  assert.equal(marker.run_id, run.run_id);
  assert.equal(run.mode, "execute");
  assert.equal(receiverRunIsNotDemo(run), true);
  assert.ok(["completed", "incomplete"].includes(run.status));
  assert.equal(run.manifest.run_id, run.run_id);
  assert.ok(digest(run.manifest.bundle_hash));
  assert.equal(verified.run_id, run.run_id);
  assert.equal(verified.source_binding.manifest_digest, retainedHash(run.manifest));
  assert.equal(verified.source_binding.run_id, run.run_id);
  assert.equal(verified.source_binding.evidence_count, run.evidence.records.length);
  assert.equal(verified.source_binding.finalized_at, run.finalized_at);
  assert.equal(verified.objective.established, accepted);
  assert.equal(verified.objective.checks.policy_unchanged, true);
  assert.equal(verified.receiver_result.policy_digest, grant.environment.policy_digest);
  assert.equal(verified.receiver_result.decision, accepted ? "accepted" : "policy_refused");
  assert.equal(verified.receiver_result.record_count, 8);
  assert.equal(verified.receiver_result.redacted_record_count, accepted ? 8 : 0);
  assert.equal(verified.receiver_result.retained_record_count, accepted ? 0 : 8);
  assert.equal(verified.receiver_result.empty_record_count, 0);
  assert.deepEqual(verified.cleanup, { run: "complete", receiver: "verified_closed" });
  assert.equal(run.cleanup.success, true);
  assert.equal(run.cleanup.outstanding_receipt_count, 0);
  assert.equal(attempt.progress.receiver_observation.state, "verified");
  assert.equal(attempt.progress.receiver_observation.terminal.decision.authenticated, true);
  assert.equal(attempt.progress.receiver_observation.terminal.decision.decision, accepted ? "accepted" : "policy_refused");
  assert.equal(attempt.progress.receiver_observation.process_exit.returncode, 0);
  assert.equal(attempt.progress.receiver_closed, true);
  assertMetadataOnly(run);
  return { job_id: attempt.job_id, attempt_id: marker.attempt_id, run_id: run.run_id,
    objective_established: accepted, receiver_decision: verified.receiver_result.decision,
    record_count: 8, redacted_record_count: accepted ? 8 : 0, cleanup: verified.cleanup };
}

export function verifyRetainedOriginal(attempt, run, expected) {
  const proof = verifiedAttempt(attempt, run, { ...expected, accepted: false });
  const capture = attempt.progress.retained_artifact_capture;
  assert.equal(capture.schema_version, "bluefire.retained-artifact-capture.v1");
  const source = assertRetainedSource(capture.source);
  assert.equal(source.run_id, run.run_id);
  assert.equal(source.attempt_id, proof.attempt_id);
  assert.equal(source.step_id, "stage_records");
  const { capture_digest: captureDigest, ...body } = capture;
  assert.equal(captureDigest, retainedHash(body));
  const stage = run.steps.find(step => step.step_id === source.step_id);
  assert.equal(stage.status, "success");
  assert.equal(stage.action_id, "sandbox.collection.stage.v1");
  assert.deepEqual(stage.artifacts.bundle.retained_source, source);
  assert.equal(stage.artifacts.bundle.sha256, source.sha256);
  assert.equal(stage.artifacts.bundle.size, source.size_bytes);
  assert.equal(stage.artifacts.bundle.receipt_ids.length, 1);
  const producer = run.evidence.records.find(record => record.record_hash === capture.producer_record_hash);
  const observed = run.evidence.records.find(record => record.record_hash === capture.observation_record_hash);
  assert.equal(producer?.provenance, "executed");
  assert.equal(observed?.provenance, "observed");
  assert.equal(producer.step_id, stage.step_id);
  assert.equal(observed.step_id, stage.step_id);
  assert.ok(stage.evidence_ids.includes(producer.evidence_id) && stage.evidence_ids.includes(observed.evidence_id));
  assert.ok(observed.parent_evidence_ids.includes(producer.evidence_id));
  assert.equal(observed.content.sha256, source.sha256);
  assert.equal(observed.content.size_bytes, source.size_bytes);
  assert.ok(run.manifest.files["artifacts.json"]);
  const retained = run.events.find(event => event.event_type === "artifact.retained" && same(event.data.source, source));
  const handoff = run.events.find(event => event.event_type === "step.completed" && event.data.action_id === "sandbox.peer.handoff.v1");
  const cleanup = run.events.find(event => event.event_type === "step.completed" && event.data.action_id === "sandbox.cleanup.v1");
  assert.ok(retained && handoff && cleanup && retained.sequence < handoff.sequence && handoff.sequence < cleanup.sequence,
    "The real successful collection must be captured before later refusal and cleanup");
  return { source, original: { ...proof, capture_digest: captureDigest,
    producer_record_hash: producer.record_hash, observation_record_hash: observed.record_hash,
    receipt_id: stage.artifacts.bundle.receipt_ids[0] } };
}

export function verifyRetainedContinuation(attempt, run, { source, original, ...expected }) {
  const proof = verifiedAttempt(attempt, run, { ...expected, accepted: true });
  assert.notEqual(proof.job_id, original.job_id);
  assert.notEqual(proof.attempt_id, original.attempt_id);
  assert.notEqual(proof.run_id, original.run_id);
  assert.deepEqual(run.materialization_steps, []);
  assert.equal(run.checkpoint_materialization, null);
  assert.equal(run.steps.length, 6);
  assert.ok(run.steps.every(step => step.status === "success" && step.execution_disposition === "execute"));
  assert.ok(!run.steps.some(step => step.action_id === "sandbox.fixture.create.v1"));
  const first = run.steps[0];
  assert.equal(first.step_id, "reuse_retained_bundle");
  assert.equal(first.action_id, RETAINED_METHOD);
  const workspace = first.artifacts.workspace;
  assert.equal(workspace.type, "artifact.sandbox.workspace.v1");
  assert.equal(workspace.fixture_path, "fixtures/input.jsonl");
  assert.equal(workspace.sha256, source.sha256);
  assert.equal(workspace.size, source.size_bytes);
  assert.equal(workspace.record_count, 8);
  assert.equal(workspace.historical_source_ref, source.source_ref);
  assert.deepEqual(workspace.historical_source, source);
  assert.equal(workspace.receipt_ids.length, 1);
  assert.notEqual(workspace.receipt_ids[0], original.receipt_id);
  const executed = run.evidence.records.find(record => first.evidence_ids.includes(record.evidence_id) && record.provenance === "executed");
  const observed = run.evidence.records.find(record => first.evidence_ids.includes(record.evidence_id) && record.provenance === "observed"
    && record.content.sha256 === source.sha256 && record.content.size_bytes === source.size_bytes);
  assert.ok(executed && observed, "Materialized bytes must have independent filesystem observation");
  assert.ok(observed.parent_evidence_ids.includes(executed.evidence_id));
  assert.equal(observed.content.path, "fixtures/input.jsonl");
  const planTransform = run.scenario.steps.find(step => step.behavior_id === "sandbox.fixture.transform.v1");
  const planCleanup = run.scenario.steps.find(step => step.behavior_id === "sandbox.cleanup.v1");
  assert.equal(planTransform.parameters.redact_values, true);
  assert.deepEqual(planTransform.inputs.workspace, { from_step: first.step_id, artifact: "workspace" });
  assert.deepEqual(planCleanup.inputs.workspace, { from_step: first.step_id, artifact: "workspace" });
  assert.deepEqual(run.steps.map(step => step.action_id), [RETAINED_METHOD, "sandbox.fixture.transform.v1",
    "sandbox.discovery.metadata.v1", "sandbox.collection.stage.v1", "sandbox.peer.handoff.v1", "sandbox.cleanup.v1"]);
  return { ...proof, materialize_step_id: first.step_id, source_ref: source.source_ref,
    materialized_sha256: workspace.sha256, materialized_size_bytes: workspace.size,
    receipt_id: workspace.receipt_ids[0], independent_observation: true,
    workspace_lineage_match: true, no_fixture_create: true };
}
