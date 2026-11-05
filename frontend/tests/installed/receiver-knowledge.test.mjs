import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "vitest";
import { URL } from "node:url";
import { receiverKnowledgeRequestAllowed, verifyReceiverKnowledge } from "./receiver-knowledge.mjs";

const stable = value => Array.isArray(value) ? value.map(stable) : value !== null && typeof value === "object"
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value;
const hash = value => `sha256:${createHash("sha256").update(JSON.stringify(stable(value))).digest("hex")}`;
const ownerId = `job-${"a".repeat(32)}`;
const attemptId = `attempt-${"b".repeat(32)}`;
const jobId = `job-${"b".repeat(32)}`;
const runId = "run-20261029T003000Z-1234567890abcdef";
const origin = "http://127.0.0.1:12345";

test("knowledge guard admits one exact already settled false-objective attempt", () => {
  const url = new URL(`${origin}/api/v1/composition/objectives/${ownerId}/knowledge`);
  const body = { schema_version: "bluefire.composition-knowledge-query.v1", attempt_ids: [attemptId] };
  const expected = { origin, ownerId, attemptId, settlement: "settled", objectiveEstablished: false };
  assert.equal(receiverKnowledgeRequestAllowed(url, body, expected), true);
  for (const invalid of [
    { ...body, arbitrary: true }, { ...body, schema_version: "new" },
    { ...body, attempt_ids: [] }, { ...body, attempt_ids: [attemptId, attemptId] },
    { ...body, attempt_ids: [`attempt-${"c".repeat(32)}`] },
  ]) assert.equal(receiverKnowledgeRequestAllowed(url, invalid, expected), false);
  for (const changed of [
    { settlement: "claimed" }, { objectiveEstablished: true }, { attemptId: undefined },
    { origin: "http://127.0.0.1:54321" }, { ownerId: `job-${"c".repeat(32)}` },
  ]) assert.equal(receiverKnowledgeRequestAllowed(url, body, { ...expected, ...changed }), false);
  assert.equal(receiverKnowledgeRequestAllowed(new URL(`${url}?all=1`), body, expected), false);
});

function fixture() {
  const record = { evidence_id: "evidence-original", step_id: "inspect", behavior_id: "sandbox.inspect.v1",
    action_id: "sandbox.inspect.v1", provenance: "observed", timestamp: "2026-10-29T00:30:00Z",
    content_hash: `sha256:${"c".repeat(64)}`, record_hash: `sha256:${"d".repeat(64)}` };
  const run = { run_id: runId, status: "incomplete", mode: "execute", finalized_at: "2026-10-29T00:30:01Z",
    manifest: { run_id: runId, schema_version: "1.0" }, evidence: { records: [record] } };
  const sourceBinding = { run_id: runId, mode: "execute", finalized_at: run.finalized_at,
    manifest_digest: hash(run.manifest), evidence_digest: `sha256:${"e".repeat(64)}`, evidence_count: 1 };
  const attempt = { job_id: jobId, state: "completed", request: { composition_attempt: {
    parent_job_id: ownerId, attempt_id: attemptId, run_id: runId,
  } }, progress: { verified_result: { objective: { established: false } } } };
  const ref = { owner_id: ownerId, attempt_id: attemptId, job_id: jobId, run_id: runId,
    evidence_id: record.evidence_id, record_hash: record.record_hash, source_binding_digest: hash(sourceBinding) };
  const finding = { finding_id: `finding-${hash(ref).slice(7)}`, evidence_id: record.evidence_id,
    step_id: record.step_id, behavior_id: record.behavior_id, action_id: record.action_id,
    provenance: "observed", observed_at: record.timestamp, content_hash: record.content_hash,
    record_hash: record.record_hash, semantic_kind: "observed_filesystem", summary: { size_bytes: 12 },
    applicability: { status: "historical_only", reason: "current_state_not_verified" }, record_ref: ref };
  const value = { schema_version: "bluefire.composition-knowledge.v1", owner_id: ownerId, attempts: [{
    attempt_id: attemptId, job_id: jobId, run_id: runId, state: "settled", job_state: "completed",
    run_status: "incomplete", source_status: "verified", source_binding: sourceBinding, problem: null,
    findings_total: 1, findings_truncated: false, findings: [finding],
  }] };
  value.knowledge_digest = hash(value);
  return { value, expected: { ownerId, attempt, run, sourceBinding } };
}

test("failed objective retains its exact historical observed record without claiming success", () => {
  const { value, expected } = fixture();
  const before = JSON.stringify(expected);
  const proof = verifyReceiverKnowledge(value, expected);
  assert.equal(proof.objective_established, false);
  assert.equal(proof.historical_only, true);
  assert.equal(proof.observed_findings_count, 1);
  assert.equal(JSON.stringify(expected), before);
});

test("knowledge verification refuses altered source, freshness, identity or inferred success", () => {
  for (const change of [
    value => { value.owner_id = `job-${"c".repeat(32)}`; },
    value => { value.attempts[0].run_id = "run-other"; },
    value => { value.attempts[0].source_status = "unavailable"; },
    value => { value.attempts[0].findings[0].applicability.status = "current"; },
    value => { value.attempts[0].findings[0].evidence_id = "evidence-other"; },
    value => { value.attempts[0].findings[0].record_ref.source_binding_digest = `sha256:${"f".repeat(64)}`; },
    value => { value.attempts[0].findings[0].provenance = "runner_reported"; },
    value => { value.attempts[0].findings_total = 2; },
  ]) {
    const { value, expected } = fixture();
    change(value);
    delete value.knowledge_digest;
    value.knowledge_digest = hash(value);
    assert.throws(() => verifyReceiverKnowledge(value, expected));
  }
  const { value, expected } = fixture();
  expected.attempt.progress.verified_result.objective.established = true;
  assert.throws(() => verifyReceiverKnowledge(value, expected));
});
