import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";

const stable = value => Array.isArray(value) ? value.map(stable)
  : value !== null && typeof value === "object"
    ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value;
const hash = value => `sha256:${createHash("sha256").update(JSON.stringify(stable(value))).digest("hex")}`;
const exact = (value, keys) => value !== null && typeof value === "object" && !Array.isArray(value)
  && isDeepStrictEqual(Object.keys(value).sort(), [...keys].sort());
const digest = value => typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);

// This inspection is admitted only for the already settled attempt selected by this journey.
export function receiverKnowledgeRequestAllowed(url, body, expected) {
  return typeof expected.ownerId === "string" && /^job-[0-9a-f]{32}$/.test(expected.ownerId)
    && typeof expected.attemptId === "string" && /^attempt-[0-9a-f]{32}$/.test(expected.attemptId)
    && expected.settlement === "settled" && expected.objectiveEstablished === false
    && url.origin === expected.origin && !url.search
    && url.pathname === `/api/v1/composition/objectives/${expected.ownerId}/knowledge`
    && exact(body, ["schema_version", "attempt_ids"])
    && body.schema_version === "bluefire.composition-knowledge-query.v1"
    && isDeepStrictEqual(body.attempt_ids, [expected.attemptId]);
}

export function verifyReceiverKnowledge(value, { ownerId, attempt, run, sourceBinding }) {
  const marker = attempt.request.composition_attempt;
  assert.equal(attempt.progress.verified_result.objective.established, false);
  assert.equal(marker.parent_job_id, ownerId);
  assert.equal(marker.run_id, run.run_id);
  assert.equal(value.schema_version, "bluefire.composition-knowledge.v1");
  assert.equal(value.owner_id, ownerId);
  assert.equal(value.attempts.length, 1);
  const { knowledge_digest: knowledgeDigest, ...body } = value;
  assert.equal(knowledgeDigest, hash(body));
  const selected = value.attempts[0];
  assert.equal(selected.attempt_id, marker.attempt_id);
  assert.equal(selected.job_id, attempt.job_id);
  assert.equal(selected.run_id, run.run_id);
  assert.equal(selected.state, "settled");
  assert.equal(selected.job_state, attempt.state);
  assert.equal(selected.run_status, run.status);
  assert.equal(selected.source_status, "verified");
  assert.equal(selected.problem, null);
  assert.deepEqual(selected.source_binding, sourceBinding);
  assert.equal(sourceBinding.manifest_digest, hash(run.manifest));
  // The verified result binds the Python-canonical evidence digest. Preserve that
  // digest rather than reserializing record floats (1.0) as JavaScript integers (1).
  assert.equal(sourceBinding.evidence_count, run.evidence.records.length);
  assert.equal(sourceBinding.run_id, run.run_id);
  assert.equal(sourceBinding.mode, "execute");
  assert.equal(sourceBinding.finalized_at, run.finalized_at);
  assert.ok(digest(sourceBinding.manifest_digest) && digest(sourceBinding.evidence_digest));
  assert.ok(Array.isArray(selected.findings) && selected.findings.length > 0 && selected.findings.length <= 32);
  assert.equal(selected.findings_total, run.evidence.records.length);
  assert.equal(selected.findings_truncated, selected.findings_total > selected.findings.length);
  assert.equal(new Set(selected.findings.map(finding => finding.finding_id)).size, selected.findings.length);
  const records = new Map(run.evidence.records.map(record => [record.evidence_id, record]));
  const sourceBindingDigest = hash(sourceBinding);
  let observed = 0;
  for (const finding of selected.findings) {
    const record = records.get(finding.evidence_id);
    assert.ok(record, "Every displayed finding must refer to this actual sealed run");
    for (const [field, source] of Object.entries({ step_id: "step_id", behavior_id: "behavior_id", action_id: "action_id", provenance: "provenance", observed_at: "timestamp", content_hash: "content_hash", record_hash: "record_hash" })) {
      assert.equal(finding[field], record[source]);
    }
    assert.deepEqual(finding.applicability, { status: "historical_only", reason: "current_state_not_verified" });
    assert.deepEqual(finding.record_ref, { owner_id: ownerId, attempt_id: marker.attempt_id,
      job_id: attempt.job_id, run_id: run.run_id, evidence_id: record.evidence_id,
      record_hash: record.record_hash, source_binding_digest: sourceBindingDigest });
    assert.equal(finding.finding_id, `finding-${hash(finding.record_ref).slice(7)}`);
    if (finding.provenance === "observed") observed += 1;
  }
  assert.ok(observed > 0, "The historical view must retain actual independent observations");
  return {
    schema_version: "bluefire.installed-composition-knowledge.v1", owner_id: ownerId,
    attempt_id: marker.attempt_id, job_id: attempt.job_id, run_id: run.run_id,
    knowledge_digest: knowledgeDigest, source_binding_digest: sourceBindingDigest,
    manifest_digest: sourceBinding.manifest_digest, evidence_digest: sourceBinding.evidence_digest,
    findings_count: selected.findings.length, observed_findings_count: observed,
    source_status: "verified", historical_only: true, source_matches_run: true,
    objective_established: false,
  };
}

export async function inspectReceiverKnowledge(page, { origin, ownerId, attempt, run, sourceBinding, readObjective, capture }) {
  const expectedPath = `/api/v1/composition/objectives/${ownerId}/knowledge`;
  const responsePromise = page.waitForResponse(response => response.request().method() === "POST"
    && response.url() === `${origin}${expectedPath}`);
  await page.getByRole("button", { name: "Findings across attempts", exact: true }).click();
  const response = await responsePromise;
  assert.ok(response.ok(), "The installed service must resolve the actual saved findings");
  assert.deepEqual(response.request().postDataJSON(), {
    schema_version: "bluefire.composition-knowledge-query.v1", attempt_ids: [attempt.request.composition_attempt.attempt_id],
  });
  const knowledge = await response.json();
  const proof = verifyReceiverKnowledge(knowledge, { ownerId, attempt, run, sourceBinding });
  const panel = page.getByRole("region", { name: "Findings across attempts", exact: true });
  await panel.getByText("Recorded history", { exact: true }).waitFor({ state: "visible" });
  const group = panel.getByRole("region", { name: "Findings from attempt 1", exact: true });
  const source = group.getByRole("link", { name: "Open source run", exact: true });
  await source.waitFor({ state: "visible" });
  assert.ok((await source.getAttribute("href")).endsWith(`/runs/${encodeURIComponent(run.run_id)}`));
  const displayed = group.locator(".composition-finding");
  assert.equal(await displayed.count(), proof.findings_count);
  const observedIndex = knowledge.attempts[0].findings.findIndex(finding => finding.provenance === "observed");
  const observed = knowledge.attempts[0].findings[observedIndex];
  const observedRow = displayed.nth(observedIndex);
  await observedRow.getByText("Observed", { exact: true }).waitFor({ state: "visible" });
  const details = observedRow.locator("details.composition-finding-source");
  await details.locator("summary").click();
  for (const text of [observed.evidence_id, observed.finding_id, observed.record_hash,
    observed.record_ref.source_binding_digest, "Historical finding; current resource state has not been checked."]) {
    await details.getByText(text, { exact: true }).waitFor({ state: "visible" });
  }
  await details.locator("summary").click();
  if (capture) await capture(panel);
  const unchanged = await readObjective();
  assert.equal(unchanged.attempts.length, 1);
  assert.equal(unchanged.attempts[0].job_id, attempt.job_id);
  assert.deepEqual(unchanged.attempts[0].request.composition_attempt, attempt.request.composition_attempt);
  assert.equal(unchanged.attempts[0].progress.verified_result.objective.established, false);
  assert.equal(unchanged.attempts[0].progress.verified_result_digest, attempt.progress.verified_result_digest);
  await page.getByRole("button", { name: "Hide findings", exact: true }).click();
  return { ...proof, opened_through_ui: true, rendered_findings: true, unchanged_attempts: true };
}
