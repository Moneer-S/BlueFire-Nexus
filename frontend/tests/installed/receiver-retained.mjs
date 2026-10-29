import assert from "node:assert/strict";
import { isDeepStrictEqual as same } from "node:util";
import { URL, URLSearchParams } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { createReceiverReloadContextCorrelation } from "./receiver-guards.mjs";
import { verifyReceiverKnowledge } from "./receiver-knowledge.mjs";
import { RETAINED_PACK, RETAINED_METHOD, RETAINED_PURPOSE_LABEL, RETAINED_QUESTION, RETAINED_REVIEWER,
  exact, assertMetadataOnly, assertRetainedSource, verifyRetainedOriginal, verifyRetainedContinuation } from "./receiver-retained-proof.mjs";

const submissionId = value => typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
const jobId = value => `job-${value.replaceAll("-", "")}`;
const reviewBody = controlId => ({ schema_version: "bluefire.composition-review-request.v2", pack: RETAINED_PACK,
  control_owner_id: controlId, question: RETAINED_QUESTION, limits: null });
export const retainedState = () => ({ active: false, ownerId: undefined, proposals: [], attempts: [],
  initialContext: undefined, historyContext: undefined, review: undefined, first: undefined, source: undefined,
  knowledge: undefined, candidate: undefined, comparisonSubmitted: false, snapshotId: undefined });

export function retainedReadAllowed(state, url) {
  return !url.search && ((state.ownerId && url.pathname === `/api/v1/composition/objectives/${state.ownerId}`)
    || state.proposals.some(id => url.pathname === `/api/v1/composition/proposals/${id}`)
    || state.snapshotId && url.pathname === `/api/v1/comparison-snapshots/${state.snapshotId}`);
}

// Return undefined for unrelated routes so the pre-existing journey retains its guards.
export function retainedPostAllowed(state, url, body, { origin, controlId, providerId, count }) {
  if (url.origin !== origin || url.search) return undefined;
  const path = url.pathname;
  if (state.active && path === "/api/v1/composition/objective-list") return exact(body, ["control_owner_id"])
    && body.control_owner_id === controlId && count("retained_list");
  if (path === "/api/v1/composition/context" && body?.pack === RETAINED_PACK) {
    return state.active && same(body, reviewBody(controlId)) && count("retained_review");
  }
  if (path === "/api/v1/composition/objectives" && body?.review?.pack === RETAINED_PACK) {
    const ok = state.active && exact(body, ["submission_id", "review", "reviewed_by", "review_digest"])
      && submissionId(body.submission_id) && same(body.review, reviewBody(controlId))
      && body.reviewed_by === RETAINED_REVIEWER && body.review_digest === state.review?.review_digest && count("retained_grant");
    if (ok) state.ownerId = jobId(body.submission_id);
    return Boolean(ok);
  }
  if (state.ownerId && path === `/api/v1/composition/objectives/${state.ownerId}/proposal-context`) {
    if (body?.schema_version === "bluefire.composition-evidence-context-query.v1") {
      return exact(body, ["schema_version", "prior_attempt_id", "attempt_ids", "knowledge_digest"])
        && Boolean(state.first && state.knowledge) && body.prior_attempt_id === state.first.attempt_id
        && same(body.attempt_ids, [state.first.attempt_id]) && body.knowledge_digest === state.knowledge.knowledge_digest
        && count("retained_history_context");
    }
    return !state.first && exact(body, ["prior_attempt_id"]) && body.prior_attempt_id === null && count("retained_initial_context");
  }
  if (state.ownerId && path === `/api/v1/composition/objectives/${state.ownerId}/proposals`) {
    const history = state.proposals.length === 1;
    const keys = ["submission_id", "provider_id", "context_digest", "prior_attempt_id"];
    if (history) keys.push("schema_version", "attempt_ids", "knowledge_digest");
    const current = history ? state.historyContext : state.initialContext;
    const ok = state.proposals.length < 2 && exact(body, keys) && submissionId(body.submission_id)
      && body.provider_id === providerId && Boolean(current) && body.context_digest === current.context_digest
      && body.prior_attempt_id === (history ? state.first?.attempt_id : null)
      && (!history || body.schema_version === "bluefire.composition-evidence-proposal-request.v1"
        && same(body.attempt_ids, [state.first.attempt_id]) && body.knowledge_digest === state.knowledge?.knowledge_digest)
      && count("retained_proposal");
    if (ok) state.proposals.push(jobId(body.submission_id));
    return Boolean(ok);
  }
  if (state.ownerId && path === `/api/v1/composition/objectives/${state.ownerId}/attempts`) {
    const ok = state.attempts.length < 2 && state.proposals.length === state.attempts.length + 1
      && exact(body, ["submission_id", "proposal", "prior_attempt_id"])
      && submissionId(body.submission_id) && Boolean(state.candidate) && same(body.proposal, state.candidate)
      && body.prior_attempt_id === (state.attempts.length ? state.first?.attempt_id : null) && count("retained_attempt");
    if (ok) state.attempts.push(jobId(body.submission_id));
    return Boolean(ok);
  }
  if (state.ownerId && path === `/api/v1/composition/objectives/${state.ownerId}/knowledge`) {
    return Boolean(state.first) && exact(body, ["schema_version", "attempt_ids"])
      && body.schema_version === "bluefire.composition-knowledge-query.v1" && same(body.attempt_ids, [state.first.attempt_id])
      && count("retained_knowledge");
  }
  if (state.ownerId && path === `/api/v1/composition/objectives/${state.ownerId}/revoke`) {
    return exact(body, []) && count("retained_revoke");
  }
  if (state.active && path === "/api/v1/comparisons") {
    const ok = Boolean(state.first && state.second) && exact(body, ["run_ids"])
      && same(body.run_ids, [state.first.run_id, state.second.run_id]) && count("retained_comparison");
    if (ok) state.comparisonSubmitted = true;
    return Boolean(ok);
  }
  return undefined;
}

export function retainedResponse(state, path, body, data) {
  if (path === "/api/v1/composition/context" && body?.pack === RETAINED_PACK) { state.review = data; return true; }
  if (path === "/api/v1/composition/objectives" && body?.review?.pack === RETAINED_PACK) return true;
  if (state.ownerId && path.startsWith(`/api/v1/composition/objectives/${state.ownerId}/`)) {
    if (path.endsWith("/proposal-context")) {
      if (body?.schema_version === "bluefire.composition-evidence-context-query.v1") state.historyContext = data;
      else state.initialContext = data;
    }
    return true;
  }
  if (state.active && path === "/api/v1/comparisons" && state.comparisonSubmitted) { state.snapshotId = data.saved_snapshot?.snapshot_id; return true; }
  return false;
}

export async function authorizeRetainedPurpose(page, { origin, model, reviewer }) {
  await page.goto(`${origin}/#/settings`, { waitUntil: "domcontentloaded" });
  await page.getByRole("button", { name: `Edit Responses API · ${model}`, exact: true }).click();
  await page.getByRole("checkbox", { name: RETAINED_PURPOSE_LABEL, exact: true }).check();
  for (const [label, value] of [["Total request attempts", "2"], ["Total request bytes", "524288"], ["Total reserved output tokens", "2048"], ["Authorization duration in seconds", "300"]]) {
    await page.getByLabel(label, { exact: false }).fill(value);
  }
  await page.getByLabel("Operator identity for model usage", { exact: true }).fill(reviewer);
  await page.getByRole("checkbox", { name: "I authorize requests to this loopback endpoint.", exact: true }).check();
  await page.getByRole("checkbox", { name: "I authorize the selected model work, reviewed lab data and these usage limits.", exact: true }).check();
  await page.getByRole("button", { name: "Authorize reviewed model usage", exact: true }).click();
  await page.getByText("Authorization saved. No model request was sent. Select this provider in Assistant or run setup when ready.", { exact: true }).waitFor();
}

export async function runRetainedJourney(page, state, options) {
  const { origin, controlId, providerId, model, read, remainingMs, capture, setStage } = options;
  const postResponse = path => page.waitForResponse(response => response.request().method() === "POST" && response.url() === `${origin}/api/v1${path}`);
  const wait = async (get, predicate, maximum) => {
    const until = Date.now() + Math.min(maximum, remainingMs());
    while (Date.now() < until) {
      const value = await get();
      if (predicate(value)) return value;
      await delay(Math.min(400, remainingMs(), Math.max(1, until - Date.now())));
    }
    throw new Error("The retained-result proof did not reach its bounded saved state");
  };
  state.active = true;
  setStage("retained-objective-review");
  await page.goto(`${origin}/#/composition?${new URLSearchParams({ control: controlId })}`, { waitUntil: "domcontentloaded" });
  await page.getByLabel("Objective question", { exact: true }).fill(RETAINED_QUESTION);
  await page.getByRole("checkbox", { name: "Keep generated results for reuse within this objective", exact: true }).check();
  const reviewResponse = postResponse("/composition/context");
  await page.getByRole("button", { name: "Review finite delegation", exact: true }).click();
  const reviewed = await reviewResponse;
  assert.ok(reviewed.ok());
  state.review = await reviewed.json();
  assert.equal(state.review.pack, RETAINED_PACK);
  assert.equal(state.review.environment.control_owner_id, controlId);
  assert.equal(state.review.limits.per_attempt_wall_ms, 90000);
  await page.getByLabel("Delegation reviewed by", { exact: true }).fill(RETAINED_REVIEWER);
  await page.getByRole("checkbox", { name: "I authorize the reviewed finite capabilities, data effects, cleanup reserve and cumulative budgets for this objective.", exact: true }).check();
  const grantResponse = postResponse("/composition/objectives");
  await page.getByRole("button", { name: "Issue capability grant", exact: true }).click();
  const issued = await grantResponse;
  assert.ok(issued.ok());
  const objective = await issued.json();
  assert.equal(objective.owner.job_id, state.ownerId);
  const grant = objective.grant.document;
  assert.equal(grant.schema_version, "bluefire.capability-grant.v2");
  assert.equal(grant.pack, RETAINED_PACK);
  assert.equal(grant.environment.control_digest, options.controlDigest);
  assert.equal(grant.snapshot.artifact_context.retention.max_bytes_per_attempt, 262144);
  assert.equal(grant.snapshot.artifact_context.retention.max_artifacts_per_attempt, 1);
  assert.ok(grant.snapshot.methods.some(item => item.behavior_id === RETAINED_METHOD));
  const workspace = `${origin}/#/composition?${new URLSearchParams({ control: controlId, objective: state.ownerId })}`;
  const requestProposal = async (history) => {
    await page.getByRole("combobox", { name: "Configured model provider", exact: true }).selectOption(providerId);
    const pending = postResponse(`/composition/objectives/${state.ownerId}/proposals`);
    await page.getByRole("button", { name: history ? "Request history-aware revision" : "Request AI graph", exact: true }).click();
    const response = await pending;
    assert.ok(response.ok());
    let value = await response.json();
    value = await wait(() => read(`/composition/proposals/${value.job.job_id}`), item => item.job.state === "completed", 20000);
    assert.equal(value.job.job_id, state.proposals[history ? 1 : 0]);
    assert.equal(value.job.request.owner_id, state.ownerId);
    assert.equal(value.proposal.owner_id, state.ownerId);
    assert.equal(value.proposal.proposal_job_id, value.job.job_id);
    assert.equal(value.job.request.context.grant_id, grant.grant_id);
    assert.equal(value.proposal.context_digest, value.job.request.context.context_digest);
    assert.equal(value.job.request.submitted_request.context_digest, value.proposal.context_digest);
    assert.equal(value.proposal.prior_attempt_id, history ? state.first.attempt_id : null);
    assert.equal(value.proposal.schema_version, "bluefire.composition-ai-result.v3");
    assert.equal(value.proposal.provider.provider_id, providerId);
    assert.equal(value.proposal.provider.model, model);
    assert.equal(value.proposal.provider.attempts, 1);
    assert.equal(value.proposal.provider.used_fallback, false);
    assert.equal(value.candidate_ready, true);
    assert.equal(value.provider_outcome, "candidate");
    assertMetadataOnly(value.job.request.context);
    state.candidate = value.proposal.candidate;
    return value;
  };
  setStage("retained-original-proposal");
  const firstProposal = await requestProposal(false);
  assert.deepEqual(firstProposal.proposal.candidate, state.initialContext.initial_proposal);
  assert.equal(firstProposal.proposal.reconsideration, null);
  assert.deepEqual(firstProposal.job.request.context.retained_artifacts.available_sources, []);
  const execute = async index => {
    const pending = postResponse(`/composition/objectives/${state.ownerId}/attempts`);
    await page.getByRole("button", { name: "Start fresh attempt within grant", exact: true }).click();
    const submitted = await pending;
    assert.ok(submitted.ok());
    const id = state.attempts[index];
    const current = await wait(() => read(`/composition/objectives/${state.ownerId}`), value => value.attempts.some(attempt =>
      attempt.job_id === id && attempt.state === "completed" && attempt.progress.settlement === "settled" && attempt.progress.verified_result), 110000);
    const attempt = current.attempts.find(item => item.job_id === id);
    const run = await read(`/runs/${attempt.request.composition_attempt.run_id}`);
    return { current, attempt, run };
  };
  setStage("retained-original-execute");
  const first = await execute(0);
  const originalProof = verifyRetainedOriginal(first.attempt, first.run, { ownerId: state.ownerId, grant });
  state.first = originalProof.original;
  state.source = originalProof.source;
  setStage("retained-history-selection");
  const knowledgeResponse = postResponse(`/composition/objectives/${state.ownerId}/knowledge`);
  await page.getByRole("button", { name: "Findings across attempts", exact: true }).click();
  const knowledgeResult = await knowledgeResponse;
  assert.ok(knowledgeResult.ok());
  state.knowledge = await knowledgeResult.json();
  verifyReceiverKnowledge(state.knowledge, { ownerId: state.ownerId, attempt: first.attempt,
    run: first.run, sourceBinding: first.attempt.progress.verified_result.source_binding });
  await page.getByRole("checkbox", { name: "Use selected historical findings to reconsider earlier choices", exact: true }).check();
  setStage("retained-continuation-proposal");
  const secondProposal = await requestProposal(true);
  const captured = secondProposal.job.request.context;
  assert.equal(captured.schema_version, "bluefire.retained-composition-evidence-context.v1");
  assert.equal(captured.historical_context.knowledge_digest, state.knowledge.knowledge_digest);
  assert.equal(captured.facts.facts.find(fact => fact.kind === "receiver_result")?.value.decision, "policy_refused");
  assert.deepEqual(captured.historical_context.attempts, state.knowledge.attempts);
  assert.deepEqual(captured.retained_artifacts.available_sources, [state.source]);
  assertRetainedSource(captured.retained_artifacts.available_sources[0]);
  const revised = secondProposal.proposal;
  assert.equal(revised.candidate.steps[0].id, "reuse_retained_bundle");
  assert.equal(revised.candidate.steps[0].behavior_id, RETAINED_METHOD);
  assert.deepEqual(revised.candidate.steps[0].parameters, { source_ref: state.source.source_ref });
  const priorSteps = firstProposal.proposal.candidate.steps;
  const after = revised.candidate.steps;
  assert.equal(after.length, priorSteps.length);
  assert.deepEqual(after.slice(1).map(step => step.behavior_id), priorSteps.slice(1).map(step => step.behavior_id));
  assert.equal(after.find(step => step.behavior_id === "sandbox.fixture.transform.v1").parameters.redact_values, true);
  assert.ok(!after.some(step => step.behavior_id === "sandbox.fixture.create.v1"));
  const reasoning = revised.reconsideration.reconsidered_choices;
  assert.equal(reasoning.length, 1);
  assert.equal(reasoning[0].attempt_id, state.first.attempt_id);
  assert.equal(reasoning[0].compiled_digest, first.attempt.request.composition_attempt.compiled_digest);
  assert.equal(reasoning[0].step_id, "transform_fixture");
  assert.ok(reasoning[0].finding_refs.some(ref => state.knowledge.attempts[0].findings.some(finding =>
    finding.finding_id === ref.finding_id && same(finding.record_ref, ref.record_ref) && finding.step_id === state.source.step_id)));
  const inspectSources = async () => {
    const panel = page.getByRole("region", { name: "Captured available results", exact: true });
    await panel.waitFor({ state: "visible" });
    const detail = panel.locator("details").first();
    if (!await detail.evaluate(element => element.open)) await detail.locator("summary").click();
    const link = detail.getByRole("link", { name: "Inspect retained source run", exact: true });
    assert.ok((await link.getAttribute("href")).endsWith(`/runs/${state.source.run_id}`));
    for (const text of [state.source.source_ref, state.source.sha256, state.source.run_id]) await detail.getByText(text, { exact: true }).waitFor();
    await page.getByRole("region", { name: "Captured historical reasoning", exact: true }).waitFor();
    return panel;
  };
  await inspectSources();
  setStage("retained-proposal-reopen");
  await page.goto("about:blank", { waitUntil: "domcontentloaded" });
  const correlation = createReceiverReloadContextCorrelation(
    request => request.isNavigationRequest() && request.frame() === page.mainFrame() && new URL(request.url()).origin === origin,
    request => request.method() === "POST" && request.url() === `${origin}/api/v1/composition/objectives/${state.ownerId}/proposal-context`
      && request.postDataJSON()?.schema_version === "bluefire.composition-evidence-context-query.v1",
  );
  const reopenedResponse = page.waitForResponse(correlation.response, { timeout: Math.min(20000, remainingMs()) });
  const reopenedRequest = page.waitForRequest(correlation.request, { timeout: Math.min(20000, remainingMs()) });
  await page.goto(`${workspace}&proposal=${state.proposals[1]}`, { waitUntil: "domcontentloaded" });
  await reopenedRequest;
  assert.ok((await reopenedResponse).ok());
  const reopened = await read(`/composition/proposals/${state.proposals[1]}`);
  assert.deepEqual(reopened.proposal, revised);
  assert.deepEqual(reopened.job.request.context, captured);
  assert.equal(reopened.candidate_ready, true);
  await inspectSources();
  const refreshed = postResponse(`/composition/objectives/${state.ownerId}/proposal-context`);
  await page.getByRole("button", { name: "Refresh available results", exact: true }).click();
  const refreshedResponse = await refreshed;
  assert.ok(refreshedResponse.ok());
  assert.deepEqual((await refreshedResponse.json()).retained_artifacts.available_sources, [state.source]);
  if (capture) await capture("receiver-retained-source-1440x900");
  setStage("retained-continuation-execute");
  const second = await execute(1);
  state.second = verifyRetainedContinuation(second.attempt, second.run, { ownerId: state.ownerId, grant,
    source: state.source, original: state.first });
  assert.equal(second.current.attempts.length, 2);
  const originalAgain = second.current.attempts.find(item => item.job_id === first.attempt.job_id);
  assert.deepEqual(originalAgain.progress.verified_result, first.attempt.progress.verified_result);
  assert.deepEqual(originalAgain.progress.retained_artifact_capture, first.attempt.progress.retained_artifact_capture);
  const sourceRun = await read(`/runs/${state.first.run_id}`);
  assert.deepEqual(sourceRun.manifest, first.run.manifest);
  assert.deepEqual(sourceRun.evidence, first.run.evidence);
  setStage("retained-grant-revoke");
  const revokeResponse = postResponse(`/composition/objectives/${state.ownerId}/revoke`);
  await page.getByRole("button", { name: "Revoke", exact: true }).click();
  const revokedResponse = await revokeResponse;
  assert.ok(revokedResponse.ok());
  const revoked = await revokedResponse.json();
  assert.equal(revoked.grant.status, "revoked");
  assert.equal(revoked.grant.cleanup_state, "settled");
  options.onRevoked();
  setStage("retained-result-comparison");
  const query = new URLSearchParams({ compare_context: "1" });
  for (const id of [state.first.run_id, state.second.run_id]) query.append("compare_run", id);
  await page.goto(`${origin}/#/compare?${query}`);
  const comparisonResponse = postResponse("/comparisons");
  await page.getByRole("button", { name: "Compare selected", exact: true }).click();
  const compared = await comparisonResponse;
  assert.ok(compared.ok());
  const comparison = await compared.json();
  state.snapshotId = comparison.saved_snapshot.snapshot_id;
  assert.deepEqual(comparison.run_ids, [state.first.run_id, state.second.run_id]);
  assert.deepEqual(comparison.summaries.map(item => item.capability_objective.established), [false, true]);
  const delta = comparison.deltas[0];
  assert.equal(delta.objective_comparability, "comparable");
  assert.equal(delta.objective_changed, true);
  assert.ok(delta.signals.includes("objective_recovered"));
  await page.goto(`${origin}/#/compare?snapshot=${state.snapshotId}`);
  await page.getByRole("region", { name: "Comparison results", exact: true }).waitFor();
  const saved = await read(`/comparison-snapshots/${state.snapshotId}`);
  assert.equal(saved.source_integrity.status, "verified");
  assert.deepEqual(saved.comparison.run_ids, comparison.run_ids);
  assert.deepEqual(saved.comparison.summaries.map(item => item.capability_objective.established), [false, true]);
  if (capture) await capture("receiver-retained-fresh-comparison-1440x900");
  state.active = false;
  return { schema_version: "bluefire.installed-retained-execution.v1", pack: RETAINED_PACK,
    owner_id: state.ownerId, control_owner_id: controlId, grant_id: grant.grant_id, grant_status: "revoked",
    policy_digest: grant.environment.policy_digest, source: state.source, original: state.first, continuation: state.second,
    model: { purpose: "bluefire_receiver_retained_composition_proposal", requests: 2, authorization_max_requests: 2,
      initial_job_id: state.proposals[0], revised_job_id: state.proposals[1], metadata_only: true,
      reopened: true, reasoning_rendered: true, current_sources_rechecked: true },
    capture_before_cleanup: true, original_failure_preserved: true, source_metadata_preserved_after_cleanup: true,
    source_disposition: "sealed_until_run_bundle_deleted", comparison: { snapshot_id: state.snapshotId,
      snapshot_digest: saved.digest, run_ids: comparison.run_ids, source_integrity: "verified",
      objective_comparability: "comparable", objective_changed: true, objective_recovered: true, reopened: true } };
}
