/* global structuredClone */
import assert from "node:assert/strict";
import { URL, URLSearchParams } from "node:url";
import { isDeepStrictEqual as same } from "node:util";
import { setTimeout as delay } from "node:timers/promises";
import { verifyReceiverKnowledge } from "./receiver-knowledge.mjs";
import { createReceiverReloadContextCorrelation } from "./receiver-guards.mjs";

export const EVIDENCE_PURPOSE = "bluefire_receiver_evidence_composition_proposal";
export const EVIDENCE_PURPOSE_LABEL = "Reconsider receiver graph choices using selected historical findings";
const exact = (value, keys) => value !== null && typeof value === "object" && !Array.isArray(value)
  && same(Object.keys(value).sort(), [...keys].sort());
const digest = value => typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);

// Only the already proved, failed receiver attempt can supply this context.
export function receiverEvidenceRequestAllowed(url, body, expected, submission = false) {
  const keys = ["schema_version", "prior_attempt_id", "attempt_ids", "knowledge_digest"];
  if (submission) keys.push("submission_id", "provider_id", "context_digest");
  return expected.authorizations === 2 && expected.settlement === "settled" && expected.objectiveEstablished === false
    && /^job-[0-9a-f]{32}$/.test(expected.ownerId ?? "") && /^attempt-[0-9a-f]{32}$/.test(expected.attemptId ?? "")
    && url.origin === expected.origin && !url.search
    && url.pathname === `/api/v1/composition/objectives/${expected.ownerId}/${submission ? "proposals" : "proposal-context"}`
    && exact(body, keys) && body.schema_version === (submission ? "bluefire.composition-evidence-proposal-request.v1" : "bluefire.composition-evidence-context-query.v1")
    && body.prior_attempt_id === expected.attemptId && same(body.attempt_ids, [expected.attemptId])
    && digest(expected.knowledgeDigest) && body.knowledge_digest === expected.knowledgeDigest
    && (!submission || (body.provider_id === expected.providerId && digest(expected.contextDigest)
      && body.context_digest === expected.contextDigest
      && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(body.submission_id ?? "")));
}

export function verifyReceiverEvidenceProposal(value, expected) {
  const { ownerId, attempt, run, sourceBinding, knowledge, initial, providerId, model } = expected;
  const marker = attempt.request.composition_attempt;
  const result = value.proposal;
  assert.equal(value.job.state, "completed");
  assert.equal(value.job.request.owner_id, ownerId);
  assert.equal(value.candidate_ready, true);
  assert.equal(value.provider_outcome, "candidate");
  assert.equal(result.schema_version, "bluefire.composition-ai-result.v2");
  assert.equal(result.owner_id, ownerId);
  assert.equal(result.proposal_job_id, value.job.job_id);
  assert.equal(result.prior_attempt_id, marker.attempt_id);
  assert.equal(result.provider.provider_id, providerId);
  assert.equal(result.provider.model, model);
  assert.equal(result.provider.attempts, 1);
  assert.equal(result.provider.used_fallback, false);
  for (const key of ["context_digest", "proposal_digest", "knowledge_digest", "model_context_digest"]) assert.ok(digest(result[key]));
  const context = value.job.request.context;
  assert.equal(context.schema_version, "bluefire.composition-evidence-proposal-context.v1");
  assert.equal(context.context_digest, result.context_digest);
  assert.equal(context.facts.prior_attempt_id, marker.attempt_id);
  const history = context.historical_context;
  assert.equal(history.knowledge_digest, knowledge.knowledge_digest);
  assert.equal(result.knowledge_digest, knowledge.knowledge_digest);
  assert.deepEqual(history.attempt_ids, [marker.attempt_id]);
  assert.deepEqual(history.attempts, knowledge.attempts);
  verifyReceiverKnowledge({ schema_version: "bluefire.composition-knowledge.v1", owner_id: ownerId,
    attempts: history.attempts, knowledge_digest: history.knowledge_digest }, { ownerId, attempt, run, sourceBinding });
  const submitted = value.job.request.submitted_request;
  assert.deepEqual(submitted, { schema_version: "bluefire.composition-evidence-proposal-request.v1",
    submission_id: value.job.job_id.slice(4).replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, "$1-$2-$3-$4-$5"),
    provider_id: providerId, context_digest: context.context_digest, prior_attempt_id: marker.attempt_id,
    attempt_ids: [marker.attempt_id], knowledge_digest: knowledge.knowledge_digest });
  const oldTransform = initial.steps.find(step => step.behavior_id === "sandbox.fixture.transform.v1");
  assert.equal(oldTransform.parameters.redact_values, false);
  const choice = history.choices.find(item => item.attempt_id === marker.attempt_id && item.step_id === oldTransform.id);
  assert.ok(choice && digest(choice.compiled_digest));
  assert.equal(choice.compiled_digest, marker.compiled_digest);
  assert.equal(choice.behavior_id, oldTransform.behavior_id);
  assert.deepEqual(choice.parameters, oldTransform.parameters);
  const changedSteps = structuredClone(initial.steps);
  changedSteps.find(step => step.id === oldTransform.id).parameters.redact_values = true;
  assert.deepEqual(result.candidate.steps, changedSteps);
  assert.deepEqual(result.candidate.edges, initial.edges);
  assert.equal(result.candidate.start, initial.start);
  assert.ok(result.candidate.evidence_refs.length > 0);
  assert.ok(result.candidate.evidence_refs.every(ref => context.facts.facts.some(fact => fact.fact_id === ref)));
  const changed = result.reconsideration.reconsidered_choices;
  assert.equal(changed.length, 1);
  assert.equal(changed[0].attempt_id, marker.attempt_id);
  assert.equal(changed[0].compiled_digest, choice.compiled_digest);
  assert.equal(changed[0].step_id, oldTransform.id);
  assert.ok(typeof changed[0].reason === "string" && changed[0].reason.trim());
  assert.ok(changed[0].finding_refs.length > 0 && changed[0].finding_refs.length <= 16);
  const findings = history.attempts.flatMap(item => item.findings);
  const cited = changed[0].finding_refs.map(ref => {
    const finding = findings.find(item => item.finding_id === ref.finding_id);
    assert.ok(finding, "Reasoning must cite an actual captured finding");
    assert.deepEqual(ref.record_ref, finding.record_ref);
    assert.equal(finding.applicability.status, "historical_only");
    return finding;
  });
  assert.ok(cited.some(finding => initial.steps.findIndex(step => step.id === finding.step_id)
    > initial.steps.findIndex(step => step.id === oldTransform.id)), "An earlier choice must use a finding from later in the failed route");
  assert.equal(new Set(cited.map(item => item.finding_id)).size, cited.length);
  assert.deepEqual(result.reconsideration.refresh_requirements.map(item => item.prerequisite).sort(),
    ["attempt_cleanup", "retained_receiver_control", "runner_environment"]);
  assert.ok(result.reconsideration.refresh_requirements.every(item => typeof item.explanation === "string" && item.explanation.trim()));
  return { schema_version: "bluefire.installed-evidence-proposal.v1", owner_id: ownerId,
    attempt_id: marker.attempt_id, source_run_id: run.run_id, job_id: value.job.job_id,
    proposal_digest: result.proposal_digest, context_digest: result.context_digest, knowledge_digest: result.knowledge_digest,
    purpose: EVIDENCE_PURPOSE, provider_id: providerId, model_authorization_requests: 1,
    reconsidered_step_id: oldTransform.id, supporting_findings: cited.length, later_finding_reused: true,
    original_redact_values: false, proposed_redact_values: true, original_objective_established: false,
    candidate_ready: true, source_matches_run: true, historical_only: true };
}

export async function authorizeReceiverEvidence(page, { origin, model, reviewer }) {
  await page.goto(`${origin}/#/settings`, { waitUntil: "domcontentloaded" });
  await page.getByRole("button", { name: `Edit Responses API · ${model}`, exact: true }).click();
  await page.getByRole("checkbox", { name: EVIDENCE_PURPOSE_LABEL, exact: true }).check();
  await page.getByLabel("Total request attempts", { exact: false }).fill("1");
  await page.getByLabel("Total request bytes", { exact: false }).fill("262144");
  await page.getByLabel("Total reserved output tokens", { exact: false }).fill("1024");
  await page.getByLabel("Authorization duration in seconds", { exact: false }).fill("300");
  await page.getByLabel("Operator identity for model usage", { exact: true }).fill(reviewer);
  await page.getByRole("checkbox", { name: "I authorize requests to this loopback endpoint.", exact: true }).check();
  await page.getByRole("checkbox", { name: "I authorize the selected model work, reviewed lab data and these usage limits.", exact: true }).check();
  await page.getByRole("button", { name: "Authorize reviewed model usage", exact: true }).click();
  await page.getByText("Authorization saved. No model request was sent. Select this provider in Assistant or run setup when ready.", { exact: true }).waitFor();
}

export async function inspectReceiverEvidenceProposal(page, expected) {
  const { origin, ownerId, controlId, providerId, readProposal, readObjective, remainingMs, capture } = expected;
  const workspace = `${origin}/#/composition?${new URLSearchParams({ control: controlId, objective: ownerId })}`;
  await page.goto(workspace, { waitUntil: "domcontentloaded" });
  const knowledgeResponse = page.waitForResponse(response => response.url() === `${origin}/api/v1/composition/objectives/${ownerId}/knowledge`
    && response.request().method() === "POST");
  await page.getByRole("button", { name: "Findings across attempts", exact: true }).click();
  const response = await knowledgeResponse;
  assert.ok(response.ok());
  const knowledge = await response.json();
  verifyReceiverKnowledge(knowledge, expected);
  await page.getByRole("checkbox", { name: "Use selected historical findings to reconsider earlier choices", exact: true }).check();
  await page.getByRole("combobox", { name: "Configured model provider", exact: true }).selectOption(providerId);
  const submission = page.waitForResponse(item => item.url() === `${origin}/api/v1/composition/objectives/${ownerId}/proposals` && item.request().method() === "POST");
  await page.getByRole("button", { name: "Request history-aware revision", exact: true }).click();
  const submitted = await submission;
  assert.ok(submitted.ok());
  let value = await submitted.json();
  const jobId = value.job.job_id;
  const until = Date.now() + Math.min(20_000, remainingMs());
  while (value.job.state !== "completed" && Date.now() < until) {
    await delay(Math.min(500, remainingMs(), Math.max(1, until - Date.now())));
    value = await readProposal(jobId);
  }
  const proof = verifyReceiverEvidenceProposal(value, { ...expected, knowledge });
  const inspect = async () => {
    const panel = page.getByRole("region", { name: "Captured historical reasoning", exact: true });
    await panel.waitFor({ state: "visible" });
    const details = panel.locator("details").filter({ has: page.getByText("Earlier choice and source findings", { exact: true }) });
    await details.locator(":scope > summary").click();
    await details.getByText("sandbox.fixture.transform.v1", { exact: true }).waitFor();
    await details.getByText('{"redact_values":false}', { exact: true }).waitFor();
    const links = details.getByRole("link", { name: "Open captured source run", exact: true });
    assert.equal(await links.count(), proof.supporting_findings);
    for (let index = 0; index < proof.supporting_findings; index += 1) {
      assert.ok((await links.nth(index).getAttribute("href")).endsWith(`/runs/${encodeURIComponent(expected.run.run_id)}`));
      await details.getByText(value.proposal.reconsideration.reconsidered_choices[0].finding_refs[index].finding_id, { exact: true }).waitFor();
    }
    await panel.getByText("Model reasoning about required refreshes", { exact: true }).waitFor();
    return panel;
  };
  await inspect();
  // A fresh document must recover the exact captured context, not merely retain React state.
  await page.goto("about:blank", { waitUntil: "domcontentloaded" });
  const correlation = createReceiverReloadContextCorrelation(
    request => request.isNavigationRequest() && request.frame() === page.mainFrame() && new URL(request.url()).origin === origin,
    request => request.method() === "POST" && request.url() === `${origin}/api/v1/composition/objectives/${ownerId}/proposal-context`
      && request.postDataJSON()?.schema_version === "bluefire.composition-evidence-context-query.v1",
  );
  const contextRequest = page.waitForRequest(correlation.request, { timeout: Math.min(20_000, remainingMs()) });
  const contextResponse = page.waitForResponse(correlation.response, { timeout: Math.min(20_000, remainingMs()) });
  await page.goto(`${workspace}&proposal=${encodeURIComponent(jobId)}`, { waitUntil: "domcontentloaded" });
  await contextRequest;
  const freshContext = await contextResponse;
  assert.ok(freshContext.ok());
  const reopenedContext = await freshContext.json();
  assert.equal(reopenedContext.schema_version, "bluefire.composition-evidence-proposal-context.v1");
  assert.equal(reopenedContext.context_digest, value.proposal.context_digest);
  assert.deepEqual(reopenedContext.historical_context, value.job.request.context.historical_context);
  const panel = await inspect();
  const reopened = await readProposal(jobId);
  assert.deepEqual(reopened.job.request, value.job.request);
  assert.deepEqual(reopened.proposal, value.proposal);
  if (capture) await capture(panel);
  const unchanged = await readObjective();
  assert.equal(unchanged.attempts.length, 1);
  assert.equal(unchanged.attempts[0].job_id, expected.attempt.job_id);
  assert.deepEqual(unchanged.attempts[0].request.composition_attempt, expected.attempt.request.composition_attempt);
  assert.equal(unchanged.attempts[0].progress.verified_result.objective.established, false);
  assert.equal(unchanged.attempts[0].progress.verified_result_digest, expected.attempt.progress.verified_result_digest);
  return { ...proof, reopened: true, rendered_reasoning: true, unchanged_attempts: true, additional_executions: 0 };
}
