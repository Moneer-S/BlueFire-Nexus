import { beforeEach, expect, it } from "vitest";
import { checkedCompositionContext, checkedCompositionObjective, checkedCompositionProposal, checkedCompositionReview, clearCompositionPending, compositionConfirmed, readCompositionPending, storeCompositionPending, type CompositionPending } from "../src/lib/composition";
import { attemptFixture, contextFixture, controlId, grantRequestFixture, objectiveFixture, ownerId, proposalFixture, proposalId, question, refusalFixture, reviewFixture, testDigest } from "./composition-fixture";
import { clearCompositionControl, compositionControlConfirmed, readCompositionControls, storeCompositionControl } from "../src/lib/composition";
import { clearCompositionCancellation, compositionCanRevise, compositionCancellationConfirmed, readCompositionCancellations, storeCompositionCancellation } from "../src/lib/composition";

beforeEach(() => localStorage.clear());
const pending = (): CompositionPending => ({ kind: "proposal", owner: ownerId, control: controlId, id: proposalId, body: { submission_id: "cccccccc-cccc-cccc-cccc-cccccccccccc", provider_id: "configured", context_digest: testDigest, prior_attempt_id: null } });
it("retains an exact submission across reload and refuses replacement", () => {
  const value = pending(); storeCompositionPending(value);
  expect(readCompositionPending()).toEqual(value);
  expect(() => storeCompositionPending({ ...value, body: { ...value.body, provider_id: "other" } })).toThrow();
  expect(() => clearCompositionPending({ ...value, id: ownerId })).toThrow();
  clearCompositionPending(value); expect(readCompositionPending()).toBeUndefined();
});
it("fails closed on malformed saved recovery state", () => {
  localStorage.setItem("bluefire.composition.pending.v1", '{"kind":"attempt"}');
  expect(readCompositionPending).toThrow();
});
it("requires exact submitted provider/context/prior identity even for failed proposals", () => {
  const value = proposalFixture();
  expect(compositionConfirmed(value, pending())).toBe(true);
  value.proposal = null; value.provider_outcome = "unknown";
  expect(compositionConfirmed(value, pending())).toBe(true);
  value.job.request.submitted_request = { ...pending().body, provider_id: "substituted" };
  expect(compositionConfirmed(value, pending())).toBe(false);
});
it("does not resolve queued attempts from job identity alone", () => {
  const value = objectiveFixture(); const operation = { ...pending(), kind: "attempt" as const, body: { submission_id: "cccccccc-cccc-cccc-cccc-cccccccccccc", proposal: contextFixture().initial_proposal, prior_attempt_id: null } };
  value.attempts = [{ job_id: proposalId, kind: "composition.attempt", state: "queued", request: { composition_attempt: { parent_job_id: ownerId, grant_id: value.grant.document.grant_id, grant_digest: testDigest, attempt_id: `attempt-${"c".repeat(32)}`, compiled_digest: testDigest, run_id: "run-proof" } }, progress: {} }];
  expect(compositionConfirmed(value, operation)).toBe(false);
  value.attempts[0]!.progress.submitted_request = operation.body;
  expect(compositionConfirmed(value, operation)).toBe(true);
  value.attempts[0]!.progress.submitted_request = { ...operation.body, prior_attempt_id: "different" };
  expect(compositionConfirmed(value, operation)).toBe(false);
});
it("rejects cross-objective/control responses and changed review questions", () => {
  expect(() => checkedCompositionObjective(objectiveFixture(), proposalId, controlId)).toThrow();
  expect(() => checkedCompositionObjective(objectiveFixture(), ownerId, proposalId)).toThrow();
  expect(() => checkedCompositionReview(reviewFixture(), { control_owner_id: controlId, question: "changed", limits: null })).toThrow();
  expect(checkedCompositionReview(reviewFixture(), { control_owner_id: controlId, question, limits: null }).review_digest).toBe(testDigest);
});
it("rejects stale context identity and malformed typed projections", () => {
  expect(() => checkedCompositionContext(contextFixture(), "grant-other")).toThrow();
  const value = contextFixture(); value.initial_scenario = {} as typeof value.initial_scenario;
  expect(() => checkedCompositionContext(value, value.grant_id)).toThrow();
});
it("checks saved provider graph ownership and rejects fallback provenance", () => {
  expect(checkedCompositionProposal(proposalFixture(), proposalId, ownerId).candidate_ready).toBe(true);
  expect(() => checkedCompositionProposal(proposalFixture(), proposalId, controlId)).toThrow();
  const value = proposalFixture(); Object.assign(value.proposal!.provider, { used_fallback: true });
  expect(() => checkedCompositionProposal(value, proposalId, ownerId)).toThrow();
});
it("retains unknown stop/revoke/continue intent independently of a pending effect", () => {
  storeCompositionPending(pending()); storeCompositionControl(ownerId, "stop");
  expect(readCompositionControls()[ownerId]).toBe("stop");
  expect(compositionControlConfirmed(objectiveFixture(), "stop")).toBe(false);
  const value = objectiveFixture(); value.grant.status = "paused";
  expect(compositionControlConfirmed(value, "stop")).toBe(true);
  expect(() => clearCompositionControl(ownerId, "revoke")).toThrow();
  clearCompositionControl(ownerId, "stop");
  expect(readCompositionControls()).toEqual({}); expect(readCompositionPending()).toEqual(pending());
});
it("never weakens an unresolved revocation or resumes across an unknown stop", () => {
  storeCompositionControl(ownerId, "stop");
  expect(() => storeCompositionControl(ownerId, "continue")).toThrow();
  storeCompositionControl(ownerId, "revoke");
  expect(() => storeCompositionControl(ownerId, "stop")).toThrow();
  expect(() => storeCompositionControl(ownerId, "continue")).toThrow();
  expect(readCompositionControls()[ownerId]).toBe("revoke");
});
it("retains exact cancellation and only reconciles the independently stopped proposal", () => {
  storeCompositionCancellation(ownerId, proposalId);
  expect(readCompositionCancellations()).toEqual({ [ownerId]: proposalId });
  expect(() => storeCompositionCancellation(ownerId, controlId)).toThrow();
  const value = proposalFixture();
  expect(compositionCancellationConfirmed(value, ownerId, proposalId)).toBe(false);
  value.job.progress.stopped = true;
  expect(compositionCancellationConfirmed(value, ownerId, proposalId)).toBe(false);
  value.candidate_ready = false;
  expect(compositionCancellationConfirmed(value, ownerId, proposalId)).toBe(true);
  expect(compositionCancellationConfirmed(value, controlId, proposalId)).toBe(false);
  expect(() => clearCompositionCancellation(ownerId, controlId)).toThrow();
  clearCompositionCancellation(ownerId, proposalId); expect(readCompositionCancellations()).toEqual({});
});
it("does not claim an established outcome from another run or incomplete checks", () => {
  const value = objectiveFixture();
  value.attempts = [{ job_id: proposalId, kind: "composition.attempt", state: "completed", request: { composition_attempt: { parent_job_id: ownerId, grant_id: value.grant.document.grant_id, grant_digest: testDigest, attempt_id: `attempt-${"c".repeat(32)}`, compiled_digest: testDigest, run_id: "run-proof" } }, progress: { verified_result_digest: testDigest, verified_result: { run_id: "different-run", objective: { established: true, checks: {} } } } }];
  expect(() => checkedCompositionObjective(value, ownerId, controlId)).toThrow();
  const result = value.attempts[0]!.progress.verified_result as { run_id: string; objective: { established: boolean; checks: Record<string, boolean> } };
  result.run_id = "run-proof";
  result.objective.checks = Object.fromEntries(["receiver_verified", "policy_unchanged", "data_class_preserved", "record_count_preserved", "all_records_redacted", "accepted", "run_cleaned", "receiver_closed"].map(key => [key, true]));
  expect(checkedCompositionObjective(value, ownerId, controlId)).toBe(value);
  result.objective.checks.run_cleaned = false;
  expect(() => checkedCompositionObjective(value, ownerId, controlId)).toThrow();
});
it("revises only exact policy-refused evidence with settled cleanup and preserved records", () => {
  const value = objectiveFixture(); const attempt = attemptFixture();
  expect(compositionCanRevise(attempt, value)).toBe(true);
  expect(compositionCanRevise(attemptFixture(true), value)).toBe(false);
  const result = attempt.progress.verified_result as { receiver_result: Record<string, unknown>; cleanup: Record<string, unknown> };
  result.receiver_result.record_count = 0; expect(compositionCanRevise(attempt, value)).toBe(false);
  result.receiver_result.record_count = 8; result.cleanup.run = "incomplete"; expect(compositionCanRevise(attempt, value)).toBe(false);
});
it("clears a refused grant only from the exact durable immutable submission", () => {
  const operation: CompositionPending = { kind: "grant", owner: ownerId, control: controlId, id: ownerId, body: grantRequestFixture() };
  const value = refusalFixture();
  expect(checkedCompositionObjective(value, ownerId, controlId)).toBe(value);
  expect(compositionConfirmed(value, operation)).toBe(true);
  value.owner.progress.submitted_request = { ...operation.body, reviewed_by: "different" };
  expect(compositionConfirmed(value, operation)).toBe(false);
  const missing = refusalFixture(); missing.owner.progress.submitted_request = undefined;
  expect(() => checkedCompositionObjective(missing, ownerId, controlId)).toThrow();
});
it.each(["composition_review_changed", "composition_admission_unavailable", "composition_admission_interrupted"])("accepts terminal refusal %s but never treats in-progress admission as refused", code => {
  const value = refusalFixture(); value.owner.progress.admission = { accepted: false, problem: { code, message: "Review this delegation again." } };
  expect(checkedCompositionObjective(value, ownerId, controlId)).toBe(value);
  value.owner.state = "queued";
  expect(() => checkedCompositionObjective(value, ownerId, controlId)).toThrow();
  value.owner.state = "completed"; value.owner.progress.admission = { accepted: false, problem: { code: "composition_admission_pending", message: "Not yet admitted." } };
  expect(() => checkedCompositionObjective(value, ownerId, controlId)).toThrow();
});
