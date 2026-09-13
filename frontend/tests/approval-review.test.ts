import { describe, expect, it } from "vitest";
import { continuationApprovalPreflight } from "../src/lib/approvalReview";
import type { AIProposalReview, PreflightReport, RunJob } from "../src/types";

function fixture() {
  const binding = { state_digest: "state", plan_digest: "plan", target_scope_digest: "scope", profile_id: "profile", maximum_tier: "controlled" };
  const request = { ...binding, approval_id: "fresh", status: "pending", expires_at: "2099-01-01T00:00:00Z" };
  const preflight: PreflightReport = { status: "approval_required", ready: false, approval_binding: binding, plan: { mode: "execute", steps: [{ step_id: "step" }] }, approval_envelope: { schema_version: "bluefire.approval-envelope.v1", scenario_id: "scenario", envelope_digest: "envelope", steps: [{ step_id: "step", options: [] }] } };
  const job: RunJob = { schema_version: "bluefire.job.v1", job_id: "job", kind: "scenario.run", state: "awaiting_approval", request: { approval_request_id: "original" }, progress: { approval_kind: "ai_proposal_execute", approval_request_id: "fresh", proposal_record_id: "proposal" }, result_ref: null, error: null };
  const review: AIProposalReview = { schema_version: "bluefire.ai-proposal-review.v1", job_id: "job", proposal_record_id: "proposal", source_run_id: "run", source_proposal_id: "source", state_digest: "old-state", plan_digest: "old-plan", proposal_digest: "proposal-digest", status: "accepted", record: {}, created_at: "2026-01-01T00:00:00Z", resolution: { approval_request_id: "fresh", continuation: { continuation_plan_digest: "plan", execute_approval_binding_digest: "fresh-binding" } }, execute_approval_review: { schema_version: "bluefire.continuation-approval-review.v1", job_id: "job", proposal_record_id: "proposal", approval_request_id: "fresh", preflight } };
  return { job, review, request, preflight };
}

describe("continuation approval review", () => {
  it("returns only the complete current request's review", () => {
    const value = fixture();
    expect(continuationApprovalPreflight(value.job, value.review, value.request)).toBe(value.preflight);
  });
  it("can retain an expired continuation for display without relaxing its receipt identity", () => {
    const value = fixture(); value.request.expires_at = "2000-01-01T00:00:00Z";
    expect(continuationApprovalPreflight(value.job, value.review, value.request)).toBeUndefined();
    expect(continuationApprovalPreflight(value.job, value.review, value.request, { forDisplayOnly: true })).toBe(value.preflight);
    value.job.progress.approval_request_id = "different";
    expect(continuationApprovalPreflight(value.job, value.review, value.request, { forDisplayOnly: true })).toBeUndefined();
  });
  const mutations: Array<[string, (value: ReturnType<typeof fixture>) => void]> = [
    ["another job", (v) => { v.review.job_id = "other"; }],
    ["another proposal", (v) => { v.review.proposal_record_id = "other"; }],
    ["original approval reused", (v) => { v.job.request!.approval_request_id = "fresh"; }],
    ["another pending request", (v) => { v.job.progress.approval_request_id = "other"; }],
    ["stale canonical request", (v) => { v.review.execute_approval_review!.approval_request_id = "other"; }],
    ["consumed request", (v) => { v.request.status = "consumed"; }],
    ["expired request", (v) => { v.request.expires_at = "2000-01-01T00:00:00Z"; }],
    ["missing canonical plan", (v) => { delete v.preflight.plan; }],
    ["missing envelope", (v) => { v.preflight.approval_envelope = null; }],
    ["stale continuation plan", (v) => { v.preflight.approval_binding!.plan_digest = "other"; }],
    ...(["state_digest", "plan_digest", "target_scope_digest", "profile_id", "maximum_tier"] as const).map((field): [string, (value: ReturnType<typeof fixture>) => void] => [`different ${field}`, (v) => { v.request[field] = "other"; }]),
  ];
  it.each(mutations)("refuses %s", (_name, mutate) => {
    const value = fixture();
    mutate(value);
    expect(continuationApprovalPreflight(value.job, value.review, value.request)).toBeUndefined();
  });
});
