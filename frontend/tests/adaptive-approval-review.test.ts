import { describe, expect, it, vi } from "vitest";
import { api, type ReplayPreparation } from "../src/lib/api";
import type { AdaptiveAuthorization, AdaptiveExecution } from "../src/lib/adaptive-execution";
import { continuationApprovalPreflight, hasAdaptiveApprovalReview, requiresAdaptiveReview, storedRunApprovalPreflight } from "../src/lib/approvalReview";
import { demoScenario } from "../src/lib/demo";
import type { AIProposalReview, PreflightReport, RunJob } from "../src/types";

const digest = `sha256:${"a".repeat(64)}`;
const methods = ["sandbox.collection.records.v1", "sandbox.collection.archive.v1"].map(id => ({ behavior_id: id, action_id: id }));
const policy: AdaptiveExecution = { schema_version: "bluefire.adaptive-execution.v1", steps: [{ step_id: "stage", methods }], eligible_outcomes: ["failed"], max_retries: 1, on_provider_failure: "stop" };

function fixture(adaptive = true) {
  const scenario = { ...structuredClone(demoScenario), ...(adaptive ? { adaptive_execution: policy } : {}) };
  const binding = { state_digest: digest, plan_digest: digest, target_scope_digest: digest, profile_id: "sandbox-execute.v1", maximum_tier: "controlled" };
  const approval = { ...binding, approval_id: "approval-reviewed", status: "pending", expires_at: "2099-01-01T00:00:00Z" };
  const planStep = { step_id: "stage", ...methods[0]!, parameters: {}, inputs: {}, expected_outputs: ["bundle"], required_capabilities: ["filesystem.write"], safety_tier: "controlled" };
  const authorization: AdaptiveAuthorization = {
    schema_version: "bluefire.adaptive-authorization.v1", authorization_digest: digest, plan_digest: digest, scenario_digest: digest, profile_digest: digest, catalog_authority_digest: digest,
    objective: "Review a finite retry", target_scope: { scope_refs: ["sandbox.workspace"] }, platform: "linux", policy, parameter_policy: "exact_reviewed_values_and_inputs", cleanup_policy: "always",
    limits: { max_steps: 12, max_seconds: 90, max_artifacts: 32, max_bytes: 1048576 },
    steps: [{ step_id: "stage", methods: methods.map(method => ({ plan_step: { ...planStep, ...method }, plan_step_digest: digest, behavior_contract_digest: digest, action_contract_digest: digest,
      execution_binding_digest: digest, capabilities: ["filesystem.write"], mutates: true, cleanup_action_id: "sandbox.cleanup.v1", cleanup_contract_digest: digest })) }],
  };
  const preflight: PreflightReport = { ready: false, status: "approval_required", plan: { mode: "execute", steps: [planStep] }, approval_binding: binding,
    approval_envelope: { schema_version: "bluefire.approval-envelope.v1", scenario_id: scenario.id, envelope_digest: digest, steps: [{ step_id: "stage", options: [] }] },
    ...(adaptive ? { adaptive_authorization: authorization } : {}),
  };
  const job: RunJob = { schema_version: "bluefire.job.v1", job_id: "job-reviewed", kind: "scenario.run", state: "awaiting_approval", progress: {}, approval_request: approval,
    request: { scenario, approval_request_id: approval.approval_id, _run_submission_preflight: preflight } };
  return { scenario, preflight, job, authorization };
}

describe("adaptive review requirements follow the saved job", () => {
  it.each(["direct", "submission", "replay"])("retains the requirement from the %s scenario when a returned review is missing", source => {
    const { scenario, preflight, job } = fixture();
    job.request = source === "direct" ? { scenario } : source === "submission" ? { _run_submission_request: { scenario } } : { replay_preparation: { scenario } };
    expect(requiresAdaptiveReview(job)).toBe(true);
    expect(hasAdaptiveApprovalReview(preflight, requiresAdaptiveReview(job))).toBe(true);
    delete preflight.adaptive_authorization;
    expect(hasAdaptiveApprovalReview(preflight, requiresAdaptiveReview(job))).toBe(false);
  });

  it("does not give a legacy job adaptive authority through current workspace defaults", () => {
    const { job, preflight } = fixture(false);
    expect(requiresAdaptiveReview(job)).toBe(false);
    expect(requiresAdaptiveReview(null)).toBe(false);
    expect(hasAdaptiveApprovalReview(preflight, requiresAdaptiveReview(job))).toBe(true);
    expect(storedRunApprovalPreflight(job)).toBe(preflight);
  });

  it.each([false, true])("refuses missing ordinary review in a saved submission (display-only=%s)", forDisplayOnly => {
    const { scenario, preflight, job } = fixture();
    delete job.request!.scenario;
    job.request!._run_submission_request = { scenario };
    delete preflight.adaptive_authorization;
    expect(storedRunApprovalPreflight(job, { forDisplayOnly })).toBeUndefined();
  });
});

describe("adaptive replay approval restoration", () => {
  function replay(adaptive = true) {
    const value = fixture(adaptive);
    const replayRequest = { exact: true };
    const prepared: ReplayPreparation = { schema_version: "bluefire.replay-preparation.v1", preparation_id: "prepared", preparation_context: {},
      binding: { source: { run_id: "run-source" }, replay_request: replayRequest }, replay_request: replayRequest, replay_extent: "full", scenario: value.scenario,
      lineage: {}, preflight: value.preflight, approval_created: false, effects_started: false };
    value.job.kind = "scenario.replay";
    value.job.request = { source_run_id: "run-source", approval_request_id: value.job.approval_request!.approval_id, replay_request: replayRequest, replay_preparation: prepared };
    return value;
  }

  it.each([false, true])("restores the original complete review without recompiling (adaptive=%s)", async adaptive => {
    const { job, preflight } = replay(adaptive);
    const fetch = vi.spyOn(globalThis, "fetch");
    await expect(api.preflightStoredJobRequest(job)).resolves.toEqual(preflight);
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each([false, true])("refuses a missing finite replay review without a public preflight fallback (display-only=%s)", async forDisplayOnly => {
    const { job, preflight } = replay();
    delete preflight.adaptive_authorization;
    const fetch = vi.spyOn(globalThis, "fetch");
    await expect(api.preflightStoredJobRequest(job, { forDisplayOnly })).rejects.toMatchObject({ code: "job_preflight_unavailable" });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("refuses an adaptive review bound to another plan", async () => {
    const { job, preflight } = replay();
    preflight.adaptive_authorization!.plan_digest = `sha256:${"b".repeat(64)}`;
    const fetch = vi.spyOn(globalThis, "fetch");
    await expect(api.preflightStoredJobRequest(job)).rejects.toMatchObject({ code: "job_preflight_unavailable" });
    expect(fetch).not.toHaveBeenCalled();
  });
});

it("requires finite review for a v4 continuation even when the parent uses a scenario reference", () => {
  const { job, preflight, authorization } = fixture();
  job.request = { scenario_id: demoScenario.id, approval_request_id: "original" };
  job.progress = { approval_kind: "ai_proposal_execute", approval_request_id: "approval-reviewed", proposal_record_id: "proposal" };
  const review: AIProposalReview = { schema_version: "bluefire.ai-proposal-review.v1", job_id: job.job_id, proposal_record_id: "proposal", source_run_id: "run-source", source_proposal_id: "source-proposal", state_digest: digest, plan_digest: digest, proposal_digest: digest, status: "accepted", record: { schema_version: "bluefire.ai-proposal-record.v4" }, created_at: "2026-01-01T00:00:00Z",
    resolution: { approval_request_id: "approval-reviewed", continuation: { continuation_plan_digest: digest, execute_approval_binding_digest: digest } },
    execute_approval_review: { schema_version: "bluefire.continuation-approval-review.v1", job_id: job.job_id, proposal_record_id: "proposal", approval_request_id: "approval-reviewed", preflight } };
  expect(continuationApprovalPreflight(job, review, job.approval_request)).toBe(preflight);
  delete preflight.adaptive_authorization;
  expect(continuationApprovalPreflight(job, review, job.approval_request)).toBeUndefined();
  expect(continuationApprovalPreflight(job, review, job.approval_request, { forDisplayOnly: true })).toBeUndefined();
  preflight.adaptive_authorization = authorization;
  expect(continuationApprovalPreflight(job, review, job.approval_request)).toBe(preflight);
});
