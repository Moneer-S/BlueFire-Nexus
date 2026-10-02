import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AdaptiveRunPath } from "../src/components/AdaptiveRunPath";
import { RunReview } from "../src/pages/Runs";
import { decisionProvenance, recordedPathNodes, selectedAttempt } from "../src/lib/adaptive-run";
import { demoCatalog } from "../src/lib/demo";
import type { AIProposal, CatalogResponse, RunRecord } from "../src/types";

// Authored component fixtures exercise presentation; they are not observed runs.
const primary = "sandbox.discovery.list.v1", alternate = "sandbox.discovery.metadata.v1", third = "sandbox.discovery.hash.v1";
const digest = `sha256:${"a".repeat(64)}`;
const catalog: CatalogResponse = { ...demoCatalog, behaviors: [
  ...demoCatalog.behaviors, { ...demoCatalog.behaviors[0]!, id: primary, title: "Discover records" },
  { ...demoCatalog.behaviors[0]!, id: third, title: "Hash selected records" },
], actions: [
  ...demoCatalog.actions, { ...demoCatalog.actions[0]!, id: primary, title: "List owned files" },
  { ...demoCatalog.actions[0]!, id: alternate, title: "Inspect file metadata" },
  { ...demoCatalog.actions[0]!, id: third, title: "Hash selected files" },
] };
function fixture(): RunRecord {
  return { run_id: "authored-run", mode: "execute", status: "completed", objective: "Verify the original collection objective", objective_reached: false,
    steps: [
      { step_id: "discover", behavior_id: primary, action_id: primary, status: "failed", runner_status: "failed", request_hash: "original-request", execution_disposition: "execute", planner_decision_id: "decision-original", evidence_ids: ["original-evidence"] },
      { step_id: "discover", behavior_id: alternate, action_id: alternate, status: "success", runner_status: "success", request_hash: "retry-request", execution_disposition: "execute", planner_decision_id: "decision-retry", evidence_ids: [] },
    ], ai_proposals: [{ schema_version: "bluefire.ai-proposal-record.v4", run_id: "authored-run", current_step_id: "discover", deterministic_decision_id: "decision-original", outcome: "failed",
      application_status: "applied_reviewed_method", application_reason: "Reviewed method selected.",
      proposal: { schema_version: "bluefire.ai-proposal.v2", proposal_id: "authored-choice", proposal_type: "select_registered_action", selected_step_id: "discover", selected_behavior_id: alternate, selected_action_id: alternate, rationale: "The file list failed; metadata can inspect the same input.", parameter_changes: [], alternatives: [], confidence: .8, requires_operator_review: false } as AIProposal,
      applied_step: { step_id: "discover", behavior_id: alternate, action_id: alternate },
      provider: { effective_provider_id: "deterministic-offline.v1", model: "software-test-model", used_fallback: false }, provider_attempt: { provider_id: "deterministic-offline.v1", kind: "deterministic", model: "software-test-model" }, provider_called: true, decision_source: "deterministic_provider",
      planner_state: { observations: { attempts: [{ step_id: "discover", failure: { classification: "execution_failure" }, evidence: [{ evidence_id: "original-evidence" }] }], remaining_budgets: { steps: 3, seconds: 20, retries: 1 }, unknowns: ["Target prevention has not been established."] } },
    }] };
}

function v5Fixture(): RunRecord {
  const run = fixture();
  const record = structuredClone(run.ai_proposals![0]!);
  record.schema_version = "bluefire.ai-proposal-record.v5";
  record.proposal_policy_digest = digest;
  record.planner_state_digest = digest;
  record.proposal_policy = { schema_version: "bluefire.ai-proposal-policy.v3", maximum_adaptive_retries: 2, adaptive_retries_used: 0,
    maximum_step_retries: 2, step_retries_used: 0, adaptive_policy_digest: digest, remaining_steps: 3,
    attempted_methods: [{ step_id: "discover", behavior_id: primary, action_id: primary }] };
  const state = record.planner_state as Record<string, unknown>;
  const observations = state.observations as Record<string, unknown>;
  state.schema_version = "bluefire.planner-state.v3";
  state.observations = { ...observations, schema_version: "bluefire.runtime-observations.v2",
    remaining_budgets: { steps: 3, seconds: 20, retries: 2, step_retries: 2 } };
  run.ai_proposals = [record];
  return run;
}

function multipleV5Fixture(): RunRecord {
  const run = v5Fixture();
  const first = run.ai_proposals![0]!;
  const second = structuredClone(first);
  second.current_step_id = "discover";
  second.deterministic_decision_id = "decision-retry";
  second.outcome = "failed";
  second.proposal = { ...first.proposal!, proposal_id: "authored-choice-2", selected_behavior_id: third, selected_action_id: third,
    rationale: "The second method failed; the remaining reviewed method can still inspect the same input." };
  second.applied_step = { step_id: "discover", behavior_id: third, action_id: third };
  second.planner_state_digest = `sha256:${"b".repeat(64)}`;
  second.planner_state = { ...(first.planner_state as Record<string, unknown>), deterministic_decision: {
    decision_id: "decision-retry", run_id: "authored-run", current_state_digest: digest } };
  second.proposal_policy = { schema_version: "bluefire.ai-proposal-policy.v3", maximum_adaptive_retries: 2, adaptive_retries_used: 1,
    maximum_step_retries: 2, step_retries_used: 1, adaptive_policy_digest: digest, remaining_steps: 2,
    attempted_methods: [{ step_id: "discover", behavior_id: primary, action_id: primary },
      { step_id: "discover", behavior_id: alternate, action_id: alternate }] };
  const secondState = second.planner_state as Record<string, unknown>;
  const secondObservations = secondState.observations as Record<string, unknown>;
  secondState.observations = { ...secondObservations,
    remaining_budgets: { steps: 2, seconds: 10, retries: 1, step_retries: 1 } };
  second.proposal_policy_digest = `sha256:${"c".repeat(64)}`;
  run.steps[1]!.status = "failed";
  run.steps[1]!.runner_status = "failed";
  run.steps.push({ step_id: "discover", behavior_id: third, action_id: third, status: "success", runner_status: "success",
    request_hash: "third-request", execution_disposition: "execute", planner_decision_id: "decision-final", evidence_ids: [] });
  run.ai_proposals = [first, second];
  return run;
}

describe("recorded adaptive path", () => {
  it("keeps both exact attempts on one node and separates selection, runner result and independent evidence", () => {
    const run = fixture(); render(<AdaptiveRunPath run={run} catalog={catalog}/>);
    const path = screen.getByRole("region", { name: "Recorded adaptive path" });
    expect(recordedPathNodes(run)).toHaveLength(1);
    expect(within(path).getAllByRole("list", { name: "Attempts at this step" })).toHaveLength(1);
    expect(within(path).getByText("Attempt 1 · run position 1")).toBeVisible();
    expect(within(path).getByText("Attempt 2 · run position 2")).toBeVisible();
    expect(within(path).getByText("List owned files")).toBeVisible();
    expect(within(path).getByText("Chosen alternative: Inspect file metadata")).toBeVisible();
    expect(within(path).getByText("Execution error · Runner returned failed")).toBeVisible();
    expect(within(path).getByText("Reported success · Runner returned success")).toBeVisible();
    expect(within(path).getByText(/Deterministic provider · software evidence/)).toBeVisible();
    expect(within(path).getAllByText("0 independently observed records")).toHaveLength(2);
    expect(within(path).queryByText(/Live provider response/)).not.toBeInTheDocument();
    expect(run.objective_reached).toBe(false);
  });

  it("does not claim dispatch from an applied proposal or from a different action's later result", () => {
    const run = fixture(); run.steps[1]!.action_id = primary;
    expect(selectedAttempt(run, run.ai_proposals![0]!)).toBeUndefined();
    render(<AdaptiveRunPath run={run} catalog={catalog}/>);
    expect(screen.getByText("Selection applied; no matching attempt is recorded.")).toBeVisible();
    expect(within(screen.getByRole("region", { name: "Recorded adaptive decision" })).queryByText("Runner returned success")).not.toBeInTheDocument();
  });

  it("retains a retry refused before dispatch without claiming its effect", () => {
    const run = fixture(); Object.assign(run.steps[1]!, { status: "blocked", runner_status: undefined, request_hash: undefined, policy: { allowed: false } });
    render(<AdaptiveRunPath run={run} catalog={catalog}/>);
    expect(screen.getByText("Stopped by BlueFire policy · Refused before dispatch")).toBeVisible();
    expect(within(screen.getByRole("region", { name: "Recorded adaptive decision" })).getByText("Refused before dispatch")).toBeVisible();
  });

  it.each([true, false])("retains an interrupted selected attempt without claiming a runner result (dispatch requested=%s)", dispatched => {
    const run = fixture();
    Object.assign(run.steps[1]!, { status: "failed", runner_status: undefined, runner_task_id: "interrupted-task", interruption: {
      schema_version: "bluefire.execution-interruption.v1", dispatch_requested: dispatched, effect_outcome: "unknown", runner_result_received: false,
      process_tree_stopped: true, cooperative_requested: true, cooperative_acknowledged: false, forced_tree_termination: true, control_cleanup_verified: true,
    } });
    const label = dispatched ? "Dispatch interrupted; effects unknown" : "Cancelled before dispatch; no runner result";
    expect(selectedAttempt(run, run.ai_proposals![0]!)).toBe(run.steps[1]);
    render(<AdaptiveRunPath run={run} catalog={catalog}/>);
    expect(screen.getByText("Attempt 2 · run position 2")).toBeVisible();
    expect(screen.getByText(`${dispatched ? "Interrupted" : "Cancelled before dispatch"} · ${label}`)).toBeVisible();
    const decision = screen.getByRole("region", { name: "Recorded adaptive decision" });
    expect(within(decision).getByText("Chosen alternative: Inspect file metadata")).toBeVisible();
    expect(within(decision).getByText(label)).toBeVisible();
    expect(within(decision).queryByText(/Runner returned|Refused before dispatch/)).not.toBeInTheDocument();
  });

  it("does not relink an unrelated run or an unmatched decision to these attempts", () => {
    const run = fixture(); run.ai_proposals![0]!.run_id = "other-run";
    expect(selectedAttempt(run, run.ai_proposals![0]!)).toBeUndefined();
    render(<AdaptiveRunPath run={run} catalog={catalog}/>);
    expect(screen.getByText("A decision could not be linked to its original attempt.")).toBeVisible();
  });

  it.each(["stopped_budget_exhausted", "stopped_no_permitted_choice", "rejected_policy", "configured_fallback"])("shows %s without requiring a returned proposal or invented model result", status => {
    const run = fixture(); run.steps.pop();
    Object.assign(run.ai_proposals![0]!, { application_status: status, proposal: null, provider: null, provider_called: status === "rejected_policy", decision_source: status === "configured_fallback" ? "configured_deterministic_fallback" : "none" });
    render(<AdaptiveRunPath run={run} catalog={catalog}/>);
    expect(screen.getByText("No alternative selected")).toBeVisible();
    expect(screen.queryByText(/Chosen alternative/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Live provider response/)).not.toBeInTheDocument();
  });

  it("distinguishes configured live response provenance from fallback without treating either as execution", () => {
    const record = fixture().ai_proposals![0]!;
    Object.assign(record, { decision_source: "provider", provider_attempt: { kind: "openai_compatible", provider_id: "authorized-local.v1", model: "configured-model" }, provider: { effective_provider_id: "authorized-local.v1", model: "configured-model", used_fallback: false } });
    expect(decisionProvenance(record).label).toBe("Live provider response");
    record.provider!.used_fallback = true;
    expect(decisionProvenance(record).label).toBe("Configured fallback · not live model evidence");
    Object.assign(record, { provider: null, proposal: null, decision_source: "none" });
    expect(decisionProvenance(record).label).toBe("Provider request did not produce a permitted choice");
  });

  it("renders coherent v5 retry projections while keeping method selection separate from recorded attempts", () => {
    const run = multipleV5Fixture();
    expect(recordedPathNodes(run)).toHaveLength(1);
    expect(selectedAttempt(run, run.ai_proposals![0]!)).toBe(run.steps[1]);
    expect(selectedAttempt(run, run.ai_proposals![1]!)).toBe(run.steps[2]);
    render(<AdaptiveRunPath run={run} catalog={catalog}/>);
    const path = screen.getByRole("region", { name: "Recorded adaptive path" });
    expect(within(path).getByText("Attempt 2 · run position 2")).toBeVisible();
    expect(within(path).getByText("Attempt 3 · run position 3")).toBeVisible();
    const decisions = within(path).getAllByRole("region", { name: "Recorded adaptive decision" });
    expect(decisions).toHaveLength(2);
    const decision = decisions[1]!;
    expect(within(decision).getByText("Chosen alternative: Hash selected files")).toBeVisible();
    expect(within(decision).getByText(/Deterministic provider · software evidence/)).toBeVisible();
    expect(within(decision).queryByText(/Live provider response/)).not.toBeInTheDocument();
    openDetails(decision);
    expect(within(decision).getByText("2 steps · 10 seconds · 1 retry · 1 retry for this step")).toBeVisible();
  });

  it("keeps v5 activity visible but reports an inconsistent retry projection as unknown", () => {
    const run = v5Fixture();
    const record = run.ai_proposals![0]!;
    const state = record.planner_state as Record<string, unknown>;
    const observations = state.observations as Record<string, unknown>;
    const budgets = observations.remaining_budgets as Record<string, unknown>;
    observations.remaining_budgets = { ...budgets, step_retries: 1 };
    expect(recordedPathNodes(run)).toHaveLength(1);
    expect(selectedAttempt(run, record)).toBe(run.steps[1]);
    render(<AdaptiveRunPath run={run} catalog={catalog}/>);
    const decision = screen.getByRole("region", { name: "Recorded adaptive decision" });
    expect(within(decision).getByText("Chosen alternative: Inspect file metadata")).toBeVisible();
    expect(within(decision).getByText(/Runner returned success/)).toBeVisible();
    openDetails(decision);
    expect(within(decision).getByText("The retained v5 retry budget projection is inconsistent; remaining adaptive allowance is unknown.")).toBeVisible();
    expect(within(decision).getByText(/Unknown retries for this step/)).toBeVisible();
  });

  it("routes v5 records through the adaptive decision trail in the full run review", () => {
    const run = multipleV5Fixture();
    render(<RunReview run={run} catalog={catalog}/>);
    const summary = screen.getByText("AI decisions (2)");
    const trail = summary.closest("details")!;
    trail.open = true;
    const decisions = within(trail).getAllByRole("region", { name: "Recorded adaptive decision" });
    expect(decisions).toHaveLength(2);
    expect(within(trail).getByText("Chosen alternative: Hash selected files")).toBeVisible();
    openDetails(decisions[1]!);
    expect(within(trail).getByText("2 steps · 10 seconds · 1 retry · 1 retry for this step")).toBeVisible();
    expect(within(trail).queryByText("Policy not reported")).not.toBeInTheDocument();
  });
});

function openDetails(decision: HTMLElement) {
  const summary = within(decision).getByText("Decision, observations and limits");
  summary.closest("details")!.open = true;
}
