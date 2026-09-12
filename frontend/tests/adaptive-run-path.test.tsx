import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AdaptiveRunPath } from "../src/components/AdaptiveRunPath";
import { decisionProvenance, recordedPathNodes, selectedAttempt } from "../src/lib/adaptive-run";
import { demoCatalog } from "../src/lib/demo";
import type { AIProposal, CatalogResponse, RunRecord } from "../src/types";

// Authored component fixtures exercise presentation; they are not observed runs.
const primary = "sandbox.discovery.list.v1", alternate = "sandbox.discovery.metadata.v1";
const catalog: CatalogResponse = { ...demoCatalog, behaviors: [
  ...demoCatalog.behaviors, { ...demoCatalog.behaviors[0]!, id: primary, title: "Discover records" },
], actions: [
  ...demoCatalog.actions, { ...demoCatalog.actions[0]!, id: primary, title: "List owned files" },
  { ...demoCatalog.actions[0]!, id: alternate, title: "Inspect file metadata" },
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
  });
});
