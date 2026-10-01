import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { AdaptiveRunPath } from "../src/components/AdaptiveRunPath";
import { decisionObservations, decisionProvenance, recordedPathNodes, selectedAttempt } from "../src/lib/adaptive-run";
import { demoCatalog } from "../src/lib/demo";
import type { AIProposal, CatalogResponse, RunRecord } from "../src/types";

// Authored component fixtures exercise presentation; they are not observed runs.
const primary = "sandbox.discovery.list.v1", alternate = "sandbox.discovery.metadata.v1";
const evidenceId = `evidence-${"a".repeat(20)}`, recordHash = `sha256:${"b".repeat(64)}`;
function projection() {
  return { schema_version: "bluefire.runtime-observations.v1", omitted_attempt_count: 0,
    attempts: [{ attempt_index: 0, step_id: "discover", behavior_id: primary, action_id: primary, outcome: "failed",
      failure: { classification: "execution_failure", telemetry_gap: false }, missing_evidence_count: 0, omitted_evidence_count: 0,
      evidence: [{ evidence_id: evidenceId, record_hash: recordHash, provenance: "observed", facts: {
        artifact_type: "collector_observation", observation_kind: "filesystem", size_bytes: 64,
        permission_status: "available", effective_access: "not_evaluated", permission_mode_octal: "0660",
        group_write_bit: true, other_write_bit: false, non_owner_write_bit: true,
      } as Record<string, unknown> }],
    }], remaining_budgets: { steps: 3, seconds: 20, retries: 1 }, unknowns: ["Target prevention is not established by a product refusal."] };
}
const catalog: CatalogResponse = { ...demoCatalog, behaviors: [
  ...demoCatalog.behaviors, { ...demoCatalog.behaviors[0]!, id: primary, title: "Discover records" },
], actions: [
  ...demoCatalog.actions, { ...demoCatalog.actions[0]!, id: primary, title: "List owned files" },
  { ...demoCatalog.actions[0]!, id: alternate, title: "Inspect file metadata" },
] };
function fixture(): RunRecord {
  return { run_id: "authored-run", mode: "execute", status: "completed", objective: "Verify the original collection objective", objective_reached: false,
    steps: [
      { step_id: "discover", behavior_id: primary, action_id: primary, status: "failed", runner_status: "failed", request_hash: "original-request", execution_disposition: "execute", planner_decision_id: "decision-original", evidence_ids: [evidenceId] },
      { step_id: "discover", behavior_id: alternate, action_id: alternate, status: "success", runner_status: "success", request_hash: "retry-request", execution_disposition: "execute", planner_decision_id: "decision-retry", evidence_ids: [] },
    ], ai_proposals: [{ schema_version: "bluefire.ai-proposal-record.v4", run_id: "authored-run", current_step_id: "discover", deterministic_decision_id: "decision-original", outcome: "failed",
      application_status: "applied_reviewed_method", application_reason: "Reviewed method selected.",
      proposal: { schema_version: "bluefire.ai-proposal.v2", proposal_id: "authored-choice", proposal_type: "select_registered_action", selected_step_id: "discover", selected_behavior_id: alternate, selected_action_id: alternate, rationale: "The file list failed; metadata can inspect the same input.", parameter_changes: [], alternatives: [], confidence: .8, requires_operator_review: false } as AIProposal,
      applied_step: { step_id: "discover", behavior_id: alternate, action_id: alternate },
      provider: { effective_provider_id: "deterministic-offline.v1", model: "software-test-model", used_fallback: false }, provider_attempt: { provider_id: "deterministic-offline.v1", kind: "deterministic", model: "software-test-model" }, provider_called: true, decision_source: "deterministic_provider",
      planner_state: { observations: projection() },
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
    Object.assign(record, { provider: null, proposal: null, decision_source: "none" });
    expect(decisionProvenance(record).label).toBe("Provider request did not produce a permitted choice");
  });
});

function observationsFixture() {
  const run = fixture(), view = projection(), record = run.ai_proposals![0]!;
  record.planner_state = { observations: view };
  return { run, record, view, attempt: view.attempts[0]!, row: view.attempts[0]!.evidence[0]! };
}
async function openObservations(run: RunRecord) {
  render(<AdaptiveRunPath run={run} catalog={catalog}/>);
  const panel = screen.getByLabelText("Recorded observations at this decision");
  await userEvent.setup().click(within(panel).getByText("Recorded observations at this decision"));
  return within(panel);
}

describe("retained observations at the exact adaptive decision", () => {
  it("shows permission facts, reported output and separate omissions without claiming effective access or provider receipt", async () => {
    const { run, attempt } = observationsFixture();
    const reported = `evidence-${"c".repeat(20)}`;
    run.steps[0]!.evidence_ids!.push(reported, `evidence-${"d".repeat(20)}`, `evidence-${"e".repeat(20)}`);
    attempt.evidence.push({ evidence_id: reported, record_hash: recordHash, provenance: "executed", facts: { reported_size_bytes: 32 } });
    attempt.missing_evidence_count = 1;
    attempt.omitted_evidence_count = 1;
    attempt.failure.telemetry_gap = true;
    const panel = await openObservations(run);
    expect(panel.getByText("Record 1 · Independent observation")).toBeVisible();
    expect(panel.getByText("0660")).toBeVisible();
    expect(panel.getByText("Group write bit")).toBeVisible();
    expect(panel.getByText("Record 2 · Reported execution")).toBeVisible();
    expect(panel.getByText("Reported size in bytes")).toBeVisible();
    expect(panel.getByText("32")).toBeVisible();
    expect(panel.getByText("Missing evidence records").nextElementSibling).toHaveTextContent("1");
    expect(panel.getByText("Evidence records omitted from this summary").nextElementSibling).toHaveTextContent("1");
    expect(panel.getByText("Telemetry gap").nextElementSibling).toHaveTextContent("Reported");
    expect(panel.getByText(/Not evaluated; mode bits/)).toBeVisible();
    expect(panel.getByText(/do not establish what a provider received or whether the objective was achieved/)).toBeVisible();
    expect(run.objective_reached).toBe(false);
  });

  it("matches the global attempt index when a step has repeated methods", () => {
    const { run, record, view, attempt } = observationsFixture();
    run.steps[1] = { ...run.steps[0]!, status: "success", planner_decision_id: "decision-retry" };
    Object.assign(record, { deterministic_decision_id: "decision-retry", outcome: "success" });
    view.attempts.push({ ...attempt, attempt_index: 1, outcome: "success", evidence: [{ ...attempt.evidence[0]!, facts: { file_count: 7 } }] });
    const result = decisionObservations(run, record);
    expect(result.available).toBe(true);
    expect(result.evidence[0]!.facts).toEqual([{ label: "Files", value: "7" }]);
  });

  it.each([
    ["synthetic", "Simulated evidence"], ["control_blocked", "BlueFire control record"],
    ["counterfactual", "Counterfactual evidence"], ["unknown", "Observation unavailable"],
  ])("keeps %s counts distinct from independent observations", async (provenance, label) => {
    const { run, row } = observationsFixture();
    row.provenance = provenance;
    row.facts = { file_count: 2 };
    const panel = await openObservations(run);
    expect(panel.getByText(`Record 1 · ${label}`)).toBeVisible();
    expect(panel.queryByText(/Independent observation/)).not.toBeInTheDocument();
  });

  it.each(["run", "decision", "duplicate-origin", "index", "duplicate-index", "step", "behavior", "action", "outcome", "record-outcome"])("refuses a mismatched %s without borrowing another attempt", async field => {
    const { run, record, view, attempt } = observationsFixture();
    if (field === "run") record.run_id = "other-run";
    if (field === "decision") record.deterministic_decision_id = "other-decision";
    if (field === "duplicate-origin") run.steps.push({ ...run.steps[0]! });
    if (field === "index") attempt.attempt_index = 1;
    if (field === "duplicate-index") view.attempts.push({ ...attempt });
    if (field === "step") attempt.step_id = "other-step";
    if (field === "behavior") attempt.behavior_id = alternate;
    if (field === "action") attempt.action_id = alternate;
    if (field === "outcome") attempt.outcome = "success";
    if (field === "record-outcome") record.outcome = "success";
    const panel = await openObservations(run);
    expect(panel.getByText(/does not contain a matching, readable observation summary/)).toBeVisible();
    expect(panel.queryByText("0660")).not.toBeInTheDocument();
  });

  it.each(["legacy", "missing-count", "negative-count", "boolean-count", "infinite-count", "unsafe-count", "inconsistent-count", "too-many-attempts", "too-many-records", "duplicate-record", "reference", "hash", "provenance"])("keeps %s unavailable instead of inventing complete evidence", field => {
    const { run, record, view, attempt, row } = observationsFixture();
    if (field === "legacy") Reflect.deleteProperty(view, "schema_version");
    if (field === "missing-count") Reflect.deleteProperty(attempt, "missing_evidence_count");
    if (field === "negative-count") attempt.omitted_evidence_count = -1;
    if (field === "boolean-count") Object.assign(attempt, { omitted_evidence_count: true });
    if (field === "infinite-count") attempt.omitted_evidence_count = Infinity;
    if (field === "unsafe-count") attempt.omitted_evidence_count = 2 ** 53;
    if (field === "inconsistent-count") attempt.missing_evidence_count = 1;
    if (field === "too-many-attempts") view.attempts = Array.from({ length: 17 }, () => attempt);
    if (field === "too-many-records") attempt.evidence = Array.from({ length: 33 }, () => row);
    if (field === "duplicate-record") { attempt.evidence.push({ ...row }); run.steps[0]!.evidence_ids!.push(`evidence-${"c".repeat(20)}`); }
    if (field === "reference") row.evidence_id = "private-path-not-an-identity";
    if (field === "hash") row.record_hash = "private-value-not-a-hash";
    if (field === "provenance") row.provenance = "private-provenance";
    expect(decisionObservations(run, record)).toMatchObject({ available: false, evidence: [] });
  });

  it("keeps a valid empty summary and absent telemetry flag distinct from verified absence", async () => {
    const { run, attempt } = observationsFixture();
    run.steps[0]!.evidence_ids = [];
    attempt.evidence = [];
    Reflect.deleteProperty(attempt.failure, "telemetry_gap");
    const panel = await openObservations(run);
    expect(panel.getByText(/does not establish that nothing happened/)).toBeVisible();
    expect(panel.getByText("Unknown; not recorded")).toBeVisible();
  });

  it.each(["extra", "enum", "negative", "boolean", "unsafe", "permission-bits", "permission-shape", "effective-access", "executed-permissions"])("does not render unsupported %s facts or raw values", async field => {
    const { run, row } = observationsFixture();
    const secret = "synthetic-private-value:/private/operator/file";
    if (field === "extra") row.facts.raw_log = secret;
    if (field === "enum") row.facts.observation_kind = secret;
    if (field === "negative") row.facts.size_bytes = -1;
    if (field === "boolean") row.facts.size_bytes = true;
    if (field === "unsafe") row.facts.size_bytes = 2 ** 53;
    if (field === "permission-bits") row.facts.other_write_bit = true;
    if (field === "permission-shape") delete row.facts.non_owner_write_bit;
    if (field === "effective-access") row.facts.effective_access = "verified";
    if (field === "executed-permissions") row.provenance = "executed";
    const panel = await openObservations(run);
    expect(panel.getByText(/facts are unreadable or outside the supported format/)).toBeVisible();
    expect(panel.queryByText("0660")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Recorded observations at this decision")).not.toHaveTextContent(secret);
  });

  it.each(["unavailable_windows", "unsupported_platform", "invalid_metadata"])("keeps %s permission metadata unavailable without invented bits", async status => {
    const { run, row } = observationsFixture();
    row.facts = { artifact_type: "file_observation", permission_status: status, effective_access: "not_evaluated" };
    const panel = await openObservations(run);
    expect(panel.getByText("File permissions")).toBeVisible();
    expect(panel.queryByText("Group write bit")).not.toBeInTheDocument();
    expect(panel.getByText(/Not evaluated; mode bits/)).toBeVisible();
  });
});
