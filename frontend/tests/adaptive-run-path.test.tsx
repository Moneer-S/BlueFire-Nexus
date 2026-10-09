import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { AdaptiveRunPath } from "../src/components/AdaptiveRunPath";
import { decisionObservations, decisionProvenance, recordedPathNodes, selectedAttempt } from "../src/lib/adaptive-run";
import { RunReview } from "../src/pages/Runs";
import { demoCatalog } from "../src/lib/demo";
import type { AIProposal, CatalogResponse, RunRecord } from "../src/types";

// Authored component fixtures exercise presentation; they are not observed runs.
const primary = "sandbox.discovery.list.v1", alternate = "sandbox.discovery.metadata.v1", third = "sandbox.discovery.hash.v1";
const digest = `sha256:${"a".repeat(64)}`;
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
  { ...demoCatalog.behaviors[0]!, id: third, title: "Hash selected records" },
], actions: [
  ...demoCatalog.actions, { ...demoCatalog.actions[0]!, id: primary, title: "List owned files" },
  { ...demoCatalog.actions[0]!, id: alternate, title: "Inspect file metadata" },
  { ...demoCatalog.actions[0]!, id: third, title: "Hash selected files" },
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
    attempts: [...projection().attempts, { attempt_index: 1, step_id: "discover", behavior_id: alternate, action_id: alternate,
      outcome: "failed", failure: { classification: "execution_failure", telemetry_gap: false },
      missing_evidence_count: 0, omitted_evidence_count: 0, evidence: [] }],
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

  it.each([
    { budget: "coherent", remainingStepRetries: 1 },
    { budget: "inconsistent", remainingStepRetries: 0 },
  ])("preserves observed permissions and coverage with a $budget v5 budget without turning a reservation into an attempt", ({ budget, remainingStepRetries }) => {
    const run = v5Fixture();
    run.steps.pop(); // The alternate was reserved, but no runner result was recorded.
    const record = run.ai_proposals![0]!;
    const policy = record.proposal_policy as Record<string, unknown>;
    Object.assign(policy, { adaptive_retries_used: 1, step_retries_used: 1, attempted_methods: [
      { step_id: "discover", behavior_id: primary, action_id: primary },
      { step_id: "discover", behavior_id: alternate, action_id: alternate },
    ] });
    const state = record.planner_state as Record<string, unknown>;
    const observations = state.observations as Record<string, unknown>;
    observations.remaining_budgets = { steps: 3, seconds: 20, retries: 1, step_retries: remainingStepRetries };
    const facts = { artifact_type: "file_observation", permission_status: "available", effective_access: "not_evaluated",
      permission_mode_octal: "0660", group_write_bit: true, other_write_bit: false, non_owner_write_bit: true };
    observations.attempts = [{ attempt_index: 0, step_id: "discover", behavior_id: primary, action_id: primary, outcome: "failed",
      failure: { classification: "execution_timeout", telemetry_gap: true },
      missing_evidence_count: 0, omitted_evidence_count: 0,
      evidence: [{ evidence_id: evidenceId, record_hash: recordHash, provenance: "observed", facts }] }];
    run.evidence = { records: [{ evidence_id: evidenceId, provenance: "observed", producer: "authored-fixture", content: facts }] };
    const before = JSON.stringify(run);

    render(<AdaptiveRunPath run={run} catalog={catalog}/>);
    const path = screen.getByRole("region", { name: "Recorded adaptive path" });
    expect(within(path).getByText("Attempt 1 · run position 1")).toBeVisible();
    expect(within(path).queryByText("Attempt 2 · run position 2")).not.toBeInTheDocument();
    expect(within(path).getByText("1 independently observed records")).toBeVisible();
    const decision = within(path).getByRole("region", { name: "Recorded adaptive decision" });
    expect(within(decision).getByText("Selection applied; no matching attempt is recorded.")).toBeVisible();
    openDetails(decision);
    expect(within(decision).getByText("Execution timeout", { selector: "dd" })).toBeVisible();
    expect(within(decision).getByText("Some observations are unavailable.")).toBeVisible();
    const evidenceRow = within(decision).getByText("Current attempt evidence", { selector: "dt" }).parentElement!;
    expect(within(evidenceRow).getByText(evidenceId, { selector: "dd" })).toBeVisible();
    const permissions = within(decision).getByRole("region", { name: "Observed file permissions" });
    expect(within(permissions).getByText("0660", { selector: "dd" })).toBeVisible();
    expect(within(permissions).getByText("From run position 1")).toBeVisible();
    expect(within(permissions).getByText("Effective access not evaluated.")).toBeVisible();
    expect(within(permissions).queryByText("Observation 2", { selector: "strong" })).not.toBeInTheDocument();
    const warning = "The retained v5 retry budget projection is inconsistent; remaining adaptive allowance is unknown.";
    if (budget === "coherent") {
      expect(within(decision).getByText("3 steps · 20 seconds · 1 retry · 1 retry for this step")).toBeVisible();
      expect(within(decision).queryByText(warning)).not.toBeInTheDocument();
    } else {
      expect(within(decision).getByText(warning)).toBeVisible();
      expect(within(decision).getByText(/Unknown retries for this step/)).toBeVisible();
    }
    expect(JSON.stringify(run)).toBe(before);
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

function observationsFixture(version: "v4" | "v5" = "v4") {
  const run = version === "v5" ? v5Fixture() : fixture(), record = run.ai_proposals![0]!;
  const view = (record.planner_state as { observations: ReturnType<typeof projection> }).observations;
  return { run, record, view, attempt: view.attempts[0]!, row: view.attempts[0]!.evidence[0]! };
}
async function openObservations(run: RunRecord) {
  render(<AdaptiveRunPath run={run} catalog={catalog}/>);
  const panel = screen.getByLabelText("Recorded observations at this decision");
  await userEvent.setup().click(within(panel).getByText("Recorded observations at this decision"));
  return within(panel);
}

describe.each(["v4", "v5"] as const)("retained %s observations at the exact adaptive decision", version => {
  it("shows permission facts, reported output and separate omissions without claiming effective access or provider receipt", async () => {
    const { run, attempt } = observationsFixture(version);
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
    const { run, record, view, attempt } = observationsFixture(version);
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
    const { run, row } = observationsFixture(version);
    row.provenance = provenance;
    row.facts = { file_count: 2 };
    const panel = await openObservations(run);
    expect(panel.getByText(`Record 1 · ${label}`)).toBeVisible();
    expect(panel.queryByText(/Independent observation/)).not.toBeInTheDocument();
  });

  it.each(["run", "decision", "duplicate-origin", "index", "duplicate-index", "step", "behavior", "action", "outcome", "record-outcome"])("refuses a mismatched %s without borrowing another attempt", async field => {
    const { run, record, view, attempt } = observationsFixture(version);
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
    const { run, record, view, attempt, row } = observationsFixture(version);
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
    const { run, attempt } = observationsFixture(version);
    run.steps[0]!.evidence_ids = [];
    attempt.evidence = [];
    Reflect.deleteProperty(attempt.failure, "telemetry_gap");
    const panel = await openObservations(run);
    expect(panel.getByText(/does not establish that nothing happened/)).toBeVisible();
    expect(panel.getByText("Unknown; not recorded")).toBeVisible();
  });

  it.each(["extra", "enum", "negative", "boolean", "unsafe", "permission-bits", "permission-shape", "effective-access", "executed-permissions"])("does not render unsupported %s facts or raw values", async field => {
    const { run, row } = observationsFixture(version);
    const unsupportedValue = "synthetic-private-value:/private/operator/file";
    if (field === "extra") row.facts.raw_log = unsupportedValue;
    if (field === "enum") row.facts.observation_kind = unsupportedValue;
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
    expect(screen.getByLabelText("Recorded observations at this decision")).not.toHaveTextContent(unsupportedValue);
  });

  it.each(["unavailable_windows", "unsupported_platform", "invalid_metadata"])("keeps %s permission metadata unavailable without invented bits", async status => {
    const { run, row } = observationsFixture(version);
    row.facts = { artifact_type: "file_observation", permission_status: status, effective_access: "not_evaluated" };
    const panel = await openObservations(run);
    expect(panel.getByText("File permissions")).toBeVisible();
    expect(panel.queryByText("Group write bit")).not.toBeInTheDocument();
    expect(panel.getByText(/Not evaluated; mode bits/)).toBeVisible();
  });
});
describe("merged observation and retry-budget boundaries", () => {
  it.each(["wrong-run", "duplicate-origin", "empty-id", "unmatched-id"])("keeps a v5 %s decision wholly unknown instead of borrowing its coherent budget", field => {
    const run = v5Fixture(), record = run.ai_proposals![0]!;
    if (field === "wrong-run") record.run_id = "other-run";
    if (field === "duplicate-origin") run.steps.push({ ...run.steps[0]! });
    if (field === "empty-id") record.deterministic_decision_id = "";
    if (field === "unmatched-id") record.deterministic_decision_id = "other-decision";
    expect(decisionObservations(run, record)).toEqual({ available: false, budgets: {}, attempts: [], evidence: [], unknowns: [] });
    render(<AdaptiveRunPath run={run} catalog={catalog}/>);
    const decision = screen.getByRole("region", { name: "Recorded adaptive decision" });
    openDetails(decision);
    expect(within(decision).getByText("Unknown steps · Unknown seconds · Unknown retries · Unknown retries for this step")).toBeVisible();
    expect(within(decision).queryByRole("region", { name: "Observed file permissions" })).not.toBeInTheDocument();
    expect(within(decision).queryByText(/retry budget projection is inconsistent/)).not.toBeInTheDocument();
  });

  it.each(["missing", "stale", "wrong-schema"])("does not borrow a %s v5 attempt summary", field => {
    const run = multipleV5Fixture(), record = run.ai_proposals![1]!;
    const observations = (record.planner_state as { observations: ReturnType<typeof projection> }).observations;
    if (field === "missing") observations.attempts = [];
    if (field === "stale") observations.attempts.pop();
    if (field === "wrong-schema") observations.schema_version = "bluefire.runtime-observations.v1";
    const result = decisionObservations(run, record);
    expect(result).toMatchObject({ available: false, evidence: [], attempts: [] });
    expect(result.budgets).toEqual(field === "wrong-schema" ? {} : { steps: 2, seconds: 10, retries: 1, stepRetries: 1 });
    if (field !== "wrong-schema") {
      render(<AdaptiveRunPath run={run} catalog={catalog}/>);
      const decision = screen.getAllByRole("region", { name: "Recorded adaptive decision" })[1]!;
      openDetails(decision);
      expect(within(decision).getByText("2 steps · 10 seconds · 1 retry · 1 retry for this step")).toBeVisible();
      expect(within(decision).queryByRole("region", { name: "Observed file permissions" })).not.toBeInTheDocument();
    }
  });

  it.each(["v4", "v5"] as const)("requires the exact observation schema for %s", version => {
    const { run, record, view } = observationsFixture(version);
    view.schema_version = version === "v4" ? "bluefire.runtime-observations.v2" : "bluefire.runtime-observations.v1";
    expect(decisionObservations(run, record)).toMatchObject({ available: false, evidence: [], attempts: [], budgets: {} });
  });

  it("selects only the current v5 attempt's facts while preserving independently bound earlier permission observations", () => {
    const run = multipleV5Fixture(), record = run.ai_proposals![1]!;
    const observations = (record.planner_state as { observations: ReturnType<typeof projection> }).observations;
    const id = `evidence-${"c".repeat(20)}`;
    run.steps[1]!.evidence_ids = [id];
    observations.attempts[1]!.evidence = [{ evidence_id: id, record_hash: recordHash, provenance: "executed", facts: { reported_size_bytes: 7 } }];
    const result = decisionObservations(run, record);
    expect(result.available).toBe(true);
    expect(result.evidence).toEqual([{ evidence_id: id, record_hash: recordHash, label: "Reported execution", facts: [{ label: "Reported size in bytes", value: "7" }] }]);
    expect(result.attempts).toHaveLength(2);
    expect(result.budgets).toEqual({ steps: 2, seconds: 10, retries: 1, stepRetries: 1 });
  });

  it.each(["behavior", "action", "outcome", "reference", "count", "duplicate-index"])("rejects an earlier attempt with mismatched %s before the permission view", field => {
    const run = multipleV5Fixture(), record = run.ai_proposals![1]!;
    const observations = (record.planner_state as { observations: ReturnType<typeof projection> }).observations;
    const earlier = observations.attempts[0]!;
    if (field === "behavior") earlier.behavior_id = alternate;
    if (field === "action") earlier.action_id = alternate;
    if (field === "outcome") earlier.outcome = "success";
    if (field === "reference") earlier.evidence[0]!.evidence_id = `evidence-${"f".repeat(20)}`;
    if (field === "count") earlier.missing_evidence_count = 1;
    if (field === "duplicate-index") observations.attempts.push({ ...earlier });
    const result = decisionObservations(run, record);
    expect(result).toMatchObject({ available: false, evidence: [], attempts: [], budgets: { retries: 1, stepRetries: 1 } });
    render(<AdaptiveRunPath run={run} catalog={catalog}/>);
    const decision = screen.getAllByRole("region", { name: "Recorded adaptive decision" })[1]!;
    openDetails(decision);
    expect(within(decision).queryByRole("region", { name: "Observed file permissions" })).not.toBeInTheDocument();
  });

  it("does not expose unsupported earlier facts through the separate permission panel", () => {
    const run = multipleV5Fixture(), record = run.ai_proposals![1]!;
    const observations = (record.planner_state as { observations: ReturnType<typeof projection> }).observations;
    observations.attempts[0]!.evidence[0]!.facts.extra = "unsupported authored value";
    const result = decisionObservations(run, record);
    expect(result.available).toBe(true);
    expect(result.attempts[0]!.evidence).toEqual([]);
  });
});

function openDetails(decision: HTMLElement) {
  const summary = within(decision).getByText("Decision, observations and limits");
  summary.closest("details")!.open = true;
}
