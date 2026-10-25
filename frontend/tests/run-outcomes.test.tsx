import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it } from "vitest";
import { RunReview } from "../src/pages/Runs";
import { demoCatalog, demoRuns, demoScenario } from "../src/lib/demo";
import { runLabel } from "../src/lib/run-presentation";
import { recordedEvidenceLabels, recordedStepLabels, runEventPresentation } from "../src/lib/run-progress-presentation";
import type { RunRecord } from "../src/types";

function run(overrides: Partial<RunRecord>): RunRecord {
  return { ...structuredClone(demoRuns[0]!), is_demo: false, mode: "execute", ...overrides };
}

it("uses the recorded attempt before the saved initial method and retains a catalog fallback", () => {
  const original = demoCatalog.behaviors[0]!, alternate = demoCatalog.behaviors[1]!;
  const saved = run({ scenario: { ...demoScenario, steps: [{ id: "reused_node", behavior_id: original.id, inputs: {}, parameters: {}, alternates: [alternate.id] }] } });
  expect(recordedStepLabels({ step_id: "reused_node", behavior_id: alternate.id, status: "success" }, demoCatalog, saved).name).toBe(alternate.title);
  expect(recordedStepLabels({ step_id: "reused_node", simulation_id: alternate.simulation_id, status: "success" }, demoCatalog, saved).name).toBe(alternate.title);
  expect(recordedStepLabels({ step_id: "reused_node", behavior_id: original.id, action_id: alternate.action_ids[0], status: "success" }, demoCatalog, saved).method).toBe(demoCatalog.actions.find(item => item.id === alternate.action_ids[0])!.title);
  expect(recordedStepLabels({ step_id: "reused_node", status: "success" }, demoCatalog, saved).name).toBe(original.title);
  expect(recordedStepLabels({ step_id: "reused_node", behavior_id: "removed.behavior.v1", status: "success" }, demoCatalog, saved).name).toBe("Reused node");
  expect(recordedStepLabels({ step_id: "reused_node", status: "success" })).toEqual({ name: "Reused node", method: "Method details unavailable" });
  saved.steps = [{ step_id: "reused_node", behavior_id: original.id, action_id: original.action_ids[0], status: "failed", evidence_ids: ["initial-evidence"] },
    { step_id: "reused_node", behavior_id: alternate.id, action_id: alternate.action_ids[0], status: "success", evidence_ids: ["retry-evidence"] }];
  const evidence = { evidence_id: "retry-evidence", step_id: "reused_node", provenance: "executed" };
  expect(recordedEvidenceLabels(evidence, demoCatalog, saved)).toEqual({ name: alternate.title, method: demoCatalog.actions.find(item => item.id === alternate.action_ids[0])!.title });
  expect(recordedEvidenceLabels({ ...evidence, behavior_id: original.id, action_id: original.action_ids[0] }, demoCatalog, saved).name).toBe(original.title);
  expect(recordedEvidenceLabels({ ...evidence, run_id: "different-run" }, demoCatalog, saved)).toEqual({ name: "Reused node", method: undefined });
  expect(recordedEvidenceLabels({ ...evidence, evidence_id: "unlinked" }, demoCatalog, saved)).toEqual({ name: "Reused node", method: undefined });
  saved.steps[0]!.evidence_ids = ["retry-evidence"];
  expect(recordedEvidenceLabels(evidence, demoCatalog, saved)).toEqual({ name: "Reused node", method: undefined });
});

it("reads canonical event data without letting obsolete flat fields claim a different outcome", () => {
  const behavior = demoCatalog.behaviors[0]!;
  const event = { event_type: "step.completed", sequence: 4, step_id: "unrelated", status: "success", data: { step_id: "selected_step", behavior_id: behavior.id, action_id: behavior.action_ids[0], status: "blocked", policy: { allowed: false }, error: { message: "This capability is outside the reviewed scope." } } };
  const before = structuredClone(event);
  const result = runEventPresentation(event, demoCatalog, null, "execute");
  expect(result).toMatchObject({ title: "Step result recorded", stepId: "selected_step", status: "blocked", sequence: 4, type: "step.completed" });
  expect(result.detail).toBe(`${behavior.title} · Stopped by BlueFire policy · This capability is outside the reviewed scope.`);
  expect(event).toEqual(before);
});

it("labels deterministic routing without claiming live model assistance", () => {
  const behavior = demoCatalog.behaviors[0]!;
  const result = runEventPresentation({ event_type: "planner.decision", data: { selected_step_id: "next", selected_behavior_id: behavior.id, proposed_by: "deterministic-planner.v1", reason: "Follow the registered route for this outcome." } }, demoCatalog);
  expect(result.title).toBe("Plan decision");
  expect(result.detail).toBe(`Deterministic routing · Next step: ${behavior.title} · Follow the registered route for this outcome.`);
  expect(result.detail).not.toMatch(/AI|model|Assistant/);
});

it("keeps synthetic events qualified and unknown records readable", () => {
  const behavior = demoCatalog.behaviors[0]!;
  const result = runEventPresentation({ event_type: "step.completed", data: { step_id: "sample_step", simulation_id: behavior.simulation_id, status: "success" } }, demoCatalog, null, "simulate");
  expect(result.detail).toBe(`${behavior.title} · Simulated success`);
  expect(runEventPresentation({ type: "old.event_kind", message: "Retained message" }).title).toBe("Old event kind");
  expect(runEventPresentation({ event_type: "step.completed", data: {} }).detail).toBe("Recorded step · Not reported");
});

it("separates original scenario notes from a partial run's unresolved limitations", () => {
  const sourceNote = "Draft only; run setup and approval are separate.";
  const runtimeNote = "Cancellation left partial observations.";
  render(<RunReview run={run({ status: "cancelled", scenario: { ...demoScenario, limitations: [sourceNote] }, limitations: [sourceNote, runtimeNote] })} catalog={demoCatalog}/>);
  const source = within(screen.getByRole("region", { name: "Scenario assumptions and source notes" }));
  const actual = within(screen.getByRole("region", { name: "Run limitations" }));
  expect(source.getByText(sourceNote)).toBeVisible();
  expect(source.getByText(/Recorded when the saved experiment was authored/)).toBeVisible();
  expect(actual.getByText(runtimeNote)).toBeVisible();
  expect(actual.queryByText(sourceNote)).not.toBeInTheDocument();
});

it("does not infer source provenance from a limitation's wording", () => {
  const note = "Unsaved AI-assisted draft";
  render(<RunReview run={run({ scenario: undefined, limitations: [note] })} catalog={demoCatalog}/>);
  expect(within(screen.getByRole("region", { name: "Recorded limitations" })).getByText(note)).toBeVisible();
  expect(screen.queryByRole("region", { name: "Scenario assumptions and source notes" })).not.toBeInTheDocument();
});

it.each([
  ["cancelled", ["Partial observations", "Source caveat", "Partial observations"]],
  ["interrupted", undefined],
  ["cancelled", []],
] as const)("retains every immutable scenario note independently of %s result copies (%j)", (status, resultNotes) => {
  const sourceNotes = ["Source caveat", "Unobserved behavior remains unverified", "Source caveat"];
  const record = run({ status, scenario: { ...demoScenario, limitations: sourceNotes }, limitations: resultNotes ? [...resultNotes] : undefined });
  const before = structuredClone(record);
  render(<RunReview run={record} catalog={demoCatalog}/>);
  const source = within(screen.getByRole("region", { name: "Scenario assumptions and source notes" }));
  expect(source.getAllByRole("listitem").map((item) => item.textContent)).toEqual(sourceNotes);
  if (resultNotes?.length) {
    const actual = within(screen.getByRole("region", { name: "Run limitations" }));
    expect(actual.getAllByRole("listitem").map((item) => item.textContent)).toEqual(["Partial observations", "Partial observations"]);
  } else {
    expect(screen.queryByText(/No limitations were attached/)).not.toBeInTheDocument();
  }
  expect(record).toEqual(before);
});

it.each([
  [{ authorized_target_scope: { scope_refs: ["canonical.workspace", "canonical.loopback"] }, policy: { authorized_target_scope: { scope_refs: ["policy.workspace"] } }, target_scope: { scope_refs: ["legacy.workspace"] } }, "canonical.workspace, canonical.loopback"],
  [{ authorized_target_scope: null, policy: { authorized_target_scope: { scope_refs: ["policy.workspace"] } }, target_scope: { scope_refs: ["legacy.workspace"] } }, "policy.workspace"],
  [{ policy: { authorized_target_scope: null }, target_scope: { scope_refs: ["legacy.workspace"] } }, "legacy.workspace"],
  [{ authorized_target_scope: null, policy: {}, target_scope: undefined }, "Not recorded"],
  [{ authorized_target_scope: { scope_refs: [] }, target_scope: { scope_refs: ["legacy.workspace"] } }, "None recorded"],
])("shows the retained authorized scope with legacy fallback: %j", async (scope, expected) => {
  const record = { ...run({}), ...scope };
  render(<RunReview run={record} catalog={demoCatalog}/>);
  await userEvent.setup().click(screen.getByText("Run identity, environment and technical record"));
  const targets = screen.getByText("Targets").closest("div")!;
  expect(within(targets).getByText(expected)).toBeVisible();
});

it("keeps unknown objective and missing observation metadata distinct from prevention and zero", async () => {
  render(<RunReview run={run({ objective_reached: undefined, evidence: undefined, status: "interrupted", steps: [] })} catalog={demoCatalog}/>);
  const outcome = within(screen.getByRole("region", { name: "Recorded run outcome" }));
  expect(outcome.getByRole("heading", { name: "Not established" })).toBeVisible();
  expect(outcome.getByText("Not reported")).toBeVisible();
  expect(outcome.getByText("None recorded")).toBeVisible();
  await userEvent.setup().click(outcome.getByText("Result details"));
  expect(outcome.getByText("This does not establish that the path completed.")).toBeVisible();
  expect(outcome.queryByText(/0 observed|prevented|path completed without/i)).not.toBeInTheDocument();
});

it("qualifies synthetic success and exposes an explicit zero observation count", async () => {
  render(<RunReview run={run({ mode: "simulate", objective_reached: true, evidence: { records: [] }, cleanup: true })} catalog={demoCatalog}/>);
  const outcome = within(screen.getByRole("region", { name: "Recorded run outcome" }));
  expect(outcome.getByRole("heading", { name: "Achieved (synthetic)" })).toBeVisible();
  expect(outcome.getByText("0 observed records")).toBeVisible();
  await userEvent.setup().click(outcome.getByText("Result details"));
  expect(outcome.getByText("Simulate does not perform lab effects.")).toBeVisible();
});

it.each([
  [{ status: "blocked", policy: { allowed: false } }, "Stopped by BlueFire policy"],
  [{ status: "blocked" }, "Blocked · inspect cause"],
  [{ status: "failed" }, "Execution error"],
  [{ status: "blocked", error: { code: "collection_output_limit" } }, "Collection size limit reached"],
  [{ status: "failed", error: { code: "collection_output_limit" } }, "Collection size limit reached"],
  [{ status: "blocked", error: { code: "artifact_limit_blocked" } }, "Artifact size limit reached"],
  [{ status: "blocked", error: { code: "atomic_gzip_unavailable" } }, "System gzip unavailable"],
  [{ status: "blocked", policy: { allowed: false }, error: { code: "collection_output_limit" } }, "Stopped by BlueFire policy"],
])("does not infer target prevention from a stopped step %j", (step, label) => {
  render(<RunReview run={run({ objective_reached: false, steps: [{ step_id: "collect", ...step }] })} catalog={demoCatalog}/>);
  const outcome = within(screen.getByRole("region", { name: "Recorded run outcome" }));
  expect(outcome.getByText(label)).toBeVisible();
  expect(outcome.getByRole("heading", { name: "Not achieved" })).toBeVisible();
  expect(outcome.queryByText("Prevented by the target")).not.toBeInTheDocument();
});

it("keeps outstanding cleanup visible and makes retained evidence inspectable", async () => {
  const user = userEvent.setup();
  render(<RunReview run={run({ cleanup: { success: true, outstanding_receipt_count: 2 }, evidence: { records: [{ evidence_id: "one", provenance: "observed", kind: "Independent file observation", summary: "Exact file content verified" }] } })} catalog={demoCatalog}/>);
  expect(screen.getByText("Needs attention · 2 outstanding effects")).toBeVisible();
  const disclosure = screen.getByText("Inspect evidence records (1)");
  disclosure.focus();
  expect(disclosure).toHaveFocus();
  await user.click(disclosure);
  expect(screen.getByText("Exact file content verified")).toBeVisible();
});

it("uses frozen procedure names and a neutral fallback when the name is unavailable", () => {
  expect(runLabel({ scenario_title: "Original experiment", objective: "Long objective", scenario_id: "internal.v1" })).toBe("Original experiment");
  expect(runLabel({ objective: "Legacy objective", scenario_id: "internal.v1" })).toBe("Run");
  expect(runLabel({ scenario_title: "   ", scenario_id: "internal.v1" })).toBe("Run");
});

it("keeps an unexecuted counterfactual row out of the first actual stop", () => {
  render(<RunReview run={run({ objective_reached: false, steps: [{ step_id: "preview", status: "blocked", execution_disposition: "counterfactual" }] })} catalog={demoCatalog}/>);
  expect(within(screen.getByRole("region", { name: "Recorded run outcome" })).getByText("None recorded")).toBeVisible();
  expect(within(screen.getByRole("region", { name: "Recorded step outcomes" })).getByText("Simulated continuation")).toBeVisible();
  expect(screen.queryByText("Blocked · inspect cause")).not.toBeInTheDocument();
});

it("accounts for refusal and unknown evidence without promoting either to observations", () => {
  render(<RunReview run={run({ evidence: { records: [{ provenance: "control_blocked" }, { provenance: "unknown" }, { provenance: "future_source" }] } })} catalog={demoCatalog}/>);
  expect(screen.getByText(/1 policy or refusal · 2 other or unknown/)).toBeVisible();
  expect(within(screen.getByRole("region", { name: "Recorded run outcome" })).getByText("0 observed records")).toBeVisible();
});

it("opens review sections and moves keyboard focus without replacing the saved record", async () => {
  const user = userEvent.setup();
  const record = run({ evidence: { records: [{ evidence_id: "observation-one", provenance: "observed", summary: "Generated records were independently read" }] }, cleanup: { success: true, outstanding_effects: 0 } });
  const before = structuredClone(record);
  render(<RunReview run={record} catalog={demoCatalog}/>);
  const navigation = within(screen.getByRole("navigation", { name: "Run review sections" }));
  await user.click(navigation.getByRole("button", { name: "Evidence" }));
  const evidence = screen.getByText("Inspect evidence records (1)");
  expect(evidence.closest("details")).toHaveAttribute("open");
  expect(evidence).toHaveFocus();
  expect(screen.getByText("Generated records were independently read")).toBeVisible();
  await user.click(navigation.getByRole("button", { name: "Detection work" }));
  expect(screen.getByText("Inspect detection candidates (1)")).toHaveFocus();
  await user.click(within(screen.getByRole("region", { name: "Evidence and detection summary" })).getByRole("button", { name: "Review candidates" }));
  expect(screen.getByText("Inspect detection candidates (1)").closest("details")).toHaveAttribute("open");
  expect(screen.getByText("Inspect detection candidates (1)")).toHaveFocus();
  await user.click(navigation.getByRole("button", { name: "Path & steps" }));
  expect(screen.getByRole("heading", { name: "Path taken" })).toHaveFocus();
  await user.click(navigation.getByRole("button", { name: "Cleanup" }));
  expect(screen.getByRole("heading", { name: "Cleanup record" })).toHaveFocus();
  await user.click(navigation.getByRole("button", { name: "Export" }));
  expect(screen.getByRole("heading", { name: "Keep this run" })).toHaveFocus();
  expect(screen.getByRole("button", { name: "Download report" })).toBeEnabled();
  expect(record).toEqual(before);
});

it("presents actual alternate attempts and keeps simulated continuations distinct in the path", () => {
  const original = demoCatalog.behaviors[0]!, alternate = demoCatalog.behaviors[1]!;
  const record = run({ scenario: { ...demoScenario, steps: [{ id: "selected", behavior_id: original.id, inputs: {}, parameters: {}, alternates: [alternate.id] }] }, steps: [
    { step_id: "selected", behavior_id: alternate.id, status: "success", evidence_ids: ["observed-one"] },
    { step_id: "preview", behavior_id: original.id, status: "success", execution_disposition: "counterfactual" },
  ] });
  render(<RunReview run={record} catalog={demoCatalog}/>);
  const path = within(screen.getByRole("region", { name: "Recorded step outcomes" }));
  const entries = path.getAllByRole("listitem");
  expect(within(entries[0]!).getByText(alternate.title)).toBeVisible();
  expect(within(entries[0]!).getByText("Reported success")).toBeVisible();
  expect(within(entries[0]!).getByText("1 linked record")).toBeVisible();
  expect(within(entries[1]!).getByText("Simulated continuation")).toBeVisible();
  expect(within(entries[1]!).queryByText("Reported success")).not.toBeInTheDocument();
});

it("does not promote cleanup success to rollback or legitimate-use proof", async () => {
  render(<RunReview run={run({ cleanup: { success: true, outstanding_effects: 0 } })} catalog={demoCatalog}/>);
  const cleanup = within(screen.getByRole("region", { name: "Cleanup and retained changes" }));
  expect(cleanup.getByText(/does not establish a defense rollback or legitimate-use outcome/)).toBeVisible();
  await userEvent.setup().click(cleanup.getByText("Recorded cleanup details"));
  expect(cleanup.getByText("Outstanding effects")).toBeVisible();
  expect(cleanup.getByText("0")).toBeVisible();
});

it("opens only the selected step's linked evidence and preserves unavailable references", async () => {
  const user = userEvent.setup();
  const record = run({ steps: [{ step_id: "collect", status: "success", evidence_ids: ["observed", "synthetic", "missing"] }], evidence: { records: [
    { evidence_id: "observed", step_id: "collect", provenance: "observed", summary: "The observer counted generated records." },
    { evidence_id: "synthetic", step_id: "collect", provenance: "synthetic", summary: "The simulator predicted a result." },
    { evidence_id: "unlinked", step_id: "collect", provenance: "executed", summary: "This record is not linked to this attempt." },
  ] } });
  const before = structuredClone(record);
  render(<RunReview run={record} catalog={demoCatalog}/>);
  const path = within(screen.getByRole("region", { name: "Recorded step outcomes" }));
  expect(path.getByRole("group", { name: "Evidence for Collect" })).not.toBeVisible();
  await user.click(path.getByText("Inspect evidence"));
  const preview = within(path.getByRole("group", { name: "Evidence for Collect" }));
  expect(preview.getByText("Observed")).toBeVisible();
  expect(preview.getByText("Synthetic")).toBeVisible();
  expect(preview.getByText("The observer counted generated records.")).toBeVisible();
  expect(preview.getByText("The simulator predicted a result.")).toBeVisible();
  expect(preview.queryByText("This record is not linked to this attempt.")).not.toBeInTheDocument();
  expect(preview.getByText(/1 linked record is unavailable/)).toBeVisible();
  await user.click(path.getByText("Step details"));
  expect(path.getByText("observed, synthetic, missing")).toBeVisible();
  await user.click(path.getByText("Inspect evidence"));
  expect(path.getByRole("group", { name: "Evidence for Collect" })).not.toBeVisible();
  expect(record).toEqual(before);
});
