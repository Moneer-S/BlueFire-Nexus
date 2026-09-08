import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it } from "vitest";
import { RunReview } from "../src/pages/Runs";
import { demoCatalog, demoRuns, demoScenario } from "../src/lib/demo";
import { runLabel } from "../src/lib/run-presentation";
import type { RunRecord } from "../src/types";

function run(overrides: Partial<RunRecord>): RunRecord {
  return { ...structuredClone(demoRuns[0]!), is_demo: false, mode: "execute", ...overrides };
}

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

it("keeps unknown objective and missing observation metadata distinct from prevention and zero", () => {
  render(<RunReview run={run({ objective_reached: undefined, evidence: undefined, status: "interrupted", steps: [] })} catalog={demoCatalog}/>);
  const outcome = within(screen.getByRole("region", { name: "Recorded run outcome" }));
  expect(outcome.getByRole("heading", { name: "Not established" })).toBeVisible();
  expect(outcome.getByText("Not reported")).toBeVisible();
  expect(outcome.getByText("None recorded")).toBeVisible();
  expect(outcome.getByText("This does not establish that the path completed.")).toBeVisible();
  expect(outcome.queryByText(/0 observed|prevented|path completed without/i)).not.toBeInTheDocument();
});

it("qualifies synthetic success and exposes an explicit zero observation count", () => {
  render(<RunReview run={run({ mode: "simulate", objective_reached: true, evidence: { records: [] }, cleanup: true })} catalog={demoCatalog}/>);
  const outcome = within(screen.getByRole("region", { name: "Recorded run outcome" }));
  expect(outcome.getByRole("heading", { name: "Achieved (synthetic)" })).toBeVisible();
  expect(outcome.getByText("0 observed records")).toBeVisible();
  expect(outcome.getByText("Simulate does not perform lab effects.")).toBeVisible();
});

it.each([
  [{ status: "blocked", policy: { allowed: false } }, "Stopped by BlueFire policy"],
  [{ status: "blocked" }, "Blocked · inspect cause"],
  [{ status: "failed" }, "Execution error"],
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
