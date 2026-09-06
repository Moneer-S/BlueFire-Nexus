import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it } from "vitest";
import { RunReview } from "../src/pages/Runs";
import { demoCatalog, demoRuns } from "../src/lib/demo";
import { runLabel } from "../src/lib/run-presentation";
import type { RunRecord } from "../src/types";

function run(overrides: Partial<RunRecord>): RunRecord {
  return { ...structuredClone(demoRuns[0]!), is_demo: false, mode: "execute", ...overrides };
}

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

it("uses saved names and leaves objective text available as a legacy fallback", () => {
  expect(runLabel({ scenario_title: "Original experiment", objective: "Long objective", scenario_id: "internal.v1" })).toBe("Original experiment");
  expect(runLabel({ objective: "Legacy objective", scenario_id: "internal.v1" })).toBe("Legacy objective");
  expect(runLabel({ scenario_title: "   ", scenario_id: "internal.v1" })).toBe("internal.v1");
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
