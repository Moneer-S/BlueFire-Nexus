import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it } from "vitest";
import { ComparisonResult } from "../src/pages/Compare";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import type { CatalogResponse, ComparisonResponse, RunRecord } from "../src/types";

type Summary = ComparisonResponse["summaries"][number] & { execution_path?: unknown };
const catalog: CatalogResponse = { ...structuredClone(demoCatalog), behaviors: [
  { ...demoCatalog.behaviors[0]!, id: "collect", title: "Collect selected records with complete JSONL field names" },
  { ...demoCatalog.behaviors[0]!, id: "archive", title: "Archive selected records with the original TAR metadata" },
], actions: [
  { ...demoCatalog.actions[0]!, id: "native.collect", title: "Native JSONL collection" },
  { ...demoCatalog.actions[0]!, id: "native.archive", title: "Native TAR archive" },
] };
const names = { baseline: "Original record collection", candidate: "Reviewed record collection" };

function fixture(mode: "execute" | "simulate" = "execute"): ComparisonResponse {
  const summaries: Summary[] = ["baseline", "candidate"].map(run_id => ({
    run_id, mode, path: ["step-collect", "step-archive"], outcomes: { "step-collect": "success", "step-archive": "blocked" },
    execution_path: [
      { step_id: "step-collect", behavior_id: "collect", action_id: mode === "execute" ? "native.collect" : null },
      { step_id: "step-archive", behavior_id: "archive", action_id: mode === "execute" ? "native.archive" : null },
    ], objective_reached: false, cleanup_success: true,
  }));
  return { comparison_id: "shared-comparison", baseline_run_id: "baseline", run_ids: summaries.map(run => run.run_id), summaries, deltas: [] };
}
function attempts(comparison: ComparisonResponse, index = 1) {
  return (comparison.summaries[index] as Summary).execution_path as Array<Record<string, unknown>>;
}
function sources(comparison: ComparisonResponse): RunRecord[] {
  return comparison.summaries.map((summary, index) => ({
    run_id: summary.run_id, mode: summary.mode as "execute" | "simulate", status: "completed", scenario: structuredClone(demoScenario),
    steps: attempts(comparison, index).map((step, position) => ({
      step_id: step.step_id as string, behavior_id: step.behavior_id as string, action_id: step.action_id as string | null,
      simulation_id: summary.mode === "simulate" ? `simulation.${position}` : undefined, status: summary.outcomes[step.step_id as string]!,
    })),
  }));
}
function result(comparison: ComparisonResponse, runs: RunRecord[] = []) {
  return <MemoryRouter><ComparisonResult comparison={comparison} catalog={catalog} names={names} runs={runs} /></MemoryRouter>;
}
function paths() { return within(screen.getByRole("region", { name: "Recorded run paths" })); }
function expectSeparate() {
  expect(paths().getAllByRole("article")).toHaveLength(2);
  expect(paths().queryByRole("article", { name: "Same recorded path" })).not.toBeInTheDocument();
  expect(paths().queryByRole("button", { name: "Compare paths side by side" })).not.toBeInTheDocument();
}

it("shows one complete recorded path with named run links and restores original lanes and details by keyboard", async () => {
  const comparison = fixture();
  // Objective/observation equality is not necessary for recorded path equality.
  comparison.summaries[1]!.objective_reached = true;
  const before = structuredClone(comparison);
  const view = render(result(comparison));
  const shared = within(paths().getByRole("article", { name: "Same recorded path" }));
  expect(paths().getAllByRole("article")).toHaveLength(1);
  expect(shared.getAllByRole("listitem")).toHaveLength(2);
  expect(shared.getByText(catalog.behaviors[0]!.title)).toBeVisible();
  expect(shared.getByText(catalog.behaviors[1]!.title)).toBeVisible();
  expect(shared.getByText("Native JSONL collection")).toBeVisible();
  expect(shared.getByText("Native TAR archive")).toBeVisible();
  expect(shared.getByText("Success")).toBeVisible();
  expect(shared.getByText("Blocked")).toBeVisible();
  expect(shared.getByRole("link", { name: "Review baseline shared path run" })).toHaveTextContent(names.baseline);
  expect(shared.getByRole("link", { name: "Review compared run 1 shared path run" })).toHaveAttribute("href", "/runs/candidate");
  const toggle = paths().getByRole("button", { name: "Compare paths side by side", pressed: false });
  toggle.focus();
  await userEvent.setup().keyboard(" ");
  expect(toggle).toHaveAttribute("aria-pressed", "true");
  expect(paths().getByRole("button", { name: "Show shared path", pressed: true })).toBe(toggle);
  const lanes = paths().getAllByRole("article");
  expect(lanes).toHaveLength(2);
  expect(paths().getByRole("link", { name: "Review baseline execution lane" })).toHaveAttribute("href", "/runs/baseline");
  await userEvent.setup().click(within(lanes[1]!).getByText("Run context and technical details", { selector: "summary" }));
  expect(within(lanes[1]!).getByText("native.collect → native.archive", { selector: "code" })).toBeVisible();
  view.rerender(result(comparison));
  expect(paths().getAllByRole("article")).toHaveLength(2);
  await userEvent.setup().click(toggle);
  expect(paths().getByRole("article", { name: "Same recorded path" })).toBeVisible();
  expect(paths().getByRole("button", { name: "Compare paths side by side", pressed: false })).toBe(toggle);
  expect(comparison).toEqual(before);
});

it("does not carry a side-by-side choice into a different comparison", async () => {
  const comparison = fixture();
  const view = render(result(comparison));
  await userEvent.setup().click(paths().getByRole("button", { name: "Compare paths side by side" }));
  view.rerender(result({ ...comparison, comparison_id: "another-comparison" }));
  expect(paths().getByRole("article", { name: "Same recorded path" })).toBeVisible();
});

it("shows an identical long run name once above concise shared-path role links", () => {
  const comparison = fixture();
  const sharedName = "A long saved objective shared by both recorded experiment runs";
  render(<MemoryRouter><ComparisonResult comparison={comparison} catalog={catalog} names={{ baseline: sharedName, candidate: sharedName }} /></MemoryRouter>);
  expect(screen.getAllByText(sharedName)).toHaveLength(1);
  expect(screen.getByRole("heading", { name: sharedName })).toBeVisible();
  const shared = within(paths().getByRole("article", { name: "Same recorded path" }));
  expect(shared.getByRole("link", { name: "Review baseline shared path run" })).toHaveTextContent(/^Baseline$/);
  expect(shared.getByRole("link", { name: "Review compared run 1 shared path run" })).toHaveTextContent(/^Compared run 1$/);
});

it("uses complete saved native identities without reading a newer source path", () => {
  const comparison = fixture();
  const runs = sources(comparison);
  for (const run of runs) Object.defineProperty(run, "steps", { get: () => { throw new Error("Saved native methods must remain authoritative"); } });
  render(result(comparison, runs));
  expect(paths().getByRole("article", { name: "Same recorded path" })).toBeVisible();
});

it("shares matching recorded partial outcomes without upgrading them to success", () => {
  const comparison = fixture();
  for (const summary of comparison.summaries) summary.outcomes["step-collect"] = "partial";
  render(result(comparison));
  const shared = within(paths().getByRole("article", { name: "Same recorded path" }));
  expect(shared.getByText("Partial")).toBeVisible();
  expect(shared.getAllByRole("listitem")[0]).toHaveAttribute("data-status", "partial");
  expect(shared.queryByText("Success")).not.toBeInTheDocument();
});

it("shares saved simulations only with exactly bound per-attempt simulator identities", () => {
  const comparison = fixture("simulate");
  const runs = sources(comparison);
  for (const run of runs) for (const step of run.steps) step.execution_disposition = "simulate";
  const before = structuredClone({ comparison, runs });
  render(result(comparison, runs));
  expect(paths().getByRole("article", { name: "Same recorded path" })).toBeVisible();
  expect(paths().getByText("Recorded methods and step results match for these runs.")).toBeVisible();
  expect({ comparison, runs }).toEqual(before);
});

it("can share a legacy path only when complete source attempts match its recorded order and results", () => {
  const comparison = fixture("simulate");
  const runs = sources(comparison);
  for (const summary of comparison.summaries as Summary[]) delete summary.execution_path;
  render(result(comparison, runs));
  expect(paths().getByRole("article", { name: "Same recorded path" })).toBeVisible();
});

it("keeps every participating run named when more than two recorded paths match", () => {
  const comparison = fixture();
  comparison.summaries.push({ ...structuredClone(comparison.summaries[1]!), run_id: "third" });
  comparison.run_ids.push("third");
  render(<MemoryRouter><ComparisonResult comparison={comparison} catalog={catalog} names={{ ...names, third: "Third recorded collection" }} /></MemoryRouter>);
  const shared = within(paths().getByRole("article", { name: "Same recorded path" }));
  expect(shared.getAllByRole("listitem")).toHaveLength(2);
  expect(shared.getAllByRole("link")).toHaveLength(3);
  expect(shared.getByRole("link", { name: "Review compared run 2 shared path run" })).toHaveTextContent("Third recorded collection");
});

it("does not repair a malformed saved path from an otherwise matching source", () => {
  const comparison = fixture("simulate");
  const runs = sources(comparison);
  attempts(comparison)[0]!.behavior_id = null;
  render(result(comparison, runs));
  expectSeparate();
});

it.each<[string, (value: ComparisonResponse) => void]>([
  ["changed action", value => { attempts(value)[0]!.action_id = "native.other"; }],
  ["changed behavior", value => { attempts(value)[0]!.behavior_id = "other"; }],
  ["missing action", value => { delete attempts(value)[0]!.action_id; }],
  ["null action", value => { attempts(value)[0]!.action_id = null; }],
  ["missing behavior", value => { delete attempts(value)[0]!.behavior_id; }],
  ["malformed method", value => { attempts(value)[0]!.action_id = {}; }],
  ["missing saved path", value => { delete (value.summaries[1] as Summary).execution_path; }],
  ["malformed saved path", value => { (value.summaries[1] as Summary).execution_path = [null, attempts(value)[1]]; }],
  ["different status", value => { value.summaries[1]!.outcomes["step-archive"] = "failed"; }],
  ["unknown status", value => { value.summaries[1]!.outcomes["step-archive"] = "unknown"; }],
  ["unrecognized status", value => { value.summaries[1]!.outcomes["step-archive"] = "unrecognized"; }],
  ["missing status", value => { delete value.summaries[1]!.outcomes["step-archive"]; }],
  ["malformed status", value => { (value.summaries[1]!.outcomes as Record<string, unknown>)["step-archive"] = null; }],
  ["missing mode", value => { delete value.summaries[1]!.mode; }],
  ["different mode", value => { value.summaries[1]!.mode = "simulate"; }],
  ["different order", value => { value.summaries[1]!.path.reverse(); attempts(value).reverse(); }],
  ["counterfactual continuation", value => { value.summaries[1]!.counterfactual_steps = ["step-archive"]; }],
  ["missing selected owner", value => { value.run_ids[1] = "unrelated"; }],
  ["missing baseline owner", value => { value.baseline_run_id = "unrelated"; }],
  ["empty paths", value => { for (const summary of value.summaries as Summary[]) { summary.path = []; summary.outcomes = {}; summary.execution_path = []; } }],
  ["repeated unresolved attempts", value => {
    for (const summary of value.summaries as Summary[]) {
      summary.path = ["step-collect", "step-collect"];
      summary.execution_path = [attempts(value, 0)[0], attempts(value, 0)[0]];
      summary.outcomes = { "step-collect": "success" };
    }
  }],
])("keeps separate lanes for %s even when no delta was recorded", (_label, change) => {
  const comparison = fixture();
  change(comparison);
  render(result(comparison));
  expectSeparate();
});

it.each<[string, (runs: RunRecord[]) => void]>([
  ["missing sources", runs => { runs.splice(0); }],
  ["different simulator", runs => { runs[1]!.steps[0]!.simulation_id = "simulation.other"; }],
  ["missing simulator", runs => { delete runs[1]!.steps[0]!.simulation_id; }],
  ["null simulator", runs => { runs[1]!.steps[0]!.simulation_id = null; }],
  ["different source action", runs => { runs[1]!.steps[0]!.action_id = "native.other"; }],
  ["different source behavior", runs => { runs[1]!.steps[0]!.behavior_id = "other"; }],
  ["different source status", runs => { runs[1]!.steps[0]!.status = "failed"; }],
  ["different source mode", runs => { runs[1]!.mode = "execute"; }],
  ["different source ID", runs => { runs[1]!.run_id = "unrelated"; }],
  ["different source order", runs => { runs[1]!.steps.reverse(); }],
  ["ambiguous source", runs => { runs.push(structuredClone(runs[1]!)); }],
  ["malformed source attempt", runs => { (runs[1]!.steps as unknown[])[0] = null; }],
  ["counterfactual source disposition", runs => { runs[1]!.steps[0]!.execution_disposition = "counterfactual"; }],
  ["unknown source disposition", runs => { runs[1]!.steps[0]!.execution_disposition = "unknown"; }],
  ["malformed falsy source disposition", runs => { (runs[1]!.steps[0] as unknown as Record<string, unknown>).execution_disposition = 0; }],
  ["malformed object source disposition", runs => { (runs[1]!.steps[0] as unknown as Record<string, unknown>).execution_disposition = {}; }],
])("keeps null-action simulations separate for %s", (_label, change) => {
  const comparison = fixture("simulate");
  const runs = sources(comparison);
  change(runs);
  render(result(comparison, runs));
  expectSeparate();
});
