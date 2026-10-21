import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { expect, it } from "vitest";
import { ComparisonResult } from "../src/pages/Compare";
import { compareDemoRuns, demoRuns } from "../src/lib/demo";

it("separates an unmet objective, missing observations, and failed cleanup without claiming prevention", () => {
  const comparison = compareDemoRuns(demoRuns.map((run) => run.run_id));
  const first = comparison.summaries[0]!;
  first.objective_reached = false;
  first.cleanup_success = false;
  first.evidence_details = undefined;
  first.first_blocked_step = "collection";
  render(<MemoryRouter><ComparisonResult comparison={comparison} /></MemoryRouter>);
  const outcomes = within(screen.getByRole("region", { name: "Compared run outcomes" }));
  const row = outcomes.getByRole("link", { name: "Review baseline run summary" }).closest("tr")!;
  expect(within(row).getByText("Not achieved")).toBeVisible();
  expect(within(row).getAllByText("Not reported")).toHaveLength(2);
  expect(within(row).getByText("Needs attention")).toBeVisible();
  const blockedStep = within(row).getByText("Collection");
  expect(blockedStep).toBeVisible();
  expect(blockedStep).toHaveAttribute("title", "collection");
  expect(within(row).queryByText(/prevented|no recorded gaps|0 observed items/i)).not.toBeInTheDocument();
});

it("keeps an explicit zero observation count and recorded gaps visible", () => {
  const comparison = compareDemoRuns(demoRuns.map((run) => run.run_id));
  comparison.summaries[0]!.evidence_details = { observed_artifacts: [], evidence_gaps: [{ reason: "collector_unavailable" }] };
  render(<MemoryRouter><ComparisonResult comparison={comparison} /></MemoryRouter>);
  const outcomes = within(screen.getByRole("region", { name: "Compared run outcomes" }));
  expect(outcomes.getByText("0 artifacts")).toBeVisible();
  expect(outcomes.getByText("1 gap")).toBeVisible();
});

it("labels synthetic objectives without implying real cleanup", () => {
  const comparison = compareDemoRuns(demoRuns.map((run) => run.run_id));
  comparison.summaries[0]!.mode = "simulate";
  comparison.summaries[0]!.objective_reached = true;
  comparison.summaries[0]!.cleanup_success = true;
  render(<MemoryRouter><ComparisonResult comparison={comparison} /></MemoryRouter>);
  const row = screen.getByRole("link", { name: "Review baseline run summary" }).closest("tr")!;
  expect(within(row).getByText("Achieved (synthetic)")).toBeVisible();
  expect(within(row).getByText("No real effects")).toBeVisible();
  expect(within(row).queryByText("Complete")).not.toBeInTheDocument();
});

it("shows comparison order without labeling unrelated selected runs as retests", () => {
  const comparison = compareDemoRuns(demoRuns.map((run) => run.run_id));
  render(<MemoryRouter><ComparisonResult comparison={comparison} /></MemoryRouter>);
  expect(screen.getByRole("heading", { name: "Baseline and compared runs" })).toBeVisible();
  expect(screen.getByRole("group", { name: "Comparison run order" })).toBeVisible();
  expect(screen.getByRole("heading", { name: "Paths taken" })).toBeVisible();
  expect(screen.getByRole("table", { name: /Recorded outcomes for the selected runs/ })).toBeVisible();
  expect(screen.queryByText(/^Retest \d/)).not.toBeInTheDocument();
  expect(screen.getByText(/Selection order does not establish a fresh retest/)).toBeVisible();
  expect(screen.getByRole("columnheader", { name: "Observed artifacts" })).toBeVisible();
  expect(screen.getByRole("columnheader", { name: "Evidence gaps" })).toBeVisible();
});

it("labels a defense note as declared and not independently verified", () => {
  const comparison = compareDemoRuns(demoRuns.map((run) => run.run_id));
  const retest = comparison.summaries[1]!;
  retest.replay_lineage = { state: "replay", defense_change_declared: true, defense_change_digest: "sha256:0123456789abcdef0123456789abcdef" };
  render(<MemoryRouter><ComparisonResult comparison={comparison} /></MemoryRouter>);
  expect(screen.getByText("Defense change declared; not independently verified.")).toBeVisible();
  expect(screen.getByText(/defense change declared; digest .* \(not independently verified\)/i)).not.toBeVisible();
});
