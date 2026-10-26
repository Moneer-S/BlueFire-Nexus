import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it } from "vitest";
import { ComparisonResult } from "../src/pages/Compare";
import { compareDemoRuns, demoRuns } from "../src/lib/demo";

function outcomeCell(result: string, runIndex = 0) {
  const table = within(screen.getByRole("region", { name: "Compared run outcomes" }));
  const row = table.getByRole("rowheader", { name: result }).closest("tr")!;
  return within(row).getAllByRole("cell")[runIndex]!;
}

it("separates an unmet objective, missing observations, and failed cleanup without claiming prevention", () => {
  const comparison = compareDemoRuns(demoRuns.map((run) => run.run_id));
  const first = comparison.summaries[0]!;
  first.objective_reached = false;
  first.cleanup_success = false;
  first.evidence_details = undefined;
  first.first_blocked_step = "collection";
  render(<MemoryRouter><ComparisonResult comparison={comparison} /></MemoryRouter>);
  const outcomes = within(screen.getByRole("region", { name: "Compared run outcomes" }));
  expect(outcomes.getByRole("link", { name: "Review baseline run summary" })).toBeVisible();
  expect(outcomeCell("Objective")).toHaveTextContent("Not achieved");
  expect(outcomeCell("Observed artifacts")).toHaveTextContent("Not reported");
  expect(outcomeCell("Evidence gaps")).toHaveTextContent("Not reported");
  expect(outcomeCell("Cleanup")).toHaveTextContent("Needs attention");
  const blockedStep = within(outcomeCell("First stopped step")).getByText("Collection");
  expect(blockedStep).toBeVisible();
  expect(blockedStep).toHaveAttribute("title", "collection");
  expect(outcomes.queryByText(/prevented|no recorded gaps|0 observed items/i)).not.toBeInTheDocument();
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
  expect(outcomeCell("Objective")).toHaveTextContent("Achieved (synthetic)");
  expect(outcomeCell("Cleanup")).toHaveTextContent("No real effects");
  expect(outcomeCell("Cleanup")).not.toHaveTextContent("Complete");
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
  expect(screen.getByRole("rowheader", { name: "Observed artifacts" })).toBeVisible();
  expect(screen.getByRole("rowheader", { name: "Evidence gaps" })).toBeVisible();
});

it.each([
  { mode: "simulate", reached: true, outcome: "Achieved (synthetic)", conclusion: /simulations achieved|simulated objectives achieved/i },
  { mode: "execute", reached: false, outcome: "Not achieved", conclusion: /unmet objectives|recorded objectives not reached/i },
] as const)("leaves the full outcomes table while removing repeated known $mode objective rows from run cards", ({ mode, reached, outcome, conclusion }) => {
  const comparison = compareDemoRuns(demoRuns.map(run => run.run_id));
  for (const summary of comparison.summaries) {
    summary.mode = mode;
    summary.objective_reached = reached;
  }
  render(<MemoryRouter><ComparisonResult comparison={comparison} /></MemoryRouter>);
  const runOrder = screen.getByRole("group", { name: "Comparison run order" });
  expect(within(screen.getByRole("region", { name: "Comparison conclusion" })).getByRole("heading")).toHaveTextContent(conclusion);
  expect(runOrder.querySelectorAll(".compare-run-objective")).toHaveLength(0);
  expect(within(runOrder).getByRole("article", { name: "Baseline result" })).toHaveTextContent(mode === "simulate" ? "Simulate · synthetic" : "Execute");
  expect(within(runOrder).getByRole("article", { name: "Compared run 1 result" })).toHaveTextContent("Run record");
  expect(outcomeCell("Objective", 0)).toHaveTextContent(outcome);
  expect(outcomeCell("Objective", 1)).toHaveTextContent(outcome);
});

it("also removes repeated known outcomes when the conclusion counts all three runs", () => {
  const comparison = compareDemoRuns(demoRuns.map(run => run.run_id));
  for (const summary of comparison.summaries) { summary.mode = "simulate"; summary.objective_reached = true; }
  comparison.summaries.push({ ...structuredClone(comparison.summaries[1]!), run_id: "third-run" });
  comparison.run_ids.push("third-run");
  render(<MemoryRouter><ComparisonResult comparison={comparison} /></MemoryRouter>);
  expect(within(screen.getByRole("region", { name: "Comparison conclusion" })).getByText(/3 achieved, 0 not reached, 0 unreported/)).toBeVisible();
  expect(screen.getByRole("group", { name: "Comparison run order" }).querySelectorAll(".compare-run-objective")).toHaveLength(0);
  expect(outcomeCell("Objective", 2)).toHaveTextContent("Achieved (synthetic)");
});

it.each(["different", "unreported", "mixed mode", "S3 read scope"] as const)("retains per-run objectives for %s conclusions", variant => {
  const comparison = compareDemoRuns(demoRuns.map(run => run.run_id));
  for (const summary of comparison.summaries) { summary.mode = "simulate"; summary.objective_reached = true; }
  if (variant === "different") comparison.summaries[1]!.objective_reached = false;
  if (variant === "unreported") comparison.summaries[1]!.objective_reached = undefined;
  if (variant === "mixed mode") comparison.summaries[1]!.mode = "execute";
  if (variant === "S3 read scope") comparison.s3_access = { schema_version: "bluefire.s3-access-comparison.v1", state: "unavailable", reason: "mixed_selection", proof_scope: "saved_read_results_only" };
  render(<MemoryRouter><ComparisonResult comparison={comparison} /></MemoryRouter>);
  const runOrder = screen.getByRole("group", { name: "Comparison run order" });
  expect(runOrder.querySelectorAll(".compare-run-objective")).toHaveLength(2);
  expect(outcomeCell("Objective", 0)).toHaveTextContent("Achieved (synthetic)");
  expect(outcomeCell("Objective", 1)).toHaveTextContent(variant === "different" ? "Not achieved" : variant === "unreported" ? "Not established" : variant === "mixed mode" ? "Achieved" : "Achieved (synthetic)");
});

it("retains card objectives when a duplicate baseline identity makes the conclusion count an extra different outcome", () => {
  const comparison = compareDemoRuns(demoRuns.map(run => run.run_id));
  for (const summary of comparison.summaries) { summary.mode = "simulate"; summary.objective_reached = true; }
  comparison.summaries.push({ ...structuredClone(comparison.summaries[0]!), objective_reached: false });
  render(<MemoryRouter><ComparisonResult comparison={comparison} /></MemoryRouter>);
  expect(within(screen.getByRole("region", { name: "Comparison conclusion" })).getByText(/2 achieved, 1 not reached, 0 unreported/)).toBeVisible();
  expect(screen.getByRole("group", { name: "Comparison run order" }).querySelectorAll(".compare-run-objective")).toHaveLength(2);
  expect(outcomeCell("Objective", 0)).toHaveTextContent("Achieved (synthetic)");
});

it("keeps identical run titles distinguishable by role and timestamp with stored IDs in details", async () => {
  const user = userEvent.setup();
  const comparison = compareDemoRuns(demoRuns.map((run) => run.run_id));
  const baselineId = `run-${"a".repeat(32)}`;
  const comparedId = `run-${"b".repeat(32)}`;
  comparison.baseline_run_id = baselineId;
  comparison.run_ids = [baselineId, comparedId];
  comparison.summaries[0]!.run_id = baselineId;
  comparison.summaries[1]!.run_id = comparedId;
  const createdAt = { [baselineId]: "2026-10-21T05:03:01Z", [comparedId]: "2026-10-21T05:03:02Z" };
  render(<MemoryRouter><ComparisonResult comparison={comparison} names={{ [baselineId]: "Same experiment", [comparedId]: "Same experiment" }} createdAt={createdAt} /></MemoryRouter>);

  const order = within(screen.getByRole("group", { name: "Comparison run order" }));
  expect(order.getByRole("article", { name: "Baseline result" })).toBeVisible();
  expect(order.getByRole("article", { name: "Compared run 1 result" })).toBeVisible();
  expect(order.getByText(baselineId, { selector: "code" })).not.toBeVisible();
  expect(order.getByText(comparedId, { selector: "code" })).not.toBeVisible();
  expect(order.getByRole("heading", { name: "Same experiment" })).toBeVisible();
  expect(order.getAllByText("Same experiment")).toHaveLength(1);
  expect(order.getByRole("link", { name: "Review baseline run" })).toHaveAttribute("href", `/runs/${baselineId}`);
  expect(order.getByRole("link", { name: "Review compared run 1" })).toHaveAttribute("href", `/runs/${comparedId}`);
  expect(document.querySelector('time[datetime="2026-10-21T05:03:01Z"]')).toBeInTheDocument();
  expect(document.querySelector('time[datetime="2026-10-21T05:03:02Z"]')).toBeInTheDocument();
  for (const summary of order.getAllByText("Run record")) await user.click(summary);
  expect(order.getByText(baselineId, { selector: "code" })).toBeVisible();
  expect(order.getByText(comparedId, { selector: "code" })).toBeVisible();
});

it("labels a defense note as declared and not independently verified", () => {
  const comparison = compareDemoRuns(demoRuns.map((run) => run.run_id));
  const retest = comparison.summaries[1]!;
  retest.replay_lineage = { state: "replay", defense_change_declared: true, defense_change_digest: "sha256:0123456789abcdef0123456789abcdef" };
  render(<MemoryRouter><ComparisonResult comparison={comparison} /></MemoryRouter>);
  expect(screen.getByText("Defense change declared; not independently verified.")).toBeVisible();
  expect(screen.getByText(/defense change declared; digest .* \(not independently verified\)/i)).not.toBeVisible();
});

it("leads with recorded changes and uses short run roles after the identifying cards", () => {
  const comparison = compareDemoRuns(demoRuns.map(run => run.run_id));
  const baseline = comparison.summaries[0]!;
  const compared = comparison.summaries[1]!;
  comparison.deltas = [{ from_run_id: baseline.run_id, to_run_id: compared.run_id, material_changed: true, first_path_divergence: 1, objective_changed: true, dimensions: { implementation: { changed: true } } }];
  const original = structuredClone(comparison);
  render(<MemoryRouter><ComparisonResult comparison={comparison} names={{ [baseline.run_id]: "Original collection with a long experiment name", [compared.run_id]: "Revised collection with a different long experiment name" }} /></MemoryRouter>);
  const conclusion = screen.getByRole("region", { name: "Comparison conclusion" });
  const runCards = screen.getByRole("group", { name: "Comparison run order" });
  expect(conclusion.compareDocumentPosition(runCards) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(within(conclusion).getByRole("heading", { name: "Different simulated objective results" })).toBeVisible();
  expect(screen.getAllByText("Original collection with a long experiment name")).toHaveLength(1);
  expect(screen.getAllByText("Revised collection with a different long experiment name")).toHaveLength(1);
  expect(screen.getByRole("link", { name: "Review baseline run summary" })).toHaveAttribute("href", `/runs/${encodeURIComponent(baseline.run_id)}`);
  const changes = within(screen.getByRole("region", { name: "Changes between runs" }));
  expect(changes.getByText("Path diverges at step 2.")).toBeVisible();
  expect(changes.getByText("Implementation changed.")).toBeVisible();
  expect(screen.queryByText(/coverage improved|successful attacks|legitimate activity impacted/i)).not.toBeInTheDocument();
  expect(comparison).toEqual(original);
});

it("keeps missing observations and cleanup visible beside explicit zero evidence", () => {
  const comparison = compareDemoRuns(demoRuns.map(run => run.run_id));
  comparison.summaries[0]!.evidence_details = undefined;
  comparison.summaries[0]!.cleanup_success = null;
  comparison.summaries[1]!.evidence_details = { observed_artifacts: [], evidence_gaps: [] };
  comparison.summaries[1]!.cleanup_success = false;
  render(<MemoryRouter><ComparisonResult comparison={comparison} /></MemoryRouter>);
  const runOrder = within(screen.getByRole("group", { name: "Comparison run order" }));
  expect(within(runOrder.getByRole("article", { name: "Baseline result" }).querySelector("footer")!).getByText("Not reported", { exact: true })).toBeVisible();
  expect(within(runOrder.getByRole("article", { name: "Compared run 1 result" }).querySelector("footer")!).getByText("0 observed artifacts", { exact: true })).toBeVisible();
  const observations = within(screen.getByRole("region", { name: "Supporting observations" }));
  expect(observations.getByText("Independently observed artifacts not reported.")).toBeVisible();
  expect(observations.getByText("0 artifacts independently observed.")).toBeVisible();
  const unknowns = within(screen.getByRole("region", { name: "Cleanup and unknowns" }));
  expect(unknowns.getByText("Evidence gaps not reported.")).toBeVisible();
  expect(unknowns.getByText("No evidence gaps recorded.")).toBeVisible();
  expect(unknowns.getByText("Not reported")).toBeVisible();
  expect(unknowns.getByText("Needs attention")).toBeVisible();
});

it.each(["simulate", "execute"] as const)("labels %s step telemetry separately from independent observations", mode => {
  const comparison = compareDemoRuns(demoRuns.map(run => run.run_id));
  comparison.summaries[0]!.mode = mode;
  comparison.summaries[0]!.telemetry = ["network.prevented", "fixture.observed"];
  comparison.summaries[0]!.evidence_details = { observed_artifacts: [], evidence_gaps: [] };
  comparison.summaries[1]!.mode = mode;
  comparison.summaries[1]!.telemetry = undefined;
  comparison.summaries[1]!.evidence_details = undefined;
  render(<MemoryRouter><ComparisonResult comparison={comparison} /></MemoryRouter>);
  const observations = within(screen.getByRole("region", { name: "Supporting observations" }));
  const baseline = observations.getByRole("heading", { name: "Baseline" }).closest("article")!;
  const compared = observations.getByRole("heading", { name: "Compared run 1" }).closest("article")!;
  const telemetryLabel = mode === "simulate" ? "Synthetic step telemetry" : "Step-reported telemetry";
  expect(baseline).toHaveTextContent(`${telemetryLabel}: Network.prevented, Fixture.observed`);
  expect(baseline).toHaveTextContent("0 artifacts independently observed.");
  expect(compared).toHaveTextContent(`${telemetryLabel}: Not reported`);
  expect(compared).toHaveTextContent("Independently observed artifacts not reported.");
});
