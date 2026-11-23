import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { expect, it } from "vitest";
import { comparisonConclusion, type RecordedComparisonLabel } from "../src/lib/comparison-conclusion";
import { demoCatalog } from "../src/lib/demo";
import { ComparisonResult } from "../src/pages/Compare";
import type { CatalogResponse, ComparisonResponse } from "../src/types";

const stepId = "collect_internal_8", originalMethod = "fixture.list.v1", changedMethod = "fixture.metadata.v1";
function fixture() {
  const summaries = ["baseline", "compared"].map(run_id => ({ run_id, mode: "simulate" as const,
    profile_id: "sandbox-simulate.v1", path: ["prepare", stepId], outcomes: { prepare: "success", [stepId]: "success" },
    objective_reached: true, cleanup_success: true }));
  const comparison: ComparisonResponse = { comparison_id: "method-comparison", baseline_run_id: "baseline",
    run_ids: ["baseline", "compared"], summaries, deltas: [{ from_run_id: "baseline", to_run_id: "compared", material_changed: true, first_path_divergence: 1 }] };
  const labels = new Map<string, { path: RecordedComparisonLabel[] }>([
    ["baseline", { path: [{ name: "Prepare workspace", record: { step_id: "prepare", behavior_id: "fixture.prepare.v1" } },
      { name: "List selected records", method: "List owned files", record: { step_id: stepId, behavior_id: originalMethod, action_id: originalMethod } }] }],
    ["compared", { path: [{ name: "Prepare workspace", record: { step_id: "prepare", behavior_id: "fixture.prepare.v1" } },
      { name: "Inspect selected metadata", method: "Inspect file metadata", record: { step_id: stepId, behavior_id: changedMethod, action_id: changedMethod } }] }],
  ]);
  return { comparison, labels };
}

it("leads with a same-step method change and achieved simulated objectives", () => {
  const { comparison, labels } = fixture();
  const before = structuredClone(comparison);
  const result = comparisonConclusion(comparison, labels);
  expect(result.title).toBe("Different method, simulated objectives achieved");
  expect(result.detail).toContain("At recorded position 2: List owned files → Inspect file metadata.");
  expect(result.differences).toMatchObject([{ index: 1, kind: "method", baselineRunId: "baseline", comparedRunId: "compared" }]);
  expect(result.detail).not.toMatch(/prevented|fresh retest|improved defense/i);
  expect(comparison).toEqual(before);
});

it("calls a different step sequence a path change rather than inferring a changed method", () => {
  const { comparison, labels } = fixture();
  comparison.summaries[1]!.path[1] = "another_step";
  expect(comparisonConclusion(comparison, labels)).toMatchObject({ title: "Different paths, simulated objectives achieved",
    differences: [{ index: 1, kind: "path" }] });
});

it("does not invent a method difference from a delta flag or unavailable identities", () => {
  const { comparison, labels } = fixture();
  labels.get("compared")!.path[1]!.record = undefined;
  const result = comparisonConclusion(comparison, labels);
  expect(result.title).toBe("Recorded path or method difference");
  expect(result.detail).toContain("Details are unavailable.");
  expect(result.differences).toEqual([]);
});

it("does not compare known method identity against an unknown value as a change", () => {
  const { comparison, labels } = fixture();
  labels.get("compared")!.path[1]!.record = { step_id: stepId };
  expect(comparisonConclusion(comparison, labels).differences).toEqual([]);
});

it("locates a later recorded change without treating earlier unknown identities as equal methods", () => {
  const { comparison, labels } = fixture();
  labels.get("baseline")!.path[0]!.record = { step_id: "prepare" };
  const result = comparisonConclusion(comparison, labels);
  expect(result.differences).toMatchObject([{ index: 1, kind: "method" }]);
  expect(result.detail).toContain("At recorded position 2:");
});

it("keeps unreported objective results explicit even when a method change is recorded", () => {
  const { comparison, labels } = fixture();
  comparison.summaries[1]!.objective_reached = undefined;
  const result = comparisonConclusion(comparison, labels);
  expect(result.title).toBe("Different method, objective result unreported");
  expect(result.title).not.toContain("same");
});

it("describes a changed objective result without claiming prevention", () => {
  const { comparison, labels } = fixture();
  comparison.summaries[1]!.objective_reached = false;
  const result = comparisonConclusion(comparison, labels);
  expect(result.title).toBe("Different simulated objective results");
  expect(result.detail).toContain("Baseline: objective achieved; compared run: objective not reached.");
  expect(result.detail).not.toMatch(/prevented|improved|retest/i);
});

it.each([false, true])("does not compare verified results from different capability objectives when the compared result is %s", comparedReached => {
  const { comparison, labels } = fixture();
  comparison.summaries[0]!.objective_reached = false;
  comparison.summaries[1]!.objective_reached = comparedReached;
  comparison.summaries[0]!.capability_objective = {
    schema_version: "bluefire.composition-objective-projection.v1", run_id: "baseline", attempt_id: "attempt-baseline",
    state: "verified", objective_digest: "sha256:baseline", established: false, result_digest: "sha256:baseline-result",
  };
  comparison.summaries[1]!.capability_objective = {
    schema_version: "bluefire.composition-objective-projection.v1", run_id: "compared", attempt_id: "attempt-compared",
    state: "verified", objective_digest: "sha256:compared", established: comparedReached, result_digest: "sha256:compared-result",
  };
  comparison.deltas[0]!.objective_comparability = "different_objectives";
  const result = comparisonConclusion(comparison, labels);
  expect(result.title).toBe("Different objectives");
  expect(result.detail).toContain("their results do not establish a change in the same objective");
  expect(result.detail).not.toMatch(/Baseline: objective|Both simulations|Neither simulation/);
});

it("does not compare a scoped capability objective against ordinary run completion", () => {
  const { comparison, labels } = fixture();
  comparison.summaries[0]!.capability_objective = {
    schema_version: "bluefire.composition-objective-projection.v1", run_id: "baseline", attempt_id: "attempt-baseline",
    state: "verified", objective_digest: "sha256:baseline", established: true, result_digest: "sha256:baseline-result",
  };
  comparison.deltas[0]!.objective_comparability = "different_objectives";
  const result = comparisonConclusion(comparison, labels);
  expect(result.title).toBe("Objective checks differ");
  expect(result.detail).toContain("Only one run has a scoped objective check");
});

it("identifies unavailable capability proof without comparing its result", () => {
  const { comparison, labels } = fixture();
  comparison.summaries[1]!.objective_reached = null;
  comparison.deltas[0]!.objective_comparability = "unverified";
  const result = comparisonConclusion(comparison, labels);
  expect(result.title).toBe("Objective proof unavailable");
  expect(result.detail).toContain("lacks verified objective result proof");
});

it.each(["profile", "scope"])("does not describe an unchanged setup when recorded %s differs", field => {
  const { comparison, labels } = fixture();
  if (field === "profile") comparison.summaries[1]!.profile_id = "other-profile.v1";
  else comparison.deltas[0]!.target_scope_changed = true;
  expect(comparisonConclusion(comparison, labels).title).toBe("Different method and setup, simulated objectives achieved");
});

it("keeps mixed run modes out of a same-simulation conclusion", () => {
  const { comparison, labels } = fixture();
  comparison.summaries[1]!.mode = "execute";
  expect(comparisonConclusion(comparison, labels).title).toBe("Run modes differ or are unreported");
});

it("distinguishes saved independent observation changes from step telemetry changes", () => {
  const { comparison, labels } = fixture();
  labels.set("compared", structuredClone(labels.get("baseline")!));
  comparison.deltas[0]!.first_path_divergence = -1;
  comparison.deltas[0]!.telemetry_added = ["file.read"];
  expect(comparisonConclusion(comparison, labels).title).toBe("Both simulations achieved their recorded objectives");
  comparison.deltas[0]!.evidence_detail_delta = { observed_artifacts_added: [{ evidence_id: "observed-record" }] };
  expect(comparisonConclusion(comparison, labels).title).toBe("Simulated objectives achieved, observations differ");
});

it("summarizes multiple runs by recorded counts rather than making a binary same-outcome claim", () => {
  const { comparison, labels } = fixture();
  comparison.summaries[1]!.objective_reached = false;
  comparison.summaries.push({ ...comparison.summaries[0]!, run_id: "third", objective_reached: undefined });
  comparison.run_ids.push("third");
  const result = comparisonConclusion(comparison, labels);
  expect(result.title).toBe("Recorded results across 3 runs");
  expect(result.detail).toContain("Recorded objectives: 1 achieved, 1 not reached, 1 unreported.");
  expect(result.title).not.toContain("same");
});

it("counts each compared run's known difference once and distinguishes unavailable multi-run details", () => {
  const { comparison, labels } = fixture();
  comparison.summaries.push({ ...comparison.summaries[0]!, run_id: "third" });
  comparison.run_ids.push("third");
  comparison.deltas.push({ from_run_id: "baseline", to_run_id: "third", first_path_divergence: 1 });
  const result = comparisonConclusion(comparison, labels);
  expect(result.detail).toContain("2 compared runs have a recorded path or method difference from baseline.");
  expect(result.detail).toContain("Details are unavailable for 1 of those differences.");
  expect(result.differences).toMatchObject([{ comparedRunId: "compared", index: 1, kind: "method" }]);
  expect(result.differences).toHaveLength(1);
});

it("handles an incomplete comparison and preserves the separate S3 read-outcome scope", () => {
  const { comparison, labels } = fixture();
  comparison.s3_access = { schema_version: "bluefire.s3-access-comparison.v1", state: "unavailable", reason: "mixed_selection", proof_scope: "saved_read_results_only" };
  expect(comparisonConclusion(comparison, labels).title).toBe("Review the saved read outcomes");
  expect(comparisonConclusion({ ...comparison, s3_access: undefined, summaries: [] }, labels).title).toBe("Recorded comparison incomplete");
});

it("renders the recorded method names in the hero and marks only the first supported difference in each lane", () => {
  const { comparison, labels } = fixture();
  for (const summary of comparison.summaries) Object.assign(summary, {
    execution_path: labels.get(summary.run_id)!.path.map(label => ({ step_id: label.record!.step_id,
      behavior_id: label.record!.behavior_id, action_id: label.record!.action_id ?? null })),
  });
  const catalog: CatalogResponse = { ...structuredClone(demoCatalog), behaviors: [
    { ...demoCatalog.behaviors[0]!, id: "fixture.prepare.v1", title: "Prepare workspace" },
    { ...demoCatalog.behaviors[0]!, id: originalMethod, title: "List selected records" },
    { ...demoCatalog.behaviors[0]!, id: changedMethod, title: "Inspect selected metadata" },
  ], actions: [
    { ...demoCatalog.actions[0]!, id: originalMethod, title: "List owned files" },
    { ...demoCatalog.actions[0]!, id: changedMethod, title: "Inspect file metadata" },
  ] };
  const before = structuredClone(comparison);
  render(<MemoryRouter><ComparisonResult comparison={comparison} catalog={catalog} /></MemoryRouter>);
  const hero = within(screen.getByRole("region", { name: "Comparison conclusion" }));
  expect(hero.getByRole("heading", { name: "Different method, simulated objectives achieved" })).toBeVisible();
  expect(hero.getByText(/List owned files → Inspect file metadata/)).toBeVisible();
  expect(hero.queryByText(new RegExp(stepId))).not.toBeInTheDocument();
  const lanes = within(screen.getByRole("region", { name: "Recorded run paths" })).getAllByRole("article");
  for (const lane of lanes) {
    const rows = within(lane).getAllByRole("listitem");
    expect(within(rows[0]!).queryByText("First recorded difference")).not.toBeInTheDocument();
    expect(within(rows[1]!).getByText("First recorded difference")).toBeVisible();
    expect(rows[1]).toHaveAttribute("data-status", "succeeded");
  }
  expect(comparison).toEqual(before);
});

it("marks a repeated step's method difference while keeping individual attempt results unreported", () => {
  const { comparison, labels } = fixture();
  const baselinePath = labels.get("baseline")!.path;
  const comparedPath = labels.get("compared")!.path;
  baselinePath[0] = structuredClone(baselinePath[1]!);
  comparedPath[0] = structuredClone(baselinePath[1]!);
  for (const summary of comparison.summaries) {
    summary.path = [stepId, stepId];
    Object.assign(summary, { execution_path: labels.get(summary.run_id)!.path.map(label => ({ ...label.record })) });
  }
  const catalog: CatalogResponse = { ...structuredClone(demoCatalog), behaviors: [
    { ...demoCatalog.behaviors[0]!, id: originalMethod, title: "List selected records" },
    { ...demoCatalog.behaviors[0]!, id: changedMethod, title: "Inspect selected metadata" },
  ], actions: [
    { ...demoCatalog.actions[0]!, id: originalMethod, title: "List owned files" },
    { ...demoCatalog.actions[0]!, id: changedMethod, title: "Inspect file metadata" },
  ] };
  render(<MemoryRouter><ComparisonResult comparison={comparison} catalog={catalog} /></MemoryRouter>);
  expect(screen.getByRole("heading", { name: "Different method, simulated objectives achieved" })).toBeVisible();
  const lanes = within(screen.getByRole("region", { name: "Recorded run paths" })).getAllByRole("article");
  for (const lane of lanes) {
    const rows = within(lane).getAllByRole("listitem");
    expect(within(rows[1]!).getByText("First recorded difference")).toBeVisible();
    for (const row of rows) {
      expect(within(row).getByText("Unreported")).toBeVisible();
      expect(row).toHaveAttribute("data-status", "not_reported");
    }
    expect(within(lane).getByText("Individual attempt results were not recorded.")).toBeVisible();
  }
});

it("does not highlight a node from a recorded divergence flag when method details are unavailable", () => {
  const { comparison } = fixture();
  render(<MemoryRouter><ComparisonResult comparison={comparison} /></MemoryRouter>);
  const hero = within(screen.getByRole("region", { name: "Comparison conclusion" }));
  expect(hero.getByRole("heading", { name: "Recorded path or method difference" })).toBeVisible();
  expect(hero.getByText(/Details are unavailable/)).toBeVisible();
  expect(screen.queryByText("First recorded difference")).not.toBeInTheDocument();
});
