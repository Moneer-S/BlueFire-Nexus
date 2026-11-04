import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it } from "vitest";
import { MemoryRouter, useLocation } from "react-router-dom";
import { EngineRetestComparison, engineComparisonConclusion } from "../src/components/EngineRetestComparison";
import type { EngineDefenseChange, EngineExperimentConclusion } from "../src/lib/engine-experiment";

const digest = (character: string) => `sha256:${character.repeat(64)}`;
const run = (character: string, second: string) => `run-20261104T1200${second}Z-${character.repeat(16)}`;
const defense: EngineDefenseChange = { change_id: `defense-change-${"8".repeat(32)}`, state: "retained", kind: "identity", summary: "Removed the generated-record reader role.", mechanism_ref: digest("7"), before_target_snapshot_ref: digest("8"), after_target_snapshot_ref: digest("9"), rollback_digest: digest("a"), applied_at: "2026-11-04T12:02:00Z" };

function LocationWitness() {
  const location = useLocation();
  return <output aria-label="Current route">{location.pathname + location.search}</output>;
}

const renderComparison = (value: EngineExperimentConclusion, change: EngineDefenseChange | null = defense, props: { comparisonHref?: string; runHref?: (runId: string) => string } = {}) => render(
  <MemoryRouter initialEntries={["/compare"]}>
    <EngineRetestComparison conclusion={value} defensiveChange={change} {...props} />
    <LocationWitness />
  </MemoryRouter>,
);

function conclusion(overrides: Partial<EngineExperimentConclusion> = {}): EngineExperimentConclusion {
  return {
    headline: "original_blocked_alternate_path_found",
    original_mechanism: { status: "established", run_id: run("1", "01"), support_refs: [`evidence-${"1".repeat(20)}`] },
    retained_reproducer: { status: "blocked", run_id: run("2", "02"), support_refs: [`evidence-${"2".repeat(20)}`] },
    adaptive_search: { status: "remaining_path_found", run_id: run("3", "03"), support_refs: [`evidence-${"3".repeat(20)}`] },
    legitimate_use: { status: "passed", run_id: run("4", "04"), support_refs: [`evidence-${"4".repeat(20)}`] },
    telemetry_health: { status: "complete", expected_sources: ["target audit"], verified_sources: ["target audit"], missing_sources: [] },
    cleanup: { status: "verified_absent", items: [] },
    defense: { state: "retained", change_id: defense.change_id, mechanism_ref: defense.mechanism_ref, before_target_snapshot_ref: defense.before_target_snapshot_ref, after_target_snapshot_ref: defense.after_target_snapshot_ref, current_target_snapshot_ref: defense.after_target_snapshot_ref, application_receipt_ref: digest("b"), reconciliation_receipt_ref: null, rollback_operation_ref: null, rollback_receipt_ref: null },
    unknowns: [],
    ...overrides,
  };
}

it("leads with a remaining path and labels each supporting run by role", async () => {
  const user = userEvent.setup();
  renderComparison(conclusion());
  expect(screen.getByRole("heading", { name: "Original route blocked; another path remains" })).toBeInTheDocument();
  const baseline = screen.getByRole("link", { name: /Baseline exploration run/ });
  expect(baseline).toHaveAttribute("href", `/runs/${run("1", "01")}`);
  expect(screen.getByRole("link", { name: /Original mechanism retest run/ })).toHaveAttribute("href", `/runs/${run("2", "02")}`);
  expect(screen.getByRole("link", { name: /Fresh adaptive search run/ })).toHaveAttribute("href", `/runs/${run("3", "03")}`);
  expect(screen.getByRole("link", { name: /Legitimate-use check run/ })).toHaveAttribute("href", `/runs/${run("4", "04")}`);
  await user.tab();
  expect(baseline).toHaveFocus();
  await user.keyboard("{Enter}");
  expect(screen.getByLabelText("Current route")).toHaveTextContent(`/runs/${run("1", "01")}`);
});

it("keeps a bounded no-path search qualified instead of declaring remediation", () => {
  const value = conclusion({
    headline: "original_blocked_no_remaining_path_observed_within_limits",
    adaptive_search: { status: "no_path_observed_within_limits", run_id: run("3", "03"), support_refs: [`evidence-${"3".repeat(20)}`], limit_qualified: true },
  });
  expect(engineComparisonConclusion(value)).toMatchObject({ tone: "warning", title: "Original route blocked; bounded search found no new path" });
  const { container } = renderComparison(value);
  expect(container.querySelector(".engine-retest-comparison")).toHaveClass("is-warning");
  expect(screen.getByText(/not proof that no other path exists/i)).toBeInTheDocument();
});

it("keeps legitimate-use failure separate and dominant", () => {
  const value = conclusion({ headline: "original_blocked_legitimate_use_failed", legitimate_use: { status: "failed", run_id: run("4", "04"), support_refs: [`evidence-${"4".repeat(20)}`] } });
  expect(engineComparisonConclusion(value)).toMatchObject({ tone: "danger", title: "The change disrupted legitimate use" });
});

it("does not hide unknown cleanup behind a favorable security result", () => {
  const value = conclusion({
    headline: "original_blocked_no_remaining_path_observed_within_limits",
    adaptive_search: { status: "no_path_observed_within_limits", run_id: run("3", "03"), support_refs: [], limit_qualified: true },
    cleanup: { status: "unknown", items: [] },
  });
  expect(engineComparisonConclusion(value)).toMatchObject({ tone: "warning", title: "Retest recorded; cleanup remains unknown" });
  renderComparison(value);
  expect(screen.getByText("Cleanup is not verified")).toBeInTheDocument();
});

it("does not present a historical result as current while target state needs reconciliation", () => {
  const value = conclusion({
    defense: { ...conclusion().defense, state: "unknown", current_target_snapshot_ref: null },
  });
  expect(engineComparisonConclusion(value)).toMatchObject({ tone: "warning", title: "Current target state needs reconciliation" });
  renderComparison(value, { ...defense, state: "unknown" });
  expect(screen.getByRole("heading", { name: "Current target state needs reconciliation" })).toBeInTheDocument();
  expect(screen.getByText(/remain available as history/i)).toBeInTheDocument();
});

it("names incomplete observation before interpreting absent findings", () => {
  const value = conclusion({
    headline: "original_blocked_no_remaining_path_observed_within_limits",
    adaptive_search: { status: "no_path_observed_within_limits", run_id: run("3", "03"), support_refs: [], limit_qualified: true },
    telemetry_health: { status: "partial", expected_sources: ["target audit", "worker receipt"], verified_sources: ["worker receipt"], missing_sources: ["target audit"] },
  });
  expect(engineComparisonConclusion(value)).toMatchObject({ title: "Original route blocked; observation is incomplete" });
  renderComparison(value);
  expect(screen.getByText("Observation is incomplete")).toBeInTheDocument();
  expect(screen.getByText(/cannot be interpreted as prevention/i)).toBeInTheDocument();
  expect(screen.getByText(/Missing: target audit/i)).toBeInTheDocument();
});

it("states when a conclusion has no supporting run route", () => {
  const value = conclusion({
    headline: "inconclusive_original_mechanism",
    original_mechanism: { status: "not_attempted", run_id: null, support_refs: [] },
    retained_reproducer: { status: "not_attempted", run_id: null, support_refs: [] },
    adaptive_search: { status: "not_attempted", run_id: null, support_refs: [] },
    legitimate_use: { status: "not_attempted", run_id: null, support_refs: [] },
  });
  renderComparison(value, null);
  expect(screen.getByText("Supporting runs unavailable")).toBeInTheDocument();
});

it("refuses external result routes instead of creating full-page navigation", () => {
  renderComparison(conclusion(), defense, {
    runHref: () => "https://outside.invalid/run",
    comparisonHref: "//outside.invalid/compare",
  });
  expect(screen.queryByRole("link")).not.toBeInTheDocument();
  expect(screen.getByText("Supporting runs unavailable")).toBeInTheDocument();
});
