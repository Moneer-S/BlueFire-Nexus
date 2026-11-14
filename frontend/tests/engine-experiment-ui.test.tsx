import { fireEvent, render, screen, within } from "@testing-library/react";
import type { ReactElement } from "react";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { EngineExperimentWorkspace } from "../src/components/EngineExperimentWorkspace";
import type { EngineAttempt, EngineControllerCheck, EngineExperiment, EngineExperimentConclusion, EngineProjectionAttempt, EngineProjectionCheck } from "../src/lib/engine-experiment";

const digest = (character: string) => `sha256:${character.repeat(64)}`;
const attemptId = (character: string) => `engine-attempt-${character.repeat(32)}`;
const jobId = (character: string) => `job-${character.repeat(32)}`;
const runId = (suffix: string, character: string) => `run-20261104T1200${suffix}Z-${character.repeat(16)}`;
const renderWorkspace = (ui: ReactElement) => render(<MemoryRouter>{ui}</MemoryRouter>);

function attemptDetail(role: "baseline" | "adaptive_search", character: string, state: EngineAttempt["state"] = "completed"): EngineAttempt {
  const active = ["queued", "preflight", "running", "stopping"].includes(state);
  return {
    attempt_id: attemptId(character), role, job_id: jobId(character), run_id: runId(role === "baseline" ? "01" : "02", character), upstream_session_id: state === "queued" || state === "preflight" ? null : `fixture-session-${character}`,
    state, completeness: active ? "unknown" : state === "completed" ? "complete" : "partial", exit_reason: null,
    started_at: state === "queued" || state === "preflight" ? null : "2026-11-04T12:00:00Z", finished_at: active ? null : "2026-11-04T12:01:00Z",
    usage: { duration_ms: active ? 1_000 : 60_000, model_requests: 1, input_tokens: 20, output_tokens: 10, tool_calls: 2, cost_microusd: 0 },
    findings: [], observations: [], artifacts: [], cleanup: { state: active ? "pending" : "verified_absent", receipt_ref: active ? null : digest(character), finished_at: active ? null : "2026-11-04T12:02:00Z", limitations: [] }, resume_supported: false,
  };
}

function attemptSummary(role: "baseline" | "adaptive_search", character: string, state: EngineProjectionAttempt["state"] = "completed"): EngineProjectionAttempt {
  const active = ["queued", "preflight", "running", "stopping"].includes(state);
  return {
    role, attempt_id: attemptId(character), job_id: jobId(character), run_id: runId(role === "baseline" ? "01" : "02", character), state, completeness: active ? "unknown" : state === "completed" ? "complete" : "partial",
    engine: { id: "strix", version: "fixture", revision: "1".repeat(40), package_digest: digest("2") }, model: { provider: "fixture-provider", id: "controlled-fixture", data_destination: "attempt-local test gateway" },
    target_snapshot_ref: digest("9"), delegation_digest: digest("4"), execution_approval_id: `approval-${character.repeat(32)}`, execution_approval_digest: digest("5"), cleanup: { state: active ? "pending" : "verified_absent", receipt_ref: active ? null : digest(character) }, engine_evidence_count: 0, limitations: [],
  };
}

function checkSummary(): EngineProjectionCheck {
  return {
    role: "retained_reproducer", check_id: `controller-check-${"c".repeat(32)}`, job_id: jobId("c"), run_id: runId("03", "c"), state: "completed", performer: "bluefire.controller", mechanism_ref: digest("a"), target_snapshot_ref: digest("9"), input_digest: digest("b"), result_digest: digest("c"), independent_evidence_refs: [`evidence-${"c".repeat(20)}`], cleanup: { state: "verified_absent", receipt_ref: digest("d") },
  };
}

function checkDetail(): EngineControllerCheck {
  const check = checkSummary();
  return {
    ...check, created_at: "2026-11-04T12:03:00Z", settled_at: "2026-11-04T12:04:00Z",
    observations: [{ evidence_id: `evidence-${"c".repeat(20)}`, check_id: check.check_id, category: "independent_security_outcome", provenance: "observed", summary: "The exact fixture mechanism was blocked.", producer: "bluefire.controller", timestamp: "2026-11-04T12:04:00Z", limitations: [] }],
    cleanup: { ...check.cleanup, finished_at: "2026-11-04T12:05:00Z", limitations: [] },
  };
}

const conclusion: EngineExperimentConclusion = {
  headline: "original_blocked_adaptive_result_unknown",
  original_mechanism: { status: "established", run_id: runId("01", "4"), support_refs: [] },
  retained_reproducer: { status: "blocked", run_id: runId("03", "c"), support_refs: [`evidence-${"c".repeat(20)}`] },
  adaptive_search: { status: "pending", run_id: runId("02", "6"), support_refs: [], limit_qualified: false },
  legitimate_use: { status: "not_attempted", run_id: null, support_refs: [] },
  telemetry_health: { status: "partial", expected_sources: ["baseline", "retained_reproducer", "adaptive_search"], verified_sources: ["retained_reproducer"], missing_sources: ["baseline", "adaptive_search"] },
  cleanup: { status: "pending", items: [{ kind: "engine_attempt", id: attemptId("4"), state: "verified_absent", receipt_ref: digest("4") }, { kind: "engine_attempt", id: attemptId("6"), state: "pending", receipt_ref: null }, { kind: "controller_check", id: `controller-check-${"c".repeat(32)}`, state: "verified_absent", receipt_ref: digest("d") }] },
  defense: { state: "applied", change_id: `defense-change-${"8".repeat(32)}`, mechanism_ref: digest("a"), before_target_snapshot_ref: digest("8"), after_target_snapshot_ref: digest("9"), current_target_snapshot_ref: digest("9"), application_receipt_ref: digest("e"), reconciliation_receipt_ref: null, rollback_operation_ref: null, rollback_receipt_ref: null },
  unknowns: ["The adaptive fixture attempt is still active."],
};

function experiment(options: { selectedContext?: EngineExperiment["selected_context"]; attempts?: EngineProjectionAttempt[]; checks?: EngineProjectionCheck[] } = {}): EngineExperiment {
  const attempts = options.attempts ?? [attemptSummary("baseline", "4"), attemptSummary("adaptive_search", "6", "running")];
  const checks = options.checks ?? [checkSummary()];
  return {
    schema_version: "bluefire.engine-experiment-workspace.v1", workspace_digest: digest("1"), experiment_id: `experiment-${"1".repeat(32)}`, revision: 2, experiment_digest: digest("f"),
    objective: { objective_ref: digest("0"), title: "Controlled tenant-record defense fixture", summary: "A labeled fixture for workspace interaction tests." },
    environment: { environment_ref: digest("7"), environment_id: "fixture-lab", display_name: "Disposable fixture lab", platform: "linux", disposable: true },
    current_target: { snapshot_ref: digest("9"), display_name: "Fixture target", captured_at: "2026-11-04T12:00:00Z" },
    engine_setup: { engine: { id: "strix", display_name: "Strix", version: "fixture", revision: "1".repeat(40), package_digest: digest("2"), sandbox_image_digest: digest("3") }, model: { provider: "fixture-provider", id: "controlled-fixture", data_destination: "attempt-local test gateway", authorization_digest: digest("6"), test_provider: true } },
    authorization: { scope_ref: digest("4"), scope_version: "bluefire.engine-capability-delegation.v1", wall_clock_seconds: 600, action_limit: 40, artifact_byte_limit: 1_048_576, cost_limit_microunits: 0 },
    defensive_change: { change_id: `defense-change-${"8".repeat(32)}`, state: "applied", kind: "identity", summary: "Removed the fixture reader role.", mechanism_ref: digest("a"), before_target_snapshot_ref: digest("8"), after_target_snapshot_ref: digest("9"), rollback_digest: digest("a"), applied_at: "2026-11-04T12:02:00Z" },
    projection: { schema_version: "bluefire.engine-experiment-projection.v1", experiment_id: `experiment-${"1".repeat(32)}`, revision: 2, experiment_digest: digest("f"), projection_digest: digest("d"), workflow_state: "adaptive_search_active", conclusion, attempts, checks, observations: [], run_integrity: [...attempts.map(item => ({ run_id: item.run_id, terminal: !["queued", "preflight", "running", "stopping"].includes(item.state), state: "verified" as const, detail: "Fixture run present." })), ...checks.map(item => ({ run_id: item.run_id, terminal: item.state !== "reserved", state: "verified" as const, detail: "Fixture run present." }))] },
    actions: [{ kind: "review_evidence", label: "Review evidence", enabled: true, reason: "Review the current bounded observations.", primary: true }], selected_context: options.selectedContext === undefined ? { kind: "engine_attempt", attempt: attemptDetail("baseline", "4") } : options.selectedContext, limitations: ["Fixture response only."],
  };
}

it("selects an exact saved engine attempt through its callback without submitting work", () => {
  const select = vi.fn(); const action = vi.fn(); const cancel = vi.fn();
  renderWorkspace(<EngineExperimentWorkspace experiment={experiment()} selectedAttemptId={attemptId("4")} onSelectAttempt={select} onPrimaryAction={action} onCancelAttempt={cancel} />);
  expect(screen.queryByRole("main")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: /Baseline exploration/i })).toHaveAttribute("aria-pressed", "true");
  const selectedButton = screen.getByRole("button", { name: /Baseline exploration/i });
  const selectedDetailId = selectedButton.getAttribute("aria-controls");
  expect(selectedDetailId).toBeTruthy();
  const selectedDetail = document.getElementById(selectedDetailId!);
  expect(selectedDetail).toHaveAttribute("tabindex", "-1");
  expect(document.getElementById(selectedDetail?.getAttribute("aria-labelledby") ?? "")).toHaveTextContent("Baseline exploration");
  expect(screen.getByRole("link", { name: "Open Baseline exploration run" })).toHaveAttribute("href", `/runs/${runId("01", "4")}`);
  expect(screen.getByText(`approval-${"4".repeat(32)}`)).toBeInTheDocument();
  expect(screen.getByText(digest("5"))).toBeInTheDocument();
  const adaptive = screen.getByRole("button", { name: /Fresh adaptive search/i });
  expect(adaptive).toHaveAttribute("aria-pressed", "false");
  expect(select).not.toHaveBeenCalled(); expect(action).not.toHaveBeenCalled(); expect(cancel).not.toHaveBeenCalled();
  fireEvent.click(adaptive);
  expect(select).toHaveBeenCalledWith(attemptId("6"));
});

it("keeps the constrained phase path keyboard reachable and identifies the current phase", () => {
  renderWorkspace(<EngineExperimentWorkspace experiment={experiment()} onSelectAttempt={vi.fn()} />);
  const phaseRail = screen.getByRole("list", { name: "Experiment phases" });
  expect(phaseRail).toHaveAttribute("tabindex", "0");
  expect(phaseRail).toHaveAttribute("aria-describedby");
  phaseRail.focus();
  expect(phaseRail).toHaveFocus();
  const adaptive = within(phaseRail).getByText("Fresh adaptive search").closest("li");
  expect(adaptive).toHaveAttribute("aria-current", "step");
  expect(adaptive).toHaveTextContent("Active");
  expect(within(phaseRail).getByText("Baseline exploration").closest("li")).toHaveTextContent("Current and verified");
});

it("marks a verified earlier snapshot as recorded history instead of current", () => {
  const value = experiment();
  value.projection.attempts = value.projection.attempts.map(item => item.role === "baseline" ? { ...item, target_snapshot_ref: digest("8") } : item);
  renderWorkspace(<EngineExperimentWorkspace experiment={value} onSelectAttempt={vi.fn()} />);
  const baseline = within(screen.getByRole("list", { name: "Experiment phases" })).getByText("Baseline exploration").closest("li");
  expect(baseline).toHaveTextContent("Recorded history");
  expect(baseline).toHaveAttribute("data-state", "recorded");
});

it("marks a terminal phase unavailable when its run integrity is unavailable", () => {
  const value = experiment();
  value.projection.run_integrity = value.projection.run_integrity.map(item => item.run_id === runId("01", "4") ? { ...item, state: "unavailable", detail: "Fixture run unavailable." } : item);
  renderWorkspace(<EngineExperimentWorkspace experiment={value} onSelectAttempt={vi.fn()} />);
  const baseline = within(screen.getByRole("list", { name: "Experiment phases" })).getByText("Baseline exploration").closest("li");
  expect(baseline).toHaveTextContent("Run unavailable");
  expect(baseline).toHaveAttribute("data-state", "unknown");
});

it("does not call independent verification complete while the baseline is incomplete", () => {
  const partial = attemptSummary("baseline", "4", "partial");
  const value = experiment({ attempts: [partial], checks: [] });
  value.projection.observations = [{ evidence_id: `evidence-${"4".repeat(20)}`, run_id: partial.run_id, attempt_id: partial.attempt_id, check_id: null, mechanism_ref: digest("4"), target_snapshot_ref: digest("9"), assessment: "unauthorized_disclosure", record_hash: digest("5") }];
  renderWorkspace(<EngineExperimentWorkspace experiment={value} onSelectAttempt={vi.fn()} />);
  const verification = within(screen.getByRole("list", { name: "Experiment phases" })).getByText("Independent verification").closest("li");
  expect(verification).toHaveTextContent("Incomplete");
  expect(verification).toHaveAttribute("data-state", "unknown");
});

it("requires the defensive application receipt before calling the change current", () => {
  const value = experiment();
  value.projection.conclusion = { ...value.projection.conclusion, defense: { ...value.projection.conclusion.defense, application_receipt_ref: null } };
  renderWorkspace(<EngineExperimentWorkspace experiment={value} onSelectAttempt={vi.fn()} />);
  const defense = within(screen.getByRole("list", { name: "Experiment phases" })).getByText("Defensive change").closest("li");
  expect(defense).toHaveTextContent("Application unverified");
  expect(defense).toHaveAttribute("data-state", "unknown");
});

it("keeps absent later work explicitly not attempted", () => {
  const value = experiment({ attempts: [attemptSummary("baseline", "4")], checks: [] });
  value.defensive_change = null;
  renderWorkspace(<EngineExperimentWorkspace experiment={value} onSelectAttempt={vi.fn()} />);
  const phases = screen.getByRole("list", { name: "Experiment phases" });
  for (const label of ["Defensive change", "Original mechanism retest", "Fresh adaptive search", "Legitimate-use check", "Comparison and disposition"]) {
    const phase = within(phases).getByText(label).closest("li");
    expect(phase).toHaveTextContent("Not attempted");
    expect(phase).toHaveAttribute("data-state", "not_attempted");
  }
});

it("does not silently substitute when a route-selected attempt is missing", () => {
  renderWorkspace(<EngineExperimentWorkspace experiment={experiment()} selectedAttemptId={attemptId("f")} onSelectAttempt={vi.fn()} />);
  expect(screen.getByText("Selected attempt is unavailable")).toBeInTheDocument();
  expect(screen.getAllByRole("button", { name: /exploration|adaptive search/i }).every(button => button.getAttribute("aria-pressed") === "false")).toBe(true);
  expect(screen.queryByText("Selected engine attempt")).not.toBeInTheDocument();
});

it("requires the exact selected presenter context before exposing details", () => {
  renderWorkspace(<EngineExperimentWorkspace experiment={experiment({ selectedContext: null })} selectedAttemptId={attemptId("4")} onSelectAttempt={vi.fn()} />);
  expect(screen.getByText("Selected attempt details are unavailable")).toBeInTheDocument();
  expect(screen.queryByText("Selected engine attempt")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: /Baseline exploration/i })).not.toHaveAttribute("aria-controls");
});

it("exposes fresh actions and cancellation but never unsupported resume", () => {
  const action = vi.fn(); const cancel = vi.fn();
  const view = renderWorkspace(<EngineExperimentWorkspace experiment={experiment()} onSelectAttempt={vi.fn()} onPrimaryAction={action} onCancelAttempt={cancel} />);
  fireEvent.click(screen.getByRole("button", { name: "Review evidence" }));
  fireEvent.click(screen.getByRole("button", { name: "Cancel attempt" }));
  expect(action).toHaveBeenCalledWith("review_evidence");
  expect(cancel).toHaveBeenCalledWith(attemptId("6"));
  expect(screen.queryByRole("button", { name: /resume/i })).not.toBeInTheDocument();
  view.rerender(<MemoryRouter><EngineExperimentWorkspace experiment={experiment()} onSelectAttempt={vi.fn()} onPrimaryAction={action} onCancelAttempt={cancel} cancellingAttemptId={attemptId("6")} /></MemoryRouter>);
  expect(screen.getByRole("button", { name: "Requesting cancellation" })).toBeDisabled();
});

it("disables the exact reserved controller check while cancellation is pending", () => {
  const pending = { ...checkSummary(), state: "reserved" as const, result_digest: null, independent_evidence_refs: [], cleanup: { state: "pending" as const, receipt_ref: null } };
  const cancel = vi.fn();
  const value = experiment({ attempts: [attemptSummary("baseline", "4")], checks: [pending] });
  renderWorkspace(<EngineExperimentWorkspace experiment={value} onSelectAttempt={vi.fn()} onCancelCheck={cancel} cancellingCheckId={pending.check_id} />);
  expect(screen.getByRole("button", { name: "Requesting cancellation" })).toBeDisabled();
  expect(cancel).not.toHaveBeenCalled();
});

it("does not promote an unmarked secondary action into the primary control", () => {
  const value = experiment();
  value.actions = [{ kind: "review_evidence", label: "Secondary fixture action", enabled: true, reason: "Fixture only.", primary: false }];
  renderWorkspace(<EngineExperimentWorkspace experiment={value} onSelectAttempt={vi.fn()} onPrimaryAction={vi.fn()} />);
  expect(screen.queryByRole("button", { name: "Secondary fixture action" })).not.toBeInTheDocument();
});

it("does not render an actionable control when the host has no action handler", () => {
  renderWorkspace(<EngineExperimentWorkspace experiment={experiment()} onSelectAttempt={vi.fn()} />);
  expect(screen.queryByRole("button", { name: "Review evidence" })).not.toBeInTheDocument();
  expect(screen.getByText("Next action is not available here")).toBeInTheDocument();
});

it("keeps controller checks separate and selects their exact saved context", () => {
  const selectCheck = vi.fn();
  renderWorkspace(<EngineExperimentWorkspace experiment={experiment({ selectedContext: { kind: "controller_check", check: checkDetail() }, attempts: [attemptSummary("baseline", "4")] })} selectedCheckId={`controller-check-${"c".repeat(32)}`} onSelectAttempt={vi.fn()} onSelectCheck={selectCheck} />);
  const checks = screen.getByRole("heading", { name: "Trusted controller checks" }).closest("section")!;
  expect(within(checks).getByText("Original mechanism retest")).toBeInTheDocument();
  expect(within(checks).getByText(/without assigning model or engine authorship/i)).toBeInTheDocument();
  expect(within(checks).queryByText("Engine assertion")).not.toBeInTheDocument();
  expect(within(checks).getByText("The exact fixture mechanism was blocked.")).toBeInTheDocument();
  const selectedButton = within(checks).getByRole("button", { name: "Selected" });
  const selectedDetailId = selectedButton.getAttribute("aria-controls");
  const selectedCard = selectedDetailId ? document.getElementById(selectedDetailId) : null;
  expect(selectedDetailId).toBeTruthy();
  expect(selectedCard).toHaveClass("engine-check-card", "is-selected");
  expect(selectedCard).toHaveAttribute("tabindex", "-1");
  expect(document.getElementById(selectedCard?.getAttribute("aria-labelledby") ?? "")).toHaveTextContent("Original mechanism retest");
  fireEvent.click(selectedButton);
  expect(selectCheck).toHaveBeenCalledWith(`controller-check-${"c".repeat(32)}`);
  const defense = screen.getByRole("heading", { name: "Defensive change" }).closest("section") ?? screen.getByRole("heading", { name: "Defensive change" }).parentElement?.parentElement;
  expect(defense).not.toBeNull();
  expect(within(defense as HTMLElement).getByText("Rollback plan")).toBeInTheDocument();
  expect(within(defense as HTMLElement).getByText("Rollback operation")).toBeInTheDocument();
});

it("focuses route-selected detail on initial load and when the route selection changes", () => {
  const initial = experiment();
  const view = render(<MemoryRouter><EngineExperimentWorkspace experiment={initial} selectedAttemptId={attemptId("4")} onSelectAttempt={vi.fn()} onSelectCheck={vi.fn()} /></MemoryRouter>);
  expect(screen.getByText("Selected engine attempt").closest("section")).toHaveFocus();

  const selectedCheckId = `controller-check-${"c".repeat(32)}`;
  const next = experiment({ selectedContext: { kind: "controller_check", check: checkDetail() }, attempts: [attemptSummary("baseline", "4")] });
  view.rerender(<MemoryRouter><EngineExperimentWorkspace experiment={next} selectedCheckId={selectedCheckId} onSelectAttempt={vi.fn()} onSelectCheck={vi.fn()} /></MemoryRouter>);

  const selectedButton = screen.getByRole("button", { name: "Selected" });
  const selectedDetailId = selectedButton.getAttribute("aria-controls");
  expect(selectedDetailId).toBeTruthy();
  expect(document.getElementById(selectedDetailId!)).toHaveFocus();
});

it("leads a completed experiment with its established outcome and recorded disposition", () => {
  const value = experiment({ attempts: [attemptSummary("baseline", "4"), attemptSummary("adaptive_search", "6")] });
  value.projection.workflow_state = "complete";
  value.actions = [{ kind: "review_evidence", label: "Review evidence", enabled: true, reason: "Reviews actual attempts, controller checks, unknowns, and cleanup together.", primary: true }];

  renderWorkspace(<EngineExperimentWorkspace experiment={value} selectedAttemptId={attemptId("4")} onSelectAttempt={vi.fn()} />);

  expect(screen.queryByText("Next action is not available here")).not.toBeInTheDocument();
  const phases = screen.getByRole("list", { name: "Experiment phases" });
  const disposition = within(phases).getByText("Comparison and disposition").closest("li");
  expect(disposition).toHaveTextContent("Conclusion incomplete");
  expect(disposition).toHaveAttribute("data-state", "unknown");
  expect(disposition).not.toHaveAttribute("aria-current");

  const outcome = screen.getByLabelText("Established experiment outcome");
  const attempts = screen.getByRole("heading", { name: "Engine attempts" }).closest("section");
  expect(outcome.compareDocumentPosition(attempts!)).toBe(Node.DOCUMENT_POSITION_FOLLOWING);

  const environment = screen.getByRole("heading", { name: "Disposable fixture lab" }).closest("section")!;
  expect(within(environment).getByText("Fixture target")).toBeVisible();
  expect(within(environment).getByText(digest("9"))).not.toBeVisible();
  expect(within(environment).getByText("Exact target identity and provenance")).toBeVisible();
});

it("makes unknown target state visible and exposes only reconciliation", () => {
  const value = experiment();
  value.current_target = null;
  value.defensive_change = value.defensive_change ? { ...value.defensive_change, state: "unknown" } : null;
  value.projection.conclusion = { ...value.projection.conclusion, defense: { ...value.projection.conclusion.defense, state: "unknown", current_target_snapshot_ref: null } };
  value.projection.workflow_state = "reconcile_defense";
  value.actions = [{ kind: "reconcile_defense", label: "Reconcile defensive change", enabled: true, reason: "Inspect the target before continuing.", primary: true }];

  renderWorkspace(<EngineExperimentWorkspace experiment={value} onSelectAttempt={vi.fn()} onPrimaryAction={vi.fn()} />);
  expect(screen.getByText("Current target state is not established").closest('[role="status"]')).toBeInTheDocument();
  expect(screen.getByText("Unavailable until reconciliation")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Reconcile defensive change" })).toBeEnabled();
  expect(screen.queryByRole("button", { name: "Start fresh adaptive search" })).not.toBeInTheDocument();
});
