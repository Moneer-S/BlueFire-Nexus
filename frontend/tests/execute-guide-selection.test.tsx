import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ComponentProps } from "react";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { ExecuteOnboarding, GUIDED_EXECUTE_SCENARIO_ID } from "../src/components/ExecuteOnboarding";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import type { PreflightReport, RunRecord } from "../src/types";

type Props = ComponentProps<typeof ExecuteOnboarding>;

function props(): Props {
  const profile = demoCatalog.runner_profiles.find((item) => item.id === "sandbox-execute.v1")!;
  return {
    profile,
    seededScenario: { ...structuredClone(demoScenario), id: GUIDED_EXECUTE_SCENARIO_ID },
    selectedScenario: { ...structuredClone(demoScenario), id: "scenario.operator.collection.v1", title: "Cedar collection" },
    config: { mode: "execute", autonomy: "off", provider: "deterministic-offline.v1", model: "deterministic-planner.v1", endpoint: "", profileId: profile.id, runnerIds: [], scopeRefs: ["sandbox.workspace"], safetyTier: "safe", approvalPolicy: "profile", approved: false, approvedBy: "", maxSeconds: 120, maxSteps: 20, maxBytes: 1024, collectors: ["collector.filesystem.sandbox.v1"], detectionBackends: [], cleanupPolicy: "always", counterfactual: "disabled", fixtureMode: false, actionImplementations: {} },
    runner: { schema_version: "v1", state: "ready", runner_id: "runner", profile_id: profile.id, loopback_only: true, enrollment: "active", process: "authenticated", runner: null, health: { accepting_execute: true } },
    runnerPending: false, runnerError: null, runnerActionPending: false,
    preflightPending: false, preflightDisabled: false, job: null,
    approvalReleased: false, run: null, jobSubmissionPending: false,
    canCreateJob: false, demoMode: false,
    onRunnerAction: vi.fn(), onSelectScenario: vi.fn(), onPreflight: vi.fn(),
    onCreateJob: vi.fn(), onReviewEnvelope: vi.fn(), onReviewApproval: vi.fn(),
  };
}

function approvedPreflight(value: Props): PreflightReport {
  return { ready: false, status: "approval_required", runner_profile: value.config.profileId,
    plan: { mode: "execute", runner_profile_id: value.config.profileId, steps: [] },
    approval_binding: { state_digest: "state", plan_digest: "plan", target_scope_digest: "scope", profile_id: value.config.profileId, maximum_tier: "safe" },
    approval_envelope: { schema_version: "v1", envelope_digest: "envelope", scenario_id: value.selectedScenario.id, steps: [] },
  };
}

function mount(value: Props) { return render(<MemoryRouter><ExecuteOnboarding {...value} /></MemoryRouter>); }

it("preserves the selected operator graph and offers review without claiming execution readiness", async () => {
  const value = props();
  const snapshot = structuredClone(value.selectedScenario);
  mount(value);
  expect(screen.getByText(/Cedar collection/)).toBeInTheDocument();
  expect(screen.getByText("Selected for review")).toBeInTheDocument();
  expect(screen.queryByText("Ready for review")).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Load starter example", hidden: true })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Apply example settings", hidden: true })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Create run request" })).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Check selected experiment" }));
  expect(value.onPreflight).toHaveBeenCalledOnce();
  expect(value.onSelectScenario).not.toHaveBeenCalled();
  expect(value.selectedScenario).toEqual(snapshot);
});

it("offers an optional starter only when the operator graph is empty", async () => {
  const value = props();
  value.selectedScenario = { ...value.selectedScenario, steps: [], edges: [], start: "" };
  mount(value);
  expect(screen.getByText("Choose an experiment")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Check selected experiment" })).not.toBeInTheDocument();
  expect(value.onSelectScenario).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Load starter example" }));
  expect(value.onSelectScenario).toHaveBeenCalledOnce();
});

it("preserves edits to a graph that retains the starter's ID", () => {
  const value = props();
  value.selectedScenario = { ...structuredClone(value.seededScenario!), title: "My edited starter" };
  mount(value);
  expect(screen.queryByRole("button", { name: "Apply example settings", hidden: true })).not.toBeInTheDocument();
  expect(value.onSelectScenario).not.toHaveBeenCalled();
});

it("advances the selected experiment only after its server preflight and keeps approval separate", async () => {
  const value = props();
  value.preflight = approvedPreflight(value);
  const view = mount(value);
  expect(screen.getByText("Ready for review")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Review run details" }));
  expect(value.onReviewEnvelope).toHaveBeenCalledOnce();
  expect(value.onCreateJob).not.toHaveBeenCalled();
  view.rerender(<MemoryRouter><ExecuteOnboarding {...value} canCreateJob /></MemoryRouter>);
  await userEvent.click(screen.getByRole("button", { name: "Create run request" }));
  expect(value.onCreateJob).toHaveBeenCalledOnce();
  expect(screen.getByText("Waiting for approval")).toBeInTheDocument();
});

it.each(["graph", "profile", "plan", "binding", "blocked"])("does not advance approval for a %s preflight mismatch", (mismatch) => {
  const value = props();
  value.preflight = approvedPreflight(value);
  value.canCreateJob = true;
  if (mismatch === "graph") value.preflight.approval_envelope!.scenario_id = "another-graph";
  if (mismatch === "profile") value.preflight.runner_profile = "another-profile";
  if (mismatch === "plan") value.preflight.plan!.runner_profile_id = "another-profile";
  if (mismatch === "binding") value.preflight.approval_binding!.profile_id = "another-profile";
  if (mismatch === "blocked") value.preflight.status = "blocked";
  mount(value);
  expect(screen.queryByText("Ready for review")).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Create run request" })).not.toBeInTheDocument();
});

it("keeps runner and approval terminology inside closed technical details", () => {
  mount(props());
  const details = screen.getByText("Technical details").closest("details")!;
  expect(details).not.toHaveAttribute("open");
  expect(within(details).getByText(/Certificate, HMAC/)).not.toBeVisible();
  expect(within(details).getByText(/immutable approval envelope/)).not.toBeVisible();
});

it("exposes an ordinary finalized result without claiming the canary-specific completion check", () => {
  const value = props();
  value.preflight = approvedPreflight(value);
  value.approvalReleased = true;
  value.job = { schema_version: "v1", job_id: "job", kind: "scenario.run", state: "completed", request: {}, progress: {}, result_ref: "run-selected", error: null, created_at: "2030-01-01", updated_at: "2030-01-01" };
  value.run = { run_id: "run-selected", scenario_id: value.selectedScenario.id, runner_profile_id: value.config.profileId, finalized_at: "2030-01-01", status: "completed", mode: "execute", objective_reached: false, steps: [] } as RunRecord;
  mount(value);
  expect(screen.getByRole("link", { name: "Review results" })).toHaveAttribute("href", "/runs/run-selected");
  expect(screen.getAllByText("Results ready")).toHaveLength(2);
  expect(screen.queryByText("Completed")).not.toBeInTheDocument();
});

it.each(["missing", "other graph", "other profile"])("does not claim completion from a %s saved result", (mismatch) => {
  const value = props();
  value.preflight = approvedPreflight(value);
  value.approvalReleased = true;
  value.job = { schema_version: "v1", job_id: "job", kind: "scenario.run", state: "completed", request: {}, progress: {}, result_ref: "run-selected", error: null, created_at: "2030-01-01", updated_at: "2030-01-01" };
  value.run = mismatch === "missing" ? null : { run_id: "run-selected", scenario_id: mismatch === "other graph" ? "another-graph" : value.selectedScenario.id, runner_profile_id: mismatch === "other profile" ? "another-profile" : value.config.profileId, finalized_at: "2030-01-01", status: "completed", mode: "execute", objective_reached: true, steps: [] } as RunRecord;
  mount(value);
  expect(screen.queryByRole("link", { name: "Review results" })).not.toBeInTheDocument();
  expect(screen.queryByText("Completed")).not.toBeInTheDocument();
  expect(screen.queryByText("Results ready")).not.toBeInTheDocument();
  expect(screen.getByText("Awaiting saved result")).toBeInTheDocument();
});
