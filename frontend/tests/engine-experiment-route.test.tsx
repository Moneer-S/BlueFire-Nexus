import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { beforeEach, expect, it, vi } from "vitest";
import { parseEngineExperimentRoute, CompositionRoute, engineReviewSelection, resolvedEngineActionAcceptance } from "../src/pages/EngineExperimentRoute";
import type { EngineExperiment } from "../src/lib/engine-experiment";
import { engineExperimentApi } from "../src/lib/engine-experiment-api";
import { AssistanceProvider, useAssistanceSelection } from "../src/state/AssistanceContext";
import { acceptedAction, actionDigest, actionWorkspace, preparedAction } from "./engine-action-fixture";

vi.mock("../src/pages/Composition", () => ({ CompositionPage: () => <h1>Ordinary composition workspace</h1> }));
vi.mock("../src/components/EngineExperimentWorkspace", () => ({
  EngineExperimentWorkspace: ({ experiment, selectedAttemptId, selectedCheckId, onSelectAttempt, onSelectCheck, onPrimaryAction, onCancelAttempt, onCancelCheck, cancellingAttemptId, cancellingCheckId }: any) => <section aria-label="Engine experiment witness">
    <h1>{experiment.objective.title}</h1>
    <output aria-label="Selected route item">{selectedAttemptId ?? selectedCheckId ?? "none"}</output>
    {experiment.projection.attempts[0] ? <button type="button" onClick={() => onSelectAttempt(experiment.projection.attempts[0].attempt_id)}>Select baseline</button> : null}
    {experiment.projection.checks[0] ? <button type="button" onClick={() => onSelectCheck(experiment.projection.checks[0].check_id)}>Select retest</button> : null}
    {experiment.actions?.find((item: { primary: boolean }) => item.primary) ? <button type="button" onClick={() => onPrimaryAction(experiment.actions.find((item: { primary: boolean }) => item.primary).kind)}>Review next action</button> : null}
    {experiment.actions?.filter((item: { kind: string }) => ["retain_defense", "rollback_defense"].includes(item.kind)).map((item: { kind: string; label: string; enabled: boolean }) => <button type="button" key={item.kind} disabled={!item.enabled} onClick={() => onPrimaryAction(item.kind)}>{item.label}</button>)}
    {experiment.projection.attempts.find((item: { state: string }) => ["queued", "preflight", "running", "stopping"].includes(item.state)) ? <button type="button" disabled={Boolean(cancellingAttemptId)} onClick={() => onCancelAttempt(experiment.projection.attempts.find((item: { state: string }) => ["queued", "preflight", "running", "stopping"].includes(item.state)).attempt_id)}>{cancellingAttemptId ? "Requesting attempt cancellation" : "Cancel active attempt"}</button> : null}
    {experiment.projection.checks.find((item: { state: string }) => item.state === "reserved") && onCancelCheck ? <button type="button" disabled={Boolean(cancellingCheckId)} onClick={() => onCancelCheck(experiment.projection.checks.find((item: { state: string }) => item.state === "reserved").check_id)}>{cancellingCheckId ? "Requesting check cancellation" : "Cancel active check"}</button> : null}
  </section>,
}));

const workspace = vi.hoisted(() => vi.fn());
const prepare = vi.hoisted(() => vi.fn());
const submit = vi.hoisted(() => vi.fn());
const controlJob = vi.hoisted(() => vi.fn());
vi.mock("../src/lib/engine-experiment-api", async importOriginal => {
  const actual = await importOriginal<typeof import("../src/lib/engine-experiment-api")>();
  return { ...actual, engineExperimentApi: { ...actual.engineExperimentApi, workspace, prepare, submit } };
});
vi.mock("../src/lib/api", async importOriginal => {
  const actual = await importOriginal<typeof import("../src/lib/api")>();
  return { ...actual, api: { ...actual.api, controlJob } };
});

const experimentId = `experiment-${"a".repeat(32)}`;
const attemptId = `engine-attempt-${"b".repeat(32)}`;
const checkId = `controller-check-${"c".repeat(32)}`;
const workspaceDigest = `sha256:${"d".repeat(64)}`;
const raw = {
  experiment_id: experimentId,
  workspace_digest: workspaceDigest,
  objective: { title: "Controlled tenant-record defense fixture" },
  projection: {
    attempts: [{ attempt_id: attemptId, state: "completed" }],
    checks: [{ check_id: checkId, state: "completed" }],
  },
} as unknown as EngineExperiment;

function Witness() {
  const location = useLocation();
  const navigate = useNavigate();
  const selection = useAssistanceSelection();
  return <><output aria-label="Current location">{`${location.pathname}${location.search}`}</output><output aria-label="Assistant selection">{selection ? JSON.stringify(selection) : "none"}</output><button type="button" onClick={() => navigate(-1)}>Browser back</button></>;
}

function mount(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } });
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><AssistanceProvider><Routes><Route path="/composition" element={<CompositionRoute />} /></Routes><Witness /></AssistanceProvider></MemoryRouter></QueryClientProvider>);
}

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  controlJob.mockReset().mockResolvedValue({});
  prepare.mockReset().mockResolvedValue(preparedAction()); submit.mockReset().mockResolvedValue(acceptedAction());
  vi.mocked(engineExperimentApi.workspace).mockReset().mockImplementation(async (_experiment, selection) => {
    if (selection?.kind === "controller_check") throw new Error("Selected workspace context changed.");
    return raw;
  });
});

function routeExperiment(workflow: EngineExperiment["projection"]["workflow_state"], attempts: Array<Record<string, unknown>>, checks: Array<Record<string, unknown>>): EngineExperiment {
  const value = actionWorkspace();
  value.actions = [{ kind: "review_evidence", label: "Review evidence", enabled: true, primary: true, reason: "Review the current work." }];
  value.projection = { ...value.projection, workflow_state: workflow, attempts, checks } as unknown as EngineExperiment["projection"];
  return value;
}

it.each([
  [`?engine_experiment=${experimentId}&engine_experiment=${experimentId}`, "duplicate experiment"],
  [`?engine_experiment=${experimentId}&attempt=${attemptId}&check=${checkId}`, "ambiguous selection"],
  [`?engine_experiment=${experimentId}&attempt=${attemptId}&attempt=${attemptId}`, "duplicate attempt"],
  [`?engine_experiment=${experimentId}&check=${checkId}&check=${checkId}`, "duplicate check"],
  [`?engine_experiment=${experimentId}&attempt=`, "empty selection"],
  [`?engine_experiment=${experimentId}&unknown=1`, "unknown field"],
  [`?engine_experiment=${experimentId}&attempt=engine%2Dattempt-${"b".repeat(32)}`, "noncanonical encoding"],
  ["?engine_experiment=invalid", "malformed experiment"],
])("rejects a %s route", (search) => {
  expect(() => parseEngineExperimentRoute(search)).toThrow(/invalid/i);
});

it("preserves ordinary Composition when no engine experiment is present", () => {
  expect(parseEngineExperimentRoute(`?attempt=${attemptId}`)).toBeNull();
  mount("/composition?view=map");
  expect(screen.getByRole("heading", { name: "Ordinary composition workspace" })).toBeVisible();
  expect(engineExperimentApi.workspace).not.toHaveBeenCalled();
});

it("loads the strict workspace, captures Assistant context, and preserves selection history", async () => {
  const user = userEvent.setup();
  mount(`/composition?engine_experiment=${experimentId}`);
  expect(await screen.findByRole("heading", { name: raw.objective.title })).toBeVisible();
  expect(engineExperimentApi.workspace).toHaveBeenCalledWith(experimentId, null);
  expect(screen.getByLabelText("Assistant selection")).toHaveTextContent(workspaceDigest);
  await waitFor(() => expect(localStorage.getItem("bluefire.local.active-defensive-work.v1")).toContain('"family":"engine"'));

  await user.click(screen.getByRole("button", { name: "Select baseline" }));
  await waitFor(() => expect(screen.getByLabelText("Current location")).toHaveTextContent(`attempt=${attemptId}`));
  await waitFor(() => expect(engineExperimentApi.workspace).toHaveBeenCalledWith(experimentId, { kind: "engine_attempt", id: attemptId }));
  expect(await screen.findByLabelText("Selected route item")).toHaveTextContent(attemptId);
  expect(screen.getByLabelText("Assistant selection")).toHaveTextContent(`"attempt_id":"${attemptId}"`);

  await user.click(screen.getByRole("button", { name: "Browser back" }));
  await waitFor(() => expect(screen.getByLabelText("Current location")).not.toHaveTextContent("attempt="));
  expect(screen.getByLabelText("Selected route item")).toHaveTextContent("none");
});

it("shows a recoverable error when the server cannot bind a requested selection", async () => {
  mount(`/composition?engine_experiment=${experimentId}&check=${checkId}`);
  expect(await screen.findByText("Engine experiment unavailable")).toBeVisible();
  expect(screen.getByRole("link", { name: "Composition workspace" })).toHaveAttribute("href", "/composition");
});

it("prepares against canonical unselected context while preserving route selection, then selects the accepted job", async () => {
  const now = vi.spyOn(Date, "now").mockReturnValue(Date.parse("2026-11-04T12:01:00Z"));
  const canonical = actionWorkspace();
  const returnedAttempt = `engine-attempt-${"f".repeat(32)}`;
  let admitted = false;
  workspace.mockImplementation(async (_id, selection) => ({ ...canonical, workspace_digest: selection ? actionDigest("8") : canonical.workspace_digest, projection: { ...canonical.projection, attempts: [{ attempt_id: attemptId, state: "completed" }, ...(admitted ? [{ attempt_id: returnedAttempt, job_id: acceptedAction().job!.job_id, state: "queued" }] : [])] } }));
  submit.mockImplementation(async () => { admitted = true; return acceptedAction(); });
  try {
    const user = userEvent.setup();
    mount(`/composition?engine_experiment=${experimentId}&attempt=${attemptId}`);
    await user.click(await screen.findByRole("button", { name: "Review next action" }));
    await screen.findByText("Intended outcome");
    expect(workspace).toHaveBeenCalledWith(experimentId);
    expect(prepare.mock.calls[0]![0].workspace_digest).toBe(canonical.workspace_digest);
    expect(screen.getByLabelText("Current location")).toHaveTextContent(`attempt=${attemptId}`);
    await user.click(screen.getByRole("checkbox")); await user.click(screen.getByRole("button", { name: "Start baseline exploration" }));
    await waitFor(() => expect(submit).toHaveBeenCalledWith(preparedAction()));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    await waitFor(() => expect(screen.getByLabelText("Current location")).toHaveTextContent(`attempt=${returnedAttempt}`));
  } finally { now.mockRestore(); }
});

it.each([
  ["baseline_active", "engine_attempt", `engine-attempt-${"1".repeat(32)}`],
  ["retained_reproducer_active", "controller_check", `controller-check-${"3".repeat(32)}`],
  ["adaptive_search_active", "engine_attempt", `engine-attempt-${"2".repeat(32)}`],
  ["legitimate_use_active", "controller_check", `controller-check-${"4".repeat(32)}`],
] as const)("selects the semantic %s work item for evidence review", (workflow, kind, expectedId) => {
  const value = routeExperiment(workflow,
    [{ role: "baseline", attempt_id: `engine-attempt-${"1".repeat(32)}` }, { role: "adaptive_search", attempt_id: `engine-attempt-${"2".repeat(32)}` }],
    [{ role: "retained_reproducer", check_id: `controller-check-${"3".repeat(32)}` }, { role: "legitimate_use", check_id: `controller-check-${"4".repeat(32)}` }]);
  expect(engineReviewSelection(value)).toEqual({ kind, id: expectedId });
});

it("routes evidence review to the active adaptive attempt instead of the first attempt", async () => {
  const value = routeExperiment("adaptive_search_active", [
    { role: "baseline", attempt_id: attemptId, state: "completed" },
    { role: "adaptive_search", attempt_id: `engine-attempt-${"f".repeat(32)}`, state: "running" },
  ], []);
  workspace.mockResolvedValue(value);
  const user = userEvent.setup();
  mount(`/composition?engine_experiment=${experimentId}`);
  await user.click(await screen.findByRole("button", { name: "Review next action" }));
  await waitFor(() => expect(screen.getByLabelText("Current location")).toHaveTextContent(`attempt=engine-attempt-${"f".repeat(32)}`));
});

it("cancels the exact active attempt job once and keeps its durable recovery path visible", async () => {
  const activeAttemptId = `engine-attempt-${"e".repeat(32)}`;
  const activeJobId = `job-${"7".repeat(32)}`;
  const value = routeExperiment("adaptive_search_active", [{ role: "adaptive_search", attempt_id: activeAttemptId, job_id: activeJobId, state: "running" }], []);
  workspace.mockResolvedValue(value);
  let settle: ((value: unknown) => void) | undefined;
  controlJob.mockImplementation(() => new Promise(resolve => { settle = resolve; }));
  const user = userEvent.setup();
  mount(`/composition?engine_experiment=${experimentId}&attempt=${activeAttemptId}`);
  await user.click(await screen.findByRole("button", { name: "Cancel active attempt" }));
  expect(controlJob).toHaveBeenCalledTimes(1);
  expect(controlJob).toHaveBeenCalledWith(activeJobId, "cancel");
  expect(screen.getByRole("button", { name: "Requesting attempt cancellation" })).toBeDisabled();
  expect(screen.getByRole("link", { name: "Open saved job in Runs" })).toHaveAttribute("href", `/runs?job=${activeJobId}`);
  await act(async () => { settle?.({ job_id: activeJobId, state: "stopping" }); });
  expect(await screen.findByText("Cancellation requested")).toBeVisible();
  expect(screen.getByLabelText("Current location")).toHaveTextContent(`attempt=${activeAttemptId}`);
});

it("surfaces attempt cancellation failure with the exact saved job link and permits another explicit request", async () => {
  const activeAttemptId = `engine-attempt-${"e".repeat(32)}`;
  const activeJobId = `job-${"8".repeat(32)}`;
  const value = routeExperiment("adaptive_search_active", [{ role: "adaptive_search", attempt_id: activeAttemptId, job_id: activeJobId, state: "running" }], []);
  workspace.mockResolvedValue(value);
  controlJob.mockRejectedValue(new Error("Cancellation could not be confirmed."));
  const user = userEvent.setup();
  mount(`/composition?engine_experiment=${experimentId}&attempt=${activeAttemptId}`);
  await user.click(await screen.findByRole("button", { name: "Cancel active attempt" }));
  expect(await screen.findByText("Cancellation was refused")).toBeVisible();
  expect(screen.getByText("Cancellation could not be confirmed.")).toBeVisible();
  expect(screen.getByRole("link", { name: "Open saved job in Runs" })).toHaveAttribute("href", `/runs?job=${activeJobId}`);
  expect(screen.getByRole("button", { name: "Cancel active attempt" })).toBeEnabled();
  expect(controlJob).toHaveBeenCalledWith(activeJobId, "cancel");
});

it("cancels the exact reserved controller-check job and preserves its selected context", async () => {
  const activeCheckId = `controller-check-${"e".repeat(32)}`;
  const activeJobId = `job-${"6".repeat(32)}`;
  const value = routeExperiment("retained_reproducer_active", [], [{ role: "retained_reproducer", check_id: activeCheckId, job_id: activeJobId, state: "reserved" }]);
  workspace.mockResolvedValue(value);
  let settle: ((value: unknown) => void) | undefined;
  controlJob.mockImplementation(() => new Promise(resolve => { settle = resolve; }));
  const user = userEvent.setup();
  mount(`/composition?engine_experiment=${experimentId}&check=${activeCheckId}`);
  await user.click(await screen.findByRole("button", { name: "Cancel active check" }));
  expect(controlJob).toHaveBeenCalledTimes(1);
  expect(controlJob).toHaveBeenCalledWith(activeJobId, "cancel");
  expect(screen.getByRole("button", { name: "Requesting check cancellation" })).toBeDisabled();
  expect(screen.getByRole("link", { name: "Open saved job in Runs" })).toHaveAttribute("href", `/runs?job=${activeJobId}`);
  await act(async () => { settle?.({ job_id: activeJobId, state: "cancelled" }); });
  expect(await screen.findByText("Cancellation requested")).toBeVisible();
  expect(screen.getByRole("button", { name: "Requesting check cancellation" })).toBeDisabled();
  expect(screen.getByLabelText("Current location")).toHaveTextContent(`check=${activeCheckId}`);
});

it("surfaces controller-check cancellation failure and re-enables the exact control", async () => {
  const activeCheckId = `controller-check-${"f".repeat(32)}`;
  const activeJobId = `job-${"5".repeat(32)}`;
  const value = routeExperiment("legitimate_use_active", [], [{ role: "legitimate_use", check_id: activeCheckId, job_id: activeJobId, state: "reserved" }]);
  workspace.mockResolvedValue(value);
  controlJob.mockRejectedValue(new Error("Controller-check cancellation could not be confirmed."));
  const user = userEvent.setup();
  mount(`/composition?engine_experiment=${experimentId}&check=${activeCheckId}`);
  await user.click(await screen.findByRole("button", { name: "Cancel active check" }));
  expect(await screen.findByText("Cancellation was refused")).toBeVisible();
  expect(screen.getByText("Controller-check cancellation could not be confirmed.")).toBeVisible();
  expect(screen.getByRole("button", { name: "Cancel active check" })).toBeEnabled();
  expect(screen.getByRole("link", { name: "Open saved job in Runs" })).toHaveAttribute("href", `/runs?job=${activeJobId}`);
  expect(controlJob).toHaveBeenCalledWith(activeJobId, "cancel");
});

it("resolves a pure transition only when its exact revision and digest are visible", () => {
  const value = actionWorkspace();
  value.revision = 2;
  value.experiment_digest = actionDigest("6");
  const receipt = { ...acceptedAction(), job: null, transition: { revision: 2, digest: actionDigest("6") } };
  expect(resolvedEngineActionAcceptance(receipt, value)).toEqual({ resolved: true, selection: null });
  expect(resolvedEngineActionAcceptance({ ...receipt, transition: { ...receipt.transition!, digest: actionDigest("7") } }, value)).toEqual({ resolved: false, selection: null });
});

it("keeps an accepted but not-yet-projected durable job reachable", async () => {
  const now = vi.spyOn(Date, "now").mockReturnValue(Date.parse("2026-11-04T12:01:00Z"));
  workspace.mockResolvedValue(actionWorkspace());
  try {
    const user = userEvent.setup();
    mount(`/composition?engine_experiment=${experimentId}`);
    await user.click(await screen.findByRole("button", { name: "Review next action" }));
    await screen.findByText("Intended outcome");
    await user.click(screen.getByRole("checkbox"));
    await user.click(screen.getByRole("button", { name: "Start baseline exploration" }));
    expect(await screen.findByText("Action accepted")).toBeVisible();
    expect(screen.getByRole("link", { name: "Open saved job in Runs" })).toHaveAttribute("href", `/runs?job=${acceptedAction().job!.job_id}`);
    expect(screen.getByRole("button", { name: "Refresh action status" })).toBeEnabled();
  } finally { now.mockRestore(); }
});

it("reviews the exact server-advertised disposition choice", async () => {
  const canonical = actionWorkspace();
  canonical.actions = [
    { kind: "retain_defense", label: "Retain applied defensive change", enabled: true, reason: "Keep the applied change.", primary: false },
    { kind: "rollback_defense", label: "Roll back defensive change", enabled: true, reason: "Restore the prior configuration.", primary: false },
  ];
  const retain = { ...preparedAction(), action_kind: "retain_defense", preparation_kind: "controller_transition", effect: { kind: "defense_disposition", summary: "Retain the applied defensive change.", changes_target: false, uses_external_engine: false }, requires_approval: false, approval: { required: false, state: "not_required", review_binding_digest: null, expires_at: null }, submission: null, limits: { wall_clock_seconds: null, action_limit: null, artifact_byte_limit: null, cost_limit_microunits: null, target_scope_digest: null, maximum_tier: null } } as const;
  workspace.mockResolvedValue(canonical);
  prepare.mockResolvedValue(retain);
  const user = userEvent.setup();
  mount(`/composition?engine_experiment=${experimentId}`);
  await user.click(await screen.findByRole("button", { name: "Retain applied defensive change" }));
  expect(await screen.findByRole("dialog")).toBeVisible();
  expect(screen.getByRole("heading", { name: "Retain defensive change" })).toBeVisible();
  expect(prepare).toHaveBeenCalledWith(canonical, "retain_defense");
  expect(screen.getByRole("checkbox")).not.toBeChecked();
});

it("does not replace an unconfirmed disposition acceptance with another choice", async () => {
  const now = vi.spyOn(Date, "now").mockReturnValue(Date.parse("2026-11-04T12:01:00Z"));
  const canonical = actionWorkspace();
  canonical.actions = [
    { kind: "retain_defense", label: "Retain applied defensive change", enabled: true, reason: "Keep the applied change.", primary: false },
    { kind: "rollback_defense", label: "Roll back defensive change", enabled: true, reason: "Restore the prior configuration.", primary: false },
  ];
  const retain = { ...preparedAction(), action_kind: "retain_defense", preparation_kind: "controller_transition", effect: { kind: "defense_disposition", summary: "Retain the applied defensive change.", changes_target: false, uses_external_engine: false }, requires_approval: false, approval: { required: false, state: "not_required", review_binding_digest: null, expires_at: null }, submission: null, limits: { wall_clock_seconds: null, action_limit: null, artifact_byte_limit: null, cost_limit_microunits: null, target_scope_digest: null, maximum_tier: null } } as const;
  workspace.mockResolvedValue(canonical); prepare.mockResolvedValue(retain); submit.mockRejectedValueOnce(new Error("network interrupted"));
  const user = userEvent.setup();
  mount(`/composition?engine_experiment=${experimentId}`);
  await user.click(await screen.findByRole("button", { name: "Retain applied defensive change" }));
  await user.click(await screen.findByRole("checkbox"));
  await user.click(screen.getByRole("button", { name: "Retain defensive change" }));
  expect(await screen.findByText(/Acceptance is unconfirmed/)).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Cancel" }));
  await user.click(screen.getByRole("button", { name: "Roll back defensive change" }));
  expect(await screen.findByText("Unconfirmed action acceptance")).toBeVisible();
  expect(screen.getByRole("button", { name: "Retry exact prepared request" })).toBeVisible();
  expect(prepare).toHaveBeenCalledTimes(1);
  expect(prepare).toHaveBeenCalledWith(canonical, "retain_defense");
  now.mockRestore();
});
