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
import type { RunJob } from "../src/types";

vi.mock("../src/pages/Composition", () => ({ CompositionPage: () => <h1>Ordinary composition workspace</h1> }));
vi.mock("../src/components/EngineExperimentWorkspace", () => ({
  EngineExperimentWorkspace: ({ experiment, selectedAttemptId, selectedCheckId, onSelectAttempt, onSelectCheck, onPrimaryAction, onCancelAttempt, onCancelCheck, cancellingAttemptId, cancellingCheckId }: any) => <section aria-label="Engine experiment witness">
    <h1>{experiment.objective.title}</h1>
    <output aria-label="Selected route item">{selectedAttemptId ?? selectedCheckId ?? "none"}</output>
    {experiment.projection.attempts[0] ? <button type="button" onClick={() => onSelectAttempt(experiment.projection.attempts[0].attempt_id)}>Select baseline</button> : null}
    {experiment.projection.attempts[1] ? <button type="button" onClick={() => onSelectAttempt(experiment.projection.attempts[1].attempt_id)}>Select adaptive</button> : null}
    {experiment.projection.checks[0] ? <button type="button" onClick={() => onSelectCheck(experiment.projection.checks[0].check_id)}>Select retest</button> : null}
    {experiment.actions?.find((item: { primary: boolean }) => item.primary) ? <button type="button" onClick={() => onPrimaryAction(experiment.actions.find((item: { primary: boolean }) => item.primary).kind)}>Review next action</button> : null}
    {experiment.actions?.filter((item: { kind: string }) => ["retain_defense", "rollback_defense"].includes(item.kind)).map((item: { kind: string; label: string; enabled: boolean }) => <button type="button" key={item.kind} disabled={!item.enabled} onClick={() => onPrimaryAction(item.kind)}>{item.label}</button>)}
    {experiment.projection.attempts.find((item: { state: string }) => ["queued", "preflight", "running", "stopping"].includes(item.state)) && onCancelAttempt ? <button type="button" disabled={Boolean(cancellingAttemptId)} onClick={() => onCancelAttempt(experiment.projection.attempts.find((item: { state: string }) => ["queued", "preflight", "running", "stopping"].includes(item.state)).attempt_id)}>{cancellingAttemptId ? "Requesting attempt cancellation" : "Cancel active attempt"}</button> : null}
    {experiment.projection.checks.find((item: { state: string }) => item.state === "reserved") && onCancelCheck ? <button type="button" disabled={Boolean(cancellingCheckId)} onClick={() => onCancelCheck(experiment.projection.checks.find((item: { state: string }) => item.state === "reserved").check_id)}>{cancellingCheckId ? "Requesting check cancellation" : "Cancel active check"}</button> : null}
  </section>,
}));

const workspace = vi.hoisted(() => vi.fn());
const prepare = vi.hoisted(() => vi.fn());
const submit = vi.hoisted(() => vi.fn());
const recover = vi.hoisted(() => vi.fn());
const controlJob = vi.hoisted(() => vi.fn());
const readJob = vi.hoisted(() => vi.fn());
vi.mock("../src/lib/engine-experiment-api", async importOriginal => {
  const actual = await importOriginal<typeof import("../src/lib/engine-experiment-api")>();
  return { ...actual, engineExperimentApi: { ...actual.engineExperimentApi, workspace, prepare, submit, recover } };
});
vi.mock("../src/lib/api", async importOriginal => {
  const actual = await importOriginal<typeof import("../src/lib/api")>();
  return { ...actual, api: { ...actual.api, controlJob, job: readJob } };
});

const experimentId = `experiment-${"a".repeat(32)}`;
const attemptId = `engine-attempt-${"b".repeat(32)}`;
const checkId = `controller-check-${"c".repeat(32)}`;
const workspaceDigest = `sha256:${"d".repeat(64)}`;
const digest = (character: string) => `sha256:${character.repeat(64)}`;
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

function engineJob(jobId: string, engineAttemptId: string, state: RunJob["state"]): RunJob {
  return {
    schema_version: "bluefire.job.v1",
    job_id: jobId,
    kind: "engine-attempt",
    state,
    request: {
      schema_version: "bluefire.engine-attempt-job.v1",
      experiment_id: experimentId,
      attempt_id: engineAttemptId,
      binding_digest: digest("1"),
      delegation_digest: digest("2"),
      execution_approval_digest: digest("3"),
      execution_approval_id: `approval-${"4".repeat(32)}`,
    },
    progress: {},
    result_ref: null,
  };
}

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  controlJob.mockReset().mockResolvedValue({});
  readJob.mockReset(); recover.mockReset().mockResolvedValue(raw);
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
  readJob.mockResolvedValue(engineJob(acceptedAction().job!.job_id, returnedAttempt, "queued"));
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

it("reconciles the exact interrupted attempt without exposing cancellation or replay", async () => {
  const activeAttemptId = `engine-attempt-${"d".repeat(32)}`;
  const activeJobId = `job-${"4".repeat(32)}`;
  const value = routeExperiment("adaptive_search_active", [{ role: "adaptive_search", attempt_id: activeAttemptId, job_id: activeJobId, state: "running", cleanup: { state: "pending", receipt_ref: null } }], []);
  workspace.mockResolvedValue(value);
  readJob.mockResolvedValue(engineJob(activeJobId, activeAttemptId, "interrupted"));
  recover.mockResolvedValue(value);
  const user = userEvent.setup();

  mount(`/composition?engine_experiment=${experimentId}&attempt=${activeAttemptId}`);

  const reconcile = await screen.findByRole("button", { name: "Reconcile saved attempt" });
  expect(screen.queryByRole("button", { name: "Cancel active attempt" })).not.toBeInTheDocument();
  await user.click(reconcile);
  await waitFor(() => expect(recover).toHaveBeenCalledExactlyOnceWith(experimentId, activeAttemptId));
  await waitFor(() => expect(workspace.mock.calls.length).toBeGreaterThanOrEqual(2));
  await waitFor(() => expect(readJob.mock.calls.filter(([id]) => id === activeJobId).length).toBeGreaterThanOrEqual(2));
  expect(controlJob).not.toHaveBeenCalled();
  expect(screen.getByText("Saved attempt reconciled")).toBeVisible();
});

it("keeps the reconciliation outcome visible after refreshed custody is verified absent", async () => {
  const activeAttemptId = `engine-attempt-${"d".repeat(32)}`;
  const activeJobId = `job-${"1".repeat(32)}`;
  const unresolved = routeExperiment("adaptive_search_active", [{ role: "adaptive_search", attempt_id: activeAttemptId, job_id: activeJobId, state: "running", cleanup: { state: "pending", receipt_ref: null } }], []);
  const reconciled = routeExperiment("review_defense", [{ role: "adaptive_search", attempt_id: activeAttemptId, job_id: activeJobId, state: "failed", cleanup: { state: "verified_absent", receipt_ref: digest("1") } }], []);
  workspace.mockResolvedValueOnce(unresolved).mockResolvedValue(reconciled);
  readJob.mockResolvedValue(engineJob(activeJobId, activeAttemptId, "interrupted"));
  recover.mockResolvedValue(reconciled);
  const user = userEvent.setup();

  mount(`/composition?engine_experiment=${experimentId}&attempt=${activeAttemptId}`);

  await user.click(await screen.findByRole("button", { name: "Reconcile saved attempt" }));
  expect(await screen.findByText("Saved attempt reconciled")).toBeVisible();
  expect(screen.getByText(/refreshed its recorded state without starting new work/i)).toBeVisible();
  expect(screen.queryByRole("button", { name: "Reconcile saved attempt" })).not.toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Open saved job in Runs" })).toHaveAttribute("href", `/runs?job=${activeJobId}`);
});

it("replaces cancellation with reconciliation when the exact saved job becomes interrupted", async () => {
  const activeAttemptId = `engine-attempt-${"7".repeat(32)}`;
  const activeJobId = `job-${"2".repeat(32)}`;
  const value = routeExperiment("adaptive_search_active", [{ role: "adaptive_search", attempt_id: activeAttemptId, job_id: activeJobId, state: "running", cleanup: { state: "pending", receipt_ref: null } }], []);
  workspace.mockResolvedValue(value);
  readJob.mockResolvedValueOnce(engineJob(activeJobId, activeAttemptId, "running")).mockResolvedValue(engineJob(activeJobId, activeAttemptId, "interrupted"));

  mount(`/composition?engine_experiment=${experimentId}&attempt=${activeAttemptId}`);

  expect(await screen.findByRole("button", { name: "Cancel active attempt" })).toBeEnabled();
  await waitFor(() => expect(readJob.mock.calls.filter(([id]) => id === activeJobId).length).toBeGreaterThanOrEqual(2), { timeout: 3500 });
  expect(await screen.findByRole("button", { name: "Reconcile saved attempt" })).toBeEnabled();
  expect(screen.queryByRole("button", { name: "Cancel active attempt" })).not.toBeInTheDocument();
});

it("does not offer cancellation against a terminal exact job with a lagging active projection", async () => {
  const activeAttemptId = `engine-attempt-${"0".repeat(32)}`;
  const activeJobId = `job-${"0".repeat(32)}`;
  const value = routeExperiment("adaptive_search_active", [{ role: "adaptive_search", attempt_id: activeAttemptId, job_id: activeJobId, state: "running", cleanup: { state: "pending", receipt_ref: null } }], []);
  workspace.mockResolvedValue(value);
  readJob.mockResolvedValue(engineJob(activeJobId, activeAttemptId, "completed"));

  mount(`/composition?engine_experiment=${experimentId}&attempt=${activeAttemptId}`);

  await waitFor(() => expect(readJob).toHaveBeenCalledWith(activeJobId));
  expect(screen.queryByRole("button", { name: "Cancel active attempt" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Reconcile saved attempt" })).not.toBeInTheDocument();
  expect(controlJob).not.toHaveBeenCalled();
});

it("does not expose unselected active-attempt cancellation for an invalid runtime job state", async () => {
  const activeAttemptId = `engine-attempt-${"a".repeat(32)}`;
  const activeJobId = `job-${"a".repeat(32)}`;
  const value = routeExperiment("adaptive_search_active", [{ role: "adaptive_search", attempt_id: activeAttemptId, job_id: activeJobId, state: "running", cleanup: { state: "pending", receipt_ref: null } }], []);
  workspace.mockResolvedValue(value);
  readJob.mockResolvedValue({ ...engineJob(activeJobId, activeAttemptId, "running"), state: "corrupt-runtime-state" as RunJob["state"] });

  mount(`/composition?engine_experiment=${experimentId}`);

  expect(await screen.findByText("Active attempt job unavailable")).toBeVisible();
  expect(screen.queryByRole("button", { name: "Cancel active attempt" })).not.toBeInTheDocument();
  expect(controlJob).not.toHaveBeenCalled();
});

it("does not expose cancellation or recovery for an unselected interrupted active job", async () => {
  const activeAttemptId = `engine-attempt-${"b".repeat(32)}`;
  const activeJobId = `job-${"b".repeat(32)}`;
  const value = routeExperiment("adaptive_search_active", [{ role: "adaptive_search", attempt_id: activeAttemptId, job_id: activeJobId, state: "running", cleanup: { state: "pending", receipt_ref: null } }], []);
  workspace.mockResolvedValue(value);
  readJob.mockResolvedValue(engineJob(activeJobId, activeAttemptId, "interrupted"));

  mount(`/composition?engine_experiment=${experimentId}`);

  await waitFor(() => expect(readJob).toHaveBeenCalledWith(activeJobId));
  expect(screen.queryByRole("button", { name: "Cancel active attempt" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Reconcile saved attempt" })).not.toBeInTheDocument();
  expect(controlJob).not.toHaveBeenCalled();
  expect(recover).not.toHaveBeenCalled();
});

it("keeps selected historical recovery separate from a mismatched active cancellation job", async () => {
  const baselineAttemptId = `engine-attempt-${"1".repeat(32)}`;
  const baselineJobId = `job-${"1".repeat(32)}`;
  const activeAttemptId = `engine-attempt-${"2".repeat(32)}`;
  const activeJobId = `job-${"2".repeat(32)}`;
  const value = routeExperiment("adaptive_search_active", [
    { role: "baseline", attempt_id: baselineAttemptId, job_id: baselineJobId, state: "failed", cleanup: { state: "unknown", receipt_ref: digest("1") } },
    { role: "adaptive_search", attempt_id: activeAttemptId, job_id: activeJobId, state: "running", cleanup: { state: "pending", receipt_ref: null } },
  ], []);
  workspace.mockResolvedValue(value);
  readJob.mockImplementation((id: string) => id === baselineJobId
    ? Promise.resolve(engineJob(baselineJobId, baselineAttemptId, "failed"))
    : Promise.resolve(engineJob(activeJobId, baselineAttemptId, "running")));

  mount(`/composition?engine_experiment=${experimentId}&attempt=${baselineAttemptId}`);

  expect(await screen.findByRole("button", { name: "Reconcile saved attempt" })).toBeEnabled();
  expect(await screen.findByText("Active attempt job unavailable")).toBeVisible();
  expect(screen.queryByRole("button", { name: "Cancel active attempt" })).not.toBeInTheDocument();
  expect(controlJob).not.toHaveBeenCalled();
});

it("binds global cancellation to a different active attempt only after its exact job is verified", async () => {
  const baselineAttemptId = `engine-attempt-${"4".repeat(32)}`;
  const baselineJobId = `job-${"4".repeat(32)}`;
  const activeAttemptId = `engine-attempt-${"5".repeat(32)}`;
  const activeJobId = `job-${"5".repeat(32)}`;
  const value = routeExperiment("adaptive_search_active", [
    { role: "baseline", attempt_id: baselineAttemptId, job_id: baselineJobId, state: "completed", cleanup: { state: "verified_absent", receipt_ref: digest("4") } },
    { role: "adaptive_search", attempt_id: activeAttemptId, job_id: activeJobId, state: "running", cleanup: { state: "pending", receipt_ref: null } },
  ], []);
  workspace.mockResolvedValue(value);
  let settleActive: ((value: RunJob) => void) | undefined;
  readJob.mockImplementation((id: string) => id === activeJobId ? new Promise(resolve => { settleActive = resolve; }) : Promise.resolve(engineJob(baselineJobId, baselineAttemptId, "completed")));

  mount(`/composition?engine_experiment=${experimentId}&attempt=${baselineAttemptId}`);

  expect(await screen.findByText(/Checking the active attempt's saved job/i)).toBeVisible();
  expect(screen.queryByRole("button", { name: "Cancel active attempt" })).not.toBeInTheDocument();
  await act(async () => { settleActive?.(engineJob(activeJobId, activeAttemptId, "running")); });
  expect(await screen.findByRole("button", { name: "Cancel active attempt" })).toBeEnabled();
  expect(readJob).not.toHaveBeenCalledWith(baselineJobId);
});

it("admits only one reconciliation while the exact request is pending", async () => {
  const activeAttemptId = `engine-attempt-${"3".repeat(32)}`;
  const activeJobId = `job-${"3".repeat(32)}`;
  const value = routeExperiment("adaptive_search_active", [{ role: "adaptive_search", attempt_id: activeAttemptId, job_id: activeJobId, state: "running", cleanup: { state: "pending", receipt_ref: null } }], []);
  workspace.mockResolvedValue(value);
  readJob.mockResolvedValue(engineJob(activeJobId, activeAttemptId, "interrupted"));
  let settle: ((value: EngineExperiment) => void) | undefined;
  recover.mockReturnValue(new Promise(resolve => { settle = resolve; }));
  const user = userEvent.setup();

  mount(`/composition?engine_experiment=${experimentId}&attempt=${activeAttemptId}`);

  const reconcile = await screen.findByRole("button", { name: "Reconcile saved attempt" });
  await user.dblClick(reconcile);
  await waitFor(() => expect(recover).toHaveBeenCalledExactlyOnceWith(experimentId, activeAttemptId));
  await act(async () => { settle?.(value); });
});

it("keeps another selected recovery disabled until the original request settles", async () => {
  const firstAttemptId = `engine-attempt-${"6".repeat(32)}`;
  const firstJobId = `job-${"6".repeat(32)}`;
  const secondAttemptId = `engine-attempt-${"7".repeat(32)}`;
  const secondJobId = `job-${"7".repeat(32)}`;
  const value = routeExperiment("review_defense", [
    { role: "baseline", attempt_id: firstAttemptId, job_id: firstJobId, state: "failed", cleanup: { state: "unknown", receipt_ref: digest("6") } },
    { role: "adaptive_search", attempt_id: secondAttemptId, job_id: secondJobId, state: "failed", cleanup: { state: "unknown", receipt_ref: digest("7") } },
  ], []);
  workspace.mockResolvedValue(value);
  readJob.mockImplementation((id: string) => Promise.resolve(id === firstJobId ? engineJob(firstJobId, firstAttemptId, "failed") : engineJob(secondJobId, secondAttemptId, "failed")));
  let settle: ((value: EngineExperiment) => void) | undefined;
  recover.mockReturnValue(new Promise(resolve => { settle = resolve; }));
  const user = userEvent.setup();

  mount(`/composition?engine_experiment=${experimentId}&attempt=${firstAttemptId}`);

  await user.click(await screen.findByRole("button", { name: "Reconcile saved attempt" }));
  await user.click(screen.getByRole("button", { name: "Select adaptive" }));
  await waitFor(() => expect(screen.getByLabelText("Current location")).toHaveTextContent(`attempt=${secondAttemptId}`));
  expect(await screen.findByRole("button", { name: "Reconciliation in progress…" })).toBeDisabled();
  expect(screen.queryByText("Saved attempt reconciled")).not.toBeInTheDocument();

  await act(async () => { settle?.(value); });
  expect(await screen.findByRole("button", { name: "Reconcile saved attempt" })).toBeEnabled();
  expect(screen.queryByText("Saved attempt reconciled")).not.toBeInTheDocument();
  expect(recover).toHaveBeenCalledExactlyOnceWith(experimentId, firstAttemptId);
});

it("offers cleanup reconciliation for a terminal attempt with exact terminal job custody", async () => {
  const terminalAttemptId = `engine-attempt-${"c".repeat(32)}`;
  const terminalJobId = `job-${"3".repeat(32)}`;
  const value = routeExperiment("review_defense", [{ role: "baseline", attempt_id: terminalAttemptId, job_id: terminalJobId, state: "failed", cleanup: { state: "unknown", receipt_ref: digest("7") } }], []);
  workspace.mockResolvedValue(value);
  readJob.mockResolvedValue(engineJob(terminalJobId, terminalAttemptId, "failed"));

  mount(`/composition?engine_experiment=${experimentId}&attempt=${terminalAttemptId}`);

  expect(await screen.findByRole("button", { name: "Reconcile saved attempt" })).toBeEnabled();
  expect(screen.getByText(/does not start or replay the engine/i)).toBeVisible();
  expect(recover).not.toHaveBeenCalled();
});

it("suppresses recovery and cancellation until the selected active job is verified", async () => {
  const activeAttemptId = `engine-attempt-${"9".repeat(32)}`;
  const activeJobId = `job-${"9".repeat(32)}`;
  const value = routeExperiment("adaptive_search_active", [{ role: "adaptive_search", attempt_id: activeAttemptId, job_id: activeJobId, state: "running", cleanup: { state: "pending", receipt_ref: null } }], []);
  workspace.mockResolvedValue(value);
  let settle: ((value: RunJob) => void) | undefined;
  readJob.mockReturnValue(new Promise(resolve => { settle = resolve; }));

  mount(`/composition?engine_experiment=${experimentId}&attempt=${activeAttemptId}`);

  expect(await screen.findByText(/Checking the selected attempt's saved job/i)).toBeVisible();
  expect(screen.queryByRole("button", { name: "Cancel active attempt" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Reconcile saved attempt" })).not.toBeInTheDocument();
  await act(async () => { settle?.(engineJob(activeJobId, `engine-attempt-${"8".repeat(32)}`, "interrupted")); });
  expect(await screen.findByText("Saved attempt job unavailable")).toBeVisible();
  expect(screen.queryByRole("button", { name: "Cancel active attempt" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Reconcile saved attempt" })).not.toBeInTheDocument();
  expect(controlJob).not.toHaveBeenCalled();
  expect(recover).not.toHaveBeenCalled();
});

it("discards a late job response after selecting another attempt", async () => {
  const firstAttemptId = `engine-attempt-${"5".repeat(32)}`;
  const secondAttemptId = `engine-attempt-${"6".repeat(32)}`;
  const firstJobId = `job-${"5".repeat(32)}`;
  const secondJobId = `job-${"6".repeat(32)}`;
  const value = routeExperiment("review_defense", [
    { role: "baseline", attempt_id: firstAttemptId, job_id: firstJobId, state: "failed", cleanup: { state: "unknown", receipt_ref: digest("5") } },
    { role: "adaptive_search", attempt_id: secondAttemptId, job_id: secondJobId, state: "running", cleanup: { state: "pending", receipt_ref: null } },
  ], []);
  workspace.mockResolvedValue(value);
  let settleFirst: ((value: RunJob) => void) | undefined;
  readJob.mockImplementation((id: string) => id === firstJobId ? new Promise(resolve => { settleFirst = resolve; }) : Promise.resolve(engineJob(secondJobId, secondAttemptId, "running")));
  const user = userEvent.setup();

  mount(`/composition?engine_experiment=${experimentId}&attempt=${firstAttemptId}`);
  await waitFor(() => expect(readJob).toHaveBeenCalledWith(firstJobId));
  await user.click(screen.getByRole("button", { name: "Select adaptive" }));
  await waitFor(() => expect(screen.getByLabelText("Current location")).toHaveTextContent(`attempt=${secondAttemptId}`));
  await waitFor(() => expect(readJob).toHaveBeenCalledWith(secondJobId));
  await act(async () => { settleFirst?.(engineJob(firstJobId, firstAttemptId, "interrupted")); });
  expect(screen.queryByRole("button", { name: "Reconcile saved attempt" })).not.toBeInTheDocument();
  expect(screen.queryByText("Saved attempt needs reconciliation")).not.toBeInTheDocument();
  expect(recover).not.toHaveBeenCalled();
});

it("cancels the exact active attempt job once and keeps its durable recovery path visible", async () => {
  const activeAttemptId = `engine-attempt-${"e".repeat(32)}`;
  const activeJobId = `job-${"7".repeat(32)}`;
  const value = routeExperiment("adaptive_search_active", [{ role: "adaptive_search", attempt_id: activeAttemptId, job_id: activeJobId, state: "running" }], []);
  workspace.mockResolvedValue(value);
  readJob.mockResolvedValue(engineJob(activeJobId, activeAttemptId, "running"));
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
  readJob.mockResolvedValue(engineJob(activeJobId, activeAttemptId, "running"));
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
