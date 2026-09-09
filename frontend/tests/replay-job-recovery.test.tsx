import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Link, MemoryRouter, useLocation } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { api, ApiError, type ReplayPreparation } from "../src/lib/api";
import { demoCatalog, demoRuns, demoScenario } from "../src/lib/demo";
import { readPendingReplay, storePendingReplay } from "../src/lib/replay-submission";
import { RunsPage } from "../src/pages/Runs";
import { ProductProvider } from "../src/state/ProductContext";
import type { RunJob } from "../src/types";

const submissionId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const firstId = `job-${submissionId.replaceAll("-", "")}`;
const secondId = "job-bbbbbbbbbbbb4bbb8bbbbbbbbbbbbbbb";
const sourceId = "run-reviewed-source";
const payload = { exact: true, mode: "execute", profile_id: "sandbox-execute.v1" };
const preparation: ReplayPreparation = {
  schema_version: "bluefire.replay-preparation.v1", preparation_id: "replay-preparation-reviewed",
  preparation_context: { schema_version: "bluefire.replay-preparation-context.v1", runner_readiness: { observed_at: "2030-01-01T00:00:00Z" } },
  binding: { source: { run_id: sourceId }, replay_request: payload }, replay_request: payload,
  replay_extent: "full", scenario: demoScenario, lineage: { source_run_id: sourceId }, effects_started: false, approval_created: false,
  preflight: {
    ready: false, status: "approval_required", scope: { scope_refs: ["sandbox.workspace"] },
    plan: { mode: "execute", steps: [], edges: [] },
    approval_binding: { state_digest: "state-reviewed", plan_digest: "plan-reviewed", target_scope_digest: "scope-reviewed", profile_id: "sandbox-execute.v1", maximum_tier: "controlled" },
    approval_envelope: { schema_version: "bluefire.approval-envelope.v1", scenario_id: demoScenario.id, envelope_digest: "envelope-reviewed", steps: [] },
  },
};

function replayJob(jobId = firstId, state: RunJob["state"] = "awaiting_approval"): RunJob {
  const approval = { approval_id: `approval-${jobId}`, status: "pending", expires_at: "2030-01-01T00:00:00Z", ...preparation.preflight.approval_binding };
  return {
    schema_version: "bluefire.job.v1", job_id: jobId, kind: "scenario.replay", state,
    request: { mode: "execute", source_run_id: sourceId, replay_request: structuredClone(payload), replay_preparation: structuredClone(preparation), approval_request_id: approval.approval_id },
    progress: { phase: state, approval_request_id: approval.approval_id }, approval_request: approval,
  };
}

function Location() { const location = useLocation(); return <output aria-label="Current route">{location.pathname}{location.search}</output>; }
const clients: QueryClient[] = [];
function mount(route = `/runs?job=${firstId}`) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity }, mutations: { retry: false } } });
  clients.push(client);
  client.setQueryData(["catalog"], demoCatalog);
  client.setQueryData(["runs"], { runs: [], unavailable_run_count: 0 });
  client.setQueryData(["scenarios"], { scenarios: [] });
  client.setQueryData(["runner-lifecycle"], { state: "unavailable" });
  const view = render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter initialEntries={[route]}><Location /><Link to={`/runs?job=${secondId}`}>Open another saved job</Link><RunsPage /></MemoryRouter></ProductProvider></QueryClientProvider>);
  return { ...view, client };
}
async function expectJobDetails(id: string) {
  await screen.findByRole("heading", { name: "Run progress" });
  const details = screen.getByText("Job details").closest("details")!;
  if (!details.open) await userEvent.setup().click(details.querySelector("summary")!);
  await waitFor(() => expect(within(details).getByText(id, { exact: true })).toBeVisible());
}
function inventory(jobs: RunJob[]) { vi.spyOn(api, "activeJobs").mockImplementation(async () => ({ schema_version: "bluefire.active-job-list.v1", jobs })); }
function receipt() {
  const value = { sourceId, payload, preparation, submissionId };
  expect(storePendingReplay(value)).toBe(true);
  return value;
}
afterEach(() => { for (const client of clients.splice(0)) client.clear(); });

it("shows a cancelled job's retained events without claiming it is awaiting a run", async () => {
  const job = { ...replayJob(firstId, "cancelled"), request: { mode: "simulate" }, progress: { run_id: "run-partial" } };
  inventory([]);
  vi.spyOn(api, "job").mockResolvedValue(job);
  vi.spyOn(api, "runEvents").mockImplementation(async (_id, cursor = 0) => ({ schema_version: "bluefire.event-page.v1", run_id: "run-partial", after_sequence: cursor, next_sequence: 3, has_more: false, items: cursor ? [] : [1, 2, 3].map((sequence) => ({ sequence, event_type: "step.completed", payload: { step_id: `partial-${sequence}` } })) }));
  mount();
  expect(await screen.findByText("Job cancelled")).toBeVisible();
  expect(await screen.findAllByText("Step.completed")).toHaveLength(3);
  expect(screen.getByText(/no finalized run record is linked/)).toBeVisible();
  expect(screen.queryByText("Awaiting a run")).not.toBeInTheDocument();
  expect(screen.queryByText(/ownership is reconciled/)).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Cancel" })).toBeDisabled();
});

it.each(["cancelled", "interrupted", "failed", "completed"] as const)("loads the linked %s record with its actual outcome and a concise result notice", async (state) => {
  const run = { ...structuredClone(demoRuns[0]!), run_id: "run-retained", status: state, steps: [] };
  const job = { ...replayJob(firstId, state), progress: {}, result_ref: run.run_id };
  inventory([]);
  vi.spyOn(api, "job").mockResolvedValue(job);
  const detail = vi.spyOn(api, "runDetail").mockResolvedValue(run);
  vi.spyOn(api, "runs").mockResolvedValue({ runs: [run], unavailable_run_count: 0 });
  mount();
  expect(await screen.findByText(`Run ${state}`)).toBeVisible();
  expect(detail).toHaveBeenCalledWith(run.run_id);
  expect(screen.getByRole("button", { name: "Review" })).toBeEnabled();
  expect(screen.getByText(`Run ${state}; its recorded result is ready for review.`)).toBeVisible();
  expect(screen.queryByText(new RegExp(`Run ${run.run_id} is`))).not.toBeInTheDocument();
  expect(screen.queryByText(/completed and its canonical/)).not.toBeInTheDocument();
});

it("keeps the ordinary run workspace open when its restored inventory selection changes", async () => {
  const user = userEvent.setup(); const first = replayJob(); const second = replayJob(secondId);
  inventory([first, second]);
  vi.spyOn(api, "job").mockImplementation(async (id) => id === firstId ? first : second);
  mount("/runs?prepare=1");
  await expectJobDetails(firstId);
  await user.selectOptions(screen.getByRole("combobox", { name: "Active durable job" }), secondId);
  await expectJobDetails(secondId);
  expect(screen.getByLabelText("Current route")).toHaveTextContent(/^\/runs\?prepare=1$/);
  expect(screen.getByRole("heading", { name: "Runs" })).toBeVisible();
  expect(screen.getByText("Review a new run \u00b7 " + demoScenario.title).closest("details")).toHaveAttribute("open");
});

it("keeps the selected inventory job in the URL and restores that exact review after reload", async () => {
  const user = userEvent.setup();
  const first = replayJob(); const second = replayJob(secondId);
  inventory([first, second]);
  vi.spyOn(api, "job").mockImplementation(async (id) => id === firstId ? first : second);
  const approval = vi.spyOn(api, "approveJob");
  const view = mount(`/runs?job=${firstId}&view=live`);
  await expectJobDetails(firstId);
  await user.selectOptions(await screen.findByRole("combobox", { name: "Active durable job" }), secondId);
  await waitFor(() => expect(screen.getByLabelText("Current route")).toHaveTextContent(`/runs?job=${secondId}&view=live`));
  const checkbox = await screen.findByRole("checkbox", { name: /I approve this exact immutable job envelope once/ });
  await waitFor(() => expect(checkbox).toBeEnabled());
  await user.click(checkbox);
  await user.type(screen.getByRole("textbox", { name: "Operator identity for this job" }), "Operator B");
  await act(async () => { await view.client.refetchQueries({ queryKey: ["job", secondId], exact: true }); });
  expect(checkbox).toBeChecked();
  expect(screen.getByRole("button", { name: "Approve and release job" })).toBeEnabled();
  const route = screen.getByLabelText("Current route").textContent!;
  view.unmount(); view.client.clear();
  mount(route);
  await expectJobDetails(secondId);
  await waitFor(() => expect(screen.getByRole("checkbox", { name: /I approve this exact immutable job envelope once/ })).toBeEnabled());
  expect(screen.getByRole("checkbox", { name: /I approve this exact immutable job envelope once/ })).not.toBeChecked();
  expect(screen.getByRole("textbox", { name: "Operator identity for this job" })).toHaveValue("");
  expect(approval).not.toHaveBeenCalled();
});

it("replaces the URL with a retry job while retaining its fresh returned approval review", async () => {
  const user = userEvent.setup(); const original = replayJob(firstId, "interrupted"); const replacement = replayJob(secondId);
  let active: RunJob[] = [];
  vi.spyOn(api, "activeJobs").mockImplementation(async () => ({ schema_version: "bluefire.active-job-list.v1", jobs: active }));
  vi.spyOn(api, "job").mockImplementation(async (id) => id === firstId ? original : replacement);
  const restoredReview = vi.spyOn(api, "preflightStoredJobRequest").mockRejectedValue(new Error("The returned replacement review must be retained"));
  const retry = vi.spyOn(api, "retryJob").mockImplementation(async () => {
    active = [replacement];
    return { schema_version: "bluefire.job-retry.v1", retry_of_job_id: firstId, source_job: original, job: replacement, preflight: preparation.preflight, approval_request: replacement.approval_request };
  });
  const view = mount();
  const button = await screen.findByRole("button", { name: "Retry as replacement" });
  await waitFor(() => expect(button).toBeEnabled());
  await user.click(button);
  await waitFor(() => expect(screen.getByLabelText("Current route")).toHaveTextContent(`/runs?job=${secondId}`));
  await waitFor(() => expect(screen.getByRole("checkbox", { name: /I approve this exact immutable job envelope once/ })).toBeEnabled());
  expect(restoredReview).not.toHaveBeenCalled();
  expect(retry).toHaveBeenCalledExactlyOnceWith(firstId);
  const route = screen.getByLabelText("Current route").textContent!;
  view.unmount(); view.client.clear(); restoredReview.mockRestore();
  mount(route);
  await expectJobDetails(secondId);
  await waitFor(() => expect(screen.getByRole("checkbox", { name: /I approve this exact immutable job envelope once/ })).toBeEnabled());
  expect(screen.getByRole("button", { name: "Approve and release job" })).toBeDisabled();
});

it("follows an incoming job URL without the previous job snapshot taking selection back", async () => {
  const user = userEvent.setup(); const first = replayJob(); const second = replayJob(secondId);
  inventory([first, second]);
  vi.spyOn(api, "job").mockImplementation(async (id) => id === firstId ? first : second);
  mount();
  const approval = await screen.findByRole("checkbox", { name: /I approve this exact immutable job envelope once/ });
  await waitFor(() => expect(approval).toBeEnabled());
  await user.click(approval);
  await user.type(screen.getByRole("textbox", { name: "Operator identity for this job" }), "Operator A");
  await user.click(screen.getByRole("link", { name: "Open another saved job" }));
  await expectJobDetails(secondId);
  await waitFor(() => expect(screen.getByRole("checkbox", { name: /I approve this exact immutable job envelope once/ })).toBeEnabled());
  expect(screen.getByLabelText("Current route")).toHaveTextContent(`/runs?job=${secondId}`);
  expect(screen.getByRole("checkbox", { name: /I approve this exact immutable job envelope once/ })).not.toBeChecked();
  expect(screen.getByRole("textbox", { name: "Operator identity for this job" })).toHaveValue("");
});

it("settles an exact receipt only after a matching fresh job GET, without approving it", async () => {
  const pendingReceipt = receipt(); const job = replayJob();
  inventory([job]);
  let resolve!: (job: RunJob) => void;
  vi.spyOn(api, "job").mockReturnValue(new Promise((done) => { resolve = done; }));
  const approval = vi.spyOn(api, "approveJob");
  const view = mount();
  await expectJobDetails(firstId);
  expect(readPendingReplay()).toEqual(pendingReceipt);
  await act(async () => { resolve(job); });
  await waitFor(() => expect(readPendingReplay()).toBeUndefined());
  expect(approval).not.toHaveBeenCalled();
  view.unmount();
});

it("keeps an incoming completed job selected when the previous job read becomes a 404", async () => {
  inventory([]);
  const completed = replayJob(secondId, "completed");
  let rejectFirst!: (reason: Error) => void;
  let resolveSecond!: (job: RunJob) => void;
  const firstRead = new Promise<RunJob>((_resolve, reject) => { rejectFirst = reject; });
  const secondRead = new Promise<RunJob>((resolve) => { resolveSecond = resolve; });
  const detail = vi.spyOn(api, "job").mockImplementation((id) => id === firstId ? firstRead : secondRead);
  const view = mount();
  await waitFor(() => expect(detail).toHaveBeenCalledWith(firstId));
  let navigated = false;
  const unsubscribe = view.client.getQueryCache().subscribe((event) => {
    if (!navigated && event.type === "updated" && event.query.queryKey[0] === "job" && event.query.queryKey[1] === firstId && event.query.state.status === "error") {
      navigated = true;
      // Publish the incoming URL in the same update as the old GET refusal.
      fireEvent.click(screen.getByRole("link", { name: "Open another saved job" }));
    }
  });
  try {
    await act(async () => { rejectFirst(new ApiError("The previous job was not found", "job_not_found", undefined, 404)); });
    await waitFor(() => expect(detail).toHaveBeenCalledWith(secondId));
    await act(async () => { resolveSecond(completed); await secondRead; });
    await expectJobDetails(secondId);
    expect(detail).toHaveBeenCalledWith(secondId);
    expect(screen.getByLabelText("Current route")).toHaveTextContent(`/runs?job=${secondId}`);
    expect(screen.queryByText("The previous job was not found")).not.toBeInTheDocument();
  } finally { unsubscribe(); }
});

it.each(["404", "job", "source", "request", "preparation", "context"])("retains the receipt when the fresh GET has a %s mismatch or refusal", async (change) => {
  const pendingReceipt = receipt(); const job = replayJob();
  inventory([]);
  if (change === "job") job.job_id = secondId;
  if (change === "source") job.request!.source_run_id = "different-source";
  if (change === "request") job.request!.replay_request = { exact: false };
  if (change === "preparation") (job.request!.replay_preparation as ReplayPreparation).preparation_id = "different-preparation";
  if (change === "context") (job.request!.replay_preparation as ReplayPreparation).preparation_context = { runner_readiness: {} };
  const detail = vi.spyOn(api, "job");
  if (change === "404") detail.mockRejectedValue(new ApiError("The job is not yet published", "job_not_found", undefined, 404));
  else detail.mockResolvedValue(job);
  const view = mount();
  await waitFor(() => expect(view.client.getQueryState(["job", firstId])?.fetchStatus).toBe("idle"));
  expect(detail).toHaveBeenCalledWith(firstId);
  expect(readPendingReplay()).toEqual(pendingReceipt);
});


it.each([false, true])("restores checkpoint review at approval and blocks mismatched restoration: %s", async (mismatch) => {
  const job = replayJob();
  const prepared = structuredClone(preparation);
  const checkpointRequest = { from_step_id: "inspect" };
  Object.assign(prepared, { replay_extent: "from_step", replay_request: checkpointRequest,
    lineage: { from_step_id: "inspect", checkpoint_id: "checkpoint-saved", restoration_plan_hash: "sha256:saved" },
    binding: { source: { run_id: sourceId }, replay_extent: "from_step", replay_request: checkpointRequest,
      resolution: { restoration_plan: { source_run_id: sourceId, checkpoint_before_step_id: "inspect", checkpoint_id: "checkpoint-saved", plan_hash: "sha256:saved" } } },
  });
  if (mismatch) prepared.lineage.restoration_plan_hash = "sha256:changed";
  job.request = { ...job.request, replay_request: checkpointRequest, replay_preparation: prepared };
  inventory([job]);
  vi.spyOn(api, "job").mockResolvedValue(job);
  const approve = vi.spyOn(api, "approveJob");
  const user = userEvent.setup();
  const view = mount();
  if (mismatch) {
    await screen.findByText("Checkpoint review unavailable");
    expect(screen.getByRole("checkbox", { name: /I approve this exact/ })).toBeDisabled();
    expect(approve).not.toHaveBeenCalled();
    return;
  }
  await screen.findByText("Restore and continue");
  const checkbox = screen.getByRole("checkbox", { name: /I approve this exact/ });
  await waitFor(() => expect(checkbox).toBeEnabled());
  await user.click(screen.getByText("Checkpoint and restoration details"));
  expect(screen.getByText(/"checkpoint_id": "checkpoint-saved"/)).toBeVisible();
  await user.click(checkbox);
  view.unmount(); view.client.clear();
  mount();
  await screen.findByText("Restore and continue");
  expect(screen.getByRole("checkbox", { name: /I approve this exact/ })).not.toBeChecked();
  expect(approve).not.toHaveBeenCalled();
});
