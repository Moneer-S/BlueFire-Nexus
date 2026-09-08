import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { ReceiverTestProgress } from "../src/components/ReceiverTestProgress";
import { api, ApiError } from "../src/lib/api";
import { demoRuns } from "../src/lib/demo";
import { ProductProvider, useProduct } from "../src/state/ProductContext";
import type { RunJob } from "../src/types";
import { nativeReceiverFixture } from "./receiver-inline-run-fixture";
import { receiverFixture } from "./receiver-defense-fixture";

const clients: QueryClient[] = [];
afterEach(() => { for (const client of clients.splice(0)) client.clear(); vi.useRealTimers(); });
let product: ReturnType<typeof useProduct>;
function Probe() { product = useProduct(); const location = useLocation(); return <output aria-label="Current location">{location.pathname}{location.search}</output>; }
function mount(envelope = nativeReceiverFixture()) {
  const selected = envelope.phases.find((phase) => phase.phase === envelope.next_action.phase)!.execution_job!;
  const server = { job: structuredClone(selected), owns: true };
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } }); clients.push(client);
  const inventory = vi.spyOn(api, "activeJobs").mockImplementation(async () => ({ schema_version: "bluefire.active-job-list.v1", jobs: server.owns ? [structuredClone(server.job)] : [] }));
  const detail = vi.spyOn(api, "job").mockImplementation(async (id) => { if (id !== server.job.job_id) throw new ApiError("Other job", "job_not_found", undefined, 404); return structuredClone(server.job); });
  const approve = vi.spyOn(api, "approveJob").mockImplementation(async (id) => {
    expect(id).toBe(server.job.job_id);
    server.job = { ...server.job, state: "running", progress: { run_id: "run-inline-phase" }, updated_at: "2026-09-07T12:00:01Z", approval_request: { ...server.job.approval_request, status: "consumed" } };
    return { schema_version: "bluefire.job-approval.v1", job: structuredClone(server.job) };
  });
  const control = vi.spyOn(api, "controlJob").mockImplementation(async (id, action) => {
    expect(id).toBe(server.job.job_id); expect(action).toBe("cancel");
    server.job = { ...server.job, state: "cancelling", updated_at: "2026-09-07T12:00:02Z" };
    return structuredClone(server.job);
  });
  const events = vi.spyOn(api, "runEvents").mockImplementation(async (runId) => ({ schema_version: "bluefire.event-page.v1", run_id: runId, after_sequence: 0, next_sequence: 1, has_more: false, items: [{ sequence: 1, type: "observation", message: "Actual retained phase event" }] }));
  vi.spyOn(api, "runDetail").mockImplementation(async (runId) => ({ ...structuredClone(demoRuns[0]!), run_id: runId, is_demo: false }));
  const submit = vi.spyOn(api, "submitRun"), replay = vi.spyOn(api, "submitReplay"), preflight = vi.spyOn(api, "preflight"), retry = vi.spyOn(api, "retryJob");
  const ui = (value: typeof envelope, disabled = false) => <QueryClientProvider client={client}><ProductProvider><MemoryRouter initialEntries={[`/compare?receiver_job=${envelope.job.job_id}`]}><Probe/><ReceiverTestProgress envelope={value} disabled={disabled} onPrepare={vi.fn()} onReview={vi.fn()}/></MemoryRouter></ProductProvider></QueryClientProvider>;
  return { ...render(ui(envelope)), ui, client, server, inventory, detail, approve, control, events, submit, replay, preflight, retry, selected };
}
const approvalCheckbox = () => screen.getByRole("checkbox", { name: /I approve this exact immutable job envelope once/ });
async function ready() { await screen.findByRole("checkbox", { name: /I approve this exact immutable job envelope once/ }); await waitFor(() => expect(approvalCheckbox()).toBeEnabled()); }
function confirm() { fireEvent.click(approvalCheckbox()); fireEvent.change(screen.getByRole("textbox", { name: "Operator identity for this job" }), { target: { value: "Reviewer" } }); }

it.each(["baseline", "protected", "restored"] as const)("reviews and releases the exact %s phase inline without new intent or navigation", async (phase) => {
  const envelope = nativeReceiverFixture(phase);
  const previous = `job-${"f".repeat(32)}`; localStorage.setItem("bluefire.local.active-job-id.v1", previous);
  const view = mount(envelope); const draft = structuredClone(product.scenario); const config = structuredClone(product.runConfig);
  await ready();
  expect(approvalCheckbox()).not.toBeChecked();
  expect(screen.getByRole("button", { name: "Approve and release job" })).toBeDisabled();
  expect(screen.queryByRole("button", { name: "Run preflight" })).not.toBeInTheDocument();
  expect(screen.queryByText(/Review a new run/)).not.toBeInTheDocument();
  confirm(); fireEvent.click(screen.getByRole("button", { name: "Approve and release job" }));
  await waitFor(() => expect(view.approve).toHaveBeenCalledExactlyOnceWith(view.selected.job_id, "Reviewer"));
  await screen.findByText("Actual retained phase event");
  expect(screen.getByRole("button", { name: "Pause" })).toBeEnabled();
  expect(screen.getByLabelText("Current location")).toHaveTextContent(`/compare?receiver_job=${envelope.job.job_id}`);
  expect(product.scenario).toEqual(draft); expect(product.runConfig).toEqual(config); expect(product.activeRun).toBeNull();
  expect(localStorage.getItem("bluefire.local.active-job-id.v1")).toBe(previous);
  expect(view.preflight).not.toHaveBeenCalled(); expect(view.submit).not.toHaveBeenCalled(); expect(view.replay).not.toHaveBeenCalled(); expect(view.retry).not.toHaveBeenCalled();
});

it("keeps Cancel on the same receiver-owned job when parent Stop disables release", async () => {
  const envelope = nativeReceiverFixture(); const view = mount(envelope); await ready(); confirm();
  view.rerender(view.ui(envelope, true));
  expect(screen.getByRole("button", { name: "Approve and release job" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Cancel" })).toBeEnabled();
  fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
  await waitFor(() => expect(view.control).toHaveBeenCalledExactlyOnceWith(view.selected.job_id, "cancel"));
  await waitFor(() => expect(screen.getAllByText(/Cancelling/).length).toBeGreaterThan(0));
  expect(view.approve).not.toHaveBeenCalled(); expect(view.retry).not.toHaveBeenCalled();
  expect(screen.queryByRole("button", { name: "Retry as replacement" })).not.toBeInTheDocument();
});

it("waits for fresh exact controller ownership and never adopts another active job", async () => {
  const envelope = nativeReceiverFixture(); const view = mount(envelope);
  const other: RunJob = { ...structuredClone(view.server.job), job_id: `job-${"e".repeat(32)}` };
  view.inventory.mockResolvedValue({ schema_version: "bluefire.active-job-list.v1", jobs: [other] });
  await act(async () => { await view.client.invalidateQueries({ queryKey: ["active-jobs"] }); });
  await screen.findByText(/not present in the active controller inventory/);
  expect(screen.queryByRole("button", { name: "Approve and release job" })).not.toBeInTheDocument();
  expect(view.detail.mock.calls.every(([id]) => id === view.selected.job_id)).toBe(true);
  expect(view.approve).not.toHaveBeenCalled(); expect(view.control).not.toHaveBeenCalled();
});

it("refuses a different immutable phase request even when its job ID matches", async () => {
  const view = mount(); view.server.job.request = { ...view.server.job.request, receiver_defense: { parent_job_id: "other-owner" } };
  await screen.findByText(/job detail response did not match/);
  expect(screen.queryByRole("button", { name: "Approve and release job" })).not.toBeInTheDocument();
  expect(view.approve).not.toHaveBeenCalled();
});

it.each(["state_digest", "plan_digest", "target_scope_digest", "profile_id", "maximum_tier"])("keeps the original report and Cancel when %s mismatches", async (field) => {
  const envelope = nativeReceiverFixture(); envelope.phases[0]!.execution_job!.approval_request![field] = "different";
  const view = mount(envelope);
  await screen.findByText("Exact approval review unavailable");
  expect(screen.getByRole("button", { name: "Approve and release job" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Cancel" })).toBeEnabled(); expect(view.approve).not.toHaveBeenCalled(); expect(view.preflight).not.toHaveBeenCalled();
});

it("reopens an expired approval as read-only inline", async () => {
  const envelope = nativeReceiverFixture(); envelope.phases[0]!.execution_job!.approval_request!.expires_at = "2000-01-01T00:00:00Z";
  const view = mount(envelope);
  await screen.findByText("Approval review expired");
  expect(screen.getByRole("button", { name: "Approve and release job" })).toBeDisabled(); expect(screen.getByRole("button", { name: "Cancel" })).toBeEnabled();
  await waitFor(() => expect(screen.getAllByText("reviewed-plan-baseline").length).toBeGreaterThan(0)); expect(view.approve).not.toHaveBeenCalled();
});

it("reconciles a lost approval response through reads without repeating release", async () => {
  const view = mount(); await ready();
  view.approve.mockImplementation(async () => { view.server.job = { ...view.server.job, state: "running", progress: { run_id: "run-inline-phase" }, updated_at: "2026-09-07T12:00:01Z" }; throw new Error("Response unavailable; checking saved state"); });
  confirm(); fireEvent.click(screen.getByRole("button", { name: "Approve and release job" }));
  await screen.findByText("Response unavailable; checking saved state");
  await act(async () => { await view.client.invalidateQueries({ queryKey: ["job", view.selected.job_id], exact: true }); });
  await screen.findByText("Actual retained phase event");
  expect(view.approve).toHaveBeenCalledTimes(1); expect(screen.queryByRole("button", { name: "Approve and release job" })).not.toBeInTheDocument(); expect(view.retry).not.toHaveBeenCalled();
});

it("discards late previous-phase approval callbacks and requires a fresh acknowledgement", async () => {
  const view = mount(); await ready();
  let resolve!: (result: Awaited<ReturnType<typeof api.approveJob>>) => void;
  view.approve.mockReturnValue(new Promise((accept) => { resolve = accept; }));
  confirm(); fireEvent.click(screen.getByRole("button", { name: "Approve and release job" }));
  const old = structuredClone(view.server.job); const next = nativeReceiverFixture("protected"); view.server.job = structuredClone(next.phases[1]!.execution_job!);
  view.rerender(view.ui(next)); await ready();
  await act(async () => resolve({ schema_version: "bluefire.job-approval.v1", job: { ...old, state: "running", updated_at: "2026-09-07T12:00:02Z" } }));
  expect(approvalCheckbox()).not.toBeChecked(); expect(screen.getByRole("textbox", { name: "Operator identity for this job" })).toHaveValue("");
  expect(screen.getByRole("button", { name: "Approve and release job" })).toBeDisabled();
  expect(within(screen.getByRole("region", { name: "Phase run approval and progress" })).getAllByText(view.server.job.job_id).length).toBeGreaterThan(0); expect(view.approve).toHaveBeenCalledTimes(1);
});

it.each(["running", "completed", "invalid_schema"])("refuses a substituted shared-cache snapshot before adopting its %s state", async (state) => {
  const view = mount(); await ready(); confirm();
  const changed = { ...structuredClone(view.server.job), state: state === "invalid_schema" ? "awaiting_approval" : state, schema_version: state === "invalid_schema" ? "unknown" : "bluefire.job.v1", request: { ...view.server.job.request, receiver_defense: { parent_job_id: "unrelated-owner" } }, result_ref: "unrelated-run", updated_at: "2098-01-01T00:00:00Z" };
  await act(async () => { view.client.setQueryData(["job", view.selected.job_id], changed); });
  await screen.findByText(/saved job response no longer matches/);
  expect(screen.queryByRole("button", { name: "Approve and release job" })).not.toBeInTheDocument();
  expect(api.runDetail).not.toHaveBeenCalledWith("unrelated-run"); expect(view.approve).not.toHaveBeenCalled();
});

it("holds release and later phase preparation after an uncertain cancellation response", async () => {
  const envelope = nativeReceiverFixture(); const view = mount(envelope); await ready(); confirm();
  let reject!: (error: Error) => void;
  view.control.mockReturnValue(new Promise((_, fail) => { reject = fail; }));
  fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
  expect(screen.getByRole("button", { name: "Approve and release job" })).toBeDisabled();
  fireEvent.click(screen.getByRole("button", { name: "Approve and release job" }));
  await act(async () => reject(new Error("Cancellation response unavailable")));
  await screen.findByText("Cancellation response unavailable");
  expect(screen.getByRole("button", { name: "Approve and release job" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Cancel" })).toBeEnabled();
  expect(view.approve).not.toHaveBeenCalled(); expect(view.control).toHaveBeenCalledTimes(1);
  view.rerender(view.ui(receiverFixture("protected", "idle")));
  expect(screen.getByText("Checking receiver shutdown")).toBeVisible();
  fireEvent.change(screen.getByRole("textbox", { name: "Prepared by" }), { target: { value: "Reviewer" } });
  expect(screen.getByRole("button", { name: "Prepare protected receiver" })).toBeDisabled();
});

it("loads only the exact finalized result while leaving the global active run untouched", async () => {
  const view = mount(); await ready(); confirm(); fireEvent.click(screen.getByRole("button", { name: "Approve and release job" }));
  await screen.findByText("Actual retained phase event");
  view.server.job = { ...view.server.job, state: "completed", result_ref: "run-inline-phase", updated_at: "2026-09-07T12:00:03Z" }; view.server.owns = false;
  await act(async () => { await view.client.invalidateQueries({ queryKey: ["job", view.selected.job_id], exact: true }); });
  await waitFor(() => expect(api.runDetail).toHaveBeenCalledExactlyOnceWith("run-inline-phase"));
  await screen.findByRole("button", { name: "Review" });
  expect(product.activeRun).toBeNull(); expect(view.approve).toHaveBeenCalledTimes(1); expect(view.retry).not.toHaveBeenCalled();
});
