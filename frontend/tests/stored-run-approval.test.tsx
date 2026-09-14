import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { storedRunApprovalPreflight } from "../src/lib/approvalReview";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { RunsPage } from "../src/pages/Runs";
import { ProductProvider } from "../src/state/ProductContext";
import type { PreflightReport, RunJob } from "../src/types";

function fixture() {
  const binding = { state_digest: "reviewed-receiver-state", plan_digest: "reviewed-plan", target_scope_digest: "reviewed-scope", profile_id: "sandbox-endpoint-deep-lab.v1", maximum_tier: "controlled" };
  const preflight: PreflightReport = { ready: false, status: "approval_required", approval_binding: binding,
    plan: { mode: "execute", steps: [{ step_id: "handoff" }], edges: [] },
    approval_envelope: { schema_version: "bluefire.approval-envelope.v1", scenario_id: demoScenario.id, envelope_digest: "reviewed-envelope", steps: [{ step_id: "handoff", options: [] }] },
  };
  const job: RunJob = { schema_version: "bluefire.job.v1", job_id: `job-${"a".repeat(32)}`, kind: "scenario.run", state: "awaiting_approval",
    request: { mode: "execute", scenario: demoScenario, approval_request_id: "approval-reviewed", _run_submission_preflight: preflight, receiver_defense: { parent_job_id: "job-owner", receiver_job_id: "job-preparation", phase: "baseline" } },
    progress: { phase: "awaiting_approval" }, approval_request: { ...binding, approval_id: "approval-reviewed", status: "pending", expires_at: "2099-01-01T00:00:00Z" },
  };
  return { job, preflight };
}

it("restores the published receiver review without posting a new public preflight", async () => {
  const { job, preflight } = fixture();
  const fetch = vi.spyOn(globalThis, "fetch");
  const restored = await api.preflightStoredJobRequest(job);
  expect(restored).toEqual(preflight);
  expect(restored).not.toBe(preflight);
  expect(restored.approval_binding?.state_digest).toBe(job.approval_request?.state_digest);
  expect(fetch).not.toHaveBeenCalled();
});

const mutations: Array<[string, (value: ReturnType<typeof fixture>) => void]> = [
  ["missing retained report", ({ job }) => { delete job.request!._run_submission_preflight; }],
  ["different original approval", ({ job }) => { job.request!.approval_request_id = "other"; }],
  ["different progress approval", ({ job }) => { job.progress.approval_request_id = "other"; }],
  ["consumed approval", ({ job }) => { job.approval_request!.status = "consumed"; }],
  ["incomplete plan", ({ preflight }) => { delete preflight.plan; }],
  ["missing alternate envelope", ({ preflight }) => { preflight.approval_envelope = null; }],
  ...(["state_digest", "plan_digest", "target_scope_digest", "profile_id", "maximum_tier"] as const).map((field): [string, (value: ReturnType<typeof fixture>) => void] => [`different ${field}`, ({ job }) => { job.approval_request![field] = "changed"; }]),
];
it.each(mutations)("does not fall back to a newly compiled review after %s", async (_name, mutate) => {
  const value = fixture(); mutate(value);
  const fetch = vi.spyOn(globalThis, "fetch");
  await expect(api.preflightStoredJobRequest(value.job)).rejects.toMatchObject({ code: "job_preflight_unavailable" });
  expect(fetch).not.toHaveBeenCalled();
});

const clients: QueryClient[] = [];
afterEach(() => { for (const client of clients.splice(0)) client.clear(); vi.useRealTimers(); });
function mount(job: RunJob) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity }, mutations: { retry: false } } });
  clients.push(client);
  client.setQueryData(["catalog"], demoCatalog);
  client.setQueryData(["runs"], { runs: [], unavailable_run_count: 0 });
  client.setQueryData(["scenarios"], { scenarios: [] });
  client.setQueryData(["runner-lifecycle"], { state: "unavailable" });
  vi.spyOn(api, "activeJobs").mockResolvedValue({ schema_version: "bluefire.active-job-list.v1", jobs: [job] });
  vi.spyOn(api, "job").mockResolvedValue(job);
  return render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter initialEntries={[`/runs?job=${job.job_id}&view=live`]}><RunsPage /></MemoryRouter></ProductProvider></QueryClientProvider>);
}

it("reopens a native receiver execution with its reviewable approval, unchecked and unreleased", async () => {
  const { job } = fixture();
  const fetch = vi.spyOn(globalThis, "fetch");
  const approve = vi.spyOn(api, "approveJob");
  mount(job);
  const checkbox = await screen.findByRole("checkbox", { name: /I approve this exact immutable job envelope once/ });
  await waitFor(() => expect(checkbox).toBeEnabled());
  expect(api.job).toHaveBeenCalledWith(job.job_id);
  expect(vi.mocked(api.job).mock.calls.every(([requestedId]) => requestedId === job.job_id)).toBe(true);
  expect(checkbox).not.toBeChecked();
  expect(screen.getByRole("textbox", { name: "Operator identity for this job" })).toHaveValue("");
  expect(screen.getByRole("button", { name: "Approve and release job" })).toBeDisabled();
  expect(screen.queryByText("Approval envelope mismatch")).not.toBeInTheDocument();
  expect(fetch.mock.calls.filter(([url]) => String(url).endsWith("/runs/preflight"))).toHaveLength(0);
  expect(approve).not.toHaveBeenCalled();
});

it("keeps the native job cancellable when the retained state does not match approval", async () => {
  const { job } = fixture(); job.approval_request!.state_digest = "different-state";
  mount(job);
  await screen.findByText("Exact approval review unavailable");
  expect(screen.getByRole("checkbox", { name: /I approve this exact immutable job envelope once/ })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Approve and release job" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Cancel" })).toBeEnabled();
});

it.each([undefined, null, "not-a-deadline", "2099", "2000-01-01T00:00:00Z"])("keeps an invalid or expired approval read-only (%s)", async (expiresAt) => {
  const { job, preflight } = fixture(); job.approval_request!.expires_at = expiresAt;
  const approve = vi.spyOn(api, "approveJob");
  const fetch = vi.spyOn(globalThis, "fetch");
  expect(storedRunApprovalPreflight(job)).toBeUndefined();
  await expect(api.preflightStoredJobRequest(job)).rejects.toMatchObject({ code: "job_preflight_unavailable" });
  expect(fetch).not.toHaveBeenCalled();
  expect(storedRunApprovalPreflight(job, { forDisplayOnly: true })).toEqual(preflight);
  await expect(api.preflightStoredJobRequest(job, { forDisplayOnly: true })).resolves.toEqual(preflight);
  expect(fetch).not.toHaveBeenCalled();
  mount(job);
  await screen.findByText(expiresAt === "2000-01-01T00:00:00Z" ? "Approval review expired" : "Approval deadline unavailable");
  expect(screen.getByText(/Cancel it and return to its setup page for a fresh review/)).toBeVisible();
  expect(screen.queryByRole("link", { name: "Open the saved control test" })).not.toBeInTheDocument();
  await waitFor(() => expect(screen.getAllByText("reviewed-plan").length).toBeGreaterThan(0));
  expect(screen.getByRole("checkbox", { name: /I approve this exact immutable job envelope once/ })).toBeDisabled();
  expect(screen.getByRole("textbox", { name: "Operator identity for this job" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Approve and release job" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Cancel" })).toBeEnabled();
  expect(approve).not.toHaveBeenCalled();
});

async function openTimedApproval() {
  const now = new Date("2026-09-07T12:00:00Z");
  vi.useFakeTimers(); vi.setSystemTime(now);
  const { job } = fixture(); job.approval_request!.expires_at = new Date(now.getTime() + 10_000).toISOString();
  const approve = vi.spyOn(api, "approveJob");
  const mounted = mount(job);
  // Each query's notification commits before the next dependent query starts.
  for (let turn = 0; turn < 5; turn += 1) await act(async () => { await vi.advanceTimersByTimeAsync(5); });
  const checkbox = screen.getByRole("checkbox", { name: /I approve this exact immutable job envelope once/ });
  expect(checkbox).toBeEnabled();
  fireEvent.click(checkbox);
  fireEvent.change(screen.getByRole("textbox", { name: "Operator identity for this job" }), { target: { value: "Reviewer" } });
  expect(screen.getByRole("button", { name: "Approve and release job" })).toBeEnabled();
  return { ...mounted, approve, now };
}

it("disables an already-open confirmed approval exactly at its deadline without releasing it", async () => {
  const opened = await openTimedApproval();
  try {
    await act(async () => { await vi.advanceTimersByTimeAsync(9_974); });
    expect(screen.getByRole("button", { name: "Approve and release job" })).toBeEnabled();
    await act(async () => { await vi.advanceTimersByTimeAsync(1); });
    expect(screen.getByText("Approval review expired")).toBeInTheDocument();
    expect(screen.getByRole("checkbox", { name: /I approve this exact immutable job envelope once/ })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Approve and release job" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Cancel" })).toBeEnabled();
    expect(screen.getAllByText("reviewed-plan").length).toBeGreaterThan(0);
    expect(opened.approve).not.toHaveBeenCalled();
  } finally { opened.unmount(); vi.useRealTimers(); }
});

it.each(["focus", "pageshow", "visibilitychange"])("rechecks expiry on foreground %s without waiting for a delayed timer", async (event) => {
  const opened = await openTimedApproval();
  try {
    vi.setSystemTime(opened.now.getTime() + 20_000);
    fireEvent(event === "visibilitychange" ? document : window, new Event(event));
    expect(screen.getByText("Approval review expired")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Approve and release job" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Cancel" })).toBeEnabled();
    expect(opened.approve).not.toHaveBeenCalled();
    vi.setSystemTime(opened.now);
    fireEvent(window, new Event("focus"));
    expect(screen.getByRole("button", { name: "Approve and release job" })).toBeDisabled();
  } finally { opened.unmount(); vi.useRealTimers(); }
});

it("refuses a click after a clock jump even before the deadline timer resumes", async () => {
  const opened = await openTimedApproval();
  try {
    vi.setSystemTime(opened.now.getTime() + 20_000);
    fireEvent.click(screen.getByRole("button", { name: "Approve and release job" }));
    expect(screen.getByText("Approval review expired")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Approve and release job" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Cancel" })).toBeEnabled();
    expect(opened.approve).not.toHaveBeenCalled();
  } finally { opened.unmount(); vi.useRealTimers(); }
});
