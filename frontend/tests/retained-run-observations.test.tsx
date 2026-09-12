import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { Link, MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { RunsPage } from "../src/pages/Runs";
import { ProductProvider } from "../src/state/ProductContext";
import type { RunJob, RunRecord } from "../src/types";

const firstId = "job-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const secondId = "job-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
function job(jobId = firstId): RunJob {
  return { schema_version: "bluefire.job.v1", job_id: jobId, kind: "scenario.run", state: "failed",
    request: { mode: "execute", scenario: demoScenario }, progress: { run_id: `run-${jobId}` }, result_ref: null,
    error: { code: "execution_callback_failed", message: "execution callback failed" } };
}
function record(value = job()): RunRecord {
  return { run_id: String(value.progress.run_id), mode: "execute", status: "interrupted", steps: [],
    evidence: { records: [{ evidence_id: "evidence-retained", step_id: "collect", provenance: "observed",
      content: { retained_measurement: 8 }, limitations: ["This record does not establish final cleanup."] }] } };
}
function envelope(observations: unknown) {
  return { schema_version: "bluefire.retained-run-observations.v1", run_id: job().progress.run_id,
    record_state: "unsealed", display_only: true, canonical: false, replay_available: false, observations };
}
const clients: QueryClient[] = [];
afterEach(() => { for (const client of clients.splice(0)) client.clear(); });
function mount(first = job()) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity }, mutations: { retry: false } } });
  clients.push(client);
  client.setQueryData(["catalog"], demoCatalog);
  client.setQueryData(["runs"], { runs: [], unavailable_run_count: 0 });
  client.setQueryData(["scenarios"], { scenarios: [] });
  client.setQueryData(["runner-lifecycle"], { state: "unavailable" });
  vi.spyOn(api, "activeJobs").mockResolvedValue({ schema_version: "bluefire.active-job-list.v1", jobs: first.state === "running" ? [first] : [] });
  vi.spyOn(api, "job").mockImplementation(async id => id === firstId ? first : job(secondId));
  vi.spyOn(api, "runEvents").mockImplementation(async id => ({ schema_version: "bluefire.event-page.v1", run_id: id, after_sequence: 0, next_sequence: 0, has_more: false, items: [] }));
  return render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter initialEntries={[`/runs?job=${firstId}&view=live`]}><Link to={`/runs?job=${secondId}&view=live`}>Open other job</Link><RunsPage /></MemoryRouter></ProductProvider></QueryClientProvider>);
}

it("shows retained observations in the failed job without promoting a final result or releasing effects", async () => {
  const detail = vi.spyOn(api, "retainedRunDetail");
  const { mode, ...progress } = record();
  vi.spyOn(globalThis, "fetch").mockImplementation(async () => new Response(JSON.stringify(envelope({ ...progress, plan: { mode } })), { status: 200 }));
  const approve = vi.spyOn(api, "approveJob");
  const submit = vi.spyOn(api, "submitRun");
  const control = vi.spyOn(api, "controlJob");
  mount();
  await screen.findByText("Final result unavailable");
  await waitFor(() => expect(detail).toHaveBeenCalledWith(job().progress.run_id));
  fireEvent.click(screen.getByRole("tab", { name: "Evidence" }));
  expect(await screen.findByLabelText("Evidence content evidence-retained")).toHaveTextContent('"retained_measurement": 8');
  expect(screen.getByText(/does not establish objective completion or verified cleanup/)).toBeVisible();
  expect(screen.getByText("Execute · Job failed · Retained observations")).toBeVisible();
  expect(screen.queryByText(/canonical local record/)).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Review" })).not.toBeInTheDocument();
  expect(screen.queryByRole("link", { name: "Review latest result" })).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Resume" })).toBeDisabled();
  expect(approve).not.toHaveBeenCalled(); expect(submit).not.toHaveBeenCalled(); expect(control).not.toHaveBeenCalled();
});

it("keeps an unsealed completed record subordinate to the failed job outcome", async () => {
  const unsealed = { ...record(), status: "completed", finalized_at: "2030-01-01T00:00:00Z" };
  const fetch = vi.spyOn(globalThis, "fetch").mockImplementation(async () => new Response(JSON.stringify(envelope(unsealed)), { status: 200 }));
  const approve = vi.spyOn(api, "approveJob");
  const submit = vi.spyOn(api, "submitRun");
  mount();
  expect(await screen.findByText("Execute · Job failed · Retained observations")).toBeVisible();
  expect(screen.queryByText(/Completed · canonical local record/)).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Review" })).not.toBeInTheDocument();
  expect(screen.queryByRole("link", { name: "Review latest result" })).not.toBeInTheDocument();
  expect(screen.getByText("Final result unavailable")).toBeVisible();
  fireEvent.click(screen.getByRole("tab", { name: "Evidence" }));
  expect(await screen.findByLabelText("Evidence content evidence-retained")).toHaveTextContent('"retained_measurement": 8');
  expect(approve).not.toHaveBeenCalled(); expect(submit).not.toHaveBeenCalled();
  expect(fetch.mock.calls.map(([url]) => url)).toContain(`/api/v1/runs/${unsealed.run_id}/retained-observations`);
});

it("offers a read-only retry after an unavailable record without claiming that evidence is absent", async () => {
  vi.spyOn(api, "retainedRunDetail").mockRejectedValueOnce(new Error("Record temporarily unavailable")).mockResolvedValue(record());
  mount();
  await screen.findByText("Retained observations unavailable");
  fireEvent.click(screen.getByRole("tab", { name: "Evidence" }));
  expect(screen.queryByText("No evidence records are available.")).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Try again" }));
  fireEvent.click(screen.getByRole("tab", { name: "Evidence" }));
  await screen.findByLabelText("Evidence content evidence-retained");
  expect(screen.queryByText("Retained observations unavailable")).not.toBeInTheDocument();
});

it("refuses a returned record with another run identity", async () => {
  vi.spyOn(api, "retainedRunDetail").mockResolvedValue(record(job(secondId)));
  mount();
  await screen.findByText("The retained record does not match this run.");
  fireEvent.click(screen.getByRole("tab", { name: "Evidence" }));
  expect(screen.queryByLabelText("Evidence content evidence-retained")).not.toBeInTheDocument();
});

it("does not read an in-progress record through the terminal recovery path", async () => {
  const first = job(); first.state = "running"; first.error = null;
  const detail = vi.spyOn(api, "retainedRunDetail");
  mount(first);
  await screen.findByText("Job details");
  expect(detail).not.toHaveBeenCalled();
  expect(screen.queryByText("Final result unavailable")).not.toBeInTheDocument();
});

it("does not attach a late observation response to another selected job", async () => {
  let finish!: (value: RunRecord) => void;
  const pending = new Promise<RunRecord>(resolve => { finish = resolve; });
  const other = record(job(secondId)); other.evidence = { records: [] };
  const detail = vi.spyOn(api, "retainedRunDetail").mockImplementation(id => id === job().progress.run_id ? pending : Promise.resolve(other));
  mount();
  await waitFor(() => expect(detail).toHaveBeenCalledWith(job().progress.run_id));
  fireEvent.click(screen.getByRole("link", { name: "Open other job" }));
  await waitFor(() => expect(detail).toHaveBeenCalledWith(job(secondId).progress.run_id));
  await act(async () => { finish(record()); await pending; });
  fireEvent.click(screen.getByRole("tab", { name: "Evidence" }));
  expect(screen.queryByLabelText("Evidence content evidence-retained")).not.toBeInTheDocument();
});
