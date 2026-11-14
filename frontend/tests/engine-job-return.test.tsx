import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { RunWorkspace } from "../src/components/RunWorkspace";
import { api } from "../src/lib/api";
import { demoCatalog } from "../src/lib/demo";
import { engineExperimentJobLink } from "../src/lib/engine-experiment-api";
import { ProductProvider } from "../src/state/ProductContext";
import type { RunJob } from "../src/types";

const experimentId = `experiment-${"a".repeat(32)}`;
const attemptId = `engine-attempt-${"b".repeat(32)}`;
const checkId = `controller-check-${"c".repeat(32)}`;
const digest = `sha256:${"d".repeat(64)}`;
const clients: QueryClient[] = [];
afterEach(() => { for (const client of clients.splice(0)) client.clear(); });

function job(kind: "engine-attempt" | "engine-controller-check" = "engine-attempt", state: RunJob["state"] = "completed"): RunJob {
  return {
    schema_version: "bluefire.job.v1", job_id: `job-${"e".repeat(32)}`, kind, state,
    request: kind === "engine-attempt" ? {
      schema_version: "bluefire.engine-attempt-job.v1", experiment_id: experimentId, attempt_id: attemptId,
      binding_digest: digest, delegation_digest: digest, execution_approval_digest: digest, execution_approval_id: `approval-${"f".repeat(32)}`,
    } : {
      schema_version: "bluefire.engine-controller-check-job.v1", experiment_id: experimentId, check_id: checkId,
      experiment_revision: 3, experiment_digest: digest, run_id: `run-20261104T120000Z-${"1".repeat(16)}`,
      role: "retained_reproducer", performer: "bluefire.controller", mechanism_ref: digest,
      target_snapshot_ref: digest, input_digest: digest, reserved_at: "2026-11-04T12:00:00Z",
    },
    progress: { experiment_id: experimentId, [kind === "engine-attempt" ? "attempt_id" : "check_id"]: kind === "engine-attempt" ? attemptId : checkId },
    result_ref: state === "running" ? null : `engine-experiment:${experimentId}`,
  };
}

it.each(["engine-attempt", "engine-controller-check"] as const)("links the exact %s request with optional saved submission metadata", kind => {
  const value = job(kind);
  const path = `/composition?engine_experiment=${experimentId}&${kind === "engine-attempt" ? `attempt=${attemptId}` : `check=${checkId}`}`;
  expect(engineExperimentJobLink(value)).toBe(path);
  value.request!._submission = { schema_version: "bluefire.job-submission.v1", submission_id: "12345678-1234-1234-1234-123456789abc", intent_digest: digest };
  expect(engineExperimentJobLink(value)).toBe(path);
});

const invalid: Array<[string, (value: RunJob) => void]> = [
  ["wrong job schema", value => { value.schema_version = "bluefire.job.v2"; }],
  ["wrong kind", value => { value.kind = "scenario.run"; }],
  ["wrong job ID", value => { value.job_id = "job-invalid"; }],
  ["array job ID", value => { Object.assign(value, { job_id: [value.job_id] }); }],
  ["wrong request schema", value => { value.request!.schema_version = "bluefire.engine-controller-check-job.v1"; }],
  ["malformed experiment", value => { value.request!.experiment_id = "experiment-invalid"; }],
  ["malformed attempt", value => { value.request!.attempt_id = "engine-attempt-invalid"; }],
  ["missing metadata", value => { delete value.request!.binding_digest; }],
  ["ambiguous record", value => { value.request!.check_id = checkId; }],
  ["other experiment in progress", value => { value.progress.experiment_id = `experiment-${"f".repeat(32)}`; }],
  ["other attempt in progress", value => { value.progress.attempt_id = `engine-attempt-${"f".repeat(32)}`; }],
  ["check in attempt progress", value => { value.progress.check_id = checkId; }],
  ["other result owner", value => { value.result_ref = `engine-experiment:experiment-${"f".repeat(32)}`; }],
  ["malformed submission", value => { value.request!._submission = { schema_version: "bluefire.job-submission.v1" }; }],
  ["array request", value => { value.request = [] as unknown as Record<string, unknown>; }],
];
it.each(invalid)("refuses %s without inventing a workspace selection", (_label, mutate) => {
  const value = job(); mutate(value);
  expect(engineExperimentJobLink(value)).toBeUndefined();
});

it.each([
  ["wrong performer", { performer: "strix" }], ["wrong role", { role: "baseline" }],
  ["array role", { role: ["retained_reproducer"] }],
  ["malformed check", { check_id: "controller-check-invalid" }], ["missing digest", { input_digest: null }],
  ["invalid revision", { experiment_revision: 0 }], ["invalid timestamp", { reserved_at: "2026-02-31T12:00:00Z" }],
] as const)("refuses controller metadata with %s", (_label, change) => {
  const value = job("engine-controller-check"); Object.assign(value.request!, change);
  expect(engineExperimentJobLink(value)).toBeUndefined();
});

function Destination() { return <output aria-label="Engine destination">{useLocation().search}</output>; }
function mount(value: RunJob) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity }, mutations: { retry: false } } });
  clients.push(client);
  client.setQueryData(["catalog"], demoCatalog);
  client.setQueryData(["runs"], { runs: [], unavailable_run_count: 0 });
  client.setQueryData(["scenarios"], { scenarios: [] });
  vi.spyOn(api, "activeJobs").mockResolvedValue({ schema_version: "bluefire.active-job-list.v1", jobs: value.state === "running" ? [value] : [] });
  vi.spyOn(api, "job").mockResolvedValue(value);
  render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter initialEntries={[`/runs?job=${value.job_id}&view=live`]}><Routes>
    <Route path="/runs" element={<RunWorkspace />} /><Route path="/composition" element={<Destination />} />
  </Routes></MemoryRouter></ProductProvider></QueryClientProvider>);
  return client;
}

it.each([
  ["engine-attempt", "completed"], ["engine-attempt", "failed"], ["engine-attempt", "running"],
  ["engine-controller-check", "completed"], ["engine-controller-check", "interrupted"],
] as const)("returns from a %s %s fallback to its selected engine workspace", async (kind, state) => {
  const value = job(kind, state);
  const readRun = vi.spyOn(api, "runDetail");
  const submit = vi.spyOn(api, "submitRun");
  const client = mount(value);
  const link = await screen.findByRole("link", { name: "Return to engine experiment and evidence" });
  expect(link).toHaveAttribute("href", engineExperimentJobLink(value));
  expect(screen.getByText(kind === "engine-attempt" ? /Review this engine attempt, its evidence and cleanup/ : /Review this trusted controller check, its evidence and cleanup/)).toBeVisible();
  link.focus();
  await client.refetchQueries({ queryKey: ["active-jobs"] });
  expect(link).toHaveFocus();
  await userEvent.setup().keyboard("{Enter}");
  await waitFor(() => expect(screen.getByLabelText("Engine destination")).toHaveTextContent(kind === "engine-attempt" ? `attempt=${attemptId}` : `check=${checkId}`));
  expect(readRun).not.toHaveBeenCalled();
  expect(submit).not.toHaveBeenCalled();
});

it("keeps malformed engine ownership out of the return callout", async () => {
  const value = job(); value.progress.attempt_id = `engine-attempt-${"f".repeat(32)}`;
  mount(value);
  await screen.findByText("Job details");
  expect(screen.queryByRole("link", { name: "Return to engine experiment and evidence" })).not.toBeInTheDocument();
});
