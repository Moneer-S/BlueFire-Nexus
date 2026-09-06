import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Link, MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { ApiError, api, type ReplayPreparation } from "../src/lib/api";
import { demoBehaviors, demoCatalog, demoRuns, demoScenario } from "../src/lib/demo";
import { ComparePage } from "../src/pages/Compare";

const behavior = { ...demoBehaviors[0]!, title: "Collect reviewed records", parameters: [{ name: "record_count", type: "integer" as const, minimum: 1, maximum: 9 }] };
const scenario = { ...demoScenario, start: "collect", edges: [], steps: [{ id: "collect", behavior_id: behavior.id, parameters: { record_count: 3 }, inputs: {}, alternates: [] }] };
const source = { ...demoRuns[0]!, mode: "execute" as const, scenario, target_scope: { scope_refs: ["sandbox.workspace"] } };
function prepared(request: Record<string, unknown>): ReplayPreparation {
  return {
    schema_version: "bluefire.replay-preparation.v1", preparation_id: "replay-preparation-reviewed",
    preparation_context: { schema_version: "bluefire.replay-preparation-context.v1", runner_readiness: { reviewed: true } },
    binding: { source: { run_id: source.run_id }, replay_request: structuredClone(request) },
    replay_request: structuredClone(request), replay_extent: "full", scenario, lineage: { source_run_id: source.run_id },
    approval_created: false, effects_started: false,
    preflight: { ready: false, status: "approval_required", scope: source.target_scope, plan: { steps: [], edges: [], mode: "execute" },
      approval_binding: { state_digest: "state-reviewed", plan_digest: "plan-reviewed", target_scope_digest: "scope-reviewed", profile_id: "reviewed-lab", maximum_tier: "controlled" },
      approval_envelope: { schema_version: "bluefire.approval-envelope.v1", envelope_digest: "envelope-reviewed", scenario_id: scenario.id, steps: [] },
    },
  };
}
function Location() { const location = useLocation(); return <output aria-label="Current route">{location.pathname}{location.search}</output>; }
function mount() {
  vi.spyOn(api, "runs").mockResolvedValue({ schema_version: "v1", runs: [source], unavailable_run_count: 0 });
  vi.spyOn(api, "catalog").mockResolvedValue({ ...demoCatalog, behaviors: [behavior] });
  vi.spyOn(api, "runDetail").mockResolvedValue(source);
  vi.spyOn(api, "preflight").mockRejectedValue(new Error("Full replay must use the exact preparation endpoint"));
  const replay = vi.spyOn(api, "replay").mockResolvedValue({ ...source, run_id: "run-20300101T000000Z-bbbbbbbbbbbbbbbb" });
  vi.spyOn(api, "submitReplay").mockImplementation(async (_id, preparation, submissionId) => ({
    schema_version: "bluefire.replay-job-submission.v1", preparation, preflight: preparation.preflight,
    job: { schema_version: "bluefire.job.v1", job_id: `job-${submissionId.replaceAll("-", "")}`, kind: "scenario.replay", state: "awaiting_approval", progress: {}, request: { source_run_id: source.run_id, replay_preparation: preparation } },
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/compare?source=${source.run_id}`]}><Location /><Link to="/builder">Leave comparison</Link><Routes><Route path="/compare" element={<ComparePage />} /><Route path="/builder" element={<h1>Experiment builder</h1>} /><Route path="/runs" element={<h1>Saved job status</h1>} /></Routes></MemoryRouter></QueryClientProvider>);
  return replay;
}
afterEach(() => vi.restoreAllMocks());

it("submits the exact preparation as a durable job without approving it and opens its saved status", async () => {
  const user = userEvent.setup();
  const prepare = vi.spyOn(api, "prepareReplay").mockImplementation(async (_id, request) => prepared(request));
  const replay = mount();
  await user.click(await screen.findByRole("button", { name: "Review Execute replay" }));
  await screen.findByRole("region", { name: "Prepared Execute replay" });
  expect(api.preflight).not.toHaveBeenCalled();
  expect(replay).not.toHaveBeenCalled();
  expect(screen.queryByRole("checkbox", { name: /I approve/ })).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Continue to approval" }));
  const request = prepare.mock.calls[0]![1];
  expect(api.submitReplay).toHaveBeenCalledWith(source.run_id, prepared(request), expect.any(String));
  const submissionId = vi.mocked(api.submitReplay).mock.calls[0]![2];
  await waitFor(() => expect(screen.getByLabelText("Current route")).toHaveTextContent(`/runs?job=job-${submissionId.replaceAll("-", "")}`));
  expect(replay).not.toHaveBeenCalled();
});

it.each(["source", "request"])("refuses a prepared response with a mismatched %s", async (change) => {
  const user = userEvent.setup();
  vi.spyOn(api, "prepareReplay").mockImplementation(async (_id, request) => {
    const result = prepared(request);
    if (change === "source") result.binding.source.run_id = "different-run";
    else result.replay_request = { exact: false };
    return result;
  });
  const replay = mount();
  await user.click(await screen.findByRole("button", { name: "Review Execute replay" }));
  expect(await screen.findByText(/returned review does not match/)).toBeVisible();
  expect(screen.getByRole("button", { name: "Continue to approval" })).toBeDisabled();
  expect(replay).not.toHaveBeenCalled();
});

it("invalidates a pending review when a numeric draft is unfinished, without sending the previous valid value", async () => {
  const user = userEvent.setup();
  let resolve!: (value: ReplayPreparation) => void;
  const pending = new Promise<ReplayPreparation>((done) => { resolve = done; });
  const prepare = vi.spyOn(api, "prepareReplay").mockReturnValue(pending);
  const replay = mount();
  await user.selectOptions(await screen.findByRole("combobox", { name: "What will change?" }), "parameters");
  await user.click(screen.getByRole("button", { name: "Change Record count" }));
  const input = screen.getByRole("spinbutton", { name: "Record count" });
  fireEvent.change(input, { target: { value: "7" } });
  await user.click(screen.getByRole("button", { name: "Review Execute replay" }));
  expect(prepare.mock.calls[0]![1]).toHaveProperty("parameter_overrides", { collect: { record_count: 7 } });
  fireEvent.change(input, { target: { value: "" } });
  await act(async () => { resolve(prepared(prepare.mock.calls[0]![1])); await pending; });
  await waitFor(() => expect(screen.getByRole("button", { name: "Review Execute replay" })).toBeDisabled());
  expect(screen.queryByRole("region", { name: "Prepared Execute replay" })).not.toBeInTheDocument();
  expect(screen.queryByRole("checkbox", { name: /I approve this reviewed Execute replay/ })).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Continue to approval" })).toBeDisabled();
  expect(replay).not.toHaveBeenCalled();
  expect(input).toHaveValue(null);
});


it.each([new Error("Connection closed before the response"), new ApiError("Response failed after publication", "replay_job_refused", undefined, 409), new ApiError("Session unavailable on retry", "browser_session_unavailable", undefined, 403), new ApiError("Queue unavailable on retry", "job_capacity_exhausted", undefined, 503)])("retries an unconfirmed publication with the same job identity and frozen prepared request: %s", async (error) => {
  const user = userEvent.setup();
  vi.spyOn(api, "prepareReplay").mockImplementation(async (_id, request) => prepared(request));
  mount();
  vi.mocked(api.submitReplay).mockRejectedValueOnce(error);
  await user.click(await screen.findByRole("button", { name: "Review Execute replay" }));
  await user.click(await screen.findByRole("button", { name: "Continue to approval" }));
  await screen.findByText("Check this submission before starting another replay");
  expect(screen.getByRole("combobox", { name: "What will change?" })).toBeDisabled();
  const first = vi.mocked(api.submitReplay).mock.calls[0]!;
  await user.click(screen.getByRole("button", { name: "Retry same submission" }));
  await waitFor(() => expect(api.submitReplay).toHaveBeenCalledTimes(2));
  expect(vi.mocked(api.submitReplay).mock.calls[1]).toEqual(first);
  expect(api.prepareReplay).toHaveBeenCalledOnce();
});


it("restores an uncertain submission after a reload and retries without preparing or approving again", async () => {
  const user = userEvent.setup();
  vi.spyOn(api, "prepareReplay").mockImplementation(async (_id, request) => prepared(request));
  mount();
  vi.mocked(api.submitReplay).mockRejectedValueOnce(new Error("Response lost"));
  await user.click(await screen.findByRole("button", { name: "Review Execute replay" }));
  await user.click(await screen.findByRole("button", { name: "Continue to approval" }));
  await screen.findByText("Check this submission before starting another replay");
  const first = structuredClone(vi.mocked(api.submitReplay).mock.calls[0]!);
  cleanup();
  vi.clearAllMocks();
  mount();
  await screen.findByText("Check this submission before starting another replay");
  expect(screen.queryByRole("checkbox", { name: /I approve/ })).not.toBeInTheDocument();
  expect(api.prepareReplay).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Retry same submission" }));
  await waitFor(() => expect(api.submitReplay).toHaveBeenCalledOnce());
  expect(vi.mocked(api.submitReplay).mock.calls[0]).toEqual(first);
  expect(api.prepareReplay).not.toHaveBeenCalled();
  await screen.findByRole("heading", { name: "Saved job status" });
  expect(sessionStorage.getItem("bluefire.replay.pending-submission.v1")).toBeNull();
});

it("does not take over navigation when a submission finishes after leaving Compare", async () => {
  const user = userEvent.setup();
  vi.spyOn(api, "prepareReplay").mockImplementation(async (_id, request) => prepared(request));
  mount();
  let resolve!: (value: Awaited<ReturnType<typeof api.submitReplay>>) => void;
  vi.mocked(api.submitReplay).mockImplementation(() => new Promise((done) => { resolve = done; }));
  await user.click(await screen.findByRole("button", { name: "Review Execute replay" }));
  await user.click(await screen.findByRole("button", { name: "Continue to approval" }));
  await waitFor(() => expect(api.submitReplay).toHaveBeenCalledOnce());
  const [, preparation, submissionId] = vi.mocked(api.submitReplay).mock.calls[0]!;
  await user.click(screen.getByRole("link", { name: "Leave comparison" }));
  await screen.findByRole("heading", { name: "Experiment builder" });
  await act(async () => { resolve({ schema_version: "bluefire.replay-job-submission.v1", preparation, preflight: preparation.preflight, job: { schema_version: "bluefire.job.v1", job_id: `job-${submissionId.replaceAll("-", "")}`, kind: "scenario.replay", state: "awaiting_approval", request: {}, progress: {} } }); });
  expect(screen.getByLabelText("Current route")).toHaveTextContent("/builder");
  expect(screen.getByRole("heading", { name: "Experiment builder" })).toBeVisible();
});
