import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation, useNavigate } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { ComparePage } from "../src/pages/Compare";
import { DetectionLabPage } from "../src/pages/DetectionLab";
import { api } from "../src/lib/api";
import { registeredDetectionLink } from "../src/lib/run-handoffs";
import { writeComparisonContext } from "../src/lib/comparison-context";
import { compareDemoRuns, demoCatalog, demoRuns, demoScenario } from "../src/lib/demo";
import type { ComparisonResponse, DetectionResource } from "../src/types";

function mount(path: string, page: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}>{page}</MemoryRouter></QueryClientProvider>);
}
function NavigationProbe() {
  const location = useLocation();
  const navigate = useNavigate();
  return <><output aria-label="Comparison route">{location.search}</output><button onClick={() => navigate(-1)}>Back to prior selection</button><button onClick={() => navigate(contextPath(demoRuns.map(run => run.run_id).reverse()))}>Reverse selected run order</button></>;
}
function contextPath(runIds: string[], baselineId = "", revisedId = "") {
  return `/compare?${writeComparisonContext(new URLSearchParams(), { runIds, baselineId, revisedId })}`;
}
function baseMocks() {
  vi.spyOn(api, "runs").mockResolvedValue({ schema_version: "v1", runs: demoRuns, unavailable_run_count: 0 });
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "runDetail").mockImplementation(async (id) => demoRuns.find((run) => run.run_id === id)!);
  vi.spyOn(api, "detections").mockResolvedValue({ schema_version: "v1", candidates: [] });
}
afterEach(() => { vi.restoreAllMocks(); });

it("prepares a full replay with only an AI setup change and preserves the graph", async () => {
  const user = userEvent.setup();
  baseMocks();
  const replay = vi.spyOn(api, "submitReplay").mockImplementation(async (_id, preparation, submissionId) => ({ schema_version: "bluefire.replay-job-submission.v1", preparation, preflight: preparation.preflight, job: { schema_version: "bluefire.job.v1", job_id: `job-${submissionId.replaceAll("-", "")}`, kind: "scenario.replay", state: "completed", progress: {} } }));
  vi.spyOn(api, "prepareReplay").mockImplementation(async (id, request) => ({ schema_version: "bluefire.replay-preparation.v1", preparation_id: "prepared", preparation_context: {}, binding: { source: { run_id: id }, replay_request: request }, replay_request: request, replay_extent: "full", scenario: demoScenario, lineage: {}, preflight: { ready: true, status: "ready" }, approval_created: false, effects_started: false }));
  mount(`/compare?source=${encodeURIComponent(demoRuns[0]!.run_id)}`, <ComparePage />);
  await screen.findByRole("heading", { name: "Compare runs" });
  await user.selectOptions(screen.getByRole("combobox", { name: "What will change?" }), "setup");
  expect(screen.getByRole("button", { name: "Create Simulate replay" })).toBeDisabled();
  await user.selectOptions(screen.getByRole("combobox", { name: "AI autonomy override" }), "assist");
  await user.click(screen.getByRole("button", { name: "Create Simulate replay" }));
  expect(api.prepareReplay).toHaveBeenCalledWith(demoRuns[0]!.run_id, expect.objectContaining({ exact: false, autonomy: "assist", from_step_id: null, swap_step_id: null, swap_behavior_id: null, parameter_overrides: null }));
  await waitFor(() => expect(replay).toHaveBeenCalledOnce());
  expect(replay.mock.calls[0]![1].replay_request).not.toHaveProperty("approval");
});

it.each(["selection", "navigation"])("discards a late comparison after %s changes and never exposes its detector export", async (change) => {
  const user = userEvent.setup();
  baseMocks();
  let finish!: (value: ComparisonResponse) => void;
  const pending = new Promise<ComparisonResponse>((resolve) => { finish = resolve; });
  const compare = vi.spyOn(api, "compare").mockReturnValue(pending);
  mount("/compare", <ComparePage />);
  await screen.findByRole("heading", { name: "Compare runs" });
  const boxes = screen.getAllByRole("checkbox");
  await user.click(boxes[0]!);
  await user.click(boxes[1]!);
  await user.click(screen.getByRole("button", { name: "Compare selected" }));
  expect(compare).toHaveBeenCalledWith([demoRuns[0]!.run_id, demoRuns[1]!.run_id]);
  if (change === "selection") await user.click(boxes[0]!);
  else await user.selectOptions(screen.getByRole("combobox", { name: "Source run" }), demoRuns[1]!.run_id);
  await act(async () => { finish(compareDemoRuns(demoRuns.map((run) => run.run_id))); await pending; });
  await waitFor(() => expect(screen.getByRole("button", { name: "Compare selected" })).toBeDisabled());
  expect(screen.queryByRole("heading", { name: "Compare detector results" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Export comparison and evidence" })).not.toBeInTheDocument();
  expect(screen.getByText(/Select at least two runs/)).toBeInTheDocument();
});

it("reports a comparison whose returned run identities do not match the request", async () => {
  const user = userEvent.setup();
  baseMocks();
  vi.spyOn(api, "compare").mockResolvedValue(compareDemoRuns([demoRuns[1]!.run_id, demoRuns[0]!.run_id]));
  mount("/compare", <ComparePage />);
  await screen.findByRole("heading", { name: "Compare runs" });
  for (const box of screen.getAllByRole("checkbox")) await user.click(box);
  await user.click(screen.getByRole("button", { name: "Compare selected" }));
  expect(await screen.findByText(/returned comparison does not match/)).toBeInTheDocument();
  expect(screen.queryByRole("heading", { name: "Compare detector results" })).not.toBeInTheDocument();
});

it("restores ordered runs and exact detector revisions only after an explicit comparison", async () => {
  const user = userEvent.setup();
  baseMocks();
  const resources: DetectionResource[] = [1, 2].map(revision => ({ kind: "detections", id: `detector-${revision}`, digest: `digest-${revision}`, status: "parsed", created_at: "2026-09-06", updated_at: "2026-09-06", document: { candidate_id: `detector-${revision}`, title: revision === 1 ? "Permission baseline" : "Revised permission rule", revision, revision_root_id: "detector-1", state: "parsed", target_language: "internal" } }));
  vi.mocked(api.detections).mockResolvedValue({ schema_version: "v1", candidates: resources });
  const evaluations = vi.spyOn(api, "detectionRunEvaluations").mockResolvedValue({ evaluations: [] });
  const compare = vi.spyOn(api, "compare").mockImplementation(async ids => compareDemoRuns(ids));
  const evaluate = vi.spyOn(api, "evaluateDetectionRun");
  const prepare = vi.spyOn(api, "prepareReplay");
  const submit = vi.spyOn(api, "submitReplay");
  const ids = [demoRuns[1]!.run_id, demoRuns[0]!.run_id];
  const view = mount(contextPath(ids, "detector-1", "detector-2"), <><NavigationProbe /><ComparePage /></>);
  await screen.findByRole("heading", { name: "Compare runs" });
  expect(compare).not.toHaveBeenCalled();
  expect(evaluations).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Compare selected" }));
  expect(compare).toHaveBeenCalledExactlyOnceWith(ids);
  expect(await screen.findByRole("combobox", { name: "Original detector" })).toHaveValue("detector-1");
  expect(screen.getByRole("combobox", { name: "Revised detector" })).toHaveValue("detector-2");
  expect(screen.getByRole("option", { name: "Permission baseline · revision 1" })).toBeInTheDocument();
  await screen.findByRole("button", { name: "Export comparison and evidence" });
  await user.selectOptions(screen.getByRole("combobox", { name: "Revised detector" }), "");
  expect(screen.getByRole("region", { name: "Comparison results" })).toBeInTheDocument();
  expect(compare).toHaveBeenCalledTimes(1);
  await user.click(screen.getByRole("button", { name: "Back to prior selection" }));
  expect(screen.getByRole("combobox", { name: "Revised detector" })).toHaveValue("detector-2");
  expect(compare).toHaveBeenCalledTimes(1);
  const reloadedPath = `/compare${screen.getByLabelText("Comparison route").textContent}`;
  view.unmount();
  mount(reloadedPath, <ComparePage />);
  await screen.findByRole("heading", { name: "Compare runs" });
  expect(screen.queryByRole("region", { name: "Comparison results" })).not.toBeInTheDocument();
  expect(compare).toHaveBeenCalledTimes(1);
  await user.click(screen.getByRole("button", { name: "Compare selected" }));
  expect(await screen.findByRole("combobox", { name: "Revised detector" })).toHaveValue("detector-2");
  expect(compare.mock.calls.map(call => call[0])).toEqual([ids, ids]);
  expect(evaluate).not.toHaveBeenCalled();
  expect(prepare).not.toHaveBeenCalled();
  expect(submit).not.toHaveBeenCalled();
});

it.each(["missing", "ambiguous"])("retains an unavailable %s run selection until explicit repair", async state => {
  const user = userEvent.setup();
  baseMocks();
  const unavailableId = state === "missing" ? "missing-run" : demoRuns[1]!.run_id;
  if (state === "ambiguous") vi.mocked(api.runs).mockResolvedValue({ schema_version: "v1", runs: [...demoRuns, demoRuns[1]!], unavailable_run_count: 0 });
  const compare = vi.spyOn(api, "compare");
  mount(contextPath([demoRuns[0]!.run_id, unavailableId]), <><NavigationProbe /><ComparePage /></>);
  await screen.findByText("Selected runs unavailable");
  expect(screen.getByRole("button", { name: "Compare selected" })).toBeDisabled();
  expect(screen.getByLabelText("Comparison route")).toHaveTextContent(encodeURIComponent(unavailableId));
  expect(compare).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Remove unavailable selections" }));
  expect(screen.queryByText("Selected runs unavailable")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Compare selected" })).toBeDisabled();
  expect(compare).not.toHaveBeenCalled();
});

it("discards a late result after only the ordered run selection changes", async () => {
  const user = userEvent.setup();
  baseMocks();
  const ids = demoRuns.map(run => run.run_id);
  let finish!: (result: ComparisonResponse) => void;
  const pending = new Promise<ComparisonResponse>(resolve => { finish = resolve; });
  const compare = vi.spyOn(api, "compare").mockReturnValue(pending);
  mount(contextPath(ids), <><NavigationProbe /><ComparePage /></>);
  await screen.findByRole("heading", { name: "Compare runs" });
  await user.click(screen.getByRole("button", { name: "Compare selected" }));
  await user.click(screen.getByRole("button", { name: "Reverse selected run order" }));
  await act(async () => { finish(compareDemoRuns(ids)); await pending; });
  expect(screen.queryByRole("region", { name: "Comparison results" })).not.toBeInTheDocument();
  expect(await screen.findByRole("button", { name: "Compare selected" })).toBeEnabled();
  expect(compare).toHaveBeenCalledTimes(1);
  expect(new URLSearchParams(screen.getByLabelText("Comparison route").textContent!).getAll("compare_run")).toEqual([...ids].reverse());
});

it("keeps malformed context explicit and repairs it without falling back to legacy runs", async () => {
  const user = userEvent.setup();
  baseMocks();
  const compare = vi.spyOn(api, "compare");
  mount(`/compare?source=${demoRuns[0]!.run_id}&replay=${demoRuns[1]!.run_id}&compare_context=2`, <ComparePage />);
  await screen.findByText("Comparison selection unavailable");
  expect(screen.getAllByRole("checkbox").every(box => !(box as HTMLInputElement).checked)).toBe(true);
  await user.click(screen.getByRole("button", { name: "Clear comparison selection" }));
  expect(screen.queryByText("Comparison selection unavailable")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Compare selected" })).toBeDisabled();
  expect(compare).not.toHaveBeenCalled();
});

it.each(["run list", "baseline"])("rejects a restored comparison with a mismatched %s", async field => {
  const user = userEvent.setup();
  baseMocks();
  const ids = demoRuns.map(run => run.run_id);
  const result = compareDemoRuns(ids);
  if (field === "run list") result.run_ids = [...ids].reverse();
  else result.baseline_run_id = ids[1]!;
  vi.spyOn(api, "compare").mockResolvedValue(result);
  mount(contextPath(ids), <ComparePage />);
  await screen.findByRole("heading", { name: "Compare runs" });
  await user.click(screen.getByRole("button", { name: "Compare selected" }));
  expect(await screen.findByText(/returned comparison does not match/)).toBeInTheDocument();
  expect(screen.queryByRole("heading", { name: "Compare detector results" })).not.toBeInTheDocument();
});

it.each(["available", "missing"])("resolves an explicit %s detector link without selecting another definition", async (state) => {
  baseMocks();
  const candidateId = "detection-aaaaaaaaaaaaaaaaaaaa";
  const candidate: DetectionResource = { kind: "detections", id: candidateId, status: "parsed", digest: "sha256:abc", created_at: "2026-09-06", updated_at: "2026-09-06", document: { candidate_id: candidateId, title: "Saved query revision", state: "parsed", target_language: "sqlite", revision: 2, rule_source: "SELECT fixture_id FROM logs" } };
  vi.mocked(api.detections).mockResolvedValue({ schema_version: "v1", candidates: [candidate] });
  vi.spyOn(api, "detectionHealth").mockResolvedValue({ schema_version: "v1", ready: true, persistence_ready: true, candidate_resources: 1, invalid_candidate_resources: 0, languages: { sqlite: { ready: true, authoritative: true, backend: "SQLite", version: "3.45.1" } }, limits: { source_bytes: 32768, fixture_bytes: 1048576, fixtures_per_action: 128, evidence_per_action: 128, notes_per_action: 128 } });
  vi.spyOn(api, "resources").mockResolvedValue({ schema_version: "v1", kind: "research-sources", resources: [] });
  const requested = state === "available" ? candidateId : "detection-bbbbbbbbbbbbbbbbbbbb";
  // The evaluated registry revision and source-run candidate are separate records,
  // even when the source contains the exact ID requested by the comparison link.
  vi.mocked(api.runDetail).mockResolvedValue({ ...demoRuns[0]!, detections: { candidates: [{ candidate_id: requested, title: "Run-linked query", state: "hypothesis", target_language: "sqlite" }] } });
  mount(registeredDetectionLink(demoRuns[0]!.run_id, requested), <DetectionLabPage />);
  if (state === "available") expect(await screen.findByRole("heading", { name: "Saved query revision" })).toBeInTheDocument();
  else {
    expect(await screen.findByText("Detector unavailable")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Saved query revision" })).not.toBeInTheDocument();
  }
  expect(screen.queryByRole("heading", { name: "Run-linked query" })).not.toBeInTheDocument();
});
