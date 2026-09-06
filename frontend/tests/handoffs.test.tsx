import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Link, MemoryRouter, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { demoCatalog, demoRuns, demoScenario } from "../src/lib/demo";
import { comparisonLink, detectionLink, sourceObservedRecords, sourceRunParam } from "../src/lib/run-handoffs";
import { ComparePage } from "../src/pages/Compare";
import { DetectionLabPage } from "../src/pages/DetectionLab";
import { RunsPage } from "../src/pages/Runs";
import { ProductProvider } from "../src/state/ProductContext";
import type { DetectionCandidate, DetectionResource, RunRecord } from "../src/types";

const sourceId = `run-${"1".repeat(32)}`;
const syntheticId = `run-${"2".repeat(32)}`;
const replayId = `run-${"3".repeat(32)}`;
const candidateId = `detection-${"4".repeat(20)}`;
const savedId = `detection-${"5".repeat(20)}`;
const resourceMetadata = { kind: "detection", digest: `sha256:${"b".repeat(64)}`, created_at: "2030-01-01T00:00:00Z", updated_at: "2030-01-01T00:00:00Z" };
const linkedCandidate: DetectionCandidate = {
  candidate_id: candidateId,
  title: "Run staging candidate",
  behavior_id: "sandbox.collection.stage.v1",
  state: "benign_evaluated",
  target_language: "internal",
  selection: { artifact_type: "file_observation", "path|contains": "staged/" },
  logsource: { category: "file_event", product: "generic" },
  provenance: { source: "run-generated" },
  parser_backend: { name: "structured-matcher", version: "1.0" },
  validation: { parsed: true },
  match_count: 2,
  observed_evidence_ids: ["evidence-observed"],
};
const observedRun: RunRecord = {
  ...structuredClone(demoRuns[0]!), run_id: sourceId, is_demo: false, mode: "execute", scenario: demoScenario,
  manifest: { schema_version: "bluefire.run-manifest.v1" },
  detections: { candidates: [linkedCandidate] },
  evidence: { records: [
    { evidence_id: "evidence-executed", run_id: sourceId, provenance: "executed", producer: "runner", content: { completed: true } },
    { evidence_id: "evidence-observed", run_id: sourceId, provenance: "observed", producer: "collector.filesystem.sandbox.v1", content: { artifact_type: "file_observation", path: "staged/records.jsonl", sha256: "a".repeat(64) } },
  ] },
};
const syntheticRun: RunRecord = {
  ...structuredClone(observedRun), run_id: syntheticId, mode: "simulate", detections: { candidates: [] },
  evidence: { records: [{ evidence_id: "evidence-synthetic", run_id: syntheticId, provenance: "synthetic", content: { artifact_type: "file_observation", path: "staged/records.jsonl" } }] },
};

let runs: RunRecord[];
let registry: DetectionResource[];
let replayBarrier: Promise<void> | undefined;

function json(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
}

function summary(run: RunRecord) {
  const result = { ...run };
  // Production history deliberately omits these full-detail documents.
  delete result.evidence; delete result.detections; delete result.manifest; delete result.scenario;
  return result;
}

function LocationProbe() {
  const location = useLocation();
  const navigate = useNavigate();
  return <><output aria-label="Current route">{location.pathname}{location.search}</output><Link to={comparisonLink(sourceId)}>Navigate to alternate source</Link><button onClick={() => navigate(-1)}>Browser back</button></>;
}

function renderJourney(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter initialEntries={[path]}><LocationProbe /><Routes><Route path="/runs/:runId" element={<RunsPage />} /><Route path="/detection-lab" element={<DetectionLabPage />} /><Route path="/compare" element={<ComparePage />} /></Routes></MemoryRouter></ProductProvider></QueryClientProvider>);
}

function postBody(suffix: string) {
  const call = vi.mocked(fetch).mock.calls.find(([url, init]) => String(url).endsWith(suffix) && init?.method === "POST");
  return call ? JSON.parse(String(call[1]?.body)) as Record<string, unknown> : undefined;
}

beforeEach(() => {
  runs = structuredClone([observedRun, syntheticRun]);
  registry = [];
  replayBarrier = undefined;
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path.endsWith("/catalog")) return json(demoCatalog);
    if (path.endsWith("/scenarios")) return json({ scenarios: [demoScenario] });
    if (path.endsWith("/jobs/active")) return json({ jobs: [] });
    if (path.endsWith("/runners/status")) return json({});
    if (path.endsWith("/detection-lab/health")) return json({ ready: true, languages: { internal: { ready: true, authoritative: true, backend: "structured-matcher", version: "1.0" } } });
    if (path.endsWith("/resources/research-sources")) return json({ resources: [] });
    if (path.endsWith("/detections/from-run")) {
      registry.push({ ...resourceMetadata, id: savedId, status: "hypothesis", document: { ...linkedCandidate, candidate_id: savedId, state: "hypothesis", parser_backend: {}, validation: {}, match_count: 0, observed_evidence_ids: [] } });
      return json({ candidate: registry.at(-1), operation: "cloned", source_run_id: sourceId, source_candidate_id: candidateId });
    }
    if (path.endsWith("/detections") && init?.method !== "POST") return json({ candidates: registry });
    if (path.endsWith(`/detections/${savedId}/parse`)) {
      registry = registry.map((resource) => ({ ...resource, status: "parsed", document: { ...resource.document, state: "parsed" } }));
      return json({ candidate: registry.at(-1) });
    }
    if (path.endsWith(`/detections/${savedId}/exercise-observed`)) return json({ candidate: registry.at(-1) });
    if (path.endsWith(`/detections/${savedId}/evaluations`)) return json({ evaluations: [] });
    if (path.endsWith(`/runs/${syntheticId}/replays`)) {
      await replayBarrier;
      const replay = { ...structuredClone(syntheticRun), run_id: replayId, replay: { source_run_id: syntheticId } };
      runs.push(replay);
      return json(replay);
    }
    if (path.endsWith("/comparisons")) return json({ comparison_id: "comparison-test", baseline_run_id: syntheticId, run_ids: [syntheticId, replayId], summaries: [], deltas: [] });
    if (path.endsWith("/runs")) return json({ runs: runs.map(summary) });
    const match = path.match(/\/runs\/([^/?]+)$/);
    if (match) {
      const run = runs.find((item) => item.run_id === decodeURIComponent(match[1]!));
      return run ? json(run) : json({ error: { code: "run_not_found", message: "Source run does not exist." } }, 404);
    }
    throw new Error(`Unexpected handoff test request: ${path}`);
  }));
});

describe("run journey handoffs", () => {
  it.each([
    [{ attempted: true, success: true, outstanding_receipt_count: 0 }, "Complete · no outstanding effects"],
    [{ attempted: true, success: true, outstanding_receipt_count: 2 }, "Needs attention · 2 outstanding effects"],
    [{ attempted: true, success: false, outstanding_receipt_count: 0 }, "Failed · cleanup needs attention"],
    [{ attempted: false }, "Not attempted"],
  ])("shows the actual retained cleanup result %#", async (cleanup, label) => {
    runs[0]!.cleanup = cleanup;
    renderJourney(`/runs/${sourceId}`);
    expect(await screen.findByText(label)).toBeVisible();
  });

  it("opens the reviewed run's full evidence and candidate from summary-only history", async () => {
    const user = userEvent.setup();
    renderJourney(`/runs/${sourceId}`);
    const detection = await screen.findByRole("link", { name: "Open Detection Lab" });
    expect(detection).toHaveAttribute("href", detectionLink(sourceId));
    expect(screen.getByRole("link", { name: "Replay & compare" })).toHaveAttribute("href", comparisonLink(sourceId));
    await user.click(detection);
    expect(await screen.findByRole("heading", { name: linkedCandidate.title })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: /Detection source run/ })).toHaveValue(sourceId);
    expect(screen.getByText("Executed: 1 · Observed: 1")).toBeInTheDocument();
    await user.click(screen.getByText("Inspect source evidence (2)"));
    expect(screen.getByText("evidence-observed", { selector: "strong" })).toBeInTheDocument();
    expect(screen.getByText(/Internal structured matcher results retain internal semantics/)).toBeInTheDocument();
  });

  it("requests server-side source import, then carries the source into observed action", async () => {
    const user = userEvent.setup();
    // Identical candidate IDs in immutable runs and the registry must not hide either record.
    registry = [{ ...resourceMetadata, id: candidateId, status: "hypothesis", document: { ...linkedCandidate, title: "Already registered candidate", state: "hypothesis" } }];
    renderJourney(detectionLink(sourceId, candidateId));
    await user.click(await screen.findByRole("button", { name: "Save hypothesis from run" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Parse / compile honestly" })).toBeEnabled());
    const body = postBody("/detections/from-run")!;
    expect(body).toEqual({ run_id: sourceId, candidate_id: candidateId });
    expect(postBody("/detections")).toBeUndefined();
    expect(body).not.toHaveProperty("state");
    expect(body).not.toHaveProperty("validation");
    expect(body).not.toHaveProperty("match_count");
    expect(body).not.toHaveProperty("observed_evidence_ids");
    expect(registry.at(-1)?.document.target_language).toBe("internal");
    await user.click(screen.getByRole("button", { name: "Parse / compile honestly" }));
    await waitFor(() => expect(postBody(`/detections/${savedId}/parse`)).toEqual({}));
    await user.click(screen.getByRole("tab", { name: "Observed" }));
    expect(screen.getByRole("combobox", { name: "Finalized run" })).toHaveValue(sourceId);
    await waitFor(() => expect(screen.getByRole("button", { name: "Exercise observed evidence" })).toBeEnabled());
    await user.type(screen.getByRole("textbox", { name: /Evidence IDs/ }), "evidence-observed");
    await user.click(screen.getByRole("button", { name: "Exercise observed evidence" }));
    await waitFor(() => expect(postBody(`/detections/${savedId}/exercise-observed`)).toEqual({ run_id: sourceId, evidence_ids: ["evidence-observed"] }));
  });

  it("keeps synthetic source records unavailable for observed exercise", async () => {
    registry = [{ ...resourceMetadata, id: savedId, status: "parsed", document: { ...linkedCandidate, candidate_id: savedId, state: "parsed" } }];
    const user = userEvent.setup();
    renderJourney(detectionLink(syntheticId));
    expect(await screen.findByText("Observed exercise unavailable")).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "Observed" }));
    expect(await screen.findByText("No eligible observed evidence")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Exercise observed evidence" })).toBeDisabled();
    expect(postBody(`/detections/${savedId}/exercise-observed`)).toBeUndefined();
  });

  it("shows a missing source failure without substituting summary candidates", async () => {
    renderJourney(detectionLink("run-missing"));
    expect(await screen.findByText("Source run unavailable")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Save hypothesis from run" })).not.toBeInTheDocument();
    expect(postBody("/detections")).toBeUndefined();
  });

  it("uses an explicitly synthetic example matching the actual internal selection fields", async () => {
    const selection = { artifact_type: "collector_observation", observation_kind: "filesystem" };
    registry = [{ ...resourceMetadata, id: savedId, status: "parsed", document: { ...linkedCandidate, title: "Registered fixture candidate", candidate_id: savedId, state: "parsed", selection } }];
    const user = userEvent.setup();
    renderJourney(detectionLink(sourceId));
    await user.click(await screen.findByRole("button", { name: /Registered fixture candidate/ }));
    await user.click(await screen.findByRole("tab", { name: "Fixtures" }));
    expect(JSON.parse(String((screen.getByRole("textbox", { name: /^Malicious fixtures JSON/ }) as HTMLTextAreaElement).value))).toEqual([{ fixture_id: "synthetic-selection-example", ...selection }]);
    expect(screen.getByText(/positive example is generated from this internal selection/)).toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: /^Benign fixtures JSON/ })).toHaveValue("");
    expect(screen.getByRole("textbox", { name: "Benign evaluation notes" })).toHaveValue("");
  });

  it("requires explicit query fixtures and offers full observed evaluation without them", async () => {
    registry = [{ ...resourceMetadata, id: savedId, status: "parsed", document: { ...linkedCandidate, title: "Registered query candidate", candidate_id: savedId, state: "parsed", target_language: "sqlite" } }];
    const user = userEvent.setup();
    renderJourney(detectionLink(sourceId));
    await user.click(await screen.findByRole("button", { name: /Registered query candidate/ }));
    await user.click(await screen.findByRole("tab", { name: "Fixtures" }));
    expect(screen.getByRole("textbox", { name: /^Malicious fixtures JSON/ })).toHaveValue("");
    expect(screen.getByRole("button", { name: "Exercise malicious fixtures" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Evaluate observed runs without fixtures" }));
    expect(screen.getByRole("combobox", { name: "Evaluation source run" })).toHaveValue(sourceId);
    expect(screen.getByRole("button", { name: "Evaluate full observed run" })).toBeEnabled();
    expect(postBody(`/detections/${savedId}/exercise-fixtures`)).toBeUndefined();
  });

  it("preselects the URL source and selects baseline plus new replay for comparison", async () => {
    const user = userEvent.setup();
    renderJourney(comparisonLink(syntheticId));
    await waitFor(() => expect(screen.getByRole("combobox", { name: "Source run" })).toHaveValue(syntheticId));
    const replayButton = screen.getByRole("button", { name: "Create Simulate replay" });
    await waitFor(() => expect(replayButton).toBeEnabled());
    expect(screen.getByRole("button", { name: "Compare selected" })).toBeDisabled();
    await user.click(replayButton);
    await waitFor(() => expect(screen.getByLabelText("Current route")).toHaveTextContent(comparisonLink(syntheticId, replayId)));
    expect(screen.getByText("2 selected")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Compare selected" }));
    await waitFor(() => expect(postBody("/comparisons")).toEqual({ run_ids: [syntheticId, replayId] }));
    expect(postBody(`/runs/${syntheticId}/replays`)).not.toHaveProperty("approval");
  });

  it("does not inherit Execute approval from source URL parameters", async () => {
    renderJourney(`${comparisonLink(sourceId)}&approved=true&approved_by=old-operator`);
    const replayButton = await screen.findByRole("button", { name: "Create approved Execute replay" });
    expect(replayButton).toBeDisabled();
    expect(screen.getByRole("checkbox", { name: /I approve this reviewed Execute replay/ })).not.toBeChecked();
    expect(screen.getByRole("textbox", { name: "Fresh replay operator identity" })).toHaveValue("");
    expect(postBody(`/runs/${sourceId}/replays`)).toBeUndefined();
  });

  it("keeps a late replay completion from overwriting navigation to another source", async () => {
    let finishReplay!: () => void;
    replayBarrier = new Promise<void>((resolve) => { finishReplay = resolve; });
    const user = userEvent.setup();
    renderJourney(comparisonLink(syntheticId));
    await waitFor(() => expect(screen.getByRole("button", { name: "Create Simulate replay" })).toBeEnabled());
    await user.click(screen.getByRole("button", { name: "Create Simulate replay" }));
    expect(screen.getByRole("combobox", { name: "Source run" })).toBeDisabled();
    await user.click(screen.getByRole("link", { name: "Navigate to alternate source" }));
    await waitFor(() => expect(screen.getByRole("combobox", { name: "Source run" })).toHaveValue(sourceId));
    await act(async () => { finishReplay(); });
    expect(await screen.findByText("Replay created")).toBeInTheDocument();
    expect(screen.getByLabelText("Current route")).toHaveTextContent(comparisonLink(sourceId));
    expect(screen.getByRole("combobox", { name: "Source run" })).toHaveValue(sourceId);
    expect(screen.getByText("1 selected")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Compare selected" })).toBeDisabled();
  });

  it("resets source-specific replay inputs on URL navigation and browser back", async () => {
    const user = userEvent.setup();
    renderJourney(comparisonLink(syntheticId));
    await waitFor(() => expect(screen.getByRole("button", { name: "Create Simulate replay" })).toBeEnabled());
    await user.click(screen.getByRole("radio", { name: /From node/ }));
    await user.selectOptions(screen.getByRole("combobox", { name: "Restart node" }), syntheticRun.steps[0]!.step_id);
    await user.selectOptions(screen.getByRole("combobox", { name: "AI autonomy override" }), "assist");
    await user.type(screen.getByRole("textbox", { name: /Declared defense change/ }), "Prior source note");
    await user.click(screen.getByRole("link", { name: "Navigate to alternate source" }));
    await waitFor(() => expect(screen.getByRole("combobox", { name: "Source run" })).toHaveValue(sourceId));
    expect(screen.getByRole("radio", { name: /Exact/ })).toBeChecked();
    expect(screen.getByRole("combobox", { name: "Restart node" })).toHaveValue("");
    expect(screen.getByRole("combobox", { name: "AI autonomy override" })).toHaveValue("preserve");
    expect(screen.getByRole("textbox", { name: /Declared defense change/ })).toHaveValue("");
    await user.click(screen.getByRole("button", { name: "Browser back" }));
    await waitFor(() => expect(screen.getByRole("combobox", { name: "Source run" })).toHaveValue(syntheticId));
    expect(screen.getByRole("radio", { name: /Exact/ })).toBeChecked();
    expect(screen.getByRole("combobox", { name: "Restart node" })).toHaveValue("");
  });
});

describe("handoff evidence boundaries", () => {
  it("retains encoded source identity while treating malformed URL values as absent", () => {
    const id = "run:a/b?c&d";
    expect(sourceRunParam(new URL(comparisonLink(id), "http://localhost").searchParams, "source")).toBe(id);
    expect(sourceRunParam(new URLSearchParams({ run: "a\nb" }), "run")).toBe("");
    expect(sourceRunParam(new URLSearchParams({ run: "a".repeat(201) }), "run")).toBe("");
  });

  it("does not label absent, synthetic, cross-run, or demo evidence as observed", () => {
    expect(sourceObservedRecords(observedRun).map((record) => record.evidence_id)).toEqual(["evidence-observed"]);
    expect(sourceObservedRecords({ ...observedRun, manifest: undefined })).toEqual([]);
    expect(sourceObservedRecords(syntheticRun)).toEqual([]);
    expect(sourceObservedRecords({ ...observedRun, run_id: "different-run" })).toEqual([]);
    expect(sourceObservedRecords({ ...observedRun, is_demo: true })).toEqual([]);
  });
});
