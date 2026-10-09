import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { createHash, webcrypto } from "node:crypto";
import { afterEach, expect, it, vi } from "vitest";
import { DetectionEvaluationQueue } from "../src/components/DetectionEvaluationQueue";
import { api } from "../src/lib/api";
import type { DetectionResource, DetectionRunEvaluation, RunRecord } from "../src/types";

const digest = `sha256:${"b".repeat(64)}`;
const runIds = ["attack-run", "benign-run", "heldout-run"];
const baselineId = "original-rule";
const revisedId = "revised-rule";

function resource(id: string, revision: number): DetectionResource {
  return {
    kind: "detections", id, status: "parsed", digest, created_at: "2026-09-06T12:00:00Z", updated_at: "2026-09-06T12:00:00Z",
    document: {
      candidate_id: id, title: "Collection detector", state: "parsed", revision, revision_root_id: "rule-family",
      definition_digest: digest, target_language: "sqlite", rule_source: "SELECT fixture_id FROM logs",
      parser_backend: { name: "SQLite", version: "3.45.1" }, validation: { query_sha256: digest, source_sha256: digest },
    },
  };
}

const resources = [resource(baselineId, 1), resource(revisedId, 2)];

function source(runId: string): RunRecord {
  const scenarioTitles: Record<string, string> = {
    "attack-run": "Attack evidence case", "benign-run": "Benign evidence case", "heldout-run": "Held-out evidence case",
  };
  return {
    run_id: runId, scenario_title: scenarioTitles[runId] ?? "Additional evidence case", mode: "execute", status: "completed", created_at: "2026-09-06T12:00:00Z",
    finalized_at: "2026-09-06T12:01:00Z", steps: [], manifest: {
      schema_version: "1.0", run_id: runId, bundle_hash: digest,
      files: { "evidence.json": { hash: digest, size_bytes: 123 } },
    },
  };
}

function manifestDigest(runId: string): string {
  const identity = JSON.stringify({ bundle_hash: digest, files: { "evidence.json": { hash: digest, size_bytes: 123 } }, run_id: runId, schema_version: "1.0" });
  return `sha256:${createHash("sha256").update(identity, "utf8").digest("hex")}`;
}

function report(runId: string, overrides: Partial<DetectionRunEvaluation> = {}, candidateId = revisedId): DetectionRunEvaluation {
  const activity = overrides.classification?.activity_label
    ?? (overrides.case_role === "attack" || overrides.case_role === "benign" ? overrides.case_role : "unknown");
  const evaluationUse = overrides.classification?.evaluation_use ?? "unspecified";
  const question = overrides.question ?? "";
  return {
    schema_version: "bluefire.detection-run-evaluation.v1", evaluation_id: `evaluation-${runId}`, question, case_role: activity,
    case_role_basis: "operator_declared", created_at: "2026-09-06T12:02:00Z", limitations: [],
    candidate: {
      candidate_id: candidateId, revision_root_id: "rule-family", revision: candidateId === baselineId ? 1 : 2, definition_digest: digest,
      query_sha256: digest, source_sha256: digest, target_language: "sqlite", parser_backend: { name: "SQLite", version: "3.45.1" },
    },
    source: { run_id: runId, manifest_digest: manifestDigest(runId), evidence_digest: digest, observed_count: 1, evidence_count: 1, excluded_provenance_counts: {} },
    result: { state: "not_matched", match_count: 0, evaluated_evidence_ids: [], matched_evidence_ids: [], gap_count: 0, gap_evidence_ids: [], mapped_fields: [], available_fields: [], unsupported_fields: [], missing_fields: [], diagnostic_codes: [] },
    backend: { name: "SQLite", executed: true, version: "3.45.1" },
    classification: {
      activity_label: activity, activity_basis: "operator_declared", source_lineage: "unknown", lineage_basis: "unavailable",
      replay_source_run_id: null, evaluation_use: evaluationUse, requested_use: evaluationUse, use_basis: "operator_declared",
      development_reasons: [], development_history_complete: true, independence_verified: false,
    },
    ...overrides,
  };
}

function queueTree(
  client: QueryClient,
  props: Partial<Parameters<typeof DetectionEvaluationQueue>[0]> = {},
) {
  const defaults = { runIds, baselineId, revisedId, resources, baselineReports: [], revisedReports: [], ready: true };
  return (
    <QueryClientProvider client={client}>
      <MemoryRouter><DetectionEvaluationQueue {...defaults} {...props} /></MemoryRouter>
    </QueryClientProvider>
  );
}

function renderWithClient(
  client: QueryClient,
  props: Partial<Parameters<typeof DetectionEvaluationQueue>[0]> = {},
) {
  return render(queueTree(client, props));
}

function mount(props: Partial<Parameters<typeof DetectionEvaluationQueue>[0]> = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return { client, ...renderWithClient(client, props) };
}

function mockReads(reports: DetectionRunEvaluation[] = []) {
  vi.stubGlobal("crypto", webcrypto);
  vi.spyOn(api, "detections").mockResolvedValue({ schema_version: "v1", candidates: resources });
  vi.spyOn(api, "detectionRunEvaluations").mockResolvedValue({ evaluations: reports });
  vi.spyOn(api, "runDetail").mockImplementation(async id => source(id));
}

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

it("previews two missing cases in comparison order and sends no request before explicit start", async () => {
  const user = userEvent.setup();
  const retained = [report("benign-run", { result: { ...report("benign-run").result, state: "insufficient_evidence", match_count: null } })];
  mockReads(retained);
  const evaluate = vi.spyOn(api, "evaluateDetectionRun").mockResolvedValue({ evaluation: report("attack-run") });
  mount({ revisedReports: retained });
  expect(evaluate).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Review missing revised evaluations" }));
  const preview = await screen.findByRole("list", { name: "" }).catch(() => screen.getByRole("list"));
  expect(within(preview).getAllByRole("listitem").map(item => item.textContent)).toEqual([
    expect.stringContaining("Attack evidence case"), expect.stringContaining("Held-out evidence case"),
  ]);
  expect(screen.getAllByRole("combobox", { name: "Activity label" }).map(select => (select as HTMLSelectElement).value)).toEqual(["unknown", "unknown"]);
  expect(screen.getAllByRole("combobox", { name: "Use of this data" }).map(select => (select as HTMLSelectElement).value)).toEqual(["unspecified", "unspecified"]);
  expect(evaluate).not.toHaveBeenCalled();
});

it("queues only missing original-rule cases and binds history, POST, and response identity to the original revision", async () => {
  const user = userEvent.setup();
  const retained = [
    report("benign-run", { result: { ...report("benign-run").result, state: "insufficient_evidence", match_count: null } }, baselineId),
    report("heldout-run", { result: { ...report("heldout-run").result, state: "backend_error", match_count: null } }, baselineId),
  ];
  mockReads();
  vi.mocked(api.detectionRunEvaluations).mockImplementation(async id => ({ evaluations: id === baselineId ? retained : [] }));
  const response = report("attack-run", {}, baselineId);
  response.question = "Does the original rule identify the observed attack?";
  response.case_role = "attack";
  response.classification = { ...response.classification!, activity_label: "attack", evaluation_use: "development", requested_use: "development" };
  const evaluate = vi.spyOn(api, "evaluateDetectionRun").mockResolvedValue({ evaluation: response });
  mount({ runIds, baselineReports: retained, revisedReports: [] });
  await user.selectOptions(screen.getByRole("combobox", { name: "Evaluate missing results for" }), "original");
  await user.click(screen.getByRole("button", { name: "Review missing original evaluations" }));
  const start = await screen.findByRole("button", { name: "Start evaluations" });
  const cases = screen.getByRole("list");
  expect(within(cases).getAllByRole("listitem")).toHaveLength(1);
  expect(within(cases).getByRole("group", { name: "Case 1 · Attack evidence case" })).toBeVisible();
  await user.type(screen.getByRole("textbox", { name: /^Experiment question/ }), response.question);
  await user.selectOptions(screen.getByRole("combobox", { name: "Activity label" }), "attack");
  await user.selectOptions(screen.getByRole("combobox", { name: "Use of this data" }), "development");
  expect(evaluate).not.toHaveBeenCalled();
  await user.click(start);
  await waitFor(() => expect(evaluate).toHaveBeenCalledOnce());
  expect(api.detectionRunEvaluations).toHaveBeenCalledWith(baselineId);
  expect(evaluate).toHaveBeenCalledWith(baselineId, {
    run_id: "attack-run", question: response.question, case_role: "attack", activity_label: "attack", evaluation_use: "development",
  });
  expect(await screen.findByText(/Evaluation retained: No matches/)).toBeInTheDocument();
});

it("refuses a revised-rule response when the frozen target is the original rule", async () => {
  const user = userEvent.setup();
  mockReads();
  const evaluate = vi.spyOn(api, "evaluateDetectionRun").mockResolvedValue({ evaluation: report("attack-run") });
  mount({ runIds: ["attack-run", "heldout-run"], baselineReports: [], revisedReports: [] });
  await user.selectOptions(screen.getByRole("combobox", { name: "Evaluate missing results for" }), "original");
  await user.click(screen.getByRole("button", { name: "Review missing original evaluations" }));
  await user.click(await screen.findByRole("button", { name: "Start evaluations" }));
  expect(await screen.findByText(/Submitted outcome unconfirmed/)).toBeInTheDocument();
  expect(evaluate).toHaveBeenCalledOnce();
  expect(evaluate).toHaveBeenCalledWith(baselineId, expect.objectContaining({ run_id: "attack-run" }));
  expect(screen.queryByText(/Evaluation retained/)).not.toBeInTheDocument();
});

it("invalidates A-to-B-to-A previews and resets case inputs on a fresh review", async () => {
  const user = userEvent.setup();
  mockReads();
  const evaluate = vi.spyOn(api, "evaluateDetectionRun");
  mount({ runIds: ["attack-run", "heldout-run"], baselineReports: [], revisedReports: [] });
  await user.click(screen.getByRole("button", { name: "Review missing revised evaluations" }));
  await screen.findByRole("button", { name: "Start evaluations" });
  const cases = screen.getAllByRole("listitem");
  const firstCase = within(cases[0]!);
  const question = firstCase.getByRole("textbox", { name: /^Experiment question/ });
  await user.type(question, "Do not carry this question across revisions");
  await user.selectOptions(firstCase.getByRole("combobox", { name: "Activity label" }), "benign");
  await user.selectOptions(firstCase.getByRole("combobox", { name: "Use of this data" }), "development");
  const side = screen.getByRole("combobox", { name: "Evaluate missing results for" });
  await user.selectOptions(side, "original");
  await user.selectOptions(side, "revised");
  expect(await screen.findByText(/evaluation side changed/)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Start evaluations" })).toBeDisabled();
  await user.click(screen.getByRole("button", { name: "Review missing revised evaluations" }));
  await waitFor(() => expect(screen.getAllByRole("textbox", { name: /^Experiment question/ }).map(input => (input as HTMLTextAreaElement).value)).toEqual(["", ""]));
  expect(screen.getAllByRole("combobox", { name: "Activity label" }).map(select => (select as HTMLSelectElement).value)).toEqual(["unknown", "unknown"]);
  expect(screen.getAllByRole("combobox", { name: "Use of this data" }).map(select => (select as HTMLSelectElement).value)).toEqual(["unspecified", "unspecified"]);
  expect(screen.getByRole("button", { name: "Start evaluations" })).toBeEnabled();
  expect(evaluate).not.toHaveBeenCalled();
});

it("sends explicit per-case choices sequentially and keeps the pending lock against double click", async () => {
  const user = userEvent.setup();
  const retained = [report("benign-run")];
  mockReads(retained);
  let resolveFirst!: (value: { evaluation: DetectionRunEvaluation }) => void;
  const first = new Promise<{ evaluation: DetectionRunEvaluation }>(resolve => { resolveFirst = resolve; });
  const evaluate = vi.spyOn(api, "evaluateDetectionRun")
    .mockReturnValueOnce(first)
    .mockImplementationOnce(async (_id, body) => ({ evaluation: report(body.run_id, { question: body.question, case_role: body.case_role, classification: report(body.run_id, { case_role: body.case_role }).classification }) }));
  mount({ revisedReports: retained });
  await user.click(screen.getByRole("button", { name: "Review missing revised evaluations" }));
  await screen.findByRole("button", { name: "Start evaluations" });
  const fields = screen.getAllByRole("group");
  await user.type(within(fields[0]!).getByRole("textbox", { name: /^Experiment question/ }), "Check attack evidence");
  await user.selectOptions(within(fields[0]!).getByRole("combobox", { name: "Activity label" }), "attack");
  await user.selectOptions(within(fields[0]!).getByRole("combobox", { name: "Use of this data" }), "development");
  const startButton = screen.getByRole("button", { name: "Start evaluations" });
  fireEvent.click(startButton);
  fireEvent.click(startButton);
  await waitFor(() => expect(evaluate).toHaveBeenCalledTimes(1));
  expect(evaluate).toHaveBeenNthCalledWith(1, revisedId, { run_id: "attack-run", question: "Check attack evidence", case_role: "attack", activity_label: "attack", evaluation_use: "development" });
  expect(evaluate).toHaveBeenCalledTimes(1);
  expect(screen.queryByRole("button", { name: "Start evaluations" })).not.toBeInTheDocument();
  resolveFirst({ evaluation: report("attack-run", {
    question: "Check attack evidence", case_role: "attack",
    classification: { ...report("attack-run").classification!, activity_label: "attack", evaluation_use: "development", requested_use: "development" },
  }) });
  await waitFor(() => expect(evaluate).toHaveBeenCalledTimes(2));
  expect(evaluate).toHaveBeenNthCalledWith(2, revisedId, { run_id: "heldout-run", question: "", case_role: "unknown", activity_label: "unknown", evaluation_use: "unspecified" });
});

it("stops future dispatch after Stop while preserving the settled request result", async () => {
  const user = userEvent.setup();
  mockReads();
  let resolveFirst!: (value: { evaluation: DetectionRunEvaluation }) => void;
  const first = new Promise<{ evaluation: DetectionRunEvaluation }>(resolve => { resolveFirst = resolve; });
  const evaluate = vi.spyOn(api, "evaluateDetectionRun").mockReturnValueOnce(first).mockResolvedValue({ evaluation: report("heldout-run") });
  mount({ runIds: ["attack-run", "heldout-run"] });
  await user.click(screen.getByRole("button", { name: "Review missing revised evaluations" }));
  await user.click(await screen.findByRole("button", { name: "Start evaluations" }));
  await waitFor(() => expect(evaluate).toHaveBeenCalledTimes(1));
  await user.click(screen.getByRole("button", { name: "Stop after current evaluation" }));
  resolveFirst({ evaluation: report("attack-run") });
  expect(await screen.findByText(/Stopped\. No further evaluations were submitted/)).toBeInTheDocument();
  expect(evaluate).toHaveBeenCalledTimes(1);
  expect(screen.getByText(/Evaluation retained: No matches/)).toBeInTheDocument();
});

it("keeps an in-flight original target fixed, stops later cases, then requires fresh history review", async () => {
  const user = userEvent.setup();
  mockReads();
  let resolveFirst!: (value: { evaluation: DetectionRunEvaluation }) => void;
  const first = new Promise<{ evaluation: DetectionRunEvaluation }>(resolve => { resolveFirst = resolve; });
  const originalResult = report("attack-run", {}, baselineId);
  const evaluate = vi.spyOn(api, "evaluateDetectionRun").mockReturnValueOnce(first);
  mount({ runIds: ["attack-run", "heldout-run"], baselineReports: [], revisedReports: [] });
  const side = screen.getByRole("combobox", { name: "Evaluate missing results for" });
  await user.selectOptions(side, "original");
  await user.click(screen.getByRole("button", { name: "Review missing original evaluations" }));
  await user.click(await screen.findByRole("button", { name: "Start evaluations" }));
  await waitFor(() => expect(evaluate).toHaveBeenCalledOnce());
  expect(evaluate).toHaveBeenCalledWith(baselineId, expect.objectContaining({ run_id: "attack-run" }));
  expect(side).toBeDisabled();
  await user.click(screen.getByRole("button", { name: "Stop after current evaluation" }));
  resolveFirst({ evaluation: originalResult });
  expect(await screen.findByText(/Stopped\. No further evaluations were submitted/)).toBeInTheDocument();
  expect(screen.getByText(/Evaluation retained: No matches/)).toBeInTheDocument();
  expect(evaluate).toHaveBeenCalledOnce();

  vi.mocked(api.detectionRunEvaluations).mockImplementation(async id => ({
    evaluations: id === baselineId ? [originalResult] : [],
  }));
  await user.click(screen.getByRole("button", { name: "Review remaining evaluations" }));
  const freshStart = await screen.findByRole("button", { name: "Start evaluations" });
  expect(screen.getByText("Original · Collection detector · revision 1")).toBeVisible();
  const cases = screen.getByRole("list");
  expect(within(cases).getAllByRole("listitem")).toHaveLength(1);
  expect(within(cases).getByRole("group", { name: "Case 1 · Held-out evidence case" })).toBeVisible();
  expect(freshStart).toBeEnabled();
  expect(evaluate).toHaveBeenCalledOnce();
});

it.each(["request rejection", "wrong run response", "wrong candidate response", "wrong manifest digest"] as const)("halts after %s and preserves earlier submitted status", async failure => {
  const user = userEvent.setup();
  mockReads();
  const evaluate = vi.spyOn(api, "evaluateDetectionRun").mockImplementation(async (_id, body) => {
    if (failure === "request rejection") throw new Error("Network timed out");
    if (failure === "wrong run response") return { evaluation: report(body.run_id === "attack-run" ? "heldout-run" : body.run_id) };
    if (failure === "wrong candidate response") return { evaluation: report(body.run_id, { candidate: { ...report(body.run_id).candidate, candidate_id: "other-rule" } }) };
    if (failure === "wrong manifest digest") return { evaluation: report(body.run_id, { source: { ...report(body.run_id).source, manifest_digest: `sha256:${"f".repeat(64)}` } }) };
    return { evaluation: report(body.run_id) };
  });
  mount({ runIds: ["attack-run", "heldout-run"] });
  await user.click(screen.getByRole("button", { name: "Review missing revised evaluations" }));
  await user.click(await screen.findByRole("button", { name: "Start evaluations" }));
  expect(await screen.findByText(/Submitted outcome unconfirmed/)).toBeInTheDocument();
  expect(evaluate).toHaveBeenCalledTimes(1);
  expect(screen.getByText(/Nothing will retry automatically/)).toBeInTheDocument();
});

it("requires a fresh explicit remaining-case review after an unconfirmed response", async () => {
  const user = userEvent.setup();
  mockReads();
  const evaluate = vi.spyOn(api, "evaluateDetectionRun").mockRejectedValue(new Error("Request timed out"));
  mount({ runIds: ["attack-run", "heldout-run"] });
  await user.click(screen.getByRole("button", { name: "Review missing revised evaluations" }));
  await user.click(await screen.findByRole("button", { name: "Start evaluations" }));
  expect(await screen.findByText(/Submitted outcome unconfirmed/)).toBeInTheDocument();
  expect(evaluate).toHaveBeenCalledTimes(1);
  await user.click(screen.getByRole("button", { name: "Review remaining evaluations" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(/fresh history read does not prove it failed to persist/);
  expect(screen.getByRole("button", { name: "Start evaluations" })).toBeEnabled();
  expect(evaluate).toHaveBeenCalledTimes(1);
});

it("keeps an unconfirmed original-result warning bound across side changes", async () => {
  const user = userEvent.setup();
  mockReads();
  const evaluate = vi.spyOn(api, "evaluateDetectionRun").mockRejectedValue(new Error("Request timed out"));
  mount({ runIds: ["attack-run", "heldout-run"], baselineReports: [], revisedReports: [] });
  const side = screen.getByRole("combobox", { name: "Evaluate missing results for" });
  await user.selectOptions(side, "original");
  await user.click(screen.getByRole("button", { name: "Review missing original evaluations" }));
  await user.click(await screen.findByRole("button", { name: "Start evaluations" }));
  expect(await screen.findByText(/Submitted outcome unconfirmed/)).toBeInTheDocument();
  expect(evaluate).toHaveBeenCalledOnce();

  await user.click(screen.getByRole("button", { name: "Review remaining evaluations" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(/fresh history read does not prove it failed to persist/);
  await user.selectOptions(side, "revised");
  expect(screen.getByText(/evaluation side changed/)).toBeInTheDocument();
  await user.selectOptions(side, "original");
  expect(screen.getByText(/evaluation side changed/)).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Review missing original evaluations" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(/fresh history read does not prove it failed to persist/);
  expect(evaluate).toHaveBeenCalledOnce();
});

it.each(["unmount", "selection change"] as const)("does not dispatch another run after %s during an in-flight request", async action => {
  const user = userEvent.setup();
  mockReads();
  let resolveFirst!: (value: { evaluation: DetectionRunEvaluation }) => void;
  const first = new Promise<{ evaluation: DetectionRunEvaluation }>(resolve => { resolveFirst = resolve; });
  const evaluate = vi.spyOn(api, "evaluateDetectionRun").mockReturnValueOnce(first).mockResolvedValue({ evaluation: report("heldout-run") });
  const view = mount({ runIds: ["attack-run", "heldout-run"] });
  await user.click(screen.getByRole("button", { name: "Review missing revised evaluations" }));
  await user.click(await screen.findByRole("button", { name: "Start evaluations" }));
  await waitFor(() => expect(evaluate).toHaveBeenCalledTimes(1));
  if (action === "unmount") {
    view.unmount();
    render(<QueryClientProvider client={view.client}><MemoryRouter><DetectionEvaluationQueue runIds={["attack-run", "heldout-run"]} baselineId={baselineId} revisedId={revisedId} resources={resources} baselineReports={[]} revisedReports={[]} ready /></MemoryRouter></QueryClientProvider>);
    expect(screen.getByRole("button", { name: "Review missing revised evaluations" })).toBeDisabled();
    expect(screen.getByText(/earlier evaluation sequence is still settling/)).toBeInTheDocument();
  }
  else view.rerender(<QueryClientProvider client={view.client}><MemoryRouter><DetectionEvaluationQueue runIds={["heldout-run", "attack-run"]} baselineId={baselineId} revisedId={revisedId} resources={resources} baselineReports={[]} revisedReports={[]} ready /></MemoryRouter></QueryClientProvider>);
  expect(screen.getByRole("combobox", { name: "Evaluate missing results for" })).toBeDisabled();
  resolveFirst({ evaluation: report("attack-run") });
  await waitFor(() => expect(view.client.isMutating({ mutationKey: ["comparison-evaluation-queue"] })).toBe(0));
  expect(evaluate).toHaveBeenCalledTimes(1);
});

it("does not dispatch on mount and stays hidden until the comparison is ready", async () => {
  mockReads();
  const evaluate = vi.spyOn(api, "evaluateDetectionRun");
  mount({ ready: false });
  expect(evaluate).not.toHaveBeenCalled();
  expect(screen.queryByRole("button", { name: "Start evaluations" })).not.toBeInTheDocument();
});

it("blocks preview when the registry contains an ambiguous selected revision", async () => {
  const user = userEvent.setup();
  const ambiguous = [...resources, resource(revisedId, 3)];
  vi.stubGlobal("crypto", webcrypto);
  vi.spyOn(api, "detections").mockResolvedValue({ schema_version: "v1", candidates: ambiguous });
  vi.spyOn(api, "detectionRunEvaluations").mockResolvedValue({ evaluations: [] });
  vi.spyOn(api, "runDetail").mockImplementation(async id => source(id));
  const evaluate = vi.spyOn(api, "evaluateDetectionRun");
  mount({ resources: ambiguous });
  await user.click(screen.getByRole("button", { name: "Review missing revised evaluations" }));
  expect(await screen.findByText(/selected saved revisions are unavailable or do not share one lineage/)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Start evaluations" })).not.toBeInTheDocument();
  expect(evaluate).not.toHaveBeenCalled();
});

it.each(["changed definition", "ambiguous revision"] as const)("blocks dispatch when the saved revision becomes %s after preview", async change => {
  const user = userEvent.setup();
  vi.stubGlobal("crypto", webcrypto);
  const currentResources = change === "changed definition"
    ? [resources[0]!, { ...resources[1]!, document: { ...resources[1]!.document, definition_digest: `sha256:${"f".repeat(64)}` } }]
    : [...resources, resource(revisedId, 3)];
  vi.spyOn(api, "detections").mockResolvedValueOnce({ schema_version: "v1", candidates: resources }).mockResolvedValueOnce({ schema_version: "v1", candidates: currentResources });
  vi.spyOn(api, "detectionRunEvaluations").mockResolvedValue({ evaluations: [] });
  vi.spyOn(api, "runDetail").mockImplementation(async id => source(id));
  const evaluate = vi.spyOn(api, "evaluateDetectionRun");
  mount({ runIds: ["attack-run", "heldout-run"] });
  await user.click(screen.getByRole("button", { name: "Review missing revised evaluations" }));
  await user.click(await screen.findByRole("button", { name: "Start evaluations" }));
  expect(await screen.findByText(/Stopped before submission/)).toBeInTheDocument();
  expect(evaluate).not.toHaveBeenCalled();
});

it.each([
  ["original", "request rejection"],
  ["original", "wrong target response"],
  ["revised", "request rejection"],
  ["revised", "wrong target response"],
] as const)("retains %s-side uncertainty after unmount and %s settlement", async (targetSide, settlement) => {
  const user = userEvent.setup();
  mockReads();
  let resolveFirst!: (value: { evaluation: DetectionRunEvaluation }) => void;
  let rejectFirst!: (reason: Error) => void;
  const first = new Promise<{ evaluation: DetectionRunEvaluation }>((resolve, reject) => {
    resolveFirst = resolve;
    rejectFirst = reject;
  });
  const wrongCandidate = targetSide === "original" ? revisedId : baselineId;
  const evaluate = vi.spyOn(api, "evaluateDetectionRun").mockReturnValueOnce(first);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const props = { runIds: ["attack-run", "heldout-run"], baselineReports: [], revisedReports: [] };
  let view = renderWithClient(client, props);
  if (targetSide === "original") {
    await user.selectOptions(screen.getByRole("combobox", { name: "Evaluate missing results for" }), "original");
  }
  await user.click(screen.getByRole("button", { name: `Review missing ${targetSide} evaluations` }));
  await user.click(await screen.findByRole("button", { name: "Start evaluations" }));
  await waitFor(() => expect(evaluate).toHaveBeenCalledOnce());
  expect(evaluate).toHaveBeenCalledWith(
    targetSide === "original" ? baselineId : revisedId,
    expect.objectContaining({ run_id: "attack-run" }),
  );

  view.unmount();
  const replacement = renderWithClient(client, props);
  expect(screen.getByRole("combobox", { name: "Evaluate missing results for" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Review missing revised evaluations" })).toBeDisabled();
  expect(await screen.findByText(/earlier evaluation sequence is still settling/)).toBeInTheDocument();
  expect(evaluate).toHaveBeenCalledOnce();
  replacement.unmount();

  if (settlement === "request rejection") rejectFirst(new Error("private request detail"));
  else resolveFirst({ evaluation: report("attack-run", {}, wrongCandidate) });
  await waitFor(() => expect(client.isMutating({ mutationKey: ["comparison-evaluation-queue"] })).toBe(0));
  expect(evaluate).toHaveBeenCalledOnce();
  view = renderWithClient(client, props);

  const reviewSide = async (side: "original" | "revised") => {
    const selector = screen.getByRole("combobox", { name: "Evaluate missing results for" });
    if ((selector as HTMLSelectElement).value !== side) await user.selectOptions(selector, side);
    await user.click(screen.getByRole("button", { name: `Review missing ${side} evaluations` }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Start evaluations" })).toBeEnabled());
  };

  await reviewSide(targetSide);
  expect(await screen.findByRole("alert")).toHaveTextContent(/earlier submission .* still unconfirmed/);
  await reviewSide(targetSide === "original" ? "revised" : "original");
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  await reviewSide(targetSide);
  expect(await screen.findByRole("alert")).toHaveTextContent(/fresh history read does not prove it failed to persist/);
  expect(evaluate).toHaveBeenCalledOnce();
  view.unmount();
});

it.each([
  ["original", "other target"],
  ["original", "other run"],
  ["original", "changed manifest"],
  ["original", "retained run"],
  ["revised", "other target"],
  ["revised", "other run"],
  ["revised", "changed manifest"],
  ["revised", "retained run"],
] as const)("does not carry %s-side uncertainty to an %s identity", async (targetSide, identityChange) => {
  const user = userEvent.setup();
  mockReads();
  const evaluate = vi.spyOn(api, "evaluateDetectionRun").mockRejectedValue(new Error("private timeout detail"));
  const view = mount({ runIds: ["attack-run", "heldout-run"], baselineReports: [], revisedReports: [] });
  if (targetSide === "original") {
    await user.selectOptions(screen.getByRole("combobox", { name: "Evaluate missing results for" }), "original");
  }
  await user.click(screen.getByRole("button", { name: `Review missing ${targetSide} evaluations` }));
  await user.click(await screen.findByRole("button", { name: "Start evaluations" }));
  expect(await screen.findByText(/Submitted outcome unconfirmed/)).toBeInTheDocument();
  await waitFor(() => expect(view.client.isMutating({ mutationKey: ["comparison-evaluation-queue"] })).toBe(0));
  await user.click(screen.getByRole("button", { name: "Review remaining evaluations" }));
  await screen.findByRole("alert");
  expect(evaluate).toHaveBeenCalledOnce();

  const targetId = targetSide === "original" ? baselineId : revisedId;
  const reviewCurrentSide = async () => {
    await user.click(screen.getByRole("button", { name: `Review missing ${targetSide} evaluations` }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Start evaluations" })).toBeEnabled());
  };

  if (identityChange === "other target") {
    const otherSide = targetSide === "original" ? "revised" : "original";
    await user.selectOptions(screen.getByRole("combobox", { name: "Evaluate missing results for" }), otherSide);
    await user.click(screen.getByRole("button", { name: `Review missing ${otherSide} evaluations` }));
  } else if (identityChange === "other run") {
    view.rerender(queueTree(view.client, {
      runIds: ["benign-run", "heldout-run"], baselineReports: [], revisedReports: [],
    }));
    await waitFor(() => expect(screen.getByText(/selection or evaluation side changed/)).toBeInTheDocument());
    await reviewCurrentSide();
  } else if (identityChange === "changed manifest") {
    vi.mocked(api.runDetail).mockImplementation(async id => {
      const current = source(id);
      return id === "attack-run"
        ? { ...current, manifest: { ...current.manifest, bundle_hash: `sha256:${"c".repeat(64)}` } }
        : current;
    });
    await reviewCurrentSide();
    expect(within(screen.getByRole("list")).getByText(/Attack evidence case/)).toBeInTheDocument();
  } else {
    vi.mocked(api.detectionRunEvaluations).mockImplementation(async id => ({
      evaluations: id === targetId ? [report("attack-run", {}, targetId)] : [],
    }));
    await reviewCurrentSide();
    expect(within(screen.getByRole("list")).queryByText(/Attack evidence case/)).not.toBeInTheDocument();
  }
  if (identityChange === "other target") {
    await waitFor(() => expect(screen.getByRole("button", { name: "Start evaluations" })).toBeEnabled());
  }
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  expect(evaluate).toHaveBeenCalledOnce();
  view.unmount();
});
