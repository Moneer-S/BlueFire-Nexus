import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, expect, it, vi } from "vitest";
import { DetectionRunEvaluations } from "../src/components/DetectionRunEvaluations";
import { demoRuns } from "../src/lib/demo";
import type { DetectionCandidate, DetectionCaseRole, DetectionRunEvaluation } from "../src/types";

const candidateId = `detection-${"a".repeat(20)}`;
const parentId = `detection-${"b".repeat(20)}`;
const runId = "run-20260906T120000Z-0123456789abcdef";
const otherRunId = "run-20260906T120001Z-0123456789abcdef";
const candidate: DetectionCandidate = { candidate_id: candidateId, state: "parsed", target_language: "sqlite", revision: 2 };
const digest = `sha256:${"a".repeat(64)}`;
let retained: DetectionRunEvaluation[];
let resultState: DetectionRunEvaluation["result"]["state"];
let reportLanguage = "sqlite";
function report(id: string, source: string, role: DetectionCaseRole): DetectionRunEvaluation {
  const missing = resultState === "insufficient_evidence";
  return {
    schema_version: "bluefire.detection-run-evaluation.v1", evaluation_id: `evaluation-${retained.length}`, question: "Does the revised detector identify staged collection?", case_role: role, case_role_basis: "operator_declared",
    candidate: { candidate_id: id, revision_root_id: parentId, revision: id === parentId ? 1 : 2, definition_digest: digest, query_sha256: reportLanguage === "internal" ? null : digest, source_sha256: reportLanguage === "internal" ? null : digest, target_language: reportLanguage, parser_backend: { name: reportLanguage } },
    source: { run_id: source, manifest_digest: digest, evidence_digest: digest, observed_count: 1, evidence_count: missing ? 2 : 1, excluded_provenance_counts: {} },
    result: { state: resultState, match_count: missing ? null : resultState === "matched" ? 1 : 0, evaluated_evidence_ids: missing ? [] : ["evidence-observed"], matched_evidence_ids: resultState === "matched" ? ["evidence-observed"] : [], gap_count: missing ? 1 : 0, gap_evidence_ids: missing ? ["evidence-gap"] : [], mapped_fields: ["artifact_type", "path"], available_fields: ["artifact_type", "path"], unsupported_fields: [], missing_fields: [], diagnostic_codes: missing ? ["source_contains_evidence_gaps"] : [] },
    backend: { name: reportLanguage === "internal" ? "bluefire-structured-matcher" : "SQLite in-memory bounded executor", executed: !missing, version: "test" }, created_at: "2026-09-06T12:00:00Z", limitations: ["Case role is operator-declared."],
  };
}
function mount(value = candidate) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><MemoryRouter><DetectionRunEvaluations candidate={value} resourceId={candidateId} sourceRunId={runId} runs={[{ ...demoRuns[0]!, run_id: runId }, { ...demoRuns[0]!, run_id: otherRunId }]} revisions={[{ id: parentId, label: "Revision 1" }, { id: candidateId, label: "Revision 2" }]} /></MemoryRouter></QueryClientProvider>);
}
beforeEach(() => {
  retained = [];
  resultState = "matched";
  reportLanguage = "sqlite";
  vi.stubGlobal("fetch", vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
    const path = String(url);
    const id = path.includes(parentId) ? parentId : candidateId;
    if (path.endsWith("/evaluate-run") && init?.method === "POST") {
      const body = JSON.parse(String(init.body)) as { run_id: string; case_role: DetectionCaseRole };
      const evaluation = report(id, body.run_id, body.case_role);
      retained.push(evaluation);
      return new Response(JSON.stringify({ evaluation }), { status: 200 });
    }
    if (path.endsWith("/evaluations")) return new Response(JSON.stringify({ evaluations: retained.filter((row) => row.candidate.candidate_id === id) }), { status: 200 });
    const sourceId = [runId, otherRunId].find(value => path.endsWith(`/runs/${value}`));
    if (sourceId) return new Response(JSON.stringify({ ...demoRuns[0]!, run_id: sourceId,
      scenario_title: sourceId === runId ? "Original collection" : "Collection after change", scenario: undefined,
      presentation: undefined }), { status: 200 });
    throw new Error(`Unexpected evaluation request: ${path}`);
  }));
});

it("submits source identity and case context only, and exposes a measured benign match", async () => {
  const user = userEvent.setup();
  mount();
  expect(screen.getByRole("combobox", { name: "Evaluation source run" })).toHaveValue(runId);
  await user.selectOptions(screen.getByRole("combobox", { name: /Activity label/ }), "benign");
  await user.click(screen.getByRole("button", { name: "Evaluate full observed run" }));
  expect(await screen.findByText("Match in a declared benign case")).toBeInTheDocument();
  const post = vi.mocked(fetch).mock.calls.find(([, init]) => init?.method === "POST")!;
  expect(String(post[0])).toContain(`/detections/${candidateId}/evaluate-run`);
  expect(JSON.parse(String(post[1]!.body))).toEqual({ run_id: runId, question: expect.any(String), case_role: "benign", activity_label: "benign", evaluation_use: "unspecified" });
  expect(candidate.state).toBe("parsed");
  expect(screen.getByText(/"matched_evidence_ids":/)).toHaveTextContent("evidence-observed");
  // A parsed query can evaluate observed evidence directly, without a fixture step.
  expect(screen.getByRole("button", { name: "Evaluate full observed run" })).toBeEnabled();
});

it("retains a telemetry gap as insufficient without presenting a zero-match result", async () => {
  resultState = "insufficient_evidence";
  const user = userEvent.setup();
  mount();
  await user.selectOptions(screen.getByRole("combobox", { name: /Use of this data/ }), "independent");
  await user.click(screen.getByRole("button", { name: "Evaluate full observed run" }));
  expect(await screen.findByText("Insufficient evidence or backend unavailable")).toBeInTheDocument();
  expect(screen.getByText("Source contains evidence gaps")).toBeInTheDocument();
  expect(screen.queryByText("0 matched records")).not.toBeInTheDocument();
  expect(retained[0]?.case_role).toBe("unknown");
});

it("keeps AI development evidence visible even when its original case was withheld", async () => {
  retained.push({ ...report(candidateId, runId, "heldout"), development_case: true });
  retained.push(report(parentId, runId, "heldout"));
  mount();
  expect(await screen.findByText("Development evidence")).toBeVisible();
  expect(screen.getByText(/This data was used or declared for rule development/)).toBeVisible();
  await userEvent.setup().selectOptions(screen.getByRole("combobox", { name: "Related revision reports" }), parentId);
  expect(await screen.findByText("Includes development data; not an untouched independent test")).toBeVisible();
});

it("shows immutable baseline and revision results together and preserves each source", async () => {
  resultState = "not_matched";
  retained.push(report(parentId, runId, "attack"));
  resultState = "matched";
  retained.push(report(candidateId, otherRunId, "replay"));
  const user = userEvent.setup();
  mount();
  await user.selectOptions(screen.getByRole("combobox", { name: "Related revision reports" }), parentId);
  await waitFor(() => expect(screen.getByText("Not matched")).toBeInTheDocument());
  expect(screen.getByText("Matched")).toBeInTheDocument();
  const table = within(screen.getByRole("region", { name: "Measured detector comparison" }));
  expect(await table.findByRole("link", { name: "Original collection" })).toHaveAttribute("href", `/runs/${runId}`);
  expect(await table.findByRole("link", { name: "Collection after change" })).toHaveAttribute("href", `/runs/${otherRunId}`);
  expect(retained.map(item => item.source.run_id)).toEqual([runId, otherRunId]);
  expect(screen.getByText(candidateId)).toBeInTheDocument();
  expect(screen.getByText(parentId)).toBeInTheDocument();
});

it.each(["yara", "spl"])("does not give %s candidates metadata-execution semantics", async (language) => {
  mount({ ...candidate, target_language: language });
  expect(screen.getByRole("button", { name: "Evaluate full observed run" })).toBeDisabled();
  expect(screen.getByText(/YARA cannot inspect file bytes from metadata alone/)).toBeInTheDocument();
  await screen.findByText("No retained run evaluations");
  expect(vi.mocked(fetch).mock.calls.some(([, init]) => init?.method === "POST")).toBe(false);
});

it("evaluates multiple runs with one exercised internal revision and truthful engine identity", async () => {
  reportLanguage = "internal";
  const user = userEvent.setup();
  const view = mount({ ...candidate, target_language: "internal", state: "observed_exercised" });
  await user.click(screen.getByRole("button", { name: "Evaluate full observed run" }));
  expect(await screen.findByText("Definition digest")).toBeVisible();
  expect(screen.queryByText("Query digest")).not.toBeInTheDocument();
  expect(screen.getByText("bluefire-structured-matcher · test · Executed")).toBeVisible();
  resultState = "not_matched";
  await user.selectOptions(screen.getByRole("combobox", { name: "Evaluation source run" }), otherRunId);
  await user.click(screen.getByRole("button", { name: "Evaluate full observed run" }));
  await screen.findByText("All retained evaluation records (2)");
  expect(retained.map(row => row.candidate.candidate_id)).toEqual([candidateId, candidateId]);
  expect(retained.map(row => row.source.run_id)).toEqual([runId, otherRunId]);
  expect(vi.mocked(fetch).mock.calls.filter(([, init]) => init?.method === "POST").every(([url]) => String(url).endsWith("/evaluate-run"))).toBe(true);
  view.unmount();
  mount({ ...candidate, target_language: "internal", state: "observed_exercised" });
  expect(await screen.findByText("All retained evaluation records (2)")).toBeVisible();
});
