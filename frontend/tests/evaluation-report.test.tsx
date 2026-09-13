import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { DetectionRunEvaluations } from "../src/components/DetectionRunEvaluations";
import { api } from "../src/lib/api";
import { demoRuns } from "../src/lib/demo";
import { evaluationReportMarkdown, type EvaluationReportGroup } from "../src/lib/evaluation-report";
import type { DetectionCandidate, DetectionRunEvaluation } from "../src/types";

const selected = "detection-selected";
const related = "detection-related";
const run = { ...demoRuns[0]!, scenario_title: "Collection measurement", presentation: undefined, scenario: undefined };
const candidate: DetectionCandidate = { candidate_id: selected, title: "Collection rule", state: "parsed", target_language: "sqlite", revision: 2 };
function report(id = selected): DetectionRunEvaluation {
  return {
    schema_version: "bluefire.detection-run-evaluation.v1", evaluation_id: `evaluation-${id}`, question: "Did collection produce the expected observation?", case_role: "attack", case_role_basis: "operator_declared", development_case: true,
    candidate: { candidate_id: id, revision_root_id: related, revision: id === related ? 1 : 2, definition_digest: "definition-digest", query_sha256: "query-digest", source_sha256: "source-digest", target_language: "sqlite", parser_backend: { name: "sqlite" } },
    source: { run_id: run.run_id, manifest_digest: "manifest-digest", evidence_digest: "evidence-digest", observed_count: 3, evidence_count: 4, excluded_provenance_counts: { derived: 1 } },
    result: { state: "matched", match_count: 1, evaluated_evidence_ids: ["observation-1", "observation-2", "observation-3"], matched_evidence_ids: ["observation-2"], gap_count: 0, gap_evidence_ids: [], mapped_fields: ["path"], available_fields: ["path"], unsupported_fields: [], missing_fields: [], diagnostic_codes: [] },
    backend: { name: "SQLite", executed: true, version: "3.50.4" }, created_at: "2026-09-09T12:00:00Z", limitations: ["Independent filesystem metadata and digest observation only."],
  };
}
const group = (id = selected, reports = [report(id)]): EvaluationReportGroup => ({ id, label: id === selected ? "Selected revision 2" : "Related revision 1", status: "loaded", reports });
const appendix = (markdown: string) => JSON.parse(markdown.split("```json\n")[1]!.split("\n```")[0]!);

it("exports actual two-revision 1-of-3 measurements, same-match comparison and exact retained records", () => {
  const records = [report(), report(related)];
  const markdown = evaluationReportMarkdown([group(selected, [records[0]!]), group(related, [records[1]!])], [run]);
  expect(markdown).toContain("Collection measurement");
  expect(markdown.match(/1 of 3 evaluated evidence records/g)).toHaveLength(2);
  expect(markdown).toContain("Same measured matches");
  expect(markdown).toContain("Development evidence");
  expect(markdown).toContain("not an untouched independent test");
  expect(markdown).toContain("unknown \\(legacy report\\)");
  expect(markdown).toContain("Independent filesystem metadata and digest observation only");
  expect(markdown).toContain("Source run created:");
  expect(appendix(markdown).evaluations).toEqual(records);
  expect(markdown).not.toContain("(partial)");
});

it.each(["insufficient_evidence", "backend_error"] as const)("does not export %s as a negative or zero-match result", state => {
  const value = report(); value.development_case = false;
  value.result = { ...value.result, state, match_count: null, gap_count: 1, missing_fields: ["file_bytes"], diagnostic_codes: ["not_available"] };
  value.backend.executed = false;
  const markdown = evaluationReportMarkdown([group(selected, [value])], []);
  expect(markdown).toContain("No supported match count");
  expect(markdown).not.toContain("0 of 3");
  expect(markdown).not.toContain("No matches");
  expect(markdown).toContain("Data use unknown");
  expect(markdown).toContain("Missing evaluations, insufficient evidence and backend errors are not negative detection results");
  expect(appendix(markdown).evaluations).toEqual([value]);
});

it("labels partial histories and never exports unavailable response data or invents a comparison", () => {
  const markdown = evaluationReportMarkdown([group(), { ...group(related), status: "unavailable" }], [run]);
  expect(markdown).toMatch(/^# Detection evaluation report \(partial\)/);
  expect(markdown).toContain("unavailable; no records from this revision included");
  expect(markdown).not.toContain("## Revision comparison");
  expect(appendix(markdown).evaluations).toEqual([report()]);
  expect(appendix(markdown).selections[1].included_evaluation_ids).toEqual([]);
});

it("deduplicates only identical retained records and refuses conflicts or stale group identity", () => {
  expect(appendix(evaluationReportMarkdown([group(selected, [report(), structuredClone(report())])], [])).evaluations).toHaveLength(1);
  const conflict = report(); conflict.question = "Different immutable content";
  expect(() => evaluationReportMarkdown([group(selected, [report(), conflict])], [])).toThrow("Conflicting retained");
  expect(() => evaluationReportMarkdown([group(related, [report()])], [])).toThrow("do not match");
  expect(() => evaluationReportMarkdown([group(), group()], [])).toThrow("ambiguous");
  expect(() => evaluationReportMarkdown([{ ...group(), status: "loading" }], [])).toThrow("Load a retained");
});

function setup() {
  const history = vi.spyOn(api, "detectionRunEvaluations").mockResolvedValue({ evaluations: [report()] });
  const evaluate = vi.spyOn(api, "evaluateDetectionRun").mockResolvedValue({ evaluation: report() });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  let props = { candidate, resourceId: selected };
  const tree = () => <QueryClientProvider client={client}><MemoryRouter><DetectionRunEvaluations {...props} sourceRunId={run.run_id} runs={[run]} revisions={[{ id: selected, label: "Current revision" }, { id: related, label: "Earlier revision" }]} /></MemoryRouter></QueryClientProvider>;
  const view = render(tree());
  let blob: Blob | undefined;
  const create = vi.fn((value: Blob) => { blob = value; return "blob:evaluation-report"; });
  const revoke = vi.fn();
  vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: create, revokeObjectURL: revoke }));
  let filename: string | undefined;
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) { filename = this.download; });
  return { history, evaluate, client, create, revoke, user: userEvent.setup(), filename: () => filename,
    change: (values: Partial<typeof props>) => { props = { ...props, ...values }; view.rerender(tree()); },
    read: () => new Promise<string>(resolve => { const reader = new FileReader(); reader.onload = () => resolve(String(reader.result)); reader.readAsText(blob!); }) };
}

it("downloads only canonical loaded reports using a fixed filename without evaluating", async () => {
  const test = setup();
  await waitFor(() => expect(screen.getByRole("button", { name: "Download evaluation report" })).toBeEnabled());
  await test.user.click(screen.getByRole("button", { name: "Download evaluation report" }));
  expect(appendix(await test.read()).evaluations).toEqual([report()]);
  expect(test.filename()).toBe("bluefire-evaluation-report.md");
  expect(test.revoke).toHaveBeenCalledWith("blob:evaluation-report");
  expect(test.evaluate).not.toHaveBeenCalled();
});

it("shows partial availability before download when related history is loading or refused", async () => {
  const test = setup();
  await screen.findByRole("button", { name: "Download evaluation report" });
  let reject!: (error: Error) => void;
  test.history.mockImplementation(id => id === related ? new Promise((_resolve, fail) => { reject = fail; }) : Promise.resolve({ evaluations: [report()] }));
  await test.user.selectOptions(screen.getByRole("combobox", { name: "Related revision reports" }), related);
  expect(screen.getByRole("button", { name: "Download available reports" })).toBeEnabled();
  expect(screen.getByText(/Some selected revision history is loading or unavailable/)).toBeVisible();
  await test.user.click(screen.getByRole("button", { name: "Download available reports" }));
  expect(await test.read()).toMatch(/^# Detection evaluation report \(partial\)/);
  await act(async () => reject(new Error("History unavailable")));
  await test.user.click(screen.getByRole("button", { name: "Download available reports" }));
  expect(appendix(await test.read()).selections[1].status).toBe("unavailable");
});

it("refuses stale query and displayed candidate identities after selection changes", async () => {
  const test = setup();
  await waitFor(() => expect(screen.getByRole("button", { name: "Download evaluation report" })).toBeEnabled());
  test.change({ resourceId: related, candidate: { ...candidate, candidate_id: related } });
  await screen.findByText(/Loaded reports do not match the selected revision/);
  expect(screen.getByRole("button", { name: "Download evaluation report" })).toBeDisabled();
  test.change({ resourceId: selected, candidate: { ...candidate, candidate_id: related } });
  await screen.findByText(/displayed candidate does not match/);
  expect(screen.getByRole("button", { name: "Download evaluation report" })).toBeDisabled();
  expect(test.create).not.toHaveBeenCalled();
});

it("never substitutes the evaluator response while canonical retained history is still loading", async () => {
  const test = setup();
  await waitFor(() => expect(screen.getByRole("button", { name: "Download evaluation report" })).toBeEnabled());
  let resolve!: (value: { evaluations: DetectionRunEvaluation[] }) => void;
  test.history.mockImplementation(() => new Promise(done => { resolve = done; }));
  act(() => test.client.removeQueries({ queryKey: ["detection-evaluations", selected] }));
  test.change({ candidate: { ...candidate, title: "Changed presentation" } });
  await test.user.click(screen.getByRole("button", { name: "Evaluate full observed run" }));
  await screen.findByText("Evaluation retained");
  expect(screen.getByRole("button", { name: "Download available reports" })).toBeDisabled();
  expect(test.create).not.toHaveBeenCalled();
  await act(async () => resolve({ evaluations: [report()] }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Download evaluation report" })).toBeEnabled());
});

it("marks cached history as unavailable for export during its canonical refresh", async () => {
  const test = setup();
  await waitFor(() => expect(screen.getByRole("button", { name: "Download evaluation report" })).toBeEnabled());
  let resolve!: (value: { evaluations: DetectionRunEvaluation[] }) => void;
  test.history.mockImplementation(() => new Promise(done => { resolve = done; }));
  act(() => { void test.client.invalidateQueries({ queryKey: ["detection-evaluations", selected] }); });
  await waitFor(() => expect(screen.getByRole("button", { name: "Download available reports" })).toBeDisabled());
  expect(test.create).not.toHaveBeenCalled();
  await act(async () => resolve({ evaluations: [report()] }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Download evaluation report" })).toBeEnabled());
});
