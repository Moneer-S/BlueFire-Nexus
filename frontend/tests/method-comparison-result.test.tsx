import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { MethodComparisonResult } from "../src/components/MethodComparisonResult";
import { api } from "../src/lib/api";
import type { MethodProposal, MethodResult, MethodSource } from "../src/lib/method-comparison";
import type { ComparisonResponse, DetectionRunEvaluation } from "../src/types";

const digest = (letter: string) => `sha256:${letter.repeat(64)}`;
function fixtures() {
  const source: MethodSource = { run_id: "original-run", manifest_digest: digest("a"), evidence_digest: digest("b"), observed_records_digest: digest("c"), mode: "execute", finalized_at: "2026-09-06T12:00:00Z", observed_count: 1, evidence_count: 1, excluded_provenance_counts: {} };
  const replaySource: MethodSource = { ...source, run_id: "replay-run", manifest_digest: digest("d"), evidence_digest: digest("e"), observed_records_digest: digest("f"), mode: "simulate", observed_count: 0, evidence_count: 9, excluded_provenance_counts: { synthetic: 9 } };
  const candidate = { candidate_id: "saved-detector", definition_digest: digest("1"), revision_root_id: "saved-detector", revision: 1, query_sha256: digest("2"), source_sha256: digest("2"), target_language: "sqlite", parser_backend: { name: "SQLite" }, resource_digest_at_evaluation: digest("3") };
  const baseline: DetectionRunEvaluation = { schema_version: "bluefire.detection-run-evaluation.v1", evaluation_id: "baseline-evaluation", question: "Does the saved rule detect the other method?", case_role: "attack", case_role_basis: "operator_declared", created_at: source.finalized_at, limitations: ["Query results do not establish host prevention."], candidate, source,
    result: { state: "matched", match_count: 1, evaluated_evidence_ids: ["observed-event"], matched_evidence_ids: ["observed-event"], gap_count: 0, gap_evidence_ids: [], mapped_fields: [], available_fields: [], unsupported_fields: [], missing_fields: [], diagnostic_codes: [] }, backend: { name: "SQLite", version: "3", executed: true } };
  const child: DetectionRunEvaluation = { ...structuredClone(baseline), evaluation_id: "child-evaluation", source: replaySource, case_role: "replay", result: { ...baseline.result, state: "insufficient_evidence", match_count: null, evaluated_evidence_ids: [], matched_evidence_ids: [] }, backend: { name: "SQLite", executed: false } };
  // Only the proposal fields read by this result panel are needed for this bounded fixture.
  const proposal = { schema_version: "bluefire.method-comparison-proposal.v1", proposal_digest: digest("4"), source_run: source, detector: { candidate_id: candidate.candidate_id, definition_digest: candidate.definition_digest, resource_digest: candidate.resource_digest_at_evaluation, target_language: "sqlite" }, option: { title_from: "Original collection", title: "Alternative collection" }, comparison_limitations: ["Full scenario replay is exploratory."], replay_extent: "full", replay_autonomy: "off" } as MethodProposal;
  const receipt: MethodResult = { schema_version: "bluefire.method-comparison-result.v1", proposal_job_id: "proposal-job", proposal_digest: proposal.proposal_digest, replay_job_id: "replay-job", source_run_id: source.run_id, child_run_id: replaySource.run_id, candidate_id: candidate.candidate_id, candidate_definition_digest: candidate.definition_digest, baseline_evaluation_id: baseline.evaluation_id, child_evaluation_id: child.evaluation_id, comparison_id: "saved-comparison", comparison_digest: digest("5") };
  const comparison: ComparisonResponse = { comparison_id: receipt.comparison_id, baseline_run_id: source.run_id, run_ids: [source.run_id, replaySource.run_id], summaries: [source, replaySource].map((run) => ({ run_id: run.run_id, mode: run.mode as "execute" | "simulate", path: ["collection"], outcomes: { collection: "succeeded" }, objective_reached: true, cleanup_success: true })), deltas: [] };
  return { proposal, receipt, replaySource, saved: { resource: { id: receipt.comparison_id, digest: receipt.comparison_digest, document: comparison } }, evaluations: [baseline, child] };
}
type Fixture = ReturnType<typeof fixtures>;
function mount(value: Fixture) {
  const saved = vi.spyOn(api, "savedComparison").mockImplementation(async () => value.saved);
  const evaluations = vi.spyOn(api, "detectionRunEvaluations").mockImplementation(async () => ({ evaluations: value.evaluations }));
  const create = vi.spyOn(api, "compare");
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const content = (props: Fixture) => <QueryClientProvider client={client}><MemoryRouter><MethodComparisonResult receipt={props.receipt} proposal={props.proposal} replaySource={props.replaySource} /></MemoryRouter></QueryClientProvider>;
  const view = render(content(value));
  return { ...view, saved, evaluations, create, rerenderFixture: (next: Fixture) => view.rerender(content(next)) };
}

it("shows actual original matches and an unevaluated synthetic replay without claiming defense success", async () => {
  const value = fixtures();
  value.evaluations[0]!.development_case = true;
  const calls = mount(value);
  const table = await screen.findByRole("table", { name: "Retained evaluations of the same saved detector" });
  const original = within(table).getByRole("rowheader", { name: /Original method/ }).closest("tr")!;
  const replay = within(table).getByRole("rowheader", { name: /Replay method/ }).closest("tr")!;
  expect(within(original).getByText("1 matched event")).toBeVisible();
  expect(within(original).getByText("1 observed / 1 total")).toBeVisible();
  expect(within(replay).getByText("Not enough evidence")).toBeVisible();
  expect(within(replay).getByText("Matched events: Not measured")).toBeVisible();
  expect(within(replay).getByText("0 observed / 9 total")).toBeVisible();
  expect(within(replay).getByText("Not executed")).toBeVisible();
  expect(screen.getByText(/Includes development evidence/)).toBeVisible();
  expect(screen.getByText("Achieved (synthetic)")).toBeVisible();
  expect(screen.getByText("No real effects")).toBeVisible();
  expect(screen.getByRole("link", { name: "Review original run" })).toHaveAttribute("href", "/runs/original-run");
  expect(screen.getByRole("link", { name: "Review replay run" })).toHaveAttribute("href", "/runs/replay-run");
  expect(calls.saved).toHaveBeenCalledWith("saved-comparison");
  expect(calls.evaluations).toHaveBeenCalledWith("saved-detector");
  expect(calls.create).not.toHaveBeenCalled();
});

it.each<[string, (value: Fixture) => void]>([
  ["saved resource identity", (v) => { v.saved.resource.id = "different"; }],
  ["saved resource digest", (v) => { v.saved.resource.digest = digest("9"); }],
  ["comparison document identity", (v) => { v.saved.resource.document.comparison_id = "different"; }],
  ["baseline identity", (v) => { v.saved.resource.document.baseline_run_id = "replay-run"; }],
  ["run order", (v) => { v.saved.resource.document.run_ids.reverse(); }],
  ["summary order", (v) => { v.saved.resource.document.summaries.reverse(); }],
  ["missing evaluation", (v) => { v.evaluations.pop(); }],
  ["duplicate evaluation", (v) => { v.evaluations.push(structuredClone(v.evaluations[1]!)); }],
  ["detector definition", (v) => { v.evaluations[1]!.candidate.definition_digest = digest("9"); }],
  ["detector source", (v) => { v.evaluations[1]!.candidate.source_sha256 = digest("9"); }],
  ["detector query", (v) => { v.evaluations[1]!.candidate.query_sha256 = digest("9"); }],
  ["baseline manifest", (v) => { v.evaluations[0]!.source = { ...v.evaluations[0]!.source, manifest_digest: digest("9") }; }],
  ["replay evidence", (v) => { v.evaluations[1]!.source = { ...v.evaluations[1]!.source, evidence_digest: digest("9") }; }],
  ["replay observation count", (v) => { v.evaluations[1]!.source = { ...v.evaluations[1]!.source, observed_count: 2 }; }],
  ["replay source binding", (v) => { v.replaySource = { ...v.replaySource, run_id: "other-run" }; }],
  ["proposal binding", (v) => { v.receipt.proposal_digest = digest("9"); }],
])("withholds results and download when %s does not match", async (_name, mutate) => {
  const value = fixtures(); mutate(value); mount(value);
  expect(await screen.findByRole("alert")).toHaveTextContent("retained records do not match");
  expect(screen.queryByRole("table")).not.toBeInTheDocument();
  expect(screen.queryByRole("link", { name: "Download saved run comparison" })).not.toBeInTheDocument();
});

it("retries only reads after unavailable records, then exports the exact saved report", async () => {
  const user = userEvent.setup(), value = fixtures();
  const calls = mount(value);
  calls.saved.mockRejectedValueOnce(new Error("Saved report unavailable"));
  // A fresh key starts a new read whose failure can be recovered explicitly.
  const next = { ...value, receipt: { ...value.receipt, comparison_digest: digest("6") } };
  value.saved.resource.digest = next.receipt.comparison_digest;
  calls.rerenderFixture(next);
  expect(await screen.findByRole("alert")).toHaveTextContent("Saved report unavailable");
  await user.click(screen.getByRole("button", { name: "Try again" }));
  const download = await screen.findByRole("link", { name: "Download saved run comparison" });
  expect(download).toHaveAttribute("href", "blob:test");
  expect(download).toHaveAttribute("download", "bluefire-method-comparison.md");
  expect(URL.createObjectURL).toHaveBeenCalledWith(expect.any(Blob));
  const blob = vi.mocked(URL.createObjectURL).mock.calls.at(-1)![0] as Blob;
  const content = await new Promise<string>((resolve) => { const reader = new FileReader(); reader.onload = () => resolve(String(reader.result)); reader.readAsText(blob); });
  expect(content).toContain("Comparison: saved-comparison");
  expect(content).toContain("Baseline: original-run");
  expect(content).toContain("replay-run");
  calls.unmount();
  expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:test");
  expect(calls.create).not.toHaveBeenCalled();
});

it("hides a previous result immediately when the operation receipt changes", async () => {
  const value = fixtures(), calls = mount(value);
  await screen.findByRole("table", { name: "Retained evaluations of the same saved detector" });
  calls.saved.mockImplementation(() => new Promise(() => undefined));
  calls.rerenderFixture({ ...value, receipt: { ...value.receipt, comparison_id: "another-comparison" } });
  expect(screen.queryByRole("table")).not.toBeInTheDocument();
  expect(screen.queryByRole("link", { name: "Download saved run comparison" })).not.toBeInTheDocument();
  await waitFor(() => expect(calls.saved).toHaveBeenCalledWith("another-comparison"));
});
