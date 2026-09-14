import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog } from "../src/lib/demo";
import { DetectionLabPage } from "../src/pages/DetectionLab";
import type { DetectionComparisonResponse, DetectionResource } from "../src/types";

const id = (n: number) => `detection-${String(n).repeat(20)}`;
const rule = (n: number): DetectionResource => ({ kind: "detections", id: id(n), status: "parsed", digest: `resource-${n}`, created_at: "2026-09-09", updated_at: "2026-09-09", document: { candidate_id: id(n), revision_root_id: id(1), revision: n, revision_kind: n === 1 ? "origin" : "source", definition_digest: `definition-${n}`, title: `Collection rule ${n}`, state: "parsed", target_language: "sqlite", behavior_id: "sandbox.collection.stage.v1", selection: { observed: true }, logsource: { category: "file_event" }, rule_source: `SELECT fixture_id FROM logs WHERE retained_record_count = ${n}` } });
const set = { added: [], removed: [], unchanged: [] };
const identity = (n: number) => ({ candidate_id: id(n), revision: n, revision_kind: n === 1 ? "origin" : "source", state: "parsed", definition_digest: `definition-${n}` });
const sourceIdentity = { target_language: "sqlite", logsource_digest: "log", selection_digest: "selection", rule_source_digest: "source" };
const fixture = { changed: false, added_fixture_ids: [], removed_fixture_ids: [], changed_fixture_ids: [], fixture_ids: set, baseline_match_count: 0, candidate_match_count: 0 };
const report: DetectionComparisonResponse = { schema_version: "bluefire.detection-comparison.v1", comparison_id: "comparison-fixture", revision_root_id: id(1), baseline: identity(1), candidate: identity(2), deltas: {
  source: { changed: false, provenance: { baseline_digest: "a", candidate_digest: "a", changed: false }, public_baselines: { changed: false, added: [], removed: [], modified: [] } },
  rule: { changed: true, changed_fields: ["rule_source"], baseline: sourceIdentity, candidate: sourceIdentity },
  fields: { changed: false, predicted: set, observed: set, drift: { changed: false, baseline: {}, candidate: {} } },
  lifecycle: { changed: false, baseline_state: "parsed", candidate_state: "parsed", baseline_actions: [], candidate_actions: [], baseline_history_digest: "a", candidate_history_digest: "a" },
  fixtures: fixture, observed: { changed: false, evidence_ids: set, run_ids: set }, benign: { ...fixture, notes: set },
} };
function mount(records = [rule(1), rule(2), rule(3)]) {
  vi.spyOn(api, "detections").mockImplementation(async () => ({ schema_version: "v1", candidates: records }));
  vi.spyOn(api, "runs").mockResolvedValue({ schema_version: "v1", unavailable_run_count: 0, runs: [] });
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "resources").mockResolvedValue({ schema_version: "v1", kind: "research-sources", resources: [] });
  vi.spyOn(api, "detectionHealth").mockResolvedValue({ schema_version: "v1", ready: true, persistence_ready: true, candidate_resources: 3, invalid_candidate_resources: 0, languages: { sqlite: { ready: true, authoritative: true, backend: "SQLite" } }, limits: { source_bytes: 262144, fixture_bytes: 1048576, fixtures_per_action: 128, evidence_per_action: 256, notes_per_action: 64 } });
  vi.spyOn(api, "detectionRunEvaluations").mockResolvedValue({ evaluations: [] });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/detection-lab?candidate=${id(1)}&candidate_scope=registry`]}><DetectionLabPage/></MemoryRouter></QueryClientProvider>);
  return { user: userEvent.setup(), records, client };
}
it("keeps advanced drafts mounted while comparison remains ahead of the disclosure", async () => {
  vi.spyOn(api, "cloneDetection").mockRejectedValue(new Error("Immutable clone refused"));
  const { user } = mount();
  await user.click(await screen.findByRole("tab", { name: "Revisions" }));
  const summary = screen.getByText("Advanced clone and tune");
  expect(summary.closest("details")).not.toHaveAttribute("open");
  expect(screen.getByRole("button", { name: "Compare immutable revisions" }).compareDocumentPosition(summary) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  await user.click(summary);
  expect(screen.getByText(/does not copy compiled source or results/)).toBeVisible();
  const reason = screen.getByRole("textbox", { name: /Required research reason/ });
  await user.click(reason); await user.paste("Retained research reason");
  await user.click(screen.getByRole("button", { name: "Create immutable clone" }));
  expect(await screen.findByText("Immutable clone refused")).toBeVisible();
  await user.click(summary);
  expect(screen.getByText("Immutable clone refused")).toBeVisible();
  await user.click(summary);
  expect(reason).toHaveValue("Retained research reason");
});
it("shows the requested saved sources after select and cached-record changes, excluding unsaved edits", async () => {
  let finish!: (value: DetectionComparisonResponse) => void;
  const compare = vi.spyOn(api, "compareDetections").mockReturnValue(new Promise(resolve => { finish = resolve; }));
  const { user, records, client } = mount();
  const editor = await screen.findByRole("textbox", { name: /SQLite source/i });
  await user.clear(editor); await user.paste("UNSAVED operator source");
  await user.click(screen.getByRole("tab", { name: "Revisions" }));
  await user.selectOptions(screen.getByRole("combobox", { name: "Candidate revision" }), id(2));
  await user.click(screen.getByRole("button", { name: "Compare immutable revisions" }));
  expect(compare).toHaveBeenCalledExactlyOnceWith(id(1), id(2));
  await user.selectOptions(screen.getByRole("combobox", { name: "Candidate revision" }), id(3));
  await act(async () => { records[1]!.document.rule_source = "LATER registry text"; await client.invalidateQueries({ queryKey: ["detections"] }); finish(report); });
  const sources = await screen.findByRole("region", { name: "Compared saved rule sources" });
  expect(within(sources).getByText(rule(1).document.rule_source!)).toBeVisible();
  expect(within(sources).getByText(rule(2).document.rule_source!)).toBeVisible();
  expect(within(sources).queryByText(/UNSAVED|LATER|Collection rule 3/)).not.toBeInTheDocument();
  expect(screen.getByRole("combobox", { name: "Candidate revision" })).toHaveValue(id(3));
  expect(screen.getByText("Comparison identity and definitions").closest("details")).not.toHaveAttribute("open");
});
it.each(["digest", "revision", "legacy", "no source"])("does not substitute unbound source for %s records", async failure => {
  vi.spyOn(api, "compareDetections").mockResolvedValue(report);
  const records = [rule(1), rule(2)];
  if (failure === "digest") records[1]!.document.definition_digest = "different-definition";
  if (failure === "legacy") delete records[1]!.document.definition_digest;
  if (failure === "revision") records[1]!.document.revision = 4;
  if (failure === "no source") delete records[1]!.document.rule_source;
  const { user } = mount(records);
  await user.click(await screen.findByRole("tab", { name: "Revisions" }));
  await user.click(screen.getByRole("button", { name: "Compare immutable revisions" }));
  const sources = await screen.findByRole("region", { name: "Compared saved rule sources" });
  if (failure === "no source") {
    expect(within(sources).getByText(/No saved rule source was recorded/)).toBeVisible();
    expect(within(sources).queryByText(rule(2).document.rule_source!)).not.toBeInTheDocument();
  } else {
    expect(within(sources).getAllByText(/Saved source unavailable/)).toHaveLength(2);
    expect(sources.querySelectorAll("pre")).toHaveLength(0);
  }
});
it("rejects returned comparison IDs that differ from the requested pair", async () => {
  vi.spyOn(api, "compareDetections").mockResolvedValue({ ...report, candidate: identity(3) });
  const { user } = mount();
  await user.click(await screen.findByRole("tab", { name: "Revisions" }));
  await user.click(screen.getByRole("button", { name: "Compare immutable revisions" }));
  expect(await screen.findByText(/returned comparison does not match/)).toBeVisible();
  expect(screen.queryByRole("region", { name: "Compared saved rule sources" })).not.toBeInTheDocument();
  await waitFor(() => expect(screen.getByRole("button", { name: "Compare immutable revisions" })).toBeEnabled());
});

it.each([false, true])("suppresses an earlier comparison refusal after newer navigation (return: %s)", async returnToOriginal => {
  let refuse!: (error: Error) => void;
  const compare = vi.spyOn(api, "compareDetections").mockReturnValue(new Promise((_resolve, reject) => { refuse = reject; }));
  const { user } = mount();
  await user.click(await screen.findByRole("tab", { name: "Revisions" }));
  await user.click(screen.getByRole("button", { name: "Compare immutable revisions" }));
  await waitFor(() => expect(compare).toHaveBeenCalledTimes(1));
  await user.click(screen.getByRole("button", { name: /^Collection rule 3/ }));
  if (returnToOriginal) await user.click(screen.getByRole("button", { name: /^Collection rule 1/ }));
  await act(async () => refuse(new Error("Earlier comparison refused")));
  expect(screen.queryByText("Earlier comparison refused")).not.toBeInTheDocument();
  expect(screen.getByRole("heading", { name: returnToOriginal ? "Collection rule 1" : "Collection rule 3" })).toBeVisible();
});
