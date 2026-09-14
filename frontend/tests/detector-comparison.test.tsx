import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { DetectorEvaluationComparison } from "../src/components/DetectorEvaluationComparison";
import { api } from "../src/lib/api";
import { compareDetectorEvaluations, evaluationLabel } from "../src/lib/detection-results";
import type { DetectionResource, DetectionRunEvaluation } from "../src/types";

function report(candidateId: string, runId: string, state: DetectionRunEvaluation["result"]["state"], role: DetectionRunEvaluation["case_role"] = "attack"): DetectionRunEvaluation {
  return { schema_version: "bluefire.detection-run-evaluation.v1", evaluation_id: `${candidateId}-${runId}-${state}`, question: "Does the saved query match the observed collection?", case_role: role, case_role_basis: "operator_declared", created_at: "2026-09-06T12:00:00Z", limitations: [],
    candidate: { candidate_id: candidateId, revision_root_id: "original", revision: candidateId === "original" ? 1 : 2, definition_digest: candidateId, query_sha256: candidateId, source_sha256: candidateId, target_language: "sqlite", parser_backend: { name: "SQLite" } },
    source: { run_id: runId, manifest_digest: `manifest-${runId}`, evidence_digest: `events-${runId}`, observed_count: 5, evidence_count: 14, excluded_provenance_counts: { executed: 9 } },
    result: { state, match_count: state === "matched" ? 1 : state === "not_matched" ? 0 : null, evaluated_evidence_ids: ["observed-1"], matched_evidence_ids: state === "matched" ? ["observed-1"] : [], gap_count: state === "insufficient_evidence" ? 1 : 0, gap_evidence_ids: [], mapped_fields: ["retained_record_count"], available_fields: ["retained_record_count"], unsupported_fields: [], missing_fields: [], diagnostic_codes: [] },
    backend: { name: "SQLite", executed: state !== "backend_error", version: "3.45.1" },
  };
}
function compare(left: DetectionRunEvaluation[], right: DetectionRunEvaluation[], ids?: string[]) { return compareDetectorEvaluations(left, right, ids); }
afterEach(() => { vi.restoreAllMocks(); });

it("compares measured events on identical evidence and retains untested selected runs", () => {
  const rows = compare([report("original", "attack", "not_matched"), report("original", "benign", "matched", "benign")], [report("revised", "attack", "matched"), report("revised", "benign", "not_matched", "benign")], ["attack", "benign", "heldout"]);
  expect(rows.map((row) => row.change)).toEqual(["New match", "Declared benign match removed", "Evaluate both revisions"]);
  expect(rows[2]?.baseline).toEqual([]);
});

it("does not compare different captured evidence or silently pick a favorable evaluation", () => {
  const left = report("original", "attack", "not_matched");
  const right = report("revised", "attack", "matched");
  right.source.evidence_digest = "different";
  expect(compare([left], [right])[0]?.change).toContain("Different evidence");
  right.source.evidence_digest = left.source.evidence_digest;
  expect(compare([left, report("original", "attack", "matched")], [right])[0]?.change).toBe("Results differ across evaluations");
});

it.each(["insufficient_evidence", "backend_error"] as const)("does not count %s as a zero-match success", (state) => {
  const right = report("revised", "attack", state);
  expect(compare([report("original", "attack", "matched")], [right])[0]?.change).toBe("Not enough evidence to compare");
  expect(evaluationLabel(right)).not.toContain("No matches");
});

it("guards missing fields, missing execution, inconsistent role labels, and lost matches", () => {
  const left = report("original", "attack", "matched");
  const right = report("revised", "attack", "not_matched");
  expect(compare([left], [right])[0]?.change).toBe("Previously matched event missed");
  right.result.missing_fields = ["retained_record_count"];
  expect(evaluationLabel(right)).toBe("Not enough evidence");
  right.result.missing_fields = [];
  right.backend.executed = false;
  expect(evaluationLabel(right)).toBe("Not enough evidence");
  right.backend.executed = true;
  right.case_role = "benign";
  expect(compare([left], [right])[0]?.change).toContain("Case labels differ");
});

it("filters unrelated runs without hiding requested runs that have no retained evaluations", () => {
  const rows = compare([report("original", "unrelated", "matched")], [], ["chosen"]);
  expect(rows.map((row) => row.runId)).toEqual(["chosen"]);
  expect(rows[0]?.change).toBe("Evaluate both revisions");
});

function resource(id: string, root: string, revision: number): DetectionResource {
  return { kind: "detections", id, status: "parsed", digest: id, created_at: "2026-09-06", updated_at: "2026-09-06", document: { candidate_id: id, title: id, state: "parsed", revision, revision_root_id: root, target_language: "sqlite", rule_source: "SELECT fixture_id FROM logs" } };
}
function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><MemoryRouter><DetectorEvaluationComparison runIds={["attack", "heldout"]} /></MemoryRouter></QueryClientProvider>);
}
it("loads only the chosen revision family and exposes missing held-out evaluations", async () => {
  const user = userEvent.setup();
  vi.spyOn(api, "detections").mockResolvedValue({ schema_version: "v1", candidates: [resource("original", "original", 1), resource("revised", "original", 2), resource("unrelated", "unrelated", 1)] });
  const fetchReports = vi.spyOn(api, "detectionRunEvaluations").mockImplementation(async (id) => ({ evaluations: [report(id, "attack", id === "original" ? "not_matched" : "matched")] }));
  mount();
  await user.selectOptions(await screen.findByRole("combobox", { name: "Original detector" }), "original");
  expect(screen.getByRole("combobox", { name: "Revised detector" })).not.toHaveTextContent("unrelated");
  await user.selectOptions(screen.getByRole("combobox", { name: "Revised detector" }), "revised");
  expect(await screen.findByText("New match")).toBeInTheDocument();
  expect(screen.getByText("Evaluate both revisions")).toBeInTheDocument();
  expect(screen.getAllByText("Not evaluated")).toHaveLength(2);
  expect(fetchReports).toHaveBeenCalledWith("original");
  expect(fetchReports).toHaveBeenCalledWith("revised");
  const evaluationLinks = screen.getAllByRole("link", { name: "Open detector and run" });
  expect(evaluationLinks.map((link) => {
    const params = new URL(link.getAttribute("href")!, "http://localhost").searchParams;
    return { run: params.get("run"), candidate: params.get("candidate"), scope: params.get("candidate_scope") };
  })).toEqual([
    { run: "attack", candidate: "original", scope: "registry" },
    { run: "attack", candidate: "revised", scope: "registry" },
  ]);
  await user.selectOptions(screen.getByRole("combobox", { name: "Original detector" }), "unrelated");
  expect(screen.getByRole("combobox", { name: "Revised detector" })).toHaveValue("");
  expect(screen.queryByText("New match")).not.toBeInTheDocument();
  await waitFor(() => expect(fetchReports).toHaveBeenCalledWith("unrelated"));
});
