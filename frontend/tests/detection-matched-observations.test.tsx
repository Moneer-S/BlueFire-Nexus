import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it, vi } from "vitest";
import { MatchedObservations } from "../src/components/MatchedObservations";
import { api } from "../src/lib/api";
import { activityLabel, evaluationUseLabel } from "../src/lib/detection-results";
import type { DetectionRunEvaluation, RunRecord } from "../src/types";

const id = "run-20260908T120000Z-0123456789abcdef";
function fixture(count = 30) {
  const records = Array.from({ length: count }, (_, i) => ({ evidence_id: `evidence-${i}`, record_hash: `sha256:record-${i}`, run_id: id, provenance: "observed", step_id: "collection", content: { observation_kind: "filesystem", path: `item-${i}`, record_count: i } }));
  const run: RunRecord = { run_id: id, mode: "execute", status: "completed", steps: [], manifest: { run_id: id }, evidence: { records } };
  const report = { evaluation_id: "retained-report", case_role: "heldout", source: { run_id: id, evidence_count: count }, result: { match_count: count, matched_evidence_ids: records.map(row => row.evidence_id), matched_evidence_hashes: Object.fromEntries(records.map(row => [row.evidence_id, row.record_hash])) } } as DetectionRunEvaluation;
  return { run, report };
}
function mount(report: DetectionRunEvaluation) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const tree = (value: DetectionRunEvaluation) => <QueryClientProvider client={client}><MatchedObservations key={value.evaluation_id} report={value}/></QueryClientProvider>;
  const view = render(tree(report));
  return (value: DetectionRunEvaluation) => view.rerender(tree(value));
}

it("loads only when opened and paginates the actual bound matches without another evaluation", async () => {
  const { run, report } = fixture();
  const read = vi.spyOn(api, "runDetail").mockResolvedValue(run);
  const evaluate = vi.spyOn(api, "evaluateDetectionRun");
  const user = userEvent.setup(); mount(report);
  expect(read).not.toHaveBeenCalled();
  await user.click(screen.getByText("Inspect matched observations (30)"));
  expect(await screen.findByText("item-24")).toBeVisible();
  expect(screen.queryByText("item-25")).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Next matches" }));
  expect(screen.getByText("item-29")).toBeVisible();
  expect(screen.queryByText("item-0")).not.toBeInTheDocument();
  expect(read).toHaveBeenCalledTimes(1);
  expect(evaluate).not.toHaveBeenCalled();
});

it.each(["identity", "hash", "provenance"])("refuses substituted %s instead of showing unrelated contents", async kind => {
  const { run, report } = fixture(1);
  if (kind === "identity") run.run_id = "another-run";
  if (kind === "hash") run.evidence!.records[0]!.record_hash = "changed";
  if (kind === "provenance") run.evidence!.records[0]!.provenance = "synthetic";
  vi.spyOn(api, "runDetail").mockResolvedValue(run);
  mount(report);
  await userEvent.setup().click(screen.getByText("Inspect matched observations (1)"));
  expect(await screen.findByRole("alert")).toHaveTextContent("do not match");
  expect(screen.queryByText("item-0")).not.toBeInTheDocument();
});

it("never lets a late previous-run read repaint the current report", async () => {
  const { run, report } = fixture(1);
  let finish!: (value: RunRecord) => void;
  vi.spyOn(api, "runDetail").mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  const change = mount(report);
  await userEvent.setup().click(screen.getByText("Inspect matched observations (1)"));
  change({ ...report, evaluation_id: "next", source: { ...report.source, run_id: "another-run" } });
  await act(async () => finish(run));
  expect(screen.queryByText("item-0")).not.toBeInTheDocument();
});

it("keeps legacy heldout context unknown and recorded development dominant", () => {
  const { report } = fixture(1);
  expect(activityLabel(report)).toBe("unknown");
  expect(evaluationUseLabel(report)).toBe("Data use unknown");
  expect(evaluationUseLabel({ ...report, development_case: true })).toBe("Development data");
});
