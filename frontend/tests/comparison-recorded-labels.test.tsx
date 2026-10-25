import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import * as Tooltip from "@radix-ui/react-tooltip";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { ComparePage, ComparisonResult } from "../src/pages/Compare";
import type { CatalogResponse, ComparisonResponse, RunRecord, SavedComparisonSnapshot } from "../src/types";

const stepId = "node_collect_8";
const primary = "recorded.list.v1", alternate = "recorded.metadata.v1", unrelated = "current.other.v1";
const primaryAction = "native.list.v1", alternateAction = "native.metadata.v1";
const catalog: CatalogResponse = { ...structuredClone(demoCatalog), behaviors: [
  { ...demoCatalog.behaviors[0]!, id: primary, title: "List selected records" },
  { ...demoCatalog.behaviors[0]!, id: alternate, title: "Inspect selected metadata" },
  { ...demoCatalog.behaviors[0]!, id: unrelated, title: "Unrelated current method" },
], actions: [
  { ...demoCatalog.actions[0]!, id: primaryAction, title: "Native file listing" },
  { ...demoCatalog.actions[0]!, id: alternateAction, title: "Native metadata inspection" },
  { ...demoCatalog.actions[0]!, id: unrelated, title: "Unrelated current action" },
] };

function fixture(): ComparisonResponse {
  const summaries = ["recorded-baseline", "recorded-variant"].map((run_id, index) => {
    const methods = index ? [[alternate, alternateAction], [primary, primaryAction]] : [[primary, primaryAction], [alternate, alternateAction]];
    const execution_path = methods.map(([behavior_id, action_id]) => ({ step_id: stepId, behavior_id, action_id }));
    return { run_id, mode: "execute" as const, path: [stepId, stepId], outcomes: { [stepId]: "blocked" },
      first_blocked_step: stepId, execution_path, first_block: { ...execution_path[1]!, status: "blocked", policy_status: null },
      objective_reached: false, cleanup_success: true };
  });
  return { comparison_id: "recorded-comparison", baseline_run_id: summaries[0]!.run_id,
    run_ids: summaries.map(summary => summary.run_id), summaries, deltas: [] };
}

function source(runId: string, conflicting = false): RunRecord {
  return { run_id: runId, mode: "execute", status: "completed", finalized_at: "2030-01-01T00:00:00Z",
    scenario: { ...structuredClone(demoScenario), steps: [{ ...demoScenario.steps[0]!, id: stepId, behavior_id: unrelated }] },
    steps: [
      { step_id: stepId, behavior_id: conflicting ? unrelated : primary, action_id: conflicting ? unrelated : primaryAction, status: "success" },
      { step_id: stepId, behavior_id: conflicting ? unrelated : alternate, action_id: conflicting ? unrelated : alternateAction, status: "blocked" },
    ] };
}

function legacy(): ComparisonResponse {
  const value = fixture();
  for (const summary of value.summaries) {
    delete (summary as unknown as Record<string, unknown>).execution_path;
    delete (summary as unknown as Record<string, unknown>).first_block;
  }
  return value;
}

function lanes() {
  return within(screen.getByRole("region", { name: "Recorded run paths" })).getAllByRole("article");
}
function stoppedCell(index: number) {
  const table = within(screen.getByRole("region", { name: "Compared run outcomes" }));
  return within(table.getByRole("rowheader", { name: "First stopped step" }).closest("tr")!).getAllByRole("cell")[index]!;
}
function mountResult(comparison: ComparisonResponse, runs: RunRecord[] = []) {
  return render(<MemoryRouter><ComparisonResult comparison={comparison} catalog={catalog} runs={runs} /></MemoryRouter>);
}

const clients: QueryClient[] = [];
afterEach(() => clients.splice(0).forEach(client => client.clear()));
function mountSaved(comparison: ComparisonResponse, runs: RunRecord[], status: "missing" | "changed") {
  const snapshot: SavedComparisonSnapshot = { snapshot_id: "saved-recorded", digest: "saved-digest", created_at: "2030-01-01T00:00:00Z",
    comparison, source_bindings: comparison.run_ids.map(run_id => ({ run_id, bundle_hash: "recorded-bundle" })),
    source_integrity: { status: "unavailable", runs: comparison.run_ids.map(run_id => ({ run_id, status })) } };
  vi.spyOn(api, "runs").mockResolvedValue({ runs, unavailable_run_count: 0 });
  vi.spyOn(api, "catalog").mockResolvedValue(catalog);
  vi.spyOn(api, "comparisonSnapshots").mockResolvedValue({ snapshots: [] });
  vi.spyOn(api, "comparisonSnapshot").mockResolvedValue(snapshot);
  const detail = vi.spyOn(api, "runDetail");
  const compare = vi.spyOn(api, "compare");
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } } });
  clients.push(client);
  render(<QueryClientProvider client={client}><Tooltip.Provider><MemoryRouter initialEntries={["/compare?snapshot=saved-recorded"]}><ComparePage /></MemoryRouter></Tooltip.Provider></QueryClientProvider>);
  return { detail, compare };
}

it("uses each saved attempt and its first block instead of another run's current method", async () => {
  const comparison = fixture();
  const runs = comparison.run_ids.map(id => source(id, true));
  const before = structuredClone({ comparison, runs, catalog });
  localStorage.setItem("bluefire.local.scenario.v1", JSON.stringify(runs[0]!.scenario));
  mountResult(comparison, runs);
  const [baseline, variant] = lanes();
  const baselineSteps = within(baseline!).getAllByRole("listitem");
  const variantSteps = within(variant!).getAllByRole("listitem");
  expect(within(baselineSteps[0]!).getByText("List selected records")).toBeVisible();
  expect(within(baselineSteps[0]!).getByText("Native file listing")).toBeVisible();
  expect(within(baselineSteps[1]!).getByText("Inspect selected metadata")).toBeVisible();
  expect(within(baselineSteps[1]!).getByText("Native metadata inspection")).toBeVisible();
  expect(within(variantSteps[0]!).getByText("Inspect selected metadata")).toBeVisible();
  expect(within(variantSteps[1]!).getByText("List selected records")).toBeVisible();
  for (const attempt of [...baselineSteps, ...variantSteps]) {
    expect(within(attempt).getByText("Unreported")).toBeVisible();
    expect(attempt).toHaveAttribute("data-status", "not_reported");
    expect(within(attempt).queryByText("Blocked")).not.toBeInTheDocument();
  }
  expect(within(baseline!).getByText("2 attempts")).toBeVisible();
  expect(within(variant!).getByText("2 attempts")).toBeVisible();
  expect(within(baseline!).getAllByText("Individual attempt results were not recorded.")).toHaveLength(1);
  expect(within(variant!).getAllByText("Individual attempt results were not recorded.")).toHaveLength(1);
  expect(screen.getAllByText("2 recorded attempts")).toHaveLength(2);
  expect(stoppedCell(0)).toHaveTextContent("Inspect selected metadata");
  expect(stoppedCell(1)).toHaveTextContent("List selected records");
  expect(within(stoppedCell(0)).getByText("Native metadata inspection")).toBeVisible();
  expect(within(stoppedCell(1)).getByText("Native file listing")).toBeVisible();
  expect(screen.queryByText("Unrelated current method")).not.toBeInTheDocument();
  expect(screen.queryByText("Unrelated current action")).not.toBeInTheDocument();

  const user = userEvent.setup();
  await user.click(within(baseline!).getByText("Run context and technical details", { selector: "summary" }));
  expect(within(baseline!).getByText(`${stepId} → ${stepId}`, { selector: "code" })).toBeVisible();
  expect(within(baseline!).getByText(`${primaryAction} → ${alternateAction}`, { selector: "code" })).toBeVisible();
  expect(within(baseline!).getByText(`${primary} → ${alternate}`, { selector: "code" })).toBeVisible();
  expect(within(baseline!).getByText(stepId, { selector: "code" })).toBeVisible();
  expect(within(baseline!).getByText(`${stepId}: Blocked`, { selector: "code" })).toBeVisible();
  expect({ comparison, runs, catalog }).toEqual(before);
});

it("keeps saved attempt labels when source run records are unavailable without fetching each run", async () => {
  const { detail, compare } = mountSaved(fixture(), [], "missing");
  await screen.findByRole("region", { name: "Comparison results" });
  expect(within(lanes()[0]!).getByText("Native metadata inspection")).toBeVisible();
  expect(stoppedCell(0)).toHaveTextContent("Inspect selected metadata");
  expect(screen.getByText(/shown as saved and was not recomputed/)).toBeVisible();
  expect(detail).not.toHaveBeenCalled();
  expect(compare).not.toHaveBeenCalled();
});

it("does not borrow changed source records for legacy saved comparisons", async () => {
  const comparison = legacy();
  const { detail, compare } = mountSaved(comparison, comparison.run_ids.map(id => source(id, true)), "changed");
  await screen.findByRole("region", { name: "Comparison results" });
  expect(stoppedCell(0)).toHaveTextContent("Node collect 8");
  expect(within(lanes()[0]!).getAllByText("Method details unavailable")).toHaveLength(2);
  expect(screen.queryByText("Unrelated current method")).not.toBeInTheDocument();
  expect(screen.queryByText("Unrelated current action")).not.toBeInTheDocument();
  expect(detail).not.toHaveBeenCalled();
  expect(compare).not.toHaveBeenCalled();
});

it("uses matching recorded attempts for legacy comparisons before the captured scenario's original method", () => {
  const comparison = legacy();
  mountResult(comparison, [source(comparison.run_ids[0]!)]);
  const steps = within(lanes()[0]!).getAllByRole("listitem");
  expect(within(steps[0]!).getByText("List selected records")).toBeVisible();
  expect(within(steps[1]!).getByText("Inspect selected metadata")).toBeVisible();
  expect(stoppedCell(0)).toHaveTextContent("Inspect selected metadata");
  expect(stoppedCell(1)).toHaveTextContent("Node collect 8");
  expect(screen.queryByText("Unrelated current method")).not.toBeInTheDocument();
});

it.each(["duplicate", "path mismatch", "outcome mismatch", "invalid saved path"])("keeps an honest readable-ID fallback for %s source provenance", reason => {
  const comparison = legacy();
  const record = source(comparison.run_ids[0]!, true);
  if (reason === "path mismatch") record.steps[0]!.step_id = "different_step";
  if (reason === "outcome mismatch") record.steps[1]!.status = "success";
  if (reason === "invalid saved path") (comparison.summaries[0] as unknown as Record<string, unknown>).execution_path = [{ step_id: "different_step", behavior_id: primary }];
  mountResult(comparison, reason === "duplicate" ? [record, structuredClone(record)] : [record]);
  const first = within(lanes()[0]!).getAllByRole("listitem")[0]!;
  expect(within(first).getByText("Node collect 8")).toBeVisible();
  expect(within(first).getByText("Method details unavailable")).toBeVisible();
  expect(screen.queryByText("Unrelated current action")).not.toBeInTheDocument();
});

it.each([null, 17, { step_id: stepId, status: null }])("uses a valid saved path despite malformed current source step %j", malformed => {
  const comparison = fixture();
  const record = source(comparison.run_ids[0]!, true);
  record.steps = [malformed, ...record.steps] as unknown as RunRecord["steps"];
  mountResult(comparison, [record]);
  const steps = within(lanes()[0]!).getAllByRole("listitem");
  expect(within(steps[0]!).getByText("Native file listing")).toBeVisible();
  expect(within(steps[1]!).getByText("Native metadata inspection")).toBeVisible();
  expect(stoppedCell(0)).toHaveTextContent("Inspect selected metadata");
  expect(screen.queryByText("Unrelated current method")).not.toBeInTheDocument();
});

it("does not inspect current source steps at all when the saved execution path exists", () => {
  const comparison = fixture();
  const record = source(comparison.run_ids[0]!);
  const readSteps = vi.fn(() => { throw new Error("A saved path must not inspect current source steps"); });
  Object.defineProperty(record, "steps", { get: readSteps });
  mountResult(comparison, [record]);
  expect(stoppedCell(0)).toHaveTextContent("Inspect selected metadata");
  expect(readSteps).not.toHaveBeenCalled();
});

it.each(["null member", "missing step ID", "invalid status", "invalid method"])("rejects the complete legacy source sequence for a %s", reason => {
  const comparison = legacy();
  const record = source(comparison.run_ids[0]!, true);
  if (reason === "null member") record.steps = [null, ...record.steps] as unknown as RunRecord["steps"];
  if (reason === "missing step ID") record.steps = [{ status: "success" }, ...record.steps] as unknown as RunRecord["steps"];
  if (reason === "invalid status") record.steps[0] = { ...record.steps[0], status: null } as unknown as RunRecord["steps"][number];
  if (reason === "invalid method") record.steps[0] = { ...record.steps[0], action_id: 17 } as unknown as RunRecord["steps"][number];
  mountResult(comparison, [record]);
  for (const attempt of within(lanes()[0]!).getAllByRole("listitem")) {
    expect(within(attempt).getByText("Node collect 8")).toBeVisible();
    expect(within(attempt).getByText("Method details unavailable")).toBeVisible();
  }
  expect(stoppedCell(0)).toHaveTextContent("Node collect 8");
  expect(screen.queryByText("Unrelated current method")).not.toBeInTheDocument();
  expect(screen.queryByText("Unrelated current action")).not.toBeInTheDocument();
});

it.each([false, true])("does not infer missing attempt identities from a captured scenario (malformed: %s)", malformed => {
  const comparison = legacy();
  const record = source(comparison.run_ids[0]!);
  record.steps = record.steps.map(({ step_id, status }) => ({ step_id, status }));
  if (malformed) record.scenario = { steps: null } as unknown as NonNullable<RunRecord["scenario"]>;
  mountResult(comparison, [record]);
  expect(stoppedCell(0)).toHaveTextContent("Node collect 8");
  const steps = within(lanes()[0]!).getAllByRole("listitem");
  expect(within(steps[0]!).getByText("Node collect 8")).toBeVisible();
  expect(screen.queryByText("Unrelated current method")).not.toBeInTheDocument();
});
