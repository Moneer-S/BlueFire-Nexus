import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import * as Tooltip from "@radix-ui/react-tooltip";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { compareDemoRuns, demoCatalog, demoRuns } from "../src/lib/demo";
import { ComparePage } from "../src/pages/Compare";
import type { ComparisonResponse, SavedComparisonSnapshot, SavedComparisonSummary } from "../src/types";

const runIds = demoRuns.slice(0, 2).map((run) => run.run_id);
const original = compareDemoRuns(runIds);
const rows: SavedComparisonSummary[] = ["snapshot-a", "snapshot-b"].map((snapshot_id) => ({
  snapshot_id, digest: `${snapshot_id}-digest`, created_at: "2026-10-18T12:00:00Z", run_ids: runIds, baseline_run_id: runIds[0]!,
}));

function saved(snapshotId: string, integrity: SavedComparisonSnapshot["source_integrity"] = {
  status: "verified", runs: runIds.map((run_id) => ({ run_id, status: "verified" })),
}): SavedComparisonSnapshot {
  return { snapshot_id: snapshotId, digest: `${snapshotId}-digest`, created_at: "2026-10-18T12:00:00Z", comparison: structuredClone(original), source_bindings: runIds.map((run_id) => ({ run_id, bundle_hash: "bundle-hash" })), source_integrity: integrity };
}

function mount(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><Tooltip.Provider><MemoryRouter initialEntries={[path]}><ComparePage /></MemoryRouter></Tooltip.Provider></QueryClientProvider>);
}

function mocks() {
  vi.spyOn(api, "runs").mockResolvedValue({ schema_version: "v1", runs: demoRuns, unavailable_run_count: 0 });
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "comparisonSnapshots").mockResolvedValue({ snapshots: rows });
}

afterEach(() => vi.restoreAllMocks());

it("saves a new comparison, reopens it, and reloads with GET only", async () => {
  const user = userEvent.setup();
  mocks();
  const compare = vi.spyOn(api, "compare").mockResolvedValue({ ...structuredClone(original), saved_snapshot: { snapshot_id: "snapshot-a", digest: "snapshot-a-digest", created_at: "2026-10-18T12:00:00Z" } });
  const read = vi.spyOn(api, "comparisonSnapshot").mockResolvedValue(saved("snapshot-a"));
  mount("/compare");
  await screen.findByRole("heading", { name: "Saved comparisons" });
  const boxes = screen.getAllByRole("checkbox");
  await user.click(boxes[0]!);
  await user.click(boxes[1]!);
  await user.click(screen.getByRole("button", { name: "Compare selected" }));
  await screen.findByRole("region", { name: "Comparison results" });
  await waitFor(() => expect(read).toHaveBeenCalledWith("snapshot-a"));
  expect(compare).toHaveBeenCalledOnce();

  await user.click(screen.getByRole("button", { name: "Reload saved comparisons" }));
  await waitFor(() => expect(read).toHaveBeenCalledTimes(2));
  expect(compare).toHaveBeenCalledOnce();
});

it("opens a missing-source snapshot as historical evidence without recomputing", async () => {
  mocks();
  const compare = vi.spyOn(api, "compare");
  vi.spyOn(api, "comparisonSnapshot").mockResolvedValue(saved("snapshot-a", {
    status: "unavailable", runs: [{ run_id: runIds[0]!, status: "verified" }, { run_id: runIds[1]!, status: "missing" }],
  }));
  mount("/compare?snapshot=snapshot-a");
  expect(await screen.findByText(/shown as saved and was not recomputed/)).toBeVisible();
  expect(screen.getByRole("region", { name: "Comparison results" })).toBeVisible();
  expect(compare).not.toHaveBeenCalled();
});

it("does not let an earlier snapshot request replace a later navigation", async () => {
  const user = userEvent.setup();
  mocks();
  let resolveFirst!: (result: SavedComparisonSnapshot) => void;
  const first = new Promise<SavedComparisonSnapshot>((resolve) => { resolveFirst = resolve; });
  const read = vi.spyOn(api, "comparisonSnapshot").mockImplementation((id) => id === "snapshot-a" ? first : Promise.resolve(saved("snapshot-b")));
  const compare = vi.spyOn(api, "compare");
  mount("/compare?snapshot=snapshot-a");
  await screen.findByRole("button", { name: "Open saved comparison snapshot-b" });
  await user.click(screen.getByRole("button", { name: "Open saved comparison snapshot-b" }));
  await screen.findByRole("region", { name: "Comparison results" });
  await act(async () => { resolveFirst(saved("snapshot-a")); await first; });
  expect(screen.getByRole("button", { name: "Open saved comparison snapshot-b" })).toHaveAttribute("aria-current", "page");
  expect(screen.getByRole("button", { name: "Open saved comparison snapshot-a" })).not.toHaveAttribute("aria-current", "page");
  expect(read).toHaveBeenCalledTimes(2);
  expect(compare).not.toHaveBeenCalled();
});

it("does not let a pending comparison replace a snapshot opened with the same runs", async () => {
  const user = userEvent.setup();
  mocks();
  let finish!: (result: ComparisonResponse) => void;
  const pending = new Promise<ComparisonResponse>((resolve) => { finish = resolve; });
  const compare = vi.spyOn(api, "compare").mockReturnValue(pending);
  vi.spyOn(api, "comparisonSnapshot").mockResolvedValue(saved("snapshot-a"));
  mount("/compare");
  await screen.findByRole("button", { name: "Open saved comparison snapshot-a" });
  const boxes = screen.getAllByRole("checkbox");
  await user.click(boxes[0]!);
  await user.click(boxes[1]!);
  await user.click(screen.getByRole("button", { name: "Compare selected" }));
  await user.click(screen.getByRole("button", { name: "Open saved comparison snapshot-a" }));
  await screen.findByRole("region", { name: "Comparison results" });
  await act(async () => {
    finish({ ...structuredClone(original), saved_snapshot: { snapshot_id: "stale-post-result", digest: "stale", created_at: "2026-10-18T12:00:00Z" } });
    await pending;
  });
  expect(compare).toHaveBeenCalledOnce();
  expect(screen.getByRole("button", { name: "Open saved comparison snapshot-a" })).toHaveAttribute("aria-current", "page");
  expect(screen.queryByRole("button", { name: "Open saved comparison stale-post-result" })).not.toBeInTheDocument();
});
