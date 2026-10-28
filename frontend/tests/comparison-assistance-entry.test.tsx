import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import * as Tooltip from "@radix-ui/react-tooltip";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { compareDemoRuns, demoCatalog, demoRuns } from "../src/lib/demo";
import { ComparePage } from "../src/pages/Compare";
import { AssistanceProvider, useAssistancePanel, useAssistanceSelection } from "../src/state/AssistanceContext";
import type { ComparisonResponse, SavedComparisonSnapshot } from "../src/types";

const runIds = demoRuns.slice(0, 2).map(run => run.run_id);
const snapshotId = `run-comparison-${"a".repeat(64)}`;
const snapshotDigest = `sha256:${"a".repeat(64)}`;
const comparison = compareDemoRuns(runIds);
function savedSnapshot(): SavedComparisonSnapshot {
  return {
    snapshot_id: snapshotId, digest: snapshotDigest, created_at: "2026-10-20T12:00:00Z",
    comparison: structuredClone(comparison), source_bindings: runIds.map(run_id => ({ run_id, bundle_hash: "sha256:source" })),
    source_integrity: { status: "verified", runs: runIds.map(run_id => ({ run_id, status: "verified" })) },
  };
}
function SelectionProbe() {
  const selection = useAssistanceSelection();
  const panel = useAssistancePanel();
  const published = selection && "kind" in selection && selection.kind === "comparison" ? selection.selected : undefined;
  return <><output aria-label="Current comparison selection">{published ? JSON.stringify(published) : "none"}</output><output aria-label="Assistant open">{String(panel?.open)}</output></>;
}
function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><Tooltip.Provider><MemoryRouter initialEntries={[`/compare?snapshot=${snapshotId}`]}><AssistanceProvider><ComparePage /><SelectionProbe /></AssistanceProvider></MemoryRouter></Tooltip.Provider></QueryClientProvider>);
}
function setup() {
  vi.spyOn(api, "runs").mockResolvedValue({ schema_version: "v1", runs: demoRuns, unavailable_run_count: 0 });
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "comparisonSnapshots").mockResolvedValue({ snapshots: [{ snapshot_id: snapshotId, digest: snapshotDigest, created_at: "2026-10-20T12:00:00Z", run_ids: runIds, baseline_run_id: runIds[0]! }] });
}
afterEach(() => vi.restoreAllMocks());

it("publishes only after the loaded saved snapshot validates and keeps selection stable across rerenders", async () => {
  setup();
  let resolve!: (value: SavedComparisonSnapshot) => void;
  const pending = new Promise<SavedComparisonSnapshot>(done => { resolve = done; });
  const read = vi.spyOn(api, "comparisonSnapshot").mockReturnValue(pending);
  mount();
  expect(await screen.findByText("Opening saved comparison", { selector: "strong" })).toBeVisible();
  expect(screen.getByLabelText("Current comparison selection")).toHaveTextContent("none");
  expect(screen.queryByRole("button", { name: "Explain comparison" })).not.toBeInTheDocument();

  await act(async () => { resolve(savedSnapshot()); await pending; });
  expect(await screen.findByRole("region", { name: "Comparison results" })).toBeVisible();
  await waitFor(() => expect(screen.getByLabelText("Current comparison selection")).toHaveTextContent(JSON.stringify({ kind: "comparison_snapshot", snapshot_id: snapshotId, snapshot_digest: snapshotDigest })));
  const explain = screen.getByRole("button", { name: "Explain comparison" });
  expect(explain).toBeVisible();
  await userEvent.setup().click(explain);
  expect(screen.getByLabelText("Assistant open")).toHaveTextContent("true");
  expect(read).toHaveBeenCalledWith(snapshotId);
  expect(read).toHaveBeenCalledTimes(1);
});

it("does not publish transient comparison results as saved Assistant context", async () => {
  setup();
  const compare = vi.spyOn(api, "compare").mockResolvedValue(comparison as ComparisonResponse);
  const user = userEvent.setup();
  mount();
  await screen.findAllByRole("button", { name: /^Open saved comparison\./ });
  const checks = screen.getAllByRole("checkbox");
  await user.click(checks[0]!);
  await user.click(checks[1]!);
  await user.click(screen.getByRole("button", { name: "Compare selected" }));
  expect(await screen.findByRole("region", { name: "Comparison results" })).toBeVisible();
  expect(screen.getByLabelText("Current comparison selection")).toHaveTextContent("none");
  expect(screen.queryByRole("button", { name: "Explain comparison" })).not.toBeInTheDocument();
  expect(compare).toHaveBeenCalledOnce();
});
