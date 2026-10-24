import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import * as Tooltip from "@radix-ui/react-tooltip";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { compareDemoRuns, demoCatalog, demoRuns } from "../src/lib/demo";
import { ComparePage } from "../src/pages/Compare";
import type { ComparisonResponse, RunRecord, SavedComparisonSnapshot, SavedComparisonSummary } from "../src/types";

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

function snapshotButton(snapshotId: string) {
  const button = document.querySelector<HTMLButtonElement>(`button[data-snapshot-id="${snapshotId}"]`);
  if (!button) throw new Error(`Saved comparison ${snapshotId} is not rendered`);
  return button;
}

function namedRun(run: RunRecord, name: string): RunRecord {
  return { ...run, presentation: { schema_version: "bluefire.run-presentation.v1", run_id: run.run_id, display_name: name, default_name: name, updated_at: null } };
}

afterEach(() => vi.restoreAllMocks());

it("shows one history header and puts reload before saved rows in keyboard order", async () => {
  const user = userEvent.setup();
  mocks();
  const compare = vi.spyOn(api, "compare");
  mount("/compare");
  const summary = await screen.findByText("Saved comparisons", { selector: "summary" });
  const history = summary.closest("details")!;
  expect(screen.getAllByText("Saved comparisons")).toHaveLength(1);
  await screen.findAllByRole("button", { name: /^Open saved comparison\./ });
  const firstRow = snapshotButton("snapshot-a");
  const reload = screen.getByRole("button", { name: "Reload saved comparisons" });
  await waitFor(() => expect(reload).toBeEnabled());

  await user.click(summary);
  expect(history).not.toHaveAttribute("open");
  expect(reload).not.toBeVisible();
  expect(firstRow).not.toBeVisible();
  await user.click(summary);
  expect(history).toHaveAttribute("open");
  expect(summary).toHaveFocus();
  await user.tab();
  expect(reload).toHaveFocus();
  await user.tab();
  expect(firstRow).toHaveFocus();
  await user.tab({ shift: true });
  expect(reload).toHaveFocus();
  await user.keyboard("{Enter}");
  await waitFor(() => expect(api.comparisonSnapshots).toHaveBeenCalledTimes(2));
  expect(history).toHaveAttribute("open");
  expect(compare).not.toHaveBeenCalled();
});

it("saves a new comparison, reopens it, and reloads with GET only", async () => {
  const user = userEvent.setup();
  mocks();
  const compare = vi.spyOn(api, "compare").mockResolvedValue({ ...structuredClone(original), saved_snapshot: { snapshot_id: "snapshot-a", digest: "snapshot-a-digest", created_at: "2026-10-18T12:00:00Z" } });
  const read = vi.spyOn(api, "comparisonSnapshot").mockResolvedValue(saved("snapshot-a"));
  mount("/compare");
  await screen.findByText("Saved comparisons", { selector: "summary" });
  const boxes = screen.getAllByRole("checkbox");
  await user.click(boxes[0]!);
  await user.click(boxes[1]!);
  await user.click(screen.getByRole("button", { name: "Compare selected" }));
  await screen.findByRole("region", { name: "Comparison results" });
  await waitFor(() => expect(read).toHaveBeenCalledWith("snapshot-a"));
  expect(compare).toHaveBeenCalledOnce();

  const savedBrowser = screen.getByText("Saved comparisons", { selector: "summary" });
  const history = savedBrowser.closest("details")!;
  await waitFor(() => expect(history).not.toHaveAttribute("open"));
  await user.click(savedBrowser);
  await user.click(snapshotButton("snapshot-a"));
  expect(history).toHaveAttribute("open");
  expect(snapshotButton("snapshot-a")).toHaveAttribute("aria-current", "page");
  expect(read).toHaveBeenCalledOnce();
  await user.click(savedBrowser);
  expect(history).not.toHaveAttribute("open");
  await user.click(savedBrowser);
  expect(history).toHaveAttribute("open");
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
  expect(screen.getByText("Saved comparisons", { selector: "summary" }).closest("details")).not.toHaveAttribute("open");
  expect(compare).not.toHaveBeenCalled();
});

it("keeps saved history visible after an explicit async selection without stealing later focus", async () => {
  const user = userEvent.setup();
  mocks();
  let resolveFirst!: (result: SavedComparisonSnapshot) => void;
  let resolveSecond!: (result: SavedComparisonSnapshot) => void;
  const first = new Promise<SavedComparisonSnapshot>(resolve => { resolveFirst = resolve; });
  const second = new Promise<SavedComparisonSnapshot>(resolve => { resolveSecond = resolve; });
  const read = vi.spyOn(api, "comparisonSnapshot").mockImplementation(id => id === "snapshot-a" ? first : second);
  const compare = vi.spyOn(api, "compare");
  mount("/compare");
  await screen.findAllByRole("button", { name: /^Open saved comparison\./ });
  const history = screen.getByText("Saved comparisons", { selector: "summary" }).closest("details")!;
  const firstButton = snapshotButton("snapshot-a");
  await user.click(firstButton);
  expect(firstButton).toHaveFocus();
  await act(async () => { resolveFirst(saved("snapshot-a")); await first; });
  await screen.findByRole("region", { name: "Comparison results" });
  expect(history).toHaveAttribute("open");
  expect(firstButton).toBeVisible();
  expect(firstButton).toHaveFocus();

  await user.click(snapshotButton("snapshot-b"));
  const otherControl = screen.getByRole("button", { name: "Refresh history" });
  await user.click(otherControl);
  await act(async () => { resolveSecond(saved("snapshot-b")); await second; });
  await screen.findByRole("region", { name: "Comparison results" });
  expect(snapshotButton("snapshot-b")).toHaveAttribute("aria-current", "page");
  expect(history).toHaveAttribute("open");
  expect(otherControl).toHaveFocus();
  expect(read).toHaveBeenCalledTimes(2);
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
  await screen.findAllByRole("button", { name: /^Open saved comparison\./ });
  await user.click(snapshotButton("snapshot-b"));
  await screen.findByRole("region", { name: "Comparison results" });
  await act(async () => { resolveFirst(saved("snapshot-a")); await first; });
  expect(snapshotButton("snapshot-b")).toHaveAttribute("aria-current", "page");
  expect(snapshotButton("snapshot-a")).not.toHaveAttribute("aria-current", "page");
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
  await screen.findAllByRole("button", { name: /^Open saved comparison\./ });
  const boxes = screen.getAllByRole("checkbox");
  await user.click(boxes[0]!);
  await user.click(boxes[1]!);
  await user.click(screen.getByRole("button", { name: "Compare selected" }));
  await user.click(snapshotButton("snapshot-a"));
  await screen.findByRole("region", { name: "Comparison results" });
  await act(async () => {
    finish({ ...structuredClone(original), saved_snapshot: { snapshot_id: "stale-post-result", digest: "stale", created_at: "2026-10-18T12:00:00Z" } });
    await pending;
  });
  expect(compare).toHaveBeenCalledOnce();
  expect(snapshotButton("snapshot-a")).toHaveAttribute("aria-current", "page");
  expect(document.querySelector('[data-snapshot-id="stale-post-result"]')).not.toBeInTheDocument();
});

it("names saved comparisons by their exact runs in recorded order, with date and count secondary", async () => {
  mocks();
  const named = [namedRun(demoRuns[0]!, "Original collection"), namedRun(demoRuns[1]!, "Redacted collection"), namedRun({ ...demoRuns[0]!, run_id: "third-run" }, "Fresh permission retest")];
  vi.mocked(api.runs).mockResolvedValue({ schema_version: "v1", runs: named, unavailable_run_count: 0 });
  const recordedIds = [named[2]!.run_id, named[0]!.run_id, named[1]!.run_id];
  vi.mocked(api.comparisonSnapshots).mockResolvedValue({ snapshots: [{ ...rows[0]!, run_ids: recordedIds, baseline_run_id: recordedIds[0]! }] });
  mount("/compare");
  const button = await screen.findByRole("button", { name: /^Open saved comparison\. Baseline: Fresh permission retest\. Compared run 1: Original collection\. Compared run 2: Redacted collection\. Saved / });
  expect(Array.from(button.querySelectorAll("strong"), node => node.textContent)).toEqual(["Baseline: Fresh permission retest", "Compared run 1: Original collection", "Compared run 2: Redacted collection"]);
  expect(button.querySelector("small")).toHaveTextContent(/3 runs$/);
  expect(button).not.toHaveTextContent("snapshot-a");
  expect(button).not.toHaveTextContent("third-run");
  expect(button).not.toHaveTextContent("digest");
});

it("keeps exact record identities in expandable details without starting a comparison", async () => {
  const user = userEvent.setup();
  mocks();
  const compare = vi.spyOn(api, "compare");
  const read = vi.spyOn(api, "comparisonSnapshot");
  mount("/compare");
  await screen.findAllByRole("button", { name: /^Open saved comparison\./ });
  const row = snapshotButton("snapshot-a").closest("li")!;
  const details = row.querySelector("details")!;
  const summary = within(row).getByText("Record details");
  expect(details).not.toHaveAttribute("open");
  summary.focus();
  expect(summary).toHaveFocus();
  await user.click(summary);
  expect(details).toHaveAttribute("open");
  expect(within(details).getByText("snapshot-a", { selector: "code" })).toBeVisible();
  expect(within(details).getByText("snapshot-a-digest", { selector: "code" })).toBeVisible();
  expect(Array.from(details.querySelectorAll("ol code"), node => node.textContent)).toEqual(runIds);
  expect(compare).not.toHaveBeenCalled();
  expect(read).not.toHaveBeenCalled();
});

it("does not substitute labels from duplicate or similar run identities", async () => {
  mocks();
  vi.mocked(api.runs).mockResolvedValue({ schema_version: "v1", runs: [
    namedRun(demoRuns[0]!, "First conflicting name"), namedRun(demoRuns[0]!, "Second conflicting name"),
    namedRun({ ...demoRuns[1]!, run_id: `${runIds[1]}-other` }, "Similar but unrelated run"),
  ], unavailable_run_count: 1 });
  mount("/compare");
  const buttons = await screen.findAllByRole("button", { name: /^Open saved comparison\. Baseline: Ambiguous run record\. Compared run 1: Run unavailable\. Saved / });
  expect(buttons).toHaveLength(2);
  for (const button of buttons) {
    expect(button).not.toHaveTextContent(/conflicting name|unrelated run/);
  }
});

it("retains long purpose labels in full instead of shortening them to identifiers", async () => {
  mocks();
  const longName = ["Verify", "Generated", "Collection", "Permission", "Recovery", "Across", "The", "Authorized", "Desktop", "Workspace", "Without", "Changing", "The", "Original", "Run"].join("");
  vi.mocked(api.runs).mockResolvedValue({ schema_version: "v1", runs: [namedRun(demoRuns[0]!, longName), namedRun(demoRuns[1]!, "Fresh retest")], unavailable_run_count: 0 });
  mount("/compare");
  await screen.findAllByRole("button", { name: /^Open saved comparison\./ });
  expect(snapshotButton("snapshot-a").querySelector("strong")).toHaveTextContent(`Baseline: ${longName}`);
  expect(snapshotButton("snapshot-a")).toHaveAccessibleName(expect.stringContaining(longName));
});
