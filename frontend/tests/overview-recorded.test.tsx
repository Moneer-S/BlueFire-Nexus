import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { api, type DeltaSummary, type RecordingSummary } from "../src/lib/api";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { OverviewPage } from "../src/pages/Overview";
import { ProductProvider } from "../src/state/ProductContext";

const shipped: RecordingSummary = {
  id: "lab-run-1",
  title: "60 published tests on one Linux host",
  kind: "test list",
  source: { engine: "bluefire-lab", environment: "GitHub-hosted runner", started: "2026-11-23T17:25:50Z", finished: "2026-11-23T17:36:23Z" },
  score: { steps: 60, took_effect: 60, alerted: 3, seen: 56, unseen: 1, stopped: 8 },
  counts: { steps: 91, events: 1931, alerts: 233 },
  origin: { kind: "shipped", run_url: "https://github.com/example/bluefire/actions/runs/1", note: "Shipped with BlueFire." },
  running: false,
};

const imported = (id: string, title: string, started: string): RecordingSummary => ({
  ...shipped, id, title, source: { ...shipped.source, started, finished: started }, origin: { kind: "imported", note: "Imported." },
});

function pairOf(before: RecordingSummary, after: RecordingSummary, id: string): DeltaSummary {
  const side = (summary: RecordingSummary) => ({ sha256: "a".repeat(64), id: summary.id, environment: "GitHub-hosted runner", started: summary.source.started });
  return {
    id, claim: "one pair of runs", declared_change: "sensors:auditd", comparable: true, refused_because: [],
    counts: { paired: 91, same: 90, better: 1, worse: 0, changed: 0, "not attributable": 0, "without cause": 0, "no verdict": 0, new: 0, gone: 0 },
    before: side(before), after: side(after), recordings: { before, after }, origin: { kind: before.origin.kind === "shipped" && after.origin.kind === "shipped" ? "shipped" : "imported", note: "A pair." },
  } as DeltaSummary;
}

function mount(recordings: RecordingSummary[], deltas: DeltaSummary[], answer?: ReturnType<typeof api.recordings>) {
  if (answer) vi.spyOn(api, "recordings").mockReturnValue(answer);
  else vi.spyOn(api, "recordings").mockResolvedValue({ recordings, unreadable_count: 0, omitted_count: 0 });
  vi.spyOn(api, "recordingDeltas").mockResolvedValue({ deltas, unreadable_count: 0, omitted_count: 0 });
  vi.spyOn(api, "catalog").mockResolvedValue(structuredClone(demoCatalog));
  vi.spyOn(api, "runs").mockResolvedValue({ runs: [], unavailable_run_count: 0 });
  vi.spyOn(api, "scenarios").mockResolvedValue({ scenarios: [structuredClone(demoScenario)] });
  vi.spyOn(api, "activeJobs").mockResolvedValue({ schema_version: "bluefire.active-job-list.v1", jobs: [] });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter initialEntries={["/"]}><OverviewPage /></MemoryRouter></ProductProvider></QueryClientProvider>);
}

describe("what the Overview offers of the recorded runs", () => {
  it("offers the shipped run first on Runs over an imported pair of later runs", async () => {
    const before = imported("later-before", "Later before", "2026-11-28T10:00:00Z");
    const after = imported("later-after", "Later after", "2026-11-29T10:00:00Z");
    mount([shipped, before, after], [pairOf(before, after, "0000000000000001")]);
    const link = await screen.findByRole("link", { name: /^Watch the first recorded run on Runs/ });
    expect(link).toHaveTextContent("60 published tests on one Linux host");
    expect(link).toHaveTextContent("Shipped with BlueFire · 3 of 60 tests alerted, 56 seen, 1 unseen");
    expect(link).toHaveAttribute("href", "/runs/recorded/lab-run-1");
    expect(screen.queryByRole("link", { name: /^See the newest change to the defense/ })).not.toBeInTheDocument();
    // The run that leads the page is the same shipped run, never the later imported ones.
    const real = screen.getByRole("region", { name: "A run recorded in CI" });
    expect(real).toHaveTextContent("60 published tests on one Linux host");
    expect(screen.getByRole("link", { name: "Play the run: 60 published tests on one Linux host" })).toHaveAttribute("href", "/runs/recorded/lab-run-1");
  });

  it("holds the real run's place above the workspace while the recordings are asked for", async () => {
    let answer: (value: Awaited<ReturnType<typeof api.recordings>>) => void = () => undefined;
    mount([shipped], [], new Promise((resolve) => { answer = resolve; }));
    const waiting = await screen.findByRole("region", { name: "Recorded runs" });
    expect(waiting).toHaveAttribute("aria-busy", "true");
    expect(waiting).toHaveTextContent(/^Loading recorded runs$/);
    const workspace = await screen.findByRole("heading", { name: /^(Example plan|Working draft)$/ });
    expect(waiting.compareDocumentPosition(workspace) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    await act(async () => { answer({ recordings: [shipped], unreadable_count: 0, omitted_count: 0 }); await Promise.resolve(); });
    expect(await screen.findByRole("region", { name: "A run recorded in CI" })).toHaveTextContent("60 published tests on one Linux host");
    expect(screen.queryByRole("region", { name: "Recorded runs" })).not.toBeInTheDocument();
  });

  it("offers the newer of an imported run and an imported pair when nothing is shipped", async () => {
    const before = imported("pair-before", "Pair before", "2026-11-24T10:00:00Z");
    const after = imported("pair-after", "Pair after", "2026-11-25T10:00:00Z");
    const later = imported("later-run", "A later run", "2026-11-30T10:00:00Z");
    mount([before, after, later], [pairOf(before, after, "0000000000000002")]);
    const link = await screen.findByRole("link", { name: /^Watch the first recorded run on Runs/ });
    expect(link).toHaveTextContent("A later run");
    expect(link).toHaveTextContent("Imported, not verified by BlueFire");
    expect(screen.queryByRole("link", { name: /^See the newest change to the defense/ })).not.toBeInTheDocument();
  });

  it("offers an imported pair whose runs are newer than every imported run of its own", async () => {
    const older = imported("older-run", "An older run", "2026-11-20T10:00:00Z");
    const before = imported("pair-before", "Pair before", "2026-11-24T10:00:00Z");
    const after = imported("pair-after", "Pair after", "2026-11-25T10:00:00Z");
    mount([older, before, after], [pairOf(before, after, "0000000000000003")]);
    const link = await screen.findByRole("link", { name: /^See the newest change to the defense/ });
    expect(link).toHaveAttribute("href", "/runs/compared/0000000000000003");
    expect(screen.queryByRole("link", { name: /^Watch the first recorded run on Runs/ })).not.toBeInTheDocument();
  });
});
