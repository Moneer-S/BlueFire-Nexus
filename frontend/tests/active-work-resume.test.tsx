import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, useLocation } from "react-router-dom";

const { loadActiveWork, scenarios, runs, catalog } = vi.hoisted(() => ({
  loadActiveWork: vi.fn(),
  scenarios: vi.fn(),
  runs: vi.fn(),
  catalog: vi.fn(),
}));

vi.mock("../src/lib/active-defensive-work", async importOriginal => ({
  ...await importOriginal<typeof import("../src/lib/active-defensive-work")>(),
  loadActiveWork,
  activeWorkHref: ({ family, id }: { family: string; id: string }) => `/${family}?saved=${id}`,
}));
vi.mock("../src/lib/api", async importOriginal => {
  const actual = await importOriginal<typeof import("../src/lib/api")>();
  return { ...actual, DEMO_MODE: false, api: { ...actual.api, scenarios, runs, catalog } };
});
vi.mock("../src/state/ProductContext", () => ({
  useProduct: () => ({
    scenario: { id: "scenario-draft", title: "Current draft", purpose: "Draft remains editable", start: "step-start", steps: [{ id: "step-start", behavior_id: "sample", inputs: {} }], edges: [] },
    scenarioIsSeededFallback: false,
    dirty: true,
    runConfig: { mode: "simulate", autonomy: "review", scopeRefs: [], profileId: "", },
  }),
}));
vi.mock("../src/components/SavedDefensiveWork", () => ({ SavedDefensiveWork: () => null }));

import { ActiveWorkResume } from "../src/components/ActiveWorkResume";
import { OverviewPage } from "../src/pages/Overview";
import { useActiveDefensiveWork, useRememberDefensiveWork, rememberActiveDefensiveWork } from "../src/state/activeDefensiveWork";

const reference = { family: "domain" as const, id: `job-${"a".repeat(32)}` };
const otherReference = { family: "cloud" as const, id: `job-${"b".repeat(32)}` };

function summary(ref: typeof reference | typeof otherReference = reference, overrides: Record<string, unknown> = {}) {
  return {
    reference: ref,
    title: "Saved access review",
    objective: "Review the recorded access change.",
    environment: "Protected test environment",
    phase: "Legitimate retest",
    recordedState: "completed",
    change: "Recorded policy: hardened",
    results: [{ label: "Recorded reads", value: "Probe denied; owner allowed" }],
    href: `/${ref.family}?saved=${ref.id}`,
    links: [{ label: "Open saved evidence", href: `/runs/${ref.id}` }],
    ...overrides,
  };
}

function newClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } } });
}

function StateReader({ family = "domain", verifiedId }: { family?: "domain" | "cloud"; verifiedId?: string }) {
  const active = useActiveDefensiveWork();
  useRememberDefensiveWork(family, verifiedId);
  return <output aria-label="Active reference">{active ? `${active.family}:${active.id}` : "none"}</output>;
}

function Location() {
  const location = useLocation();
  return <output aria-label="Current route">{location.pathname}{location.search}</output>;
}

function mountResume(ref = reference) {
  const client = newClient();
  const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={["/overview?tab=work"]}><ActiveWorkResume reference={ref} /><Location /></MemoryRouter></QueryClientProvider>);
  return { ...view, client };
}

function mountOverview() {
  const client = newClient();
  const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={["/overview?tab=work"]}><OverviewPage /><Location /></MemoryRouter></QueryClientProvider>);
  return { ...view, client };
}

beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  rememberActiveDefensiveWork(undefined);
  scenarios.mockResolvedValue({ scenarios: [] });
  runs.mockResolvedValue({ runs: [], unavailable_run_count: 0 });
  catalog.mockResolvedValue({ behaviors: [], runner_profiles: [] });
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  window.localStorage.clear();
  rememberActiveDefensiveWork(undefined);
});

describe("active work resume", () => {
  it("registers only a verified reference and leaves it intact for missing or invalid workflow data", async () => {
    const view = render(<StateReader verifiedId={undefined} />);
    expect(screen.getByLabelText("Active reference")).toHaveTextContent("none");

    view.rerender(<StateReader verifiedId={reference.id} />);
    await waitFor(() => expect(screen.getByLabelText("Active reference")).toHaveTextContent(`domain:${reference.id}`));

    view.rerender(<StateReader verifiedId={undefined} />);
    expect(screen.getByLabelText("Active reference")).toHaveTextContent(`domain:${reference.id}`);
    rememberActiveDefensiveWork({ family: "domain", id: "not-a-validated-job" } as never);
    expect(screen.getByLabelText("Active reference")).toHaveTextContent(`domain:${reference.id}`);
  });

  it("reopens the stored reference after remount and falls back to in-memory state when storage is unavailable", async () => {
    const first = render(<StateReader verifiedId={reference.id} />);
    await waitFor(() => expect(screen.getByLabelText("Active reference")).toHaveTextContent(`domain:${reference.id}`));
    first.unmount();
    render(<StateReader />);
    expect(screen.getByLabelText("Active reference")).toHaveTextContent(`domain:${reference.id}`);

    cleanup();
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => { throw new Error("storage blocked"); });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("storage blocked"); });
    const memoryOnly = render(<StateReader verifiedId={reference.id} />);
    await waitFor(() => expect(screen.getByLabelText("Active reference")).toHaveTextContent(`domain:${reference.id}`));
    memoryOnly.unmount();
    render(<StateReader />);
    expect(screen.getByLabelText("Active reference")).toHaveTextContent(`domain:${reference.id}`);
  });

  it("keeps the newly selected record when an older request resolves late", async () => {
    let resolveFirst!: (value: ReturnType<typeof summary>) => void;
    let resolveSecond!: (value: ReturnType<typeof summary>) => void;
    loadActiveWork.mockImplementation((ref: typeof reference | typeof otherReference) => new Promise(resolve => {
      if (ref.id === reference.id) resolveFirst = resolve;
      else resolveSecond = resolve;
    }));
    const client = newClient();
    const view = render(<QueryClientProvider client={client}><MemoryRouter><ActiveWorkResume reference={reference} /></MemoryRouter></QueryClientProvider>);
    view.rerender(<QueryClientProvider client={client}><MemoryRouter><ActiveWorkResume reference={otherReference} /></MemoryRouter></QueryClientProvider>);

    resolveSecond(summary(otherReference, { title: "Newly selected record", objective: "Second reference" }));
    expect(await screen.findByText("Second reference")).toBeInTheDocument();
    resolveFirst(summary(reference, { title: "Stale record", objective: "First reference" }));
    await waitFor(() => expect(screen.getByText("Second reference")).toBeInTheDocument());
    expect(screen.queryByText("First reference")).not.toBeInTheDocument();
  });

  it("rechecks a remounted objective despite a fresh global cache and marks retained evidence while checking", async () => {
    let finishRefresh!: (value: ReturnType<typeof summary>) => void;
    loadActiveWork.mockResolvedValueOnce(summary(reference, { phase: "Earlier stage" })).mockImplementationOnce(() => new Promise(resolve => { finishRefresh = resolve; }));
    const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 15_000, gcTime: 60_000 } } });
    const tree = (key = 0) => <QueryClientProvider client={client}><MemoryRouter key={key}><ActiveWorkResume reference={reference} /></MemoryRouter></QueryClientProvider>;
    const view = render(tree());
    expect(await screen.findByText("Earlier stage")).toBeInTheDocument();
    view.unmount();

    render(tree(1));
    expect(screen.getByText("Earlier stage")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Checking the current saved state");
    finishRefresh(summary(reference, { phase: "Current stage" }));
    expect(await screen.findByText("Current stage")).toBeInTheDocument();
    expect(screen.queryByText("Checking the current saved state")).not.toBeInTheDocument();
  });

  it("preserves the last loaded evidence and its route when refreshing fails", async () => {
    loadActiveWork.mockResolvedValueOnce(summary()).mockRejectedValueOnce(new Error("offline"));
    const user = userEvent.setup();
    mountResume();
    expect(await screen.findByText("Review the recorded access change.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Refresh active objective" }));
    expect(await screen.findByText("Previously loaded evidence. Its current state could not be checked.")).toBeInTheDocument();
    expect(screen.getByText("Probe denied; owner allowed")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Continue objective/ })).toHaveAttribute("href", `/${reference.family}?saved=${reference.id}`);
    expect(screen.getByLabelText("Current route")).toHaveTextContent("/overview?tab=work");
  });

  it("shows the current draft without changing its contents when the active objective is dismissed", async () => {
    const draftBytes = JSON.stringify({ title: "Current draft", marker: "keep-this-local-work" });
    window.localStorage.setItem("bluefire.local.scenario.v1", draftBytes);
    rememberActiveDefensiveWork(reference);
    loadActiveWork.mockResolvedValue(summary());
    const user = userEvent.setup();
    mountOverview();
    expect(await screen.findByRole("heading", { name: "Active objective" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Show working draft" }));
    expect(await screen.findByRole("heading", { name: "Working draft" })).toBeInTheDocument();
    expect(screen.getByText("Current draft")).toBeInTheDocument();
    expect(screen.getByText("Draft remains editable")).toBeInTheDocument();
    expect(screen.getByLabelText("Current route")).toHaveTextContent("/overview?tab=work");
    expect(window.localStorage.getItem("bluefire.local.active-defensive-work.v1")).toBeNull();
    expect(window.localStorage.getItem("bluefire.local.scenario.v1")).toBe(draftBytes);
  });

  it("adds exact saved phase context without changing objective outcomes or fetching the owner twice", async () => {
    rememberActiveDefensiveWork(reference);
    const records = ["baseline", "protected", "legitimate", "unrelated"].map((phase, index) => ({
      run_id: `run-${phase}`, scenario_id: "receiver-collection", scenario_title: "Public record handoff",
      created_at: `2026-10-25T12:0${index}:00Z`, mode: "execute", status: phase === "protected" ? "incomplete" : "completed",
      objective_reached: phase !== "protected", is_demo: false,
    }));
    const before = structuredClone(records);
    runs.mockResolvedValue({ runs: records, unavailable_run_count: 0 });
    loadActiveWork.mockResolvedValue(summary(reference, { runContexts: [
      { runId: "run-baseline", phase: "Baseline", receiverDecision: "Accepted by the receiver" },
      { runId: "run-protected", phase: "Redaction required", receiverDecision: "Prevented by the receiver" },
      { runId: "run-legitimate", phase: "Legitimate redacted use", receiverDecision: "Accepted by the receiver" },
    ] }));
    const user = userEvent.setup();
    mountOverview();
    const recent = within(await screen.findByRole("region", { name: "Recent outcomes" }));
    await recent.findByText("Redaction required");
    const row = within(recent.getByText("Redaction required").closest("tr")!);
    expect(row.getByText("Not achieved")).toBeVisible();
    expect(row.getByText("Incomplete")).toBeVisible();
    expect(row.getByText("Prevented by the receiver")).toBeVisible();
    expect(row.getByRole("link")).toHaveAttribute("href", "/runs/run-protected");
    const unrelated = within(recent.getAllByRole("link", { name: "Public record handoff" })[3]!.closest("tr")!);
    expect(unrelated.queryByText(/by the receiver/)).not.toBeInTheDocument();
    expect(unrelated.queryByText(/Baseline|Redaction required|Legitimate redacted use/)).not.toBeInTheDocument();
    expect(loadActiveWork).toHaveBeenCalledTimes(1);
    expect(records).toEqual(before);
    await user.click(screen.getByRole("button", { name: "Show working draft" }));
    expect(recent.queryByText("Redaction required")).not.toBeInTheDocument();
    expect(recent.queryByText("Prevented by the receiver")).not.toBeInTheDocument();
    expect(recent.getAllByRole("link", { name: "Public record handoff" })).toHaveLength(4);
  });
});
