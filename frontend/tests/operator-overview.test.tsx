import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { OverviewPage } from "../src/pages/Overview";
import { ProductProvider } from "../src/state/ProductContext";
import { api } from "../src/lib/api";
import { demoCatalog, demoRuns, demoScenario } from "../src/lib/demo";

let clients: QueryClient[] = [];
beforeEach(() => {
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "receiverTests").mockResolvedValue({ schema_version: "bluefire.receiver-defense-list.v1", jobs: [], truncated: false, next_cursor: null });
  vi.spyOn(api, "runs").mockResolvedValue({ runs: [], unavailable_run_count: 0 });
  vi.spyOn(api, "scenarios").mockResolvedValue({ scenarios: [demoScenario] });
});
afterEach(() => { clients.forEach(client => client.clear()); clients = []; });
function mount(client = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } })) {
  clients.push(client);
  return { client, ...render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter><OverviewPage/></MemoryRouter></ProductProvider></QueryClientProvider>) };
}
it("does not turn an unavailable run history into an empty history", async () => {
  vi.mocked(api.runs).mockRejectedValue(new Error("History request failed"));
  mount();
  expect(await screen.findByText("Run history unavailable")).toBeVisible();
  expect(screen.queryByText("No runs have been recorded.")).not.toBeInTheDocument();
  expect(screen.getByRole("heading", { name: "Example plan" })).toBeVisible();
  expect(screen.getByText("Built-in example")).toBeVisible();
  expect(screen.getByRole("link", { name: "Open example plan" })).toHaveAttribute("href", "/builder");
  expect(screen.queryByRole("heading", { name: "Working draft" })).not.toBeInTheDocument();
});
it("retries only failed run history and replaces the unavailable state with a real empty result", async () => {
  vi.mocked(api.runs).mockRejectedValueOnce(new Error("History request failed")).mockResolvedValue({ runs: [], unavailable_run_count: 0 });
  const user = userEvent.setup(); mount();
  await screen.findByText("Run history unavailable");
  await user.click(screen.getByRole("button", { name: "Try again" }));
  expect(await screen.findByText("No runs have been recorded.")).toBeVisible();
  expect(api.runs).toHaveBeenCalledTimes(2); expect(api.scenarios).toHaveBeenCalledTimes(1);
});
it("preserves cached runs when refreshing their state fails", async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  client.setQueryData(["runs"], { runs: [demoRuns[0]] });
  vi.mocked(api.runs).mockRejectedValue(new Error("Service stopped"));
  mount(client);
  expect(await screen.findByText("Showing previously loaded runs. Their current state could not be checked.")).toBeVisible();
  expect(screen.getByRole("table").querySelector("tbody tr")).not.toBeNull();
  expect(screen.queryByText("No runs have been recorded.")).not.toBeInTheDocument();
});
it("keeps experiment failure separate from successfully empty run history", async () => {
  vi.mocked(api.scenarios).mockRejectedValue(new Error("Library request failed")); mount();
  expect(await screen.findByText("Experiments unavailable")).toBeVisible();
  expect(await screen.findByText("No runs have been recorded.")).toBeVisible();
  expect(screen.queryByText("No experiments are available.")).not.toBeInTheDocument();
});
it("shows loading until history actually responds", async () => {
  let release!: (value: {runs: typeof demoRuns; unavailable_run_count: number}) => void;
  vi.mocked(api.runs).mockImplementation(() => new Promise(resolve => { release = resolve; }));
  mount(); expect(screen.getByText("Loading run history")).toBeVisible();
  expect(screen.queryByText("No runs have been recorded.")).not.toBeInTheDocument();
  await act(async () => release({ runs: [], unavailable_run_count: 0 }));
  await waitFor(() => expect(screen.getByText("No runs have been recorded.")).toBeVisible());
});
it("opens the exact experiment in the library without replacing the current draft", async () => {
  mount();
  expect(await screen.findByRole("link", {name:"Open in library"})).toHaveAttribute("href", "/scenarios?selected=" + encodeURIComponent(demoScenario.id));
  expect(screen.queryByText("Active experiment")).not.toBeInTheDocument();
  expect(screen.queryByRole("heading", {name:"Readiness"})).not.toBeInTheDocument();
});

it("distinguishes a retained working draft from the built-in example without renaming it", async () => {
  const draft = { ...structuredClone(demoScenario), title: "My collection review" };
  localStorage.setItem("bluefire.local.scenario.v1", JSON.stringify(draft));
  mount();
  expect(screen.getByRole("heading", { name: "Working draft" })).toBeVisible();
  expect(screen.getByRole("heading", { name: draft.title })).toBeVisible();
  expect(screen.queryByRole("heading", { name: "Example plan" })).not.toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Continue editing" })).toHaveAttribute("href", "/builder");
  expect(screen.getByText("Unsaved changes")).toBeVisible();
  expect(JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!)).toEqual(draft);
});

it("reports unreadable records without claiming there are no runs", async () => {
  vi.mocked(api.runs).mockResolvedValue({ runs: [], unavailable_run_count: 2 }); mount();
  expect(await screen.findByText(/2 run records are unavailable/)).toBeVisible();
  expect(screen.queryByText("No runs have been recorded.")).not.toBeInTheDocument();
});

it("shows recorded objective outcomes separately from completed process status without changing review links", async () => {
  const cases = [
    { title: "Simulated objective reached", mode: "simulate", reached: true, label: "Achieved (synthetic)" },
    { title: "Executed objective reached", mode: "execute", reached: true, label: "Achieved" },
    { title: "Completed without objective", mode: "execute", reached: false, label: "Not achieved" },
    { title: "Completed without reported result", mode: "simulate", reached: undefined, label: "Not established" },
  ] as const;
  const runs = cases.map((item, index) => ({ ...structuredClone(demoRuns[0]!),
    run_id: `run-20261025T120000Z-${String(index).padStart(16, "0")}`,
    scenario: undefined, presentation: undefined, scenario_title: item.title,
    mode: item.mode, status: "completed", objective_reached: item.reached,
  }));
  const before = structuredClone(runs);
  vi.mocked(api.runs).mockResolvedValue({ runs, unavailable_run_count: 0 });
  mount();
  const recent = within(await screen.findByRole("region", { name: "Recent outcomes" }));
  expect(await recent.findByRole("columnheader", { name: "Outcome" })).toBeVisible();
  for (const [index, item] of cases.entries()) {
    const link = recent.getByRole("link", { name: item.title });
    expect(link).toHaveAttribute("href", `/runs/${runs[index]!.run_id}`);
    const row = within(link.closest("tr")!);
    const outcome = within(row.getAllByRole("cell")[2]!);
    expect(outcome.getByText(item.label, { exact: true })).toBeVisible();
    expect(outcome.getByText("Completed", { exact: true })).toBeVisible();
    expect(outcome.getByText("Run status:", { exact: true })).toHaveClass("sr-only");
    expect(row.getByText(item.mode === "simulate" ? "Simulate" : "Execute", { exact: true })).toBeVisible();
  }
  expect(api.runs).toHaveBeenCalledTimes(1);
  expect(runs).toEqual(before);
});
