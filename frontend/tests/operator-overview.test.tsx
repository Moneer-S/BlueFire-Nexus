import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { OverviewPage } from "../src/pages/Overview";
import { ProductProvider } from "../src/state/ProductContext";
import { api } from "../src/lib/api";
import { demoRuns, demoScenario } from "../src/lib/demo";

let clients: QueryClient[] = [];
beforeEach(() => {
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
  expect(screen.getByRole("heading", { name: "Working draft" })).toBeVisible();
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

it("reports unreadable records without claiming there are no runs", async () => {
  vi.mocked(api.runs).mockResolvedValue({ runs: [], unavailable_run_count: 2 }); mount();
  expect(await screen.findByText(/2 run records are unavailable/)).toBeVisible();
  expect(screen.queryByText("No runs have been recorded.")).not.toBeInTheDocument();
});
