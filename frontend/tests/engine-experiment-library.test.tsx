import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { EngineExperimentLibrary } from "../src/components/EngineExperimentLibrary";
import { engineExperimentApi, type EngineExperimentHead } from "../src/lib/engine-experiment-api";
import { actionWorkspace } from "./engine-action-fixture";

const clients: QueryClient[] = [];
afterEach(() => { clients.splice(0).forEach(client => client.clear()); vi.restoreAllMocks(); });
const head = (index: number): EngineExperimentHead => ({ schema_version: "bluefire.engine-experiment-head.v1", experiment_id: `experiment-${String(index).repeat(32)}`, active_revision: 1, active_digest: `sha256:${"b".repeat(64)}`, created_at: "2026-11-04T12:00:00Z", updated_at: `2026-11-04T12:0${index}:00Z` });
function mount(heads: EngineExperimentHead[]) {
  vi.spyOn(engineExperimentApi, "list").mockResolvedValue({ schema_version: "bluefire.engine-experiment-list.v1", experiments: heads });
  vi.spyOn(engineExperimentApi, "workspace").mockImplementation(async id => {
    const value = actionWorkspace();
    return { ...value, experiment_id: id, objective: { ...value.objective, title: `Saved ${id}` }, projection: { ...value.projection, conclusion: { defense: { state: "not_reviewed" }, cleanup: { status: "not_started" } } as typeof value.projection.conclusion } };
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } }); clients.push(client);
  return render(<QueryClientProvider client={client}><MemoryRouter><EngineExperimentLibrary /></MemoryRouter></QueryClientProvider>);
}

it("browses beyond Home's five records and resumes exact saved identities without creating work", async () => {
  const user = userEvent.setup();
  const prepare = vi.spyOn(engineExperimentApi, "prepare");
  const submit = vi.spyOn(engineExperimentApi, "submit");
  mount([1, 2, 3, 4, 5, 6].map(head));
  const newest = await screen.findByRole("link", { name: `Saved ${head(6).experiment_id}` });
  expect(newest).toHaveAttribute("href", `/composition?engine_experiment=${head(6).experiment_id}`);
  expect(screen.getByText("Showing 1 to 5 of 6 saved experiments.")).toBeVisible();
  expect(engineExperimentApi.workspace).toHaveBeenCalledTimes(5);
  expect(engineExperimentApi.workspace).not.toHaveBeenCalledWith(head(1).experiment_id);
  const next = screen.getByRole("button", { name: "Next" }); next.focus(); await user.keyboard("{Enter}");
  expect(await screen.findByRole("link", { name: `Saved ${head(1).experiment_id}` })).toHaveAttribute("href", `/composition?engine_experiment=${head(1).experiment_id}`);
  expect(screen.getByText("Showing 6 to 6 of 6 saved experiments.")).toBeVisible();
  expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
  expect(prepare).not.toHaveBeenCalled(); expect(submit).not.toHaveBeenCalled();
});

it("withholds a resume link when the checked head no longer matches the workspace", async () => {
  mount([head(1)]);
  vi.mocked(engineExperimentApi.workspace).mockResolvedValue({ ...actionWorkspace(), revision: 2 });
  expect(await screen.findByText("Saved experiment unavailable")).toBeVisible();
  expect(screen.queryByRole("link", { name: /Saved experiment-/ })).not.toBeInTheDocument();
});

it("shows an honest empty installed history with no browser create action", async () => {
  mount([]);
  expect(await screen.findByText("No saved defense experiment")).toBeVisible();
  expect(engineExperimentApi.workspace).not.toHaveBeenCalled();
  expect(screen.queryByRole("button", { name: /create|start/i })).not.toBeInTheDocument();
});
