import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import * as Tooltip from "@radix-ui/react-tooltip";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Link, MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { BuilderPage } from "../src/pages/Builder";
import { ProductProvider, useProduct } from "../src/state/ProductContext";

function NavigationTarget() {
  const { scenario, setScenario, dirty } = useProduct();
  return <><h1>Navigation target</h1><output>{dirty ? "Unsaved target" : "Saved target"}</output><button onClick={() => setScenario({ ...scenario, title: "Newer scenario after navigation" })}>Change scenario after navigation</button><Link to="/builder">Return to Builder</Link></>;
}

function renderBuilder(scenario = demoScenario) {
  window.localStorage.setItem("bluefire.local.scenario.v1", JSON.stringify(scenario));
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(["catalog"], demoCatalog);
  return render(<QueryClientProvider client={client}><Tooltip.Provider><MemoryRouter initialEntries={["/builder"]}><ProductProvider><Routes><Route path="/builder" element={<BuilderPage />} /><Route path="/runs" element={<NavigationTarget />} /></Routes></ProductProvider></MemoryRouter></Tooltip.Provider></QueryClientProvider>);
}

describe("Builder selection and navigation", () => {
  it.each([false, true])("reconciles a save after Builder unmount without clearing a later edit: %s", async (editAfterNavigation) => {
    let finishSave!: (value: Awaited<ReturnType<typeof api.saveScenarioVersion>>) => void;
    const pending = new Promise<Awaited<ReturnType<typeof api.saveScenarioVersion>>>((resolve) => { finishSave = resolve; });
    const save = vi.spyOn(api, "saveScenarioVersion").mockReturnValue(pending);
    const user = userEvent.setup();
    renderBuilder();
    const name = await screen.findByRole("textbox", { name: "Experiment name" });
    await user.type(name, " submitted");
    await user.click(screen.getByRole("button", { name: "Save version" }));
    await waitFor(() => expect(save).toHaveBeenCalledOnce());
    const submitted = save.mock.calls[0]![0];
    await user.click(screen.getByRole("link", { name: "Review run" }));
    expect(await screen.findByRole("heading", { name: "Navigation target" })).toBeVisible();
    if (editAfterNavigation) await user.click(screen.getByRole("button", { name: "Change scenario after navigation" }));
    await act(async () => finishSave({ schema_version: "bluefire.scenario-version.v1", scenario: { scenario_id: submitted.id, title: submitted.title, version: 2, digest: "a".repeat(64), created_at: "2030-01-01T00:00:00Z", document: submitted } }));
    expect(await screen.findByText(editAfterNavigation ? "Unsaved target" : "Saved target")).toBeVisible();
    const leaving = new Event("beforeunload", { cancelable: true });
    window.dispatchEvent(leaving);
    expect(leaving.defaultPrevented).toBe(editAfterNavigation);
    await user.click(screen.getByRole("link", { name: "Return to Builder" }));
    expect(await screen.findByRole("textbox", { name: "Experiment name" })).toHaveValue(editAfterNavigation ? "Newer scenario after navigation" : submitted.title);
    expect(screen.getByText(editAfterNavigation ? "Unsaved changes" : "Working copy", { exact: true })).toBeVisible();
  });

  it.each(["copy", "delete", "duplicate"])("preserves a hidden selected branch during %s", async (operation) => {
    const user = userEvent.setup();
    vi.spyOn(window, "confirm").mockReturnValue(true);
    renderBuilder();
    await user.click(await screen.findByRole("button", { name: "Steps" }));
    await user.click(screen.getByRole("button", { name: "Show all branches" }));
    const branch = demoScenario.steps.find((step) => step.id === "fallback")!;
    const title = demoCatalog.behaviors.find((behavior) => behavior.id === branch.behavior_id)!.title;
    const branchName = new RegExp(`^\\d+ ${title}`);
    await user.click(within(screen.getByRole("list", { name: "Experiment steps" })).getByRole("button", { name: branchName }));
    if (operation === "duplicate") await user.click(screen.getByRole("button", { name: "Copy selected node" }));
    await user.click(screen.getByRole("button", { name: "Focus on success path" }));
    expect(within(screen.getByRole("list", { name: "Experiment steps" })).queryByRole("button", { name: branchName })).not.toBeInTheDocument();
    if (operation === "copy") {
      await user.keyboard("{Control>}c{/Control}");
      await user.keyboard("{Control>}v{/Control}");
    } else if (operation === "duplicate") {
      await user.keyboard("{Control>}d{/Control}");
    } else {
      await user.click(screen.getByRole("button", { name: "Delete selected node" }));
    }
    const cached = JSON.parse(window.localStorage.getItem("bluefire.local.scenario.v1")!);
    expect(cached).toEqual(demoScenario);
    expect(screen.getByRole("button", { name: "Delete selected node" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Copy selected node" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Duplicate selected node" })).toBeDisabled();
    expect(window.confirm).not.toHaveBeenCalled();
  }, 15000);

  it("still copies and deletes the visible selected step", async () => {
    const user = userEvent.setup();
    vi.spyOn(window, "confirm").mockReturnValue(true);
    renderBuilder();
    await user.click(await screen.findByRole("button", { name: "Steps" }));
    await user.keyboard("{Control>}c{/Control}");
    await user.keyboard("{Control>}v{/Control}");
    await waitFor(() => expect(JSON.parse(window.localStorage.getItem("bluefire.local.scenario.v1")!).steps).toHaveLength(demoScenario.steps.length + 1));
    const added = JSON.parse(window.localStorage.getItem("bluefire.local.scenario.v1")!).steps.at(-1) as { id: string };
    expect(screen.getByLabelText(/^Step ID/)).toHaveValue(added.id);
    await waitFor(() => expect(screen.getByTestId(`rf__node-${added.id}`)).toHaveClass("selected"));
    await user.click(screen.getByRole("button", { name: "Delete selected node" }));
    await waitFor(() => expect(JSON.parse(window.localStorage.getItem("bluefire.local.scenario.v1")!)).toEqual(demoScenario));
    expect(window.confirm).toHaveBeenCalledOnce();
  }, 15000);

  it("preserves the visible selection when changing sections and returning from the step list", async () => {
    const scenario: typeof demoScenario = { ...structuredClone(demoScenario), start: "step_1", steps: Array.from({ length: 17 }, (_, index) => ({ ...structuredClone(demoScenario.steps[0]!), id: `step_${index + 1}` })), edges: [], layout: undefined };
    scenario.edges = scenario.steps.slice(1).map((step, index) => ({ from_step: scenario.steps[index]!.id, outcome: "success", to_step: step.id }));
    const user = userEvent.setup();
    renderBuilder(scenario);
    await user.click(await screen.findByRole("button", { name: "Next section" }));
    expect(screen.getByRole("combobox", { name: "Path section" })).toHaveValue("1");
    expect(screen.getByRole("button", { name: "Copy selected node" })).toBeEnabled();
    await user.click(screen.getByRole("button", { name: "Steps" }));
    const list = within(screen.getByRole("list", { name: "Experiment steps" }));
    expect(list.getByRole("button", { pressed: true })).toHaveAccessibleName(/^9 /);
    await user.click(list.getAllByRole("button").at(-1)!);
    await user.click(screen.getByRole("button", { name: "Canvas" }));
    expect(screen.getByRole("combobox", { name: "Path section" })).toHaveValue("2");
    expect(screen.getByRole("button", { name: "Copy selected node" })).toBeEnabled();
  }, 15000);
});
