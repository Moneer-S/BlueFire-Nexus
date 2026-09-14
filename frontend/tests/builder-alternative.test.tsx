import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import * as Tooltip from "@radix-ui/react-tooltip";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Link, MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { selectScenarioAlternative } from "../src/lib/scenario";
import { BuilderPage } from "../src/pages/Builder";
import { ProductProvider, UI_PREFERENCE_SCHEMA_VERSION, useProduct } from "../src/state/ProductContext";
import type { Behavior, Scenario } from "../src/types";

const stage = demoCatalog.behaviors.find((behavior) => behavior.id === "sandbox.collection.stage.v1")!;
const primary: Behavior = { ...structuredClone(stage), id: "sandbox.collection.records.v1", title: "Selected-record collection", compatible_behaviors: ["sandbox.collection.archive.v1"] };
const alternative: Behavior = { ...structuredClone(primary), id: "sandbox.collection.archive.v1", title: "Whole-file collection", compatible_behaviors: [primary.id] };
const catalog = { ...structuredClone(demoCatalog), behaviors: [...demoCatalog.behaviors, primary, alternative] };
const behaviors = new Map(catalog.behaviors.map((behavior) => [behavior.id, behavior]));
const scenario: Scenario = {
  ...structuredClone(demoScenario),
  title: "Method selection preserves the full graph",
  steps: demoScenario.steps.map((step) => step.id === "stage" ? { ...structuredClone(step), behavior_id: primary.id, parameters: { bundle_format: "jsonl", reviewed_label: "retained operator parameter" }, alternates: [alternative.id] } : structuredClone(step)),
  layout: Object.fromEntries(demoScenario.steps.map((step, index) => [step.id, { x: 100 + index * 13, y: 200 + index * 29 }])),
};
const swapped: Scenario = { ...scenario, steps: scenario.steps.map((step) => step.id === "stage" ? { ...step, behavior_id: alternative.id, alternates: [primary.id] } : step) };

function StateWitness() {
  const { scenario: current, runConfig, setRunConfig } = useProduct();
  return <>
    <output aria-label="Full scenario witness">{JSON.stringify(current)}</output>
    <output aria-label="Run configuration witness">{JSON.stringify(runConfig)}</output>
    <button onClick={() => setRunConfig({ ...runConfig, actionImplementations: { stage: primary.id, place_fixture: "sandbox.fixture.create.v1" } })}>Select reviewed actions</button>
    <button onClick={() => setRunConfig({ ...runConfig, approved: true, approvedBy: "test-operator" })}>Set ephemeral approval witness</button>
  </>;
}

function renderBuilder(initial = scenario) {
  window.localStorage.setItem("bluefire.local.scenario.v1", JSON.stringify(initial));
  window.localStorage.setItem("bluefire.local.run-config.v1", JSON.stringify({ schema_version: UI_PREFERENCE_SCHEMA_VERSION, theme: "dark", effect_mode: "execute", autonomy: "off" }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(["catalog"], catalog);
  vi.spyOn(api, "catalog").mockResolvedValue(catalog);
  return render(<QueryClientProvider client={client}><Tooltip.Provider><MemoryRouter initialEntries={["/builder"]}><ProductProvider><StateWitness /><Routes><Route path="/builder" element={<BuilderPage />} /><Route path="/runs" element={<><h1>Run review navigation witness</h1><Link to="/builder">Back to Builder</Link></>} /></Routes></ProductProvider></MemoryRouter></Tooltip.Provider></QueryClientProvider>);
}

function draft() { return JSON.parse(screen.getByLabelText("Full scenario witness").textContent!); }
function configuration() { return JSON.parse(screen.getByLabelText("Run configuration witness").textContent!); }

describe("Builder alternative method selection", () => {
  it("saves exact retry choices, reopens them in the graph, and requires repair after an alternative is removed", async () => {
    const user = userEvent.setup();
    const save = vi.spyOn(api, "saveScenarioVersion").mockImplementation(async document => ({
      schema_version: "bluefire.scenario-version.v1", scenario: { scenario_id: document.id, title: document.title, version: 2,
        digest: "saved-version", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z", document: structuredClone(document) },
    }));
    const rendered = renderBuilder();
    await user.click(screen.getByRole("button", { name: "Steps" }));
    await user.click(within(screen.getByRole("list", { name: "Experiment steps" })).getByRole("button", { name: /^4 Selected-record collection/ }));
    await user.click(screen.getByRole("button", { name: "Configure adaptive retry" }));
    const methods = within(screen.getByRole("group", { name: "Permitted methods" })).getAllByRole("checkbox");
    expect(methods[0]).toBeChecked();
    await user.click(methods[1]!);
    await user.click(screen.getByRole("button", { name: "Apply retry choices" }));
    const expected = draft();
    expect(expected.adaptive_execution.steps).toEqual([{ step_id: "stage", methods: [
      { behavior_id: primary.id, action_id: primary.action_ids[0] },
      { behavior_id: alternative.id, action_id: alternative.action_ids[0] },
    ] }]);
    expect(expected.steps).toEqual(scenario.steps);
    await user.click(screen.getByRole("button", { name: "Save version" }));
    expect(await screen.findByText("Version 2 saved.")).toBeVisible();
    expect(save.mock.calls[0]![0]).toEqual(expected);
    const reopened = (await save.mock.results[0]!.value).scenario.document;
    rendered.unmount();
    renderBuilder(reopened);
    expect(draft()).toEqual(expected);
    await user.click(screen.getByRole("button", { name: "Steps" }));
    await user.click(within(screen.getByRole("list", { name: "Experiment steps" })).getByRole("button", { name: /^4 Selected-record collection/ }));
    for (const choice of within(screen.getByRole("group", { name: "Permitted methods" })).getAllByRole("checkbox")) expect(choice).toBeChecked();
    await user.click(screen.getByRole("checkbox", { name: "Whole-file collection" }));
    expect(screen.getByRole("region", { name: "Retry choices need attention" })).toBeVisible();
    expect(draft().adaptive_execution).toEqual(expected.adaptive_execution);
    await user.click(screen.getByRole("button", { name: "Save version" }));
    expect(save).toHaveBeenCalledOnce();
    await user.click(screen.getByRole("button", { name: "Apply retry choices" }));
    expect(draft()).toEqual(expected);
  }, 20000);

  it("changes the selected method, preserves the full draft and invalidates only affected authority across undo, redo and navigation", async () => {
    const user = userEvent.setup();
    const validate = vi.spyOn(api, "validate").mockResolvedValue({ valid: true, issues: [] });
    const save = vi.spyOn(api, "saveScenarioVersion");
    const run = vi.spyOn(api, "submitRun");
    renderBuilder();
    await user.click(screen.getByRole("button", { name: "Select reviewed actions" }));
    await user.click(screen.getByRole("button", { name: "Set ephemeral approval witness" }));
    expect(configuration().approved).toBe(true);
    await user.click(screen.getByRole("button", { name: "Steps" }));
    await user.click(within(screen.getByRole("list", { name: "Experiment steps" })).getByRole("button", { name: /^4 Selected-record collection/ }));
    await user.click(screen.getByRole("button", { name: "Validate" }));
    expect(await screen.findByText("Experiment validated", { exact: true })).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Use Whole-file collection for this step" }));
    expect(draft()).toEqual(swapped);
    expect(screen.getByText(/is the primary method for this step/)).toHaveTextContent("Whole-file collection is the primary method for this step.");
    expect(screen.queryByText(/is saved with this experiment/)).not.toBeInTheDocument();
    expect(JSON.parse(window.localStorage.getItem("bluefire.local.scenario.v1")!)).toEqual(swapped);
    expect(screen.getByText("Not validated", { exact: true })).toBeVisible();
    expect(configuration().actionImplementations).toEqual({ place_fixture: "sandbox.fixture.create.v1" });
    expect(configuration().approved).toBe(false);
    expect(configuration().approvedBy).toBe("");
    expect(screen.getByText(/Whole-file collection selected\. Inputs, parameters, and connections are preserved/)).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Undo" }));
    expect(draft()).toEqual(scenario);
    expect(configuration().approved).toBe(false);
    expect(configuration().actionImplementations).toEqual({ place_fixture: "sandbox.fixture.create.v1" });
    await user.click(screen.getByRole("button", { name: "Redo" }));
    expect(draft()).toEqual(swapped);
    await user.click(screen.getByRole("link", { name: "Review run" }));
    expect(await screen.findByRole("heading", { name: "Run review navigation witness" })).toBeVisible();
    expect(draft()).toEqual(swapped);
    await user.click(screen.getByRole("link", { name: "Back to Builder" }));
    await waitFor(() => expect(screen.getByRole("textbox", { name: "Experiment name" })).toHaveValue(swapped.title));
    expect(draft()).toEqual(swapped);
    expect(configuration().actionImplementations).toEqual({ place_fixture: "sandbox.fixture.create.v1" });
    expect(configuration().approved).toBe(false);
    expect(validate).toHaveBeenCalledOnce();
    expect(validate.mock.calls[0]![0]).toEqual(scenario);
    expect(save).not.toHaveBeenCalled();
    expect(run).not.toHaveBeenCalled();
  }, 20000);

  it.each(["not-installed.v1", "sandbox.fixture.create.v1"])("refuses unknown or undeclared target %s without changing any draft field", (target) => {
    const before = structuredClone(scenario);
    expect(() => selectScenarioAlternative(scenario, "stage", target, behaviors)).toThrow(/available alternative/);
    expect(scenario).toEqual(before);
  });

  it("rejects a missing step or current primary and does not mutate its source when selecting a declared alternative", () => {
    expect(() => selectScenarioAlternative(scenario, "missing-step", alternative.id, behaviors)).toThrow();
    expect(() => selectScenarioAlternative(scenario, "stage", primary.id, behaviors)).toThrow();
    const before = structuredClone(scenario);
    expect(selectScenarioAlternative(scenario, "stage", alternative.id, behaviors)).toEqual(swapped);
    expect(scenario).toEqual(before);
  });
});
