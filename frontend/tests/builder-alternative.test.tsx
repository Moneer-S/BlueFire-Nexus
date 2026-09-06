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

function renderBuilder() {
  window.localStorage.setItem("bluefire.local.scenario.v1", JSON.stringify(scenario));
  window.localStorage.setItem("bluefire.local.run-config.v1", JSON.stringify({ schema_version: UI_PREFERENCE_SCHEMA_VERSION, theme: "dark", effect_mode: "execute", autonomy: "off" }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(["catalog"], catalog);
  vi.spyOn(api, "catalog").mockResolvedValue(catalog);
  return render(<QueryClientProvider client={client}><Tooltip.Provider><MemoryRouter initialEntries={["/builder"]}><ProductProvider><StateWitness /><Routes><Route path="/builder" element={<BuilderPage />} /><Route path="/runs" element={<><h1>Run review navigation witness</h1><Link to="/builder">Back to Builder</Link></>} /></Routes></ProductProvider></MemoryRouter></Tooltip.Provider></QueryClientProvider>);
}

function draft() { return JSON.parse(screen.getByLabelText("Full scenario witness").textContent!); }
function configuration() { return JSON.parse(screen.getByLabelText("Run configuration witness").textContent!); }

describe("Builder alternative method selection", () => {
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
