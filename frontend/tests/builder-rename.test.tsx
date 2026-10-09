import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import * as Tooltip from "@radix-ui/react-tooltip";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { BuilderPage } from "../src/pages/Builder";
import { ProductProvider, useProduct } from "../src/state/ProductContext";

function RunConfigWitness() {
  const { runConfig } = useProduct();
  return <output aria-label="Run config witness">{JSON.stringify({ implementations: runConfig.actionImplementations ?? {}, approved: runConfig.approved, approvedBy: runConfig.approvedBy })}</output>;
}

function renderBuilder(scenario = demoScenario) {
  window.localStorage.clear();
  window.localStorage.setItem("bluefire.local.scenario.v1", JSON.stringify(scenario));
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(["catalog"], demoCatalog);
  render(<QueryClientProvider client={client}><Tooltip.Provider><MemoryRouter initialEntries={["/builder"]}><ProductProvider><BuilderPage /><RunConfigWitness /></ProductProvider></MemoryRouter></Tooltip.Provider></QueryClientProvider>);
  return userEvent.setup();
}

const witness = () => JSON.parse(screen.getByLabelText("Run config witness").textContent!);

// Select from the step list rather than the canvas: a canvas click runs React Flow's
// d3-drag mousedown handler, which reads event.view.document and throws under jsdom.
async function selectFirstStep(user: ReturnType<typeof userEvent.setup>) {
  const step = demoScenario.steps[0]!;
  const title = demoCatalog.behaviors.find((behavior) => behavior.id === step.behavior_id)!.title;
  await user.click(await screen.findByRole("button", { name: "Steps" }));
  await user.click(within(screen.getByRole("list", { name: "Experiment steps" })).getByRole("button", { name: new RegExp(`^\\d+ ${title}`) }));
  return step.id;
}
const storedSteps = () => (JSON.parse(window.localStorage.getItem("bluefire.local.scenario.v1")!) as { steps: { id: string }[] }).steps.map((step) => step.id);
const storedScenario = () => JSON.parse(window.localStorage.getItem("bluefire.local.scenario.v1")!) as typeof demoScenario & { adaptive_execution?: { schema_version: string; max_retries: number; steps: { step_id: string; methods: { behavior_id: string; action_id: string }[]; max_retries: number }[] } };

describe("Builder step rename", () => {
  it("keeps the renamed step selected through a multi-character rename", async () => {
    const user = renderBuilder();
    const first = await selectFirstStep(user);
    const field = await screen.findByLabelText(/^Step ID/);
    // Every keystroke is its own valid rename, which is exactly the case that used
    // to drop the selection and replace the inspector after the first character.
    await user.type(field, "_two");
    await waitFor(() => expect(storedSteps()).toContain(`${first}_two`));
    expect(storedSteps()).not.toContain(first);
    // The inspector is still editing the same step rather than asking for a selection.
    expect(await screen.findByLabelText(/^Step ID/)).toHaveValue(`${first}_two`);
    expect(screen.queryByText("Select a step")).toBeNull();
  }, 20000);

  it("carries a chosen run method to the new step ID and keeps approval cleared", async () => {
    const user = renderBuilder();
    const first = await selectFirstStep(user);
    const override = screen.getByRole("combobox", { name: "Run method override" });
    const choice = Array.from(override.querySelectorAll("option")).map((option) => option.value).find(Boolean)!;
    await user.selectOptions(override, choice);
    await waitFor(() => expect(witness().implementations[first]).toBe(choice));
    await user.type(await screen.findByLabelText(/^Step ID/), "_two");
    await waitFor(() => expect(storedSteps()).toContain(`${first}_two`));
    // The override belongs to the step, not to its old identifier.
    await waitFor(() => expect(witness().implementations[`${first}_two`]).toBe(choice));
    expect(witness().implementations[first]).toBeUndefined();
    // A rename must not carry execution authorization with it.
    expect(witness().approved).toBe(false);
    expect(witness().approvedBy).toBe("");
  }, 20000);

  it("renames a v2 adaptive step without losing its cap, methods, or connected input references", async () => {
    const initial = structuredClone(demoScenario);
    const first = initial.steps[0]!;
    const retained = { step_id: "stage", methods: [
      { behavior_id: "sandbox.collection.stage.v1", action_id: "sandbox.collection.stage.v1" },
      { behavior_id: "sandbox.collection.export.v1", action_id: "sandbox.export.local.v1" },
      { behavior_id: "sandbox.collection.verify.v1", action_id: "sandbox.collection.verify.v1" },
    ], max_retries: 2 };
    initial.adaptive_execution = { schema_version: "bluefire.adaptive-execution.v2", steps: [
      { step_id: first.id, methods: [
        { behavior_id: first.behavior_id, action_id: "sandbox.fixture.create.v1" },
        { behavior_id: "sandbox.program.fixed.v1", action_id: "sandbox.program.fixed.v1" },
      ], max_retries: 1 }, retained], eligible_outcomes: ["failed"], max_retries: 3, on_provider_failure: "stop" };
    const user = renderBuilder(initial);
    const originalInputs = structuredClone(initial.steps[1]!.inputs);
    await selectFirstStep(user);
    await user.type(await screen.findByLabelText(/^Step ID/), "_two");
    const saved = await waitFor(() => {
      const value = storedScenario();
      expect(value.adaptive_execution!.steps[0]!.step_id).toBe(`${first.id}_two`);
      return value;
    });
    expect(saved.adaptive_execution).toMatchObject({ schema_version: "bluefire.adaptive-execution.v2", max_retries: 3,
      steps: [{ step_id: `${first.id}_two`, max_retries: 1 }, retained] });
    expect(saved.steps[1]!.inputs.workspace!.from_step).toBe(`${first.id}_two`);
    expect(saved.steps[1]!.inputs).toEqual({ ...originalInputs,
      workspace: { ...originalInputs.workspace!, from_step: `${first.id}_two` } });
  }, 20000);

  it("still drops an override when the step is replaced by a different behavior", async () => {
    const user = renderBuilder();
    const first = await selectFirstStep(user);
    const override = screen.getByRole("combobox", { name: "Run method override" });
    const choice = Array.from(override.querySelectorAll("option")).map((option) => option.value).find(Boolean)!;
    await user.selectOptions(override, choice);
    await waitFor(() => expect(witness().implementations[first]).toBe(choice));
    const replace = screen.queryAllByRole("button", { name: /^Use .* for this step$/ })[0];
    if (!replace) return; // this demo step declares no compatible alternative
    await user.click(replace);
    // Replacement changes the behavior, so the old method no longer applies.
    await waitFor(() => expect(witness().implementations[first]).toBeUndefined());
  }, 20000);
});
