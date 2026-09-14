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

function renderBuilder() {
  window.localStorage.clear();
  window.localStorage.setItem("bluefire.local.scenario.v1", JSON.stringify(demoScenario));
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
