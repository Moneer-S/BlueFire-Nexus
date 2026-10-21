import * as Tooltip from "@radix-ui/react-tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { BuilderPage } from "../src/pages/Builder";
import { ProductProvider, useProduct } from "../src/state/ProductContext";
import type { Scenario } from "../src/types";

const initial: Scenario = { ...structuredClone(demoScenario), layout: Object.fromEntries(demoScenario.steps.map((step, i) => [step.id, { x: 13 + i * 17, y: 29 + i * 41 }])) };
const replacement: Scenario = { ...structuredClone(initial), id: "externally-loaded-experiment", title: "Loaded experiment", purpose: "Preserve the external graph", steps: initial.steps.map((step) => ({ ...structuredClone(step), parameters: { ...step.parameters, operator_note: "loaded value" } })) };

function Witness() {
  const { scenario, setScenario } = useProduct();
  return <><output aria-label="Active graph">{JSON.stringify(scenario)}</output><button onClick={() => setScenario(structuredClone(replacement), false)}>Load external scenario</button></>;
}

function setup(scenario: Scenario = initial) {
  window.localStorage.setItem("bluefire.local.scenario.v1", JSON.stringify(scenario));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(["catalog"], demoCatalog);
  render(<QueryClientProvider client={client}><Tooltip.Provider><MemoryRouter><ProductProvider><Witness /><BuilderPage /></ProductProvider></MemoryRouter></Tooltip.Provider></QueryClientProvider>);
  return userEvent.setup();
}

function graph(): Scenario { return JSON.parse(screen.getByLabelText("Active graph").textContent!); }
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

describe("Builder draft and validation identity", () => {
  it("arranges only the focused group and keeps that explicit change undoable", async () => {
    window.sessionStorage.clear();
    const scenario: Scenario = {
      ...structuredClone(demoScenario),
      steps: Array.from({ length: 6 }, (_, index) => ({ ...structuredClone(demoScenario.steps[0]!), id: `group-step-${index}`, inputs: {} })),
      start: "group-step-0",
      edges: Array.from({ length: 5 }, (_, index) => ({ from_step: `group-step-${index}`, outcome: "success" as const, to_step: `group-step-${index + 1}` })),
      layout: { "group-step-0": { x: 900, y: 700 }, "group-step-1": { x: 1200, y: 300 } },
    };
    const user = setup(scenario);
    const group = await screen.findByRole("combobox", { name: "Step group" });
    await user.selectOptions(group, "1");
    const arrange = await screen.findByRole("button", { name: "Arrange visible group" });
    await user.click(arrange);
    const arranged = graph().layout!;
    expect(Object.keys(arranged).sort()).toEqual(["group-step-0", "group-step-1", "group-step-3", "group-step-4", "group-step-5"]);
    expect(arranged["group-step-0"]).toEqual(scenario.layout!["group-step-0"]);
    expect(arranged["group-step-1"]).toEqual(scenario.layout!["group-step-1"]);
    for (const id of ["group-step-3", "group-step-4", "group-step-5"]) expect(Number.isFinite(arranged[id]!.x) && Number.isFinite(arranged[id]!.y)).toBe(true);
    await user.click(screen.getByRole("button", { name: "Undo" }));
    expect(graph().layout).toEqual(scenario.layout);
  }, 20000);

  it.each(["valid", "invalid", "error"] as const)("ignores a delayed %s response after an edit and validates the current graph on a fresh request", async (outcome) => {
    const pending = deferred<Awaited<ReturnType<typeof api.validate>>>();
    const validate = vi.spyOn(api, "validate").mockReturnValueOnce(pending.promise).mockResolvedValue({ valid: true, issues: [] });
    const user = setup();
    await user.click(screen.getByRole("button", { name: "Validate" }));
    expect(validate.mock.calls[0]![0]).toEqual(initial);
    await user.click(screen.getByRole("button", { name: "Arrange visible group" }));
    const edited = graph();
    expect(edited).not.toEqual(initial);
    await act(async () => {
      if (outcome === "error") pending.reject(new Error("obsolete request failure"));
      else pending.resolve({ valid: outcome === "valid", issues: outcome === "invalid" ? ["place_fixture obsolete finding"] : [] });
    });
    await waitFor(() => expect(screen.getByRole("button", { name: "Validate" })).toBeEnabled());
    expect(screen.getByText("Not validated", { exact: true })).toBeVisible();
    expect(screen.queryByText(/obsolete (finding|request failure)/)).not.toBeInTheDocument();
    expect(document.querySelector(".flow-node.invalid")).toBeNull();
    expect(graph()).toEqual(edited);
    await user.click(screen.getByRole("button", { name: "Validate" }));
    expect(await screen.findByText("Experiment validated", { exact: true })).toBeVisible();
    expect(validate.mock.calls[1]![0]).toEqual(edited);
    await user.click(screen.getByRole("button", { name: "Undo" }));
    expect(graph()).toEqual(initial);
    expect(screen.getByText("Not validated", { exact: true })).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Redo" }));
    expect(graph()).toEqual(edited);
    expect(screen.getByText("Not validated", { exact: true })).toBeVisible();
  }, 20000);

  it("accepts a validation response for the unchanged submitted snapshot", async () => {
    const pending = deferred<Awaited<ReturnType<typeof api.validate>>>();
    vi.spyOn(api, "validate").mockReturnValue(pending.promise);
    const user = setup();
    await user.click(screen.getByRole("button", { name: "Validate" }));
    await act(async () => pending.resolve({ valid: true, issues: [] }));
    expect(await screen.findByText("Ready for review", { exact: true })).toBeVisible();
    expect(graph()).toEqual(initial);
  }, 20000);

  it("uses an external context replacement as the new undo seed and discards its predecessor's pending validation", async () => {
    const pending = deferred<Awaited<ReturnType<typeof api.validate>>>();
    vi.spyOn(api, "validate").mockReturnValue(pending.promise);
    const user = setup();
    await user.click(screen.getByRole("button", { name: "Validate" }));
    await user.click(screen.getByRole("button", { name: "Arrange visible group" }));
    expect(screen.getByRole("button", { name: "Undo" })).toBeEnabled();
    await user.click(screen.getByRole("button", { name: "Load external scenario" }));
    expect(graph()).toEqual(replacement);
    expect(screen.getByRole("button", { name: "Undo" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Redo" })).toBeDisabled();
    await act(async () => pending.resolve({ valid: true, issues: [] }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Validate" })).toBeEnabled());
    expect(screen.getByText("Not validated", { exact: true })).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Arrange visible group" }));
    const edited = graph();
    expect(edited).not.toEqual(replacement);
    expect(edited.steps).toEqual(replacement.steps);
    expect(edited.edges).toEqual(replacement.edges);
    await user.click(screen.getByRole("button", { name: "Undo" }));
    expect(graph()).toEqual(replacement);
    expect(screen.getByRole("button", { name: "Undo" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Redo" }));
    expect(graph()).toEqual(edited);
    expect(JSON.parse(window.localStorage.getItem("bluefire.local.scenario.v1")!)).toEqual(edited);
  }, 20000);
});
