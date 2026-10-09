import * as Tooltip from "@radix-ui/react-tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { api, ApiError } from "../src/lib/api";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { BuilderPage } from "../src/pages/Builder";
import { ProductProvider } from "../src/state/ProductContext";
import type { Scenario } from "../src/types";

function disconnectedGraph(): Scenario {
  const steps = Array.from({ length: 13 }, (_, index) => ({ ...structuredClone(demoScenario.steps[0]!), id: `step_${index + 1}` }));
  return { ...structuredClone(demoScenario), start: steps[0]!.id, steps, edges: steps.slice(1, -1).map((step, index) => ({ from_step: steps[index]!.id, outcome: "success", to_step: step.id })), layout: undefined };
}
function mount(scenario = disconnectedGraph()) {
  localStorage.setItem("bluefire.local.scenario.v1", JSON.stringify(scenario));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(["catalog"], demoCatalog);
  return render(<QueryClientProvider client={client}><Tooltip.Provider><MemoryRouter><ProductProvider><BuilderPage/></ProductProvider></MemoryRouter></Tooltip.Provider></QueryClientProvider>);
}
function rejection(code: "scenario_invalid" | "scenario_version_invalid") {
  return new ApiError("Scenario validation failed.", code, ["scenario contains unreachable steps: step_13"], 422);
}
function graph(): Scenario { return JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!); }

it.each(["Validate", "Save version"] as const)("shows an actionable %s refusal and reveals the disconnected step without changing the graph", async (action) => {
  const validate = vi.spyOn(api, "validate").mockRejectedValue(rejection("scenario_invalid"));
  const save = vi.spyOn(api, "saveScenarioVersion").mockRejectedValue(rejection("scenario_version_invalid"));
  const before = disconnectedGraph();
  const view = mount(before);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: action }));
  expect(await screen.findByText("Review the affected steps")).toBeVisible();
  const feedback = view.container.querySelector(".validation-bar") as HTMLElement;
  expect(feedback).toHaveAttribute("role", "alert");
  expect(within(feedback).getByText(/Place deterministic fixture \(step 13\): This step cannot be reached.*Connect a route/)).toBeVisible();
  expect(screen.queryByText("Check the highlighted steps")).not.toBeInTheDocument();
  expect(view.container.querySelector('.react-flow__node[data-id="step_13"]')).toBeNull();
  if (action === "Save version") {
    expect(save).toHaveBeenCalledExactlyOnceWith(before);
    expect(validate).not.toHaveBeenCalled();
    expect(view.container.querySelector(".compatibility-banner")).toHaveClass("error");
    expect(view.container.querySelector(".compatibility-banner")).toHaveAttribute("role", "alert");
    expect(localStorage.getItem("bluefire.local.scenario-saved.v1")).toBeNull();
    expect(screen.getByText("Unsaved changes")).toBeVisible();
  } else {
    expect(validate).toHaveBeenCalledExactlyOnceWith(before);
    expect(save).not.toHaveBeenCalled();
  }
  await user.click(within(feedback).getByRole("button", { name: "Show Place deterministic fixture (step 13)" }));
  await waitFor(() => expect(screen.getByTestId("rf__node-step_13")).toHaveClass("selected"));
  expect(screen.getByTestId("rf__node-step_13").querySelector(".flow-node")).toHaveClass("invalid");
  expect(screen.getByLabelText(/^Step ID/)).toHaveValue("step_13");
  expect(screen.getByRole("combobox", { name: "Path section" })).toHaveValue("all");
  expect(graph()).toEqual(JSON.parse(JSON.stringify(before)));
}, 15000);

it("does not attach a delayed save refusal to a newer edit", async () => {
  let reject!: (error: Error) => void;
  const pending = new Promise<Awaited<ReturnType<typeof api.saveScenarioVersion>>>((_, no) => { reject = no; });
  const save = vi.spyOn(api, "saveScenarioVersion").mockReturnValue(pending);
  const view = mount();
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Save version" }));
  expect(save).toHaveBeenCalledOnce();
  const name = screen.getByRole("textbox", { name: "Experiment name" });
  await user.clear(name);
  await user.type(name, "Newer graph revision");
  const edited = graph();
  await act(async () => reject(rejection("scenario_version_invalid")));
  await waitFor(() => expect(screen.getByRole("button", { name: "Save version" })).toBeEnabled());
  expect(screen.queryByText(/Save refused/)).not.toBeInTheDocument();
  expect(screen.getByText("Not validated", { exact: true })).toBeVisible();
  expect(view.container.querySelector(".flow-node.invalid")).toBeNull();
  expect(graph()).toEqual(edited);
  expect(localStorage.getItem("bluefire.local.scenario-saved.v1")).toBeNull();
}, 15000);

it("keeps unknown service failures private and does not claim a highlighted defect", async () => {
  vi.spyOn(api, "validate").mockRejectedValue(new ApiError("Traceback C:\\example\\internal.py", "scenario_invalid", [{ stack: "confidential value" }], 422));
  const view = mount(demoScenario);
  await userEvent.click(await screen.findByRole("button", { name: "Validate" }));
  expect(await screen.findByText("Review the validation findings")).toBeVisible();
  expect(screen.getByText(/Review the experiment’s steps, connections and parameters/)).toBeVisible();
  expect(view.container).not.toHaveTextContent(/Traceback|internal\.py|confidential value/);
  expect(view.container.querySelector(".flow-node.invalid")).toBeNull();
  expect(within(view.container.querySelector(".validation-bar") as HTMLElement).queryByRole("button")).not.toBeInTheDocument();
});
