import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import * as Tooltip from "@radix-ui/react-tooltip";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Link, MemoryRouter, Route, Routes } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { guaranteedInputSources } from "../src/lib/graph-authoring";
import { configurationForMode } from "../src/lib/run-configuration";
import { BuilderPage } from "../src/pages/Builder";
import { ProductProvider, useProduct } from "../src/state/ProductContext";

function RunIntent() {
  const { runConfig, setRunConfig, scenario } = useProduct();
  return <><output aria-label="Run overrides">{JSON.stringify(runConfig.actionImplementations)}</output><output aria-label="Run mode">{runConfig.mode}</output><button onClick={() => setRunConfig(configurationForMode(runConfig, runConfig.mode === "simulate" ? "execute" : "simulate", demoCatalog, scenario))}>Switch run mode</button></>;
}

function renderBuilder(scenario = demoScenario) {
  localStorage.setItem("bluefire.local.scenario.v1", JSON.stringify(scenario));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(["catalog"], demoCatalog);
  return render(<QueryClientProvider client={client}><Tooltip.Provider><MemoryRouter initialEntries={["/builder"]}><ProductProvider><RunIntent/><Routes><Route path="/builder" element={<BuilderPage/>}/><Route path="/scenarios" element={<><h1>Examples</h1><Link to="/builder">Return to editor</Link></>}/></Routes></ProductProvider></MemoryRouter></Tooltip.Provider></QueryClientProvider>);
}

it("requires an authored question before saving and retains it across navigation", async () => {
  const save = vi.spyOn(api, "saveScenarioVersion").mockRejectedValue(new Error("Service unavailable"));
  const user = userEvent.setup();
  renderBuilder({ ...structuredClone(demoScenario), purpose: "" });
  await user.click(await screen.findByRole("button", { name: "Save version" }));
  expect(save).not.toHaveBeenCalled();
  const question = screen.getByRole("textbox", { name: "Experiment question" });
  await waitFor(() => expect(question).toHaveFocus());
  expect(question).toHaveAttribute("aria-invalid", "true");
  await user.type(question, "Does redaction prevent retained records from reaching staging?");
  await user.click(screen.getByRole("button", { name: "Save version" }));
  await waitFor(() => expect(save).toHaveBeenCalledOnce());
  expect(save.mock.calls[0]![0].purpose).toBe("Does redaction prevent retained records from reaching staging?");
  expect(await screen.findByText(/Save refused: Service unavailable/)).toBeVisible();
  await user.click(screen.getByRole("link", { name: "Browse examples" }));
  await user.click(screen.getByRole("link", { name: "Return to editor" }));
  await user.click(screen.getByText("Experiment purpose", { exact: true }));
  expect(screen.getByRole("textbox", { name: "Experiment question" })).toHaveValue(save.mock.calls[0]![0].purpose);
  expect(screen.queryByRole("button", { name: "Offline draft" })).not.toBeInTheDocument();
});

it("lets an author choose a run method during Simulate and retains it across mode and navigation changes", async () => {
  const user = userEvent.setup();
  renderBuilder();
  await user.click(await screen.findByRole("button", { name: "Steps" }));
  await user.click(within(screen.getByRole("list", { name: "Experiment steps" })).getAllByRole("button")[0]!);
  const method = screen.getByRole("combobox", { name: "Run method override" });
  expect(screen.getByLabelText("Run mode")).toHaveTextContent("simulate");
  expect(method).toBeEnabled();
  await user.selectOptions(method, "sandbox.fixture.create.v1");
  const expected = '{"place_fixture":"sandbox.fixture.create.v1"}';
  expect(screen.getByLabelText("Run overrides")).toHaveTextContent(expected);
  await user.click(screen.getByRole("button", { name: "Switch run mode" }));
  expect(screen.getByLabelText("Run mode")).toHaveTextContent("execute");
  expect(screen.getByLabelText("Run overrides")).toHaveTextContent(expected);
  await user.click(screen.getByRole("button", { name: "Switch run mode" }));
  await user.click(screen.getByRole("link", { name: "Browse examples" }));
  await user.click(screen.getByRole("link", { name: "Return to editor" }));
  expect(screen.getByLabelText("Run overrides")).toHaveTextContent(expected);
  expect(JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!)).toEqual(demoScenario);
});

it("offers an actual first-step action without creating a purpose or changing other graph state", async () => {
  const user = userEvent.setup();
  const empty = { ...structuredClone(demoScenario), purpose: "", start: "", steps: [], edges: [], layout: {} };
  renderBuilder(empty);
  await user.click(await screen.findByRole("button", { name: "Add first step" }));
  expect(screen.getByRole("textbox", { name: "Search palette" })).toBeVisible();
  expect(JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!)).toEqual(empty);
});

it("offers only producers guaranteed on all paths and keeps an invalid existing binding visible", async () => {
  const scenario = structuredClone(demoScenario);
  scenario.edges.push({ from_step: "run_fixture", outcome: "blocked", to_step: "stage" });
  const before = structuredClone(scenario);
  expect(guaranteedInputSources(scenario, "stage")).toEqual(new Set(["place_fixture", "run_fixture"]));
  expect(guaranteedInputSources(scenario, "missing")).toEqual(new Set());
  const user = userEvent.setup();
  renderBuilder(scenario);
  await user.click(await screen.findByRole("button", { name: "Steps" }));
  await user.click(within(screen.getByRole("list", { name: "Experiment steps" })).getByRole("button", { name: /^4 Stage selected records/ }));
  const records = screen.getByRole("combobox", { name: "Records" });
  expect(records).toHaveValue("discover:records");
  expect(records).toHaveAttribute("aria-invalid", "true");
  expect(within(records).getByRole("option", { name: "Current connection needs attention" })).toBeDisabled();
  expect(screen.getByText(/This connection is not guaranteed on every path/)).toBeVisible();
  expect(JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!)).toEqual(before);
});
