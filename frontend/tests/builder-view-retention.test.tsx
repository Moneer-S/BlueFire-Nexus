import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import * as Tooltip from "@radix-ui/react-tooltip";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Link, MemoryRouter, Route, Routes } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { graphDocument, type GraphEnvelope } from "../src/lib/graph-assistance";
import { defaultGraphView } from "../src/lib/graph-view-retention";
import { BuilderPage } from "../src/pages/Builder";
import { ProductProvider, useProduct } from "../src/state/ProductContext";
import type { Scenario } from "../src/types";

const key = `bluefire.working-graph-view.v1:${demoScenario.id}`;
const graphKey = "bluefire.local.scenario.v1";
function Navigation() {
  const { scenario, setScenario } = useProduct();
  return <><Link to="/elsewhere">Leave editor</Link><Link to="/builder">Return to editor</Link><button onClick={() => setScenario({ ...scenario, id: "scenario.different.v1" })}>Choose different experiment</button></>;
}
function setup(scenario: Scenario = structuredClone(demoScenario)) {
  localStorage.setItem(graphKey, JSON.stringify(scenario));
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  const validate = vi.spyOn(api, "validate");
  const save = vi.spyOn(api, "saveScenarioVersion");
  const mount = () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
    client.setQueryData(["catalog"], demoCatalog);
    return render(<QueryClientProvider client={client}><Tooltip.Provider><MemoryRouter initialEntries={["/builder"]}><ProductProvider><Navigation/><Routes><Route path="/builder" element={<BuilderPage/>}/><Route path="/elsewhere" element={<p>Another page</p>}/></Routes></ProductProvider></MemoryRouter></Tooltip.Provider></QueryClientProvider>);
  };
  let view = mount();
  return { user: userEvent.setup(), validate, save, remount: () => { view.unmount(); view = mount(); } };
}
function branchButton() {
  const branch = demoScenario.steps.find(step => step.id === "fallback")!;
  const title = demoCatalog.behaviors.find(behavior => behavior.id === branch.behavior_id)!.title;
  return within(screen.getByRole("list", { name: "Experiment steps" })).getByRole("button", { name: new RegExp(`^\\d+ ${title}`) });
}
function assertGraphUnchanged() { expect(JSON.parse(localStorage.getItem(graphKey)!)).toEqual(demoScenario); }

it("restores a selected branch, Steps view and inspector on navigation and browser remount without changing the graph", async () => {
  const { user, remount, validate, save } = setup();
  await user.click(screen.getByRole("button", { name: "Steps" }));
  await user.click(screen.getByRole("button", { name: "Show all branches" }));
  await user.click(branchButton());
  expect(branchButton()).toHaveAttribute("aria-pressed", "true");
  await user.click(screen.getByRole("link", { name: "Leave editor" }));
  await user.click(screen.getByRole("link", { name: "Return to editor" }));
  expect(branchButton()).toHaveAttribute("aria-pressed", "true");
  expect(screen.getByRole("button", { name: "Close step details" })).toBeVisible();
  remount();
  expect(branchButton()).toHaveAttribute("aria-pressed", "true");
  expect(screen.getByRole("button", { name: "Close step details" })).toBeVisible();
  assertGraphUnchanged();
  expect(validate).not.toHaveBeenCalled(); expect(save).not.toHaveBeenCalled();
  // Hiding a branch still clears selection and cannot make Delete act on it.
  const confirm = vi.spyOn(window, "confirm");
  await user.click(screen.getByRole("button", { name: "Focus on success path" }));
  expect(screen.getByRole("button", { name: "Delete selected node" })).toBeDisabled();
  await user.click(screen.getByRole("button", { name: "Delete selected node" }));
  expect(confirm).not.toHaveBeenCalled(); assertGraphUnchanged();
});

it("retains individually expanded branches and a closed inspector without selecting the next experiment", async () => {
  const { user, remount } = setup();
  await user.click(screen.getByRole("button", { name: "Steps" }));
  const list = within(screen.getByRole("list", { name: "Experiment steps" }));
  const branchSource = demoScenario.steps.find(step => demoScenario.edges.some(edge => edge.from_step === step.id && edge.to_step === "fallback"))!;
  const title = demoCatalog.behaviors.find(behavior => behavior.id === branchSource.behavior_id)!.title;
  await user.click(list.getByRole("button", { name: new RegExp(`^\\d+ ${title}`) }));
  await user.click(screen.getByRole("button", { name: "Expand selected branches" }));
  await user.click(branchButton());
  await user.click(screen.getByRole("button", { name: "Close step details" }));
  remount();
  expect(branchButton()).toHaveAttribute("aria-pressed", "true");
  expect(screen.queryByRole("button", { name: "Close step details" })).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Show all branches" })).toBeVisible();
  assertGraphUnchanged();
  await user.click(screen.getByRole("button", { name: "Choose different experiment" }));
  expect(screen.getByRole("button", { name: "Canvas" })).toHaveAttribute("aria-pressed", "true");
  expect(screen.queryByRole("list", { name: "Experiment steps" })).not.toBeInTheDocument();
});

it("restores the selected section on the actual canvas after remount", async () => {
  const scenario: Scenario = { ...structuredClone(demoScenario), start: "step_1", steps: Array.from({ length: 17 }, (_, index) => ({ ...structuredClone(demoScenario.steps[0]!), id: `step_${index + 1}` })), edges: [], layout: undefined };
  scenario.edges = scenario.steps.slice(1).map((step, index) => ({ from_step: scenario.steps[index]!.id, outcome: "success", to_step: step.id }));
  const { user, remount } = setup(scenario);
  await user.click(screen.getByRole("button", { name: "Next section" }));
  expect(screen.getByRole("combobox", { name: "Path section" })).toHaveValue("1");
  remount();
  expect(screen.getByRole("combobox", { name: "Path section" })).toHaveValue("1");
  expect(document.querySelector('.react-flow__node[data-id="step_9"]')).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Copy selected node" })).toBeEnabled();
  expect(JSON.parse(localStorage.getItem(graphKey)!)).toEqual(scenario);
});

it.each(["unknown-step", "wrong-behavior", "wrong-scenario", "malformed", "oversized"])("ignores %s view storage without changing graph edges or input bindings", (kind) => {
  const view = { ...defaultGraphView(demoScenario), mode: "steps", inspector: true };
  if (kind === "unknown-step") view.selected = { id: "absent", behavior: demoScenario.steps[0]!.behavior_id };
  if (kind === "wrong-behavior") view.selected = { id: demoScenario.steps[0]!.id, behavior: "unrelated.behavior" };
  const record = kind === "malformed" ? "{" : kind === "oversized" ? "x".repeat(32769) : JSON.stringify({ scenarioId: kind === "wrong-scenario" ? "other" : demoScenario.id, view });
  sessionStorage.setItem(key, record);
  setup();
  expect(screen.getByRole("button", { name: "Canvas" })).toHaveAttribute("aria-pressed", "true");
  expect(screen.queryByRole("button", { name: "Close step details" })).not.toBeInTheDocument();
  expect(sessionStorage.getItem(key)).toBe(record);
  assertGraphUnchanged();
});

it("keeps step selection usable when browser view storage is unavailable", async () => {
  const { user } = setup();
  const write = vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("Storage unavailable"); });
  await user.click(screen.getByRole("button", { name: "Steps" }));
  await user.click(screen.getByRole("button", { name: "Show all branches" }));
  await user.click(branchButton());
  expect(branchButton()).toHaveAttribute("aria-pressed", "true");
  expect(write).toHaveBeenCalled(); assertGraphUnchanged();
});

it.each(["saved", "proposal"])("does not restore or replace the working view while inspecting a %s graph", async (kind) => {
  const branch = demoScenario.steps.find(step => step.id === "fallback")!;
  const record = JSON.stringify({ scenarioId: demoScenario.id, view: { ...defaultGraphView(demoScenario), selected: { id: branch.id, behavior: branch.behavior_id }, mode: "steps", allBranches: true, inspector: true } });
  sessionStorage.setItem(key, record);
  const read = vi.spyOn(Storage.prototype, "getItem");
  const write = vi.spyOn(Storage.prototype, "setItem");
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  const document = graphDocument(structuredClone(demoScenario));
  const digest = `sha256:${"a".repeat(64)}`;
  const jobId = `job-${"b".repeat(32)}`;
  vi.spyOn(api, "immutableScenarioVersion").mockResolvedValue({ schema_version: "bluefire.scenario-version.v1", scenario: { scenario_id: document.id, version: 1, digest, title: document.title, created_at: "2030-01-01", document } });
  const envelope: GraphEnvelope = { review_ready: true, job: { schema_version: "bluefire.job.v1", job_id: jobId, kind: "graph.ai.propose", state: "completed", progress: {} }, application: null,
    proposal: { schema_version: "bluefire.graph-ai-proposal.v1", proposal_job_id: jobId, proposal_digest: digest, context_digest: digest, catalog_digest: digest, base_scenario: null,
      scenario: document, validation: { valid: true }, rationale: "Review only", assumptions: [], limitations: [], provider: { effective_provider_id: "fixture", model: "fixture", used_fallback: false, attempts: 1 } } };
  vi.spyOn(api, "graphProposal").mockResolvedValue(envelope);
  const query = new URLSearchParams(kind === "saved" ? { saved_scenario: document.id, version: "1", digest } : { graph_job: jobId });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const user = userEvent.setup();
  render(<QueryClientProvider client={client}><Tooltip.Provider><MemoryRouter initialEntries={[`/builder?${query}`]}><ProductProvider><BuilderPage/></ProductProvider></MemoryRouter></Tooltip.Provider></QueryClientProvider>);
  expect(await screen.findByRole("button", { name: "Canvas" })).toHaveAttribute("aria-pressed", "true");
  expect(screen.queryByRole("button", { name: "Close step details" })).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Steps" }));
  await user.click(screen.getByRole("button", { name: "Show all branches" }));
  await user.click(branchButton());
  expect(read.mock.calls.some(([item]) => item === key)).toBe(false);
  expect(write.mock.calls.some(([item]) => item === key)).toBe(false);
  expect(sessionStorage.getItem(key)).toBe(record);
});
