import * as Tooltip from "@radix-ui/react-tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ReactFlowProps, Viewport } from "@xyflow/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { BuilderPage } from "../src/pages/Builder";
import { ProductProvider } from "../src/state/ProductContext";
import type { Outcome, Scenario } from "../src/types";

const state = vi.hoisted(() => ({ props: {} as ReactFlowProps, viewport: { x: 0, y: 0, zoom: 1 } as Viewport }));
const flow = vi.hoisted(() => ({
  getNode: (id: string) => state.props.nodes?.find(node => node.id === id),
  getViewport: () => state.viewport,
  getZoom: () => state.viewport.zoom,
  setViewport: vi.fn(async (viewport: Viewport) => { state.viewport = viewport; return true; }),
  fitView: vi.fn(async () => true),
  screenToFlowPosition: vi.fn(),
  deleteElements: vi.fn(),
}));
vi.mock("@xyflow/react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@xyflow/react")>();
  return {
    ...actual,
    useNodesInitialized: () => true,
    useReactFlow: () => flow,
    ReactFlow: (props: ReactFlowProps) => {
      state.props = props;
      return <div>{props.nodes?.filter(node => !node.hidden).map(node => <button key={node.id} onClick={event => props.onNodeClick?.(event, node)}>Select {node.id}</button>)}</div>;
    },
  };
});

let width = 1000;
let height = 480;
const observers = new Set<ResizeObserverCallback>();
const originalResizeObserver = globalThis.ResizeObserver;
class CanvasResizeObserver {
  constructor(private callback: ResizeObserverCallback) {}
  observe(target: Element) { if (target.classList.contains("graph-canvas")) observers.add(this.callback); }
  unobserve() {}
  disconnect() { observers.delete(this.callback); }
}

beforeEach(() => {
  width = 1000; height = 480;
  state.viewport = { x: 0, y: 0, zoom: 1 };
  flow.setViewport.mockClear().mockImplementation(async (viewport: Viewport) => { state.viewport = viewport; return true; });
  flow.fitView.mockClear();
  globalThis.ResizeObserver = CanvasResizeObserver;
  vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockImplementation(function(this: HTMLElement) { return this.classList.contains("graph-canvas") ? width : 0; });
  vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockImplementation(function(this: HTMLElement) { return this.classList.contains("graph-canvas") ? height : 0; });
});
afterEach(() => { globalThis.ResizeObserver = originalResizeObserver; observers.clear(); });

function renderBuilder(initial: Scenario = demoScenario) {
  const scenario = structuredClone(initial);
  scenario.layout = Object.fromEntries(scenario.steps.map((step, index) => [step.id, { x: 48, y: 48 + index * 276 }]));
  localStorage.setItem("bluefire.local.scenario.v1", JSON.stringify(scenario));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(["catalog"], demoCatalog);
  render(<QueryClientProvider client={client}><Tooltip.Provider><MemoryRouter><ProductProvider><BuilderPage /></ProductProvider></MemoryRouter></Tooltip.Provider></QueryClientProvider>);
  return scenario;
}

function resizeCanvas(nextWidth: number, nextHeight: number) {
  width = nextWidth; height = nextHeight;
  act(() => { observers.forEach(callback => callback([], {} as ResizeObserver)); });
}

describe("Builder viewport controls", () => {
  it("opens at a readable start and only fits the whole graph on an explicit request", async () => {
    const scenario = renderBuilder();
    await waitFor(() => expect(flow.setViewport).toHaveBeenCalled());
    expect(state.viewport.zoom).toBeLessThanOrEqual(1);
    expect(state.viewport.zoom).toBeGreaterThan(0.5);
    const initialViewport = { ...state.viewport };
    expect(state.props.fitView).toBeUndefined();
    expect(flow.fitView).not.toHaveBeenCalled();
    fireEvent.change(screen.getByRole("textbox", { name: "Experiment name" }), { target: { value: "Renamed graph" } });
    expect(state.viewport).toEqual(initialViewport);
    expect(JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!).layout).toEqual(scenario.layout);
    flow.setViewport.mockClear();
    fireEvent.click(screen.getByRole("button", { name: "Fit visible graph" }));
    expect(flow.setViewport).toHaveBeenCalledOnce();
  });

  it("keeps user zoom across panel and window resizes, moving only an obscured selection", async () => {
    renderBuilder();
    await waitFor(() => expect(flow.setViewport).toHaveBeenCalled());
    state.viewport = { x: 120, y: 50, zoom: 1.2 };
    flow.setViewport.mockClear();
    fireEvent.click(screen.getByRole("button", { name: "Show node inspector" }));
    resizeCanvas(710, 440);
    await act(async () => { await new Promise(resolve => requestAnimationFrame(resolve)); });
    expect(flow.setViewport).not.toHaveBeenCalled();
    resizeCanvas(400, 300);
    await waitFor(() => expect(flow.setViewport).toHaveBeenCalled());
    expect(state.viewport.zoom).toBe(1.2);
    expect(state.viewport.x).toBeCloseTo(30.4);
    expect(state.viewport.y).toBeCloseTo(50);
    const adjusted = { ...state.viewport };
    flow.setViewport.mockClear();
    resizeCanvas(1000, 480);
    await act(async () => { await new Promise(resolve => requestAnimationFrame(resolve)); });
    expect(state.viewport).toEqual(adjusted);
    expect(flow.setViewport).not.toHaveBeenCalled();
  });

  it("opens an overview selection at readable scale and uses the resized canvas to focus the selected step", async () => {
    const scenario = renderBuilder();
    await waitFor(() => expect(flow.setViewport).toHaveBeenCalled());
    state.viewport = { x: 10, y: 10, zoom: 0.13 };
    width = 650; height = 380;
    const target = scenario.steps[1]!;
    fireEvent.click(screen.getByRole("button", { name: `Select ${target.id}` }));
    await waitFor(() => expect(state.viewport.zoom).toBe(1));
    expect(state.viewport).toEqual({ x: 167, y: -186, zoom: 1 });
    state.viewport = { x: 2, y: 3, zoom: 0.4 };
    fireEvent.click(screen.getByLabelText("View options", { selector: "summary" }));
    fireEvent.click(screen.getByRole("button", { name: "Focus selected step" }));
    expect(state.viewport).toEqual({ x: 167, y: -186, zoom: 1 });
  });

  it("keeps conditional route labels inside the canvas when the inspector or Assistant narrows it", async () => {
    const scenario = renderBuilder();
    await waitFor(() => expect(flow.setViewport).toHaveBeenCalled());
    fireEvent.click(screen.getByRole("button", { name: "Select transport" }));
    await act(async () => { await new Promise(resolve => requestAnimationFrame(resolve)); });
    const position = scenario.layout!.transport!;
    state.viewport = { x: 150, y: -position.y + 70, zoom: 1 };
    flow.setViewport.mockClear();
    resizeCanvas(400, 300);
    await waitFor(() => expect(flow.setViewport).toHaveBeenCalled());
    expect(state.viewport.zoom).toBe(1);
    expect(state.viewport.x + position.x + 220).toBeLessThanOrEqual(304);
    expect(JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!).layout).toEqual(scenario.layout);
  });

  it("keeps a nine-step plan connected and readable without changing saved positions or execution edges", async () => {
    const scenario = structuredClone(demoScenario);
    const template = structuredClone(scenario.steps[0]!);
    scenario.steps = Array.from({ length: 9 }, (_, index) => ({ ...structuredClone(template), id: `focus_step_${index + 1}`, inputs: {} }));
    scenario.steps[3]!.inputs = { archived: { from_step: "focus_step_1", artifact: "records" } };
    scenario.steps[7]!.inputs = { report: { from_step: "focus_step_2", artifact: "bundle" } };
    scenario.start = scenario.steps[0]!.id;
    scenario.edges = scenario.steps.slice(1).map((step, index) => ({ from_step: scenario.steps[index]!.id, outcome: "success" as Outcome, to_step: step.id }));
    delete scenario.adaptive_execution;
    sessionStorage.clear();
    const rendered = renderBuilder(scenario);
    await waitFor(() => expect(flow.setViewport).toHaveBeenCalled());
    expect(screen.queryByRole("button", { name: "Next group" })).not.toBeInTheDocument();
    expect(screen.queryByRole("combobox", { name: "Step group" })).not.toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /^Select focus_step_/ })).toHaveLength(9);
    expect(state.viewport.zoom).toBeGreaterThanOrEqual(0.72);
    expect(state.props.edges?.filter(edge => edge.data?.kind === "route")).toHaveLength(scenario.edges.length);
    expect(state.props.edges?.filter(edge => edge.data?.kind === "artifact")).toHaveLength(2);
    expect(state.props.nodes?.map(node => [node.id, node.position])).toEqual(rendered.steps.map(step => [step.id, rendered.layout![step.id]]));
    expect(JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!).layout).toEqual(rendered.layout);

    fireEvent.click(screen.getByRole("button", { name: "Select focus_step_8" }));
    await waitFor(() => expect(state.viewport.zoom).toBeGreaterThanOrEqual(0.72));
    fireEvent.click(screen.getByRole("button", { name: "Steps" }));
    expect(screen.getByRole("list", { name: "Experiment steps" }).querySelector('button[aria-pressed="true"] .step-number')?.textContent).toBe("8");
    fireEvent.click(screen.getByRole("button", { name: "Canvas" }));
    expect(screen.getAllByRole("button", { name: /^Select focus_step_/ })).toHaveLength(9);
    fireEvent.click(screen.getByRole("button", { name: "Fit visible graph" }));
    expect(state.viewport.zoom).toBeLessThan(0.72);
    expect(state.props.edges?.filter(edge => edge.data?.kind === "route").map(edge => edge.id)).toEqual(scenario.edges.map((edge, index) => `route-${edge.from_step}-${edge.outcome}-${edge.to_step}-${index}`));
    expect(JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!).edges).toEqual(scenario.edges);
    expect(JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!).steps).toEqual(scenario.steps);
  });

  it("retains separate cross-group data bindings when step titles repeat", async () => {
    const scenario = structuredClone(demoScenario);
    const template = structuredClone(scenario.steps[0]!);
    scenario.steps = Array.from({ length: 6 }, (_, index) => ({ ...structuredClone(template), id: `duplicate_step_${index + 1}`, inputs: {} }));
    scenario.steps[3]!.inputs = { archived: { from_step: "duplicate_step_1", artifact: "records" } };
    scenario.steps[4]!.inputs = { archived: { from_step: "duplicate_step_2", artifact: "records" } };
    scenario.start = scenario.steps[0]!.id;
    scenario.edges = scenario.steps.slice(1).map((step, index) => ({ from_step: scenario.steps[index]!.id, outcome: "success" as Outcome, to_step: step.id }));
    delete scenario.adaptive_execution;
    scenario.edges.push({ from_step: "duplicate_step_2", outcome: "blocked", to_step: "duplicate_step_4" });
    renderBuilder(scenario);
    fireEvent.click(screen.getByLabelText("View options", { selector: "summary" }));
    const group = screen.getByRole("combobox", { name: "Step group" });
    fireEvent.change(group, { target: { value: "2" } });
    fireEvent.click(screen.getByText("Group connections").closest("details")!.querySelector("summary")!);
    const dependencies = screen.getByText("Data dependencies (2)").closest("details")!;
    fireEvent.click(dependencies.querySelector("summary")!);
    expect(screen.getByText("Place deterministic fixture · Step 1 · records → Place deterministic fixture · Step 4 · Archived")).toBeVisible();
    expect(screen.getByText("Place deterministic fixture · Step 2 · records → Place deterministic fixture · Step 5 · Archived")).toBeVisible();
  });

  it("keeps an 82-step connected group and whole-plan navigation readable while retaining explicit overview", async () => {
    const scenario = structuredClone(demoScenario);
    const template = structuredClone(scenario.steps[0]!);
    scenario.steps = Array.from({ length: 84 }, (_, index) => ({ ...structuredClone(template), id: `long_step_${index + 1}`, inputs: {} }));
    scenario.start = scenario.steps[0]!.id;
    scenario.edges = scenario.steps.slice(1, 83).map((step, index) => ({ from_step: scenario.steps[index]!.id, outcome: "success" as Outcome, to_step: step.id }));
    scenario.edges.push({ from_step: scenario.start, outcome: "blocked", to_step: "long_step_84" });
    delete scenario.adaptive_execution;
    const rendered = renderBuilder(scenario);
    await waitFor(() => expect(flow.setViewport).toHaveBeenCalled());
    fireEvent.click(screen.getByLabelText("View options", { selector: "summary" }));
    const group = screen.getByRole("combobox", { name: "Step group" });
    const longGroup = screen.getByRole("option", { name: /82 steps$/ }) as HTMLOptionElement;

    const expectReadableSelection = (id: string) => {
      const node = state.props.nodes?.find(item => item.id === id);
      if (!node) throw new Error("The selected graph node is missing");
      expect(node.hidden).toBe(false);
      expect(node.selected).toBe(true);
      expect(state.viewport.zoom).toBeGreaterThanOrEqual(0.72);
      const x = state.viewport.x + node.position.x * state.viewport.zoom;
      const y = state.viewport.y + node.position.y * state.viewport.zoom;
      expect(x).toBeGreaterThanOrEqual(0);
      expect(y).toBeGreaterThanOrEqual(0);
      expect(x + 220 * state.viewport.zoom).toBeLessThanOrEqual(width);
      expect(y + 104 * state.viewport.zoom).toBeLessThanOrEqual(height);
    };
    const navigate = async (action: () => void) => {
      flow.setViewport.mockClear();
      action();
      await waitFor(() => expect(flow.setViewport).toHaveBeenCalled());
    };

    // Enter from a selection outside the long group, including its old viewport.
    fireEvent.click(screen.getByRole("button", { name: "Fit visible graph" }));
    expect(state.viewport.zoom).toBeLessThan(0.72);
    await navigate(() => fireEvent.change(group, { target: { value: longGroup.value } }));
    expect(screen.getAllByRole("button", { name: /^Select long_step_/ })).toHaveLength(82);
    expectReadableSelection("long_step_2");

    await navigate(() => fireEvent.click(screen.getByRole("button", { name: "Arrange visible group" })));
    expectReadableSelection("long_step_2");
    const arranged = JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!) as Scenario;
    expect(arranged.layout).not.toEqual(rendered.layout);
    expect(arranged.layout!.long_step_1).toEqual(rendered.layout!.long_step_1);
    expect(arranged.layout!.long_step_84).toEqual(rendered.layout!.long_step_84);
    expect(arranged.steps).toEqual(rendered.steps);
    expect(arranged.edges).toEqual(rendered.edges);
    fireEvent.click(screen.getByRole("button", { name: "Undo" }));
    await waitFor(() => expect(state.props.nodes?.map(node => [node.id, node.position])).toEqual(rendered.steps.map(step => [step.id, rendered.layout![step.id]])));
    expect(JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!)).toEqual(rendered);

    fireEvent.click(screen.getByRole("button", { name: "Select long_step_80" }));
    await waitFor(() => expectReadableSelection("long_step_80"));
    fireEvent.click(screen.getByRole("button", { name: "Fit visible graph" }));
    expect(state.viewport.zoom).toBeLessThan(0.72);
    await navigate(() => fireEvent.click(screen.getByRole("button", { name: "Return to whole plan" })));
    expect(screen.getAllByRole("button", { name: /^Select long_step_/ })).toHaveLength(84);
    expectReadableSelection("long_step_80");

    await navigate(() => fireEvent.change(group, { target: { value: longGroup.value } }));
    fireEvent.click(screen.getByRole("button", { name: "Fit visible graph" }));
    expect(state.viewport.zoom).toBeLessThan(0.72);
    await navigate(() => fireEvent.click(screen.getByRole("button", { name: "Show all branches" })));
    expect(screen.getAllByRole("button", { name: /^Select long_step_/ })).toHaveLength(84);
    expectReadableSelection("long_step_80");
    expect(JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!)).toEqual(rendered);
  });
});
