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
    expect(state.viewport).toEqual({ x: 326, y: -24, zoom: 1 });
    expect(state.props.fitView).toBeUndefined();
    expect(flow.fitView).not.toHaveBeenCalled();
    fireEvent.change(screen.getByRole("textbox", { name: "Experiment name" }), { target: { value: "Renamed graph" } });
    expect(state.viewport.zoom).toBe(1);
    expect(JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!).layout).toEqual(scenario.layout);
    fireEvent.click(screen.getByRole("button", { name: "Fit visible graph" }));
    expect(flow.fitView).toHaveBeenCalledOnce();
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
    expect(state.viewport.x).toBeCloseTo(16);
    expect(state.viewport.y).toBeCloseTo(2.4);
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
    expect(state.viewport).toEqual({ x: 151, y: -224, zoom: 1 });
    state.viewport = { x: 2, y: 3, zoom: 0.4 };
    fireEvent.click(screen.getByRole("button", { name: "Focus selected step" }));
    expect(state.viewport).toEqual({ x: 151, y: -224, zoom: 1 });
  });

  it("frames long graphs in display-only groups without changing saved positions or execution edges", async () => {
    const scenario = structuredClone(demoScenario);
    const template = structuredClone(scenario.steps[0]!);
    scenario.steps = Array.from({ length: 9 }, (_, index) => ({ ...structuredClone(template), id: `focus_step_${index + 1}`, inputs: {} }));
    scenario.start = scenario.steps[0]!.id;
    scenario.edges = scenario.steps.slice(1).map((step, index) => ({ from_step: scenario.steps[index]!.id, outcome: "success" as Outcome, to_step: step.id }));
    delete scenario.adaptive_execution;
    const rendered = renderBuilder(scenario);
    await waitFor(() => expect(flow.setViewport).toHaveBeenCalled());
    expect(screen.getByRole("navigation", { name: "Experiment step groups" })).toBeVisible();
    const group = screen.getByRole("combobox", { name: "Step group" });
    expect(group.querySelectorAll("option")).toHaveLength(4);
    expect(screen.getAllByRole("button", { name: /^Select focus_step_/ })).toHaveLength(4);

    fireEvent.change(group, { target: { value: "1" } });
    await waitFor(() => expect(screen.getByRole("button", { name: "Select focus_step_5" })).toBeVisible());
    expect(screen.queryByRole("button", { name: "Select focus_step_1" })).not.toBeInTheDocument();
    expect(state.props.edges).toHaveLength(scenario.edges.length);
    expect(state.props.nodes?.map(node => [node.id, node.position])).toEqual(rendered.steps.map(step => [step.id, rendered.layout![step.id]]));
    expect(JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!).layout).toEqual(rendered.layout);

    fireEvent.change(group, { target: { value: "all" } });
    await waitFor(() => expect(screen.getAllByRole("button", { name: /^Select focus_step_/ })).toHaveLength(9));
    expect(state.props.edges?.map(edge => edge.id)).toEqual(scenario.edges.map((edge, index) => `route-${edge.from_step}-${edge.outcome}-${edge.to_step}-${index}`));
    expect(JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!).edges).toEqual(scenario.edges);
  });
});
