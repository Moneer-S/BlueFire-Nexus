import * as Tooltip from "@radix-ui/react-tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
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
      return <div aria-label="Rendered graph steps">{props.nodes?.filter(node => !node.hidden).map(node => <button key={node.id} onClick={event => props.onNodeClick?.(event, node)}>Select {node.id}</button>)}</div>;
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

function renderBuilder(initial: Scenario = demoScenario, layout?: Scenario["layout"]) {
  const scenario = structuredClone(initial);
  scenario.layout = layout ?? Object.fromEntries(scenario.steps.map((step, index) => [step.id, { x: 48, y: 48 + index * 276 }]));
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

function expectReadableSelection(id: string) {
  const node = state.props.nodes?.find(item => item.id === id);
  if (!node) throw new Error("The selected graph node is missing");
  expect(node.hidden).toBe(false);
  expect(node.selected).toBe(true);
  expect(state.viewport.zoom).toBeGreaterThanOrEqual(0.8);
  const x = state.viewport.x + node.position.x * state.viewport.zoom;
  const y = state.viewport.y + node.position.y * state.viewport.zoom;
  expect(x).toBeGreaterThanOrEqual(0);
  expect(y).toBeGreaterThanOrEqual(0);
  expect(x + 220 * state.viewport.zoom).toBeLessThanOrEqual(width);
  expect(y + 104 * state.viewport.zoom).toBeLessThanOrEqual(height);
}

async function navigateReadable(action: () => void, selectedId: string, visibleSteps: number) {
  action();
  // A group can retain the same readable frame. Await its scheduled framing,
  // then check the committed view rather than requiring a redundant setter.
  await act(async () => { await new Promise(resolve => requestAnimationFrame(resolve)); });
  await waitFor(() => {
    expectReadableSelection(selectedId);
    expect(state.props.nodes?.filter(node => !node.hidden)).toHaveLength(visibleSteps);
  });
}

async function focusLongGroup() {
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
  const controls = within(screen.getByLabelText("Graph workspace controls"));
  const group = screen.getByLabelText("Step group");
  const longGroupValue = (within(group).getByRole("option", { name: /82 steps$/ }) as HTMLOptionElement).value;
  const fit = controls.getByRole("button", { name: "Fit visible graph" });

  // Enter from a selection outside the long group, including its old viewport.
  fireEvent.click(fit);
  expect(state.viewport.zoom).toBeLessThan(0.72);
  await navigateReadable(() => fireEvent.change(group, { target: { value: longGroupValue } }), "long_step_2", 82);
  expect(state.props.nodes?.filter(node => !node.hidden)).toHaveLength(82);
  return { rendered, controls, group, longGroupValue, fit };
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

  it("keeps user zoom across resizes and recovers a temporary shrink pan when space returns", async () => {
    renderBuilder();
    await waitFor(() => expect(flow.setViewport).toHaveBeenCalled());
    const original = { x: 120, y: 50, zoom: 1.2 };
    state.viewport = original;
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
    flow.setViewport.mockClear();
    resizeCanvas(1000, 480);
    await waitFor(() => expect(state.viewport).toEqual(original));
    expect(flow.setViewport).toHaveBeenCalledOnce();
  });

  it.each(["pan", "zoom"] as const)("preserves an operator %s after an automatic canvas adjustment", async (change) => {
    renderBuilder();
    await waitFor(() => expect(flow.setViewport).toHaveBeenCalled());
    state.viewport = { x: 120, y: 50, zoom: 1.2 };
    resizeCanvas(400, 300);
    await waitFor(() => expect(state.viewport.x).toBeCloseTo(30.4));
    const chosen = { ...state.viewport, ...(change === "pan" ? { x: state.viewport.x - 15 } : { zoom: 1.3 }) };
    state.viewport = chosen;
    act(() => state.props.onMove?.(new MouseEvent("mousemove"), chosen));
    flow.setViewport.mockClear();
    resizeCanvas(1000, 480);
    await act(async () => { await new Promise(resolve => requestAnimationFrame(resolve)); });
    expect(state.viewport).toEqual(chosen);
    expect(flow.setViewport).not.toHaveBeenCalled();
  });

  it("does not pan underneath a dragged card or restore stale context after the geometry changes", async () => {
    const rendered = renderBuilder();
    await waitFor(() => expect(flow.setViewport).toHaveBeenCalled());
    state.viewport = { x: 120, y: 50, zoom: 1.2 };
    resizeCanvas(400, 300);
    await waitFor(() => expect(state.viewport.x).toBeCloseTo(30.4));
    const adjusted = { ...state.viewport };
    flow.setViewport.mockClear();

    // Cross the current canvas edge, then move back inside the future larger pane.
    // Drag previews update the card, not the saved layout or operator viewport.
    for (const x of [700, 100]) {
      act(() => state.props.onNodesChange?.([{ id: rendered.start, type: "position", position: { x, y: 48 }, dragging: true }]));
      await act(async () => { await new Promise(resolve => requestAnimationFrame(resolve)); });
      expect(state.props.nodes?.find(node => node.id === rendered.start)).toMatchObject({ position: { x, y: 48 }, dragging: true });
      expect(state.viewport).toEqual(adjusted);
      expect(flow.setViewport).not.toHaveBeenCalled();
    }

    resizeCanvas(1000, 480);
    await act(async () => { await new Promise(resolve => requestAnimationFrame(resolve)); });
    expect(state.viewport).toEqual(adjusted);
    expect(flow.setViewport).not.toHaveBeenCalled();
    expect(JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!)).toEqual(rendered);
  });

  it("recovers preceding cards after a dock round trip at the same zoom and saved positions", async () => {
    const scenario = structuredClone(demoScenario);
    const template = structuredClone(scenario.steps[0]!);
    scenario.steps = Array.from({ length: 9 }, (_, index) => ({ ...structuredClone(template), id: `context_step_${index + 1}`, inputs: {} }));
    scenario.start = scenario.steps[0]!.id;
    scenario.edges = scenario.steps.slice(1).map((step, index) => ({ from_step: scenario.steps[index]!.id, outcome: "success" as Outcome, to_step: step.id }));
    scenario.edges.push({ from_step: "context_step_8", outcome: "blocked", to_step: "context_step_9" }, { from_step: "context_step_8", outcome: "failed", to_step: "context_step_9" });
    delete scenario.adaptive_execution;
    const layout = Object.fromEntries(scenario.steps.map((step, index) => [step.id, { x: 32 + Math.floor(index / 3) * 308, y: 32 + (index % 3) * 148 }]));
    width = 870; height = 602;
    const rendered = renderBuilder(scenario, layout);
    await waitFor(() => expect(flow.setViewport).toHaveBeenCalled());
    fireEvent.click(screen.getByRole("button", { name: "Select context_step_8" }));
    await act(async () => { await new Promise(resolve => requestAnimationFrame(resolve)); });
    state.viewport = { x: -94, y: 69, zoom: 1 };

    resizeCanvas(530, 606);
    await waitFor(() => expect(state.viewport.x).toBeCloseTo(-434));
    resizeCanvas(456, 474);
    await waitFor(() => expect(state.viewport.x).toBeCloseTo(-508));
    expect(state.viewport.x + layout.context_step_6!.x).toBeLessThan(0);
    resizeCanvas(796, 470);
    await waitFor(() => expect(state.viewport.x + layout.context_step_6!.x).toBeGreaterThanOrEqual(24));
    expect(state.viewport.zoom).toBe(1);
    for (const step of rendered.steps.slice(3)) {
      const position = layout[step.id]!;
      expect(state.viewport.x + position.x).toBeGreaterThanOrEqual(24);
      expect(state.viewport.x + position.x + 220).toBeLessThanOrEqual(width - 24);
      expect(state.viewport.y + position.y).toBeGreaterThanOrEqual(24);
      expect(state.viewport.y + position.y + 104).toBeLessThanOrEqual(height - 24);
    }
    expect(state.viewport.x + layout.context_step_8!.x + 220 + 72).toBeLessThanOrEqual(width - 24);
    expect(state.props.nodes?.find(node => node.id === "context_step_8")?.selected).toBe(true);
    expect(JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!)).toEqual(rendered);
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
    const { rendered, group, longGroupValue, fit } = await focusLongGroup();
    const graphSteps = within(screen.getByLabelText("Rendered graph steps"));
    await navigateReadable(() => fireEvent.click(graphSteps.getByText("Select long_step_80")), "long_step_80", 82);
    fireEvent.click(fit);
    expect(state.viewport.zoom).toBeLessThan(0.72);
    await navigateReadable(() => fireEvent.click(screen.getByText("Return to whole plan", { selector: "button" })), "long_step_80", 84);
    expect(state.props.nodes?.filter(node => !node.hidden)).toHaveLength(84);

    const wholePlanViewport = { ...state.viewport };
    await navigateReadable(() => fireEvent.change(group, { target: { value: longGroupValue } }), "long_step_80", 82);
    expect(group).toHaveValue(longGroupValue);
    expect(state.viewport).toEqual(wholePlanViewport);
    fireEvent.click(fit);
    expect(state.viewport.zoom).toBeLessThan(0.72);
    await navigateReadable(() => fireEvent.click(screen.getByText("Show all branches", { selector: "button" })), "long_step_80", 84);
    expect(state.props.nodes?.filter(node => !node.hidden)).toHaveLength(84);
    expect(JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!)).toEqual(rendered);
  });

  it("arranges an 82-step group readably and restores all saved positions with Undo", async () => {
    const { rendered, controls, fit } = await focusLongGroup();
    fireEvent.click(fit);
    expect(state.viewport.zoom).toBeLessThan(0.72);
    await navigateReadable(() => fireEvent.click(controls.getByRole("button", { name: "Arrange visible group" })), "long_step_2", 82);
    const arranged = JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!) as Scenario;
    expect(arranged.layout).not.toEqual(rendered.layout);
    expect(arranged.layout!.long_step_1).toEqual(rendered.layout!.long_step_1);
    expect(arranged.layout!.long_step_84).toEqual(rendered.layout!.long_step_84);
    expect(arranged.steps).toEqual(rendered.steps);
    expect(arranged.edges).toEqual(rendered.edges);
    fireEvent.click(controls.getByRole("button", { name: "Undo" }));
    await waitFor(() => expect(state.props.nodes?.map(node => [node.id, node.position])).toEqual(rendered.steps.map(step => [step.id, rendered.layout![step.id]])));
    expect(JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!)).toEqual(rendered);
  });
});
