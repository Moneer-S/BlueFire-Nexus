import * as Tooltip from "@radix-ui/react-tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactFlowProps, Viewport } from "@xyflow/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { GraphWorkspace } from "../src/pages/Builder";
import { demoActions, demoCatalog, demoScenario } from "../src/lib/demo";
import { GRAPH_NODE_HEIGHT, GRAPH_NODE_WIDTH } from "../src/lib/graph-view";
import type { GraphEditorDraft } from "../src/lib/graph-assistance";
import type { Scenario } from "../src/types";
import { ProductProvider } from "../src/state/ProductContext";

const state = vi.hoisted(() => ({ props: {} as ReactFlowProps, viewport: { x: 0, y: 0, zoom: 1 } as Viewport }));
const flow = vi.hoisted(() => ({
  getNode: (id: string) => state.props.nodes?.find(node => node.id === id),
  getNodes: () => state.props.nodes ?? [],
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
      return <div>{props.nodes?.filter(node => !node.hidden).map(node => <button key={node.id} aria-pressed={node.selected} onClick={event => props.onNodeClick?.(event, node)}>Select {node.id}</button>)}</div>;
    },
  };
});

const originalResizeObserver = globalThis.ResizeObserver;
const originalScrollIntoView = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "scrollIntoView");
const scrollIntoView = vi.fn();
let visibleCanvasGeometry = false;
function testRect(width: number, height: number): DOMRect {
  return { x: 0, y: 0, left: 0, top: 0, right: width, bottom: height, width, height, toJSON: () => ({}) } as DOMRect;
}
class CanvasResizeObserver {
  constructor(private callback: ResizeObserverCallback) {}
  observe(target: Element) { if (target.classList.contains("graph-canvas")) this.callback([], {} as ResizeObserver); }
  unobserve() {}
  disconnect() {}
}

beforeEach(() => {
  state.viewport = { x: 0, y: 0, zoom: 1 };
  scrollIntoView.mockClear();
  Object.defineProperty(HTMLElement.prototype, "scrollIntoView", { configurable: true, value: scrollIntoView });
  flow.setViewport.mockClear().mockImplementation(async (viewport: Viewport) => { state.viewport = viewport; return true; });
  globalThis.ResizeObserver = CanvasResizeObserver;
  vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockImplementation(function(this: HTMLElement) { return this.classList.contains("graph-canvas") || (visibleCanvasGeometry && this.tagName === "MAIN") ? 900 : 0; });
  vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockImplementation(function(this: HTMLElement) { return this.classList.contains("graph-canvas") || (visibleCanvasGeometry && this.tagName === "MAIN") ? 480 : 0; });
  vi.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockImplementation(function(this: HTMLElement) {
    return visibleCanvasGeometry && (this.classList.contains("graph-canvas") || this.tagName === "MAIN") ? testRect(900, 480) : testRect(0, 0);
  });
});
afterEach(() => {
  visibleCanvasGeometry = false;
  globalThis.ResizeObserver = originalResizeObserver;
  if (originalScrollIntoView) Object.defineProperty(HTMLElement.prototype, "scrollIntoView", originalScrollIntoView);
  else delete (HTMLElement.prototype as Partial<HTMLElement>).scrollIntoView;
  vi.restoreAllMocks();
});

function renderWorkspace(initial: Scenario = demoScenario, review?: GraphEditorDraft) {
  const scenario = structuredClone(initial);
  localStorage.setItem("bluefire.local.scenario.v1", JSON.stringify(scenario));
  sessionStorage.removeItem(`bluefire.working-graph-view.v2:${scenario.id}`);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(["catalog"], demoCatalog);
  render(<QueryClientProvider client={client}><Tooltip.Provider><MemoryRouter><ProductProvider><GraphWorkspace behaviors={demoCatalog.behaviors} actions={demoActions} review={review} /></ProductProvider></MemoryRouter></Tooltip.Provider></QueryClientProvider>);
  return scenario;
}

async function searchFor(user: ReturnType<typeof userEvent.setup>, query: string) {
  await user.click(screen.getByRole("button", { name: "Find step" }));
  const input = await screen.findByRole("textbox", { name: "Find a step" });
  await user.type(input, query);
  return screen.getByRole("dialog", { name: "Find a step in this experiment" });
}

describe("Builder graph step search", () => {
  it("reveals and selects a disconnected step by exact ID on the whole canvas without changing the scenario", async () => {
    const scenario = structuredClone(demoScenario);
    const orphan = { ...structuredClone(scenario.steps[0]!), id: "orphan_step" };
    scenario.steps.push(orphan);
    scenario.layout = { ...(scenario.layout ?? {}), orphan_step: { x: 1200, y: 840 } };
    visibleCanvasGeometry = true;
    const saved = renderWorkspace(scenario);
    const user = userEvent.setup();
    // The opening frame can equal the default viewport, so wait for the canvas itself.
    expect(await screen.findByRole("button", { name: "Select orphan_step" })).toBeInTheDocument();
    let dialog = await searchFor(user, "fallback");
    await user.click(within(dialog).getByRole("button", { name: /Use approved local fallback.*fallback/ }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Select fallback" })).toHaveAttribute("aria-pressed", "true"));
    expect(state.props.nodes?.find(node => node.id === "fallback")?.hidden).toBe(false);

    dialog = await searchFor(user, "orphan_step");
    state.viewport = { x: 0, y: 0, zoom: 0.2 };
    await user.click(within(dialog).getByRole("button", { name: /Step 8 · orphan_step/ }));

    await waitFor(() => expect(screen.getByRole("button", { name: "Select orphan_step" })).toHaveAttribute("aria-pressed", "true"));
    expect(state.props.nodes?.every(node => !node.hidden)).toBe(true);
    const selected = state.props.nodes?.find(node => node.id === "orphan_step");
    expect(selected?.hidden).toBe(false);
    // Focus keeps the tail readable without leaving empty space past the graph.
    await waitFor(() => expect(state.viewport).toEqual({ x: -544, y: -472, zoom: 1 }));
    const selectedRect = {
      left: state.viewport.x + selected!.position.x * state.viewport.zoom,
      top: state.viewport.y + selected!.position.y * state.viewport.zoom,
      right: state.viewport.x + (selected!.position.x + GRAPH_NODE_WIDTH) * state.viewport.zoom,
      bottom: state.viewport.y + (selected!.position.y + GRAPH_NODE_HEIGHT) * state.viewport.zoom,
    };
    expect(selectedRect.left).toBeGreaterThanOrEqual(0);
    expect(selectedRect.top).toBeGreaterThanOrEqual(0);
    expect(selectedRect.right).toBeLessThanOrEqual(900);
    expect(selectedRect.bottom).toBeLessThanOrEqual(480);
    expect(selectedRect.right).toBe(900 - 24);
    expect(selectedRect.bottom).toBe(480 - 24);
    expect(JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!)).toEqual(saved);
    expect(state.props.edges?.filter(edge => edge.data?.kind === "route").map(edge => edge.id)).toEqual(saved.edges.map((edge, index) => `route-${edge.from_step}-${edge.outcome}-${edge.to_step}-${index}`));
    expect(state.props.nodes?.find(node => node.id === "orphan_step")?.position).toEqual(saved.layout?.orphan_step);
  });

  it("scrolls the selected late disconnected row into view in Steps mode", async () => {
    const scenario = structuredClone(demoScenario);
    scenario.steps.push({ ...structuredClone(scenario.steps[0]!), id: "list_orphan" });
    const saved = renderWorkspace(scenario);
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Steps" }));

    const dialog = await searchFor(user, "list_orphan");
    await user.click(within(dialog).getByRole("button", { name: /Step 8 · list_orphan/ }));
    const list = within(await screen.findByRole("list", { name: "Experiment steps" }));
    const selected = list.getByRole("button", { pressed: true });
    await waitFor(() => expect(scrollIntoView).toHaveBeenCalledWith({ block: "nearest", behavior: "instant" }));

    expect(selected).toHaveAttribute("data-step-id", "list_orphan");
    expect(scrollIntoView.mock.contexts[0]).toBe(selected);
    expect(screen.getByRole("button", { name: "Steps" })).toHaveAttribute("aria-pressed", "true");
    expect(JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!)).toEqual(saved);
  });

  it("finds by behavior purpose, disambiguates duplicate titles, and reports no matches", async () => {
    const scenario = structuredClone(demoScenario);
    scenario.steps = [
      { ...structuredClone(scenario.steps[0]!), id: "fixture_first" },
      { ...structuredClone(scenario.steps[0]!), id: "fixture_second" },
    ];
    scenario.start = "fixture_first";
    scenario.edges = [];
    const user = userEvent.setup();
    renderWorkspace(scenario);

    const dialog = await searchFor(user, "synthetic research material");
    expect(within(dialog).getByRole("button", { name: /Step 1 · fixture_first/ })).toBeVisible();
    expect(within(dialog).getByRole("button", { name: /Step 2 · fixture_second/ })).toBeVisible();
    await user.clear(within(dialog).getByRole("textbox", { name: "Find a step" }));
    await user.type(within(dialog).getByRole("textbox", { name: "Find a step" }), "no-step-has-this-title");
    expect(within(dialog).getByText("No matching steps.")).toBeVisible();
  });

  it("keeps graph shortcuts inside the search dialog and restores trigger focus on Escape", async () => {
    const user = userEvent.setup();
    renderWorkspace();
    const readScenario = () => JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!);
    const stepCount = () => readScenario().steps.length as number;
    await user.click(screen.getByRole("button", { name: "Auto-layout" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Undo" })).toBeEnabled());
    await user.click(screen.getByRole("button", { name: "Select place_fixture" }));
    await user.keyboard("{Control>}c{/Control}");

    const initialCount = stepCount();
    await user.keyboard("{Control>}v{/Control}");
    await waitFor(() => expect(stepCount()).toBe(initialCount + 1));
    await user.click(screen.getByRole("button", { name: "Select place_fixture" }));
    await user.keyboard("{Control>}z{/Control}");
    await waitFor(() => expect(stepCount()).toBe(initialCount));
    await user.click(screen.getByRole("button", { name: "Select place_fixture" }));
    await user.keyboard("{Control>}d{/Control}");
    await act(async () => { await new Promise(resolve => window.setTimeout(resolve, 0)); });
    await waitFor(() => expect(stepCount()).toBe(initialCount + 1));
    await user.click(screen.getByRole("button", { name: "Select place_fixture" }));
    await user.keyboard("{Control>}z{/Control}");
    await waitFor(() => expect(stepCount()).toBe(initialCount));
    await user.click(screen.getByRole("button", { name: "Select place_fixture" }));
    await user.keyboard("{Control>}c{/Control}");
    expect(screen.getByText("Place deterministic fixture copied.")).toBeVisible();
    const expected = readScenario();

    const dialog = await searchFor(user, "Place deterministic fixture");
    const result = within(dialog).getByRole("button", { name: /Place deterministic fixture/ });
    result.focus();
    await user.keyboard("{Control>}z{/Control}");
    expect(readScenario()).toEqual(expected);
    await user.keyboard("{Control>}v{/Control}");
    expect(readScenario()).toEqual(expected);
    await user.keyboard("{Control>}d{/Control}");
    await act(async () => { await new Promise(resolve => window.setTimeout(resolve, 0)); });
    expect(readScenario()).toEqual(expected);
    expect(dialog).toBeVisible();

    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Find a step in this experiment" })).not.toBeInTheDocument());
    expect(screen.getByRole("button", { name: "Find step" })).toHaveFocus();
    expect(readScenario()).toEqual(expected);
  });

  it("allows view-only review search and selection without requesting a graph edit", async () => {
    const scenario = structuredClone(demoScenario);
    const setScenario = vi.fn();
    const review: GraphEditorDraft = { scenario, setScenario, dirty: false, controls: null, details: null, readOnly: true, statusLabel: "Saved version" };
    const user = userEvent.setup();
    renderWorkspace(scenario, review);
    await user.click(screen.getByRole("button", { name: "Steps" }));

    const dialog = await searchFor(user, "Collect approved operating-system");
    await user.click(within(dialog).getByRole("button", { name: /Collect bounded system facts/ }));

    const list = within(screen.getByRole("list", { name: "Experiment steps" }));
    expect(list.getByRole("button", { pressed: true })).toHaveAccessibleName(/^3 Collect bounded system facts/);
    expect(screen.getByRole("button", { name: "Steps" })).toHaveAttribute("aria-pressed", "true");
    expect(setScenario).not.toHaveBeenCalled();
    expect(JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!)).toEqual(scenario);
  });
});
