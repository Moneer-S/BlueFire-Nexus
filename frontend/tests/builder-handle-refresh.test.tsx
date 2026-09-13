import * as Tooltip from "@radix-ui/react-tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactFlowProps } from "@xyflow/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { BuilderPage } from "../src/pages/Builder";
import { ProductProvider, useProduct } from "../src/state/ProductContext";
import type { Behavior, Scenario, ScenarioStep } from "../src/types";

// Observe the real internal handle lookup; keep the real canvas and node renderer.
vi.mock("@xyflow/react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@xyflow/react")>();
  function BoundsProbe() {
    const bounds = actual.useStore((state) => JSON.stringify([...state.nodeLookup].map(([id, node]) => ({
      id, measured: node.measured, handles: node.internals.handleBounds,
    }))));
    return <output aria-label="Measured graph handles">{bounds}</output>;
  }
  return { ...actual, ReactFlow: (props: ReactFlowProps) => <actual.ReactFlow {...props} fitView={false}>{props.children}<BoundsProbe /></actual.ReactFlow> };
});

const base = demoCatalog.behaviors[0]!;
const behavior = (id: string, input: string, outputs: string[]): Behavior => ({
  ...base, id, title: "Same size fixture", purpose: "Same size fixture content", parameters: [],
  inputs: [{ name: input, type: "artifact.fixture.v1", required: true }],
  outputs: outputs.map((name) => ({ name, type: "artifact.fixture.v1" })),
});
const original = behavior("fixture.original", "old_input", ["old_output", "shared_output"]);
const replacement = behavior("fixture.replacement", "new_input", ["shared_output", "new_output"]);
const initial: Scenario = {
  ...demoScenario, start: "source", steps: [
    { id: "source", behavior_id: original.id, inputs: {}, parameters: {}, alternates: [] },
    { id: "sink", behavior_id: original.id, inputs: { old_input: { from_step: "source", artifact: "old_output" } }, parameters: {}, alternates: [] },
  ], edges: [{ from_step: "source", to_step: "sink", outcome: "success" }],
  layout: { source: { x: 0, y: 0 }, sink: { x: 400, y: 0 } },
};

function ReplaceGraph() {
  const { scenario, setScenario } = useProduct();
  return <button onClick={() => setScenario({ ...scenario, steps: scenario.steps.map((step): ScenarioStep => ({
    ...step, behavior_id: replacement.id,
    inputs: step.id === "sink" ? { new_input: { from_step: "source", artifact: "new_output" } } : {},
  })) })}>Replace same-ID node handles</button>;
}

function fixedMeasurements() {
  // Node size never changes, so a real ResizeObserver would not report another
  // resize after the behavior swap. Re-observing an element still gets its initial report.
  vi.spyOn(globalThis, "ResizeObserver").mockImplementation(function (callback) {
    const observed = new Set<Element>();
    const observer: ResizeObserver = {
      observe(target) {
        observed.add(target);
        queueMicrotask(() => {
          if (!observed.has(target)) return;
          const contentRect = target.getBoundingClientRect();
          const size = { inlineSize: contentRect.width, blockSize: contentRect.height };
          callback([{ target, contentRect, borderBoxSize: [size], contentBoxSize: [size], devicePixelContentBoxSize: [size] }], observer);
        });
      },
      unobserve(target) { observed.delete(target); }, disconnect() { observed.clear(); },
    };
    return observer;
  });
  Object.defineProperty(SVGElement.prototype, "getBBox", { configurable: true, value: () => ({ x: 0, y: 0, width: 60, height: 14 }) });
  vi.spyOn(HTMLElement.prototype, "offsetWidth", "get").mockImplementation(function (this: HTMLElement) {
    return this.classList.contains("react-flow__handle") ? 10 : this.classList.contains("react-flow__node") ? 252 : 1000;
  });
  vi.spyOn(HTMLElement.prototype, "offsetHeight", "get").mockImplementation(function (this: HTMLElement) {
    return this.classList.contains("react-flow__handle") ? 10 : this.classList.contains("react-flow__node") ? 160 : 700;
  });
  vi.spyOn(Element.prototype, "getBoundingClientRect").mockImplementation(function (this: Element) {
    const element = this as HTMLElement;
    const isHandle = element.classList.contains("react-flow__handle");
    const isNode = element.classList.contains("react-flow__node");
    // Browser rectangles include viewport zoom; offset dimensions above do not.
    // The canvas may now frame its measured nodes before their handles change.
    const viewport = element.closest(".react-flow__viewport");
    const scale = viewport && (isHandle || isNode) ? new window.DOMMatrixReadOnly(getComputedStyle(viewport).transform).m22 : 1;
    const x = (isHandle && element.classList.contains("output-handle") ? 252 : 0) * scale;
    const y = (isHandle ? Number.parseFloat(element.style.top) || 0 : 0) * scale;
    const width = (isHandle ? 10 : isNode ? 252 : 1000) * scale;
    const height = (isHandle ? 10 : isNode ? 160 : 700) * scale;
    return { x, y, width, height, left: x, top: y, right: x + width, bottom: y + height, toJSON: () => ({}) };
  });
}

afterEach(() => { cleanup(); Reflect.deleteProperty(SVGElement.prototype, "getBBox"); });

it("refreshes same-size reused nodes' handle IDs and order so the new artifact edge can render", async () => {
  fixedMeasurements();
  const user = userEvent.setup();
  const catalog = { ...demoCatalog, behaviors: [original, replacement] };
  window.localStorage.setItem("bluefire.local.scenario.v1", JSON.stringify(initial));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(["catalog"], catalog);
  vi.spyOn(api, "catalog").mockResolvedValue(catalog);
  render(<QueryClientProvider client={client}><Tooltip.Provider><MemoryRouter><ProductProvider><ReplaceGraph /><BuilderPage /></ProductProvider></MemoryRouter></Tooltip.Provider></QueryClientProvider>);
  await user.click(await screen.findByRole("checkbox", { name: "Show input connections" }));
  type MeasuredNode = { id: string; measured: { width: number; height: number }; handles?: { source: { id: string; y: number }[]; target: { id: string }[] } };
  const nodes = () => JSON.parse(screen.getByLabelText("Measured graph handles").textContent!) as MeasuredNode[];
  await waitFor(() => expect(nodes().find((node) => node.id === "source")?.handles?.source.map((handle) => handle.id)).toContain("out:old_output"));
  const oldEdge = await screen.findByTestId("rf__edge-artifact-source-old_output-sink-old_input");
  expect(oldEdge.querySelector("path.react-flow__edge-path")).toHaveAttribute("d");
  const before = nodes();
  const oldSharedY = before.find((node) => node.id === "source")!.handles!.source.find((handle) => handle.id === "out:shared_output")!.y;
  await user.click(screen.getByRole("button", { name: "Replace same-ID node handles" }));
  await waitFor(() => {
    const after = nodes();
    expect(after.map((node) => node.measured)).toEqual(before.map((node) => node.measured));
    for (const node of after) {
      expect(node.handles?.source.map((handle) => handle.id)).toContain("out:new_output");
      expect(node.handles?.source.map((handle) => handle.id)).not.toContain("out:old_output");
      expect(node.handles?.target.map((handle) => handle.id)).toContain("in:new_input");
      expect(node.handles?.target.map((handle) => handle.id)).not.toContain("in:old_input");
    }
    expect(after.find((node) => node.id === "source")!.handles!.source.find((handle) => handle.id === "out:shared_output")!.y).toBe(oldSharedY - 18);
  });
  expect(screen.queryByTestId("rf__edge-artifact-source-old_output-sink-old_input")).not.toBeInTheDocument();
  const newEdge = await screen.findByTestId("rf__edge-artifact-source-new_output-sink-new_input");
  expect(newEdge.querySelector("path.react-flow__edge-path")).toHaveAttribute("d", expect.stringMatching(/^M/));
});
