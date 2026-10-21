import * as Tooltip from "@radix-ui/react-tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { NodeProps, ReactFlowProps } from "@xyflow/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import * as graphView from "../src/lib/graph-view";
import { BuilderPage } from "../src/pages/Builder";
import { ProductProvider, useProduct } from "../src/state/ProductContext";
import type { Scenario, ScenarioEdge } from "../src/types";

const nodeRenders = vi.hoisted(() => [] as string[]);
const renderedGraphs = vi.hoisted(() => [] as Pick<ReactFlowProps, "nodes" | "edges">[]);
vi.mock("@xyflow/react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@xyflow/react")>();
  const measuredTypes = new WeakMap<object, ReactFlowProps["nodeTypes"]>();
  return {
    ...actual,
    ReactFlow: (props: ReactFlowProps) => {
      renderedGraphs.push({ nodes: props.nodes, edges: props.edges });
      let nodeTypes = props.nodeTypes;
      if (nodeTypes?.behavior) {
        if (!measuredTypes.has(nodeTypes)) {
          const Original = nodeTypes.behavior;
          measuredTypes.set(nodeTypes, { ...nodeTypes, behavior: (node: NodeProps) => { nodeRenders.push(node.id); return <Original {...node} />; } });
        }
        nodeTypes = measuredTypes.get(nodeTypes);
      }
      return <actual.ReactFlow {...props} nodeTypes={nodeTypes} />;
    },
  };
});

function ContextControls() {
  const { scenario, setScenario, runConfig, setRunConfig, dirty } = useProduct();
  return <>
    <output aria-label="Draft state">{dirty ? "dirty" : "saved"}</output>
    <output aria-label="Approval state">{runConfig.approved ? runConfig.approvedBy : "none"}</output>
    <output aria-label="Selected methods">{JSON.stringify(runConfig.actionImplementations)}</output>
    <button onClick={() => setRunConfig({ ...runConfig, actionImplementations: { [scenario.steps[0]!.id]: "sandbox.fixture.create.v1" } })}>Select method in context</button>
    <button onClick={() => setRunConfig({ ...runConfig, approved: true, approvedBy: "test-reviewer" })}>Approve current context</button>
    <button onClick={() => setScenario({ ...scenario, steps: scenario.steps.map((step, index) => index ? step : { ...step, behavior_id: scenario.steps[1]!.behavior_id }) })}>Change first behavior in context</button>
    <button onClick={() => setScenario({ ...scenario, layout: { ...scenario.layout, [scenario.steps[0]!.id]: { x: 902, y: 301 } } })}>Move first step in context</button>
    <button onClick={() => setScenario({ ...scenario, edges: [] })}>Clear routes in context</button>
    <button onClick={() => setScenario({ ...scenario, start: scenario.steps[1]!.id })}>Change start in context</button>
  </>;
}

function renderBuilder(scenario: Scenario = demoScenario) {
  window.localStorage.setItem("bluefire.local.scenario.v1", JSON.stringify(scenario));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(["catalog"], demoCatalog);
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  return render(<QueryClientProvider client={client}><Tooltip.Provider><MemoryRouter><ProductProvider><ContextControls /><BuilderPage /></ProductProvider></MemoryRouter></Tooltip.Provider></QueryClientProvider>);
}

function largeLayoutScenario(mode: "absent" | "partial" | "complete"): Scenario {
  const steps = Array.from({ length: 128 }, (_, index) => ({
    ...structuredClone(demoScenario.steps[0]!),
    id: `layout-step-${index}`,
    inputs: {},
  }));
  const edges: ScenarioEdge[] = steps.slice(0, -1).map((step, index) => ({
    from_step: step.id,
    outcome: "success" as const,
    to_step: steps[index + 1]!.id,
  }));
  const branchOutcomes = ["partial", "blocked", "failed"] as const;
  for (let index = 0; index < 43; index += 1) {
    branchOutcomes.forEach((outcome, offset) => {
      edges.push({ from_step: steps[index]!.id, outcome, to_step: steps[index + offset + 2]!.id });
    });
  }
  const layout = mode === "absent"
    ? undefined
    : Object.fromEntries(steps.flatMap((step, index) => mode === "partial" && index > 0
      ? []
      : [[step.id, mode === "partial" ? { x: 902, y: 301 } : { x: 17 + index * 13, y: 29 + index * 7 }] as const]));
  return {
    ...structuredClone(demoScenario),
    id: `builder-layout-${mode}`,
    start: steps[0]!.id,
    steps,
    edges,
    layout,
  };
}

describe("Builder metadata and graph updates", () => {
  it.each(["absent", "partial", "complete"] as const)(
    "builds fallback positions once for a %s saved layout and keeps them presentation-only",
    async (mode) => {
      const scenario = largeLayoutScenario(mode);
      const originalLayout = structuredClone(scenario.layout);
      const layout = vi.spyOn(graphView, "initialGraphLayout");
      const { unmount } = renderBuilder(scenario);
      try {
        await screen.findByRole("textbox", { name: "Experiment name" });
        await waitFor(() => expect(renderedGraphs.at(-1)?.nodes).toHaveLength(128));

        expect(layout).toHaveBeenCalledTimes(mode === "complete" ? 0 : 1);
        const nodes = renderedGraphs.at(-1)!.nodes!;
        for (const [index, node] of nodes.entries()) {
          const saved = scenario.layout?.[node.id];
          expect(node.position).toEqual(saved ?? {
            x: 48 + (index % 4) * 294,
            y: 48 + Math.floor(index / 4) * 190,
          });
        }
        const originalCoordinates = nodes.map(({ id, position }) => [id, { ...position }] as const);
        expect(JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!).layout).toEqual(originalLayout);

        fireEvent.change(screen.getByRole("textbox", { name: "Experiment name" }), {
          target: { value: `${scenario.title} edited` },
        });
        fireEvent.click(screen.getByRole("button", { name: "Steps" }));
        fireEvent.click(screen.getByRole("button", { name: "Canvas" }));
        expect(layout).toHaveBeenCalledTimes(mode === "complete" ? 0 : 1);
        expect(renderedGraphs.at(-1)!.nodes!.map(({ id, position }) => [id, { ...position }])).toEqual(originalCoordinates);
        expect(JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!).layout).toEqual(originalLayout);
      } finally {
        unmount();
        layout.mockRestore();
      }
    },
  );

  it("keeps graph objects stable through typed name edits while immediately invalidating approval", async () => {
    const user = userEvent.setup();
    renderBuilder();
    const name = await screen.findByRole("textbox", { name: "Experiment name" });
    await user.click(screen.getByRole("button", { name: "Select method in context" }));
    await user.click(screen.getByRole("button", { name: "Approve current context" }));
    expect(screen.getByLabelText("Approval state")).toHaveTextContent("test-reviewer");
    const original = renderedGraphs.at(-1)!;
    renderedGraphs.length = 0;
    nodeRenders.length = 0;

    for (const character of " edit") {
      await user.type(name, character);
      expect(screen.getByLabelText("Draft state")).toHaveTextContent("dirty");
      expect(screen.getByLabelText("Approval state")).toHaveTextContent("none");
      expect(screen.getByLabelText("Selected methods")).toHaveTextContent("sandbox.fixture.create.v1");
      expect(nodeRenders).toEqual([]);
      expect(renderedGraphs.length).toBeGreaterThan(0);
      for (const graph of renderedGraphs) {
        expect(graph.nodes).toBe(original.nodes);
        expect(graph.edges).toBe(original.edges);
      }
    }
    expect(name).toHaveValue(demoScenario.title + " edit");
    const persisted = JSON.parse(window.localStorage.getItem("bluefire.local.scenario.v1")!);
    expect(persisted).toEqual({ ...demoScenario, title: demoScenario.title + " edit" });
    const leaving = new Event("beforeunload", { cancelable: true });
    window.dispatchEvent(leaving);
    expect(leaving.defaultPrevented).toBe(true);
  });

  it("remounts the palette with its filters and keyboard toggle focus intact", async () => {
    const user = userEvent.setup();
    renderBuilder();
    expect(screen.queryByRole("textbox", { name: "Search palette", hidden: true })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Add step" }));
    await user.type(screen.getByRole("textbox", { name: "Search palette" }), "fix");
    await user.selectOptions(screen.getByRole("combobox", { name: "Safety tier filter" }), "safe");
    await user.click(screen.getByRole("button", { name: "Add step" }));
    const toggle = screen.getByRole("button", { name: "Add step" });
    expect(toggle).toHaveFocus();
    expect(screen.queryByRole("textbox", { name: "Search palette", hidden: true })).not.toBeInTheDocument();
    await user.keyboard("{Enter}");
    expect(screen.getByRole("textbox", { name: "Search palette" })).toHaveValue("fix");
    expect(screen.getByRole("combobox", { name: "Safety tier filter" })).toHaveValue("safe");
    expect(screen.getByRole("button", { name: "Add step" })).toHaveFocus();
  });

  it("returns focus from closed step details and reopens the same selected step by keyboard", async () => {
    const user = userEvent.setup();
    renderBuilder();
    expect(screen.queryByLabelText(/^Step ID/)).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Show node inspector" }));
    expect(screen.getByLabelText(/^Step ID/)).toHaveValue(demoScenario.steps[0]!.id);
    await user.click(screen.getByRole("button", { name: "Close step details" }));
    expect(screen.queryByLabelText(/^Step ID/)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Show node inspector" })).toHaveFocus();
    await user.keyboard("{Enter}");
    expect(screen.getByLabelText(/^Step ID/)).toHaveValue(demoScenario.steps[0]!.id);
    expect(screen.getByRole("button", { name: "Hide node inspector" })).toHaveFocus();
  });
  it("refreshes changed graph inputs and removes a method when its behavior changes", async () => {
    const user = userEvent.setup();
    renderBuilder();
    await screen.findByRole("textbox", { name: "Experiment name" });
    await user.click(screen.getByRole("button", { name: "Select method in context" }));
    await user.click(screen.getByRole("button", { name: "Approve current context" }));
    const original = renderedGraphs.at(-1)!;
    expect(original.nodes![0]!.data.method).toBe(demoCatalog.actions.find((action) => action.id === "sandbox.fixture.create.v1")!.title);
    const originalBytes = localStorage.getItem("bluefire.local.scenario.v1");
    const selectedId = demoScenario.steps[1]!.id;
    fireEvent.click(screen.getByTestId(`rf__node-${selectedId}`));
    expect(renderedGraphs.at(-1)!.nodes!.filter((node) => node.selected).map((node) => node.id)).toEqual([selectedId]);
    for (const node of renderedGraphs.at(-1)!.nodes!) expect(node.data).toBe(original.nodes!.find((item) => item.id === node.id)!.data);
    for (const edge of renderedGraphs.at(-1)!.edges!) expect(edge.data).toBe(original.edges!.find((item) => item.id === edge.id)!.data);
    expect(localStorage.getItem("bluefire.local.scenario.v1")).toBe(originalBytes);
    nodeRenders.length = 0;
    await user.click(screen.getByRole("button", { name: "Change first behavior in context" }));
    expect(nodeRenders).toContain(demoScenario.steps[0]!.id);
    expect(screen.getByLabelText("Selected methods")).toHaveTextContent("{}");
    expect(screen.getByLabelText("Approval state")).toHaveTextContent("none");
    await waitFor(() => expect(renderedGraphs.at(-1)!.nodes).not.toBe(original.nodes));
    expect(renderedGraphs.at(-1)!.nodes![0]!.data.behavior).toEqual(demoCatalog.behaviors.find((behavior) => behavior.id === demoScenario.steps[1]!.behavior_id));
    expect(renderedGraphs.at(-1)!.nodes![0]!.data.method).toBeUndefined();
    expect(renderedGraphs.at(-1)!.nodes!.find((node) => node.id === selectedId)!.selected).toBe(true);

    await user.click(screen.getByRole("button", { name: "Move first step in context" }));
    await waitFor(() => expect(renderedGraphs.at(-1)!.nodes![0]!.position).toEqual({ x: 902, y: 301 }));
    expect(renderedGraphs.at(-1)!.nodes!.find((node) => node.id === selectedId)!.selected).toBe(true);
    await user.click(screen.getByRole("button", { name: "Clear routes in context" }));
    await waitFor(() => expect(renderedGraphs.at(-1)!.edges!.filter((edge) => edge.data?.kind === "route")).toHaveLength(0));
    await user.click(screen.getByRole("button", { name: "Change start in context" }));
    await waitFor(() => expect(renderedGraphs.at(-1)!.nodes!.filter((node) => !node.hidden).map((node) => node.id)).toEqual([demoScenario.steps[1]!.id]));
    const persisted = JSON.parse(window.localStorage.getItem("bluefire.local.scenario.v1")!);
    expect(persisted.title).toBe(demoScenario.title);
    expect(persisted.start).toBe(demoScenario.steps[1]!.id);
    expect(persisted.edges).toEqual([]);
  });
});
