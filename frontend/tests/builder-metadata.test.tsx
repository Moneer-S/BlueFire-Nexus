import * as Tooltip from "@radix-ui/react-tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { NodeProps, ReactFlowProps } from "@xyflow/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import * as graphView from "../src/lib/graph-view";
import { BuilderPage } from "../src/pages/Builder";
import { ProductProvider, useProduct } from "../src/state/ProductContext";
import type { Scenario, ScenarioEdge } from "../src/types";

const nodeRenders = vi.hoisted(() => [] as string[]);
const renderedGraphs = vi.hoisted(() => [] as Pick<ReactFlowProps, "nodes" | "edges" | "onNodesChange">[]);
beforeEach(() => { nodeRenders.length = 0; renderedGraphs.length = 0; });
vi.mock("@xyflow/react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@xyflow/react")>();
  const measuredTypes = new WeakMap<object, ReactFlowProps["nodeTypes"]>();
  return {
    ...actual,
    ReactFlow: (props: ReactFlowProps) => {
      renderedGraphs.push({ nodes: props.nodes, edges: props.edges, onNodesChange: props.onNodesChange });
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
  return { ...render(<QueryClientProvider client={client}><Tooltip.Provider><MemoryRouter><ProductProvider><ContextControls /><BuilderPage /></ProductProvider></MemoryRouter></Tooltip.Provider></QueryClientProvider>), client };
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
  it("refreshes saved work listings after saving a renamed experiment", async () => {
    const { client } = renderBuilder();
    client.setQueryData(["scenarios"], { scenarios: [demoScenario] });
    client.setQueryData(["scenario-versions"], { scenarios: [] });
    client.setQueryData(["scenario-versions", "history", demoScenario.id], []);
    const save = vi.spyOn(api, "saveScenarioVersion").mockImplementation(async (document) => ({
      schema_version: "bluefire.scenario-versions.v1",
      scenario: { scenario_id: document.id, title: document.title, version: 2, digest: "a".repeat(64), created_at: "2026-10-21T00:00:00Z", document },
    }));
    fireEvent.change(await screen.findByRole("textbox", { name: "Experiment name" }), { target: { value: "A useful saved experiment name" } });
    expect(screen.getAllByRole("textbox", { name: "Experiment name" })).toHaveLength(1);
    expect(screen.getByRole("heading", { level: 1, name: "A useful saved experiment name" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Save version" }));
    await screen.findByText("Version 2 saved.");
    expect(save).toHaveBeenCalledWith(expect.objectContaining({ title: "A useful saved experiment name" }));
    expect(client.getQueryState(["scenarios"])?.isInvalidated).toBe(true);
    expect(client.getQueryState(["scenario-versions"])?.isInvalidated).toBe(true);
    expect(client.getQueryState(["scenario-versions", "history", demoScenario.id])?.isInvalidated).toBe(true);
  });

  it.each(["absent", "partial", "complete"] as const)(
    "builds fallback positions once for a %s saved layout and keeps them presentation-only",
    async (mode) => {
      const scenario = largeLayoutScenario(mode);
      const originalLayout = structuredClone(scenario.layout);
      const layout = vi.spyOn(graphView, "initialGraphLayout");
      const { unmount } = renderBuilder(scenario);
      try {
        const name = await screen.findByRole("textbox", { name: "Experiment name" });
        const viewControls = within(screen.getByLabelText("Experiment view"));
        await waitFor(() => expect(renderedGraphs.at(-1)?.nodes).toHaveLength(128));

        expect(layout).toHaveBeenCalledTimes(mode === "complete" ? 0 : 1);
        const nodes = renderedGraphs.at(-1)!.nodes!;
        const positions = new Map(nodes.map(node => [node.id, node.position]));
        for (const node of nodes) {
          const saved = scenario.layout?.[node.id];
          if (saved) expect(node.position).toEqual(saved);
          expect(Number.isFinite(node.position.x) && Number.isFinite(node.position.y)).toBe(true);
        }
        if (mode !== "complete") {
          // Check every pair, but report offending identities in one assertion
          // instead of constructing thousands of independent matcher contexts.
          const collisions: [string, string][] = [];
          for (let index = 0; index < nodes.length; index += 1) for (let otherIndex = index + 1; otherIndex < nodes.length; otherIndex += 1) {
            const node = nodes[index]!, other = nodes[otherIndex]!;
            const a = node.position, b = other.position;
            if (!(a.x + graphView.GRAPH_NODE_WIDTH <= b.x || b.x + graphView.GRAPH_NODE_WIDTH <= a.x || a.y + graphView.GRAPH_NODE_HEIGHT <= b.y || b.y + graphView.GRAPH_NODE_HEIGHT <= a.y)) collisions.push([node.id, other.id]);
          }
          expect(collisions).toEqual([]);
          // Generated column flow reads down each column, then right: a success
          // route never points back up or left against that reading order.
          const backwardEdges = scenario.edges.filter(edge => edge.outcome === "success" && !scenario.layout?.[edge.from_step] && !scenario.layout?.[edge.to_step]
            && positions.get(edge.to_step)!.x <= positions.get(edge.from_step)!.x && positions.get(edge.to_step)!.y <= positions.get(edge.from_step)!.y);
          expect(backwardEdges).toEqual([]);
        }
        const originalCoordinates = nodes.map(({ id, position }) => [id, { ...position }] as const);
        expect(JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!).layout).toEqual(originalLayout);

        fireEvent.change(name, {
          target: { value: `${scenario.title} edited` },
        });
        fireEvent.click(viewControls.getByRole("button", { name: "Steps" }));
        expect(viewControls.getByRole("button", { name: "Steps" })).toHaveAttribute("aria-pressed", "true");
        fireEvent.click(viewControls.getByRole("button", { name: "Canvas" }));
        expect(viewControls.getByRole("button", { name: "Canvas" })).toHaveAttribute("aria-pressed", "true");
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
  it("updates folded route summaries without replacing obstacles or unaffected graph data", async () => {
    const steps = demoScenario.steps.slice(0, 3).map(step => ({ ...structuredClone(step), inputs: {} }));
    const scenario: Scenario = {
      ...structuredClone(demoScenario), id: "builder-aggregate-metadata", steps, start: steps[0]!.id,
      edges: [
        { from_step: steps[0]!.id, outcome: "success", to_step: steps[1]!.id },
        { from_step: steps[1]!.id, outcome: "success", to_step: steps[2]!.id },
        ...(["partial", "blocked", "failed"] as const).map(outcome => ({ from_step: steps[0]!.id, outcome, to_step: steps[1]!.id })),
      ],
      layout: Object.fromEntries(steps.map((step, index) => [step.id, { x: 48, y: 48 + index * 200 }])),
    };
    renderBuilder(scenario);
    fireEvent.click(await screen.findByRole("button", { name: "Show route list" }));
    const buttons = within(screen.getByRole("list", { name: "Visible routes" })).getAllByRole("button");
    fireEvent.click(buttons[1]!);
    const original = renderedGraphs.at(-1)!;
    const aggregate = original.edges![0]!;
    const obstacles = aggregate.data!.obstacles;
    expect(obstacles).toHaveLength(steps.length);
    const originalBytes = localStorage.getItem("bluefire.local.scenario.v1");
    expect(aggregate.data!.alsoOn).toEqual(["partial", "blocked", "failed"]);
    expect(aggregate.ariaLabel).toContain("Any outcome");
    expect(original.edges!.slice(2).every(edge => edge.hidden)).toBe(true);

    for (const [index, remaining] of [[2, ["blocked", "failed"]], [3, ["partial", "failed"]]] as const) {
      fireEvent.click(buttons[index]!);
      const inspected = renderedGraphs.at(-1)!;
      expect(inspected.edges![0]!.data).not.toBe(aggregate.data);
      expect(inspected.edges![0]!.data!.alsoOn).toEqual(remaining);
      expect(inspected.edges![0]!.ariaLabel).toContain(`Also ${remaining.join(", ")}`);
      expect(inspected.edges![index]!.selected).toBe(true);
      expect(inspected.edges![index]!.hidden).toBe(false);
      for (const edge of inspected.edges!) {
        expect(edge.data!.obstacles).toBe(obstacles);
        if (edge.id !== aggregate.id) expect(edge.data).toBe(original.edges!.find(item => item.id === edge.id)!.data);
      }
      for (const node of inspected.nodes!) expect(node.data).toBe(original.nodes!.find(item => item.id === node.id)!.data);
      expect(localStorage.getItem("bluefire.local.scenario.v1")).toBe(originalBytes);
    }
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
    await user.click(screen.getByLabelText("View options", { selector: "summary" }));
    await user.click(screen.getByRole("button", { name: "Focus on success path" }));
    await user.click(screen.getByRole("button", { name: "Clear routes in context" }));
    await waitFor(() => expect(renderedGraphs.at(-1)!.edges!.filter((edge) => edge.data?.kind === "route")).toHaveLength(0));
    await user.click(screen.getByRole("button", { name: "Change start in context" }));
    await waitFor(() => expect(renderedGraphs.at(-1)!.nodes!.filter((node) => !node.hidden).map((node) => node.id)).toEqual([demoScenario.steps[1]!.id]));
    const persisted = JSON.parse(window.localStorage.getItem("bluefire.local.scenario.v1")!);
    expect(persisted.title).toBe(demoScenario.title);
    expect(persisted.start).toBe(demoScenario.steps[1]!.id);
    expect(persisted.edges).toEqual([]);
  });

  it("refreshes moved connection handles without replacing unchanged node data", async () => {
    const steps = demoScenario.steps.slice(0, 3).map(step => ({ ...structuredClone(step), inputs: {} }));
    const scenario = {
      ...structuredClone(demoScenario), steps, start: steps[0]!.id,
      edges: steps.slice(1).map((step, index) => ({ from_step: steps[index]!.id, outcome: "success" as const, to_step: step.id })),
      layout: Object.fromEntries(steps.map((step, index) => [step.id, { x: 48, y: 48 + index * 200 }])),
    };
    renderBuilder(scenario);
    await screen.findByRole("textbox", { name: "Experiment name" });
    const original = renderedGraphs.at(-1)!;
    expect(original.nodes![0]!.data.routeOut).toBe("bottom");
    expect(original.nodes![1]!.data.routeIn).toBe("top");

    act(() => original.onNodesChange?.([{ id: steps[0]!.id, type: "position", position: { x: 902, y: 301 }, dragging: true }]));
    const moved = renderedGraphs.at(-1)!;
    expect(moved.nodes![0]!.data.routeOut).toBe("right");
    expect(moved.nodes![1]!.data.routeIn).toBe("left");
    expect(moved.nodes![0]!.data).not.toBe(original.nodes![0]!.data);
    expect(moved.nodes![1]!.data).not.toBe(original.nodes![1]!.data);
    expect(moved.nodes![2]!.data).toBe(original.nodes![2]!.data);
    expect(JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!).layout).toEqual(scenario.layout);
  });
});
