import * as Tooltip from "@radix-ui/react-tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactFlowProps } from "@xyflow/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { BuilderPage } from "../src/pages/Builder";
import { ProductProvider, useProduct } from "../src/state/ProductContext";

const renderedGraphs = vi.hoisted(() => [] as Pick<ReactFlowProps, "nodes" | "edges">[]);
vi.mock("@xyflow/react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@xyflow/react")>();
  return {
    ...actual,
    ReactFlow: (props: ReactFlowProps) => {
      renderedGraphs.push({ nodes: props.nodes, edges: props.edges });
      return <actual.ReactFlow {...props} />;
    },
  };
});

function ContextControls() {
  const { scenario, setScenario, runConfig, setRunConfig, dirty } = useProduct();
  return <>
    <output aria-label="Draft state">{dirty ? "dirty" : "saved"}</output>
    <output aria-label="Approval state">{runConfig.approved ? runConfig.approvedBy : "none"}</output>
    <output aria-label="Selected methods">{JSON.stringify(runConfig.actionImplementations)}</output>
    <button onClick={() => setRunConfig({ ...runConfig, actionImplementations: { [scenario.steps[0]!.id]: "test-selected-method" } })}>Select method in context</button>
    <button onClick={() => setRunConfig({ ...runConfig, approved: true, approvedBy: "test-reviewer" })}>Approve current context</button>
    <button onClick={() => setScenario({ ...scenario, steps: scenario.steps.map((step, index) => index ? step : { ...step, behavior_id: scenario.steps[1]!.behavior_id }) })}>Change first behavior in context</button>
    <button onClick={() => setScenario({ ...scenario, layout: { ...scenario.layout, [scenario.steps[0]!.id]: { x: 902, y: 301 } } })}>Move first step in context</button>
    <button onClick={() => setScenario({ ...scenario, edges: [] })}>Clear routes in context</button>
    <button onClick={() => setScenario({ ...scenario, start: scenario.steps[1]!.id })}>Change start in context</button>
  </>;
}

function renderBuilder() {
  window.localStorage.setItem("bluefire.local.scenario.v1", JSON.stringify(demoScenario));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(["catalog"], demoCatalog);
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  return render(<QueryClientProvider client={client}><Tooltip.Provider><MemoryRouter><ProductProvider><ContextControls /><BuilderPage /></ProductProvider></MemoryRouter></Tooltip.Provider></QueryClientProvider>);
}

describe("Builder metadata and graph updates", () => {
  it("keeps graph objects stable through typed name edits while immediately invalidating approval", async () => {
    const user = userEvent.setup();
    renderBuilder();
    const name = await screen.findByRole("textbox", { name: "Experiment name" });
    await user.click(screen.getByRole("button", { name: "Select method in context" }));
    await user.click(screen.getByRole("button", { name: "Approve current context" }));
    expect(screen.getByLabelText("Approval state")).toHaveTextContent("test-reviewer");
    const original = renderedGraphs.at(-1)!;
    renderedGraphs.length = 0;

    for (const character of " edit") {
      await user.type(name, character);
      expect(screen.getByLabelText("Draft state")).toHaveTextContent("dirty");
      expect(screen.getByLabelText("Approval state")).toHaveTextContent("none");
      expect(screen.getByLabelText("Selected methods")).toHaveTextContent("test-selected-method");
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

  it("refreshes changed graph inputs and removes a method when its behavior changes", async () => {
    const user = userEvent.setup();
    renderBuilder();
    await screen.findByRole("textbox", { name: "Experiment name" });
    await user.click(screen.getByRole("button", { name: "Select method in context" }));
    await user.click(screen.getByRole("button", { name: "Approve current context" }));
    const original = renderedGraphs.at(-1)!;
    await user.click(screen.getByRole("button", { name: "Change first behavior in context" }));
    expect(screen.getByLabelText("Selected methods")).toHaveTextContent("{}");
    expect(screen.getByLabelText("Approval state")).toHaveTextContent("none");
    await waitFor(() => expect(renderedGraphs.at(-1)!.nodes).not.toBe(original.nodes));
    expect(renderedGraphs.at(-1)!.nodes![0]!.data.behavior).toEqual(demoCatalog.behaviors.find((behavior) => behavior.id === demoScenario.steps[1]!.behavior_id));

    await user.click(screen.getByRole("button", { name: "Move first step in context" }));
    await waitFor(() => expect(renderedGraphs.at(-1)!.nodes![0]!.position).toEqual({ x: 902, y: 301 }));
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
