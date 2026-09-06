import { describe, expect, it } from "vitest";
import { graphView, initialGraphLayout } from "../src/lib/graph-view";
import { deleteScenarioGraphElements } from "../src/lib/scenario";
import { demoScenario } from "../src/lib/demo";
import type { Scenario, ScenarioStep } from "../src/types";

function branchedScenario(): Scenario {
  return { ...structuredClone(demoScenario), start: "first", steps: ["first", "normal", "alternative", "cleanup", "detached"].map((id): ScenarioStep => ({ ...structuredClone(demoScenario.steps[0]!), id, inputs: id === "cleanup" ? { files: { from_step: "alternative", artifact: "files" } } : {} })), edges: [
    { from_step: "first", outcome: "success", to_step: "normal" },
    { from_step: "first", outcome: "blocked", to_step: "alternative" },
    { from_step: "normal", outcome: "success", to_step: "cleanup" },
    { from_step: "alternative", outcome: "success", to_step: "cleanup" },
    { from_step: "cleanup", outcome: "failed", to_step: "first" },
  ], layout: { first: { x: 915, y: 21 } } };
}

describe("experiment presentation", () => {
  it("focuses the success path while retaining hidden inputs, branches, and saved positions", () => {
    const scenario = branchedScenario(); const serialized = JSON.stringify(scenario);
    const view = graphView(scenario, false);
    expect([...view.visible]).toEqual(["first", "normal", "cleanup"]);
    expect(view.hiddenSteps).toBe(2);
    expect(view.hiddenBranches).toBe(3);
    expect(scenario.steps[3]?.inputs.files).toEqual({ from_step: "alternative", artifact: "files" });
    initialGraphLayout(scenario);
    expect(JSON.stringify(scenario)).toBe(serialized);
  });

  it("expands one decision branch including a shared continuation without looping", () => {
    const scenario = branchedScenario();
    expect([...graphView(scenario, false, new Set(["first", "cleanup"])).visible]).toEqual(["first", "normal", "alternative", "cleanup"]);
    expect(graphView(scenario, true).hiddenSteps).toBe(0);
    expect(graphView(scenario, false).hiddenSteps).toBe(2);
  });

  it("deleting a visible step still repairs connections from the full experiment", () => {
    const scenario = branchedScenario();
    graphView(scenario, false);
    const result = deleteScenarioGraphElements(scenario, ["cleanup"], []);
    expect(result.edges.some((edge) => edge.to_step === "cleanup" || edge.from_step === "cleanup")).toBe(false);
    expect(result.steps.map((step) => step.id)).toContain("alternative");
    expect(scenario.steps).toHaveLength(5);
  });

  it("shows a broken start as empty focus with an explicit hidden count and a complete all-steps view", () => {
    const scenario = { ...branchedScenario(), start: "missing" };
    expect(graphView(scenario, false).hiddenSteps).toBe(5);
    expect(graphView(scenario, true).ordered).toHaveLength(5);
  });
});
