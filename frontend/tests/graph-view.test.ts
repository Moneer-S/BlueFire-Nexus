import { describe, expect, it } from "vitest";
import { graphSections, graphView, initialGraphLayout } from "../src/lib/graph-view";
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
  it("keeps a long connected path whole instead of paging every three steps", () => {
    const steps = Array.from({ length: 25 }, (_, index): ScenarioStep => ({ ...structuredClone(demoScenario.steps[0]!), id: `step_${index}`, inputs: index ? { files: { from_step: `step_${index - 1}`, artifact: "files" } } : {} }));
    const serialized = JSON.stringify(steps);
    const edges = steps.slice(1).map((step, index) => ({ from_step: steps[index]!.id, outcome: "success" as const, to_step: step.id }));
    const sections = graphSections(steps, edges);
    expect(sections.map((section) => section.title)).toEqual(["All steps"]);
    expect(sections.flatMap((section) => section.steps)).toEqual(steps);
    expect(sections[0]?.steps[3]).toBe(steps[3]);
    expect(sections[0]?.steps[3]?.inputs.files).toEqual({ from_step: "step_2", artifact: "files" });
    expect(JSON.stringify(steps)).toBe(serialized);
    expect(graphSections(steps.slice(0, 3))).toHaveLength(1);
    expect(graphSections(steps.slice(0, 12))).toHaveLength(1);
  });
  it("offers focus groups at actual decisions and joins, preserving every step and binding", () => {
    const scenario = branchedScenario();
    const before = structuredClone(scenario);
    const sections = graphSections(scenario.steps, scenario.edges, scenario.start);
    expect(sections.map(section => section.steps.map(step => step.id))).toEqual([["first"], ["normal"], ["alternative"], ["cleanup"], ["detached"]]);
    expect(sections.find(section => section.steps[0]?.id === "cleanup")?.title).toBe("Join at step 4");
    expect(sections.flatMap(section => section.steps)).toEqual(scenario.steps);
    expect(scenario).toEqual(before);
  });
  it("keeps a connected path whole when saved steps are not in route order", () => {
    const steps = ["cleanup", "root", "mid"].map((id): ScenarioStep => ({ ...structuredClone(demoScenario.steps[0]!), id, inputs: {} }));
    const edges: Scenario["edges"] = [{ from_step: "root", outcome: "success", to_step: "mid" }, { from_step: "mid", outcome: "success", to_step: "cleanup" }];
    const before = structuredClone({ steps, edges });
    for (const start of [undefined, "root"]) {
      const sections = graphSections(steps, edges, start);
      expect(sections.map(section => section.title)).toEqual(["All steps"]);
      expect(sections[0]?.steps).toEqual([steps[1], steps[2], steps[0]]);
      expect(sections[0]?.steps[0]).toBe(steps[1]);
    }
    expect({ steps, edges }).toEqual(before);
  });
  it("anchors the actual entry and preserves branch boundaries with a reordered saved graph", () => {
    const scenario = branchedScenario();
    scenario.steps = [scenario.steps[3]!, scenario.steps[2]!, scenario.steps[0]!, scenario.steps[4]!, scenario.steps[1]!];
    const before = structuredClone(scenario);
    const sections = graphSections(scenario.steps, scenario.edges, scenario.start);
    expect(sections[0]?.title).toBe("Main path");
    expect(sections[0]?.steps.map(step => step.id)).toEqual(["first"]);
    expect(sections.find(section => section.steps[0]?.id === "cleanup")?.title).toBe("Join at step 1");
    expect(sections.flatMap(section => section.steps).map(step => step.id).sort()).toEqual(scenario.steps.map(step => step.id).sort());
    expect(sections.flatMap(section => section.steps).every(step => scenario.steps.includes(step))).toBe(true);
    expect(scenario).toEqual(before);
  });
  it("retains an empty view group when the current projection has no visible steps", () => {
    expect(graphSections([], demoScenario.edges, "missing")).toEqual([{ title: "All steps", steps: [] }]);
  });
  it("packs a nine-step success chain in both dimensions without changing saved coordinates or execution", () => {
    const steps = Array.from({ length: 9 }, (_, index) => ({ ...structuredClone(demoScenario.steps[0]!), id: `step_${index}`, inputs: {} }));
    const scenario = { ...structuredClone(demoScenario), steps, start: steps[0]!.id, edges: steps.slice(1).map((step, index) => ({ from_step: steps[index]!.id, outcome: "success" as const, to_step: step.id })), layout: { step_0: { x: 910, y: 600 } } };
    const before = structuredClone(scenario);
    const compact = initialGraphLayout(scenario);
    expect(new Set(Object.values(compact).map(position => position.x)).size).toBeGreaterThan(1);
    expect(new Set(Object.values(compact).map(position => position.y)).size).toBeGreaterThan(1);
    expect(Math.max(...Object.values(compact).map(position => position.x))).toBeLessThan(800);
    expect(initialGraphLayout(scenario, true).step_0).toEqual(scenario.layout.step_0);
    expect(scenario).toEqual(before);
  });
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
