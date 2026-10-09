import { describe, expect, it } from "vitest";
import { graphStepName } from "../src/components/GraphDeleteDialog";
import { ApiError } from "../src/lib/api";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { scenarioAuthoringFailure, scenarioDiagnostics } from "../src/lib/scenario-diagnostics";
import type { Scenario } from "../src/types";

const behaviors = new Map(demoCatalog.behaviors.map(behavior => [behavior.id, behavior]));
const project = (details: unknown, scenario = demoScenario) => scenarioDiagnostics(details, scenario, behaviors, id => graphStepName(scenario, behaviors, id));
const failure = (error: unknown) => scenarioAuthoringFailure(error, demoScenario, behaviors, id => graphStepName(demoScenario, behaviors, id));

describe("safe authoring diagnostics", () => {
  it("names disconnected copies distinctly and binds only exact existing steps", () => {
    const scenario = structuredClone(demoScenario);
    scenario.steps.push({ ...structuredClone(scenario.steps[0]!), id: "place_fixture_copy" });
    expect(project(["scenario contains unreachable steps: place_fixture_copy, missing_step"], scenario)).toEqual([
      { stepId: "place_fixture_copy", message: "Place deterministic fixture (step 8): This step cannot be reached. Connect a route from an earlier step, or remove it." },
    ]);
    expect(project(["step place_fixture_copy.parameters.record_count must have type integer"], scenario)[0]).toEqual({ stepId: "place_fixture_copy", message: "Place deterministic fixture (step 8): Record count is invalid. Enter a whole number." });
  });

  it.each([
    ["step stage is missing input bindings: records", "stage", /required inputs: Records/],
    ["step stage input records is not guaranteed by all incoming paths", "stage", /Records needs a compatible output.*every incoming path/],
    ["step place_fixture.parameters.record_count is below the minimum", "place_fixture", /Record count is invalid.*allowed range/],
    ["step stage.parameters.bundle_format is not an allowed value", "stage", /Bundle format is invalid.*allowed values/],
  ])("projects the known registry failure %s", (detail, stepId, message) => {
    expect(project([detail])).toEqual([{ stepId, message: expect.stringMatching(message) }]);
  });

  it("keeps graph-wide findings actionable without inventing a highlighted step", () => {
    expect(project(["scenario graph contains a cycle"])).toEqual([{ message: "A route loops back to an earlier step. Remove the loop so every path can finish." }]);
  });

  it.each([
    ["Traceback:\n  C:\\example\\internal.py:42\nconfidential value"],
    ["C:\\example\\private.db"],
    [{ stack: "confidential value" }],
    ["step missing_step.parameters.record_count is below the minimum"],
    ["step place_fixture.parameters.unknown_secret is not an allowed value"],
    ["step place_fixture.parameters.record_count is below the minimum" + " ".repeat(1600)],
    { unexpected: "confidential value" },
  ].map(details => ({ details })))("does not expose unrecognized or oversized details %#", ({ details }) => {
    expect(project(details)).toEqual([{ message: "Review the experiment’s steps, connections and parameters, then validate again." }]);
  });

  it("bounds both inspected details and resulting step guidance", () => {
    const scenario: Scenario = { ...structuredClone(demoScenario), steps: Array.from({ length: 30 }, (_, index) => ({ ...structuredClone(demoScenario.steps[0]!), id: `copy_${index}` })) };
    const detail = `scenario contains unreachable steps: ${scenario.steps.map(step => step.id).join(", ")}`;
    expect(project([detail], scenario)).toHaveLength(8);
    expect(project([...Array.from({ length: 8 }, () => null), detail], scenario)).toEqual([{ message: "Review the experiment’s steps, connections and parameters, then validate again." }]);
  });

  it.each(["scenario_invalid", "scenario_version_invalid"])("accepts details only from the explicit %s rejection contract", code => {
    const result = failure(new ApiError("Generic safe summary", code, ["scenario contains unreachable steps: stage"], 422));
    expect(result.rejected).toBe(true);
    expect(result.findings[0]?.stepId).toBe("stage");
    for (const error of [new ApiError("confidential value", "unknown_error", ["scenario contains unreachable steps: stage"], 422), new ApiError("confidential value", code, ["scenario contains unreachable steps: stage"], 500), new Error("confidential value")]) {
      expect(failure(error)).toEqual({ rejected: false, findings: [{ message: "The request could not be completed. Try again; your working copy is preserved." }] });
    }
  });
});
