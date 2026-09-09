import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { expect, it, vi } from "vitest";
import { ParameterField } from "../src/components/ParameterField";
import { ReplayParameterEditor, type ReplayParameterOverrides } from "../src/components/ReplayParameterEditor";
import { demoBehaviors, demoScenario } from "../src/lib/demo";
import { stepParameterSummary } from "../src/lib/graph-authoring";
import { parameterValueLabel } from "../src/lib/parameters";
import type { Behavior, ParameterSpec, Scenario } from "../src/types";

const spec: ParameterSpec = { name: "stage_variant", type: "string", enum: ["primary", "heldout"], default: "primary" };
const ids = ["sandbox.collection.records.v1", "sandbox.collection.archive.v1", "sandbox.collection.atomic-gzip.v1"];
it.each(ids)("labels only the folder choices for %s and returns unchanged enum values", async (id) => {
  const user = userEvent.setup(); const change = vi.fn();
  const behavior: Behavior = { ...demoBehaviors[0]!, id, parameters: [spec] };
  const step = { ...demoScenario.steps[0]!, behavior_id: id, parameters: { stage_variant: "primary" } };
  const original = JSON.stringify({ behavior, step });
  const view = render(<ParameterField spec={spec} behaviorId={id} value="primary" onChange={change}/>);
  expect(screen.getByRole("combobox")).toHaveDisplayValue("Main staging folder");
  await user.selectOptions(screen.getByRole("combobox"), screen.getByRole("option", { name: "Alternate staging folder" }));
  expect(change).toHaveBeenLastCalledWith("heldout");
  view.rerender(<ParameterField spec={spec} behaviorId={id} value="heldout" onChange={change}/>);
  expect(screen.getByRole("combobox")).toHaveDisplayValue("Alternate staging folder");
  await user.selectOptions(screen.getByRole("combobox"), screen.getByRole("option", { name: "Main staging folder" }));
  expect(change).toHaveBeenLastCalledWith("primary");
  expect(stepParameterSummary(step, behavior)).toBe("Stage variant: Main staging folder");
  expect(stepParameterSummary({ ...step, parameters: { stage_variant: "heldout" } }, behavior)).toBe("Stage variant: Alternate staging folder");
  expect(JSON.stringify({ behavior, step })).toBe(original);
});

it("does not relabel unrelated behaviors, parameter names or future values", () => {
  render(<ParameterField spec={spec} behaviorId="custom.collection.v1" value="heldout" onChange={vi.fn()}/>);
  expect(screen.getByRole("combobox")).toHaveDisplayValue("heldout");
  expect(parameterValueLabel(ids[0], "case_role", "heldout")).toBeUndefined();
  expect(parameterValueLabel(ids[0], "stage_variant", "future")).toBeUndefined();
  expect(parameterValueLabel(undefined, "stage_variant", "primary")).toBeUndefined();
});

it("round-trips a readable replay override without changing the source or retaining a reset override", async () => {
  const user = userEvent.setup();
  const behavior: Behavior = { ...demoBehaviors[0]!, id: ids[2]!, parameters: [spec] };
  const scenario: Scenario = { ...structuredClone(demoScenario), steps: [{ ...demoScenario.steps[0]!, id: "collect", behavior_id: behavior.id, parameters: { stage_variant: "primary" } }], edges: [], start: "collect" };
  const original = JSON.stringify(scenario);
  function Harness() {
    const [value, setValue] = useState<ReplayParameterOverrides>({});
    return <><ReplayParameterEditor scenario={scenario} behaviors={[behavior]} value={value} onChange={setValue}/><output aria-label="Exact overrides">{JSON.stringify(value)}</output></>;
  }
  render(<Harness/>);
  const row = within(screen.getByRole("group", { name: "Stage variant" }));
  expect(row.getByText(/Original: Main staging folder/)).toBeVisible();
  await user.click(row.getByRole("button", { name: "Change Stage variant" }));
  await user.selectOptions(row.getByRole("combobox"), row.getByRole("option", { name: "Alternate staging folder" }));
  expect(screen.getByLabelText("Exact overrides")).toHaveTextContent('{"collect":{"stage_variant":"heldout"}}');
  expect(JSON.stringify(scenario)).toBe(original);
  await user.click(row.getByRole("button", { name: "Reset Stage variant to original" }));
  expect(screen.getByLabelText("Exact overrides")).toHaveTextContent("{}");
  expect(JSON.stringify(scenario)).toBe(original);
});
