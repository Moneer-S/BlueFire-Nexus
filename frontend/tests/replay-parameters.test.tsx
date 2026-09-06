import { fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { ReplayParameterEditor, type ReplayParameterOverrides } from "../src/components/ReplayParameterEditor";
import { demoBehaviors, demoScenario } from "../src/lib/demo";
import type { Behavior, Scenario } from "../src/types";

const behavior: Behavior = {
  ...structuredClone(demoBehaviors[0]!), title: "Collect reviewed records",
  parameters: [
    { name: "record_count", type: "integer", required: true, minimum: 1, maximum: 9 },
    { name: "ratio", type: "number", minimum: null, maximum: null },
    { name: "enabled", type: "boolean" },
    { name: "number_choice", type: "integer", enum: [1, 2] },
    { name: "boolean_choice", type: "boolean", enum: [true, false] },
    { name: "list_choice", type: "string_list", enum: [["alpha"], ["beta", "gamma"]] },
    { name: "tags", type: "string_list" },
    { name: "optional_count", type: "integer", default: null, minimum: null, maximum: null },
    { name: "null_count", type: "number", default: null, minimum: null, maximum: null },
    { name: "declared_default", type: "integer", default: 7 },
  ],
};
const scenario: Scenario = {
  ...structuredClone(demoScenario), start: "collect", edges: [],
  steps: [{ id: "collect", behavior_id: behavior.id, parameters: { record_count: 3, ratio: 0.5, enabled: false, number_choice: 1, boolean_choice: false, list_choice: ["alpha"], tags: ["blue"], null_count: null }, inputs: {}, alternates: [] }],
};

function Harness({ initial = {}, disabled = false }: { initial?: ReplayParameterOverrides; disabled?: boolean }) {
  const [value, setValue] = useState(initial);
  const [valid, setValid] = useState(true);
  return <><ReplayParameterEditor scenario={scenario} behaviors={[behavior]} value={value} disabled={disabled} onChange={(next) => setValue(JSON.parse(JSON.stringify(next)))} onValidityChange={setValid} />
    <output aria-label="Typed overrides">{JSON.stringify(value)}</output>
    <button disabled={!valid}>Prepare reviewed replay</button>
    <button onClick={() => setValue(structuredClone(value))}>Replace external value</button>
    <button onClick={() => setValue({})}>Clear external overrides</button>
  </>;
}
const overrides = () => JSON.parse(screen.getByLabelText("Typed overrides").textContent ?? "{}");
const prepare = () => screen.getByRole("button", { name: "Prepare reviewed replay" });
async function edit(name: string) {
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: `Change ${name}` }));
  return user;
}

describe("typed replay parameter changes", () => {
  it("shows human step and parameter labels without inventing absent or null source values", () => {
    const change = vi.fn();
    render(<ReplayParameterEditor scenario={scenario} behaviors={[behavior]} value={{}} onChange={change} />);
    expect(screen.getByText("Step 1: Collect reviewed records")).toBeVisible();
    expect(within(screen.getByRole("group", { name: "Optional count" })).getByText(/Not set in original/)).toBeVisible();
    expect(within(screen.getByRole("group", { name: "Declared default" })).getByText(/Not set in original/)).toBeVisible();
    expect(within(screen.getByRole("group", { name: "Null count" })).getByText(/Null in original/)).toBeVisible();
    expect(change).not.toHaveBeenCalled();
    expect(screen.queryByRole("textbox", { name: /JSON/i })).not.toBeInTheDocument();
  });

  it("focuses the opened control, emits an integer override, and resets to the source", async () => {
    render(<Harness />);
    const user = await edit("Record count");
    const input = screen.getByRole("spinbutton", { name: "Record count" });
    expect(input).toHaveFocus();
    await user.clear(input);
    expect(input).toHaveValue(null);
    expect(prepare()).toBeDisabled();
    expect(overrides()).toEqual({});
    await user.type(input, "7");
    expect(overrides()).toEqual({ collect: { record_count: 7 } });
    expect(prepare()).toBeEnabled();
    expect(within(screen.getByRole("group", { name: "Record count" })).getByText("Override changed")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Reset Record count to original" }));
    expect(overrides()).toEqual({});
    expect(screen.getByRole("button", { name: "Change Record count" })).toHaveFocus();
    expect(scenario.steps[0]!.parameters.record_count).toBe(3);
  });

  it.each(["", "NaN", "0", "10", "2.5"])("keeps invalid numeric draft %j visible and blocks the previous valid override", (draft) => {
    render(<Harness initial={{ collect: { record_count: 4 } }} />);
    const input = screen.getByRole("spinbutton", { name: "Record count" });
    fireEvent.change(input, { target: { value: draft } });
    expect(input).toHaveValue(draft === "" || draft === "NaN" ? null : Number(draft));
    expect(screen.getByRole("group", { name: "Record count" })).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByRole("alert")).toBeVisible();
    expect(prepare()).toBeDisabled();
    expect(overrides()).toEqual({ collect: { record_count: 4 } });
    expect(screen.getByLabelText("Typed overrides")).not.toHaveTextContent("null");
    fireEvent.change(input, { target: { value: "5" } });
    expect(overrides()).toEqual({ collect: { record_count: 5 } });
    expect(prepare()).toBeEnabled();
  });

  it("preserves fractional and negative numbers when numeric bounds are null", async () => {
    render(<Harness />);
    const user = await edit("Ratio");
    const input = screen.getByRole("spinbutton", { name: "Ratio" });
    await user.clear(input);
    await user.type(input, "-2.5");
    expect(overrides()).toEqual({ collect: { ratio: -2.5 } });
    expect(prepare()).toBeEnabled();
  });

  it("preserves numeric, boolean and array enum members as their actual types", async () => {
    render(<Harness />);
    const user = await edit("Number choice");
    const numbers = screen.getByRole("combobox", { name: "Number choice" });
    await user.selectOptions(numbers, within(numbers).getByRole("option", { name: "2" }));
    expect(overrides()).toEqual({ collect: { number_choice: 2 } });
    await edit("Boolean choice");
    const booleans = screen.getByRole("combobox", { name: "Boolean choice" });
    await user.selectOptions(booleans, within(booleans).getByRole("option", { name: "true" }));
    expect(overrides()).toEqual({ collect: { number_choice: 2, boolean_choice: true } });
    await edit("List choice");
    const lists = screen.getByRole("combobox", { name: "List choice" });
    await user.selectOptions(lists, within(lists).getByRole("option", { name: "beta, gamma" }));
    expect(overrides()).toEqual({ collect: { number_choice: 2, boolean_choice: true, list_choice: ["beta", "gamma"] } });
    expect(prepare()).toBeEnabled();
  });

  it("uses real booleans and removes a change when it returns to the original", async () => {
    render(<Harness />);
    const user = await edit("Enabled");
    const checkbox = screen.getByRole("checkbox", { name: /Enabled/ });
    await user.click(checkbox);
    expect(overrides()).toEqual({ collect: { enabled: true } });
    await user.click(checkbox);
    expect(overrides()).toEqual({});
  });

  it("allows typing comma-separated lists without deleting the unfinished separator", async () => {
    render(<Harness />);
    const user = await edit("Tags");
    const input = screen.getByRole("textbox", { name: "Tags" });
    await user.clear(input);
    await user.type(input, "red, blue");
    expect(input).toHaveValue("red, blue");
    expect(overrides()).toEqual({ collect: { tags: ["red", "blue"] } });
  });

  it.each(["Optional count", "Null count"])("does not serialize null or use a default when editing %s", async (name) => {
    render(<Harness />);
    const user = await edit(name);
    expect(prepare()).toBeDisabled();
    expect(overrides()).toEqual({});
    const input = screen.getByRole("spinbutton", { name });
    await user.type(input, "0");
    expect(Object.values(overrides().collect)).toEqual([0]);
    expect(prepare()).toBeEnabled();
    await user.click(screen.getByRole("button", { name: `Reset ${name} to original` }));
    expect(overrides()).toEqual({});
    expect(scenario.steps[0]!.parameters).not.toHaveProperty("optional_count");
    expect(scenario.steps[0]!.parameters.null_count).toBeNull();
  });

  it("clears invalid local drafts on an external value replacement even with equal content", async () => {
    render(<Harness initial={{ collect: { record_count: 4 } }} />);
    fireEvent.change(screen.getByRole("spinbutton", { name: "Record count" }), { target: { value: "" } });
    expect(prepare()).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: "Replace external value" }));
    expect(screen.getByRole("spinbutton", { name: "Record count" })).toHaveValue(4);
    expect(prepare()).toBeEnabled();
  });

  it("retains an invalid numeric draft when another field emits a controlled value echo", async () => {
    render(<Harness initial={{ collect: { record_count: 4 } }} />);
    fireEvent.change(screen.getByRole("spinbutton", { name: "Record count" }), { target: { value: "" } });
    const user = await edit("Enabled");
    await user.click(screen.getByRole("checkbox", { name: /Enabled/ }));
    expect(screen.getByRole("spinbutton", { name: "Record count" })).toHaveValue(null);
    expect(overrides()).toEqual({ collect: { record_count: 4, enabled: true } });
    expect(prepare()).toBeDisabled();
  });

  it("clears local drafts when source content changes under the same scenario ID", () => {
    const changed = vi.fn(); const valid = vi.fn(); const value = { collect: { record_count: 4 } };
    const view = render(<ReplayParameterEditor scenario={scenario} behaviors={[behavior]} value={value} onChange={changed} onValidityChange={valid} />);
    fireEvent.change(screen.getByRole("spinbutton", { name: "Record count" }), { target: { value: "" } });
    expect(valid).toHaveBeenLastCalledWith(false);
    const next = structuredClone(scenario); next.steps[0]!.parameters.record_count = 8;
    view.rerender(<ReplayParameterEditor scenario={next} behaviors={[behavior]} value={value} onChange={changed} onValidityChange={valid} />);
    expect(screen.getByRole("spinbutton", { name: "Record count" })).toHaveValue(4);
    expect(within(screen.getByRole("group", { name: "Record count" })).getByText(/Original: 8/)).toBeVisible();
    expect(valid).toHaveBeenLastCalledWith(true);
  });

  it("prevents edits and resets while disabled", () => {
    const change = vi.fn();
    render(<ReplayParameterEditor scenario={scenario} behaviors={[behavior]} value={{ collect: { record_count: 4 } }} onChange={change} disabled />);
    const input = screen.getByRole("spinbutton", { name: "Record count" });
    expect(input).toBeDisabled();
    expect(screen.getByRole("button", { name: "Reset Record count to original" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Change Ratio" })).toBeDisabled();
    fireEvent.change(input, { target: { value: "5" } });
    expect(change).not.toHaveBeenCalled();
  });

  it("does not label an externally supplied original value as a changed value", () => {
    render(<Harness initial={{ collect: { record_count: 3 } }} />);
    const row = within(screen.getByRole("group", { name: "Record count" }));
    expect(row.getByText("Override matches original")).toBeVisible();
    expect(row.queryByText("Override changed")).not.toBeInTheDocument();
    expect(overrides()).toEqual({ collect: { record_count: 3 } });
  });

  it.each<ReplayParameterOverrides>([{ collect: { record_count: null } }, { collect: { unknown_parameter: 1 } }, { absent_step: { count: 1 } }])("exposes invalid supplied overrides without silently dropping them", (initial) => {
    render(<Harness initial={initial} />);
    expect(prepare()).toBeDisabled();
    expect(overrides()).toEqual(initial);
    expect(screen.getByRole("alert")).toBeVisible();
  });
});
