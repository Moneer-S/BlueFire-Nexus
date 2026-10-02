import { fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import { expect, it, vi } from "vitest";
import { InternalBenignFixtureEditor } from "../src/components/InternalBenignFixtureEditor";
import { buildInternalBenignFixtures, readInternalBenignFixtureDraft, readInternalBenignFixtures, type InternalBenignFixtureDraft, type InternalBenignFixtureSample } from "../src/lib/internal-benign-fixtures";
import { structuredRuleFields } from "../src/lib/structured-rule-selection";

function editor(initialSource = "", initialDraft: InternalBenignFixtureDraft | null = null, selection?: Record<string, unknown>, disabled = false) {
  const apply = vi.fn();
  const edited = vi.fn();
  function Harness() {
    const [source, setSource] = useState(initialSource);
    const [draft, setDraft] = useState(initialDraft);
    return <><InternalBenignFixtureEditor source={source} draft={draft} onDraft={next => { edited(next); setDraft(next); }} onApply={next => { apply(next); setSource(next); setDraft(null); }} selection={selection} disabled={disabled} /><output data-testid="sample-source">{source}</output></>;
  }
  render(<Harness />);
  return { apply, edited };
}

const click = (name: string) => fireEvent.click(screen.getByRole("button", { name }));
const change = (name: string, value: string) => fireEvent.change(screen.getByLabelText(name), { target: { value } });

it("creates only a named partial sample and requires explicit Apply", () => {
  const { apply, edited } = editor("", null, { path: "intended", group_write_bit: false });
  expect(edited).not.toHaveBeenCalled();
  expect(screen.getByText(/Omitted fields are unknown/)).toBeVisible();
  click("Add sample");
  expect(screen.getByLabelText("Sample name 1")).toHaveValue("benign-sample-1");
  expect(screen.queryByLabelText("Value 1 for sample 1")).not.toBeInTheDocument();
  expect(screen.getByText(/Missing rule fields/)).toHaveTextContent("Observed path, Group write bit");
  expect(apply).not.toHaveBeenCalled();
  expect(screen.getByTestId("sample-source").textContent).toBe("");
  click("Apply samples");
  expect(apply).toHaveBeenCalledExactlyOnceWith('[{"fixture_id":"benign-sample-1"}]');
  expect(screen.queryByRole("button", { name: "Discard sample edits" })).not.toBeInTheDocument();
});

it("requires chosen fields, counts and booleans without defaulting to zero or false", () => {
  const { apply } = editor();
  click("Add sample");
  click("Add field to sample 1");
  expect(screen.getByLabelText("Field 1 for sample 1")).toHaveValue("");
  expect(screen.getByRole("button", { name: "Apply samples" })).toBeDisabled();
  change("Field 1 for sample 1", "record_count");
  expect(screen.getByLabelText("Value 1 for sample 1")).toHaveValue("");
  expect(screen.getByRole("button", { name: "Apply samples" })).toBeDisabled();
  change("Value 1 for sample 1", "0");
  click("Add field to sample 1");
  change("Field 2 for sample 1", "other_write_bit");
  expect(screen.getByLabelText("Value 2 for sample 1")).toHaveValue("");
  expect(screen.getByRole("button", { name: "Apply samples" })).toBeDisabled();
  change("Value 2 for sample 1", "false");
  click("Add field to sample 1");
  change("Field 3 for sample 1", "permission_mode_octal");
  change("Value 3 for sample 1", "0660");
  click("Apply samples");
  expect(JSON.parse(apply.mock.calls[0]![0])).toEqual([{ fixture_id: "benign-sample-1", record_count: 0, other_write_bit: false, permission_mode_octal: "0660" }]);
});

it("omits a removed field only after Apply and keeps custom text and the other values intact", () => {
  const source = '[ {"fixture_id":"normal-files","path":"  docs/α  ","container":"custom","record_count":8} ]';
  const { apply } = editor(source);
  click("Remove field 2 from sample 1");
  expect(screen.getByTestId("sample-source").textContent).toBe(source);
  expect(apply).not.toHaveBeenCalled();
  click("Apply samples");
  expect(JSON.parse(apply.mock.calls[0]![0])).toEqual([{ fixture_id: "normal-files", path: "  docs/α  ", record_count: 8 }]);
});

it("keeps an authored empty string distinct from removing its field", () => {
  const { apply } = editor('[{"fixture_id":"one","path":"file"}]');
  change("Value 1 for sample 1", "");
  click("Apply samples");
  expect(JSON.parse(apply.mock.calls[0]![0])).toEqual([{ fixture_id: "one", path: "" }]);
  click("Remove field 1 from sample 1");
  click("Apply samples");
  expect(JSON.parse(apply.mock.calls[1]![0])).toEqual([{ fixture_id: "one" }]);
});

it("displays and applies newline text without a single-line input stripping it", () => {
  const value = "first\nsecond\t😀";
  const { apply } = editor(JSON.stringify([{ fixture_id: "one", path: value }]));
  expect(screen.getByLabelText("Value 1 for sample 1")).toHaveValue(value);
  change("Sample name 1", "renamed");
  click("Apply samples");
  expect(JSON.parse(apply.mock.calls[0]![0])).toEqual([{ fixture_id: "renamed", path: value }]);
});

it("generates unique names and retains invalid names and duplicate fields until repaired or discarded", () => {
  const source = '[{"fixture_id":"benign-sample-1","path":"original"}]';
  const { apply, edited } = editor(source);
  click("Add sample");
  expect(screen.getByLabelText("Sample name 2")).toHaveValue("benign-sample-2");
  change("Sample name 2", "benign-sample-1");
  expect(screen.getByRole("alert")).toHaveTextContent("already used");
  expect(screen.getByRole("button", { name: "Apply samples" })).toBeDisabled();
  change("Sample name 2", "");
  const pending = edited.mock.calls.at(-1)![0];
  expect(readInternalBenignFixtureDraft(JSON.stringify(pending))).toEqual(pending);
  click("Discard sample edits");
  expect(screen.queryByLabelText("Sample name 2")).not.toBeInTheDocument();
  click("Add field to sample 1");
  change("Field 2 for sample 1", "path");
  expect(screen.getByRole("alert")).toHaveTextContent("already present");
  expect(apply).not.toHaveBeenCalled();
  expect(screen.getByTestId("sample-source").textContent).toBe(source);
});

it("requires another explicit value after changing a field's type", () => {
  const { apply } = editor('[{"fixture_id":"one","record_count":1}]');
  change("Field 1 for sample 1", "group_write_bit");
  expect(screen.getByLabelText("Value 1 for sample 1")).toHaveValue("");
  expect(screen.getByRole("button", { name: "Apply samples" })).toBeDisabled();
  change("Value 1 for sample 1", "true");
  click("Apply samples");
  expect(JSON.parse(apply.mock.calls[0]![0])).toEqual([{ fixture_id: "one", group_write_bit: true }]);
});

it.each([
  ' [ {"fixture_id":"one","path":null,"custom":{"keep":true}} ] ',
  '[{"fixture_id":"one","path":"first","path":"second"}]',
  '[{"fixture_id":"one","record_count":9007199254740991.1}]',
  '[{"fixture_id":"one","path":"\\ud800"}]',
  JSON.stringify(Array.from({ length: 17 }, (_, index) => ({ fixture_id: `row-${index}` }))),
])("leaves unsupported advanced JSON byte-exact without partial controls (case %#)", source => {
  const { apply, edited } = editor(source);
  expect(screen.getByText(/Use JSON for these samples/)).toBeVisible();
  expect(screen.getByTestId("sample-source").textContent).toBe(source);
  expect(screen.queryByRole("button", { name: "Add sample" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Apply samples" })).not.toBeInTheDocument();
  expect(apply).not.toHaveBeenCalled();
  expect(edited).not.toHaveBeenCalled();
});

it("binds retained edits to their exact source and permits only explicit discard after a source change", () => {
  const source = '[{"fixture_id":"current","path":"current"}]';
  const draft = { source: "", samples: [{ fixtureId: "retained", fields: [{ field: "record_count", value: "1e" }] }] };
  const { apply, edited } = editor(source, draft);
  expect(screen.getByRole("alert")).toHaveTextContent("different JSON inputs");
  expect(screen.queryByRole("button", { name: "Apply samples" })).not.toBeInTheDocument();
  expect(edited).not.toHaveBeenCalled();
  click("Discard sample edits");
  expect(screen.getByLabelText("Sample name 1")).toHaveValue("current");
  expect(screen.getByLabelText("Value 1 for sample 1")).toHaveValue("current");
  expect(screen.getByTestId("sample-source").textContent).toBe(source);
  expect(apply).not.toHaveBeenCalled();
});

it("shows restored incomplete numeric and boolean input without applying it", () => {
  const draft = { source: "", samples: [{ fixtureId: "one", fields: [{ field: "record_count", value: "1e" }, { field: "other_write_bit", value: "invalid" }] }] };
  const { apply, edited } = editor("", draft);
  expect(screen.getByLabelText("Value 1 for sample 1")).toHaveValue("1e");
  expect(screen.getByLabelText("Value 2 for sample 1")).toHaveValue("invalid");
  expect(screen.getByRole("button", { name: "Apply samples" })).toBeDisabled();
  expect(apply).not.toHaveBeenCalled();
  expect(edited).not.toHaveBeenCalled();
});

it("keeps all mutation controls disabled when the lifecycle action is unavailable", () => {
  const draft = { source: "", samples: [{ fixtureId: "one", fields: [{ field: "path", value: "normal" }] }] };
  const { apply, edited } = editor("", draft, undefined, true);
  for (const input of screen.getAllByRole("textbox")) expect(input).toBeDisabled();
  for (const button of screen.getAllByRole("button")) expect(button).toBeDisabled();
  click("Apply samples");
  expect(apply).not.toHaveBeenCalled();
  expect(edited).not.toHaveBeenCalled();
});

it("emits compact JSON at the byte boundary so Apply output remains visually editable", () => {
  const names = structuredRuleFields.filter(field => field.type === "string" && field.key !== "permission_mode_octal").map(field => field.key);
  const samples: InternalBenignFixtureSample[] = Array.from({ length: 16 }, (_, index) => ({ fixtureId: `row-${index}`, fields: names.map(field => ({ field, value: "" })) }));
  const built = buildInternalBenignFixtures(samples);
  if (!built.ok) throw new Error(built.error);
  let remaining = 1048576 - new TextEncoder().encode(JSON.stringify(built.fixtures)).byteLength;
  for (const sample of samples) for (const field of sample.fields) {
    if (remaining >= 3) { const count = Math.min(4096, Math.floor(remaining / 3)); field.value = "漢".repeat(count); remaining -= count * 3; }
    else if (remaining) { field.value = "x".repeat(remaining); remaining = 0; }
  }
  expect(remaining).toBe(0);
  const { apply } = editor("", { source: "", samples });
  expect(screen.getByRole("button", { name: "Add sample" })).toBeDisabled();
  click("Apply samples");
  const output = apply.mock.calls[0]![0] as string;
  expect(new TextEncoder().encode(output).byteLength).toBe(1048576);
  expect(readInternalBenignFixtures(output)).toEqual({ supported: true, samples });
  expect(screen.getByRole("button", { name: "Apply samples" })).toBeDisabled();
  expect(screen.queryByText(/Use JSON for these samples/)).not.toBeInTheDocument();
});

it("retains over-budget samples and keeps their fields editable while Apply is disabled", () => {
  const fields = structuredRuleFields.filter(field => field.type === "string" && field.key !== "permission_mode_octal").map(field => ({ field: field.key, value: "漢".repeat(4096) }));
  const samples = Array.from({ length: 16 }, (_, index) => ({ fixtureId: `row-${index}`, fields: structuredClone(fields) }));
  const draft = { source: "", samples };
  expect(readInternalBenignFixtureDraft(JSON.stringify(draft))).toEqual(draft);
  const { apply } = editor("", draft);
  expect(screen.getByRole("alert")).toHaveTextContent("one-megabyte fixture limit");
  expect(screen.getByRole("button", { name: "Apply samples" })).toBeDisabled();
  expect(screen.getByLabelText("Value 1 for sample 1")).toBeEnabled();
  expect(screen.getByLabelText("Value 6 for sample 16")).toHaveValue("漢".repeat(4096));
  expect(screen.getByTestId("sample-source").textContent).toBe("");
  expect(apply).not.toHaveBeenCalled();
});
