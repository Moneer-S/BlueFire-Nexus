import { describe, expect, it } from "vitest";
import {
  buildStructuredSelection,
  isStructuredRuleDraftText,
  readStructuredRuleDraft,
  readStructuredSelection,
  structuredRuleLimits,
  structuredRuleOperators,
  type StructuredRuleCondition,
} from "../src/lib/structured-rule-selection";

const condition = (field: string, value: string, operator = "equals"): StructuredRuleCondition => ({ field, operator, value });

function expectBuildRefusal(input: StructuredRuleCondition[]) {
  const before = structuredClone(input);
  const frozen = Object.freeze(input.map(item => Object.freeze(item)));
  const result = buildStructuredSelection(frozen);
  expect(result.ok).toBe(false);
  expect(result).not.toHaveProperty("selection");
  if (!result.ok) expect(result.error).toEqual(expect.any(String));
  expect(frozen).toEqual(before);
}

function expectReadRefusal(source: string) {
  const result = readStructuredSelection(source);
  expect(result.supported).toBe(false);
  expect(result).not.toHaveProperty("conditions");
  if (!result.supported) expect(result.reason).toEqual(expect.any(String));
}

describe("visual structured rule selection", () => {
  it("round-trips a mixed permission rule without converting booleans, counts or octal text", () => {
    const selection = {
      observation_kind: "filesystem",
      permission_status: "available",
      permission_mode_octal: "0660",
      group_write_bit: true,
      other_write_bit: false,
      non_owner_write_bit: true,
      record_count: 0,
    };
    const source = JSON.stringify(selection, null, 2);
    const restored = readStructuredSelection(source);
    expect(restored).toEqual({ supported: true, conditions: [
      condition("observation_kind", "filesystem"), condition("permission_status", "available"),
      condition("permission_mode_octal", "0660"), condition("group_write_bit", "true"),
      condition("other_write_bit", "false"), condition("non_owner_write_bit", "true"),
      condition("record_count", "0"),
    ] });
    if (!restored.supported) throw new Error("authored selection should be supported");
    expect(buildStructuredSelection(restored.conditions)).toEqual({ ok: true, selection });
    expect(JSON.parse(source)).toEqual(selection);
  });

  it("removes only the collection-format condition while retaining the reusable content rule", () => {
    const source = '{"observation_kind":"collection_semantics","container":"gzip","retained_record_count":8,"redacted_record_count":0}';
    const restored = readStructuredSelection(source);
    if (!restored.supported) throw new Error("authored selection should be supported");
    const before = structuredClone(restored.conditions);
    const withoutContainer = restored.conditions.filter(item => item.field !== "container");
    expect(buildStructuredSelection(withoutContainer)).toEqual({ ok: true, selection: {
      observation_kind: "collection_semantics", retained_record_count: 8, redacted_record_count: 0,
    } });
    expect(restored.conditions).toEqual(before);
    expect(JSON.parse(source).container).toBe("gzip");
  });

  it("retains multiple operators on one field as distinct conjunction predicates", () => {
    const input = [condition("path", " staged/", "startswith"), condition("path", "α", "contains"), condition("path", ".jsonl ", "endswith")];
    const built = buildStructuredSelection(input);
    expect(built).toEqual({ ok: true, selection: { "path|startswith": " staged/", "path|contains": "α", "path|endswith": ".jsonl " } });
    if (!built.ok) throw new Error("authored selection should be supported");
    expect(readStructuredSelection(JSON.stringify(built.selection))).toEqual({ supported: true, conditions: input });
  });

  it.each(["", "  exact custom value  ", 'quote: "path", braces: {[]} comma: , backslash: \\', "line\nnext\tα"])("preserves string content exactly: %j", value => {
    const input = [condition("path", value)];
    const built = buildStructuredSelection(input);
    expect(built).toEqual({ ok: true, selection: { path: value } });
    expect(readStructuredSelection(JSON.stringify({ path: value }))).toEqual({ supported: true, conditions: input });
  });

  it.each(["contains", "startswith", "endswith"])("encodes the %s string operator without changing its value", operator => {
    const input = [condition("container", "zip", operator)];
    expect(buildStructuredSelection(input)).toEqual({ ok: true, selection: { [`container|${operator}`]: "zip" } });
    expect(readStructuredSelection(JSON.stringify({ [`container|${operator}`]: "zip" }))).toEqual({ supported: true, conditions: input });
  });

  it.each([
    { field: "path", operators: ["equals", "contains", "startswith", "endswith"] },
    { field: "container", operators: ["equals", "contains", "startswith", "endswith"] },
    { field: "group_write_bit", operators: ["equals"] },
    { field: "record_count", operators: ["equals"] },
  ])("offers only type-appropriate operators for $field", ({ field, operators }) => {
    expect(structuredRuleOperators(field)).toEqual(operators);
  });

  it.each(["0", "8", "9007199254740991"])("keeps the exact safe count %s as a number", value => {
    const input = [condition("retained_record_count", value)];
    expect(buildStructuredSelection(input)).toEqual({ ok: true, selection: { retained_record_count: Number(value) } });
    expect(readStructuredSelection(`{"retained_record_count":${value}}`)).toEqual({ supported: true, conditions: input });
  });

  it.each(["", "-1", "-0", "+1", "01", "1.0", "1e3", "NaN", "Infinity", "9007199254740992", " 8", "8 "])("refuses ambiguous or out-of-range draft count %j without partial output", value => {
    expectBuildRefusal([condition("container", "gzip"), condition("record_count", value)]);
  });

  it.each(["true", "false"])("builds boolean %s as a boolean, never a count or string", value => {
    expect(buildStructuredSelection([condition("group_write_bit", value)])).toEqual({ ok: true, selection: { group_write_bit: value === "true" } });
  });

  it.each(["0", "1", "True", "FALSE", "yes", "false "])("refuses non-boolean draft spelling %j", value => {
    expectBuildRefusal([condition("group_write_bit", value)]);
  });

  it.each(["0000", "0660", "7777"])("retains four-digit octal mode %s as text", value => {
    expect(buildStructuredSelection([condition("permission_mode_octal", value)])).toEqual({ ok: true, selection: { permission_mode_octal: value } });
    expect(readStructuredSelection(JSON.stringify({ permission_mode_octal: value }))).toEqual({ supported: true, conditions: [condition("permission_mode_octal", value)] });
  });

  it.each(["660", "00660", "0880", "0o660", "0660 "])("leaves invalid octal equality %j to advanced editing", value => {
    expectBuildRefusal([condition("permission_mode_octal", value)]);
    expectReadRefusal(JSON.stringify({ permission_mode_octal: value }));
  });

  it.each([
    { label: "unknown field", draft: condition("command", "authored unsupported value") },
    { label: "prototype field", draft: condition("__proto__", "authored unsupported value") },
    { label: "unknown operator", draft: condition("path", "staged/", "regex") },
    { label: "compound operator", draft: condition("path", "staged/", "contains|all") },
    { label: "boolean string operator", draft: condition("group_write_bit", "true", "contains") },
    { label: "numeric string operator", draft: condition("record_count", "8", "startswith") },
  ])("refuses $label after valid conditions without emitting a partial rule", ({ draft }) => {
    expectBuildRefusal([condition("container", "gzip"), draft]);
  });

  it("rejects repeated field/operator pairs instead of replacing the earlier condition", () => {
    expectBuildRefusal([condition("path", "first", "contains"), condition("path", "second", "contains")]);
  });

  it("refuses runtime type confusion in draft values without coercion", () => {
    const invalid = { field: "path", operator: "equals", value: false } as unknown as StructuredRuleCondition;
    expectBuildRefusal([condition("container", "gzip"), invalid]);
  });

  it.each<[string, Record<string, unknown>]>([
    ["boolean count", { record_count: true }],
    ["numeric boolean", { group_write_bit: 1 }],
    ["string boolean", { other_write_bit: "false" }],
    ["string count", { record_count: "8" }],
    ["numeric mode", { permission_mode_octal: 660 }],
    ["fractional count", { retained_record_count: 1.5 }],
    ["negative count", { empty_record_count: -1 }],
    ["unsafe count", { redacted_record_count: 9007199254740992 }],
    ["array alternative", { path: ["first", "second"] }],
    ["nested expression", { path: { contains: "staged/" } }],
    ["null value", { effective_access: null }],
    ["unknown field", { custom_fact: "retained only in advanced JSON" }],
    ["unsupported operator", { "path|regex": "staged/.*" }],
    ["compound operator", { "path|contains|all": "staged/" }],
    ["explicit equality suffix", { "path|equals": "staged/" }],
    ["empty operator suffix", { "path|": "staged/" }],
    ["operator on boolean", { "group_write_bit|contains": true }],
  ])("refuses the whole saved selection for %s, including otherwise valid preceding conditions", (_label, unsupported) => {
    const selection = { container: "gzip", ...unsupported };
    const before = structuredClone(selection);
    const source = JSON.stringify(selection);
    expectReadRefusal(source);
    expect(selection).toEqual(before);
    expect(JSON.parse(source)).toEqual(before);
  });

  it.each(["", "{", "[]", "null", "false", "8", '"selection"'])("refuses invalid or non-object JSON %j", source => {
    expectReadRefusal(source);
  });

  it.each([
    '{"path":"first","path":"second"}',
    '{"path":{"contains":"first"},"path":"second"}',
    String.raw`{"path":"first","\u0070ath":"second"}`,
    String.raw`{"path|contains":"first","path\u007ccontains":"second"}`,
  ])("refuses duplicate decoded JSON keys without discarding an earlier predicate: %s", source => {
    expectReadRefusal(source);
  });

  it("does not mistake quoted keys or nested delimiters inside string values for duplicate predicates", () => {
    const selection = { path: '"path":"other", {"container":"gzip"}, ["path"], \\', container: "jsonl" };
    const restored = readStructuredSelection(JSON.stringify(selection));
    if (!restored.supported) throw new Error("literal string contents are valid");
    expect(buildStructuredSelection(restored.conditions)).toEqual({ ok: true, selection });
  });

  it("permits an empty authoring draft without allowing an empty rule to be applied", () => {
    expect(readStructuredSelection("{} ")).toEqual({ supported: true, conditions: [] });
    expectBuildRefusal([]);
  });

  it("accepts the text boundary exactly and refuses the next character without truncation", () => {
    expect(structuredRuleLimits.stringLength).toBe(4096);
    const value = "x".repeat(4096);
    expect(buildStructuredSelection([condition("path", value)])).toEqual({ ok: true, selection: { path: value } });
    expect(readStructuredSelection(JSON.stringify({ path: value }))).toEqual({ supported: true, conditions: [condition("path", value)] });
    expectBuildRefusal([condition("path", value + "x")]);
    expectReadRefusal(JSON.stringify({ container: "gzip", path: value + "x" }));
  });

  it("accepts 32 distinct conditions and refuses the 33rd without dropping any input", () => {
    expect(structuredRuleLimits.conditions).toBe(32);
    const fields = ["artifact_type", "observation_kind", "path", "container", "permission_status", "permission_mode_octal", "effective_access"];
    const conditions = fields.flatMap(field => ["equals", "contains", "startswith", "endswith"].map(operator => condition(field, field === "permission_mode_octal" ? "0660" : "authored", operator)));
    conditions.push(...["record_count", "retained_record_count", "redacted_record_count", "empty_record_count"].map(field => condition(field, "0")));
    expect(conditions).toHaveLength(32);
    const built = buildStructuredSelection(conditions);
    if (!built.ok) throw new Error("the boundary selection should be supported");
    expect(Object.keys(built.selection)).toHaveLength(32);
    expect(readStructuredSelection(JSON.stringify(built.selection))).toEqual({ supported: true, conditions });
    expectBuildRefusal([...conditions, condition("group_write_bit", "false")]);
    expectReadRefusal(JSON.stringify({ ...built.selection, group_write_bit: false }));
  });

  it("bounds source text before parsing while allowing whitespace at the exact limit", () => {
    expect(structuredRuleLimits.sourceLength).toBe(262144);
    const source = "{}".padEnd(262144, " ");
    expect(readStructuredSelection(source)).toEqual({ supported: true, conditions: [] });
    expectReadRefusal(source + " ");
  });
});

describe("persisted visual rule drafts", () => {
  it("retains incomplete edits and the exact prior JSON without allowing application", () => {
    const draft = {
      source: '{ "container" : "gzip", "record_count" : 8 }',
      conditions: [condition("record_count", "1e3"), condition("group_write_bit", "")],
    };
    const text = JSON.stringify(draft);
    const restored = readStructuredRuleDraft(text);
    expect(restored).toEqual(draft);
    expect(restored).not.toBe(draft);
    expect(isStructuredRuleDraftText(text)).toBe(true);
    if (!restored) throw new Error("an incomplete draft is retainable");
    expectBuildRefusal(restored.conditions);
    expect(JSON.parse(text)).toEqual(draft);
  });

  it("retains duplicate pending rows for repair without allowing the last row to overwrite the first", () => {
    const draft = { source: "{}", conditions: [condition("container", "gzip"), condition("container", "jsonl")] };
    expect(readStructuredRuleDraft(JSON.stringify(draft))).toEqual(draft);
    expectBuildRefusal(draft.conditions);
  });

  it("accepts the legacy empty draft marker without inventing an editable draft", () => {
    expect(isStructuredRuleDraftText("")).toBe(true);
    expect(readStructuredRuleDraft("")).toBeNull();
  });

  it.each([null, false, 1, {}, []])("rejects a non-text persisted envelope: %j", value => {
    expect(isStructuredRuleDraftText(value)).toBe(false);
  });

  it.each<[string, unknown]>([
    ["missing source", { conditions: [] }],
    ["extra envelope field", { source: "{}", conditions: [], extra: "preserve outside visual editing" }],
    ["non-string source", { source: {}, conditions: [] }],
    ["unsupported source", { source: '{"path":["first","second"]}', conditions: [] }],
    ["duplicate source predicates", { source: '{"path":"first","path":"second"}', conditions: [] }],
    ["non-array conditions", { source: "{}", conditions: {} }],
    ["null row", { source: "{}", conditions: [null] }],
    ["array row", { source: "{}", conditions: [["path", "equals", "x"]] }],
    ["missing row value", { source: "{}", conditions: [{ field: "path", operator: "equals" }] }],
    ["extra row field", { source: "{}", conditions: [{ ...condition("path", "x"), extra: true }] }],
    ["unknown field", { source: "{}", conditions: [condition("arbitrary_field", "x")] }],
    ["unsupported operator", { source: "{}", conditions: [condition("path", "x", "regex")] }],
    ["numeric string operator", { source: "{}", conditions: [condition("record_count", "8", "contains")] }],
    ["non-text pending value", { source: "{}", conditions: [{ field: "path", operator: "equals", value: true }] }],
    ["oversized pending value", { source: "{}", conditions: [condition("path", "x".repeat(4097))] }],
    ["too many rows", { source: "{}", conditions: Array.from({ length: 33 }, () => condition("path", "x")) }],
    ["oversized source", { source: "{}".padEnd(262145, " "), conditions: [] }],
  ])("refuses the entire persisted draft for %s", (_label, draft) => {
    const before = structuredClone(draft);
    const text = JSON.stringify(draft);
    expect(readStructuredRuleDraft(text)).toBeNull();
    expect(isStructuredRuleDraftText(text)).toBe(false);
    expect(draft).toEqual(before);
  });

  it("keeps invalid JSON unavailable instead of producing an empty editable draft", () => {
    expect(readStructuredRuleDraft("{")).toBeNull();
    expect(isStructuredRuleDraftText("{")).toBe(false);
  });

  it("preserves exact row and text boundaries in a draft that still needs semantic repair", () => {
    const draft = { source: "{}", conditions: Array.from({ length: 32 }, () => condition("path", "x".repeat(4096))) };
    const restored = readStructuredRuleDraft(JSON.stringify(draft));
    expect(restored).toEqual(draft);
    expectBuildRefusal(draft.conditions);
  });

  it("accepts the exact serialized draft limit and refuses its next character", () => {
    expect(structuredRuleLimits.draftLength).toBe(1048576);
    const draft = { source: "{}", conditions: [] };
    const text = JSON.stringify(draft).padEnd(1048576, " ");
    expect(readStructuredRuleDraft(text)).toEqual(draft);
    expect(isStructuredRuleDraftText(text)).toBe(true);
    expect(readStructuredRuleDraft(text + " ")).toBeNull();
    expect(isStructuredRuleDraftText(text + " ")).toBe(false);
  });
});
